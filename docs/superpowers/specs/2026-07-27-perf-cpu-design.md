# Performance / CPU reduction design

Date: 2026-07-27. Goal: improve proxy performance and lower CPU. Scope: the four fixes below,
selected from a measured baseline on dispatch-dev-1 (2 vCPU Amazon Linux 1, redis 7 +
redis-benchmark in host-network containers on loopback, proxy as native `-O2 -std=gnu99` build).

## Where the CPU goes (measured)

Baseline, single-process proxy, 50 clients, 32-byte values, SET+GET:

| case | rps (SET/GET) | p50 ms | proxy CPU µs/op (r1 / r2) |
|---|---|---|---|
| direct to redis | 57–63k | 0.36–0.38 | — |
| via proxy, no pipeline (P1) | 28.6–30.3k | 0.74–0.82 | 25.8 / 27.2 |
| via proxy, pipeline 16 (P16) | 124–128k | 5.5–6.0 | 7.1 / 7.2 |
| via proxy, 2 workers (P1) | 24.0–26.8k | 0.90–0.98 | 31.4 / 32.0 |
| via proxy, P1, mbuf 512 | 29.5–30.6k | 0.75–0.80 | 25.5 / 26.5 |

(2-round matrix, rounds consistent. CPU µs/op = utime+stime tick delta across all proxy processes /
ops driven.)

Syscall profile (strace -c, 12 s under P1 load):

| syscall | calls | per writev |
|---|---|---|
| epoll_ctl | 55,420 | 2.00 |
| read | 27,745 | 1.00 |
| writev | 27,708 | 1.00 |
| getpeername | 26,289 | 0.95 |

Reading: at P1 the proxy is syscall-bound. The 16x-pipelined case amortizes syscalls over 16
requests and CPU/op falls 3.6x — confirming syscalls, not parsing/hashing, dominate. Two of the
~5 hot-path syscalls per op are epoll_ctl arm/disarm churn (Fix 1); one is a per-request
getpeername that feeds a log line compiled out of release builds (Fix 4).

## Verdicts on the candidate list

| Issue | Verdict | Why |
|---|---|---|
| Multithreading / worker_processes | NO CODE CHANGE | Multi-process + SO_REUSEPORT already exists and is `auto` in the deployed config. On the 2-core test box 2 workers measured WORSE than 1 (31.5 vs 26.4 µs/op, lower rps — contention with colocated backend/client). Guidance: worth `auto` only on 4+ core hosts dedicated to the proxy. |
| Blocking getaddrinfo in event loop | FIX (2) | `core_dns_maintenance` and conn-setup call `getaddrinfo` synchronously inside the event loop every `dns_resolve_interval` (10 s in staging). A slow resolver freezes every in-flight request on the worker. Worst tail-latency hazard in the fork; contradicts its own µs-level routing goals. |
| epoll_ctl churn + next-tick sends | FIX (1) | Measured 2 epoll_ctl per op. Also every forward waits one loop tick before the write happens. |
| req_log syscall work for compiled-out log | FIX (4) | Measured ~1 getpeername + gettimeofday + format prep per op, feeding an empty macro in release builds. Found via strace, not in the original candidate list. |
| Connect-time-only latency EWMA | FIX (3) | Routing weights go stale between connection churn events; probe paths force churn just to refresh them. Fresh signal is nearly free (see below). |
| mbuf 16 KB default | TUNE ONLY | `-m 512` measured within noise of 16 KB on this workload — CPU is not in mbuf handling. Knob already exists; tune per deployment for memory, not CPU. |
| mget/mset fragmentation copies | SKIP | Invasive; staging stats show `fragments: 0` — the dispatch workload never multi-keys through the proxy. |

## Fix 1: deferred send flush (kills epoll_ctl churn + one-tick send delay)

Redis-style "clients to write" pattern:

- `struct conn` gains `unsigned in_flushq:1` and `TAILQ_ENTRY(conn) flush_tqe` (conn_tqe is taken
  by server/free queues; a conn can be in both at once).
- `struct context` gains a `flush_connq` TAILQ head.
- New `conn_pend_flush(ctx, conn)`: flag-guarded O(1) append. Replaces `event_add_out` at the
  message-enqueue sites: req_forward (nc_request.c:610), rsp forward (nc_response.c:266),
  local-reply (nc_request.c:672), forward-error (nc_request.c:547), server-close error broadcast
  (nc_server.c:475, 508).
- `core_loop`: after `event_wait` returns (all ready-event callbacks have run), drain the queue:
  for each conn — unlink + clear flag first; skip if `err || done` (close path owns it); skip if
  `connecting` (connect completion arrives via the EPOLLOUT that `event_add_conn` already armed);
  else call `conn->send()`; if data remains pending (`conn->smsg != NULL` or unsent queue head —
  EAGAIN / partial write) → `event_add_out`.
- `core_close`: unlink from flush queue when flagged (no dangling entries).
- `_conn_get`: clear `in_flushq` on conn reuse.
- `msg_send` drops `ASSERT(conn->send_active)` — direct sends are now legal.
- The `event_del_out` calls inside `req_send_next`/`rsp_send_next` stay: they no-op when EPOLLOUT
  is not armed and disarm it after a partial-write recovery drains.

Preserved behavior: writev batching (everything enqueued during one tick still coalesces into one
writev per conn), EAGAIN handling (leftover arms EPOLLOUT, the existing core_send path resumes),
error handling (send failure sets `conn->err`, conn is left armed, next tick's event delivers it to
the normal close path — no reentrant close from inside forwarding code).

Effect per hop, common case: `epoll_ctl(+W)` … wait one tick … `writev` … `epoll_ctl(−W)` becomes
just `writev`.

## Fix 2: async DNS resolver

- One resolver pthread per proxy process, started alongside the stats thread; a request queue
  (mutex + condvar) and a self-pipe whose read end is registered in the event loop.
- The loop enqueues `{server*, hostname copy, port, max_addresses}` when
  `server_should_resolve_dns()` fires; the thread runs ONLY `nc_resolve_multi_with_hostnames()`
  (the getaddrinfo wrapper — the sole blocking piece of `server_dns_resolve`); the result
  `{addrs, hostnames, n, status}` comes back over the pipe; the LOOP applies it via the existing
  merge/accumulate logic (`server_dns_resolve` splits into thread-side resolve + loop-side
  `server_dns_apply`). The thread never touches server/pool structs; hostname is copied into the
  request.
- At most one in-flight resolve per server (flag on `server_dns`); failure logs and retries on the
  existing interval cadence.
- Conn-setup (`server_resolve`) stops resolving inline — it always uses the current cached addrs.
  Staleness stays bounded by `dns_resolve_interval`, same as today between maintenance ticks.
- Startup keeps the first resolve synchronous (an address is needed before listening; not a hot
  path).
- Teardown: stop + join the resolver thread before ctx teardown so no result can land on a freed
  ctx.
- Portability: pipe, not eventfd — kqueue/macOS builds and the mac unit harness keep working.

## Fix 3: request-RTT EWMA feed

- The per-response server RTT is already computed for stats:
  `stats_server_record_latency(ctx, conn->owner, nc_msec_now() - pmsg->forward_start_ts)`
  (nc_response.c:289), with `forward_start_ts` stamped in req_forward (nc_request.c:772).
- Change `forward_start_ts` to usec resolution (`nc_usec_now()`; 3 total uses); the stats site
  divides by 1000 so reported stats are unchanged. µs resolution is required — the routing model
  discriminates same-AZ vs cross-AZ replicas by hundreds of µs, which msec math flattens to 0–1.
- At that site, for dynamic servers, also call `server_measure_latency(server, conn->addr_idx,
  rtt_us)` — same saturating EWMA, same 90/10 blend as connect-time samples.
- Guards: skip error responses; validate `conn->addr_idx < dns->naddresses` (a DNS refresh can
  shrink the array while a response is in flight).
- Connect-time sampling remains (first sample for untested addrs, coverage across idle periods).
- Follow-on (out of scope): with fresh per-request signal, probe-forced connection churn
  (`connection_max_lifetime` recycling for measurement's sake) can be relaxed.

## Fix 4: req_log gating

Wrap `req_log()`'s body in `#ifdef NC_DEBUG_LOG` — the same conditional that defines the
`log_debug()` macro consuming its output (nc_log.h:56/74). Release builds stop paying
gettimeofday + getpeername + format prep per request for a line that cannot print. Debug builds
keep exactly today's behavior. (This also stops release builds from NUL-patching the key inside
the request buffer at nc_request.c:80 — a side effect that only existed to pretty-print the key.)

## Testing

- TDD with the existing C unit harness (tests/unit/run.sh); new tests: flush-queue drain semantics
  where unit-testable, `server_dns_apply` merge behavior driven with fake resolver results, EWMA
  RTT-feed guards. All existing tests must stay green.
- Functional: tests/docker/run.sh and run-latency.sh (compose v2 — run where available; not on
  dispatch-dev-1).
- Benchmark: same run-bench.sh matrix on dispatch-dev-1, before/after, plus strace syscall counts
  (expect epoll_ctl ≈ 0 per op steady-state and getpeername gone).

## Rollout note

The deployed image on dispatch-dev-1 is 2.1.1; this work lands on develop (2.2.0 line). Benchmark
comparisons are develop-vs-develop+fixes, not vs the deployed 2.1.1.

## Measured result (branch perf/cpu-reduction, same matrix + host as baseline)

Two iterations were benchmarked. Full deferred flush (every conn) killed all epoll_ctl churn but
HALVED requests-per-writev to the backend — the old one-tick EPOLLOUT wait had been accidentally
coalescing two ticks of requests per server writev — costing ~10% unpipelined throughput. The
landed design is a hybrid: client conns use the flush queue, server conns keep arm-on-empty.

| case | metric | baseline (r1/r2) | hybrid (r1/r2) | delta |
|---|---|---|---|---|
| w0-P1 | CPU µs/op | 25.8 / 27.2 | 25.4 / 27.6 | parity (noise) |
| w0-P1 | GET rps | 30.3k / 29.9k | 30.7k / 28.7k | parity |
| w0-P16 | CPU µs/op | 7.1 / 7.2 | **4.4 / 4.7** | **−35%** |
| w0-P16 | SET rps | 120k / 124k | **220k / 199k** | **+65%** |
| w0-P16 | GET rps | 116k / 128k | **169k / 165k** | **+35%** |
| w2-P1 | CPU µs/op | 31.4 / 32.0 | **26.8 / 26.7** | **−15%** |

Syscall mix under identical strace windows (counts are strace-throttled; the per-op RATIO is the
signal): baseline ~5.1 syscalls/op (1 read + 1 writev + 2 epoll_ctl + ~0.95 getpeername); hybrid
~2.1 syscalls/op (1 read + 1 writev + 0.1 epoll_ctl). getpeername eliminated (Fix 4), epoll_ctl
−91% (Fix 1 hybrid).

Not benchmarkable here but landed: the event loop no longer blocks in getaddrinfo (Fix 2 — tail
latency insurance under resolver trouble), and replica EWMA now updates per response instead of
per connect (Fix 3 — verified by tests/docker/run-latency.sh: spread, band membership and
failover re-weighting all pass through the patched proxy).

Multi-worker note: with the syscall churn gone, 2-worker CPU/op landed within ~1 µs of
single-worker (26.7 vs 26.5) — the earlier "workers cost +19% CPU/op" penalty was mostly
epoll_ctl churn. Throughput on the 2-core shared box still favors a single worker; the `auto`
guidance in the verdict table stands.
