# twemproxy (fork) — zone- & latency-aware Redis proxy

Fork of [twemproxy](https://github.com/coolnagour/twemproxy) built for AWS ElastiCache:
it resolves a reader endpoint's DNS continuously, discovers every replica behind it, measures
per-replica latency and routes reads to the fastest healthy set — writes go straight to the
primary. Multi-arch image: `linux/amd64` + `linux/arm64` (glibc, debian bookworm base).

## Tags

- `2.3.0` — perf/CPU release: async DNS resolution off the event loop, deferred client send
  flush (−91% epoll_ctl), per-request RTT feeding replica weights, release-build logging cost
  removed. Measured: −35% CPU/op and +35–65% throughput pipelined; ~2 syscalls/op (was ~5).
- `2.2.x` — latency-weighted read distribution across discovered replicas.
- `2.1.x` — zone-aware routing, dynamic ElastiCache endpoint discovery.

## Quick start

```yaml
services:
  twemproxy:
    image: bobbymaher/twemproxy:2.3.0
    ports:
      - "6379:6379"   # write pool -> primary endpoint
      - "6378:6378"   # read pool  -> reader endpoint (replica discovery)
      - "22222:22222" # stats (HTTP JSON)
    environment:
      WRITE_HOST: "my-cluster.abc123.euw1.cache.amazonaws.com:6379"
      READ_HOST: "my-cluster-ro.abc123.euw1.cache.amazonaws.com:6379"
      DYNAMIC_SERVER_CONNECTIONS: "true"
```

Point clients' writes at `:6379` and reads at `:6378`. Stats: `curl localhost:22222/stats`.

## Configuration (env vars)

| Variable | Default | Meaning |
|---|---|---|
| `WRITE_HOST` | `redis-write:6379` | Primary endpoint (write pool) |
| `READ_HOST` | `redis-read:6379` | Reader endpoint (read pool, DNS-discovered replicas) |
| `DNS_RESOLVE_INTERVAL` | `30` | Seconds between reader-endpoint re-resolves |
| `DNS_HEALTH_CHECK_INTERVAL` | `30` | Seconds between replica health checks |
| `DNS_EXPIRATION_MINUTES` | `5` | Drop replicas unseen in DNS for this long |
| `SERVER_CONNECTIONS` | `1` | Connections per server (static sizing) |
| `DYNAMIC_SERVER_CONNECTIONS` | `false` | Size connections from the healthy replica set |
| `MAX_SERVER_CONNECTIONS` | `10` | Cap for dynamic sizing |
| `CONNECTION_MAX_LIFETIME` | `30` | Seconds before a server connection is recycled |
| `LATENCY_BAND_FACTOR` | `3` | Replicas within `factor x` fastest stay in the read set |
| `CROSS_AZ_SURCHARGE_US` | `0` | Effective-latency penalty for cross-AZ replicas (µs) |

A full `nutcracker.yml` is generated at startup from these; mount your own at
`/etc/twemproxy/nutcracker.yml` to bypass templating entirely.

## Notes

- `worker_processes: auto` is set in the generated config (SO_REUSEPORT workers). On small
  hosts (≤2 cores) a single worker often measures better.
- Source, benchmarks and design docs: https://github.com/coolnagour/twemproxy
