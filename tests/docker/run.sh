#!/usr/bin/env bash
#
# Integration test for the twemproxy fork's headline feature: in-process
# discovery of MANY read replicas behind ONE hostname, via DNS, plus a working
# write path and a traffic driver.
#
# See docker-compose-test.yml for the full "why this stands in for ElastiCache"
# rationale. In short: a Compose service scaled to N containers resolves its
# service name to N A-records, exactly like an ElastiCache reader endpoint --
# so we exercise real replica discovery / health / failover without AWS.
#
# What this asserts (each step exits non-zero on failure):
#   1. Build image, bring stack up, scale redis-read=3, wait for twemproxy
#      HEALTHY.
#   2. DISCOVERY (the core assertion): the read pool's dynamic server reports
#      addresses == 3 in /stats -> in-process multi-replica discovery works.
#   3. CORRECTNESS: SET via the write port (6379), GET via the read port (6378)
#      returns the same value (reads served by a real replica).
#   4. LOAD: redis-benchmark through the write port (set,incr) and read port
#      (get) at concurrency; assert rc=0, no dropped connections.
#   5. FAILOVER + REDISCOVERY: kill one replica -> reads keep succeeding, and
#      the discovered count drops 3 -> 2; restart it -> count returns to 2 -> 3.
#
# Run it:  bash tests/docker/run.sh
# Needs:   docker + compose v2 on the host, plus curl and jq on the host.
# Bounded: a few minutes (the 3 -> 2 prune waits out dns_expiration_minutes=1).
#
# shellcheck disable=SC2317  # functions are called via traps / indirectly

set -euo pipefail

#--------------------------------------------------------------------------
# Setup: locate the compose file, pick a unique project name, define helpers.
#--------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose-test.yml"
PROJECT="twemfork-itest-$$"

# Host ports the proxy publishes (see compose). Stats is scraped from the host;
# redis traffic is driven from inside a backend container over the test network.
STATS_URL="http://127.0.0.1:22222"

# Tunables (kept in step with the SHORT intervals in the compose file).
READ_REPLICAS=3
HEALTH_WAIT_SECS=90       # max wait for twemproxy to report HEALTHY
DISCOVERY_WAIT_SECS=45    # max wait for addresses to reach 3 (a few resolve ticks)
ROUNDTRIP_WAIT_SECS=20    # max wait for the written value to replicate to a reader
PRUNE_WAIT_SECS=110       # max wait for a killed replica to drop out (expiration=1min)
REDISCOVER_WAIT_SECS=45   # max wait for a restarted replica to be re-added

FAILURES=0

# Compose wrapper bound to our file + isolated project name.
dc() { docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" "$@"; }

# Run a command inside the redis-write backend (has redis-cli + redis-benchmark),
# targeting the proxy by its in-network service name. -T = no TTY (script-safe).
in_redis() { dc exec -T redis-write "$@"; }

pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
step() { printf '\n=== %s ===\n' "$1"; }

# Pull the discovered-address count for the dynamic read server out of /stats.
# The fork emits, per dynamic server, a "dns_hosts" object that includes
# {"type":"dynamic", "addresses":N, ...}. We find that object anywhere in the
# document and read .addresses. Prints the integer, or nothing if not present
# yet (server not resolved -> dns_hosts is null).
discovered_count() {
  curl -fsS --max-time 3 "${STATS_URL}/stats" 2>/dev/null \
    | jq -r 'first(.. | objects | select(.type? == "dynamic") | .addresses) // empty' 2>/dev/null
}

# Print the whole dynamic dns_hosts object (for evidence).
dns_hosts_json() {
  curl -fsS --max-time 3 "${STATS_URL}/stats" 2>/dev/null \
    | jq 'first(.. | objects | select(.type? == "dynamic"))' 2>/dev/null
}

#--------------------------------------------------------------------------
# Teardown: always remove everything, even on Ctrl-C or a failed assertion.
#--------------------------------------------------------------------------
# shellcheck disable=SC2329  # invoked indirectly via the EXIT/INT/TERM trap
cleanup() {
  local rc=$?
  step "TEARDOWN"
  echo "Removing project ${PROJECT} (containers + network + volumes)..."
  dc down --remove-orphans -v --timeout 5 >/dev/null 2>&1 || true
  echo "Done."
  # Preserve the real exit status (set -e failure or our explicit exit codes).
  trap - EXIT
  exit "${rc}"
}
trap cleanup EXIT INT TERM

#--------------------------------------------------------------------------
# Preflight: required host tools.
#--------------------------------------------------------------------------
step "PREFLIGHT"
for tool in docker curl jq; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "ERROR: required tool '${tool}' not found on host." >&2
    exit 2
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: 'docker compose' (v2) not available." >&2
  exit 2
fi
echo "docker, compose v2, curl, jq all present."

# The only host port we publish is the stats port (22222). Fail fast with a
# clear message if something already holds it, instead of dying mid-`up` with a
# cryptic 'port is already allocated'. (redis 6378/6379 are NOT published -- see
# the compose file -- so a local redis on 6379 does not affect this test.)
if lsof -nP -iTCP:22222 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "ERROR: host port 22222 (stats) is already in use. Free it or stop the" >&2
  echo "       process holding it, then re-run. (lsof -nP -iTCP:22222 -sTCP:LISTEN)" >&2
  exit 2
fi
echo "host stats port 22222 is free."

#--------------------------------------------------------------------------
# 1. Build + bring up + scale + wait for twemproxy HEALTHY.
#--------------------------------------------------------------------------
step "1. BUILD + UP (scale redis-read=${READ_REPLICAS})"
# Tear down any stale run of this exact project first (paranoia; project name
# includes the PID so collisions are unlikely).
dc down --remove-orphans -v >/dev/null 2>&1 || true
dc build twemproxy
dc up -d --scale "redis-read=${READ_REPLICAS}"

echo "Containers:"
dc ps

# Sanity: the scaled service must resolve to ${READ_REPLICAS} A-records, or the
# whole premise (compose-DNS == reader-endpoint) is invalid. Probe from the
# write backend.
step "1a. VERIFY compose DNS returns ${READ_REPLICAS} A-records for redis-read"
dns_ips="$(in_redis getent hosts redis-read | awk '{print $1}' | sort -u || true)"
dns_n="$(printf '%s\n' "${dns_ips}" | grep -c . || true)"
echo "redis-read resolves to:"
printf '%s\n' "${dns_ips}" | sed 's/^/    /'
if [ "${dns_n}" -eq "${READ_REPLICAS}" ]; then
  pass "compose DNS returns ${READ_REPLICAS} distinct IPs for redis-read"
else
  fail "compose DNS returned ${dns_n} IPs, expected ${READ_REPLICAS} (premise broken)"
fi

step "1b. WAIT for twemproxy HEALTHY (<= ${HEALTH_WAIT_SECS}s)"
cid="$(dc ps -q twemproxy)"
if [ -z "${cid}" ]; then
  fail "twemproxy container not found"
else
  healthy=0
  for _ in $(seq 1 "${HEALTH_WAIT_SECS}"); do
    state="$(docker inspect -f '{{.State.Health.Status}}' "${cid}" 2>/dev/null || echo unknown)"
    if [ "${state}" = "healthy" ]; then healthy=1; break; fi
    sleep 1
  done
  if [ "${healthy}" -eq 1 ]; then
    pass "twemproxy reports HEALTHY"
  else
    fail "twemproxy not HEALTHY within ${HEALTH_WAIT_SECS}s (last state: ${state:-unknown})"
    echo "--- twemproxy logs (tail) ---"
    dc logs --tail 60 twemproxy || true
  fi
fi

#--------------------------------------------------------------------------
# 2. DISCOVERY -- the core assertion. addresses must reach READ_REPLICAS.
#--------------------------------------------------------------------------
step "2. DISCOVERY: read pool must discover all ${READ_REPLICAS} replicas"
count=""
for _ in $(seq 1 "${DISCOVERY_WAIT_SECS}"); do
  count="$(discovered_count || true)"
  if [ "${count:-0}" = "${READ_REPLICAS}" ]; then break; fi
  sleep 1
done
echo "Discovered dns_hosts object from /stats:"
dns_hosts_json | sed 's/^/    /' || true
if [ "${count:-0}" = "${READ_REPLICAS}" ]; then
  pass "read pool discovered all ${READ_REPLICAS} replicas (addresses=${count})"
else
  fail "read pool discovered ${count:-0} replicas, expected ${READ_REPLICAS}"
  echo "--- twemproxy logs (tail, DNS lines) ---"
  dc logs --tail 120 twemproxy 2>/dev/null | grep -iE 'dns|address|resolv' | tail -30 || true
fi

#--------------------------------------------------------------------------
# 3. CORRECTNESS through the proxy: write via 6379, read back via 6378.
#--------------------------------------------------------------------------
step "3. CORRECTNESS: SET via write port, GET via read port"
KEY="itest:roundtrip:$$"
VAL="hello-from-write-$$"
# Write to the primary through the WRITE pool (twemproxy:6379).
set_reply="$(in_redis redis-cli -h twemproxy -p 6379 SET "${KEY}" "${VAL}" || true)"
echo "  SET (write port 6379) -> ${set_reply}"

# Read back through the READ pool (twemproxy:6378). Replicas are real redis
# replicas of redis-write, so the value appears after a brief replication lag.
# Poll until it shows up or we time out.
got=""
for _ in $(seq 1 "${ROUNDTRIP_WAIT_SECS}"); do
  got="$(in_redis redis-cli -h twemproxy -p 6378 GET "${KEY}" 2>/dev/null || true)"
  if [ "${got}" = "${VAL}" ]; then break; fi
  sleep 1
done
echo "  GET (read port 6378)  -> ${got}"
if [ "${set_reply}" = "OK" ] && [ "${got}" = "${VAL}" ]; then
  pass "round-trip OK (write->primary, read-back from replica via proxy)"
else
  fail "round-trip mismatch (set='${set_reply}', got='${got}', want='${VAL}')"
fi

#--------------------------------------------------------------------------
# 4. LOAD: redis-benchmark through both ports. Assert rc=0, no dropped conns.
#--------------------------------------------------------------------------
step "4. LOAD: redis-benchmark through write (set,incr) and read (get) ports"
BENCH_REQUESTS=20000
BENCH_CLIENTS=50

# Write-side load: SET + INCR through 6379. -q = quiet (one rps line per test).
echo "  --- write port 6379: SET, INCR (${BENCH_REQUESTS} reqs, ${BENCH_CLIENTS} clients) ---"
if in_redis redis-benchmark -h twemproxy -p 6379 \
      -n "${BENCH_REQUESTS}" -c "${BENCH_CLIENTS}" -t set,incr -q \
      | sed 's/^/    /'; then
  pass "write-port benchmark completed rc=0 (no dropped connections)"
else
  fail "write-port benchmark failed (rc!=0 -> dropped/refused connections)"
fi

# Read-side load: GET through 6378. The keyspace was just written above; GET on
# missing keys still round-trips fine through the proxy, which is what we assert.
echo "  --- read port 6378: GET (${BENCH_REQUESTS} reqs, ${BENCH_CLIENTS} clients) ---"
if in_redis redis-benchmark -h twemproxy -p 6378 \
      -n "${BENCH_REQUESTS}" -c "${BENCH_CLIENTS}" -t get -q \
      | sed 's/^/    /'; then
  pass "read-port benchmark completed rc=0 (no dropped connections)"
else
  fail "read-port benchmark failed (rc!=0 -> dropped/refused connections)"
fi

#--------------------------------------------------------------------------
# 5. FAILOVER + REDISCOVERY: kill a replica -> reads survive + count 3->2,
#    restart it -> count 2->3.
#--------------------------------------------------------------------------
step "5. FAILOVER: kill one replica, assert reads survive + count drops to 2"
victim="$(dc ps -q redis-read | head -1)"
if [ -z "${victim}" ]; then
  fail "could not find a redis-read replica to kill"
else
  echo "  Killing replica container ${victim} ..."
  docker kill "${victim}" >/dev/null

  # Reads must KEEP succeeding immediately (routed to survivors via health +
  # auto_eject). Hammer the read port a few times right after the kill.
  read_ok=1
  for _ in $(seq 1 20); do
    if ! in_redis redis-cli -h twemproxy -p 6378 GET "${KEY}" >/dev/null 2>&1; then
      read_ok=0; break
    fi
  done
  if [ "${read_ok}" -eq 1 ]; then
    pass "reads on 6378 kept succeeding right after replica kill"
  else
    fail "a read on 6378 failed after replica kill (no failover to survivors)"
  fi

  # The discovered count should drop to READ_REPLICAS-1 once the dead IP ages
  # out of the discovered set (dns_expiration_minutes=1 -> ~60s after it stops
  # appearing in DNS).
  want_after_kill=$((READ_REPLICAS - 1))
  echo "  Waiting up to ${PRUNE_WAIT_SECS}s for discovered count to drop to ${want_after_kill} ..."
  dropped=0
  for _ in $(seq 1 "${PRUNE_WAIT_SECS}"); do
    c="$(discovered_count || true)"
    if [ "${c:-0}" = "${want_after_kill}" ]; then dropped=1; break; fi
    sleep 1
  done
  echo "  discovered count now: $(discovered_count || echo '?')"
  if [ "${dropped}" -eq 1 ]; then
    pass "dead replica ejected: discovered count dropped ${READ_REPLICAS} -> ${want_after_kill}"
  else
    fail "discovered count did not drop to ${want_after_kill} within ${PRUNE_WAIT_SECS}s (now: $(discovered_count || echo '?'))"
  fi
fi

step "5b. REDISCOVERY: restart the replica, assert count returns to ${READ_REPLICAS}"
echo "  Re-scaling redis-read back to ${READ_REPLICAS} ..."
dc up -d --scale "redis-read=${READ_REPLICAS}" --no-recreate
rediscovered=0
for _ in $(seq 1 "${REDISCOVER_WAIT_SECS}"); do
  c="$(discovered_count || true)"
  if [ "${c:-0}" = "${READ_REPLICAS}" ]; then rediscovered=1; break; fi
  sleep 1
done
echo "  discovered count now: $(discovered_count || echo '?')"
echo "  final dns_hosts object:"
dns_hosts_json | sed 's/^/    /' || true
if [ "${rediscovered}" -eq 1 ]; then
  pass "rediscovery OK: discovered count returned ${want_after_kill:-2} -> ${READ_REPLICAS}"
else
  fail "discovered count did not return to ${READ_REPLICAS} within ${REDISCOVER_WAIT_SECS}s"
fi

#--------------------------------------------------------------------------
# Verdict.
#--------------------------------------------------------------------------
step "RESULT"
if [ "${FAILURES}" -eq 0 ]; then
  echo "ALL ASSERTIONS PASSED."
  exit 0
else
  echo "${FAILURES} ASSERTION(S) FAILED."
  exit 1
fi
