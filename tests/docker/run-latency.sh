#!/usr/bin/env bash
#
# Integration test: LATENCY-WEIGHTED multi-replica read distribution.
#
# Sibling of run.sh (which proves bare DNS discovery / health / failover). This
# proves the headline feature: with >=3 read replicas behind one dynamic
# endpoint and dynamic_server_connections ON, reads (1) SPREAD across multiple
# replicas instead of pinning one, (2) follow LATENCY -- fast replicas are used,
# a far replica falls OUT of the good-latency band and gets ~no traffic -- and
# (3) RE-WEIGHT on failover when a near replica dies.
#
# See docker-compose-latency-test.yml for the topology and the netem latency
# injection (three replicas under one `redis-read` alias, each with its own
# `tc netem delay`: near-a +10ms, near-b +15ms, far +200ms). The two nears are
# kept close so both reliably stay in the good-latency band; the far one is set
# far beyond the band so it is reliably excluded.
#
# What is asserted (deterministic PASS/FAIL gates), vs. reported (evidence):
#
#   GOAL 1  Multi-replica spread (the core regression fix):
#     ASSERT current_server_connections >= 2  (was 1-pinned before the fix)
#     ASSERT >= 2 distinct replicas show backend connections from the proxy.
#
#   GOAL 2  Latency-responsiveness:
#     ASSERT both near replicas are in_good_set=true and the far one is
#            in_good_set=false (the band is computed from measured latency).
#     ASSERT eff_latency(far) > eff_latency(both nears)  (skew is seen).
#     ASSERT the far replica gets ~no traffic (its request share is tiny).
#     REPORT the near-a vs near-b split (faster should lean higher) -- printed
#            as directional evidence, NOT hard-asserted: connect-time latency +
#            connection recycling make the fine split noisy in docker. The
#            precise inverse-latency percentages are AWS-gated (real per-AZ
#            latency); see the design's "zone selection stays AWS-gated" note.
#
#   GOAL 3  Failover re-weighting:
#     Kill a near replica mid-load. ASSERT reads keep succeeding and the pool
#            re-converges to a healthy good set (>= 1 surviving in-band replica,
#            killed replica ejected). REPORT whether the far replica re-enters
#            the band once a near is gone.
#
# Why the per-address `requests` counter is used only as supporting evidence:
# it is bumped against the server's single current_addr_idx (the address chosen
# for the most-recently-opened connection), not per connection, so it is a
# directional signal, not an exact per-request tally. The DETERMINISTIC proof of
# spread is the connection distribution at the redis backends + the good-set
# size; the band membership is the deterministic proof of latency-responsiveness.
#
# Run it:  bash tests/docker/run-latency.sh
# Needs:   docker + compose v2 on the host, plus curl and jq on the host.
# Bounded: a few minutes (netem replicas apt-install iproute2; latency EWMA and
#          the failover prune wait out the short DNS intervals).
#
# shellcheck disable=SC2317  # functions are called via traps / indirectly

set -euo pipefail

#--------------------------------------------------------------------------
# Setup
#--------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose-latency-test.yml"
PROJECT="twemfork-lat-$$"
STATS_URL="http://127.0.0.1:22222"

# The three replica services and their injected one-way delays (ms), kept in
# step with docker-compose-latency-test.yml. NEAR_SVCS are expected in-band;
# FAR_SVC is expected out-of-band.
NEAR_A_SVC="redis-read-near-a"; NEAR_A_MS=10
NEAR_B_SVC="redis-read-near-b"; NEAR_B_MS=15
FAR_SVC="redis-read-far";       FAR_MS=200
ALL_SVCS=("${NEAR_A_SVC}" "${NEAR_B_SVC}" "${FAR_SVC}")
N_REPLICAS=3

# Waits (condition-polled, not fixed sleeps where it matters).
HEALTH_WAIT_SECS=120     # twemproxy HEALTHY (replicas apt-install iproute2 first)
DISCOVERY_WAIT_SECS=60   # /stats addresses -> 3
CONVERGE_WAIT_SECS=90    # latency EWMA settles so band = {nears in, far out}
PRUNE_WAIT_SECS=120      # killed replica drops out (dns_expiration_minutes=1)

FAILURES=0

dc() { docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" "$@"; }
# Drive redis from inside the write backend (has redis-cli + redis-benchmark).
in_redis() { dc exec -T redis-write "$@"; }

pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
step() { printf '\n=== %s ===\n' "$1"; }

# Whole dynamic dns_hosts object from /stats (for evidence + parsing).
dyn_json() {
  curl -fsS --max-time 4 "${STATS_URL}/stats" 2>/dev/null \
    | jq -c 'first(.. | objects | select(.type? == "dynamic"))' 2>/dev/null
}
discovered_count() {
  dyn_json | jq -r '.addresses // empty' 2>/dev/null
}

# Map a replica service name -> its IP on twemnet (so we can label each /stats
# address_details entry, which all share the `redis-read` cname). Echoes the IP.
svc_ip() {
  local svc="$1" cid ip
  cid="$(dc ps -q "${svc}" 2>/dev/null | head -1)"
  [ -z "${cid}" ] && { echo ""; return; }
  ip="$(docker inspect "${cid}" \
        --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)"
  echo "${ip}"
}

# A field for a given IP from the current /stats address_details. Usage:
#   addr_field <ip> <jq-field>   e.g. addr_field 172.18.0.3 in_good_set
addr_field() {
  local ip="$1" field="$2"
  dyn_json | jq -r --arg ip "${ip}" --arg f "${field}" \
    '.address_details[]? | select(.ip == $ip) | .[$f]' 2>/dev/null
}

# Cumulative connections a replica has accepted from the proxy (ground-truth of
# "did reads land here"). Echoes an integer (0 if unavailable).
svc_total_conns() {
  local svc="$1" v
  v="$(dc exec -T "${svc}" redis-cli INFO stats 2>/dev/null \
        | tr -d '\r' | awk -F: '/total_connections_received/{print $2}')"
  echo "${v:-0}"
}
svc_connected_clients() {
  local svc="$1" v
  v="$(dc exec -T "${svc}" redis-cli INFO clients 2>/dev/null \
        | tr -d '\r' | awk -F: '/connected_clients/{print $2}')"
  echo "${v:-0}"
}

#--------------------------------------------------------------------------
# Teardown (always; survives Ctrl-C and a failed assertion).
#--------------------------------------------------------------------------
# shellcheck disable=SC2329  # invoked via the EXIT/INT/TERM trap
cleanup() {
  local rc=$?
  step "TEARDOWN"
  echo "Removing project ${PROJECT} (containers + network + volumes)..."
  dc down --remove-orphans -v --timeout 5 >/dev/null 2>&1 || true
  echo "Done."
  trap - EXIT
  exit "${rc}"
}
trap cleanup EXIT INT TERM

#--------------------------------------------------------------------------
# Preflight
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
if lsof -nP -iTCP:22222 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "ERROR: host port 22222 (stats) is already in use. Free it and re-run." >&2
  exit 2
fi
echo "docker, compose v2, curl, jq present; stats port 22222 free."

#--------------------------------------------------------------------------
# 1. Build + up + wait HEALTHY
#--------------------------------------------------------------------------
step "1. BUILD + UP (3 latency-shaped replicas under one alias)"
dc down --remove-orphans -v >/dev/null 2>&1 || true
dc build twemproxy
dc up -d

echo "Containers:"
dc ps

step "1a. VERIFY the shared alias 'redis-read' resolves to ${N_REPLICAS} A-records"
dns_ips="$(in_redis getent hosts redis-read 2>/dev/null | awk '{print $1}' | sort -u || true)"
dns_n="$(printf '%s\n' "${dns_ips}" | grep -c . || true)"
echo "redis-read resolves to:"; printf '%s\n' "${dns_ips}" | sed 's/^/    /'
if [ "${dns_n}" -eq "${N_REPLICAS}" ]; then
  pass "alias returns ${N_REPLICAS} distinct IPs"
else
  fail "alias returned ${dns_n} IPs, expected ${N_REPLICAS} (premise broken)"
fi

step "1b. MAP replica service -> IP (to label /stats entries)"
NEAR_A_IP="$(svc_ip "${NEAR_A_SVC}")"
NEAR_B_IP="$(svc_ip "${NEAR_B_SVC}")"
FAR_IP="$(svc_ip "${FAR_SVC}")"
printf '    %-22s +%-4sms  ip=%s\n' "${NEAR_A_SVC}" "${NEAR_A_MS}" "${NEAR_A_IP}"
printf '    %-22s +%-4sms  ip=%s\n' "${NEAR_B_SVC}" "${NEAR_B_MS}" "${NEAR_B_IP}"
printf '    %-22s +%-4sms  ip=%s\n' "${FAR_SVC}"    "${FAR_MS}"    "${FAR_IP}"
if [ -n "${NEAR_A_IP}" ] && [ -n "${NEAR_B_IP}" ] && [ -n "${FAR_IP}" ]; then
  pass "all three replica IPs resolved"
else
  fail "could not resolve one or more replica IPs (cannot label stats)"
fi

step "1c. WAIT for twemproxy HEALTHY (<= ${HEALTH_WAIT_SECS}s)"
cid="$(dc ps -q twemproxy)"
healthy=0
if [ -n "${cid}" ]; then
  for _ in $(seq 1 "${HEALTH_WAIT_SECS}"); do
    state="$(docker inspect -f '{{.State.Health.Status}}' "${cid}" 2>/dev/null || echo unknown)"
    [ "${state}" = "healthy" ] && { healthy=1; break; }
    # If the container died (e.g. a crash on boot), stop waiting and surface it.
    run_state="$(docker inspect -f '{{.State.Status}}' "${cid}" 2>/dev/null || echo unknown)"
    [ "${run_state}" = "exited" ] && break
    sleep 1
  done
fi
if [ "${healthy}" -eq 1 ]; then
  pass "twemproxy reports HEALTHY"
else
  fail "twemproxy not HEALTHY within ${HEALTH_WAIT_SECS}s (state: ${state:-?}, run: ${run_state:-?})"
  echo "--- twemproxy logs (tail) ---"; dc logs --tail 80 twemproxy || true
fi

#--------------------------------------------------------------------------
# 2. Discovery: all 3 replicas seen
#--------------------------------------------------------------------------
step "2. DISCOVERY: read pool must discover all ${N_REPLICAS} replicas"
count=""
for _ in $(seq 1 "${DISCOVERY_WAIT_SECS}"); do
  count="$(discovered_count || true)"
  [ "${count:-0}" = "${N_REPLICAS}" ] && break
  sleep 1
done
if [ "${count:-0}" = "${N_REPLICAS}" ]; then
  pass "discovered all ${N_REPLICAS} replicas"
else
  fail "discovered ${count:-0} replicas, expected ${N_REPLICAS}"
fi

#--------------------------------------------------------------------------
# 3. Correctness: write via 6379, read back via 6378 (real replica data)
#--------------------------------------------------------------------------
step "3. CORRECTNESS: SET via write port, GET via read port"
KEY="lat:roundtrip:$$"; VAL="hello-$$"
set_reply="$(in_redis redis-cli -h twemproxy -p 6379 SET "${KEY}" "${VAL}" 2>/dev/null || true)"
got=""
for _ in $(seq 1 30); do
  got="$(in_redis redis-cli -h twemproxy -p 6378 GET "${KEY}" 2>/dev/null || true)"
  [ "${got}" = "${VAL}" ] && break
  sleep 1
done
echo "  SET(6379)='${set_reply}'  GET(6378)='${got}'"
if [ "${set_reply}" = "OK" ] && [ "${got}" = "${VAL}" ]; then
  pass "round-trip OK through the latency-shaped replica set"
else
  fail "round-trip mismatch (set='${set_reply}', got='${got}')"
fi

#--------------------------------------------------------------------------
# 4. Converge the latency band: warm every replica so its EWMA is measured,
#    then wait until band = {both nears in, far out}. This convergence IS the
#    core of GOAL 2's assertion, polled as a condition (not a fixed sleep).
#--------------------------------------------------------------------------
step "4. CONVERGE latency band (warm replicas, wait for nears-in / far-out)"
# A first read wave forces connections (hence connect-latency samples) across
# the discovered set. We send several short waves so the periodic-probe path
# also measures replicas that did not get an initial connection.
warm_wave() { in_redis redis-benchmark -h twemproxy -p 6378 -n 8000 -c 20 -t get -q >/dev/null 2>&1 || true; }
warm_wave

converged=0
for _ in $(seq 1 "${CONVERGE_WAIT_SECS}"); do
  ga="$(addr_field "${NEAR_A_IP}" in_good_set)"
  gb="$(addr_field "${NEAR_B_IP}" in_good_set)"
  gf="$(addr_field "${FAR_IP}" in_good_set)"
  if [ "${ga}" = "true" ] && [ "${gb}" = "true" ] && [ "${gf}" = "false" ]; then
    converged=1; break
  fi
  # nudge measurements along every few seconds
  case "$_" in *[05]) warm_wave;; esac
  sleep 1
done

echo "  band membership now: near-a=${ga:-?} near-b=${gb:-?} far=${gf:-?}"
echo "  --- full dynamic stats ---"
dyn_json | jq '{addresses, current_server_connections, max_server_connections,
                details: [.address_details[] | {ip, latency_us, eff_latency, weight, in_good_set, healthy, requests}]}' \
          | sed 's/^/    /' || true

#--------------------------------------------------------------------------
# 5. GOAL 2 assertions: latency-responsiveness (band + skew + far gets ~none)
#--------------------------------------------------------------------------
step "5. GOAL 2 - latency-responsiveness"
ea="$(addr_field "${NEAR_A_IP}" eff_latency)"; ea="${ea:-0}"
eb="$(addr_field "${NEAR_B_IP}" eff_latency)"; eb="${eb:-0}"
ef="$(addr_field "${FAR_IP}" eff_latency)";    ef="${ef:-0}"
ra="$(addr_field "${NEAR_A_IP}" requests)";    ra="${ra:-0}"
rb="$(addr_field "${NEAR_B_IP}" requests)";    rb="${rb:-0}"
rf="$(addr_field "${FAR_IP}" requests)";       rf="${rf:-0}"
printf '  eff_latency(us): near-a=%s near-b=%s far=%s\n' "${ea}" "${eb}" "${ef}"
printf '  requests:        near-a=%s near-b=%s far=%s\n' "${ra}" "${rb}" "${rf}"

if [ "${converged}" -eq 1 ]; then
  pass "band converged: both nears in_good_set, far excluded (in_good_set=false)"
else
  fail "band did not converge to {nears in, far out} within ${CONVERGE_WAIT_SECS}s (near-a=${ga:-?} near-b=${gb:-?} far=${gf:-?})"
fi

# eff_latency(far) must exceed both nears (the +200ms skew is visible). The far
# delay is far beyond the band, so even after EWMA noise it dominates.
if [ "${ef}" -gt "${ea}" ] && [ "${ef}" -gt "${eb}" ]; then
  pass "far replica has the highest effective latency (skew observed: far=${ef}us > near-a=${ea}us, near-b=${eb}us)"
else
  fail "far eff_latency (${ef}us) not greater than both nears (a=${ea}us, b=${eb}us)"
fi

# GROUND-TRUTH "far gets ~no traffic": while far is OUT of band, drive a fresh
# load wave and check that far accepts ~no NEW connections from the proxy, while
# the in-band nears do. This is stronger than the per-address `requests` counter
# (which aliases on current_addr_idx); a connection only lands on far if the
# weighted pick chose it, which it will not while far is out of band.
step "5a. GOAL 2 - far replica receives ~no new connections while out-of-band"
declare -A c0
for svc in "${ALL_SVCS[@]}"; do c0[$svc]="$(svc_total_conns "${svc}")"; done
echo "  driving a converged load wave (far is out of band)..."
for _ in 1 2 3; do
  in_redis redis-benchmark -h twemproxy -p 6378 -n 8000 -c 16 -t get -q >/dev/null 2>&1 || true
  sleep 2   # let connections recycle (lifetime 2s) so new picks happen
done
da=$(( $(svc_total_conns "${NEAR_A_SVC}") - c0[${NEAR_A_SVC}] ))
db=$(( $(svc_total_conns "${NEAR_B_SVC}") - c0[${NEAR_B_SVC}] ))
df=$(( $(svc_total_conns "${FAR_SVC}")    - c0[${FAR_SVC}] ))
printf '  new connections this wave: near-a=%s near-b=%s far=%s\n' "${da}" "${db}" "${df}"
near_conn_total=$((da + db))
# far should get a tiny fraction of the near connection total (a stray probe
# connection or two is tolerated; the nears must clearly dominate).
if [ "${near_conn_total}" -gt 0 ] && [ $((df * 5)) -lt "${near_conn_total}" ]; then
  pass "far got ~no new connections (far=${df} vs nears=${near_conn_total}) -- traffic shifted to the fast replicas"
elif [ "${df}" -le 2 ] && [ "${near_conn_total}" -ge 2 ]; then
  pass "far got ~no new connections (far=${df}, nears=${near_conn_total})"
else
  fail "far received non-trivial new connections (far=${df} vs nears=${near_conn_total})"
fi

# Corroborating signal from the stats `requests` counter (evidence, not a gate):
near_total=$((ra + rb))
echo "  (corroboration) per-address requests: near total=${near_total}, far=${rf}"

# Directional evidence only (NOT a gate): faster near should lean higher. The
# nears are close (+${NEAR_A_MS} vs +${NEAR_B_MS}ms), so the lean is small and
# noisy in docker -- see the header for why it is not hard-asserted.
step "5b. EVIDENCE (not asserted): near-a vs near-b lean"
printf '  near-a (+%sms) requests=%s conns=%s   near-b (+%sms) requests=%s conns=%s\n' \
       "${NEAR_A_MS}" "${ra}" "${da}" "${NEAR_B_MS}" "${rb}" "${db}"
if [ "${ra}" -gt "${rb}" ]; then
  echo "  -> directional: faster near-a received more requests than near-b (expected lean)."
elif [ "${ra}" -eq "${rb}" ]; then
  echo "  -> near-a == near-b (within docker timing noise / current_addr_idx aliasing)."
else
  echo "  -> near-b >= near-a this run (timing noise; the band gate above is the real signal)."
fi
echo "  backend connections accepted from proxy (connected now):"
for svc in "${ALL_SVCS[@]}"; do
  printf '      %-22s connected_clients=%s\n' "${svc}" "$(svc_connected_clients "${svc}")"
done

#--------------------------------------------------------------------------
# 6. GOAL 1 assertions: multi-replica spread (the core regression fix)
#--------------------------------------------------------------------------
step "6. GOAL 1 - multi-replica spread (vs the old 1-pinned replica)"
# Baseline cumulative connections, then a heavy wave, then the delta per replica:
# the proof that reads land on MULTIPLE replicas, not one pinned address.
declare -A base_conn
for svc in "${ALL_SVCS[@]}"; do base_conn[$svc]="$(svc_total_conns "${svc}")"; done

echo "  driving heavy read load (3 waves) to exercise connection spread..."
for _ in 1 2 3; do
  in_redis redis-benchmark -h twemproxy -p 6378 -n 20000 -c 40 -t get -q >/dev/null 2>&1 || true
done
sleep 3

cur_conns="$(dyn_json | jq -r '.current_server_connections // 0')"
echo "  current_server_connections = ${cur_conns} (max ${MAX_SERVER_CONNECTIONS:-8})"
replicas_with_conns=0
echo "  connection delta per replica over the load:"
for svc in "${ALL_SVCS[@]}"; do
  now="$(svc_total_conns "${svc}")"
  delta=$((now - ${base_conn[$svc]}))
  printf '      %-22s delta=%s\n' "${svc}" "${delta}"
  [ "${delta}" -gt 0 ] && replicas_with_conns=$((replicas_with_conns + 1))
done

if [ "${cur_conns:-0}" -ge 2 ]; then
  pass "pool holds >= 2 server connections (current_server_connections=${cur_conns}) -- NOT 1-pinned"
else
  fail "pool holds only ${cur_conns} connection(s) -- expected >= 2 (multi-replica spread broken)"
fi

# At least the two in-band nears should take connections under load. (The far
# one may legitimately take ~0 -- it is out of band.)
if [ "${replicas_with_conns}" -ge 2 ]; then
  pass "reads landed on >= 2 distinct replicas under load (spread confirmed)"
else
  fail "reads landed on only ${replicas_with_conns} replica(s) under load (still pinning)"
fi

#--------------------------------------------------------------------------
# 7. GOAL 3 assertions: failover re-weighting
#--------------------------------------------------------------------------
step "7. GOAL 3 - failover: kill a near replica, reads survive + pool re-converges"
echo "  killing ${NEAR_A_SVC} (the faster near) ..."
victim_cid="$(dc ps -q "${NEAR_A_SVC}" | head -1)"
if [ -z "${victim_cid}" ]; then
  fail "could not find ${NEAR_A_SVC} to kill"
else
  docker kill "${victim_cid}" >/dev/null

  # Reads must keep succeeding immediately (routed to survivors).
  read_ok=1
  for _ in $(seq 1 30); do
    if ! in_redis redis-cli -h twemproxy -p 6378 GET "${KEY}" >/dev/null 2>&1; then
      read_ok=0; break
    fi
  done
  if [ "${read_ok}" -eq 1 ]; then
    pass "reads kept succeeding right after the near replica was killed"
  else
    fail "a read failed after the near replica was killed (no failover)"
  fi

  # Keep load on so the pool re-measures + re-weights while the dead IP ages out.
  echo "  driving load while the dead replica ages out (expiration=1min)..."
  reconverged=0
  for s in $(seq 1 "${PRUNE_WAIT_SECS}"); do
    case "${s}" in *[05]) in_redis redis-benchmark -h twemproxy -p 6378 -n 6000 -c 20 -t get -q >/dev/null 2>&1 || true;; esac
    # Re-converged when the killed replica is gone from the discovered set OR
    # marked unhealthy/out-of-band, AND at least one in-band replica remains.
    av="$(addr_field "${NEAR_A_IP}" healthy)"   # "" once pruned, else true/false
    gb_now="$(addr_field "${NEAR_B_IP}" in_good_set)"
    gf_now="$(addr_field "${FAR_IP}" in_good_set)"
    killed_gone_or_down=0
    { [ -z "${av}" ] || [ "${av}" = "false" ]; } && killed_gone_or_down=1
    in_band_survivor=0
    { [ "${gb_now}" = "true" ] || [ "${gf_now}" = "true" ]; } && in_band_survivor=1
    if [ "${killed_gone_or_down}" -eq 1 ] && [ "${in_band_survivor}" -eq 1 ]; then
      reconverged=1; break
    fi
    sleep 1
  done

  echo "  --- post-failover dynamic stats ---"
  dyn_json | jq '{addresses, current_server_connections,
                  details: [.address_details[] | {ip, eff_latency, in_good_set, healthy, requests}]}' \
            | sed 's/^/    /' || true

  gb_now="$(addr_field "${NEAR_B_IP}" in_good_set)"
  gf_now="$(addr_field "${FAR_IP}" in_good_set)"
  if [ "${reconverged}" -eq 1 ]; then
    pass "pool re-converged after failover (killed replica down/ejected, an in-band survivor remains)"
  else
    fail "pool did not re-converge within ${PRUNE_WAIT_SECS}s after failover"
  fi
  # Evidence: did the far replica re-enter the band now that a near is gone?
  if [ "${gf_now}" = "true" ]; then
    echo "  -> EVIDENCE: the far replica RE-ENTERED the good band after the near died (re-weighting upward)."
  else
    echo "  -> EVIDENCE: surviving near-b (in_good_set=${gb_now:-?}) absorbed the load; far stayed out of band."
  fi
fi

#--------------------------------------------------------------------------
# Verdict
#--------------------------------------------------------------------------
step "RESULT"
if [ "${FAILURES}" -eq 0 ]; then
  echo "ALL ASSERTIONS PASSED."
  exit 0
else
  echo "${FAILURES} ASSERTION(S) FAILED."
  exit 1
fi
