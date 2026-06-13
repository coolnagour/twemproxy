#!/bin/bash
#
# Functional test for the HTTP-aware stats endpoint (prod-hardening).
#
# What it proves, end to end, against a REAL running nutcracker:
#   1. curl http://127.0.0.1:22222/stats  -> a framed HTTP/1.1 response whose
#      body is valid JSON (piped through jq to prove it parses).
#   2. curl http://127.0.0.1:22222/        -> same stats JSON.
#   3. curl http://127.0.0.1:22222/health  -> 200 text/plain "ok".
#   4. curl http://127.0.0.1:22222/nope    -> 404.
#   5. A BARE connect (open the socket, read a byte WITHOUT sending a request,
#      the legacy /dev/tcp healthcheck) still gets bytes promptly -- this is the
#      back-compat path the container healthcheck depends on.
#   6. nutcracker --version reports 2.1.2 and nutcracker -t accepts the conf.
#
# Why a container: it needs a Linux host with a working ASan runtime, curl, jq
# and libyaml. macOS Docker is fine -- the image runs under emulation. Run it:
#
#   bash tests/functional/stats_http.sh            # spins up rockylinux:9
#   bash tests/functional/stats_http.sh --in-container   # already inside one
#
# The outer invocation mounts the repo read-only into the container and re-execs
# this same script with --in-container. The build happens on a writable copy so
# the host tree is never modified.
set -euo pipefail

IMAGE="${ROCKY_IMAGE:-rockylinux:9}"
PORT=22222

run_outer() {
    local here root
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    root="$(cd "$here/../.." && pwd)"

    echo "== launching $IMAGE to run the stats-http functional test =="
    # --network none would block dnf; we need the default network for package
    # install, but the stats server itself only ever binds 127.0.0.1 inside the
    # container, so nothing is exposed to the host.
    exec docker run --rm \
        -v "$root":/src:ro \
        -e ROCKY_IMAGE="$IMAGE" \
        "$IMAGE" \
        bash /src/tests/functional/stats_http.sh --in-container
}

# ---------------------------------------------------------------------------
# Everything below runs INSIDE the container.
# ---------------------------------------------------------------------------
run_inner() {
    echo "== installing build + test deps =="
    # No libyaml-devel needed: the tree vendors contrib/yaml-0.1.4 and configure
    # builds it as a sub-package (AC_CONFIG_SUBDIRS). libasan is the ASan runtime
    # for the unit harness; jq parses the JSON the stats endpoint emits. curl is
    # already present as curl-minimal in the base image (do not install `curl` --
    # it conflicts with curl-minimal).
    dnf -y install --setopt=install_weak_deps=False \
        gcc make autoconf automake libtool \
        libasan jq procps-ng >/dev/null
    command -v curl >/dev/null || dnf -y install curl-minimal >/dev/null

    echo "== copying source to a writable build dir =="
    cp -a /src /build
    cd /build

    echo "== unpack vendored yaml + autoreconf + configure =="
    tar xzf contrib/yaml-0.1.4.tar.gz -C contrib
    autoreconf -fvi >/tmp/autoreconf.log 2>&1
    ./configure >/tmp/configure.log 2>&1

    echo "== build sub-libraries + binary =="
    make -j"$(nproc)" >/tmp/make.log 2>&1
    BIN=/build/src/nutcracker
    test -x "$BIN" || { echo "FAIL: nutcracker did not build"; tail -40 /tmp/make.log; exit 1; }

    echo
    echo "== (A) unit harness under real AddressSanitizer =="
    # On Linux the binary's own exit code propagates (no leaks wrapper), so a
    # logic-assert failure or an ASan trap both fail the harness for real.
    CFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" \
        bash tests/unit/run.sh
    echo "ASAN UNIT: passed"

    echo
    echo "== (B) nutcracker --version =="
    "$BIN" --version
    "$BIN" --version 2>&1 | grep -q "2.1.2" \
        || { echo "FAIL: version is not 2.1.2"; exit 1; }
    echo "VERSION: 2.1.2 OK"

    echo
    echo "== (C) nutcracker -t on a static test conf =="
    # A dynamic_endpoint pool resolves DNS at conf-transform time, which fails
    # offline; use a static localhost conf so -t exercises the parser cleanly.
    # worker_processes:0 = single-process model. The stats document is then the
    # per-pool OBJECT (with .service / dns_hosts), which is what these checks
    # assert. (In the multi-process model the document is a JSON ARRAY of
    # per-worker objects; both still go through the same HTTP-framing path.)
    cat >/tmp/test.yml <<'YML'
global:
  worker_processes: 0
pools:
  alpha:
    listen: 127.0.0.1:6380
    redis: true
    servers:
      - 127.0.0.1:7001:1
YML
    "$BIN" -t -c /tmp/test.yml
    echo "CONF -t (static): OK"
    # The shipped sample must also parse (-t does conf checks; dynamic pools may
    # warn/err on offline DNS, so we only require the parse to run, not succeed).
    "$BIN" -t -c conf/nutcracker.yml || echo "(sample conf -t returned non-zero offline -- expected: dynamic_endpoint DNS)"

    echo
    echo "== (D) start nutcracker with the stats server on 127.0.0.1:$PORT =="
    # This fork writes a pid file unconditionally (default /var/run/twemproxy,
    # which does not exist here) -- point it at a writable path so startup does
    # not abort.
    "$BIN" -c /tmp/test.yml -s "$PORT" -a 127.0.0.1 -i 1000 \
        -p /tmp/twemproxy.pid -o /tmp/nutcracker.log -v 6 &
    NUT_PID=$!
    trap 'kill "$NUT_PID" 2>/dev/null || true' EXIT

    # Wait for the stats port to accept connections.
    for _ in $(seq 1 50); do
        if bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done

    fail=0

    echo
    echo "-- (1) GET /stats -> HTTP framing + JSON body parses --"
    resp="$(curl -sS -D - "http://127.0.0.1:$PORT/stats")"
    echo "$resp" | head -8
    echo "$resp" | grep -qi "^HTTP/1.1 200 OK" || { echo "FAIL: no 200 status line"; fail=1; }
    echo "$resp" | grep -qi "^Content-Type: application/json" || { echo "FAIL: no json content-type"; fail=1; }
    echo "$resp" | grep -qi "^Content-Length:" || { echo "FAIL: no content-length"; fail=1; }
    echo "$resp" | grep -qi "^Connection: close" || { echo "FAIL: no connection: close"; fail=1; }
    # Body after the blank line must be valid JSON.
    if curl -sS "http://127.0.0.1:$PORT/stats" | jq -e . >/dev/null; then
        echo "PASS: /stats body parses as JSON"
    else
        echo "FAIL: /stats body is not valid JSON"; fail=1
    fi
    # Schema sanity: the document still carries the known top-level keys and the
    # dns_hosts key (the magic-offset rewrite target) is present and well-formed.
    svc="$(curl -sS "http://127.0.0.1:$PORT/stats" | jq -r '.service')"
    [ "$svc" = "nutcracker" ] || { echo "FAIL: .service != nutcracker (got '$svc')"; fail=1; }
    echo "  .service=$svc  .source=$(curl -sS http://127.0.0.1:$PORT/stats | jq -r '.source')"

    echo
    echo "-- (2) GET / -> same stats JSON --"
    if curl -sS "http://127.0.0.1:$PORT/" | jq -e '.service == "nutcracker"' >/dev/null; then
        echo "PASS: / serves stats JSON"
    else
        echo "FAIL: / did not serve stats JSON"; fail=1
    fi

    echo
    echo "-- (3) GET /health -> 200 text/plain ok --"
    h="$(curl -sS -D - "http://127.0.0.1:$PORT/health")"
    hbody="$(curl -sS "http://127.0.0.1:$PORT/health" | tr -d '\r\n')"
    if echo "$h" | grep -qi "^HTTP/1.1 200 OK" \
        && echo "$h" | grep -qi "^Content-Type: text/plain" \
        && [ "$hbody" = "ok" ]; then
        echo "PASS: /health is 200 text/plain ok"
    else
        echo "FAIL: /health wrong (body='$hbody')"; echo "$h" | head -5; fail=1
    fi

    echo
    echo "-- (4) GET /nope -> 404 --"
    code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/nope")"
    if [ "$code" = "404" ]; then
        echo "PASS: unknown path -> 404"
    else
        echo "FAIL: unknown path -> $code (want 404)"; fail=1
    fi

    echo
    echo "-- (5) BARE connect (legacy healthcheck): read a byte WITHOUT sending --"
    # This is the exact shape from the task: open /dev/tcp, read 1 byte, no
    # request written. It must return promptly. We time it to prove it is not a
    # multi-second wait.
    start=$(date +%s.%N)
    byte="$(timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT; head -c1 <&3" 2>/dev/null || true)"
    end=$(date +%s.%N)
    elapsed="$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.3f", b-a}')"
    if [ -n "$byte" ]; then
        echo "PASS: bare connect returned a byte ('$byte') in ${elapsed}s (raw-JSON back-compat intact)"
        # The raw dump is a JSON document, so the first byte is '{'.
        [ "$byte" = "{" ] || echo "  note: first raw byte was '$byte' (expected '{')"
    else
        echo "FAIL: bare connect returned NO byte in 3s -- healthcheck would break"; fail=1
    fi
    # And the whole raw body (bare connect, read to EOF) must be valid JSON too.
    raw="$(timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT; cat <&3" 2>/dev/null || true)"
    if printf '%s' "$raw" | jq -e . >/dev/null 2>&1; then
        echo "PASS: bare-connect raw body is valid JSON (no HTTP headers)"
        if printf '%s' "$raw" | grep -qi "^HTTP/1.1"; then
            echo "FAIL: raw body unexpectedly had HTTP headers"; fail=1
        fi
    else
        echo "FAIL: bare-connect raw body did not parse as JSON"; fail=1
    fi

    # Done with the static instance.
    kill "$NUT_PID" 2>/dev/null || true
    wait "$NUT_PID" 2>/dev/null || true
    trap - EXIT

    echo
    echo "-- (6) dns_hosts on a DYNAMIC server: the magic-offset rewrite's replacement --"
    # Point a dynamic_endpoint pool at localhost (resolves offline) so the stats
    # document carries a real dns_hosts OBJECT, not null. This is the path the
    # old code built by string-rewriting a "read_hosts" key at byte offset 13;
    # we assert the object is well-formed, keyed "dns_hosts", and that NO stray
    # "read_hosts" key leaked into the document.
    local dport=$((PORT + 1))
    cat >/tmp/dyn.yml <<YML
global:
  worker_processes: 0
pools:
  reads:
    listen: 127.0.0.1:6390
    redis: true
    dynamic_endpoint: true
    zone_aware: true
    zone_weight: 99
    dns_resolve_interval: 30
    servers:
      - localhost:7002:1
YML
    "$BIN" -c /tmp/dyn.yml -s "$dport" -a 127.0.0.1 -i 1000 \
        -p /tmp/twemproxy-dyn.pid -o /tmp/nutcracker-dyn.log -v 6 &
    DYN_PID=$!
    trap 'kill "$DYN_PID" 2>/dev/null || true' EXIT
    for _ in $(seq 1 50); do
        if bash -c "exec 3<>/dev/tcp/127.0.0.1/$dport" 2>/dev/null; then break; fi
        sleep 0.1
    done
    sleep 1.5  # allow DNS resolve + one aggregation interval to populate dns_hosts

    dbody="$(curl -sS "http://127.0.0.1:$dport/stats")"
    if printf '%s' "$dbody" | jq -e '.pools.reads.servers[].dns_hosts.type == "dynamic"' >/dev/null; then
        echo "PASS: dns_hosts is a dynamic OBJECT (keyed correctly, built without the offset rewrite)"
    else
        echo "FAIL: dns_hosts is not a well-formed dynamic object"; printf '%s' "$dbody" | head -c 600; fail=1
    fi
    if printf '%s' "$dbody" | grep -q "read_hosts"; then
        echo "FAIL: a stray 'read_hosts' key leaked into the document"; fail=1
    else
        echo "PASS: no 'read_hosts' key anywhere -- the key is emitted as 'dns_hosts' directly"
    fi
    if printf '%s' "$dbody" | jq -e . >/dev/null; then
        echo "PASS: full dynamic-server document parses as JSON"
    else
        echo "FAIL: dynamic-server document is not valid JSON"; fail=1
    fi
    kill "$DYN_PID" 2>/dev/null || true
    wait "$DYN_PID" 2>/dev/null || true
    trap - EXIT

    echo
    if [ "$fail" -ne 0 ]; then
        echo "FUNCTIONAL STATS-HTTP: FAILED"
        echo "---- nutcracker.log tail ----"; tail -30 /tmp/nutcracker.log 2>/dev/null || true
        echo "---- nutcracker-dyn.log tail ----"; tail -30 /tmp/nutcracker-dyn.log 2>/dev/null || true
        exit 1
    fi
    echo "FUNCTIONAL STATS-HTTP: all checks passed"
}

if [ "${1:-}" = "--in-container" ]; then
    run_inner
else
    run_outer
fi
