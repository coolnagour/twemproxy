#!/bin/bash
#
# Build and run the standalone server_dns unit tests.
#
# Why this is not just `make check`: twemproxy ships no C unit-test framework
# (tests/ is Python integration needing a live redis), and on macOS the source
# tree does not compile under the project's strict flags because nc_server.c
# uses inet_ntop() without including <arpa/inet.h> (it resolves transitively on
# Linux via -D_GNU_SOURCE). This script compiles every src/*.c (except nc.c,
# which owns main()) with a local -include arpa/inet.h workaround and links them
# with the prebuilt sub-library archives, so each test drives the REAL
# nc_server.c code and the real struct string handling.
#
# Tests run here (all on the array-of-structs server_dns layout):
#   test_remove_address  -- server_dns_remove_address_at() single struct shift:
#                           survivors keep their fields + current_addr_idx fixup.
#   test_address_cap     -- the accumulate-append cap at max_addresses. Built
#                           TWICE:
#                             * default (cap present)  -> must exit 0 (clean).
#                             * -DTEST_NO_CAP          -> reproduces the pre-cap
#                               bug (naddresses>16); must exit non-zero. This is
#                               the TDD red->green evidence for the cap.
#                           (Before the struct-of-arrays -> array-of-structs
#                           refactor this also guarded a heap OOB write into the
#                           fixed-size lazy arrays; with one realloc-grown array
#                           that OOB class is structurally gone, so the FORCE-OOB
#                           heap-guard demo build was dropped.)
#
# Memory safety: ASan is the preferred checker (see the AddressSanitizer build
# in the task brief). Where the ASan runtime refuses to initialise (some macOS
# toolchains abort in sanitizer_malloc_mac.inc), this script falls back to the
# macOS `leaks` tool, which flags leaks and aborts on double-free, OR to
# libgmalloc when LIBGMALLOC=1 is set (DYLD_INSERT_LIBRARIES=libgmalloc.dylib
# traps heap OOB read/write/double-free). On Linux, build with
# CFLAGS/LDFLAGS=-fsanitize=address and run the binaries directly under ASan.
#
# Usage:
#   bash tests/unit/run.sh                 # plain / leaks (whichever is present)
#   LIBGMALLOC=1 bash tests/unit/run.sh    # heap-OOB guard run (macOS)
#   CFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" bash tests/unit/run.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="${TMPDIR:-/tmp}/twemproxy-unit"
mkdir -p "$out"

cc="${CC:-cc}"

# Does the linker support GNU ld's --wrap? (GNU ld / lld: yes; Apple ld: no.)
# One test below (test_dns_resolve_integration) intercepts getaddrinfo via
# --wrap, so it can only build where --wrap is available. Probe by actually
# linking a tiny program that wraps a symbol -- more reliable than sniffing
# `uname`, since a Linux box could in principle use a non-GNU linker and macOS
# could (rarely) have an lld in front. Result -> wrap_supported=yes|no.
wrap_supported=no
{
    _wrap_probe_dir="$(mktemp -d "${out:-${TMPDIR:-/tmp}}/wrapprobe.XXXXXX")"
    printf 'int __wrap_probe_fn(void){return 0;}\nint probe_fn(void);\nint main(void){return probe_fn();}\n' \
        > "$_wrap_probe_dir/p.c"
    if "$cc" -Wl,--wrap=probe_fn "$_wrap_probe_dir/p.c" -o "$_wrap_probe_dir/p" >/dev/null 2>&1; then
        wrap_supported=yes
    fi
    rm -rf "$_wrap_probe_dir"
} || true

# config.h carries the HAVE_KQUEUE/HAVE_EPOLL event-mechanism define that
# nc_core.h requires; run ./configure first if it is missing.
if [ ! -f "$root/config.h" ]; then
    echo "config.h missing -- run ./configure in $root first" >&2
    exit 2
fi

incs=(-I "$root" -I "$root/src" -I "$root/src/hashkit" -I "$root/src/proto" \
      -I "$root/src/event" -I "$root/contrib/yaml-0.1.4/include")

# -include arpa/inet.h is the macOS portability shim described above; harmless
# on Linux. -Wno-implicit-function-declaration keeps that shim from being fatal
# on toolchains that still miss a prototype.
cflags=(-g -O0 -D_GNU_SOURCE -DHAVE_CONFIG_H -include arpa/inet.h \
        -Wno-implicit-function-declaration -fno-strict-aliasing)

# Allow an ASan build on platforms where the runtime works:
#   CFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" bash tests/unit/run.sh
# Word-splitting into array elements is intentional (each flag is one arg).
read -ra extra_cflags <<< "${CFLAGS:-}"
read -ra extra_ldflags <<< "${LDFLAGS:-}"

# Compile every production object once (shared by all test binaries). nc.c owns
# main() so it is excluded from the link.
objs=()
for src in "$root"/src/*.c; do
    base="$(basename "$src" .c)"
    [ "$base" = "nc" ] && continue
    obj="$out/$base.o"
    "$cc" -c "${cflags[@]}" "${extra_cflags[@]}" "${incs[@]}" "$src" -o "$obj"
    objs+=("$obj")
done

archives=(
    "$root/src/hashkit/libhashkit.a"
    "$root/src/proto/libproto.a"
    "$root/src/event/libevent.a"
    "$root/contrib/yaml-0.1.4/src/.libs/libyaml.a"
)
for a in "${archives[@]}"; do
    if [ ! -f "$a" ]; then
        echo "missing archive $a -- run 'make' (sub-libraries) in $root first" >&2
        exit 2
    fi
done

# build_test <binary-name> <test-source> [extra-cflags...] [WRAP_LDFLAGS <ldflags...>]
# Compiles the test source against the shared production objects + archives.
# Any args BEFORE a literal WRAP_LDFLAGS token are extra COMPILE flags (e.g.
# -DTEST_FOO); any args AFTER it are extra LINK flags (e.g. -Wl,--wrap=...).
# The token is optional -- existing callers pass only compile flags.
build_test() {
    local name="$1" tsrc="$2"; shift 2
    local tobj="$out/$name.o" bin="$out/$name"
    local cextra=() lextra=() seen_sep=0 arg
    for arg in "$@"; do
        if [ "$arg" = "WRAP_LDFLAGS" ]; then seen_sep=1; continue; fi
        if [ "$seen_sep" -eq 0 ]; then cextra+=("$arg"); else lextra+=("$arg"); fi
    done
    "$cc" -c "${cflags[@]}" "${extra_cflags[@]}" "${cextra[@]}" "${incs[@]}" \
        "$tsrc" -o "$tobj"
    "$cc" -g -O0 "${extra_ldflags[@]}" "${lextra[@]}" \
        "$tobj" "${objs[@]}" "${archives[@]}" \
        -lm -lpthread -o "$bin"
    echo "built $bin" >&2     # progress to stderr; stdout carries only the path
    printf '%s' "$bin"
}

# run_test <binary> <expected-rc> <label>
# Runs the binary under the best available memory checker and asserts the exit
# code matches <expected-rc> (lets us treat the -DTEST_NO_CAP "bug reproduces"
# build's non-zero exit as a PASS for the harness).
run_test() {
    local bin="$1" expect="$2" label="$3" rc=0

    echo "=== $label ==="
    if [ -n "${LDFLAGS:-}" ] && printf '%s' "${LDFLAGS}" | grep -q 'fsanitize=address'; then
        echo "running under AddressSanitizer"
        "$bin" || rc=$?
    elif [ "${LIBGMALLOC:-0}" = "1" ] && [ -f /usr/lib/libgmalloc.dylib ]; then
        echo "running under libgmalloc (heap OOB guard)"
        # MALLOC_PROTECT_BEFORE traps OOB *under*-reads/writes too; combined
        # with the default trailing guard page this catches writes on either
        # side of an allocation.
        DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib \
            MALLOC_PROTECT_BEFORE=1 MALLOC_FILL_SPACE=1 \
            "$bin" || rc=$?
    elif command -v valgrind >/dev/null 2>&1; then
        echo "running under valgrind"
        valgrind --error-exitcode=99 --leak-check=full "$bin" || rc=$?
    elif command -v leaks >/dev/null 2>&1; then
        # `leaks --atExit -- BIN` reports leaks via ITS OWN exit code and
        # DISCARDS the wrapped binary's exit code -- so a failed assertion in a
        # no-leak test (e.g. the pure picker/good-band tests) would be masked as
        # rc=0. Run the binary DIRECTLY to capture its real exit code, THEN run
        # leaks purely for leak detection; a leak escalates an otherwise-clean
        # run to a non-zero rc.
        echo "running under macOS leaks (direct rc + leak scan)"
        "$bin" || rc=$?
        local leak_rc=0
        MallocStackLogging=1 leaks --atExit -- "$bin" >/dev/null 2>&1 || leak_rc=$?
        if [ "$rc" -eq 0 ] && [ "$leak_rc" -ne 0 ]; then
            echo "leaks reported a leak (leaks rc=$leak_rc) on an otherwise-clean run" >&2
            rc=$leak_rc
        fi
    else
        echo "running plain (no memory checker available)"
        "$bin" || rc=$?
    fi

    if [ "$rc" -ne "$expect" ]; then
        echo "RESULT: $label -> rc=$rc, expected $expect -- FAIL" >&2
        return 1
    fi
    echo "RESULT: $label -> rc=$rc (expected $expect) -- PASS"
    return 0
}

# run_nonzero <binary> <label>
# Runs a build that MUST report a problem (non-zero exit). Used for the no-cap
# "bug reproduces" build: it returns 1 from main() on a plain build, and under
# libgmalloc/ASan it may instead die from a heap-guard signal (rc>128). Any
# non-zero is the expected red; only exit 0 is a FAIL.
run_nonzero() {
    local bin="$1" label="$2" rc=0

    echo "=== $label ==="
    if [ "${LIBGMALLOC:-0}" = "1" ] && [ -f /usr/lib/libgmalloc.dylib ]; then
        echo "running under libgmalloc (heap OOB guard)"
        DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib MALLOC_PROTECT_BEFORE=1 \
            "$bin" || rc=$?
    elif [ -n "${LDFLAGS:-}" ] && printf '%s' "${LDFLAGS}" | grep -q 'fsanitize=address'; then
        echo "running under AddressSanitizer"
        "$bin" || rc=$?
    else
        "$bin" || rc=$?
    fi

    if [ "$rc" -eq 0 ]; then
        echo "RESULT: $label -> exited 0, the bug did NOT reproduce -- FAIL" >&2
        return 1
    fi
    echo "RESULT: $label -> rc=$rc (non-zero) -- PASS (bug reproduced pre-fix)"
    return 0
}

# run_leaks_must_leak <binary> <label>
# For a build that should LEAK (the new_hostnames omit-the-free red). A leak is
# only visible to the macOS `leaks` tool -- libgmalloc/ASan trap OOB & double-
# free, not plain leaks, and a no-checker run cannot see a leak at all. So this
# runner ALWAYS runs the binary directly under `leaks --atExit` (independent of
# the LIBGMALLOC/LDFLAGS mode selected for the other tests) and PASSES only when
# `leaks` reports a leak (non-zero exit). If `leaks` is unavailable (non-macOS),
# it SKIPS -- on Linux the same red is shown by ASan's LeakSanitizer instead.
run_leaks_must_leak() {
    local bin="$1" label="$2" rc=0

    echo "=== $label ==="
    if ! command -v leaks >/dev/null 2>&1; then
        echo "RESULT: $label -> SKIPPED (no macOS \`leaks\`; on Linux use ASan/LSan)"
        return 0
    fi
    echo "running under macOS leaks (--atExit); a leak is the EXPECTED red"
    MallocStackLogging=1 leaks --atExit -- "$bin" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "RESULT: $label -> leaks found NONE, the leak did NOT reproduce -- FAIL" >&2
        return 1
    fi
    echo "RESULT: $label -> leaks reported a leak (rc=$rc) -- PASS (leak reproduced pre-fix)"
    return 0
}

# --- remove: single struct shift -------------------------------------------
bin_remove="$(build_test test_remove_address "$here/test_remove_address.c")"

# --- accumulate cap --------------------------------------------------------
# Two builds from one source via compile flags:
#   capped : mirrors the FIXED nc_server.c  -> must exit 0 (clean).
#   nocap  : mirrors the PRE-cap nc_server.c -> must exit non-zero (the cap is
#            gone; naddresses runs past 16, violating the invariant). This is
#            the TDD red. (The old OOB-into-fixed-lazy-array hazard is gone with
#            the single realloc-grown array, so there is no FORCE-OOB build.)
bin_cap="$(build_test test_address_cap "$here/test_address_cap.c")"
bin_nocap="$(build_test test_address_cap_nocap "$here/test_address_cap.c" -DTEST_NO_CAP)"

# --- single-realloc grow safety in the accumulate-append --------------------
# Two builds from one source. The nc_realloc failure-injection shim is wired in
# WITHIN the source (an #undef/#define after the headers -- a command-line
# -Dnc_realloc gets clobbered by nc_util.h's own macro), so no extra flag here:
#   fixed : mirrors the FIXED write-back (realloc into a temp, write back to
#           dns->addrs only on success) -> a forced realloc failure leaves
#           dns->addrs intact and does not bump naddresses -> exit 0, clean
#           under libgmalloc + leaks.
#   buggy : -DTEST_REALLOC_BUGGY mirrors the footgun write-back (assign the
#           realloc result straight back to dns->addrs, check after) -> the same
#           forced failure clobbers dns->addrs with NULL and leaks the original
#           block. Must exit non-zero; under libgmalloc the NULL deref traps,
#           under leaks the orphan is reported. This is the TDD red.
bin_realloc="$(build_test test_realloc_safety "$here/test_realloc_safety.c")"
bin_realloc_buggy="$(build_test test_realloc_safety_buggy "$here/test_realloc_safety.c" \
                  -DTEST_REALLOC_BUGGY)"
# Error-path leak fix: free new_hostnames (+ element strings) on the accumulate
# nomem path. The FIXED build is the default test_realloc_safety above (its
# nomem branch frees the temp hostname array exactly like the success tail), so
# the run_test under `leaks` already asserts GREEN (0 leaks) for this fix.
#   omit : -DTEST_OMIT_HOSTNAMES_FREE drops that free -> the nomem path orphans
#          the temp hostname array + its element strings (no other owner) ->
#          `leaks` reports them. This is the TDD red. A leak is only observable
#          under `leaks` (libgmalloc/ASan trap OOB/double-free, not leaks; a
#          plain run sees nothing), so the red assertion below is leaks-gated.
bin_realloc_omit_hn="$(build_test test_realloc_safety_omit_hostnames \
                  "$here/test_realloc_safety.c" -DTEST_OMIT_HOSTNAMES_FREE)"

# --- fix #1: connection-max-lifetime quiescence guard ----------------------
# Two builds from one source:
#   fixed : drives the REAL core_conn_lifetime_should_recycle() from nc_core.c
#           (which calls the REAL server_active()) -> an expired-but-BUSY conn
#           is NOT recycled, an expired-and-quiescent conn IS -> exit 0.
#   prefix: -DTEST_PREFIX_NO_QUIESCENCE_GUARD swaps in a faithful mirror of the
#           PRE-fix decision (expiry only, no quiescence check) -> the
#           expired-BUSY conn is (wrongly) recycled, so the "kept" assertion
#           fails -> non-zero exit. This is the TDD red.
bin_lifetime="$(build_test test_lifetime_quiescent "$here/test_lifetime_quiescent.c")"
bin_lifetime_prefix="$(build_test test_lifetime_quiescent_prefix \
                  "$here/test_lifetime_quiescent.c" -DTEST_PREFIX_NO_QUIESCENCE_GUARD)"

# --- fix #5: explicit dynamic_endpoint flag (drop -ro hostname auto-detect) -
# Two builds from one source:
#   fixed : drives the REAL conf_pool_servers_are_dynamic() from nc_conf.c --
#           is_dynamic is decided solely by the explicit dynamic_endpoint flag,
#           never the hostname -> a -ro host WITHOUT the flag stays static
#           (anti-footgun) -> exit 0.
#   prefix: -DTEST_PREFIX_RO_AUTODETECT swaps in a faithful mirror of the
#           PRE-fix decision (is_dynamic inferred from a "-ro" substring in the
#           hostname, flag ignored) -> the -ro-host-without-flag case is
#           (wrongly) reported dynamic, so the anti-footgun assertion fails ->
#           non-zero exit. This is the TDD red.
bin_dynep="$(build_test test_dynamic_endpoint "$here/test_dynamic_endpoint.c")"
bin_dynep_prefix="$(build_test test_dynamic_endpoint_prefix \
                  "$here/test_dynamic_endpoint.c" -DTEST_PREFIX_RO_AUTODETECT)"

# NOTE: the "fix #N" labels ABOVE refer to the earlier hardening campaign. The
# two tests BELOW cover the prod-hardening round (this file's bug numbers), kept
# named "prod-hardening #1/#2" so they do not collide with the labels above.

# --- prod-hardening #1: failed-first-resolve leaves a clean, freeable dns ----
# Drives the REAL server_dns_init() + REAL server_dns_deinit() on a failed-first-
# resolve (hostname starts with '/', so the resolver fails offline with zero
# allocation). Two builds from one source:
#   fixed : real init (nc_zalloc) leaves the single owned pointer dns->addrs NULL
#           after the failed resolve -> deinit frees nothing wild -> exit 0,
#           clean under ASan / libgmalloc / leaks.
#   prefix: -DTEST_PREFIX_NO_NULL_INIT mirrors a PRE-fix-style init (nc_alloc,
#           struct pre-filled with 0xAB garbage, the addrs = NULL init omitted)
#           then calls the REAL deinit -> deinit nc_free()s a garbage pointer ->
#           wild free. Asserts addrs is garbage (plain build fails) and the wild
#           free traps under ASan/libgmalloc. This is the TDD red.
bin_dnsinit="$(build_test test_dns_init_deinit "$here/test_dns_init_deinit.c")"
bin_dnsinit_prefix="$(build_test test_dns_init_deinit_prefix \
                  "$here/test_dns_init_deinit.c" -DTEST_PREFIX_NO_NULL_INIT)"

# --- prod-hardening #2: first-resolution OOM leaves an inconsistent dns ------
# Mirrors the first-resolution publish-count + single dns_addr-array alloc +
# alloc-failure cleanup of server_dns_resolve() against a REAL struct server_dns,
# with an nc_alloc failure-injection shim. Two builds from one source:
#   fixed : the cleanup reverts the count -> empty, self-consistent dns
#           (naddresses==0, addrs==NULL); a simulated next access is a guarded
#           no-op -> exit 0, clean under ASan / libgmalloc / leaks.
#   prefix: -DTEST_PREFIX_NO_REVERT mirrors the PRE-fix cleanup (count left
#           published while addrs is NULL) -> inconsistent dns; asserts fire
#           (plain build fails) and indexing addrs NULL-derefs (ASan/libgmalloc
#           trap). This is the TDD red.
bin_dnsoom="$(build_test test_dns_resolve_oom "$here/test_dns_resolve_oom.c")"
bin_dnsoom_prefix="$(build_test test_dns_resolve_oom_prefix \
                  "$here/test_dns_resolve_oom.c" -DTEST_PREFIX_NO_REVERT)"

# --- prod-hardening #3: HTTP-aware stats endpoint ---------------------------
# Drives the REAL stats_request_classify() + stats_http_format_header() from
# nc_stats.c -- the pure request-classification and response-header helpers the
# HTTP-aware stats server uses. Proves: a bare connect classifies RAW (the
# legacy /dev/tcp healthcheck keeps getting raw JSON), GET //GET /stats serve
# the JSON, GET /health is the health probe, HEAD /stats is headers-only, an
# unknown path is 404, a known method with a malformed line is 400, and the
# header formatter emits a well-formed HTTP/1.1 status line + required headers
# (and reports overflow). The socket round-trip itself is covered by the
# functional curl test (task verification), not here. Single fixed build only:
# this is straight-line logic, no pre-fix red variant to stage.
bin_statshttp="$(build_test test_stats_http "$here/test_stats_http.c")"

# --- prod-hardening #4: real DNS-resolve pipeline integration (Linux only) ---
# Drives the REAL server_dns_resolve() across multiple cycles by intercepting
# getaddrinfo()/freeaddrinfo() (and nc_usec_now() for a deterministic clock)
# with GNU ld's --wrap. This exercises the real accumulate/expire/remove merge
# over a real struct server_dns -- the code path the round-2 memory-safety bugs
# lived in -- not a mirror. --wrap is GNU ld only, so this test only BUILDS
# where the linker supports it; on macOS (Apple ld) it is cleanly SKIPPED. When
# built, it is run like the others (expected rc 0).
bin_dnsintegration=""
if [ "$wrap_supported" = "yes" ]; then
    bin_dnsintegration="$(build_test test_dns_resolve_integration \
        "$here/test_dns_resolve_integration.c" \
        WRAP_LDFLAGS \
        -Wl,--wrap=getaddrinfo -Wl,--wrap=freeaddrinfo -Wl,--wrap=nc_usec_now)"
fi

# --- latency-weighted reads #1: pure weighted picker -----------------------
# Drives the REAL server_weighted_pick() from nc_server.c -- a pure, allocation-
# free, integer-only latency-weighted selector. No DNS/network dependency, so no
# pre-fix mirror variant: this is straight-line probabilistic logic. The test
# seeds srandom(1) itself for reproducible draw counts and asserts the share
# split matches inverse-eff-latency weights, a single replica is always chosen,
# and a far/slow replica keeps a tiny nonzero share. Single fixed build.
bin_weightedpick="$(build_test test_weighted_pick "$here/test_weighted_pick.c")"

# --- latency-weighted reads #2: effective-latency + good-latency band -------
# Drives the REAL server_addr_eff_latency() + server_build_good_set() from
# nc_server.c against a hand-built struct server_dns (no network). Asserts the
# cross-AZ surcharge shifts effective latency, the good set keeps replicas within
# band_factor*min and drops the far one, the output is sorted ascending by
# effective latency, and the max_count cap keeps the lowest-eff members. Both
# helpers are allocation-free (caller buffers) so the leaks run finds nothing.
# Single fixed build.
bin_goodband="$(build_test test_good_band "$here/test_good_band.c")"

# --- latency-weighted reads #3: unified selection in server_select_best_address
# Drives the REAL server_select_best_address() end to end against a hand-built
# server+pool+dns (4 replicas: two same-AZ 100/110us, one cross-AZ 120us, one far
# 5000us). Proves the Task-3 tail (good-latency band -> weighted pick) chooses the
# in-band replicas inverse-latency-weighted, NEVER the far one, tracks the
# same/cross zone counters, and degenerates to a single healthy replica. The
# untested/probe paths are neutralised via the dns fields (see the test header);
# the residual ~5% random-probe is pinned off the far replica via current_addr_idx.
# Single build: this is the REAL integration path, RED on the pre-Task-3 discrete
# tail (far drew traffic, distribution was uniform-ish) and GREEN after the
# rewrite. It allocates (healthy/zone arrays + the hand-built stats graph), so the
# leaks run guards every path frees.
bin_selectweighted="$(build_test test_select_weighted "$here/test_select_weighted.c")"

# --- latency-weighted reads #4: multi-connection count wiring ---------------
# Drives the REAL server_good_set_size() + server_update_dynamic_connections()
# from nc_server.c against a hand-built server+pool+dns. Proves the Task-4
# connection-count DECISION: a dynamic_endpoint server's target count is the
# good-latency-band size (min(|good_set|, max_server_connections)), NOT raw
# naddresses (a far/out-of-band replica does not inflate it); the max cap holds;
# a surcharge that pushes a cross-AZ replica out of band shrinks the count; a
# fully-degraded fleet floors at >=1 instead of collapsing to 0; and the STATIC
# path is untouched (cap stays server_connections=1, the update is a no-op). The
# count helpers never call stats_* (unlike server_select_best_address), so the
# test runs with a NULL ctx. Both helpers are allocation-free (caller stack
# buffers), so the leaks run finds nothing. Single fixed build: the pre-Task-4
# tree does not even LINK this (server_good_set_size did not exist) -- the
# strongest red -- and the far-does-not-inflate assert additionally fails the
# old min(naddresses,max) target.
bin_dynconncount="$(build_test test_dynamic_conn_count "$here/test_dynamic_conn_count.c")"

# --- latency-weighted reads #5: config knobs + zone_weight deprecation -------
# Drives the REAL conf parse pipeline (conf_create -> conf_pool_each_transform
# via server_pool_init) against temp YAML files. Proves cross_az_surcharge_us +
# latency_band_factor parse onto the server_pool, omitted keys take the
# CONF_DEFAULT_*, latency_band_factor:0 passes through (keep-all), a pool that
# sets zone_weight emits a deprecation warning during validation (captured by
# redirecting stderr), and a clean config emits none. All pools are
# dynamic_endpoint:false so the transform stays offline (no DNS). It allocates
# (the parsed conf graph + the transformed server_pool), so the leaks run guards
# every path frees. Two builds from one source:
#   fixed : the REAL nc_conf.c -> knobs parse + the deprecation warning fires.
#   prefix: -DTEST_PREFIX_NO_PARSE mirrors the PRE-Task-5 world (the transform
#           hardcodes CONF_DEFAULT_* regardless of config, and no deprecation
#           warning exists) -> the configured-non-default assertion AND the
#           warning-emitted assertion both fail -> non-zero exit. The TDD red.
bin_confknobs="$(build_test test_conf_latency_knobs "$here/test_conf_latency_knobs.c")"
bin_confknobs_prefix="$(build_test test_conf_latency_knobs_prefix \
                  "$here/test_conf_latency_knobs.c" -DTEST_PREFIX_NO_PARSE)"

# --- latency-weighted reads #6: per-replica stats observability -------------
# Drives the REAL server_get_read_hosts_info() (the per-server address_details[]
# JSON the HTTP stats endpoint embeds) against a hand-built dynamic
# server+pool+dns, then string-parses the rendered JSON. Proves each replica
# carries the three new fields -- eff_latency, weight, in_good_set -- and that
# they are sane: eff_latency == measured latency at surcharge 0, weight ==
# WEIGHT_SCALE/(eff+floor) (the SAME math as server_weighted_pick, via the shared
# helper), the fastest replica has the largest weight, the far replica is out of
# the good set with a tiny weight, a cross_az_surcharge_us shifts the cross-AZ
# eff_latency and evicts the close cross-AZ replica from the band, and the
# document stays balanced JSON. It allocates (the hand-built dns + addrs), so the
# leaks run guards every path frees. Single fixed build (no compile-time mirror,
# same shape as test_stats_http): the field-presence assertions are themselves
# the red against the pre-Task-6 render that did not emit them.
bin_statsreplica="$(build_test test_stats_replica_fields "$here/test_stats_replica_fields.c")"

echo
fail=0
run_test    "$bin_remove" 0 "test_remove_address (single struct shift, fixed build)" || fail=1
run_test    "$bin_cap"    0 "test_address_cap (cap, fixed build)" || fail=1
run_nonzero "$bin_nocap"    "test_address_cap (NO-CAP bug reproduction)" || fail=1
run_test    "$bin_realloc" 0 "test_realloc_safety (single-realloc grow + new_hostnames free, fixed build)" || fail=1
run_nonzero "$bin_realloc_buggy" "test_realloc_safety (footgun-writeback NULL-clobber/leak reproduction)" || fail=1
run_leaks_must_leak "$bin_realloc_omit_hn" "test_realloc_safety (new_hostnames error-path leak, OMIT-FREE leak reproduction)" || fail=1
run_test    "$bin_lifetime" 0 "test_lifetime_quiescent (fix #1 quiescence guard, fixed build)" || fail=1
run_nonzero "$bin_lifetime_prefix" "test_lifetime_quiescent (fix #1, NO-GUARD bug reproduction)" || fail=1
run_test    "$bin_dynep" 0 "test_dynamic_endpoint (fix #5 explicit flag, fixed build)" || fail=1
run_nonzero "$bin_dynep_prefix" "test_dynamic_endpoint (fix #5, -ro AUTO-DETECT footgun reproduction)" || fail=1
run_test    "$bin_dnsinit" 0 "test_dns_init_deinit (prod-hardening #1 clean-empty-dns, fixed build)" || fail=1
run_nonzero "$bin_dnsinit_prefix" "test_dns_init_deinit (prod-hardening #1, NO-NULL-INIT wild-free reproduction)" || fail=1
run_test    "$bin_dnsoom" 0 "test_dns_resolve_oom (prod-hardening #2 revert-count, fixed build)" || fail=1
run_nonzero "$bin_dnsoom_prefix" "test_dns_resolve_oom (prod-hardening #2, NO-REVERT inconsistent-dns reproduction)" || fail=1
run_test    "$bin_statshttp" 0 "test_stats_http (prod-hardening #3 HTTP-aware stats classify+format)" || fail=1
run_test    "$bin_weightedpick" 0 "test_weighted_pick (latency-weighted reads #1 pure weighted picker)" || fail=1
run_test    "$bin_goodband" 0 "test_good_band (latency-weighted reads #2 eff-latency + good-latency band)" || fail=1
run_test    "$bin_selectweighted" 0 "test_select_weighted (latency-weighted reads #3 unified server_select_best_address)" || fail=1
run_test    "$bin_dynconncount" 0 "test_dynamic_conn_count (latency-weighted reads #4 multi-connection count wiring)" || fail=1
run_test    "$bin_confknobs" 0 "test_conf_latency_knobs (latency-weighted reads #5 conf knobs + zone_weight deprecation, fixed build)" || fail=1
run_nonzero "$bin_confknobs_prefix" "test_conf_latency_knobs (latency-weighted reads #5, NO-PARSE pre-Task-5 reproduction)" || fail=1
run_test    "$bin_statsreplica" 0 "test_stats_replica_fields (latency-weighted reads #6 eff_latency/weight/in_good_set per replica)" || fail=1
if [ "$wrap_supported" = "yes" ]; then
    run_test "$bin_dnsintegration" 0 "test_dns_resolve_integration (prod-hardening #4 real server_dns_resolve pipeline via getaddrinfo --wrap)" || fail=1
else
    echo "=== test_dns_resolve_integration (prod-hardening #4 real server_dns_resolve pipeline) ==="
    echo "RESULT: test_dns_resolve_integration -> SKIPPED (linker has no --wrap; GNU ld / Linux only -- on macOS the accumulate/expire/remove merge is covered by test_dns_resolve_oom + the other server_dns tests)"
fi

echo
if [ "$fail" -ne 0 ]; then
    echo "UNIT TESTS: FAILED" >&2
    exit 1
fi
echo "UNIT TESTS: all passed"
