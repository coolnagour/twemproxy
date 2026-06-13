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
# Tests run here:
#   test_remove_address  -- server_dns_remove_address_at() array-shift alignment
#                           (fix #2).
#   test_address_cap     -- the accumulate-append cap at max_addresses (fix #3),
#                           guarding the lazy parallel arrays against an OOB
#                           write. Built TWICE:
#                             * default (cap present)  -> must exit 0 (clean).
#                             * -DTEST_NO_CAP          -> reproduces the pre-fix
#                               bug (naddresses>16 + OOB lazy-array write);
#                               must exit non-zero. This is the TDD red->green
#                               evidence for the fix.
#
# Memory safety: ASan is the preferred checker (see the AddressSanitizer build
# in the task brief). Where the ASan runtime refuses to initialise (some macOS
# toolchains abort in sanitizer_malloc_mac.inc), this script falls back to the
# macOS `leaks` tool, which flags leaks and aborts on double-free, OR to
# libgmalloc when LIBGMALLOC=1 is set (DYLD_INSERT_LIBRARIES=libgmalloc.dylib
# traps heap OOB read/write/double-free -- meaningful for the fix #3 OOB). On
# Linux, build with CFLAGS/LDFLAGS=-fsanitize=address and run the binaries
# directly under ASan instead.
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

# build_test <binary-name> <test-source> [extra-cflags...]
# Compiles the test source against the shared production objects + archives.
build_test() {
    local name="$1" tsrc="$2"; shift 2
    local tobj="$out/$name.o" bin="$out/$name"
    "$cc" -c "${cflags[@]}" "${extra_cflags[@]}" "$@" "${incs[@]}" \
        "$tsrc" -o "$tobj"
    "$cc" -g -O0 "${extra_ldflags[@]}" \
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
        echo "running under macOS leaks (--atExit)"
        MallocStackLogging=1 leaks --atExit -- "$bin" || rc=$?
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

# --- fix #2: array-shift alignment -----------------------------------------
bin_remove="$(build_test test_remove_address "$here/test_remove_address.c")"

# --- fix #3: accumulate cap ------------------------------------------------
# Three builds from one source via compile flags:
#   capped   : mirrors the FIXED nc_server.c  -> must exit 0 (clean).
#   nocap    : mirrors the PRE-fix nc_server.c -> must exit non-zero (the
#              cap is gone; naddresses runs past 16 and the lazy-array touch
#              is reported OOB). This is the TDD red.
#   forceoob : nocap + actually performs the genuine out-of-bounds lazy-array
#              write. Built and run ONLY under a heap guard (LIBGMALLOC=1 or
#              ASan), where it traps the corruption with a hard fault. Skipped
#              on plain runs because a real OOB write smashes the heap.
bin_cap="$(build_test test_address_cap "$here/test_address_cap.c")"
bin_nocap="$(build_test test_address_cap_nocap "$here/test_address_cap.c" -DTEST_NO_CAP)"

echo
fail=0
run_test    "$bin_remove" 0 "test_remove_address (fix #2 alignment)"     || fail=1
run_test    "$bin_cap"    0 "test_address_cap (fix #3 cap, fixed build)" || fail=1
run_nonzero "$bin_nocap"    "test_address_cap (fix #3, NO-CAP bug reproduction)" || fail=1

# Heap-guard demonstration: only meaningful (and only safe) under a guard.
if [ "${LIBGMALLOC:-0}" = "1" ] && [ -f /usr/lib/libgmalloc.dylib ]; then
    bin_forceoob="$(build_test test_address_cap_forceoob "$here/test_address_cap.c" \
                        -DTEST_NO_CAP -DTEST_FORCE_OOB_WRITE)"
    echo "=== test_address_cap (fix #3, FORCE-OOB heap-guard trap; abort expected) ==="
    echo "running under libgmalloc (heap OOB guard)"
    foob_rc=0
    DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib "$bin_forceoob" >/dev/null 2>&1 || foob_rc=$?
    if [ "$foob_rc" -gt 128 ]; then
        echo "RESULT: FORCE-OOB -> died from signal $((foob_rc-128)) -- PASS (libgmalloc trapped the heap OOB write)"
    else
        echo "RESULT: FORCE-OOB -> rc=$foob_rc (no heap-guard trap) -- FAIL" >&2
        fail=1
    fi
fi

echo
if [ "$fail" -ne 0 ]; then
    echo "UNIT TESTS: FAILED" >&2
    exit 1
fi
echo "UNIT TESTS: all passed"
