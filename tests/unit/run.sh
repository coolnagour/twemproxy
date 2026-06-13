#!/bin/bash
#
# Build and run the standalone server_dns unit test.
#
# Why this is not just `make check`: twemproxy ships no C unit-test framework
# (tests/ is Python integration needing a live redis), and on macOS the source
# tree does not compile under the project's strict flags because nc_server.c
# uses inet_ntop() without including <arpa/inet.h> (it resolves transitively on
# Linux via -D_GNU_SOURCE). This script compiles every src/*.c (except nc.c,
# which owns main()) with a local -include arpa/inet.h workaround and links them
# with the prebuilt sub-library archives, so the test drives the REAL
# server_dns_remove_address_at() and the real struct string handling.
#
# Memory safety: ASan is the preferred checker (see the AddressSanitizer build
# in the task brief). Where the ASan runtime refuses to initialise (some macOS
# toolchains abort in sanitizer_malloc_mac.inc), this script falls back to the
# macOS `leaks` tool, which flags leaks and aborts on double-free. On Linux,
# build with CFLAGS/LDFLAGS=-fsanitize=address and run ./test_remove_address
# directly under ASan instead.
#
# Usage: bash tests/unit/run.sh
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

objs=()
for src in "$root"/src/*.c; do
    base="$(basename "$src" .c)"
    [ "$base" = "nc" ] && continue   # nc.c owns main()
    obj="$out/$base.o"
    "$cc" -c "${cflags[@]}" "${extra_cflags[@]}" "${incs[@]}" "$src" -o "$obj"
    objs+=("$obj")
done

# The test object.
"$cc" -c "${cflags[@]}" "${extra_cflags[@]}" "${incs[@]}" \
    "$here/test_remove_address.c" -o "$out/test_remove_address.o"

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

bin="$out/test_remove_address"
"$cc" -g -O0 "${extra_ldflags[@]}" \
    "$out/test_remove_address.o" "${objs[@]}" "${archives[@]}" \
    -lm -lpthread -o "$bin"

echo "built $bin"

# Run, preferring a real memory checker.
if [ -n "${LDFLAGS:-}" ] && printf '%s' "${LDFLAGS}" | grep -q 'fsanitize=address'; then
    echo "running under AddressSanitizer"
    "$bin"
elif command -v valgrind >/dev/null 2>&1; then
    echo "running under valgrind"
    valgrind --error-exitcode=99 --leak-check=full "$bin"
elif command -v leaks >/dev/null 2>&1; then
    echo "running under macOS leaks (--atExit)"
    MallocStackLogging=1 leaks --atExit -- "$bin"
else
    echo "running plain (no memory checker available)"
    "$bin"
fi
