MAINTAINERCLEANFILES = Makefile.in aclocal.m4 configure config.h.in config.h.in~ stamp-h.in

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = contrib src

dist_man_MANS = man/nutcracker.8

EXTRA_DIST = README.md NOTICE LICENSE ChangeLog conf scripts notes

test:
	sh run_test.sh

# `make check` -> build the project, then run our standalone C unit harness
# (tests/unit/run.sh). The harness compiles every src/*.c against the prebuilt
# sub-library archives and drives the REAL nc_server.c / nc_util.c code (see the
# header in run.sh).
#
# Why `check-recursive` is overridden:
# `make check` normally descends into every SUBDIR's `check` target. One SUBDIR
# is the VENDORED libyaml (contrib/yaml-0.1.4), whose own bundled test suite
# (test-reader) leaks under AddressSanitizer -- a third-party issue we neither
# own nor want to run. Recursing into it aborts `make check` under ASan before
# our harness ever runs. We are not testing libyaml here, only linking its
# archive, so we replace the recursive step with two explicit steps:
#   1. all-recursive -- BUILD every subdir (produces libhashkit / libproto /
#      libevent / libyaml) WITHOUT running their self-tests.
#   2. check-am      -- run THIS directory's check (which depends on all-am and
#      then runs check-local below). This is the part the generated
#      check-recursive would have run in `.` after descending.
check-recursive:
	$(MAKE) $(AM_MAKEFLAGS) all-recursive
	$(MAKE) $(AM_MAKEFLAGS) check-am

# CC is forwarded so a CI ASan build works, e.g.:
#   make check CC=gcc \
#     CFLAGS='-fsanitize=address,undefined -g' \
#     LDFLAGS='-fsanitize=address,undefined'
# (run.sh reads CFLAGS/LDFLAGS from the environment for the sanitizer build.)
check-local:
	CC='$(CC)' bash $(top_srcdir)/tests/unit/run.sh
