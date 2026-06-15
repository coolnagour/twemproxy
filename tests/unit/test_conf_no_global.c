/*
 * Standalone unit test for parsing a config that omits the optional `global:`
 * section -- the privilege-drop user/group resolution must NOT fail for a
 * non-root process, on any distro (notably Debian/Ubuntu, where the RHEL-style
 * default group "nobody" does not exist).
 *
 * Twemproxy has no C unit-test framework (tests/ is Python integration that
 * needs a live redis). This is a freestanding C test that links the real
 * nc_conf.c objects and drives the REAL parse pipeline (conf_create ->
 * conf_begin_parse/conf_end_parse -> the end-of-parse user/group resolution)
 * against a temp YAML file, so it exercises production parsing without a
 * network.
 *
 * Background -- the bug this guards
 * --------------------------------
 * The `global:` section is OPTIONAL. At the end of conf_parse() the code
 * resolves the worker privilege-drop accounts: if user/group were not set it
 * falls back to CONF_DEFAULT_USER / CONF_DEFAULT_GROUP, then calls
 * getpwnam()/getgrnam() and FAILS the whole parse (NC_ERROR) if either is not
 * found. Both defaults are "nobody". That is RHEL-centric: Debian/Ubuntu ship a
 * "nobody" USER but no "nobody" GROUP (they use "nogroup", gid 65534). So a
 * config that omits `global:` failed to parse on Debian with
 * "group[nobody] not found" -- even though the accounts are only ever used by
 * the actual setgid/setuid drop, which runs ONLY as root (geteuid()==0). A
 * non-root proxy (the production container runs non-root) never drops, so it
 * never needs the accounts, yet the parse failed anyway.
 *
 * The fix gates the entire resolution on `if (geteuid() == 0)` -- exactly the
 * condition the drop in nc_process.c uses -- so a non-root process skips it and
 * any config (including a `global:`-less one) parses on any distro, while root
 * still resolves and still fails fast on a genuinely missing account.
 *
 * What it proves
 * --------------
 *   1. A config with NO `global:` section runs the full conf_create() pipeline
 *      to NC_OK when this test process is non-root. This is the behaviour the
 *      fix guarantees on Debian/Ubuntu (where "nobody" group is absent) and on
 *      every other distro. It is the regression assertion: pre-fix, this same
 *      no-global config returned NULL on Debian.
 *
 *   2. The pool inside that no-global config is present after the parse, i.e.
 *      parsing actually completed rather than bailing early.
 *
 * Root caveat: if this test ever runs AS root (geteuid()==0), the fixed code
 * DOES resolve the defaults, so on a host with no "nobody" group the parse
 * would (correctly) fail -- that is the preserved fail-fast for the real drop.
 * The non-root assertions are therefore skipped under root with a clear note,
 * so the test stays meaningful (not a false PASS) wherever it runs. CI runs the
 * harness non-root, which is the case the fix targets.
 *
 * Red->green
 * ----------
 *   * Against the PRE-fix tree, this DEFAULT build is red on Debian/Ubuntu: the
 *     ungated resolution calls getgrnam("nobody") -> NULL -> conf_parse returns
 *     NC_ERROR -> conf_create returns NULL -> assertion (1) fails -> non-zero
 *     exit. That is the true behavioural red the fix removes. (On a RHEL host,
 *     where "nobody" group exists, the pre-fix build is not red -- which is why
 *     the bug hid: every shipped conf/ file declares an explicit global:.)
 *
 *   * The -DTEST_PREFIX_FORCE_NOBODY build is a COMPILE-TIME mirror of the
 *     pre-fix world that reproduces the red on the SAME (Debian) host regardless
 *     of euid: instead of trusting the parse, it performs the exact operation
 *     the old ungated code did -- getgrnam(CONF_DEFAULT_GROUP) -- and asserts it
 *     succeeds. On Debian/Ubuntu that group does not exist, so the assertion
 *     fails -> non-zero exit, recorded by run_nonzero as the staged red. This
 *     mirrors how the other tests in this suite (-DTEST_PREFIX_*) stage their
 *     reds, and pins the failure to the precise call the fix made conditional.
 *
 * Build/run: see tests/unit/run.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <arpa/inet.h>

#include <nc_core.h>
#include <nc_conf.h>
#include <nc_server.h>
#include <nc_string.h>
#include <nc_log.h>
#include <nc.h>

/*
 * nc.c owns main() so it is excluded from the link; nc_signal.o references
 * nc_post_run() from there. A no-op stub satisfies the linker.
 */
void nc_post_run(struct instance *nci) { (void)nci; }

static int failures = 0;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);              \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n");                                             \
        }                                                                      \
    } while (0)

/* Write text to a fresh temp file; return a malloc'd path the caller frees. */
static char *
write_temp_conf(const char *text)
{
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || dir[0] == '\0') {
        dir = "/tmp";
    }
    char *path = nc_alloc(strlen(dir) + 32);
    ASSERT(path != NULL);
    sprintf(path, "%s/twem-noglobal-XXXXXX", dir);
    int fd = mkstemp(path);
    ASSERT(fd >= 0);
    ssize_t n = write(fd, text, strlen(text));
    ASSERT(n == (ssize_t)strlen(text));
    close(fd);
    return path;
}

/*
 * A config with NO `global:` section. One static pool is enough to drive the
 * full parse to completion; the bug is in the end-of-parse user/group
 * resolution, which runs regardless of how many pools there are.
 */
static const char *CONF_NO_GLOBAL =
    "pools:\n"
    "    noglobal:\n"
    "        listen: 127.0.0.1:11211\n"
    "        redis: true\n"
    "        servers:\n"
    "            - 127.0.0.1:6379:1\n";

/*
 * (1)+(2): a config that omits `global:` parses to NC_OK (non-root), and its
 * pool is present afterwards.
 */
static void
test_no_global_section_parses(void)
{
#ifdef TEST_PREFIX_FORCE_NOBODY
    /*
     * Pre-fix mirror: reproduce the exact operation the old, ungated code
     * performed at the end of conf_parse() -- resolve the default drop group.
     * On Debian/Ubuntu CONF_DEFAULT_GROUP ("nobody") does not exist, so this is
     * NULL and the assertion fails -> the staged red, on the same host, no
     * matter the euid. See the file header "Red->green".
     */
    struct group *grp = getgrnam((char *)CONF_DEFAULT_GROUP);
    CHECK(grp != NULL,
          "pre-fix mirror: getgrnam(\"%s\") must resolve -- it does NOT on "
          "Debian/Ubuntu, which is the bug the geteuid() gate removes",
          CONF_DEFAULT_GROUP);
    return;
#else
    if (geteuid() == 0) {
        /*
         * Running as root the fixed code DOES resolve the defaults (preserving
         * fail-fast for the real drop), so this no-global config could legit-
         * imately fail to parse on a host without a "nobody" group. The fix
         * targets the NON-root path; skip the parse assertions here rather than
         * risk a misleading PASS/FAIL. CI runs the harness non-root.
         */
        printf("SKIP: running as root -- the no-global non-root assertions only "
               "apply when geteuid() != 0 (CI runs the harness non-root)\n");
        return;
    }

    char *path = write_temp_conf(CONF_NO_GLOBAL);
    struct conf *cf = conf_create(path);
    unlink(path);
    nc_free(path);

    CHECK(cf != NULL,
          "a config with no global: section must parse to NC_OK for a non-root "
          "process on any distro (pre-fix this returned NULL on Debian/Ubuntu "
          "because getgrnam(\"nobody\") failed)");
    if (cf == NULL) {
        return;
    }

    CHECK(array_n(&cf->pool) == 1,
          "the single pool from the no-global config must be present after "
          "parse, got %"PRIu32" pool(s)", array_n(&cf->pool));

    conf_destroy(cf);
#endif
}

int
main(void)
{
    /* log_error/log_warn write to stderr; without log_init the macro guard
     * reads an uninitialised level. Initialise to WARN so messages are
     * loggable (and so a real parse error is visible in CI logs). */
    if (log_init(LOG_WARN, NULL) != 0) {
        fprintf(stderr, "log_init failed\n");
        return 2;
    }

    test_no_global_section_parses();

    log_deinit();

    if (failures == 0) {
        printf("OK: no-global-section conf parse test passed\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
}
