/*
 * Standalone unit test for the explicit dynamic_endpoint flag (fix #5 of the
 * prod-hardening campaign).
 *
 * Twemproxy has no C unit-test framework (tests/ is Python integration that
 * needs a live redis). This is a freestanding C test that links the real
 * nc_conf.c object and drives the production decision predicate directly, so we
 * exercise production code without a network or a parsed YAML file.
 *
 * The bug (the "-ro" footgun)
 * ---------------------------
 * The fork decided whether a backend used the dynamic DNS accumulator + zone
 * routing (is_dynamic) by testing whether the server HOSTNAME contained the
 * substring "-ro" (old src/nc_conf.c conf_server_each_transform). That was a
 * footgun: any pool whose endpoint hostname merely contained the letters "ro"
 * (e.g. a primary endpoint named "...prod-rw..." or any host with "ro" in it)
 * was silently turned into a latency-routed accumulator. For a WRITE pool that
 * meant an ElastiCache failover could route writes to a demoted read replica
 * for minutes.
 *
 * The fix
 * -------
 * Dynamic mode is now an EXPLICIT per-pool opt-in: the dynamic_endpoint
 * directive (default false). is_dynamic is driven solely by that flag; the
 * hostname is never inspected. The -ro substring trigger is removed entirely.
 *
 * What this test proves (driving REAL production code):
 *   1. dynamic_endpoint=true  -> servers are dynamic, regardless of hostname.
 *   2. dynamic_endpoint=false -> servers are NOT dynamic, EVEN IF the hostname
 *      contains "-ro". This is the anti-footgun assertion.
 *   3. dynamic_endpoint unset (CONF_UNSET_NUM, i.e. the parser default before
 *      finalize) -> NOT dynamic.
 *
 * Fidelity / red->green
 * ---------------------
 * The default build calls the REAL production predicate
 * conf_pool_servers_are_dynamic() from nc_conf.c -- the exact function the real
 * conf_pool_each_transform uses to set each server's is_dynamic. (We test the
 * predicate rather than running conf_pool_each_transform end to end because, for
 * a dynamic pool, the transform also calls server_dns_init() ->
 * server_dns_resolve(), which performs real network DNS resolution; the
 * decision logic -- the thing the fix changes -- is fully captured by the
 * predicate. This mirrors how fix #1 tests core_conn_lifetime_should_recycle()
 * directly rather than running the whole maintenance sweep.)
 *
 * To produce the TDD red, the -DTEST_PREFIX_RO_AUTODETECT build replaces the
 * real predicate with a faithful mirror of the PRE-fix decision: is_dynamic is
 * inferred from a "-ro" substring in the hostname, ignoring the flag. Under
 * that build the anti-footgun case (test_no_flag_ro_hostname_is_static) flips:
 * a "-ro" host with the flag OFF is (wrongly) reported dynamic, so the
 * assertion fails -> non-zero exit. This mirrors how test_address_cap
 * (-DTEST_NO_CAP), test_realloc_safety (-DTEST_REALLOC_BUGGY), and
 * test_lifetime_quiescent (-DTEST_PREFIX_NO_QUIESCENCE_GUARD) stage their red
 * builds in this same suite.
 *
 * Build/run: see tests/unit/run.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <nc_core.h>
#include <nc_conf.h>
#include <nc_string.h>
#include <nc.h>

/*
 * nc.c owns main() so it is excluded from the link; nc_signal.o references
 * nc_post_run() from there. The test never raises a fatal signal, so a no-op
 * stub satisfies the linker without affecting behaviour.
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

#ifdef TEST_PREFIX_RO_AUTODETECT
/*
 * Faithful mirror of the PRE-fix decision in conf_server_each_transform(): a
 * server is dynamic purely when its hostname contains the substring "-ro",
 * with NO reference to any explicit flag. This reproduces the footgun. Keep
 * this in lock-step with the old condition that was removed from
 * src/nc_conf.c (strstr(hostname, "-ro") != NULL on addrstr, guarded by
 * addrstr.len > 3).
 */
static bool
decide_dynamic(int dynamic_endpoint, struct string *addrstr)
{
    char *hostname;
    bool dynamic = false;

    (void)dynamic_endpoint; /* the old code never looked at any flag */

    if (addrstr->len > 3) {
        hostname = nc_alloc(addrstr->len + 1);
        if (hostname != NULL) {
            nc_memcpy(hostname, addrstr->data, addrstr->len);
            hostname[addrstr->len] = '\0';
            if (strstr(hostname, "-ro") != NULL) {
                dynamic = true;
            }
            nc_free(hostname);
        }
    }
    return dynamic;
}
#else
/* Default: drive the REAL production predicate from nc_conf.c. */
#define decide_dynamic(flag, addrstr) \
    conf_pool_servers_are_dynamic((flag), (addrstr))
#endif

/* Wrap a NUL-terminated literal as a (non-owning) struct string for the test. */
static struct string
mk_str(char *literal)
{
    struct string s;
    s.data = (uint8_t *)literal;
    s.len = (uint32_t)strlen(literal);
    return s;
}

/* A read-replica style hostname that contains "-ro" -- the footgun trigger. */
static char HOST_RO[]   = "my-redis-ro.cache.amazonaws.com";
/* A write/primary hostname. Note it contains the letters "ro" (in "-rw"/in
 * "prod") but NOT the "-ro" substring the old code keyed on -- still, the
 * point of the fix is that NO hostname should matter. */
static char HOST_WRITE[] = "my-redis-primary.cache.amazonaws.com";

/*
 * (1) dynamic_endpoint = true -> servers ARE dynamic, regardless of hostname.
 * True under both builds for the -ro host (the mirror also says dynamic for a
 * -ro host); for the write host this is the GREEN-only direction.
 */
static void
test_flag_true_is_dynamic(void)
{
    struct string ro = mk_str(HOST_RO);
    struct string wr = mk_str(HOST_WRITE);

    CHECK(decide_dynamic(1, &ro),
          "dynamic_endpoint:true must make a -ro-host server dynamic");
    CHECK(decide_dynamic(1, &wr),
          "dynamic_endpoint:true must make a write-host server dynamic "
          "(decision is flag-driven, not hostname-driven)");
}

/*
 * (2) ANTI-FOOTGUN: dynamic_endpoint = false but hostname contains "-ro" ->
 * the server must be STATIC. This is the assertion that fails pre-fix: the
 * old -ro substring logic (mirrored under -DTEST_PREFIX_RO_AUTODETECT) reports
 * the -ro host as dynamic even with the flag off -> red.
 */
static void
test_no_flag_ro_hostname_is_static(void)
{
    struct string ro = mk_str(HOST_RO);

    CHECK(!decide_dynamic(0, &ro),
          "ANTI-FOOTGUN: a pool WITHOUT dynamic_endpoint must keep its server "
          "STATIC even when the hostname contains \"-ro\"");
}

/*
 * (3) dynamic_endpoint = false, ordinary write hostname -> static. Green under
 * both builds, but pins the common write-pool case.
 */
static void
test_no_flag_write_hostname_is_static(void)
{
    struct string wr = mk_str(HOST_WRITE);

    CHECK(!decide_dynamic(0, &wr),
          "a write pool without dynamic_endpoint must be static");
}

/*
 * (4) dynamic_endpoint left UNSET (CONF_UNSET_NUM == -1, the parser's value
 * before conf finalize applies the default) -> treated as NOT dynamic. The
 * real predicate must not mistake the sentinel for "on". (Under the -ro mirror
 * this is hostname-driven, so for the -ro host it would say dynamic -- but
 * that case is already the red asserted in (2); here we use a write host so
 * this stays a clean GREEN check of the sentinel handling on both builds.)
 */
static void
test_unset_flag_is_static(void)
{
    struct string wr = mk_str(HOST_WRITE);

    CHECK(!decide_dynamic(CONF_UNSET_NUM, &wr),
          "an unset dynamic_endpoint sentinel must not be treated as enabled");
}

int
main(void)
{
    test_flag_true_is_dynamic();
    test_no_flag_ro_hostname_is_static();
    test_no_flag_write_hostname_is_static();
    test_unset_flag_is_static();

    if (failures == 0) {
        printf("OK: all dynamic_endpoint flag tests passed\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
}
