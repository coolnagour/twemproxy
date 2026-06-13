/*
 * Standalone unit test for the server_dns_init() / server_dns_deinit() pair on
 * the FAILED-FIRST-RESOLVE path, on the array-of-structs layout.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS GUARDS
 * ---------------------------------------------------------------------------
 * server_dns_init() deliberately tolerates a failed first DNS resolve ("will
 * retry later") and returns NC_OK with the dns kept. The first resolve is the
 * only thing that allocates the per-address array, so on a failed first resolve
 * the dns must be left EMPTY and self-consistent: addrs == NULL, naddresses == 0.
 * server_dns_deinit() must then free it cleanly -- it frees dns->addrs guarded by
 * "if (addrs != NULL)", so addrs MUST be NULL here or deinit wild-frees garbage.
 *
 * Pre-refactor history: struct server_dns had ~11 owned pointers and the bug was
 * that init() forgot to NULL two of them (last_connected / request_counts), so a
 * failed first resolve left them as heap garbage that deinit wild-freed. The fix
 * was nc_zalloc + explicit NULL inits. After folding the parallel arrays into a
 * single dns_addr array there is exactly ONE owned pointer (dns->addrs), still
 * zalloc'd to NULL -- so the multi-pointer footgun is gone, but the SAME
 * end-to-end contract (failed first resolve => clean empty dns => clean deinit)
 * still holds and is what this test drives through the REAL init + REAL deinit.
 *
 * No network needed: nc_resolve_multi_with_hostnames() returns NC_ERROR
 * IMMEDIATELY (zero allocation, zero DNS traffic) when the hostname starts with
 * '/'. So a server whose addrstr is "/no/such/resolve" gives a deterministic,
 * offline "first resolve failed".
 *
 * ---------------------------------------------------------------------------
 * BEFORE/AFTER (TDD red->green)
 * ---------------------------------------------------------------------------
 *   default build (FIXED): drives the REAL server_dns_init() (nc_zalloc) then the
 *     REAL server_dns_deinit(). addrs is NULL, naddresses 0, deinit frees nothing
 *     wild -> exit 0, clean under ASan / libgmalloc / leaks.
 *
 *   -DTEST_PREFIX_NO_NULL_INIT (PRE-FIX style): builds a faithful mirror of a
 *     buggy init -- nc_alloc the struct (NOT zalloc), memset it to 0xAB garbage,
 *     run the field inits EXCEPT the addrs = NULL one, copy the hostname, attempt
 *     the (failing) first resolve -- then calls the REAL server_dns_deinit().
 *     dns->addrs is garbage (non-NULL), so deinit nc_free()s a wild pointer. We
 *     also self-report it (addrs non-NULL after init, which the fixed code
 *     guarantees it is not), so a PLAIN build FAILS; under ASan/libgmalloc the
 *     wild free traps. This is the TDD red.
 *
 *     *** KEEP the mirror init below IN SYNC with server_dns_init() in
 *         src/nc_server.c (a faithful copy of the body minus the addrs NULL
 *         init). ***
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
#include <nc_server.h>
#include <nc_string.h>
#include <nc_util.h>
#include <nc.h>

/*
 * nc.c owns main() so it is excluded from the link; nc_signal.o references
 * nc_post_run() from there. (Same as the other tests in this suite.)
 */
void nc_post_run(struct instance *nci) { (void)nci; }

/*
 * MAX_ADDRESSES_PER_SERVER and DNS_RESOLVE_INTERVAL_USEC are file-local #defines
 * in src/nc_server.c (not the header). Mirror their values here. Only used by the
 * TEST_PREFIX_NO_NULL_INIT mirror; the GREEN build drives the real init.
 *
 *     *** KEEP IN SYNC with src/nc_server.c. ***
 */
#define TEST_MAX_ADDRESSES_PER_SERVER  16
#define TEST_DNS_RESOLVE_INTERVAL_USEC (30 * 1000000)

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

/*
 * Build a minimal-but-valid struct server whose addrstr starts with '/', so the
 * first resolve fails offline (no network, no allocation). owner is left NULL:
 * server_dns_init() and server_dns_resolve() both guard server->owner /
 * server->owner->ctx with NULL checks, so a NULL pool means "use defaults" and
 * "skip stats", never a deref.
 */
static void
make_server(struct server *s)
{
    memset(s, 0, sizeof(*s));
    s->idx = 0;
    s->owner = NULL;                 /* no pool -> defaults + stats skipped */
    s->port = 6379;
    s->is_dynamic = 1;
    s->dns = NULL;
    string_init(&s->pname);
    string_init(&s->name);
    string_init(&s->addrstr);
    /* leading '/' => resolver's unix-socket guard returns NC_ERROR at once */
    string_copy(&s->pname,   (uint8_t *)"/no/such/resolve:6379", 21);
    string_copy(&s->name,    (uint8_t *)"/no/such/resolve",      16);
    string_copy(&s->addrstr, (uint8_t *)"/no/such/resolve",      16);
}

static void
free_server_strings(struct server *s)
{
    if (s->pname.data)   string_deinit(&s->pname);
    if (s->name.data)    string_deinit(&s->name);
    if (s->addrstr.data) string_deinit(&s->addrstr);
}

#ifdef TEST_PREFIX_NO_NULL_INIT
/*
 * Faithful mirror of a PRE-FIX-style server_dns_init() body for the AoS layout:
 * nc_alloc (NOT zalloc), memset to 0xAB so the owned pointer starts as non-NULL
 * garbage, run the field inits EXCEPT dns->addrs = NULL (the one the "bug"
 * forgets), copy the hostname, attempt the first resolve (fails offline), adopt
 * the dns onto the server. Returns the half-built server->dns.
 */
static void
prefix_buggy_dns_init(struct server *server)
{
    struct server_dns *dns;
    struct server_pool *pool;
    rstatus_t status;

    dns = nc_alloc(sizeof(struct server_dns));
    if (dns == NULL) { return; }

    /* Guarantee the owned pointer starts as non-NULL garbage (the bug). */
    memset(dns, 0xAB, sizeof(struct server_dns));

    pool = server->owner;

    string_init(&dns->hostname);
    /* BUG: dns->addrs intentionally NOT set to NULL here. */
    dns->naddresses = 0;
    dns->max_addresses = TEST_MAX_ADDRESSES_PER_SERVER;
    dns->last_resolved = 0;
    if (pool != NULL && pool->dns_resolve_interval > 0) {
        dns->resolve_interval = pool->dns_resolve_interval;
    } else {
        dns->resolve_interval = TEST_DNS_RESOLVE_INTERVAL_USEC;
    }
    dns->health_initialized = false;
    dns->health_check_interval = pool ? pool->dns_health_check_interval : 30000000LL;
    dns->consecutive_failures_limit = pool ? pool->dns_failure_threshold : 3;
    dns->zones_assigned = false;
    dns->local_zone_id = 0;
    dns->next_zone_id = 1;
    dns->last_zone_analysis = 0;

    status = string_copy(&dns->hostname, server->addrstr.data, server->addrstr.len);
    if (status != NC_OK) { nc_free(dns); return; }

    server->dns = dns;
    server->current_addr_idx = 0;

    /* First resolve -- fails offline ('/'-prefixed); dns stays half-built. */
    (void)server_dns_resolve(server);
}
#endif /* TEST_PREFIX_NO_NULL_INIT */

int
main(void)
{
    struct server s;
    make_server(&s);

#ifdef TEST_PREFIX_NO_NULL_INIT
    /* RED: reproduce the pre-fix half-built dns, then REAL deinit. */
    prefix_buggy_dns_init(&s);

    CHECK(s.dns != NULL, "prefix init did not produce a dns");

    /*
     * The whole point: the pre-fix init leaves dns->addrs NON-NULL (garbage). The
     * FIXED init guarantees it is NULL after a failed first resolve. Detect the
     * garbage so a PLAIN build fails even without a heap guard.
     */
    if (s.dns != NULL) {
        CHECK(s.dns->addrs != NULL,
              "expected pre-fix garbage in dns->addrs, got NULL "
              "(mirror drifted from the buggy code?)");
    }

    /*
     * REAL server_dns_deinit(): on the pre-fix dns it nc_free()s the garbage
     * addrs pointer -> wild free (ASan/libgmalloc trap here; a plain build may
     * crash or silently corrupt -- the assert above already flagged it).
     */
    server_dns_deinit(&s);
    free_server_strings(&s);

    if (failures > 0) {
        printf("EXPECTED-FAIL (pre-fix no-NULL-init build): %d assertion(s) -- "
               "dns->addrs left as garbage, REAL deinit wild-frees it\n", failures);
        return 1;
    }
    fprintf(stderr,
            "UNEXPECTED: pre-fix build saw addrs NULL -- the nc_alloc block "
            "happened to be zero; rely on ASan/libgmalloc, treat as not-exercised\n");
    return 2;
#else
    /* GREEN: drive the REAL init + REAL deinit. */
    rstatus_t status = server_dns_init(&s);

    /* init tolerates a failed first resolve and returns NC_OK with dns kept. */
    CHECK(status == NC_OK,
          "server_dns_init returned %d (expected NC_OK; it must tolerate a "
          "failed first resolve)", status);
    CHECK(s.dns != NULL,
          "server_dns_init left server->dns NULL after a failed first resolve "
          "(it should keep the dns to retry later)");

    if (s.dns != NULL) {
        /* The failed first resolve must leave an EMPTY, consistent dns: a single
         * owned array pointer, NULL, with a zero count. */
        CHECK(s.dns->naddresses == 0,
              "naddresses=%u after failed first resolve (expected 0)",
              s.dns->naddresses);
        CHECK(s.dns->addrs == NULL,
              "addrs non-NULL after failed first resolve (expected NULL -- deinit "
              "would wild-free it)");
    }

    /* REAL deinit: must be a clean free under every memory checker. */
    server_dns_deinit(&s);
    CHECK(s.dns == NULL, "server_dns_deinit did not NULL server->dns");

    free_server_strings(&s);

    if (failures == 0) {
        printf("OK: server_dns_init tolerates a failed first resolve leaving an "
               "empty, consistent dns (addrs=NULL, naddresses=0); "
               "server_dns_deinit frees it with no wild free\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
#endif
}
