/*
 * Standalone unit test for the server_dns_init() / server_dns_deinit() pair on
 * the FAILED-FIRST-RESOLVE path (prod-hardening bug #1).
 *
 * ---------------------------------------------------------------------------
 * THE BUG THIS GUARDS (pre-fix server_dns_init(), src/nc_server.c)
 * ---------------------------------------------------------------------------
 * server_dns_init() allocated struct server_dns with nc_alloc() (uninitialised
 * memory) and then NULL-initialised MOST of its pointer fields by hand -- but it
 * forgot two: dns->last_connected and dns->request_counts. Those stayed at
 * whatever garbage the heap block held.
 *
 * On the happy path that does not matter: the first DNS resolve succeeds and
 * server_dns_resolve()'s first-resolution branch nc_alloc()s every parallel
 * array (last_connected / request_counts included) and overwrites the garbage
 * with real pointers. But if the FIRST resolve FAILS, that branch never runs.
 * server_dns_init() deliberately tolerates a failed first resolve ("will retry
 * later") and returns NC_OK with the dns kept. So the dns is left half-built:
 * last_connected and request_counts still hold GARBAGE.
 *
 * Later, server_dns_deinit() frees every parallel array guarded only by
 * "if (ptr != NULL) nc_free(ptr)". Garbage is almost never NULL, so it calls
 * nc_free() on two wild pointers -> wild free / heap corruption at shutdown.
 *
 * ---------------------------------------------------------------------------
 * THE FIX
 * ---------------------------------------------------------------------------
 *   1. Allocate the struct with nc_zalloc() (zero every field up front), and
 *   2. add the two missing explicit NULL inits (belt-and-braces / documents
 *      intent).
 * Now a failed first resolve leaves last_connected == request_counts == NULL,
 * so server_dns_deinit() skips them -- no wild free.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS TEST EXISTS (the entry point the mirror tests missed)
 * ---------------------------------------------------------------------------
 * The other server_dns tests mirror INNER decision blocks (cap, realloc write-
 * back, index fixup) against a hand-built fixture. None of them drive the actual
 * server_dns_init()/server_dns_deinit() ENTRY POINTS -- which is exactly why a
 * missing NULL-init in init() slipped through. This test drives the REAL init +
 * REAL deinit end to end.
 *
 * No network needed: nc_resolve_multi_with_hostnames() returns NC_ERROR
 * IMMEDIATELY, with zero allocation and zero DNS traffic, when the hostname
 * starts with '/' (its "unix domain sockets don't support multiple addresses"
 * guard). So a server whose addrstr is "/no/such/resolve" gives a deterministic,
 * offline "first resolve failed" -- precisely the half-built-dns path. (errno is
 * not even consulted; the guard fires before getaddrinfo.)
 *
 * ---------------------------------------------------------------------------
 * BEFORE/AFTER (TDD red->green)
 * ---------------------------------------------------------------------------
 *   default build (FIXED): calls the REAL server_dns_init() -- with the
 *     nc_zalloc + NULL inits -- then the REAL server_dns_deinit(). last_connected
 *     and request_counts are NULL, deinit skips them, no wild free -> exit 0,
 *     clean under ASan / libgmalloc / leaks.
 *
 *   -DTEST_PREFIX_NO_NULL_INIT (PRE-FIX): builds a faithful mirror of the pre-fix
 *     init -- nc_alloc the struct, deliberately fill it with non-NULL garbage,
 *     run ONLY the NULL inits the buggy code did (omitting last_connected /
 *     request_counts), copy the hostname, attempt the (failing) first resolve --
 *     then calls the REAL server_dns_deinit(). deinit now nc_free()s the two
 *     garbage pointers -> wild free. We also self-report it (the two fields are
 *     non-NULL after init, which the fixed code guarantees they are not), so a
 *     PLAIN build FAILS non-zero; under ASan/libgmalloc the wild nc_free() traps.
 *     This is the TDD red.
 *
 *     *** KEEP the mirror init below IN SYNC with server_dns_init() in
 *         src/nc_server.c (it is a faithful copy of the pre-fix body minus the
 *         two missing NULL inits). ***
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
 * nc_post_run() from there. The test never raises a fatal signal, so a no-op
 * stub satisfies the linker. (Same as the other tests in this suite.)
 */
void nc_post_run(struct instance *nci) { (void)nci; }

/*
 * MAX_ADDRESSES_PER_SERVER and DNS_RESOLVE_INTERVAL_USEC are file-local #defines
 * in src/nc_server.c (not the header), so the pre-fix mirror below cannot name
 * them. Mirror their values here -- same convention test_realloc_safety.c uses
 * for DEFAULT_LATENCY_USEC. Only used by the TEST_PREFIX_NO_NULL_INIT mirror;
 * the GREEN build drives the real init and never touches these.
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
 * first resolve fails offline (no network, no allocation -- see file header).
 * owner is left NULL: server_dns_init() and server_dns_resolve() both guard
 * server->owner / server->owner->ctx with NULL checks, so a NULL pool means "use
 * defaults" and "skip stats", never a deref.
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
 * Faithful mirror of the PRE-FIX server_dns_init() body: nc_alloc (NOT zalloc),
 * NULL-init every pointer field EXCEPT last_connected / request_counts (the two
 * the bug forgot), copy the hostname, attempt the first resolve (which fails
 * offline), and adopt the dns onto the server -- exactly as the buggy code left
 * it. To make the latent garbage deterministic (an nc_alloc block could happen
 * to be zero), we memset the struct to 0xAB first so the un-initialised fields
 * are guaranteed non-NULL wild pointers. Returns the half-built server->dns.
 */
static void
prefix_buggy_dns_init(struct server *server)
{
    struct server_dns *dns;
    struct server_pool *pool;
    rstatus_t status;

    dns = nc_alloc(sizeof(struct server_dns));
    if (dns == NULL) { return; }

    /* Guarantee the forgotten fields start as non-NULL garbage (the bug). */
    memset(dns, 0xAB, sizeof(struct server_dns));

    pool = server->owner;

    string_init(&dns->hostname);
    dns->addresses = NULL;
    dns->naddresses = 0;
    dns->max_addresses = TEST_MAX_ADDRESSES_PER_SERVER;
    dns->last_resolved = 0;
    if (pool != NULL && pool->dns_resolve_interval > 0) {
        dns->resolve_interval = pool->dns_resolve_interval;
    } else {
        dns->resolve_interval = TEST_DNS_RESOLVE_INTERVAL_USEC;
    }
    dns->latencies = NULL;
    dns->last_latency_check = NULL;
    dns->failure_counts = NULL;
    dns->last_seen = NULL;
    /* BUG: last_connected and request_counts intentionally NOT NULLed here. */
    dns->hostnames = NULL;
    dns->health_scores = NULL;
    dns->last_health_check = NULL;
    dns->health_check_interval = pool ? pool->dns_health_check_interval : 30000000LL;
    dns->consecutive_failures_limit = pool ? pool->dns_failure_threshold : 3;
    dns->zone_ids = NULL;
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
     * The whole point: the pre-fix init leaves these two NON-NULL (garbage). The
     * FIXED init guarantees they are NULL after a failed first resolve. Detect
     * the garbage so a PLAIN build fails even without a heap guard.
     */
    if (s.dns != NULL) {
        CHECK(s.dns->last_connected != NULL,
              "expected pre-fix garbage in last_connected, got NULL "
              "(mirror drifted from the buggy code?)");
        CHECK(s.dns->request_counts != NULL,
              "expected pre-fix garbage in request_counts, got NULL "
              "(mirror drifted from the buggy code?)");
    }

    /*
     * REAL server_dns_deinit(): on the pre-fix dns it nc_free()s the two garbage
     * pointers -> wild free (ASan/libgmalloc trap here; a plain build may crash
     * or silently corrupt -- the asserts above already flagged it).
     */
    server_dns_deinit(&s);
    free_server_strings(&s);

    if (failures > 0) {
        printf("EXPECTED-FAIL (pre-fix no-NULL-init build): %d assertion(s) -- "
               "last_connected/request_counts left as garbage, REAL deinit wild-"
               "frees them\n", failures);
        return 1;
    }
    fprintf(stderr,
            "UNEXPECTED: pre-fix build saw both fields NULL -- the nc_alloc block "
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
        /* The failed first resolve must leave an EMPTY, consistent dns... */
        CHECK(s.dns->naddresses == 0,
              "naddresses=%u after failed first resolve (expected 0)",
              s.dns->naddresses);
        CHECK(s.dns->addresses == NULL,
              "addresses non-NULL after failed first resolve (expected NULL)");
        /* ...and crucially the two formerly-forgotten fields must be NULL, so
         * deinit does not wild-free them. */
        CHECK(s.dns->last_connected == NULL,
              "last_connected not NULL after init+failed-resolve -- deinit will "
              "wild-free it (fix #1 regressed)");
        CHECK(s.dns->request_counts == NULL,
              "request_counts not NULL after init+failed-resolve -- deinit will "
              "wild-free it (fix #1 regressed)");
    }

    /* REAL deinit: must be a clean free under every memory checker. */
    server_dns_deinit(&s);
    CHECK(s.dns == NULL, "server_dns_deinit did not NULL server->dns");

    free_server_strings(&s);

    if (failures == 0) {
        printf("OK: server_dns_init tolerates a failed first resolve leaving an "
               "empty, fully-NULLed dns; server_dns_deinit frees it with no wild "
               "free\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
#endif
}
