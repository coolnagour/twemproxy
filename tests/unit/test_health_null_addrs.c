/*
 * Regression test for the NULL-addrs health-check crash found by the
 * latency-weighted-reads docker integration test (tests/docker/run-latency.sh).
 *
 * THE BUG
 * -------
 * On a dynamic_endpoint (read) pool's FIRST DNS resolution,
 * server_dns_resolve() published the resolved count (dns->naddresses = N) and
 * then called server_update_dynamic_connections() BEFORE allocating the
 * dns->addrs array. Since Task 4 that sizing path walks the addresses to build
 * the good-latency set:
 *
 *   server_update_dynamic_connections
 *     -> server_good_set_size
 *        -> for i in 0..naddresses: server_is_healthy(server, i)
 *           -> server_health_check(server, i)
 *              -> a = &dns->addrs[i];  a->last_health_check  // NULL deref
 *
 * The bound check `addr_idx >= naddresses` passed (0 < N) but dns->addrs was
 * still NULL, so dereferencing &dns->addrs[0] SIGSEGV'd the daemon on boot --
 * exactly when a read pool resolves to >= 1 address with
 * dynamic_server_connections on (the production read-pool shape). It crashed the
 * process before the event loop even started.
 *
 * THE FIX (two parts, both in src/nc_server.c)
 * --------------------------------------------
 *   1. Root cause: server_dns_resolve() now calls
 *      server_update_dynamic_connections() AFTER dns->addrs is allocated and
 *      every entry is dns_addr_init'd (first-resolution path), matching the
 *      accumulate path which already did.
 *   2. Defense in depth: server_health_check() and server_is_healthy() now also
 *      guard `dns->addrs == NULL` (not just the index bound), so no future
 *      caller can re-trigger this NULL deref.
 *
 * WHAT THIS TEST DRIVES
 * ---------------------
 * It cannot easily reproduce the resolve-path ORDERING from a unit (that needs
 * the real resolver, intercepted via --wrap, which is GNU-ld only -- see
 * test_dns_resolve_integration.c). Instead it asserts the safety CONTRACT that
 * the crash violated, against the REAL functions in nc_server.c: with a dynamic
 * server whose dns has naddresses > 0 but addrs == NULL, none of the health /
 * good-set / connection-sizing entry points may crash; they must return the
 * safe "nothing to do" answer.
 *
 * RED vs GREEN: on the FIXED tree this exits 0. On a tree where part 2 (the
 * addrs==NULL guard) is reverted, server_health_check() dereferences the NULL
 * array and this test SIGSEGVs (non-zero) -- the regression is caught without
 * docker, on macOS and in CI alike.
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
#include <nc_conf.h>
#include <nc_string.h>

/* nc.c owns main(); stub nc_post_run for the linker (see sibling tests). */
void nc_post_run(struct instance *nci) { (void)nci; }

static int failures = 0;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);               \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n");                                             \
        }                                                                      \
    } while (0)

/*
 * Build a dynamic server + pool whose dns reports naddresses = n but has NOT
 * allocated its addrs array yet -- the exact transient state the first-
 * resolution path passed to the sizing code before the fix. addrs stays NULL.
 */
static void
make_server_naddrs_no_addrs(struct server *server, struct server_pool *pool,
                            struct server_dns *dns, uint32_t n)
{
    memset(pool, 0, sizeof(*pool));
    memset(server, 0, sizeof(*server));
    memset(dns, 0, sizeof(*dns));

    pool->idx = 0;
    pool->ctx = NULL;
    pool->zone_aware = 1;
    pool->cross_az_surcharge_us = 0;
    pool->latency_band_factor = CONF_DEFAULT_LATENCY_BAND_FACTOR;
    pool->server_connections = 1;
    pool->max_server_connections = 8;
    pool->dynamic_server_connections = 1;          /* the read-pool shape */
    pool->current_server_connections = 1;
    pool->dns_failure_threshold = 3;
    pool->dns_expiration_minutes = 3600000000LL;
    string_init(&pool->name);

    dns->max_addresses = 16;
    dns->naddresses = n;                           /* count published... */
    dns->addrs = NULL;                             /* ...array NOT built yet */
    dns->zones_assigned = false;
    dns->local_zone_id = 0;
    dns->next_zone_id = 1;
    dns->health_initialized = false;
    dns->health_check_interval = 30000000LL;
    dns->consecutive_failures_limit = 3;
    string_init(&dns->hostname);

    server->idx = 0;
    server->owner = pool;
    server->dns = dns;
    server->is_dynamic = 1;
    server->current_addr_idx = 0;
    string_set_text(&server->pname, "reader-ro:6379");
}

/*
 * The crash site: server_is_healthy(i) -> server_health_check(i) on every
 * index while addrs is NULL. Must NOT deref the NULL array. server_is_healthy
 * returns true ("assume healthy if we can't check") on the guarded path; the
 * point of the assert is simply that we got here at all (no SIGSEGV).
 */
static void
test_is_healthy_null_addrs_does_not_crash(void)
{
    struct server server;
    struct server_pool pool;
    struct server_dns dns;
    uint32_t i;

    make_server_naddrs_no_addrs(&server, &pool, &dns, 3);

    for (i = 0; i < dns.naddresses; i++) {
        bool h = server_is_healthy(&server, i);   /* pre-fix: SIGSEGV here */
        CHECK(h == true,
              "server_is_healthy(addr %"PRIu32") with addrs==NULL should be the "
              "safe default true, got false", i);
    }
    printf("  server_is_healthy survived addrs==NULL for all %"PRIu32" indices\n",
           dns.naddresses);
}

/*
 * server_good_set_size() walks every index calling server_is_healthy(); with
 * addrs == NULL nothing can be healthy, so it must return 0 -- and, critically,
 * must not crash getting there.
 */
static void
test_good_set_size_null_addrs_is_zero(void)
{
    struct server server;
    struct server_pool pool;
    struct server_dns dns;
    uint32_t gss;

    make_server_naddrs_no_addrs(&server, &pool, &dns, 3);

    gss = server_good_set_size(&server);           /* pre-fix: SIGSEGV */
    CHECK(gss == 0,
          "good_set_size with addrs==NULL should be 0, got %"PRIu32, gss);
    printf("  server_good_set_size(addrs==NULL) = %"PRIu32" (expected 0)\n", gss);
}

/*
 * server_update_dynamic_connections() is what the resolve path actually called
 * too early. With addrs == NULL the good set is empty, so it falls back to
 * min(naddresses, max) and floors at >= 1 -- never collapsing the pool and,
 * above all, never crashing.
 */
static void
test_update_dynamic_connections_null_addrs(void)
{
    struct server server;
    struct server_pool pool;
    struct server_dns dns;

    make_server_naddrs_no_addrs(&server, &pool, &dns, 3);

    server_update_dynamic_connections(&server);    /* pre-fix: SIGSEGV */
    CHECK(pool.current_server_connections >= 1,
          "current_server_connections with addrs==NULL should floor at >=1, got %"PRIu32,
          pool.current_server_connections);
    CHECK(pool.current_server_connections <= dns.naddresses,
          "current_server_connections (%"PRIu32") should be <= naddresses (%"PRIu32")",
          pool.current_server_connections, dns.naddresses);
    printf("  server_update_dynamic_connections(addrs==NULL) -> count=%"PRIu32
           " (floored, no crash)\n", pool.current_server_connections);
}

int
main(void)
{
    test_is_healthy_null_addrs_does_not_crash();
    test_good_set_size_null_addrs_is_zero();
    test_update_dynamic_connections_null_addrs();

    if (failures != 0) {
        fprintf(stderr, "test_health_null_addrs: %d CHECK failure(s)\n", failures);
        return 1;
    }
    printf("OK: health/good-set/connection-sizing all safe with addrs==NULL\n");
    return 0;
}
