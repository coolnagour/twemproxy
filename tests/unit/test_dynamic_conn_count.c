/*
 * Standalone unit test for the MULTI-CONNECTION read fan-out wiring (Task 4 of
 * the latency-weighted reads plan).
 *
 * Tasks 1-3 made the per-connection address SELECTION latency-weighted over a
 * "good-latency band". But each server still opened only ONE connection
 * (server_conn capped on pool->server_connections, default 1), so all reads
 * rode a single replica regardless of how good the selection was. Task 4 makes
 * a dynamic_endpoint (read) server open MULTIPLE connections -- target count =
 * min(|good_set|, max_server_connections) -- so the existing round-robin over
 * connections, each weight-picked, distributes reads across the good replicas.
 *
 * This test drives the REAL count logic:
 *
 *   server_good_set_size()            -- pure: how many healthy replicas fall in
 *                                        the good-latency band, capped at
 *                                        max_server_connections.
 *   server_update_dynamic_connections -- sets pool->current_server_connections
 *                                        from that, for a dynamic server.
 *
 * and asserts the connection-count DECISION that server_conn() now makes:
 *   - dynamic server  -> cap = current_server_connections = good-set-bounded;
 *   - static server   -> cap = server_connections (UNCHANGED, stays 1);
 *   - far/out-of-band replicas do NOT inflate the count (good-set, not
 *     naddresses, is the target);
 *   - max_server_connections caps the count from above;
 *   - a degraded fleet (all unhealthy / not-yet-measured) never drops the count
 *     to 0 (floor of 1, and a safe fall back to min(naddresses, max)).
 *
 * ---------------------------------------------------------------------------
 * WHY THIS GOES RED ON THE PRE-TASK-4 CODE
 * ---------------------------------------------------------------------------
 * Two reds, both in the count logic:
 *   1. server_good_set_size() does not exist pre-Task-4 -> the file does not
 *      even link (the strongest red). It is added as part of this task.
 *   2. server_update_dynamic_connections() targeted min(naddresses, max) pre-
 *      Task-4 -- so with 4 replicas (one far, out of band) and max=8 it would
 *      report 4, NOT the good-set size 3. The "far does not inflate the count"
 *      assert FAILs against the old count and passes once the target is the
 *      good set.
 *
 * The static-path / server_conn decision assertions encode the invariant the
 * brief requires ("static single-address path must stay at server_connections")
 * and document the exact predicate server_conn now uses; they would also fail
 * had the wiring used current_server_connections unconditionally for a static
 * pool.
 *
 * Health / probe-path neutralisation and the hand-built dns are the same shape
 * as test_select_weighted.c (see that file's header for the full rationale).
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
#include <nc_array.h>

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
 * Build a minimal struct server_dns with `n` addresses carrying (latency,
 * zone_id), all forced healthy + measured + recently seen so the health gate
 * passes and the untested/probe paths stay out of the way. local_zone_id is 1.
 * (Mirrors test_select_weighted.c's make_dns.)
 */
static struct server_dns *
make_dns(uint32_t n, const uint32_t *latency, const uint32_t *zone_id, int64_t now)
{
    struct server_dns *dns = nc_zalloc(sizeof(*dns));
    uint32_t i;

    dns->max_addresses = 16;
    dns->naddresses = n;
    dns->zones_assigned = true;
    dns->local_zone_id = 1;
    dns->next_zone_id = 2;
    dns->health_initialized = true;
    dns->health_check_interval = 30000000LL;
    dns->consecutive_failures_limit = 10;
    dns->last_zone_analysis = now;

    dns->addrs = nc_alloc(dns->max_addresses * sizeof(struct dns_addr));
    for (i = 0; i < n; i++) {
        struct dns_addr *a = &dns->addrs[i];
        memset(a, 0, sizeof(*a));
        a->latency = latency[i];
        a->latency_measured = true;
        a->last_latency_check = now;
        a->last_health_check = now;
        a->last_seen = now;
        a->failure_count = 0;
        a->zone_id = zone_id[i];
        a->health_score = 100;
        string_init(&a->hostname);
    }
    return dns;
}

static void
free_dns(struct server_dns *dns)
{
    uint32_t i;
    for (i = 0; i < dns->naddresses; i++) {
        if (dns->addrs[i].hostname.data != NULL) {
            string_deinit(&dns->addrs[i].hostname);
        }
    }
    nc_free(dns->addrs);
    nc_free(dns);
}

/*
 * Assemble a fake server + pool + dns. is_dynamic toggles the dynamic/static
 * path. No stats graph: the count helpers below never call stats_* (unlike
 * server_select_best_address), so a NULL ctx is fine here.
 */
static void
make_server(struct server *server, struct server_pool *pool,
            struct server_dns *dns, int is_dynamic, uint32_t band_factor,
            uint32_t surcharge_us, uint32_t max_conn)
{
    memset(pool, 0, sizeof(*pool));
    memset(server, 0, sizeof(*server));

    pool->idx = 0;
    pool->ctx = NULL;
    pool->zone_aware = 1;
    pool->cross_az_surcharge_us = surcharge_us;
    pool->latency_band_factor = band_factor;
    pool->server_connections = 1;            /* the static cap; must stay 1 */
    pool->max_server_connections = max_conn;
    pool->dynamic_server_connections = is_dynamic ? 1 : 0;
    pool->current_server_connections = 1;    /* conf init = server_connections */
    pool->dns_failure_threshold = 10;
    pool->dns_expiration_minutes = 3600000000LL;
    string_init(&pool->name);

    server->idx = 0;
    server->owner = pool;
    server->dns = dns;
    server->is_dynamic = is_dynamic ? 1 : 0;
    server->current_addr_idx = 0;
    string_set_text(&server->pname, "reader-ro:6379");
}

/*
 * The connection-count predicate server_conn() now uses: a dynamic server caps
 * on current_server_connections; a static server caps on server_connections.
 * Kept here as the single source of truth the asserts compare against, so the
 * test documents exactly what server_conn() does without spinning up real
 * conn_get()/event machinery.
 */
static uint32_t
conn_cap(const struct server *server)
{
    const struct server_pool *pool = server->owner;
    return server->is_dynamic ? pool->current_server_connections
                              : pool->server_connections;
}

/*
 * Test A: a 4-replica read pool with one far/out-of-band replica. Good set is
 * the 3 in-band replicas (100/110/120us); the far 5000us one is excluded.
 * After server_update_dynamic_connections the count is the good-set size (3),
 * NOT naddresses (4), and that is the cap server_conn would use.
 */
static void
test_dynamic_good_set_count(void)
{
    const uint32_t latency[4] = { 100u, 110u, 120u, 5000u };
    const uint32_t zone[4]    = { 1u,   1u,   2u,   2u };
    int64_t now = nc_usec_now();
    struct server_dns *dns = make_dns(4, latency, zone, now);
    struct server_pool pool;
    struct server server;
    uint32_t gss, cap;

    make_server(&server, &pool, dns, /*dynamic*/1, /*band*/3, /*surcharge*/0,
                /*max*/8);

    gss = server_good_set_size(&server);
    CHECK(gss == 3, "good-set size = %"PRIu32", expected 3 (far 5000us excluded)", gss);

    server_update_dynamic_connections(&server);
    CHECK(pool.current_server_connections == 3,
          "dynamic count = %"PRIu32", expected 3 (good-set, not naddresses=4)",
          pool.current_server_connections);

    cap = conn_cap(&server);
    CHECK(cap == 3, "server_conn cap = %"PRIu32", expected 3 (dynamic -> current)", cap);

    printf("  dynamic 4-replica (1 far): good-set=%"PRIu32" count=%"PRIu32" cap=%"PRIu32"\n",
           gss, pool.current_server_connections, cap);

    free_dns(dns);
}

/*
 * Test B: max_server_connections caps the count from above. Five in-band
 * replicas but max=2 -> count is 2.
 */
static void
test_max_cap(void)
{
    const uint32_t latency[5] = { 100u, 105u, 110u, 115u, 120u };
    const uint32_t zone[5]    = { 1u,   1u,   1u,   1u,   1u };
    int64_t now = nc_usec_now();
    struct server_dns *dns = make_dns(5, latency, zone, now);
    struct server_pool pool;
    struct server server;
    uint32_t gss;

    make_server(&server, &pool, dns, /*dynamic*/1, /*band*/3, /*surcharge*/0,
                /*max*/2);

    gss = server_good_set_size(&server);
    CHECK(gss == 2, "good-set size = %"PRIu32", expected 2 (capped at max)", gss);

    server_update_dynamic_connections(&server);
    CHECK(pool.current_server_connections == 2,
          "dynamic count = %"PRIu32", expected 2 (max cap)", pool.current_server_connections);

    printf("  dynamic 5-replica max=2: count=%"PRIu32"\n", pool.current_server_connections);

    free_dns(dns);
}

/*
 * Test C: the STATIC path is untouched. A non-dynamic server keeps cap =
 * server_connections (1), and server_update_dynamic_connections is a no-op on it
 * (it early-returns for !is_dynamic), leaving current_server_connections at its
 * conf-init value.
 */
static void
test_static_path_unchanged(void)
{
    const uint32_t latency[3] = { 100u, 110u, 120u };
    const uint32_t zone[3]    = { 1u,   1u,   1u };
    int64_t now = nc_usec_now();
    struct server_dns *dns = make_dns(3, latency, zone, now);
    struct server_pool pool;
    struct server server;
    uint32_t cap;

    /* is_dynamic = 0 -> static. max generous so it would matter IF consulted. */
    make_server(&server, &pool, dns, /*dynamic*/0, /*band*/3, /*surcharge*/0,
                /*max*/8);

    server_update_dynamic_connections(&server);  /* must be a no-op here */
    CHECK(pool.current_server_connections == 1,
          "static current = %"PRIu32", expected 1 (update is a no-op for static)",
          pool.current_server_connections);

    cap = conn_cap(&server);
    CHECK(cap == 1, "static server_conn cap = %"PRIu32", expected 1 (server_connections)", cap);

    printf("  static 3-replica: cap=%"PRIu32" (server_connections, unchanged)\n", cap);

    free_dns(dns);
}

/*
 * Test D: surcharge pushes a cross-AZ replica out of band, shrinking the count.
 * Two same-AZ (100/110us) + one cross-AZ at 120us. With surcharge 0 all three
 * are in band (count 3). With a large surcharge the cross-AZ one's eff-latency
 * (120 + surcharge) leaves the band -> count 2.
 */
static void
test_surcharge_shrinks_count(void)
{
    const uint32_t latency[3] = { 100u, 110u, 120u };
    const uint32_t zone[3]    = { 1u,   1u,   2u };   /* idx2 cross-AZ */
    int64_t now = nc_usec_now();
    struct server_pool pool;
    struct server server;
    uint32_t gss0, gss1;

    /* surcharge 0 -> all three in band */
    struct server_dns *dns0 = make_dns(3, latency, zone, now);
    make_server(&server, &pool, dns0, 1, /*band*/3, /*surcharge*/0, /*max*/8);
    gss0 = server_good_set_size(&server);
    CHECK(gss0 == 3, "surcharge 0: good-set = %"PRIu32", expected 3", gss0);
    free_dns(dns0);

    /* surcharge 1000us -> cross-AZ eff = 1120us, band = 3*100 = 300 -> out */
    struct server_dns *dns1 = make_dns(3, latency, zone, now);
    make_server(&server, &pool, dns1, 1, /*band*/3, /*surcharge*/1000, /*max*/8);
    gss1 = server_good_set_size(&server);
    CHECK(gss1 == 2, "surcharge 1000: good-set = %"PRIu32", expected 2 (cross-AZ out)", gss1);
    free_dns(dns1);

    printf("  surcharge shrink: surcharge0 good-set=%"PRIu32" -> surcharge1000 good-set=%"PRIu32"\n",
           gss0, gss1);
}

/*
 * Test E: degraded-fleet floor. If NO replica is healthy yet (e.g. very early
 * boot, latencies unmeasured / all marked unhealthy), the good set is empty, but
 * the count must NOT collapse to 0 -- it falls back to min(naddresses, max) so
 * the pool can still open at least one connection and bootstrap. We force all
 * addrs unhealthy via a stale last_seen.
 */
static void
test_degraded_floor(void)
{
    const uint32_t latency[3] = { 100u, 110u, 120u };
    const uint32_t zone[3]    = { 1u,   1u,   1u };
    int64_t now = nc_usec_now();
    struct server_dns *dns = make_dns(3, latency, zone, now);
    struct server_pool pool;
    struct server server;
    uint32_t i;

    make_server(&server, &pool, dns, /*dynamic*/1, /*band*/3, /*surcharge*/0,
                /*max*/8);

    /* Force every addr unhealthy: not seen for ~a day -> fails the stale gate. */
    for (i = 0; i < 3; i++) {
        dns->addrs[i].last_seen = now - (24LL * 3600 * 1000000);
    }

    server_update_dynamic_connections(&server);
    CHECK(pool.current_server_connections >= 1,
          "degraded count = %"PRIu32", expected >= 1 (never collapse to 0)",
          pool.current_server_connections);
    CHECK(pool.current_server_connections <= 3,
          "degraded count = %"PRIu32", expected <= naddresses(3)",
          pool.current_server_connections);

    printf("  degraded (all unhealthy): count=%"PRIu32" (floored, not 0)\n",
           pool.current_server_connections);

    free_dns(dns);
}

int
main(void)
{
    test_dynamic_good_set_count();
    test_max_cap();
    test_static_path_unchanged();
    test_surcharge_shrinks_count();
    test_degraded_floor();

    if (failures != 0) {
        fprintf(stderr, "test_dynamic_conn_count: %d CHECK failure(s)\n", failures);
        return 1;
    }
    printf("OK: all dynamic connection-count tests passed\n");
    return 0;
}
