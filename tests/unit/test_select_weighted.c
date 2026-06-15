/*
 * Standalone unit test for the UNIFIED latency-weighted read selection in
 * server_select_best_address() (Task 3 of the latency-weighted reads plan).
 *
 * Tasks 1 and 2 added the pure helpers (server_weighted_pick,
 * server_addr_eff_latency, server_build_good_set) and their own tests. Task 3
 * REPLACES the old discrete same-zone%/uniform tail of server_select_best_address
 * with: build the good-latency band -> weighted-random pick over it. This test
 * drives the REAL server_select_best_address() end to end and asserts the new
 * behaviour:
 *
 *   - a far/out-of-band replica (eff_latency well past band_factor*min) is NEVER
 *     chosen by the selection tail;
 *   - the in-band replicas get traffic roughly inverse-latency-weighted (the
 *     fastest takes the largest share, ordering strictly preserved);
 *   - the same_zone_selections / cross_zone_selections counters are incremented
 *     according to whether the CHOSEN address is local-zone;
 *   - a single healthy replica degenerates to "always that one".
 *
 * ---------------------------------------------------------------------------
 * WHY THIS GOES RED ON THE PRE-TASK-3 CODE
 * ---------------------------------------------------------------------------
 * The pre-Task-3 tail picked `healthy_servers[random()%healthy_count]` in its
 * "distributed" branch -- which INCLUDES the far replica -- so the far replica
 * drew a meaningful (~several %) share, and the distribution was uniform-ish
 * rather than inverse-latency-weighted. The "far is never chosen" + "inverse-
 * weighted ordering" asserts below therefore FAIL against the old code (RED) and
 * pass once the tail is the good-band + weighted pick (GREEN).
 *
 * ---------------------------------------------------------------------------
 * HOW THE PROBE PATHS ARE NEUTRALISED (no production change -- inputs only)
 * ---------------------------------------------------------------------------
 * server_select_best_address runs three paths BEFORE the weighting tail, and the
 * task requires they stay EXACTLY as-is. We make them no-ops for this test purely
 * by choosing the dns fields they gate on:
 *
 *   1. untested-prioritise: skipped because every addr has latency_measured=true.
 *   2. periodic-probe: skipped because every addr's last_latency_check is recent
 *      (set to nc_usec_now()), so none looks "stale" (>5 min) to probe.
 *      server_detect_zones_by_latency is likewise rate-limited (last_zone_analysis
 *      = now), so it returns early and leaves our hand-assigned zone_ids intact.
 *   3. ~5% random-probe: this path returns `healthy_servers[random()%healthy]`
 *      ONLY when that index != server->current_addr_idx. We pin current_addr_idx
 *      to the FAR replica's index, so on the ~5% of draws the random probe lands
 *      on the far replica it is suppressed (== current) and falls through to the
 *      weighted tail (which excludes the far one); on the other random-probe
 *      draws it returns an in-band replica. Net: the far replica is NEVER
 *      returned by ANY path, while the small residual random-probe traffic only
 *      ever lands on in-band replicas -- so "far never chosen" holds exactly and
 *      the in-band ordering is unaffected (the residual just nudges the in-band
 *      shares a hair toward uniform; the assertions below tolerate that).
 *
 * Health is forced ON: is_dynamic=1, health_score=100, failure_count=0,
 * last_seen recent, and pool->dns_failure_threshold (which server_health_check
 * copies into dns->consecutive_failures_limit on its first run) set well above 0.
 *
 * ---------------------------------------------------------------------------
 * STATS GRAPH
 * ---------------------------------------------------------------------------
 * server_select_best_address calls stats_server_set/incr, which walk
 * ctx->stats->current[pool_idx].server[server_idx].metric[field]. We build that
 * object graph by hand with the real array API (one pool, one server,
 * STATS_SERVER_NFIELD zeroed metrics) so the REAL stats functions run and we can
 * read the same_zone_selections / cross_zone_selections counters back. We do NOT
 * use stats_create(): its worker thread dereferences st->owner->shared_mem
 * (never set for a bare struct), which would crash a unit test.
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
#include <nc_stats.h>

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

/* Index meanings used throughout (latency / zone): kept as named constants so
 * the asserts read clearly. zone 1 == local (same-AZ). */
enum {
    IDX_NEAR_100 = 0,   /* same-AZ, 100us  */
    IDX_NEAR_110 = 1,   /* same-AZ, 110us  */
    IDX_CROSS_120 = 2,  /* cross-AZ close, 120us */
    IDX_FAR_5000 = 3    /* far, 5000us -- out of band */
};

/*
 * Build a minimal struct server_dns with `n` addresses carrying (latency,
 * zone_id). All addrs are forced healthy + measured + recently seen/checked so
 * the health gate passes and the untested/probe paths are skipped. local_zone_id
 * is fixed to 1. now is the clock captured once by the caller.
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
    dns->health_initialized = true;          /* skip the first-run reinit branch */
    dns->health_check_interval = 30000000LL; /* 30s; with recent last_health_check -> no recompute */
    dns->consecutive_failures_limit = 10;    /* failure_count(0) < this -> healthy */
    dns->last_zone_analysis = now;           /* rate-limit zone detection + probe counter */

    dns->addrs = nc_alloc(dns->max_addresses * sizeof(struct dns_addr));
    for (i = 0; i < n; i++) {
        struct dns_addr *a = &dns->addrs[i];
        memset(a, 0, sizeof(*a));
        a->latency = latency[i];
        a->latency_measured = true;     /* skip untested-prioritise */
        a->last_latency_check = now;    /* recent -> skip periodic-probe */
        a->last_health_check = now;     /* recent -> server_health_check no-ops */
        a->last_seen = now;             /* recent -> not "stale in DNS" */
        a->failure_count = 0;
        a->zone_id = zone_id[i];
        a->health_score = 100;          /* > 30 -> healthy */
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
 * Hand-build ctx->stats so the real stats_server_set/incr resolve. One pool, one
 * server, STATS_SERVER_NFIELD zeroed metrics. We deliberately do NOT call
 * stats_create (its worker thread would crash on a bare context). Returns the
 * struct stats by out-param; caller frees with free_stats.
 */
static void
build_stats(struct stats *st)
{
    struct stats_pool *stp;
    struct stats_server *sts;
    uint32_t f;
    rstatus_t status;

    memset(st, 0, sizeof(*st));
    array_null(&st->current);

    status = array_init(&st->current, 1, sizeof(struct stats_pool));
    CHECK(status == NC_OK, "stats current array_init failed");

    stp = array_push(&st->current);
    memset(stp, 0, sizeof(*stp));
    string_init(&stp->name);
    array_null(&stp->metric);
    array_null(&stp->server);
    array_null(&stp->latency);

    status = array_init(&stp->server, 1, sizeof(struct stats_server));
    CHECK(status == NC_OK, "stats pool server array_init failed");

    sts = array_push(&stp->server);
    memset(sts, 0, sizeof(*sts));
    string_init(&sts->name);
    array_null(&sts->metric);
    array_null(&sts->latency);

    status = array_init(&sts->metric, STATS_SERVER_NFIELD, sizeof(struct stats_metric));
    CHECK(status == NC_OK, "stats server metric array_init failed");
    for (f = 0; f < STATS_SERVER_NFIELD; f++) {
        struct stats_metric *stm = array_push(&sts->metric);
        memset(stm, 0, sizeof(*stm));
        /* type left STATS_INVALID(0): the type ASSERTs in _stats_server_* are
         * no-ops in this (non-debug) build, and we only read .value.counter. */
        string_init(&stm->name);
    }
}

static void
free_stats(struct stats *st)
{
    struct stats_pool *stp = array_get(&st->current, 0);
    struct stats_server *sts = array_get(&stp->server, 0);
    array_deinit(&sts->metric);
    array_deinit(&stp->server);
    array_deinit(&st->current);
}

/* Read a server stats counter back out of the hand-built graph. */
static int64_t
read_counter(struct stats *st, stats_server_field_t fidx)
{
    struct stats_pool *stp = array_get(&st->current, 0);
    struct stats_server *sts = array_get(&stp->server, 0);
    struct stats_metric *stm = array_get(&sts->metric, fidx);
    return stm->value.counter;
}

/*
 * Assemble a fake server + pool + dns wired for the zone-aware weighted tail.
 * current_addr_idx is pinned to the FAR replica so the residual ~5% random-probe
 * never returns it (see the file header).
 */
static void
make_server(struct server *server, struct server_pool *pool, struct context *ctx,
            struct stats *st, struct server_dns *dns)
{
    memset(pool, 0, sizeof(*pool));
    memset(server, 0, sizeof(*server));
    memset(ctx, 0, sizeof(*ctx));

    ctx->stats = st;

    pool->idx = 0;
    pool->ctx = ctx;
    pool->zone_aware = 1;
    pool->zone_weight = 25;                      /* legacy knob; tail no longer uses it */
    pool->cross_az_surcharge_us = 0;             /* pure latency */
    pool->latency_band_factor = 3;               /* {100,110,120} in, 5000 out */
    pool->max_server_connections = 8;            /* cap (> good-set size, so no cap effect) */
    pool->dns_failure_threshold = 10;            /* copied into dns->consecutive_failures_limit on first health check */
    pool->dns_expiration_minutes = 3600000000LL; /* huge -> never "stale" in the health gate */
    string_init(&pool->name);

    server->idx = 0;
    server->owner = pool;
    server->dns = dns;
    server->is_dynamic = 1;
    server->current_addr_idx = IDX_FAR_5000;     /* pin to far -> random-probe suppresses far */
    string_set_text(&server->pname, "reader-ro:6379");
}

/*
 * Test A: full 4-replica distribution. Far never chosen; in-band inverse-latency-
 * weighted (near100 > near110 > cross120); zone counters tracked.
 */
static void
test_weighted_distribution(void)
{
    const uint32_t latency[4] = { 100u, 110u, 120u, 5000u };
    const uint32_t zone[4]    = { 1u,   1u,   2u,   2u };   /* far also cross-AZ */
    const uint32_t draws      = 200000u;
    int64_t now = nc_usec_now();
    struct server_dns *dns = make_dns(4, latency, zone, now);
    struct stats st;
    struct context ctx;
    struct server_pool pool;
    struct server server;
    uint64_t counts[4] = { 0, 0, 0, 0 };
    uint32_t d;
    int64_t same, cross;
    double s0, s1, s2;

    build_stats(&st);
    make_server(&server, &pool, &ctx, &st, dns);

    for (d = 0; d < draws; d++) {
        uint32_t pick = server_select_best_address(&server);
        CHECK(pick < 4, "pick %"PRIu32" out of range", pick);
        if (pick < 4) {
            counts[pick]++;
        }
    }

    /* (1) The far/out-of-band replica is NEVER chosen. */
    CHECK(counts[IDX_FAR_5000] == 0,
          "far replica (5000us) chosen %" PRIu64 " times -- must be 0 (out of band)",
          counts[IDX_FAR_5000]);

    /* (2) All three in-band replicas get traffic. */
    CHECK(counts[IDX_NEAR_100] > 0 && counts[IDX_NEAR_110] > 0 && counts[IDX_CROSS_120] > 0,
          "in-band replica starved: near100=%" PRIu64 " near110=%" PRIu64 " cross120=%" PRIu64,
          counts[IDX_NEAR_100], counts[IDX_NEAR_110], counts[IDX_CROSS_120]);

    /* (3) Inverse-latency ordering: faster gets more. */
    CHECK(counts[IDX_NEAR_100] > counts[IDX_NEAR_110],
          "near100 (%" PRIu64 ") should beat near110 (%" PRIu64 ")",
          counts[IDX_NEAR_100], counts[IDX_NEAR_110]);
    CHECK(counts[IDX_NEAR_110] > counts[IDX_CROSS_120],
          "near110 (%" PRIu64 ") should beat cross120 (%" PRIu64 ")",
          counts[IDX_NEAR_110], counts[IDX_CROSS_120]);

    /*
     * (4) Shares roughly match inverse-eff-latency weights (floor 50):
     *   w100=1e6/150=6666, w110=1e6/160=6250, w120=1e6/170=5882; total 18798
     *   -> 0.3546 / 0.3325 / 0.3129. The residual random-probe nudges these a
     *   hair toward uniform, so allow a generous +-4% absolute band.
     */
    s0 = (double)counts[IDX_NEAR_100] / (double)draws;
    s1 = (double)counts[IDX_NEAR_110] / (double)draws;
    s2 = (double)counts[IDX_CROSS_120] / (double)draws;
    CHECK(s0 > 0.3546 - 0.04 && s0 < 0.3546 + 0.04,
          "near100 share %.4f outside 0.3546+-0.04", s0);
    CHECK(s1 > 0.3325 - 0.04 && s1 < 0.3325 + 0.04,
          "near110 share %.4f outside 0.3325+-0.04", s1);
    CHECK(s2 > 0.3129 - 0.04 && s2 < 0.3129 + 0.04,
          "cross120 share %.4f outside 0.3129+-0.04", s2);

    /*
     * (5) Zone counters: the weighted-pick tail increments same_zone_selections
     * for a local-zone choice (near100, near110) and cross_zone_selections for a
     * cross-zone choice (cross120). Both must be > 0, and same-zone dominates
     * (two local in-band vs one cross-zone in-band). (The residual random-probe
     * path does NOT touch these counters, so they reflect the weighted tail.)
     */
    same  = read_counter(&st, STATS_SERVER_same_zone_selections);
    cross = read_counter(&st, STATS_SERVER_cross_zone_selections);
    CHECK(same > 0, "same_zone_selections is %" PRId64 ", expected > 0", same);
    CHECK(cross > 0, "cross_zone_selections is %" PRId64 ", expected > 0", cross);
    CHECK(same > cross,
          "same_zone_selections (%" PRId64 ") should exceed cross (%" PRId64 ")",
          same, cross);

    printf("  weighted dist: near100=%.4f near110=%.4f cross120=%.4f far=%" PRIu64
           " | same=%" PRId64 " cross=%" PRId64 "\n",
           s0, s1, s2, counts[IDX_FAR_5000], same, cross);

    free_stats(&st);
    free_dns(dns);
}

/*
 * Test B: single healthy replica degenerates to "always that one". With two
 * addresses where only one is healthy, the healthy_count==1 fast path returns
 * it every time. We force addr1 unhealthy via a stale last_seen.
 */
static void
test_single_healthy_degenerate(void)
{
    const uint32_t latency[2] = { 250u, 100u };
    const uint32_t zone[2]    = { 1u,   2u };
    const uint32_t draws      = 1000u;
    int64_t now = nc_usec_now();
    struct server_dns *dns = make_dns(2, latency, zone, now);
    struct stats st;
    struct context ctx;
    struct server_pool pool;
    struct server server;
    uint32_t d;

    build_stats(&st);
    make_server(&server, &pool, &ctx, &st, dns);
    server.current_addr_idx = 0; /* the one healthy addr */

    /* Force addr1 unhealthy: not seen in DNS for ages -> fails the stale gate. */
    dns->addrs[1].last_seen = now - (24LL * 3600 * 1000000); /* ~1 day ago */

    for (d = 0; d < draws; d++) {
        uint32_t pick = server_select_best_address(&server);
        CHECK(pick == 0,
              "single-healthy pick=%"PRIu32" expected 0 (only addr0 healthy)", pick);
    }

    printf("  single-healthy degenerate: addr0 chosen on all %u draws\n", draws);

    free_stats(&st);
    free_dns(dns);
}

int
main(void)
{
    /*
     * Deterministic seed: server_weighted_pick / the probe paths read random()
     * but never seed it (the process seeds once at startup in nc_pre_run()).
     * Seeding here makes the draw counts reproducible so the asserted shares are
     * stable across runs/platforms.
     */
    srandom(1);

    test_weighted_distribution();
    test_single_healthy_degenerate();

    if (failures == 0) {
        printf("OK: all unified latency-weighted selection tests passed\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
}
