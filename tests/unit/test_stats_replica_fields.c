/*
 * Standalone unit test for the per-replica latency observability fields in the
 * stats JSON (Task 6 of the latency-weighted-reads plan).
 *
 * Task 6 adds three read-only fields to each entry of the per-server
 * address_details[] array emitted by server_get_read_hosts_info() (nc_server.c,
 * the fragment the HTTP stats endpoint embeds under "dns_hosts"):
 *
 *   eff_latency  -- server_addr_eff_latency(dns, i, pool->cross_az_surcharge_us)
 *   weight       -- the SAME integer weight used by selection:
 *                   WEIGHT_SCALE / (eff_latency + LATENCY_FLOOR_US), computed via
 *                   the shared server_addr_weight() helper so stats can never
 *                   drift from server_weighted_pick().
 *   in_good_set  -- whether the replica is in the current good-latency band
 *                   (built with server_build_good_set over the healthy set, the
 *                   exact membership selection uses).
 *
 * This test drives the REAL server_get_read_hosts_info() against a hand-built
 * dynamic server+pool+dns (no network), then string-parses the JSON it renders
 * and asserts the three fields are present and sane. It needs no ctx->stats:
 * the render reads only the dns + pool and calls server_is_healthy /
 * server_addr_eff_latency / server_build_good_set, none of which touch stats.
 *
 * Replicas (mirrors test_select_weighted): two same-AZ (100us, 110us), one
 * close cross-AZ (120us), one far cross-AZ (5000us). With band_factor 3 the far
 * one is out of band; with cross_az_surcharge_us 0 the eff_latency == latency.
 *
 * Red->green
 * ----------
 * Against the PRE-Task-6 tree the three fields are simply absent from the
 * rendered JSON, so every "field present" assertion fails -> non-zero exit (the
 * behavioural red). After Task 6 they are emitted with the values above ->
 * green. This is a single fixed build with no compile-time mirror variant, the
 * same shape as test_stats_http: the render is straight-line formatting, and the
 * field-presence assertions are themselves the red against the old code.
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

enum {
    IDX_NEAR_100 = 0,   /* same-AZ, 100us  */
    IDX_NEAR_110 = 1,   /* same-AZ, 110us  */
    IDX_CROSS_120 = 2,  /* cross-AZ close, 120us */
    IDX_FAR_5000 = 3    /* far, 5000us -- out of band */
};

/*
 * Build a minimal struct server_dns with `n` addresses carrying (latency,
 * zone_id). All addrs forced healthy + measured + recently seen so the health
 * gate passes. AF_INET sockaddr filled so inet_ntop renders an ip. local_zone_id
 * fixed to 1. (Lifted from test_select_weighted's make_dns, plus the hostname +
 * sockaddr the render path reads.)
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
    dns->next_zone_id = 3;                    /* two zones detected (1 local, 2 cross) */
    dns->health_initialized = true;
    dns->health_check_interval = 30000000LL;
    dns->consecutive_failures_limit = 10;
    dns->last_zone_analysis = now;
    dns->resolve_interval = 30000000LL;       /* 30s */
    dns->last_resolved = now;
    string_set_text(&dns->hostname, "reader-ro.cache.example.com");

    dns->addrs = nc_alloc(dns->max_addresses * sizeof(struct dns_addr));
    for (i = 0; i < n; i++) {
        struct dns_addr *a = &dns->addrs[i];
        struct sockaddr_in *in = (struct sockaddr_in *)&a->addr.addr;
        memset(a, 0, sizeof(*a));
        a->latency = latency[i];
        a->latency_measured = true;
        a->last_latency_check = now;
        a->last_health_check = now;
        a->last_seen = now;
        a->failure_count = 0;
        a->zone_id = zone_id[i];
        a->health_score = 100;
        a->request_count = 0;
        string_init(&a->hostname);

        /* A distinct, valid IPv4 per replica so inet_ntop renders cleanly. */
        in->sin_family = AF_INET;
        in->sin_port = htons(6379);
        in->sin_addr.s_addr = htonl(0x0A000001u + i); /* 10.0.0.1, .2, ... */
        a->addr.family = AF_INET;
        a->addr.addrlen = sizeof(struct sockaddr_in);
    }
    return dns;
}

static void
free_dns(struct server_dns *dns)
{
    uint32_t i;
    for (i = 0; i < dns->naddresses; i++) {
        /*
         * Per-addr hostnames are string_init'd (len 0, data NULL) here, so there
         * is nothing owned to free. (We never string_deinit dns->hostname or
         * server->pname/addrstr either: those are string_set_text references to
         * string literals -- non-owning -- so freeing them would abort.)
         */
        if (dns->addrs[i].hostname.data != NULL) {
            string_deinit(&dns->addrs[i].hostname);
        }
    }
    nc_free(dns->addrs);
    nc_free(dns);
}

static void
make_server(struct server *server, struct server_pool *pool,
            struct server_dns *dns, uint32_t surcharge_us)
{
    memset(pool, 0, sizeof(*pool));
    memset(server, 0, sizeof(*server));

    pool->idx = 0;
    pool->ctx = NULL;
    pool->zone_aware = 1;
    pool->zone_weight = 95;                      /* legacy knob; still rendered */
    pool->cross_az_surcharge_us = surcharge_us;
    pool->latency_band_factor = 3;               /* {100,110,120} in, 5000 out */
    pool->max_server_connections = 8;
    pool->current_server_connections = 3;
    pool->dynamic_server_connections = 1;
    pool->dns_failure_threshold = 10;
    pool->dns_expiration_minutes = 3600000000LL; /* never "stale" */
    string_init(&pool->name);

    server->idx = 0;
    server->owner = pool;
    server->dns = dns;
    server->is_dynamic = 1;
    server->current_addr_idx = IDX_NEAR_100;
    string_set_text(&server->pname, "reader-ro:6379");
    string_set_text(&server->addrstr, "reader-ro.cache.example.com");
}

/*
 * Return a pointer to the start of the i-th address object in the rendered
 * address_details[] array, by scanning for the i-th `"index": <i>` token. NULL
 * if not found. The render emits exactly one object per address in order.
 */
static const char *
nth_addr_object(const char *json, uint32_t idx)
{
    char needle[32];
    snprintf(needle, sizeof(needle), "\"index\": %"PRIu32, idx);
    return strstr(json, needle);
}

/*
 * Extract the unsigned integer value of `field` within the address object that
 * begins at `obj` (and ends before the next address object / the closing
 * bracket). Returns true + *out on success. `end` bounds the search so we do not
 * read a later object's same-named field.
 */
static bool
field_u64(const char *obj, const char *end, const char *field, uint64_t *out)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\": ", field);
    const char *p = strstr(obj, needle);
    if (p == NULL || (end != NULL && p >= end)) {
        return false;
    }
    p += strlen(needle);
    *out = strtoull(p, NULL, 10);
    return true;
}

/* Extract a boolean field ("true"/"false") within [obj, end). */
static bool
field_bool(const char *obj, const char *end, const char *field, bool *out)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\": ", field);
    const char *p = strstr(obj, needle);
    if (p == NULL || (end != NULL && p >= end)) {
        return false;
    }
    p += strlen(needle);
    if (strncmp(p, "true", 4) == 0) { *out = true; return true; }
    if (strncmp(p, "false", 5) == 0) { *out = false; return true; }
    return false;
}

/* Balanced-delimiter check: every '{' has a '}' and every '[' a ']'. */
static bool
json_balanced(const char *s)
{
    int curly = 0, square = 0;
    bool in_str = false;
    for (; *s; s++) {
        if (in_str) {
            if (*s == '\\') { if (s[1]) s++; continue; }
            if (*s == '"') in_str = false;
            continue;
        }
        switch (*s) {
        case '"': in_str = true; break;
        case '{': curly++; break;
        case '}': curly--; break;
        case '[': square++; break;
        case ']': square--; break;
        default: break;
        }
        if (curly < 0 || square < 0) return false;
    }
    return curly == 0 && square == 0;
}

/*
 * Main case: 4 replicas, surcharge 0. Assert each new field is present, the
 * eff_latency equals the measured latency (no surcharge), the fastest replica
 * has the largest weight, the far replica is out of the good set with a tiny
 * weight, and the document stays balanced JSON.
 */
static void
test_fields_present_and_sane(void)
{
    const uint32_t latency[4] = { 100u, 110u, 120u, 5000u };
    const uint32_t zone[4]    = { 1u,   1u,   2u,   2u };
    int64_t now = nc_usec_now();
    struct server_dns *dns = make_dns(4, latency, zone, now);
    struct server_pool pool;
    struct server server;
    char buf[16384];

    make_server(&server, &pool, dns, 0u);

    rstatus_t st = server_get_read_hosts_info(&server, "dns_hosts", buf, sizeof(buf));
    CHECK(st == NC_OK, "server_get_read_hosts_info must succeed");
    if (st != NC_OK) { free_dns(dns); return; }

    CHECK(json_balanced(buf), "rendered dns_hosts JSON must be balanced");

    /* Per-replica extraction. */
    uint64_t eff[4] = {0,0,0,0};
    uint64_t w[4]   = {0,0,0,0};
    bool ings[4]    = {false,false,false,false};
    uint32_t i;
    bool all_present = true;

    for (i = 0; i < 4; i++) {
        const char *obj = nth_addr_object(buf, i);
        const char *nxt = (i < 3) ? nth_addr_object(buf, i + 1) : NULL;
        CHECK(obj != NULL, "address object %"PRIu32" must be present", i);
        if (obj == NULL) { all_present = false; continue; }

        bool ok_eff = field_u64(obj, nxt, "eff_latency", &eff[i]);
        bool ok_w   = field_u64(obj, nxt, "weight", &w[i]);
        bool ok_ig  = field_bool(obj, nxt, "in_good_set", &ings[i]);
        CHECK(ok_eff, "replica %"PRIu32" must carry an \"eff_latency\" field", i);
        CHECK(ok_w, "replica %"PRIu32" must carry a \"weight\" field", i);
        CHECK(ok_ig, "replica %"PRIu32" must carry an \"in_good_set\" field", i);
        all_present = all_present && ok_eff && ok_w && ok_ig;
    }
    if (!all_present) { free_dns(dns); return; }

    /* eff_latency == measured latency when surcharge is 0 (incl. cross-AZ). */
    for (i = 0; i < 4; i++) {
        CHECK(eff[i] == latency[i],
              "replica %"PRIu32" eff_latency %"PRIu64" must equal latency %"PRIu32
              " at surcharge 0", i, eff[i], latency[i]);
    }

    /* weight matches WEIGHT_SCALE/(eff+LATENCY_FLOOR_US) exactly. */
    for (i = 0; i < 4; i++) {
        uint64_t expect = (uint64_t)WEIGHT_SCALE / (eff[i] + LATENCY_FLOOR_US);
        CHECK(w[i] == expect,
              "replica %"PRIu32" weight %"PRIu64" must equal %"PRIu64
              " (WEIGHT_SCALE/(eff+floor))", i, w[i], expect);
    }

    /* Fastest replica has the largest weight; far has the smallest. */
    CHECK(w[IDX_NEAR_100] > w[IDX_NEAR_110] &&
          w[IDX_NEAR_110] > w[IDX_CROSS_120] &&
          w[IDX_CROSS_120] > w[IDX_FAR_5000],
          "weights must decrease with latency: 100us=%"PRIu64" 110us=%"PRIu64
          " 120us=%"PRIu64" far=%"PRIu64,
          w[IDX_NEAR_100], w[IDX_NEAR_110], w[IDX_CROSS_120], w[IDX_FAR_5000]);

    /* Far replica's weight is tiny relative to the fastest (>10x smaller). */
    CHECK(w[IDX_FAR_5000] * 10 < w[IDX_NEAR_100],
          "far replica weight %"PRIu64" should be far below the fastest %"PRIu64,
          w[IDX_FAR_5000], w[IDX_NEAR_100]);

    /* Good-set membership: the three near replicas in, the far one out. */
    CHECK(ings[IDX_NEAR_100] && ings[IDX_NEAR_110] && ings[IDX_CROSS_120],
          "the three in-band replicas must report in_good_set=true "
          "(100=%d 110=%d 120=%d)",
          ings[IDX_NEAR_100], ings[IDX_NEAR_110], ings[IDX_CROSS_120]);
    CHECK(!ings[IDX_FAR_5000],
          "the far replica (5000us > 3*150) must report in_good_set=false");

    printf("  surcharge0: eff={%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"} "
           "w={%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"} "
           "in_good_set={%d,%d,%d,%d}\n",
           eff[0], eff[1], eff[2], eff[3],
           w[0], w[1], w[2], w[3],
           ings[0], ings[1], ings[2], ings[3]);

    free_dns(dns);
}

/*
 * Surcharge case: cross_az_surcharge_us = 1000 adds to the two cross-AZ replicas'
 * eff_latency (not the same-AZ ones), and pushes cross120 (120+1000=1120 >
 * 3*100=300) OUT of the good set, shrinking it to the two same-AZ replicas.
 * Proves eff_latency/weight/in_good_set all track the surcharge dial.
 */
static void
test_surcharge_shifts_fields(void)
{
    const uint32_t latency[4] = { 100u, 110u, 120u, 5000u };
    const uint32_t zone[4]    = { 1u,   1u,   2u,   2u };
    const uint32_t surcharge  = 1000u;
    int64_t now = nc_usec_now();
    struct server_dns *dns = make_dns(4, latency, zone, now);
    struct server_pool pool;
    struct server server;
    char buf[16384];

    make_server(&server, &pool, dns, surcharge);

    rstatus_t st = server_get_read_hosts_info(&server, "dns_hosts", buf, sizeof(buf));
    CHECK(st == NC_OK, "server_get_read_hosts_info (surcharge) must succeed");
    if (st != NC_OK) { free_dns(dns); return; }
    CHECK(json_balanced(buf), "rendered JSON (surcharge) must be balanced");

    uint64_t eff[4] = {0,0,0,0};
    bool ings[4]    = {false,false,false,false};
    uint32_t i;
    for (i = 0; i < 4; i++) {
        const char *obj = nth_addr_object(buf, i);
        const char *nxt = (i < 3) ? nth_addr_object(buf, i + 1) : NULL;
        CHECK(obj != NULL, "address object %"PRIu32" present (surcharge)", i);
        if (obj == NULL) { free_dns(dns); return; }
        CHECK(field_u64(obj, nxt, "eff_latency", &eff[i]), "eff_latency present");
        CHECK(field_bool(obj, nxt, "in_good_set", &ings[i]), "in_good_set present");
    }

    /* Same-AZ unchanged; cross-AZ gets +surcharge. */
    CHECK(eff[IDX_NEAR_100] == 100, "same-AZ eff_latency unchanged by surcharge, got %"PRIu64, eff[IDX_NEAR_100]);
    CHECK(eff[IDX_NEAR_110] == 110, "same-AZ eff_latency unchanged by surcharge, got %"PRIu64, eff[IDX_NEAR_110]);
    CHECK(eff[IDX_CROSS_120] == 120 + surcharge,
          "cross-AZ eff_latency must be latency+surcharge=%u, got %"PRIu64,
          120 + surcharge, eff[IDX_CROSS_120]);
    CHECK(eff[IDX_FAR_5000] == 5000 + surcharge,
          "far cross-AZ eff_latency must be latency+surcharge=%u, got %"PRIu64,
          5000 + surcharge, eff[IDX_FAR_5000]);

    /* The surcharge pushes cross120 out of band: only the two same-AZ remain. */
    CHECK(ings[IDX_NEAR_100] && ings[IDX_NEAR_110],
          "the two same-AZ replicas stay in the good set under surcharge");
    CHECK(!ings[IDX_CROSS_120],
          "cross120 (eff 1120 > 3*100) must drop OUT of the good set under surcharge");
    CHECK(!ings[IDX_FAR_5000], "far replica stays out of the good set under surcharge");

    printf("  surcharge%u: eff={%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"} "
           "in_good_set={%d,%d,%d,%d}\n",
           surcharge, eff[0], eff[1], eff[2], eff[3],
           ings[0], ings[1], ings[2], ings[3]);

    free_dns(dns);
}

int
main(void)
{
    test_fields_present_and_sane();
    test_surcharge_shifts_fields();

    if (failures == 0) {
        printf("OK: all per-replica stats-field tests passed\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
}
