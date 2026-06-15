/*
 * Standalone unit test for the effective-latency + good-latency-band helpers
 * (Task 2 of the latency-weighted reads plan):
 *
 *   server_addr_eff_latency(dns, i, surcharge_us)
 *       -> dns->addrs[i].latency + (cross_az ? surcharge_us : 0),
 *          where cross_az = (dns->addrs[i].zone_id != dns->local_zone_id).
 *
 *   server_build_good_set(healthy_idxs, eff_latency, healthy_count,
 *                         band_factor, max_count, out_idxs, out_eff_latency)
 *       -> writes the subset of healthy indices whose eff_latency is within
 *          band_factor*min_eff_latency, SORTED ASCENDING by eff_latency, capped
 *          at max_count (lowest-eff members kept first). Returns the count.
 *
 * Both are NON-static in nc_server.c so this test drives the REAL code -- they
 * are pure and allocation-free (caller-provided output buffers), no network/DNS,
 * so no mirror is needed (cf. test_dns_resolve_oom.c which mirrors unreachable
 * inline code). server_build_good_set allocates nothing, so there is nothing to
 * leak; the macOS `leaks` run still guards against any accidental allocation.
 *
 * ---------------------------------------------------------------------------
 * WHAT WE ASSERT (the contract from the spec/plan)
 * ---------------------------------------------------------------------------
 *   1. eff_latency: a same-AZ addr is unchanged by the surcharge; a cross-AZ addr
 *      gets +surcharge_us.
 *   2. Good set {same-az 100, cross-az 120 (surcharge 0), far 5000}, band 3 ->
 *      {100,120} (min=100, threshold=300; 5000 dropped). Sorted ascending.
 *   3. With surcharge_us=2000 the cross-az addr's eff_latency becomes 2120, which
 *      exceeds the 300 threshold -> good set {100} only.
 *   4. Output is sorted ascending by eff_latency even when the healthy input is
 *      given out of order.
 *   5. The max_count cap is honoured (and keeps the LOWEST-eff members).
 *
 * This is the TDD evidence: written BEFORE the helpers existed, so the first
 * harness run failed to resolve the symbols at link time (RED); the asserts go
 * GREEN once the helpers are implemented.
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
 * Build a minimal struct server_dns with `n` addresses carrying the given
 * per-addr (latency, zone_id). local_zone_id is fixed to 1 (so zone_id==1 is
 * same-AZ, anything else is cross-AZ). Only the fields the helpers read are set;
 * hostnames are left empty (string_init) so free_dns is trivially clean.
 */
static struct server_dns *
make_dns(uint32_t n, const uint32_t *latency, const uint32_t *zone_id)
{
    struct server_dns *dns = nc_zalloc(sizeof(*dns));
    uint32_t i;

    dns->max_addresses = 16;
    dns->naddresses = n;
    dns->zones_assigned = true;
    dns->local_zone_id = 1;
    dns->next_zone_id = 2;

    dns->addrs = nc_alloc(dns->max_addresses * sizeof(struct dns_addr));
    for (i = 0; i < n; i++) {
        struct dns_addr *a = &dns->addrs[i];
        memset(a, 0, sizeof(*a));
        a->latency = latency[i];
        a->latency_measured = true;
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

/* Test 1: effective latency = latency + (cross_az ? surcharge : 0). */
static void
test_eff_latency(void)
{
    /* addr0 same-AZ (zone 1), addr1 cross-AZ (zone 2). */
    const uint32_t latency[2] = { 100u, 120u };
    const uint32_t zone[2]    = { 1u, 2u };
    struct server_dns *dns = make_dns(2, latency, zone);

    /* surcharge 0: both unchanged. */
    CHECK(server_addr_eff_latency(dns, 0, 0u) == 100u,
          "same-az eff(0,surcharge=0)=%"PRIu32" expected 100",
          server_addr_eff_latency(dns, 0, 0u));
    CHECK(server_addr_eff_latency(dns, 1, 0u) == 120u,
          "cross-az eff(1,surcharge=0)=%"PRIu32" expected 120",
          server_addr_eff_latency(dns, 1, 0u));

    /* surcharge 2000: same-az unchanged, cross-az +2000. */
    CHECK(server_addr_eff_latency(dns, 0, 2000u) == 100u,
          "same-az eff(0,surcharge=2000)=%"PRIu32" expected 100 (no surcharge for same-AZ)",
          server_addr_eff_latency(dns, 0, 2000u));
    CHECK(server_addr_eff_latency(dns, 1, 2000u) == 2120u,
          "cross-az eff(1,surcharge=2000)=%"PRIu32" expected 2120",
          server_addr_eff_latency(dns, 1, 2000u));

    free_dns(dns);
}

/*
 * Test 2: good set {same-az 100, cross-az 120 (surcharge 0), far 5000}, band 3.
 * min eff = 100, threshold = 300. addr2 (5000) drops out -> {100,120} sorted asc.
 */
static void
test_good_set_basic(void)
{
    const uint32_t healthy[3] = { 0u, 1u, 2u };
    const uint32_t eff[3]     = { 100u, 120u, 5000u };
    uint32_t out_idx[3];
    uint32_t out_eff[3];
    uint32_t k;

    k = server_build_good_set(healthy, eff, 3, /*band*/3u, /*max*/8u,
                              out_idx, out_eff);

    CHECK(k == 2, "good set size %"PRIu32" expected 2", k);
    if (k == 2) {
        CHECK(out_idx[0] == 0 && out_eff[0] == 100u,
              "good[0]=idx%"PRIu32"/eff%"PRIu32" expected idx0/100",
              out_idx[0], out_eff[0]);
        CHECK(out_idx[1] == 1 && out_eff[1] == 120u,
              "good[1]=idx%"PRIu32"/eff%"PRIu32" expected idx1/120",
              out_idx[1], out_eff[1]);
    }
    /* the far one (5000) must NOT appear. */
    for (k = 0; k < 2; k++) {
        CHECK(out_idx[k] != 2u, "far addr idx2 wrongly in good set at slot %"PRIu32, k);
    }
    /* This case feeds eff[] directly (no dns), so there is nothing to free. */
}

/*
 * Test 3: with the cross-AZ surcharge applied UPSTREAM (eff already includes it),
 * the cross-AZ replica's eff becomes 2120, above the 300 threshold -> good set
 * collapses to {100}. We compute eff via server_addr_eff_latency to prove the
 * two helpers compose the way Task 3 will wire them.
 */
static void
test_good_set_surcharge_excludes_cross_az(void)
{
    const uint32_t latency[3] = { 100u, 120u, 5000u };
    const uint32_t zone[3]    = { 1u, 2u, 3u };       /* addr0 same-AZ, others cross */
    struct server_dns *dns = make_dns(3, latency, zone);
    const uint32_t healthy[3] = { 0u, 1u, 2u };
    uint32_t eff[3];
    uint32_t out_idx[3];
    uint32_t out_eff[3];
    uint32_t i, k;

    /* Compose: effective latency WITH a 2000us cross-AZ surcharge. */
    for (i = 0; i < 3; i++) {
        eff[i] = server_addr_eff_latency(dns, i, 2000u);
    }
    /* addr0=100 (same-AZ), addr1=2120, addr2=7000. */
    CHECK(eff[0] == 100u && eff[1] == 2120u && eff[2] == 7000u,
          "composed eff = {%"PRIu32",%"PRIu32",%"PRIu32"} expected {100,2120,7000}",
          eff[0], eff[1], eff[2]);

    k = server_build_good_set(healthy, eff, 3, /*band*/3u, /*max*/8u,
                              out_idx, out_eff);

    /* min=100, threshold=300 -> only addr0 (100) qualifies. */
    CHECK(k == 1, "good set size %"PRIu32" expected 1 (surcharge excludes cross-AZ)", k);
    if (k >= 1) {
        CHECK(out_idx[0] == 0u && out_eff[0] == 100u,
              "good[0]=idx%"PRIu32"/eff%"PRIu32" expected idx0/100",
              out_idx[0], out_eff[0]);
    }

    free_dns(dns);
}

/* Test 4: output is sorted ascending by eff_latency even with out-of-order input. */
static void
test_good_set_sorted(void)
{
    /*
     * server_build_good_set reads healthy[] and eff[] in lockstep: eff[k] is the
     * effective latency of address healthy[k]. We feed the pairs deliberately
     * OUT of latency order to prove the helper sorts them:
     *   slot0: addr 3, eff 250
     *   slot1: addr 1, eff 120
     *   slot2: addr 2, eff 200
     *   slot3: addr 0, eff 100   (the fastest is given LAST)
     * min=100, threshold=3*100=300 -> all four survive (250<=300). Sorting
     * ascending by eff gives addrs 0,1,2,3 with effs 100,120,200,250.
     */
    const uint32_t healthy[4] = { 3u, 1u, 2u, 0u };
    const uint32_t eff[4]     = { 250u, 120u, 200u, 100u };
    uint32_t out_idx[4];
    uint32_t out_eff[4];
    uint32_t k;

    k = server_build_good_set(healthy, eff, 4, /*band*/3u, /*max*/8u,
                              out_idx, out_eff);

    CHECK(k == 4, "good set size %"PRIu32" expected 4 (all within band)", k);
    if (k == 4) {
        CHECK(out_eff[0] == 100u && out_eff[1] == 120u &&
              out_eff[2] == 200u && out_eff[3] == 250u,
              "eff order = {%"PRIu32",%"PRIu32",%"PRIu32",%"PRIu32"} expected "
              "{100,120,200,250}", out_eff[0], out_eff[1], out_eff[2], out_eff[3]);
        CHECK(out_idx[0] == 0u && out_idx[1] == 1u &&
              out_idx[2] == 2u && out_idx[3] == 3u,
              "idx order = {%"PRIu32",%"PRIu32",%"PRIu32",%"PRIu32"} expected "
              "{0,1,2,3} (addrs in eff-ascending order)",
              out_idx[0], out_idx[1], out_idx[2], out_idx[3]);
    }
}

/* Test 5: the max_count cap is honoured and keeps the LOWEST-eff members. */
static void
test_good_set_cap(void)
{
    const uint32_t healthy[4] = { 0u, 1u, 2u, 3u };
    const uint32_t eff[4]     = { 100u, 120u, 200u, 250u };  /* all within band 3 */
    uint32_t out_idx[4];
    uint32_t out_eff[4];
    uint32_t k;

    /* cap at 2: keep the two lowest-eff (100, 120). */
    k = server_build_good_set(healthy, eff, 4, /*band*/3u, /*max*/2u,
                              out_idx, out_eff);

    CHECK(k == 2, "capped good set size %"PRIu32" expected 2", k);
    if (k == 2) {
        CHECK(out_eff[0] == 100u && out_eff[1] == 120u,
              "capped eff = {%"PRIu32",%"PRIu32"} expected {100,120} (lowest two)",
              out_eff[0], out_eff[1]);
        CHECK(out_idx[0] == 0u && out_idx[1] == 1u,
              "capped idx = {%"PRIu32",%"PRIu32"} expected {0,1}",
              out_idx[0], out_idx[1]);
    }

    /* out_eff may be NULL -- caller might not want it. */
    k = server_build_good_set(healthy, eff, 4, 3u, 3u, out_idx, NULL);
    CHECK(k == 3, "good set (NULL out_eff) size %"PRIu32" expected 3", k);
    if (k == 3) {
        CHECK(out_idx[0] == 0u && out_idx[1] == 1u && out_idx[2] == 2u,
              "good set (NULL out_eff) idx = {%"PRIu32",%"PRIu32",%"PRIu32"} "
              "expected {0,1,2}", out_idx[0], out_idx[1], out_idx[2]);
    }
}

/* Test 6: empty healthy set -> 0, no writes. */
static void
test_good_set_empty(void)
{
    uint32_t out_idx[1] = { 99u };
    uint32_t out_eff[1] = { 99u };
    uint32_t k = server_build_good_set(NULL, NULL, 0, 3u, 8u, out_idx, out_eff);
    CHECK(k == 0, "empty healthy set returned %"PRIu32" expected 0", k);
}

int
main(void)
{
    test_eff_latency();
    test_good_set_basic();
    test_good_set_surcharge_excludes_cross_az();
    test_good_set_sorted();
    test_good_set_cap();
    test_good_set_empty();

    if (failures == 0) {
        printf("OK: all effective-latency + good-band tests passed\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
}
