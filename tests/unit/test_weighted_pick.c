/*
 * Standalone unit test for server_weighted_pick() -- the pure, allocation-free
 * latency-weighted replica picker (Task 1 of the latency-weighted reads plan).
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS DRIVES
 * ---------------------------------------------------------------------------
 * server_weighted_pick(eff_latency, idxs, count) returns ONE element of idxs[]
 * with probability proportional to 1/(eff_latency[k] + LATENCY_FLOOR_US). It is
 * NON-static in nc_server.c precisely so this test can call the REAL production
 * function -- there is no network / DNS dependency, so no mirror is needed (cf.
 * test_dns_resolve_oom.c, which mirrors an inline block it cannot reach).
 *
 * The picker uses random() (the existing seeded PRNG) but does NOT seed it; the
 * caller owns the seed. We srandom(1) here so the draw counts are deterministic
 * and the asserted shares are reproducible across runs/platforms.
 *
 * ---------------------------------------------------------------------------
 * WHAT WE ASSERT (the contract from the spec/plan)
 * ---------------------------------------------------------------------------
 *   1. Two replicas {100us, 110us} (floor 50): over 100k draws idx0 gets the
 *      larger share (~51.6%) and idx1 the smaller (~48.4%), each within +-2%.
 *      The exact integer weights are 1e6/150=6666 and 1e6/160=6250, so the
 *      true split is 6666/12916=51.61% vs 48.39%.
 *   2. A single replica {100us} is ALWAYS returned (the count==1 fast path).
 *   3. A far/slow replica {100,110,10000} still draws a >0 but small share
 *      (<5%): weight 1e6/10050=99 out of total 13015 -> ~0.76%. This proves a
 *      slow-but-in-set replica is never starved to exactly zero (probing can
 *      keep its latency fresh) yet gets little traffic.
 *
 * This is the TDD evidence: written BEFORE server_weighted_pick() existed, so
 * the first harness run failed to resolve the symbol at link time (RED); once
 * the function is implemented the asserts below go GREEN.
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
 * Draw `draws` times from server_weighted_pick over idxs[0..count) and tally how
 * often each *index value* came back, into counts[] (caller-sized to the max
 * index value + 1). Asserts every returned value is one of idxs[].
 */
static void
tally(const uint32_t *eff_latency, const uint32_t *idxs, uint32_t count,
      uint32_t draws, uint64_t *counts, uint32_t counts_len)
{
    uint32_t d;
    for (d = 0; d < draws; d++) {
        uint32_t pick = server_weighted_pick(eff_latency, idxs, count);
        bool in_set = false;
        uint32_t k;
        for (k = 0; k < count; k++) {
            if (idxs[k] == pick) { in_set = true; break; }
        }
        CHECK(in_set, "pick %"PRIu32" is not one of the %"PRIu32" idxs", pick, count);
        CHECK(pick < counts_len, "pick %"PRIu32" out of counts range %"PRIu32,
              pick, counts_len);
        if (pick < counts_len) {
            counts[pick]++;
        }
    }
}

/* Test 1: two replicas, slightly different latency -> proportional split. */
static void
test_two_replica_split(void)
{
    const uint32_t eff_latency[2] = { 100u, 110u };
    const uint32_t idxs[2]        = { 0u, 1u };
    const uint32_t draws          = 100000u;
    uint64_t counts[2] = { 0, 0 };
    double share0, share1;

    tally(eff_latency, idxs, 2, draws, counts, 2);

    share0 = (double)counts[0] / (double)draws;
    share1 = (double)counts[1] / (double)draws;

    /*
     * True weights with LATENCY_FLOOR_US=50: 1e6/150=6666, 1e6/160=6250 ->
     * 51.61% / 48.39%. Allow +-2% absolute around those targets.
     */
    CHECK(share0 > 0.516 - 0.02 && share0 < 0.516 + 0.02,
          "idx0 share %.4f outside 51.6%%+-2%% (counts0=%" PRIu64 ")",
          share0, counts[0]);
    CHECK(share1 > 0.484 - 0.02 && share1 < 0.484 + 0.02,
          "idx1 share %.4f outside 48.4%%+-2%% (counts1=%" PRIu64 ")",
          share1, counts[1]);
    /* The faster replica must take the larger share. */
    CHECK(counts[0] > counts[1],
          "faster idx0 (%" PRIu64 ") did not beat slower idx1 (%" PRIu64 ")",
          counts[0], counts[1]);

    printf("  two-replica split: idx0=%.4f idx1=%.4f (target 0.5161/0.4839)\n",
           share0, share1);
}

/* Test 2: a single replica is always returned. */
static void
test_single_replica(void)
{
    const uint32_t eff_latency[1] = { 100u };
    const uint32_t idxs[1]        = { 7u };   /* arbitrary non-zero index value */
    uint32_t i;

    for (i = 0; i < 1000u; i++) {
        uint32_t pick = server_weighted_pick(eff_latency, idxs, 1);
        CHECK(pick == 7u, "single-replica pick=%"PRIu32" expected 7", pick);
    }
}

/* Test 3: a far/slow replica gets a >0 but small (<5%) share. */
static void
test_slow_replica_small_nonzero(void)
{
    const uint32_t eff_latency[3] = { 100u, 110u, 10000u };
    const uint32_t idxs[3]        = { 0u, 1u, 2u };
    const uint32_t draws          = 100000u;
    uint64_t counts[3] = { 0, 0, 0 };
    double share2;

    tally(eff_latency, idxs, 3, draws, counts, 3);

    share2 = (double)counts[2] / (double)draws;

    /* weight2 = 1e6/10050 = 99 of total 13015 -> ~0.76%: >0 but well under 5%. */
    CHECK(counts[2] > 0,
          "slow idx2 got ZERO draws -- a slow-but-in-set replica must keep a "
          "nonzero share so probing can re-measure it");
    CHECK(share2 < 0.05,
          "slow idx2 share %.4f too large (expected <5%%, counts2=%" PRIu64 ")",
          share2, counts[2]);
    /* And it must still be the smallest of the three. */
    CHECK(counts[2] < counts[0] && counts[2] < counts[1],
          "slow idx2 (%" PRIu64 ") not the smallest share (idx0=%" PRIu64
          ", idx1=%" PRIu64 ")", counts[2], counts[0], counts[1]);

    printf("  slow-replica share: idx2=%.6f (counts2=%" PRIu64 " of %u)\n",
           share2, counts[2], draws);
}

int
main(void)
{
    /*
     * Deterministic seed: the picker reads random() but never seeds it (the
     * process seeds once at startup in nc_pre_run()). Seeding here makes the
     * draw counts reproducible so the asserted shares are stable.
     */
    srandom(1);

    test_two_replica_split();
    test_single_replica();
    test_slow_replica_small_nonzero();

    if (failures == 0) {
        printf("OK: all server_weighted_pick tests passed\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
}
