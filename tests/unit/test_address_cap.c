/*
 * Standalone unit test for the server_dns accumulate-append address cap
 * (fork-hardening fix #3: prevent a heap OOB write to the lazy parallel
 * arrays when a rotating endpoint yields more than max_addresses distinct
 * IPs over the accumulation window).
 *
 * Why this shape (read this before changing the test):
 *   The real append lives INLINE in server_dns_resolve() (src/nc_server.c),
 *   in the `if (!found)` block of the accumulate loop. That function calls
 *   the real network resolver (nc_resolve_multi_with_hostnames in nc_util.c),
 *   so it cannot be driven offline, and the append cannot be called in
 *   isolation. So this test MIRRORS the production accumulate decision in
 *   append_addr_if_new() below -- exactly like test_remove_address.c mirrors
 *   the inline current_addr_idx fixup in apply_current_idx_fixup(). The mirror
 *   runs against a REAL, production-shaped `struct server_dns` (the real struct
 *   layout from the linked nc_server.c object; lazy arrays calloc'd ONCE to
 *   max_addresses, never grown -- the production sizing model).
 *
 *   *** KEEP append_addr_if_new() IN SYNC with the `if (!found)` block of
 *       server_dns_resolve() in src/nc_server.c. ***
 *
 * What it proves:
 *   1. Feeding >16 distinct addresses through the accumulate decision NEVER
 *      lets naddresses exceed max_addresses (16) -- the cap holds.
 *   2. After every append the test writes/reads the LAZY arrays
 *      (zone_ids / health_scores / last_health_check) at the new tail index,
 *      exactly as the production zone-analysis and health-check code do
 *      (nc_server.c lines ~2387 and ~2521-2527). Those arrays are sized to
 *      max_addresses; without the cap, naddresses > 16 makes that touch an
 *      out-of-bounds write -- caught by libgmalloc/ASan/leaks.
 *
 * Before/after demonstration (this is the TDD red->green):
 *   Compile with -DTEST_NO_CAP to reproduce the PRE-fix behaviour (no cap
 *   guard). naddresses runs to 25, the lazy-array touch writes past the
 *   16-slot allocation, and the run reports OOB (and traps under libgmalloc).
 *   The default build (cap present, mirroring the fixed nc_server.c) stays
 *   within 16 and exits clean. run.sh builds BOTH variants.
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
#include <nc.h>

/*
 * nc.c owns main() so it is excluded from the link; nc_signal.o references
 * nc_post_run() from there. The test never raises a fatal signal, so a no-op
 * stub satisfies the linker without affecting behaviour. (Same as
 * test_remove_address.c.)
 */
void nc_post_run(struct instance *nci) { (void)nci; }

/*
 * DEFAULT_LATENCY_USEC is a file-local #define in src/nc_server.c (not the
 * header), so it is not visible here. The exact value does not matter for the
 * cap/bounds invariants under test; mirror it for fidelity.
 */
#define TEST_DEFAULT_LATENCY_USEC 100

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
 * Encode the logical address index into the low bytes of an IPv4 address, so
 * each fed address is distinct. addr for index L is 10.0.(L>>8).(L&0xFF),
 * which stays unique well past 16 (and past 256). Port is fixed so the
 * dedup compares purely on the address bits.
 */
static void
make_addr(struct sockinfo *si, uint32_t logical)
{
    struct sockaddr_in *in = (struct sockaddr_in *)&si->addr;

    memset(si, 0, sizeof(*si));
    si->family = AF_INET;
    si->addrlen = sizeof(struct sockaddr_in);
    in->sin_family = AF_INET;
    in->sin_port = htons(6379);
    in->sin_addr.s_addr =
        htonl(0x0A000000u | ((logical & 0xFF00u)) | (logical & 0xFFu));
}

/*
 * Build a server_dns shaped exactly like production after the first
 * resolution of a single address: eager arrays sized to naddresses(=1), lazy
 * arrays calloc'd ONCE to max_addresses(=16) and never grown. This mirrors
 * make_dns()+the lazy-array calloc sites in nc_server.c.
 */
static struct server_dns *
make_dns_one(void)
{
    struct server_dns *dns = nc_zalloc(sizeof(*dns));

    dns->max_addresses = 16;          /* == MAX_ADDRESSES_PER_SERVER */
    dns->naddresses = 1;
    dns->next_zone_id = 1;
    dns->local_zone_id = 1;
    string_init(&dns->hostname);
    string_copy(&dns->hostname, (uint8_t *)"reader.example", 14);

    dns->addresses          = nc_alloc(1 * sizeof(struct sockinfo));
    dns->latencies          = nc_alloc(1 * sizeof(uint32_t));
    dns->last_latency_check = nc_alloc(1 * sizeof(int64_t));
    dns->failure_counts     = nc_alloc(1 * sizeof(uint32_t));
    dns->last_seen          = nc_alloc(1 * sizeof(int64_t));
    dns->last_connected     = nc_alloc(1 * sizeof(int64_t));
    dns->request_counts     = nc_alloc(1 * sizeof(uint64_t));
    dns->hostnames          = nc_alloc(1 * sizeof(struct string));

    /* Lazy arrays: fixed cap, exactly like the production calloc sites. */
    dns->zone_ids          = nc_calloc(dns->max_addresses, sizeof(uint32_t));
    dns->health_scores     = nc_calloc(dns->max_addresses, sizeof(uint32_t));
    dns->last_health_check = nc_calloc(dns->max_addresses, sizeof(int64_t));

    make_addr(&dns->addresses[0], 0);
    dns->latencies[0]          = TEST_DEFAULT_LATENCY_USEC;
    dns->last_latency_check[0] = 0;
    dns->failure_counts[0]     = 0;
    dns->last_seen[0]          = 0;
    dns->last_connected[0]     = 0;
    dns->request_counts[0]     = 0;
    string_init(&dns->hostnames[0]);
    string_copy(&dns->hostnames[0], dns->hostname.data, dns->hostname.len);

    dns->zone_ids[0]          = 0;
    dns->health_scores[0]     = 100;
    dns->last_health_check[0] = 0;

    return dns;
}

static void
free_dns(struct server_dns *dns)
{
    uint32_t i;
    for (i = 0; i < dns->naddresses; i++) {
        if (dns->hostnames[i].data != NULL) {
            string_deinit(&dns->hostnames[i]);
        }
    }
    nc_free(dns->addresses);
    nc_free(dns->latencies);
    nc_free(dns->last_latency_check);
    nc_free(dns->failure_counts);
    nc_free(dns->last_seen);
    nc_free(dns->last_connected);
    nc_free(dns->request_counts);
    nc_free(dns->hostnames);
    if (dns->zone_ids) nc_free(dns->zone_ids);
    if (dns->health_scores) nc_free(dns->health_scores);
    if (dns->last_health_check) nc_free(dns->last_health_check);
    if (dns->hostname.data) string_deinit(&dns->hostname);
    nc_free(dns);
}

static bool
addr_already_known(struct server_dns *dns, struct sockinfo *cand)
{
    uint32_t j;
    struct sockaddr *new_addr = (struct sockaddr *)&cand->addr;

    for (j = 0; j < dns->naddresses; j++) {
        struct sockaddr *existing_addr = (struct sockaddr *)&dns->addresses[j].addr;
        if (existing_addr->sa_family == new_addr->sa_family &&
            existing_addr->sa_family == AF_INET) {
            struct sockaddr_in *e = (struct sockaddr_in *)existing_addr;
            struct sockaddr_in *n = (struct sockaddr_in *)new_addr;
            if (e->sin_addr.s_addr == n->sin_addr.s_addr &&
                e->sin_port == n->sin_port) {
                dns->last_seen[j] = 1; /* mirror: update last_seen on match */
                return true;
            }
        }
    }
    return false;
}

/*
 * MIRROR of the `if (!found)` block in server_dns_resolve() (src/nc_server.c).
 * Returns true if the address was appended, false if it was a duplicate or
 * dropped by the cap. Keep this in sync with the production block.
 *
 * The ONLY behavioural difference between the pre-fix and post-fix production
 * code is the cap guard, gated here by TEST_NO_CAP so run.sh can build both
 * the "bug reproduces" and the "bug fixed" variants from one source.
 */
static bool
append_addr_if_new(struct server_dns *dns, struct sockinfo *cand)
{
    uint32_t new_size;
    struct sockinfo *na;
    uint32_t *nl, *nf;
    int64_t *nllc, *nls, *nlc;
    uint64_t *nrc;
    struct string *nh;

    if (addr_already_known(dns, cand)) {
        return false; /* found: not appended */
    }

#ifndef TEST_NO_CAP
    /* --- fix #3 cap guard (mirrors nc_server.c) --- */
    if (dns->naddresses >= dns->max_addresses) {
        /* production logs log_warn and continues; here we just skip-append. */
        return false;
    }
#endif

    new_size = dns->naddresses + 1;
    na   = nc_realloc(dns->addresses, new_size * sizeof(struct sockinfo));
    nl   = nc_realloc(dns->latencies, new_size * sizeof(uint32_t));
    nllc = nc_realloc(dns->last_latency_check, new_size * sizeof(int64_t));
    nf   = nc_realloc(dns->failure_counts, new_size * sizeof(uint32_t));
    nls  = nc_realloc(dns->last_seen, new_size * sizeof(int64_t));
    nlc  = nc_realloc(dns->last_connected, new_size * sizeof(int64_t));
    nrc  = nc_realloc(dns->request_counts, new_size * sizeof(uint64_t));
    nh   = nc_realloc(dns->hostnames, new_size * sizeof(struct string));

    /* In a unit test nc_realloc never fails; assert rather than branch. */
    CHECK(na && nl && nllc && nf && nls && nlc && nrc && nh,
          "nc_realloc returned NULL in test harness");

    dns->addresses = na;
    dns->latencies = nl;
    dns->last_latency_check = nllc;
    dns->failure_counts = nf;
    dns->last_seen = nls;
    dns->last_connected = nlc;
    dns->request_counts = nrc;
    dns->hostnames = nh;

    memcpy(&dns->addresses[dns->naddresses], cand, sizeof(struct sockinfo));
    dns->latencies[dns->naddresses] = TEST_DEFAULT_LATENCY_USEC;
    dns->last_latency_check[dns->naddresses] = 0;
    dns->failure_counts[dns->naddresses] = 0;
    dns->last_seen[dns->naddresses] = 1;
    dns->last_connected[dns->naddresses] = 0;
    dns->request_counts[dns->naddresses] = 0;
    string_init(&dns->hostnames[dns->naddresses]);
    string_copy(&dns->hostnames[dns->naddresses],
                dns->hostname.data, dns->hostname.len);

    dns->naddresses++;
    return true;
}

/*
 * Touch the LAZY arrays at index k exactly the way production does:
 *   - zone analysis writes zone_ids[k]               (nc_server.c ~line 2387)
 *   - health check reads last_health_check[k] then
 *     writes health_scores[k] / last_health_check[k] (nc_server.c ~2521-2527)
 * The lazy arrays are sized to max_addresses, so if naddresses has run past
 * max_addresses these accesses are out of bounds. We range-check first and
 * report OOB ourselves (so a plain build still FAILS, not just the
 * libgmalloc/ASan build), then perform the real touch so the heap guard also
 * traps the write on a no-cap build.
 */
static void
touch_lazy_arrays_like_production(struct server_dns *dns)
{
    uint32_t k;
    for (k = 0; k < dns->naddresses; k++) {
        CHECK(k < dns->max_addresses,
              "OOB lazy-array access: index %u >= max_addresses %u "
              "(naddresses=%u) -> heap OOB write to zone_ids/health_scores/"
              "last_health_check", k, dns->max_addresses, dns->naddresses);
        if (k >= dns->max_addresses) {
#ifdef TEST_FORCE_OOB_WRITE
            /*
             * Heap-guard demonstration build only. Perform the GENUINE
             * out-of-bounds write that the pre-fix production code performs
             * (zone analysis / health update past the max_addresses-sized lazy
             * arrays). Under libgmalloc/ASan this traps with a hard fault,
             * proving the heap guard catches THIS bug's corruption -- not just
             * our own range-check. Without a guard this would smash the heap,
             * so this path is gated behind a flag and never used in the normal
             * pass/fail builds.
             */
            dns->zone_ids[k] = dns->local_zone_id;            /* OOB write */
            dns->health_scores[k] = 90;                       /* OOB write */
            dns->last_health_check[k] = 1;                    /* OOB write */
#endif
            /*
             * Default (no FORCE flag): do NOT actually write past the
             * allocation -- that is the corruption we are guarding against and
             * would smash the heap for the rest of the run. We have already
             * recorded the OOB via CHECK above. Stop probing once OOB is hit.
             */
            return;
        }
        /* real production-style touch, in bounds */
        dns->zone_ids[k] = dns->local_zone_id;
        (void)dns->last_health_check[k];
        dns->health_scores[k] = (dns->health_scores[k] * 7 + 90 * 3) / 10;
        dns->last_health_check[k] = 1;
    }
}

/*
 * Drive the accumulate path with `feed` distinct addresses (> max_addresses)
 * and assert the cap holds and the lazy arrays are never indexed OOB.
 */
static void
test_accumulate_cap(uint32_t feed)
{
    struct server_dns *dns = make_dns_one();
    uint32_t appended = 0;
    uint32_t i;

    CHECK(dns->naddresses == 1, "precondition: naddresses=%u expected 1",
          dns->naddresses);

    /* Feed addresses 1..feed (address 0 is already present from make_dns_one). */
    for (i = 1; i <= feed; i++) {
        struct sockinfo cand;
        bool did;
        make_addr(&cand, i);
        did = append_addr_if_new(dns, &cand);
        if (did) {
            appended++;
        }
        /*
         * Production re-touches the lazy arrays for every address after an
         * append (forced zone re-analysis + per-request health updates). Do
         * the same each iteration so an OOB shows the instant naddresses would
         * pass the cap, not only at the end.
         */
        touch_lazy_arrays_like_production(dns);

        /* The core invariant fix #2's helper relies on. */
        CHECK(dns->naddresses <= dns->max_addresses,
              "naddresses=%u exceeded max_addresses=%u after feeding addr %u",
              dns->naddresses, dns->max_addresses, i);
    }

    /* Re-feeding an already-known address must never grow the array. */
    {
        struct sockinfo dup;
        uint32_t before = dns->naddresses;
        make_addr(&dup, 1); /* address 1 was fed above */
        (void)append_addr_if_new(dns, &dup);
        CHECK(dns->naddresses == before,
              "duplicate address grew naddresses %u -> %u",
              before, dns->naddresses);
    }

#ifndef TEST_NO_CAP
    /* Fixed build: must settle exactly at the cap, no more. */
    CHECK(dns->naddresses == dns->max_addresses,
          "naddresses=%u expected to settle at cap %u",
          dns->naddresses, dns->max_addresses);
    /* 1 initial + appended distinct; appended must be max-1 (cap reached). */
    CHECK(appended == dns->max_addresses - 1,
          "appended=%u expected %u (cap-bounded)",
          appended, dns->max_addresses - 1);
#else
    /*
     * No-cap (pre-fix) build: every distinct address was appended, so
     * naddresses ran to 1+feed and blew past max_addresses. The CHECKs above
     * already recorded the failures; assert the overflow happened so the
     * "bug reproduces" build returns non-zero deterministically.
     */
    CHECK(dns->naddresses > dns->max_addresses,
          "no-cap build expected naddresses(%u) > max_addresses(%u)",
          dns->naddresses, dns->max_addresses);
#endif

    free_dns(dns);
}

int
main(void)
{
    /* Feed 25 distinct addresses -- comfortably past the 16 cap. */
    test_accumulate_cap(25);

#ifdef TEST_NO_CAP
    if (failures > 0) {
        printf("EXPECTED-FAIL (no-cap build): %d assertion(s) -- "
               "this is the pre-fix bug reproducing (naddresses>16 + OOB)\n",
               failures);
        return 1;
    }
    fprintf(stderr,
            "UNEXPECTED: no-cap build did not overflow -- test is not "
            "exercising the bug\n");
    return 2;
#else
    if (failures == 0) {
        printf("OK: accumulate-append cap holds at max_addresses; "
               "no OOB of lazy arrays\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
#endif
}
