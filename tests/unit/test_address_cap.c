/*
 * Standalone unit test for the server_dns accumulate-append address cap, on the
 * array-of-structs layout.
 *
 * Why this shape (read this before changing the test):
 *   The real append lives INLINE in server_dns_resolve() (src/nc_server.c),
 *   in the `if (!found)` block of the accumulate loop. That function calls
 *   the real network resolver (nc_resolve_multi_with_hostnames in nc_util.c),
 *   so it cannot be driven offline, and the append cannot be called in
 *   isolation. So this test MIRRORS the production accumulate decision in
 *   append_addr_if_new() below -- exactly like test_remove_address.c mirrors
 *   the inline current_addr_idx fixup. The mirror runs against a REAL,
 *   production-shaped `struct server_dns` (the real struct layout from the
 *   linked nc_server.c object: a single dns_addr array, realloc-grown).
 *
 *   *** KEEP append_addr_if_new() IN SYNC with the `if (!found)` block of
 *       server_dns_resolve() in src/nc_server.c. ***
 *
 * What it proves:
 *   Feeding >16 distinct addresses through the accumulate decision NEVER lets
 *   naddresses exceed max_addresses (16) -- the cap holds, and an over-cap
 *   append is dropped (the array does not grow past the cap).
 *
 * Note on the old "OOB lazy array" red: before the struct-of-arrays ->
 * array-of-structs refactor, zone_ids/health_scores/last_health_check were
 * lazily calloc'd to a FIXED max_addresses(=16) while the eager arrays grew, so
 * blowing past the cap produced a heap OOB write into those fixed arrays. With
 * AoS there is ONE array, realloc-grown with naddresses, so every per-address
 * field is always in bounds -- that specific OOB class is STRUCTURALLY gone. The
 * cap is now a pure policy bound, and the remaining behavioural contract (the
 * invariant naddresses <= max_addresses) is what this test asserts.
 *
 * Before/after demonstration (this is the TDD red->green):
 *   Compile with -DTEST_NO_CAP to reproduce the PRE-cap behaviour (no cap
 *   guard). naddresses runs to 25, violating the invariant; the run reports it
 *   and exits non-zero. The default build (cap present, mirroring nc_server.c)
 *   stays within 16 and exits clean. run.sh builds BOTH variants.
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
 * nc_post_run() from there. (Same as test_remove_address.c.)
 */
void nc_post_run(struct instance *nci) { (void)nci; }

/*
 * DEFAULT_LATENCY_USEC is a file-local #define in src/nc_server.c (not the
 * header). The exact value does not matter for the cap invariant under test;
 * mirror it for fidelity.
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
 * each fed address is distinct. Port is fixed so the dedup compares purely on
 * the address bits.
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
 * Build a server_dns shaped exactly like production after the first resolution
 * of a single address: one dns_addr array holding naddresses(=1), realloc-grown
 * thereafter. This mirrors the production first-resolution alloc in nc_server.c.
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

    dns->addrs = nc_alloc(1 * sizeof(struct dns_addr));

    memset(&dns->addrs[0], 0, sizeof(struct dns_addr));
    make_addr(&dns->addrs[0].addr, 0);
    dns->addrs[0].latency          = TEST_DEFAULT_LATENCY_USEC;
    dns->addrs[0].latency_measured = false;
    dns->addrs[0].health_score     = 100;
    string_init(&dns->addrs[0].hostname);
    string_copy(&dns->addrs[0].hostname, dns->hostname.data, dns->hostname.len);

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
    if (dns->hostname.data) string_deinit(&dns->hostname);
    nc_free(dns);
}

static bool
addr_already_known(struct server_dns *dns, struct sockinfo *cand)
{
    uint32_t j;
    struct sockaddr *new_addr = (struct sockaddr *)&cand->addr;

    for (j = 0; j < dns->naddresses; j++) {
        struct sockaddr *existing_addr = (struct sockaddr *)&dns->addrs[j].addr.addr;
        if (existing_addr->sa_family == new_addr->sa_family &&
            existing_addr->sa_family == AF_INET) {
            struct sockaddr_in *e = (struct sockaddr_in *)existing_addr;
            struct sockaddr_in *n = (struct sockaddr_in *)new_addr;
            if (e->sin_addr.s_addr == n->sin_addr.s_addr &&
                e->sin_port == n->sin_port) {
                dns->addrs[j].last_seen = 1; /* mirror: update last_seen on match */
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
 * The ONLY behavioural difference between the pre-cap and post-cap production
 * code is the cap guard, gated here by TEST_NO_CAP so run.sh can build both the
 * "bug reproduces" and the "bug fixed" variants from one source.
 */
static bool
append_addr_if_new(struct server_dns *dns, struct sockinfo *cand)
{
    uint32_t new_size;
    struct dns_addr *p;
    struct dns_addr *a;

    if (addr_already_known(dns, cand)) {
        return false; /* found: not appended */
    }

#ifndef TEST_NO_CAP
    /* --- cap guard (mirrors nc_server.c) --- */
    if (dns->naddresses >= dns->max_addresses) {
        /* production logs log_warn and continues; here we just skip-append. */
        return false;
    }
#endif

    new_size = dns->naddresses + 1;
    p = nc_realloc(dns->addrs, new_size * sizeof(struct dns_addr));

    /* In a unit test nc_realloc never fails; assert rather than branch. */
    CHECK(p != NULL, "nc_realloc returned NULL in test harness");
    dns->addrs = p;

    a = &dns->addrs[dns->naddresses];
    memset(a, 0, sizeof(*a));
    memcpy(&a->addr, cand, sizeof(struct sockinfo));
    a->latency          = TEST_DEFAULT_LATENCY_USEC;
    a->latency_measured = false;
    a->last_seen        = 1;
    a->health_score     = 100;
    string_init(&a->hostname);
    string_copy(&a->hostname, dns->hostname.data, dns->hostname.len);

    dns->naddresses++;
    return true;
}

/*
 * Drive the accumulate path with `feed` distinct addresses (> max_addresses)
 * and assert the cap holds. With AoS every per-address field lives in the one
 * realloc-grown array, so we additionally read each appended slot's fields each
 * iteration to give ASan/libgmalloc/leaks a live target -- any miscount that
 * indexed past the live array would be caught here.
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
        uint32_t k;
        volatile uint32_t sink = 0;

        make_addr(&cand, i);
        did = append_addr_if_new(dns, &cand);
        if (did) {
            appended++;
        }

        /* Touch every live address record (in bounds for the whole array). */
        for (k = 0; k < dns->naddresses; k++) {
            sink += dns->addrs[k].latency;
            sink += dns->addrs[k].zone_id;
            sink += dns->addrs[k].health_score;
            sink += dns->addrs[k].hostname.len;
        }
        (void)sink;

        /* The core invariant the remove helper relies on. */
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
     * No-cap (pre-cap) build: every distinct address was appended, so
     * naddresses ran to 1+feed and blew past max_addresses. The per-iteration
     * CHECK already recorded the failures; assert the overflow happened so the
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
               "this is the pre-cap bug reproducing (naddresses>16)\n",
               failures);
        return 1;
    }
    fprintf(stderr,
            "UNEXPECTED: no-cap build did not overflow -- test is not "
            "exercising the bug\n");
    return 2;
#else
    if (failures == 0) {
        printf("OK: accumulate-append cap holds at max_addresses (AoS)\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
#endif
}
