/*
 * Standalone unit test for the FIRST-RESOLUTION out-of-memory path of
 * server_dns_resolve(), on the array-of-structs layout.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS GUARDS
 * ---------------------------------------------------------------------------
 * On the FIRST successful DNS resolve, server_dns_resolve() publishes the
 * resolved count and then allocates the per-address array:
 *
 *     dns->naddresses = new_naddresses;     // publish the count (>0)
 *     ... clamp naddresses to max_addresses ...
 *     dns->addrs = nc_alloc(naddresses * sizeof(struct dns_addr));
 *     if (dns->addrs == NULL) {
 *         // MUST revert: roll back to an empty, self-consistent dns
 *         dns->naddresses = 0;
 *         ... free the temp resolved list + temp hostnames ...
 *         return NC_ENOMEM;
 *     }
 *     ... init each addr from the resolved list ...
 *
 * If the alloc fails and the count is NOT rolled back, the dns is INCONSISTENT:
 * naddresses says ">0" but addrs is NULL. The next client request or DNS tick
 * that indexes dns->addrs[idx] (guarded only by naddresses>0) dereferences NULL
 * -> crash. The fix rolls naddresses back to 0 so addrs==NULL && naddresses==0:
 * no consumer can index, and the next resolve retries cleanly (last_resolved is
 * not set on this path, so the server stays "due").
 *
 * Pre-refactor history: the first-resolution branch ADOPTED the resolved list
 * into dns->addresses and allocated EIGHT parallel arrays; the bug was leaving
 * that adoption published with the parallel arrays NULL. After folding into a
 * single dns_addr array, the resolved list is a TEMP that is copied-from and
 * freed (the types differ), and there is ONE alloc -- but the SAME contract
 * (revert to empty on OOM) is what this test drives.
 *
 * ---------------------------------------------------------------------------
 * WHY A MIRROR (read before changing the test)
 * ---------------------------------------------------------------------------
 * The first-resolution block is INLINE in server_dns_resolve(), reachable only
 * after a real DNS success, so the alloc OOM cannot be injected into the real
 * call. first_resolution_adopt() below MIRRORS the publish-count + alloc +
 * failure-cleanup block, run against a REAL struct server_dns. The ONLY
 * behavioural difference between the two builds is whether the cleanup reverts
 * the count, gated by TEST_PREFIX_NO_REVERT.
 *
 *     *** KEEP first_resolution_adopt()'s block IN SYNC with the
 *         first-resolution branch of server_dns_resolve() in src/nc_server.c. ***
 *
 * ---------------------------------------------------------------------------
 * FAILURE INJECTION
 * ---------------------------------------------------------------------------
 * Swaps the production nc_alloc macro for a counting shim via an in-source
 * #undef/#define AFTER the headers. arm_alloc_fail_after(K) lets K allocs
 * succeed then fails the (K+1)th.
 *
 * ---------------------------------------------------------------------------
 * BEFORE/AFTER (TDD red->green)
 * ---------------------------------------------------------------------------
 *   default build (FIXED): after a forced OOM the dns is reverted to addrs==NULL,
 *     naddresses==0; a simulated "next request" access is a guarded no-op -> exit
 *     0, clean under ASan / libgmalloc / leaks.
 *   -DTEST_PREFIX_NO_REVERT (PRE-FIX): the same OOM leaves naddresses>0 while
 *     addrs is NULL. We assert consistency (it is NOT -> asserts fire, plain
 *     build non-zero) then index dns->addrs[0] guarded by naddresses>0 -- a
 *     genuine NULL deref that ASan/libgmalloc trap. This is the TDD red.
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

/* nc.c owns main(); stub nc_post_run for the linker (see sibling tests). */
void nc_post_run(struct instance *nci) { (void)nci; }

/*
 * File-local in src/nc_server.c, mirrored here (same convention as the sibling
 * tests). KEEP IN SYNC.
 */
#define TEST_MAX_ADDRESSES_PER_SERVER  16
#define TEST_DEFAULT_LATENCY_USEC      100

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

/* ------------------------------------------------------------------------- *
 * nc_alloc failure-injection shim.
 * ------------------------------------------------------------------------- */

static int  alloc_calls_left = -1;     /* <0 == disarmed (forward everything) */
static bool alloc_armed      = false;

static void
arm_alloc_fail_after(int succeed)
{
    alloc_armed = true;
    alloc_calls_left = succeed;
}

static void
disarm_alloc(void)
{
    alloc_armed = false;
    alloc_calls_left = -1;
}

static void *
test_alloc(size_t size)
{
    if (alloc_armed) {
        if (alloc_calls_left <= 0) {
            return NULL;                 /* the forced OOM */
        }
        alloc_calls_left--;
    }
    return _nc_alloc(size, __FILE__, __LINE__);
}

/* ------------------------------------------------------------------------- *
 * Production-shaped EMPTY server_dns fixture: a freshly-initialised dns exactly
 * as server_dns_init() leaves it BEFORE the first resolve (addrs NULL,
 * naddresses 0). Built with the REAL allocator (shim disarmed here).
 * ------------------------------------------------------------------------- */
static struct server_dns *
make_empty_dns(void)
{
    struct server_dns *dns = nc_zalloc(sizeof(*dns));

    dns->max_addresses = TEST_MAX_ADDRESSES_PER_SERVER;
    dns->naddresses = 0;
    dns->addrs = NULL;
    dns->last_resolved = 0;
    dns->resolve_interval = 30 * 1000000;
    dns->next_zone_id = 1;
    string_init(&dns->hostname);
    string_copy(&dns->hostname, (uint8_t *)"reader.example", 14);
    return dns;
}

static void
free_dns(struct server_dns *dns)
{
    uint32_t i;
    if (dns->addrs != NULL) {
        for (i = 0; i < dns->naddresses; i++) {
            if (dns->addrs[i].hostname.data != NULL) {
                string_deinit(&dns->addrs[i].hostname);
            }
        }
        nc_free(dns->addrs);
    }
    if (dns->hostname.data) string_deinit(&dns->hostname);
    nc_free(dns);
}

/*
 * Build a fake resolved list (what nc_resolve_multi_with_hostnames would return)
 * via the REAL allocator -- a TEMP sockinfo array the first-resolution branch
 * copies from. Allocated while the shim is disarmed.
 */
static struct sockinfo *
make_resolved(uint32_t n)
{
    struct sockinfo *a = nc_alloc(n * sizeof(struct sockinfo));
    uint32_t i;
    for (i = 0; i < n; i++) {
        struct sockaddr_in *in = (struct sockaddr_in *)&a[i].addr;
        memset(&a[i], 0, sizeof(a[i]));
        a[i].family = AF_INET;
        a[i].addrlen = sizeof(struct sockaddr_in);
        in->sin_family = AF_INET;
        in->sin_port = htons(6379);
        in->sin_addr.s_addr = htonl(0x0A000001u + i);
    }
    return a;
}

/*
 * Route the mirror's nc_alloc through the failure-injection shim. Must be done
 * HERE, not via -Dnc_alloc. We #undef + point nc_alloc at the shim AFTER all
 * headers + fixtures are compiled, so only first_resolution_adopt() is affected.
 */
#undef nc_alloc
#define nc_alloc(_s) test_alloc((size_t)(_s))

/* ------------------------------------------------------------------------- *
 * MIRROR of the first-resolution branch of server_dns_resolve(): publish the
 * count, clamp it, alloc the single dns_addr array, and -- on a forced alloc
 * failure -- run the cleanup. The TWO builds differ ONLY in whether the cleanup
 * reverts the count (the fix), gated by TEST_PREFIX_NO_REVERT.
 *
 *     *** KEEP IN SYNC with the first-resolution branch in src/nc_server.c. ***
 *
 * Returns NC_OK on full success, NC_ENOMEM on the forced array OOM.
 * `new_addresses` is the TEMP resolved list (freed on every exit, like prod).
 * ------------------------------------------------------------------------- */
static int
first_resolution_adopt(struct server_dns *dns, struct sockinfo *new_addresses,
                       uint32_t new_naddresses,
                       char **new_hostnames, uint32_t new_hostnames_n)
{
    uint32_t i;

    /* Publish the count first (so a dynamic-connections update would see it). */
    dns->naddresses = new_naddresses;

    if (dns->naddresses > dns->max_addresses) {
        dns->naddresses = dns->max_addresses;
    }

    /* One allocation for the whole address array. */
    dns->addrs = nc_alloc(dns->naddresses * sizeof(struct dns_addr));
    if (dns->addrs == NULL) {
#ifdef TEST_PREFIX_NO_REVERT
        /*
         * PRE-FIX cleanup: count NOT reverted. dns->naddresses stays >0 while
         * dns->addrs is NULL -> inconsistent dns (the bug). The temp resolved
         * list is freed (it was never adopted -- the types differ), so this test
         * does not leak it; we deliberately leave naddresses published to
         * reproduce the inconsistency the fix removes.
         */
        /* leave dns->naddresses as-is (the inconsistency) */
#else
        /* FIXED cleanup: revert the count to an EMPTY, consistent dns. */
        dns->naddresses = 0;
#endif
        if (new_addresses) nc_free(new_addresses);
        if (new_hostnames != NULL) {
            for (uint32_t hi = 0; hi < new_hostnames_n; hi++) {
                if (new_hostnames[hi] != NULL) nc_free(new_hostnames[hi]);
            }
            nc_free(new_hostnames);
        }
        return NC_ENOMEM;
    }

    /* Full-success init (not exercised by the OOM test, kept for fidelity). */
    for (i = 0; i < dns->naddresses; i++) {
        struct dns_addr *a = &dns->addrs[i];
        memset(a, 0, sizeof(*a));
        memcpy(&a->addr, &new_addresses[i], sizeof(struct sockinfo));
        a->latency = TEST_DEFAULT_LATENCY_USEC;
        a->latency_measured = false;
        a->last_seen = 1;
        a->health_score = 100;
        string_init(&a->hostname);
        string_copy(&a->hostname, dns->hostname.data, dns->hostname.len);
    }
    if (new_addresses) nc_free(new_addresses);
    if (new_hostnames != NULL) {
        for (uint32_t hi = 0; hi < new_hostnames_n; hi++) {
            if (new_hostnames[hi] != NULL) nc_free(new_hostnames[hi]);
        }
        nc_free(new_hostnames);
    }
    return NC_OK;
}

/* A populated temp hostname array, like the resolver returns (heap char* array,
 * element strings via the same allocator, plus a NULL hole). Built disarmed. */
static char **
make_temp_hostnames(uint32_t n)
{
    char **hn = nc_alloc(n * sizeof(char *));
    uint32_t i;
    for (i = 0; i < n; i++) {
        if (i == 1) { hn[i] = NULL; continue; }
        const char *name = "reader-az1.example.internal";
        size_t len = strlen(name) + 1;
        hn[i] = nc_alloc(len);
        memcpy(hn[i], name, len);
    }
    return hn;
}

int
main(void)
{
    struct server_dns *dns = make_empty_dns();
    uint32_t n = 3;
    struct sockinfo *resolved = make_resolved(n);
    char **temp_hn = make_temp_hostnames(n);
    int rc;

    /*
     * Fail the FIRST alloc the mirror makes (the dns_addr array alloc). With one
     * array there is exactly one alloc on this path, so arm_alloc_fail_after(0)
     * fails it -- the exact shape that exposes a missing revert.
     */
    arm_alloc_fail_after(0);
    rc = first_resolution_adopt(dns, resolved, n, temp_hn, n);
    disarm_alloc();

    CHECK(rc == NC_ENOMEM,
          "expected NC_ENOMEM from forced array OOM, got %d", rc);

#ifdef TEST_PREFIX_NO_REVERT
    /*
     * RED: the pre-fix cleanup leaves the dns INCONSISTENT. Assert the
     * consistency the fix guarantees -- which the buggy build VIOLATES.
     */
    CHECK(dns->naddresses == 0,
          "pre-fix: naddresses=%u after OOM (count not reverted) -- inconsistent "
          "with a NULL addrs array", dns->naddresses);
    CHECK(dns->addrs == NULL,
          "pre-fix: addrs is NULL after OOM (expected) while naddresses>0 -- "
          "inconsistent dns");

    /*
     * Do exactly what the next client request / DNS tick does: a consumer sees
     * naddresses>0 and indexes the addrs array. On the buggy dns that array is
     * NULL -> genuine NULL deref (ASan/libgmalloc trap here).
     */
    if (dns->naddresses > 0 && dns->addrs == NULL) {
        volatile uint32_t sink = 0;
        sink += dns->addrs[0].latency;        /* NULL[0] deref */
        (void)sink;
        CHECK(false,
              "pre-fix: indexed addrs on the inconsistent dns without trapping -- "
              "NULL deref went unnoticed");
    }

    free_dns(dns);

    if (failures > 0) {
        printf("EXPECTED-FAIL (pre-fix no-revert build): %d assertion(s) -- "
               "count left published with a NULL addrs array; the next index is a "
               "NULL deref\n", failures);
        return 1;
    }
    fprintf(stderr,
            "UNEXPECTED: pre-fix build looked consistent -- mirror drifted? "
            "rely on ASan/libgmalloc; treat as not-exercised\n");
    return 2;
#else
    /*
     * GREEN: the fixed cleanup reverted the count. The dns must be EMPTY and
     * self-consistent, and a simulated "next request" access must be a guarded
     * no-op (no array to index because naddresses==0).
     */
    CHECK(dns->naddresses == 0,
          "naddresses=%u after OOM (expected 0 -- count must be reverted)",
          dns->naddresses);
    CHECK(dns->addrs == NULL,
          "addrs non-NULL after OOM (expected NULL)");
    CHECK(dns->last_resolved == 0,
          "last_resolved=%" PRId64 " after OOM (expected 0 so the next resolve is "
          "still 'due' and retries)", dns->last_resolved);

    if (dns->naddresses > 0 && dns->addrs != NULL) {
        volatile uint32_t sink = dns->addrs[0].latency;   /* must NOT run */
        (void)sink;
        CHECK(false, "fixed dns wrongly reported naddresses>0 after OOM");
    }

    free_dns(dns);

    if (failures == 0) {
        printf("OK: first-resolution OOM reverts the count -> empty, "
               "self-consistent dns (naddresses=0, addrs=NULL); next access is a "
               "guarded no-op; next resolve is still due\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
#endif
}
