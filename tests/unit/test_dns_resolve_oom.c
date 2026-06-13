/*
 * Standalone unit test for the FIRST-RESOLUTION out-of-memory path of
 * server_dns_resolve() (prod-hardening bug #2).
 *
 * ---------------------------------------------------------------------------
 * THE BUG THIS GUARDS (pre-fix server_dns_resolve(), src/nc_server.c)
 * ---------------------------------------------------------------------------
 * On the FIRST successful DNS resolve, the first-resolution branch:
 *
 *     dns->addresses  = new_addresses;     // ADOPT the resolved list
 *     dns->naddresses = new_naddresses;    // ...and publish the count (>0)
 *     ... clamp naddresses to max_addresses ...
 *     dns->latencies          = nc_alloc(...);   // eager parallel arrays
 *     dns->last_latency_check = nc_alloc(...);
 *     dns->failure_counts     = nc_alloc(...);
 *     dns->last_seen          = nc_alloc(...);
 *     dns->last_connected     = nc_alloc(...);
 *     dns->request_counts     = nc_alloc(...);
 *     dns->hostnames          = nc_alloc(...);
 *     if (any of those == NULL) {
 *         // pre-fix cleanup: free + NULL the eager arrays only
 *         ... nc_free(dns->latencies); dns->latencies = NULL; ... (etc) ...
 *         free_hostnames_temp(new_hostnames, new_naddresses);
 *         return NC_ENOMEM;                // <-- BUT adoption NOT reverted!
 *     }
 *
 * The adoption (dns->addresses = new_addresses; dns->naddresses = N>0) is left
 * in place while every parallel tracking array is now NULL. So the dns is
 * INCONSISTENT: naddresses says "I have N addresses" but latencies /
 * last_connected / request_counts / ... are all NULL. The very next client
 * request or DNS tick that indexes a parallel array (e.g. dns->latencies[idx],
 * dns->last_connected[idx]) dereferences NULL -> crash.
 *
 * Worse, last_resolved stays at its prior value but addresses!=NULL, so the
 * "first resolution" branch (guarded by addresses==NULL || naddresses==0) is no
 * longer taken on the next resolve either -- the dns is wedged inconsistent.
 *
 * ---------------------------------------------------------------------------
 * THE FIX (mirrored below, gated by TEST_PREFIX_NO_REVERT)
 * ---------------------------------------------------------------------------
 * In the alloc-failure cleanup, REVERT the adoption too -- roll the dns all the
 * way back to an EMPTY, self-consistent state:
 *
 *     ... free + NULL the eager arrays (as before) ...
 *     nc_free(dns->addresses);            // owns new_addresses now
 *     dns->addresses  = NULL;
 *     dns->naddresses = 0;
 *     free_hostnames_temp(new_hostnames, new_naddresses);
 *     return NC_ENOMEM;
 *
 * Now naddresses==0 && addresses==NULL: no parallel-array index can run (every
 * consumer guards on naddresses/addresses), and the next resolve takes the
 * first-resolution branch again (addresses==NULL) and retries cleanly.
 * last_resolved is NOT set on this path, so server_dns_resolve_due() still
 * reports the server as due.
 *
 * ---------------------------------------------------------------------------
 * WHY A MIRROR (read before changing the test)
 * ---------------------------------------------------------------------------
 * The first-resolution block is INLINE in server_dns_resolve(), which only
 * reaches it AFTER a successful nc_resolve_multi_with_hostnames() (real DNS) --
 * so it cannot be driven offline, and the eager-array OOM cannot be injected
 * into the real call. So -- exactly like test_realloc_safety.c mirrors the
 * accumulate realloc block and test_address_cap.c mirrors the cap -- the
 * function below MIRRORS the adopt + eager-alloc + alloc-failure-cleanup block,
 * run against a REAL, production-shaped struct server_dns (the real struct
 * layout from the linked nc_server.c object). The ONLY behavioural difference
 * between the two builds is whether the cleanup reverts the adoption, gated by
 * TEST_PREFIX_NO_REVERT.
 *
 *     *** KEEP first_resolution_adopt()'s adopt + alloc + cleanup block IN SYNC
 *         with the first-resolution branch of server_dns_resolve() in
 *         src/nc_server.c. ***
 *
 * ---------------------------------------------------------------------------
 * FAILURE INJECTION
 * ---------------------------------------------------------------------------
 * Like test_realloc_safety.c swaps nc_realloc, this file swaps the production
 * nc_alloc macro for a counting shim via an in-source #undef/#define AFTER the
 * headers (a command-line -Dnc_alloc gets clobbered by nc_util.h's own macro).
 * Disarmed, the shim forwards to the real _nc_alloc. Armed (arm_alloc_fail_after
 * (K)) it lets the next K allocs succeed and returns NULL on the (K+1)th -- a
 * real partial OOM partway through the eager-array allocations.
 *
 * ---------------------------------------------------------------------------
 * BEFORE/AFTER (TDD red->green)
 * ---------------------------------------------------------------------------
 *   default build (FIXED cleanup): after a forced eager-array OOM, the dns is
 *     reverted to addresses==NULL, naddresses==0; a simulated "next request"
 *     access is a guarded no-op (nothing to index) -> exit 0, clean under ASan /
 *     libgmalloc / leaks.
 *
 *   -DTEST_PREFIX_NO_REVERT (PRE-FIX cleanup): the same forced OOM leaves
 *     addresses adopted (non-NULL) and naddresses>0 while the parallel arrays
 *     are NULL. We assert the dns is consistent (it is NOT -> the asserts fire,
 *     plain build exits non-zero) AND then perform the access a real consumer
 *     would -- index dns->latencies[0] guarded by naddresses>0 -- which is a
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
 * File-local in src/nc_server.c, mirrored here (same convention as
 * test_realloc_safety.c / test_dns_init_deinit.c). KEEP IN SYNC.
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
 * nc_alloc failure-injection shim (mirrors the nc_realloc shim in
 * test_realloc_safety.c). Wired to the mirror via an in-source #undef/#define of
 * nc_alloc further down -- NOT a command-line -Dnc_alloc (nc_util.h re-#defines
 * nc_alloc and would clobber it).
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

/*
 * Drop-in for nc_alloc(_s). The production macro forwards file/line; here a
 * 1-arg shim is enough (this translation unit is the only caller of the macro
 * after the #define below -- nc_server.c keeps the real macro). Armed: count
 * down, return NULL on the failing call. Disarmed: forward to _nc_alloc.
 */
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
 * as server_dns_init() leaves it BEFORE the first resolve (all arrays NULL,
 * naddresses 0). Built with the REAL allocator (shim disarmed at this point), so
 * the only allocs the shim sees are inside first_resolution_adopt().
 * ------------------------------------------------------------------------- */
static struct server_dns *
make_empty_dns(void)
{
    struct server_dns *dns = nc_zalloc(sizeof(*dns));

    dns->max_addresses = TEST_MAX_ADDRESSES_PER_SERVER;
    dns->naddresses = 0;
    dns->addresses = NULL;
    dns->last_resolved = 0;
    dns->resolve_interval = 30 * 1000000;
    dns->next_zone_id = 1;
    string_init(&dns->hostname);
    string_copy(&dns->hostname, (uint8_t *)"reader.example", 14);
    /* nc_zalloc already NULLed every parallel-array pointer. */
    return dns;
}

static void
free_dns(struct server_dns *dns)
{
    uint32_t i;
    for (i = 0; i < dns->naddresses; i++) {
        if (dns->hostnames != NULL && dns->hostnames[i].data != NULL) {
            string_deinit(&dns->hostnames[i]);
        }
    }
    if (dns->addresses)          nc_free(dns->addresses);
    if (dns->latencies)          nc_free(dns->latencies);
    if (dns->last_latency_check) nc_free(dns->last_latency_check);
    if (dns->failure_counts)     nc_free(dns->failure_counts);
    if (dns->last_seen)          nc_free(dns->last_seen);
    if (dns->last_connected)     nc_free(dns->last_connected);
    if (dns->request_counts)     nc_free(dns->request_counts);
    if (dns->hostnames)          nc_free(dns->hostnames);
    if (dns->hostname.data)      string_deinit(&dns->hostname);
    nc_free(dns);
}

/*
 * Build a fake resolved list (what nc_resolve_multi_with_hostnames would return)
 * via the REAL allocator -- this is the new_addresses the first-resolution branch
 * adopts. Allocated while the shim is disarmed.
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
 * HERE, not via -Dnc_alloc: nc_util.h unconditionally re-#defines nc_alloc(_s),
 * so a command-line define is clobbered. We #undef + point nc_alloc at the shim
 * AFTER all headers + fixtures are compiled, so only first_resolution_adopt()
 * below is affected; make_* / free_dns above keep the real nc_alloc.
 */
#undef nc_alloc
#define nc_alloc(_s) test_alloc((size_t)(_s))

/* ------------------------------------------------------------------------- *
 * MIRROR of the first-resolution branch of server_dns_resolve(): adopt
 * new_addresses, clamp the count, alloc the eager parallel arrays, and -- on a
 * forced alloc failure -- run the cleanup. The TWO builds differ ONLY in whether
 * the cleanup reverts the adoption (the fix), gated by TEST_PREFIX_NO_REVERT.
 *
 *     *** KEEP IN SYNC with the first-resolution branch in src/nc_server.c. ***
 *
 * Returns NC_OK on full success, NC_ENOMEM on the forced eager-array OOM.
 * ------------------------------------------------------------------------- */
static int
first_resolution_adopt(struct server_dns *dns, struct sockinfo *new_addresses,
                       uint32_t new_naddresses,
                       char **new_hostnames, uint32_t new_hostnames_n)
{
    /* ADOPT (exactly as production: publish addresses + count >0). */
    dns->addresses = new_addresses;
    dns->naddresses = new_naddresses;

    if (dns->naddresses > dns->max_addresses) {
        dns->naddresses = dns->max_addresses;
    }

    dns->latencies          = nc_alloc(dns->naddresses * sizeof(uint32_t));
    dns->last_latency_check = nc_alloc(dns->naddresses * sizeof(int64_t));
    dns->failure_counts     = nc_alloc(dns->naddresses * sizeof(uint32_t));
    dns->last_seen          = nc_alloc(dns->naddresses * sizeof(int64_t));
    dns->last_connected     = nc_alloc(dns->naddresses * sizeof(int64_t));
    dns->request_counts     = nc_alloc(dns->naddresses * sizeof(uint64_t));
    dns->hostnames          = nc_alloc(dns->naddresses * sizeof(struct string));

    if (dns->latencies == NULL || dns->last_latency_check == NULL ||
        dns->failure_counts == NULL || dns->last_seen == NULL ||
        dns->last_connected == NULL || dns->request_counts == NULL ||
        dns->hostnames == NULL) {
        /* Free + NULL the eager arrays (both builds do this). */
        if (dns->latencies != NULL)          { nc_free(dns->latencies);          dns->latencies = NULL; }
        if (dns->last_latency_check != NULL)  { nc_free(dns->last_latency_check);  dns->last_latency_check = NULL; }
        if (dns->failure_counts != NULL)      { nc_free(dns->failure_counts);      dns->failure_counts = NULL; }
        if (dns->last_seen != NULL)           { nc_free(dns->last_seen);           dns->last_seen = NULL; }
        if (dns->last_connected != NULL)      { nc_free(dns->last_connected);      dns->last_connected = NULL; }
        if (dns->request_counts != NULL)      { nc_free(dns->request_counts);      dns->request_counts = NULL; }
        if (dns->hostnames != NULL)           { nc_free(dns->hostnames);           dns->hostnames = NULL; }

#ifdef TEST_PREFIX_NO_REVERT
        /*
         * PRE-FIX cleanup: adoption NOT reverted. dns->addresses still points at
         * new_addresses and dns->naddresses is still >0 while every parallel
         * array is NULL -> inconsistent dns (the bug). We must still release
         * new_addresses so THIS test does not leak it on the buggy path (the
         * real bug is the inconsistency, not a leak), but we deliberately leave
         * addresses/naddresses published to reproduce the inconsistency the fix
         * removes. To both (a) reproduce the dangling-index hazard and (b) not
         * leak, free the block but leave the pointer published (a faithful stand-
         * in for "addresses adopted, arrays gone").
         */
        /* leave dns->addresses / dns->naddresses as-is (the inconsistency) */
#else
        /*
         * FIXED cleanup: revert the adoption to an EMPTY, consistent dns.
         * new_addresses lives in dns->addresses, so freeing dns->addresses
         * releases it.
         */
        if (dns->addresses != NULL) { nc_free(dns->addresses); dns->addresses = NULL; }
        dns->naddresses = 0;
#endif
        if (new_hostnames != NULL) {
            for (uint32_t hi = 0; hi < new_hostnames_n; hi++) {
                if (new_hostnames[hi] != NULL) nc_free(new_hostnames[hi]);
            }
            nc_free(new_hostnames);
        }
        return NC_ENOMEM;
    }

    /* Full-success init (not exercised by the OOM test, kept for fidelity). */
    {
        uint32_t i;
        for (i = 0; i < dns->naddresses; i++) {
            dns->latencies[i] = TEST_DEFAULT_LATENCY_USEC;
            dns->last_latency_check[i] = 0;
            dns->failure_counts[i] = 0;
            dns->last_seen[i] = 1;
            dns->last_connected[i] = 0;
            dns->request_counts[i] = 0;
            string_init(&dns->hostnames[i]);
            string_copy(&dns->hostnames[i], dns->hostname.data, dns->hostname.len);
        }
    }
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
     * Fail the 4th eager alloc (3 succeed first): a genuine mid-sequence OOM
     * after the adoption, with some arrays allocated and some not -- the exact
     * shape that exposes the missing revert.
     */
    arm_alloc_fail_after(3);
    rc = first_resolution_adopt(dns, resolved, n, temp_hn, n);
    disarm_alloc();

    CHECK(rc == NC_ENOMEM,
          "expected NC_ENOMEM from forced eager-array OOM, got %d", rc);

#ifdef TEST_PREFIX_NO_REVERT
    /*
     * RED: the pre-fix cleanup leaves the dns INCONSISTENT. Assert the
     * consistency the fix guarantees -- which the buggy build VIOLATES, so these
     * fire and a plain build exits non-zero.
     */
    CHECK(dns->naddresses == 0,
          "pre-fix: naddresses=%u after OOM (adoption not reverted) -- "
          "inconsistent with NULL parallel arrays", dns->naddresses);
    CHECK(dns->addresses == NULL,
          "pre-fix: addresses still adopted (non-NULL) after OOM while parallel "
          "arrays are NULL -- inconsistent dns");

    /*
     * Now do exactly what the next client request / DNS tick does: a consumer
     * sees naddresses>0 and indexes a parallel array. On the buggy dns that
     * array is NULL -> genuine NULL deref (ASan/libgmalloc trap here). Guarded
     * by the buggy naddresses>0 so it only runs when the inconsistency exists.
     */
    if (dns->naddresses > 0 && dns->addresses != NULL) {
        volatile uint32_t sink = 0;
        /* dns->latencies is NULL on the buggy path -> NULL[0] deref. */
        sink += dns->latencies[0];
        sink += (uint32_t)dns->last_connected[0];
        (void)sink;
        /* If we reach here without trapping (no sanitizer), still a failure. */
        CHECK(false,
              "pre-fix: indexed a parallel array on the inconsistent dns "
              "without trapping -- NULL deref went unnoticed");
    }

    /*
     * If we get here on a plain (no-sanitizer) build the deref above did not
     * crash the process, so the asserts are our evidence. free_dns is safe:
     * dns->addresses still aliases the live `resolved` block (we never freed it
     * on the buggy path), so it is freed exactly once here. (resolved is owned
     * solely via dns->addresses now -- do not free it separately.)
     */
    free_dns(dns);

    if (failures > 0) {
        printf("EXPECTED-FAIL (pre-fix no-revert build): %d assertion(s) -- "
               "adoption left published with NULL parallel arrays; the next "
               "parallel-array index is a NULL deref\n", failures);
        return 1;
    }
    fprintf(stderr,
            "UNEXPECTED: pre-fix build looked consistent -- mirror drifted? "
            "rely on ASan/libgmalloc; treat as not-exercised\n");
    return 2;
#else
    /*
     * GREEN: the fixed cleanup reverted the adoption. The dns must be EMPTY and
     * self-consistent, and a simulated "next request" access must be a guarded
     * no-op (no parallel array to index because naddresses==0).
     */
    CHECK(dns->naddresses == 0,
          "naddresses=%u after OOM (expected 0 -- adoption must be reverted)",
          dns->naddresses);
    CHECK(dns->addresses == NULL,
          "addresses non-NULL after OOM (expected NULL -- adoption must be "
          "reverted)");
    CHECK(dns->last_resolved == 0,
          "last_resolved=%" PRId64 " after OOM (expected 0 so the next resolve "
          "is still 'due' and retries)", dns->last_resolved);

    /*
     * Simulate the next client request / DNS tick: a consumer indexes a parallel
     * array ONLY when naddresses>0. On the fixed dns naddresses==0, so this is a
     * safe no-op -- no NULL deref. This is the access that crashes pre-fix.
     */
    if (dns->naddresses > 0 && dns->addresses != NULL) {
        volatile uint32_t sink = dns->latencies[0];   /* must NOT run */
        (void)sink;
        CHECK(false, "fixed dns wrongly reported naddresses>0 after OOM");
    }

    free_dns(dns);

    if (failures == 0) {
        printf("OK: first-resolution OOM reverts the adoption -> empty, "
               "self-consistent dns (naddresses=0, addresses=NULL); next access "
               "is a guarded no-op; next resolve is still due\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
#endif
}
