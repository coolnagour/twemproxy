/*
 * Standalone unit test for the realloc-failure safety of the server_dns
 * accumulate-append path, on the array-of-structs layout.
 *
 * ---------------------------------------------------------------------------
 * WHAT CHANGED WITH THE AoS REFACTOR
 * ---------------------------------------------------------------------------
 * The append path used to grow EIGHT parallel arrays with eight nc_reallocs,
 * which created a partial-failure hazard: if realloc #6 failed after #1..#5
 * succeeded, a naive write-back-last left every already-grown dns->* dangling at
 * a freed block and leaked the grown blocks. The old version of this test proved
 * the "all-or-nothing, realloc straight into dns->*" fix for that eight-array
 * dance.
 *
 * After folding the parallel arrays into ONE dns_addr array there is a SINGLE
 * realloc. The eight-way partial-failure class is STRUCTURALLY gone. But a
 * single realloc still has the classic footgun:
 *
 *     dns->addrs = nc_realloc(dns->addrs, new_size);   // WRONG
 *
 * On failure nc_realloc returns NULL and leaves the ORIGINAL block valid -- but
 * the line above just overwrote dns->addrs with NULL, so the original block
 * leaks AND dns->addrs now dangles at NULL while naddresses still says ">0".
 * The fix is to realloc into a temporary, check it, and only then write back
 * (and never bump naddresses on failure):
 *
 *     struct dns_addr *p = nc_realloc(dns->addrs, new_size);
 *     if (p == NULL) { ...free temps...; return NC_ENOMEM; }   // dns->addrs intact
 *     dns->addrs = p;
 *
 * ---------------------------------------------------------------------------
 * WHY A MIRROR (read before changing the test)
 * ---------------------------------------------------------------------------
 * The real append is INLINE in server_dns_resolve(), which calls the network
 * resolver, so it cannot run offline. append_addr_grow() below MIRRORS the
 * single-realloc grow of the `if (!found)` path, run against a REAL,
 * production-shaped struct server_dns. The ONLY behavioural difference between
 * the two builds is the write-back strategy, gated by TEST_REALLOC_BUGGY.
 *
 *     *** KEEP append_addr_grow()'s realloc/write-back block IN SYNC with the
 *         `if (!found)` realloc block of server_dns_resolve() in
 *         src/nc_server.c. ***
 *
 * ---------------------------------------------------------------------------
 * FAILURE INJECTION
 * ---------------------------------------------------------------------------
 * This file swaps the production nc_realloc macro for the shim below via an
 * in-source #undef/#define (a command-line -Dnc_realloc gets clobbered by
 * nc_util.h's own macro). Disarmed, the shim relocates-on-success (so a stale
 * pointer becomes a deterministic UAF) and forwards to the real allocator.
 * Armed via arm_realloc_fail_after(0) it fails the very next realloc, leaving
 * the caller's pointer intact (the real realloc contract the fix relies on).
 *
 * ---------------------------------------------------------------------------
 * BEFORE/AFTER (TDD red->green)
 * ---------------------------------------------------------------------------
 *   default build (fixed write-back): after a forced realloc failure, dns->addrs
 *     still points at the live block, naddresses is unchanged, addresses[0] is
 *     readable, and a retry append succeeds -> exits 0, clean under libgmalloc +
 *     leaks.
 *   -DTEST_REALLOC_BUGGY (footgun write-back): the same forced failure overwrites
 *     dns->addrs with NULL and leaks the original block. We report it ourselves
 *     (dns->addrs == NULL while naddresses>0) so a PLAIN build FAILS, and the
 *     subsequent read of dns->addrs[0] is a genuine NULL deref that ASan/
 *     libgmalloc trap, while `leaks` flags the orphaned block. run.sh builds
 *     BOTH variants.
 *
 * ---------------------------------------------------------------------------
 * ALSO COVERED: the new_hostnames error-path leak
 * ---------------------------------------------------------------------------
 * server_dns_resolve() carries a function-local temporary alongside the resolved
 * list: char **new_hostnames. The success tail frees both; the nomem branch must
 * too, or it leaks the array + element strings on any realloc OOM. append_addr_
 * grow() takes a populated new_hostnames temp and frees it in its nomem branch.
 * The -DTEST_OMIT_HOSTNAMES_FREE build drops that free, so `leaks` reports the
 * orphans (the RED for this fix).
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
 * nc_post_run() from there. (Same as the sibling tests.)
 */
void nc_post_run(struct instance *nci) { (void)nci; }

/*
 * DEFAULT_LATENCY_USEC is file-local in src/nc_server.c. Its value is irrelevant
 * to the realloc-safety invariant under test; mirror it.
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

/* ------------------------------------------------------------------------- *
 * nc_realloc failure-injection shim. Wired to the mirror further down via an
 * in-source #undef/#define of nc_realloc.
 * ------------------------------------------------------------------------- */

static int  realloc_calls_left = -1;   /* <0 == disarmed (forward everything) */
static bool realloc_armed      = false;

/* Arm: allow the next `succeed` reallocs, then fail (return NULL) on the one
 * after. succeed==0 fails the very first armed call. */
static void
arm_realloc_fail_after(int succeed)
{
    realloc_armed = true;
    realloc_calls_left = succeed;
}

static void
disarm_realloc(void)
{
    realloc_armed = false;
    realloc_calls_left = -1;
}

/*
 * Drop-in for nc_realloc(_p,_s). Disarmed: relocate-grow via the real allocator
 * so a stale pointer copy is guaranteed to dangle. Armed: count down; on the
 * failing call return NULL and leave `ptr` intact (the real realloc contract).
 */
static void *
test_realloc(void *ptr, size_t size)
{
    void *p;

    if (realloc_armed) {
        if (realloc_calls_left <= 0) {
            return NULL;                 /* failing realloc: original stays valid */
        }
        realloc_calls_left--;
    }

    p = _nc_realloc(ptr, size, __FILE__, __LINE__);   /* correct-size grow */
    if (p == NULL) {
        return NULL;
    }
    {
        void *moved = _nc_alloc(size, __FILE__, __LINE__);
        if (moved == NULL) {
            return p;
        }
        memcpy(moved, p, size);
        _nc_free(p, __FILE__, __LINE__);
        return moved;
    }
}

/* ------------------------------------------------------------------------- *
 * Production-shaped server_dns fixture: one dns_addr array sized to `start`.
 * Built via the REAL allocator (shim disarmed), so the only realloc the shim
 * sees is the one inside append_addr_grow().
 * ------------------------------------------------------------------------- */

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

static struct server_dns *
make_dns_n(uint32_t start)
{
    struct server_dns *dns = nc_zalloc(sizeof(*dns));
    uint32_t i;

    dns->max_addresses = 16;          /* == MAX_ADDRESSES_PER_SERVER */
    dns->naddresses = start;
    dns->next_zone_id = 1;
    dns->local_zone_id = 1;
    string_init(&dns->hostname);
    string_copy(&dns->hostname, (uint8_t *)"reader.example", 14);

    dns->addrs = nc_alloc(start * sizeof(struct dns_addr));

    for (i = 0; i < start; i++) {
        struct dns_addr *a = &dns->addrs[i];
        memset(a, 0, sizeof(*a));
        make_addr(&a->addr, i);
        a->latency          = TEST_DEFAULT_LATENCY_USEC;
        a->latency_measured = false;
        a->health_score     = 100;
        string_init(&a->hostname);
        string_copy(&a->hostname, dns->hostname.data, dns->hostname.len);
    }

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
 * Route the mirror's nc_realloc through the failure-injection shim. Must be done
 * HERE, not via -Dnc_realloc: nc_util.h unconditionally re-#defines nc_realloc,
 * so a command-line define is clobbered. We #undef + point nc_realloc at the
 * shim AFTER all headers + the fixture are compiled, so only append_addr_grow()
 * is affected; make_dns_n / free_dns keep the real nc_alloc/nc_free.
 */
#undef nc_realloc
#define nc_realloc(_p, _s) test_realloc((_p), (size_t)(_s))

/* ------------------------------------------------------------------------- *
 * MIRROR of the single-realloc grow of the `if (!found)` path in
 * server_dns_resolve(). `new_addresses_temp` / `new_hostnames_temp` stand in for
 * the two function-local temporaries the production nomem branch frees.
 *
 *     *** KEEP this block (and its nomem temp-free) IN SYNC with the `if
 *         (!found)` realloc block AND success tail of server_dns_resolve() in
 *         src/nc_server.c. ***
 *
 * Returns NC_OK on success, NC_ENOMEM on a forced realloc failure.
 * ------------------------------------------------------------------------- */
static int
append_addr_grow(struct server_dns *dns, struct sockinfo *cand,
                 void *new_addresses_temp,
                 char **new_hostnames_temp, uint32_t new_hostnames_temp_n)
{
    uint32_t new_size = dns->naddresses + 1;
    struct dns_addr *a;

#ifdef TEST_REALLOC_BUGGY
    /* ---- FOOTGUN: assign realloc result straight back, check after ---- */
    dns->addrs = nc_realloc(dns->addrs, new_size * sizeof(struct dns_addr));
    if (dns->addrs == NULL) {
        /*
         * On failure realloc left the ORIGINAL block valid, but we just clobbered
         * dns->addrs with NULL -> original block leaks, dns->addrs dangles at
         * NULL while naddresses is unchanged (>0). Free the temps so THIS bug is
         * isolated to the addrs leak, then bail.
         */
        if (new_addresses_temp) nc_free(new_addresses_temp);
        if (new_hostnames_temp != NULL) {
            for (uint32_t hi = 0; hi < new_hostnames_temp_n; hi++) {
                if (new_hostnames_temp[hi] != NULL) nc_free(new_hostnames_temp[hi]);
            }
            nc_free(new_hostnames_temp);
        }
        return NC_ENOMEM;
    }
#else
    /* ---- FIXED: realloc into a temp, write back only on success ---- */
    {
        struct dns_addr *p = nc_realloc(dns->addrs, new_size * sizeof(struct dns_addr));
        if (p == NULL) goto nomem;
        dns->addrs = p;
    }
#endif

    /* New element copy into slot [naddresses], then bump. */
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
    return NC_OK;

#ifndef TEST_REALLOC_BUGGY
nomem:
    /* Fixed nomem branch: dns->addrs untouched (realloc returned NULL), free the
     * temps, return WITHOUT bumping naddresses. */
    if (new_addresses_temp) nc_free(new_addresses_temp);
    /*
     * Mirror of the production nomem hostname-free (== the success-tail free).
     * -DTEST_OMIT_HOSTNAMES_FREE omits this, reproducing the pre-fix leak so
     * `leaks` reports the orphaned array + element strings (the TDD red).
     */
#ifndef TEST_OMIT_HOSTNAMES_FREE
    if (new_hostnames_temp != NULL) {
        for (uint32_t hi = 0; hi < new_hostnames_temp_n; hi++) {
            if (new_hostnames_temp[hi] != NULL) {
                nc_free(new_hostnames_temp[hi]);
            }
        }
        nc_free(new_hostnames_temp);
    }
#endif
    return NC_ENOMEM;
#endif
}

/* ------------------------------------------------------------------------- *
 * The test: force the grow realloc to fail, then assert dns->addrs is intact,
 * naddresses unchanged, addresses readable, and a retry works. No leak.
 * ------------------------------------------------------------------------- */
static void
test_realloc_failure(void)
{
    struct server_dns *dns = make_dns_n(3);   /* 3 existing addresses */
    uint32_t naddr_before = dns->naddresses;
    struct dns_addr *addrs_before = dns->addrs;
    struct sockinfo cand;
    int rc;

    /* Stand-in for the function-local resolved list the nomem branch frees. */
    void *temp_resolved = nc_alloc(64);

    /* Stand-in for the parallel hostname array (char ** + count): a heap array of
     * char* with element strings via the SAME allocator, plus a NULL hole to
     * exercise the per-element guard. On a forced OOM the nomem branch must free
     * all of it -- `leaks` flags the orphans if the hostname-free is absent
     * (TEST_OMIT_HOSTNAMES_FREE). */
    uint32_t hn_n = 3;
    char **temp_hostnames = nc_alloc(hn_n * sizeof(char *));
    {
        uint32_t hi;
        for (hi = 0; hi < hn_n; hi++) {
            if (hi == 1) { temp_hostnames[hi] = NULL; continue; }
            const char *name = "reader-az1.example.internal";
            size_t len = strlen(name) + 1;
            temp_hostnames[hi] = nc_alloc(len);
            memcpy(temp_hostnames[hi], name, len);
        }
    }

    make_addr(&cand, 99);

    /* Arm: fail the very next realloc (the grow). */
    arm_realloc_fail_after(0);
    rc = append_addr_grow(dns, &cand, temp_resolved, temp_hostnames, hn_n);
    disarm_realloc();

    /* (1) The append must report OOM. */
    CHECK(rc == NC_ENOMEM,
          "expected NC_ENOMEM from forced realloc failure, got %d", rc);

    /* (2) naddresses must be UNCHANGED across the failed append. */
    CHECK(dns->naddresses == naddr_before,
          "naddresses changed across failed append: %u -> %u "
          "(must not bump on OOM)", naddr_before, dns->naddresses);

    /*
     * (3) dns->addrs must NOT dangle. On the fixed build realloc returned NULL
     * and dns->addrs was never overwritten, so it still equals the original live
     * block. On the buggy build dns->addrs was clobbered with NULL (and the
     * original leaked) -- this assert fires on a plain build, and the read below
     * is a NULL deref the heap guard traps.
     */
    CHECK(dns->addrs != NULL,
          "dns->addrs is NULL after failed append -- original block leaked and "
          "the pointer dangles (the realloc footgun)");
    CHECK(dns->addrs == addrs_before,
          "dns->addrs changed after a FAILED realloc (expected the original "
          "block to stay, untouched)");

    /*
     * (4) The address records must still be readable at [0, naddresses). Slot 0
     * was seeded with AF_INET / port 6379 by make_dns_n.
     */
    if (dns->addrs != NULL) {
        volatile uint32_t sink = 0;
        uint32_t k;
        for (k = 0; k < dns->naddresses; k++) {
            struct sockaddr_in *in = (struct sockaddr_in *)&dns->addrs[k].addr.addr;
            sink += in->sin_family;
            sink += dns->addrs[k].latency;
            sink += dns->addrs[k].hostname.len;
        }
        (void)sink;

        struct sockaddr_in *in0 = (struct sockaddr_in *)&dns->addrs[0].addr.addr;
        CHECK(in0->sin_family == AF_INET,
              "addrs[0] not readable/intact after failed append (family=%d)",
              in0->sin_family);
        CHECK(ntohs(in0->sin_port) == 6379,
              "addrs[0] port corrupted after failed append (%u)",
              ntohs(in0->sin_port));
    }

    /*
     * (5) A retry append must still work (the struct is consistent). Only
     * meaningful on the fixed build -- on the buggy build dns->addrs is NULL.
     */
#ifndef TEST_REALLOC_BUGGY
    {
        struct sockinfo cand2;
        void *temp2 = nc_alloc(64);
        int rc2;
        make_addr(&cand2, 100);
        rc2 = append_addr_grow(dns, &cand2, temp2, NULL, 0);   /* disarmed -> succeeds */
        CHECK(rc2 == NC_OK,
              "retry append after OOM failed (rc=%d) -- struct not consistent", rc2);
        CHECK(dns->naddresses == naddr_before + 1,
              "retry append did not grow naddresses (%u, expected %u)",
              dns->naddresses, naddr_before + 1);
        nc_free(temp2);  /* success path does not free the temp; do it here */
    }
#endif

    free_dns(dns);

    /*
     * NOTE on leaks: on the buggy build the original addrs block is orphaned
     * (dns->addrs was nulled), so `leaks --atExit` reports it. The new_hostnames
     * temp + its element strings are owned by the append on a forced OOM; the
     * fixed nomem branch frees them, so the default build is leak-clean.
     * -DTEST_OMIT_HOSTNAMES_FREE skips that free -> `leaks` reports those orphans
     * too (the TDD red). We do NOT free temp_hostnames here on purpose -- the
     * append owns that cleanup on the nomem path, exactly as production does.
     */
}

int
main(void)
{
    test_realloc_failure();

#ifdef TEST_REALLOC_BUGGY
    if (failures > 0) {
        printf("EXPECTED-FAIL (footgun-writeback build): %d assertion(s) -- "
               "the pre-fix realloc NULL-clobber/leak reproducing\n", failures);
        return 1;
    }
    fprintf(stderr,
            "UNEXPECTED: buggy build reported no dangle/leak via asserts -- "
            "rely on libgmalloc/leaks; treat as not-exercised\n");
    return 2;
#else
    if (failures == 0) {
        printf("OK: single-realloc grow holds; dns->addrs intact and naddresses "
               "unchanged on forced OOM; no leak\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
#endif
}
