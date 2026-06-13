/*
 * Standalone unit test for the realloc-failure safety of the server_dns
 * accumulate-append path (fork-hardening fix #4: an all-or-nothing realloc so a
 * partial out-of-memory failure can never leave a dns->* array dangling at a
 * freed block, nor leak the blocks that did grow).
 *
 * ---------------------------------------------------------------------------
 * THE BUG THIS GUARDS (pre-fix server_dns_resolve(), src/nc_server.c)
 * ---------------------------------------------------------------------------
 * The append path grows 8 eager parallel arrays with nc_realloc, into LOCAL
 * variables, then does a single combined NULL-check afterwards:
 *
 *     struct sockinfo *new_addr_array = nc_realloc(dns->addresses, ...);
 *     uint32_t        *new_latencies  = nc_realloc(dns->latencies, ...);
 *     ...  (8 reallocs into locals)
 *     if (new_addr_array == NULL || new_latencies == NULL || ...) {
 *         nc_free(new_addresses);          // temp resolved list
 *         return NC_ENOMEM;                // <-- returns WITHOUT write-back
 *     }
 *     dns->addresses = new_addr_array;     // write-back only on full success
 *     ...
 *
 * realloc(p,n) FREES/relocates the old block on success. So once the first few
 * reallocs succeed, dns->addresses et al. still point at the OLD (now freed)
 * blocks -- the grown blocks live only in the locals. If a LATER realloc
 * returns NULL the function returns before the write-back, so:
 *   - every dns->* that was already grown now DANGLES at freed memory
 *     (use-after-free / heap corruption on the next resolve or read), and
 *   - the successfully-grown blocks are LEAKED (only the discarded locals
 *     referenced them).
 *
 * ---------------------------------------------------------------------------
 * THE FIX (mirrored below, gated by TEST_REALLOC_BUGGY)
 * ---------------------------------------------------------------------------
 * Exploit the C guarantee that realloc returns NULL on failure and leaves the
 * ORIGINAL pointer valid (not freed). Realloc each array straight back into its
 * dns-> field, checking each before the next; on any failure goto nomem (free
 * the temp resolved list, return NC_ENOMEM) WITHOUT incrementing naddresses:
 *
 *     void *p;
 *     p = nc_realloc(dns->addresses, ...); if (p==NULL) goto nomem; dns->addresses = p;
 *     p = nc_realloc(dns->latencies, ...); if (p==NULL) goto nomem; dns->latencies = p;
 *     ...  (all 8)
 *
 * Then: the failing array's dns->X is untouched (realloc returned NULL, old
 * block intact); the already-processed arrays were grown AND written back
 * (valid, merely larger than naddresses); the not-yet-processed arrays are
 * still at the old size. naddresses is NOT bumped, so every array's allocation
 * is >= naddresses -> fix #2's helper invariant holds, no dangle, no leak. The
 * next resolve just reallocs again.
 *
 * ---------------------------------------------------------------------------
 * WHY A MIRROR (read before changing the test)
 * ---------------------------------------------------------------------------
 * The real append is INLINE in server_dns_resolve(), which calls the network
 * resolver (nc_resolve_multi_with_hostnames), so it cannot run offline and the
 * append cannot be driven in isolation. So -- exactly like test_address_cap.c
 * mirrors the cap decision and test_remove_address.c mirrors the index fixup --
 * append_addr_grow() below MIRRORS the realloc-grow block of the `if (!found)`
 * path, run against a REAL, production-shaped `struct server_dns` (the real
 * struct layout from the linked nc_server.c object; lazy arrays calloc'd ONCE
 * to max_addresses). The ONLY behavioural difference between the two builds is
 * the write-back strategy, gated by TEST_REALLOC_BUGGY -- so run.sh builds the
 * "bug reproduces" and the "bug fixed" variants from this one source.
 *
 *     *** KEEP append_addr_grow()'s realloc/write-back block IN SYNC with the
 *         `if (!found)` realloc block of server_dns_resolve() in
 *         src/nc_server.c. ***
 *
 * ---------------------------------------------------------------------------
 * FAILURE INJECTION (the UAF/leak is invisible to a normal run -- it only
 * triggers when a realloc actually fails partway through)
 * ---------------------------------------------------------------------------
 * This file swaps the production nc_realloc macro for the shim below via an
 * in-source #undef/#define (NOT a command-line -Dnc_realloc -- nc_util.h
 * re-#defines nc_realloc and would clobber it; see the note above
 * append_addr_grow). Disarmed, the shim forwards to the real _nc_realloc. Armed
 * (via arm_realloc_fail_after(K)) it lets the next K reallocs succeed and
 * returns NULL on the (K+1)th -- i.e. a real partial OOM.
 *
 * Fidelity note (important): on every SUCCESS the shim RELOCATES the block
 * (alloc-fresh + memcpy + free-old) instead of calling realloc in place. That
 * is behaviour realloc is explicitly permitted (and, under libgmalloc, always
 * does -- each realloc lands on a fresh guarded page). Forcing the move makes
 * the pre-fix dangling-pointer read a DETERMINISTIC use-after-free every run
 * (otherwise an in-place grow could leave the old pointer coincidentally
 * valid and mask the bug). The failing call leaves the caller's pointer intact,
 * exactly like the real realloc contract the fix relies on.
 *
 * ---------------------------------------------------------------------------
 * BEFORE/AFTER (TDD red->green)
 * ---------------------------------------------------------------------------
 *   default build (fixed write-back): after a forced mid-sequence realloc
 *     failure, every dns->* still points at a live block, naddresses is
 *     unchanged, and nothing leaks -> exits 0, clean under libgmalloc + leaks.
 *
 *   -DTEST_REALLOC_BUGGY (pre-fix write-back): the same forced failure returns
 *     with dns->* dangling at freed blocks and the grown blocks leaked. We
 *     report it ourselves (the dangling pointers no longer equal the live
 *     blocks) so a PLAIN build FAILS (non-zero), and the subsequent read of
 *     dns->addresses[0] is a genuine UAF that libgmalloc traps, while `leaks`
 *     flags the orphaned blocks. run.sh builds BOTH variants.
 *
 * ---------------------------------------------------------------------------
 * ALSO COVERED HERE: the new_hostnames error-path leak fix
 * ---------------------------------------------------------------------------
 * server_dns_resolve() carries a SECOND function-local temporary alongside the
 * resolved-address list: char **new_hostnames (+ new_naddresses), the parallel
 * array of captured canonical hostname strings. The success tail frees BOTH
 * temporaries; the pre-fix nomem (OOM) branch freed ONLY the resolved list,
 * leaking new_hostnames and every non-NULL element string on any realloc OOM
 * during the append. The fix mirrors the success-tail hostname free into nomem.
 *
 * append_addr_grow() below takes a populated new_hostnames temp (a heap char*
 * array with non-NULL element strings allocated via the same allocator, plus a
 * NULL hole to exercise the per-element guard) and, in its nomem branch, frees
 * it the way the fixed production nomem does. Variant flag for THIS fix:
 *
 *   default build (hostname-free present): the forced-OOM nomem frees the temp
 *     array + element strings -> leak-clean under `leaks` (GREEN).
 *   -DTEST_OMIT_HOSTNAMES_FREE (hostname-free absent): the forced-OOM nomem
 *     skips that free; the array + its element strings are orphaned with no
 *     other owner -> `leaks --atExit` reports them (the RED for this fix).
 *
 * run.sh builds and runs the default (must be leak-clean) variant; the
 * TEST_OMIT_HOSTNAMES_FREE red is demonstrable on demand (see the comment by
 * its build line in run.sh) since `leaks` is what distinguishes the two and the
 * harness's run_test path runs every binary under it on macOS.
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
 * stub satisfies the linker. (Same as test_address_cap.c / test_remove_address.c.)
 */
void nc_post_run(struct instance *nci) { (void)nci; }

/*
 * DEFAULT_LATENCY_USEC is file-local in src/nc_server.c (not the header). Its
 * value is irrelevant to the realloc-safety invariant under test; mirror it.
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
 * in-source #undef/#define of nc_realloc (see the note above append_addr_grow
 * for why a command-line -Dnc_realloc does not work).
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
 * Drop-in for nc_realloc(_p,_s). The production macro forwards file/line; here
 * the test source is the only caller, so a 2-arg shim is enough (the override
 * is scoped to this translation unit only -- nc_server.c keeps the real macro).
 *
 * Disarmed: relocate-grow via the real allocator (see fidelity note in the file
 * header) so behaviour matches an out-of-place realloc.
 * Armed: count down; on the failing call return NULL and leave `ptr` intact
 * (the real realloc contract the fix depends on).
 */
static void *
test_realloc(void *ptr, size_t size)
{
    void *p;

    if (realloc_armed) {
        if (realloc_calls_left <= 0) {
            /* The failing realloc: original block stays valid, return NULL. */
            return NULL;
        }
        realloc_calls_left--;
    }

    /*
     * Success path. First grow correctly via the real realloc (gives a block of
     * exactly `size` bytes whose old contents are preserved and whose original
     * block is freed). Then RELOCATE that block to a fresh allocation and free
     * it, so the address the caller passed in is guaranteed gone. Any stale
     * copy of the old pointer (the pre-fix dns->* on an early-grown array) is
     * now a dangling pointer -> deterministic use-after-free for the buggy
     * build, harmless for the fixed build (which never keeps a stale copy).
     */
    p = _nc_realloc(ptr, size, __FILE__, __LINE__);   /* correct-size grow */
    if (p == NULL) {
        return NULL;                                  /* genuine OOM */
    }
    {
        void *moved = _nc_alloc(size, __FILE__, __LINE__);
        if (moved == NULL) {
            return p; /* fall back to the realloc'd block; still valid */
        }
        memcpy(moved, p, size);                        /* p is exactly `size` */
        _nc_free(p, __FILE__, __LINE__);
        return moved;
    }
}

/* ------------------------------------------------------------------------- *
 * Production-shaped server_dns fixture (mirrors make_dns_one in
 * test_address_cap.c: eager arrays sized to naddresses, lazy arrays calloc'd
 * once to max_addresses).
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

/*
 * Build with `start` addresses already present (eager arrays sized to start,
 * lazy arrays calloc'd to max_addresses). The fixture allocates via the REAL
 * allocator (these calls happen while the shim is disarmed), so the only
 * reallocs the shim sees are the ones inside append_addr_grow().
 */
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

    dns->addresses          = nc_alloc(start * sizeof(struct sockinfo));
    dns->latencies          = nc_alloc(start * sizeof(uint32_t));
    dns->last_latency_check = nc_alloc(start * sizeof(int64_t));
    dns->failure_counts     = nc_alloc(start * sizeof(uint32_t));
    dns->last_seen          = nc_alloc(start * sizeof(int64_t));
    dns->last_connected     = nc_alloc(start * sizeof(int64_t));
    dns->request_counts     = nc_alloc(start * sizeof(uint64_t));
    dns->hostnames          = nc_alloc(start * sizeof(struct string));

    /* Lazy arrays: fixed cap, exactly like the production calloc sites. */
    dns->zone_ids          = nc_calloc(dns->max_addresses, sizeof(uint32_t));
    dns->health_scores     = nc_calloc(dns->max_addresses, sizeof(uint32_t));
    dns->last_health_check = nc_calloc(dns->max_addresses, sizeof(int64_t));

    for (i = 0; i < start; i++) {
        make_addr(&dns->addresses[i], i);
        dns->latencies[i]          = TEST_DEFAULT_LATENCY_USEC;
        dns->last_latency_check[i] = 0;
        dns->failure_counts[i]     = 0;
        dns->last_seen[i]          = 0;
        dns->last_connected[i]     = 0;
        dns->request_counts[i]     = 0;
        string_init(&dns->hostnames[i]);
        string_copy(&dns->hostnames[i], dns->hostname.data, dns->hostname.len);
        dns->zone_ids[i]          = 0;
        dns->health_scores[i]     = 100;
        dns->last_health_check[i] = 0;
    }

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

/*
 * Route the mirror's nc_realloc through the failure-injection shim.
 *
 * NOTE: this must be done HERE, not via -Dnc_realloc on the command line.
 * nc_util.h unconditionally re-#defines nc_realloc(_p,_s) to _nc_realloc(...),
 * so any command-line -Dnc_realloc is clobbered by the header and the shim is
 * never reached (verified with `cc -E`). We #undef the header macro and point
 * nc_realloc at the shim AFTER all headers + the fixture are compiled, so only
 * append_addr_grow() below (the production mirror) is affected; make_dns_n /
 * free_dns above keep the real nc_alloc/nc_calloc/nc_free.
 */
#undef nc_realloc
#define nc_realloc(_p, _s) test_realloc((_p), (size_t)(_s))

/* ------------------------------------------------------------------------- *
 * MIRROR of the realloc-grow block of the `if (!found)` path in
 * server_dns_resolve(). The cap guard and the dedup are not relevant here (we
 * always grow), so only the realloc/write-back + new-slot copy + naddresses++
 * are mirrored. `new_addresses_temp` stands in for the function-local resolved
 * list that the production nomem branch frees.
 *
 * `new_hostnames_temp` / `new_hostnames_temp_n` stand in for the SECOND
 * function-local temporary the production code carries: the parallel array of
 * captured canonical hostname strings (char **new_hostnames + new_naddresses).
 * The success tail of server_dns_resolve() frees BOTH temporaries -- the
 * resolved list AND new_hostnames (per-element strings + the array). The
 * pre-fix nomem branch freed ONLY the resolved list, leaking new_hostnames and
 * every non-NULL element string on any realloc OOM. The fix mirrors the
 * success tail's hostname free into nomem. This test models that array
 * (populated with at least one non-NULL element string allocated via the SAME
 * allocator) and asserts nomem frees it: default build (fix present) leaks
 * nothing; the -DTEST_OMIT_HOSTNAMES_FREE build (fix absent) leaks the array +
 * its element strings -> `leaks` reports them (the TDD red for THIS fix).
 *
 *     *** KEEP this nomem hostname-free block IN SYNC with both the nomem
 *         label AND the success tail of server_dns_resolve() in
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

#ifdef TEST_REALLOC_BUGGY
    /* ---- PRE-FIX: realloc into locals, combined check, write-back last ---- */
    struct sockinfo *new_addr_array       = nc_realloc(dns->addresses, new_size * sizeof(*dns->addresses));
    uint32_t        *new_latencies        = nc_realloc(dns->latencies, new_size * sizeof(*dns->latencies));
    int64_t         *new_last_latency     = nc_realloc(dns->last_latency_check, new_size * sizeof(*dns->last_latency_check));
    uint32_t        *new_failure_counts   = nc_realloc(dns->failure_counts, new_size * sizeof(*dns->failure_counts));
    int64_t         *new_last_seen        = nc_realloc(dns->last_seen, new_size * sizeof(*dns->last_seen));
    int64_t         *new_last_connected   = nc_realloc(dns->last_connected, new_size * sizeof(*dns->last_connected));
    uint64_t        *new_request_counts   = nc_realloc(dns->request_counts, new_size * sizeof(*dns->request_counts));
    struct string   *new_hostnames_array  = nc_realloc(dns->hostnames, new_size * sizeof(*dns->hostnames));

    if (new_addr_array == NULL || new_latencies == NULL ||
        new_last_latency == NULL || new_failure_counts == NULL ||
        new_last_seen == NULL || new_last_connected == NULL ||
        new_request_counts == NULL || new_hostnames_array == NULL) {
        /*
         * Pre-fix nomem branch FOR FIX #4 (the realloc write-back bug): free the
         * temp resolved list and return -- the successful new_* locals are
         * dropped on the floor (LEAK) and dns->* is left pointing at the blocks
         * realloc already freed (DANGLING). The new_hostnames temp is freed
         * unconditionally here so this (fix #4) variant does not also leak it --
         * the new_hostnames-leak red is isolated to the fixed-writeback build
         * below, gated by TEST_OMIT_HOSTNAMES_FREE.
         */
        if (new_addresses_temp) nc_free(new_addresses_temp);
        if (new_hostnames_temp != NULL) {
            for (uint32_t hi = 0; hi < new_hostnames_temp_n; hi++) {
                if (new_hostnames_temp[hi] != NULL) {
                    nc_free(new_hostnames_temp[hi]);
                }
            }
            nc_free(new_hostnames_temp);
        }
        return NC_ENOMEM;
    }

    dns->addresses          = new_addr_array;
    dns->latencies          = new_latencies;
    dns->last_latency_check = new_last_latency;
    dns->failure_counts     = new_failure_counts;
    dns->last_seen          = new_last_seen;
    dns->last_connected     = new_last_connected;
    dns->request_counts     = new_request_counts;
    dns->hostnames          = new_hostnames_array;
#else
    /* ---- FIXED: all-or-nothing, realloc straight back into dns->* ---- */
    void *p;
    p = nc_realloc(dns->addresses,          new_size * sizeof(*dns->addresses));          if (p == NULL) goto nomem; dns->addresses          = p;
    p = nc_realloc(dns->latencies,          new_size * sizeof(*dns->latencies));          if (p == NULL) goto nomem; dns->latencies          = p;
    p = nc_realloc(dns->last_latency_check, new_size * sizeof(*dns->last_latency_check)); if (p == NULL) goto nomem; dns->last_latency_check = p;
    p = nc_realloc(dns->failure_counts,     new_size * sizeof(*dns->failure_counts));     if (p == NULL) goto nomem; dns->failure_counts     = p;
    p = nc_realloc(dns->last_seen,          new_size * sizeof(*dns->last_seen));          if (p == NULL) goto nomem; dns->last_seen          = p;
    p = nc_realloc(dns->last_connected,     new_size * sizeof(*dns->last_connected));     if (p == NULL) goto nomem; dns->last_connected     = p;
    p = nc_realloc(dns->request_counts,     new_size * sizeof(*dns->request_counts));     if (p == NULL) goto nomem; dns->request_counts     = p;
    p = nc_realloc(dns->hostnames,          new_size * sizeof(*dns->hostnames));          if (p == NULL) goto nomem; dns->hostnames          = p;
#endif

    /* New element copy into slot [naddresses], then bump -- unchanged. */
    memcpy(&dns->addresses[dns->naddresses], cand, sizeof(struct sockinfo));
    dns->latencies[dns->naddresses]          = TEST_DEFAULT_LATENCY_USEC;
    dns->last_latency_check[dns->naddresses] = 0;
    dns->failure_counts[dns->naddresses]     = 0;
    dns->last_seen[dns->naddresses]          = 1;
    dns->last_connected[dns->naddresses]     = 0;
    dns->request_counts[dns->naddresses]     = 0;
    string_init(&dns->hostnames[dns->naddresses]);
    string_copy(&dns->hostnames[dns->naddresses],
                dns->hostname.data, dns->hostname.len);

    dns->naddresses++;
    return NC_OK;

#ifndef TEST_REALLOC_BUGGY
nomem:
    /* Fixed nomem branch: free the temp resolved list, return WITHOUT bumping
     * naddresses. dns->* arrays are all >= naddresses, none dangling. */
    if (new_addresses_temp) nc_free(new_addresses_temp);
    /*
     * Mirror of the production nomem hostname-free (== the success-tail free):
     * release the parallel new_hostnames temp + every captured element string.
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
 * The test: force a realloc failure partway through the 8 grows, then assert
 * no dangling pointer, naddresses unchanged, no leak.
 * ------------------------------------------------------------------------- */

/*
 * Snapshot the 8 eager pointers so we can detect, on a plain build, whether the
 * failed append left any of them changed to a (now-freed) block. On the fixed
 * build the failing array's pointer is unchanged and the grown ones point at
 * LIVE blocks; on the buggy build dns->* is whatever the locals would have been
 * (and on the early-failure indices, still the freed originals) -- we detect
 * the breakage via the live-readback + naddresses checks below rather than by
 * pointer identity, so this works for either variant.
 */
static void
test_realloc_failure_at(int fail_after)
{
    struct server_dns *dns = make_dns_n(3);   /* 3 existing addresses */
    uint32_t naddr_before = dns->naddresses;
    struct sockinfo cand;
    int rc;

    /* A stand-in for the function-local resolved list the production nomem
     * branch frees. Allocated live; the append must free it on failure (no
     * leak) -- `leaks` will catch it if either variant forgets. */
    void *temp_resolved = nc_alloc(64);

    /*
     * A stand-in for the SECOND function-local temp: the parallel hostname
     * array (char **new_hostnames + new_naddresses). Build it exactly like the
     * production resolver does -- a heap array of char* with each element a
     * strdup-style heap copy via the SAME allocator the production code frees
     * with (nc_alloc/nc_free). At least one non-NULL element string MUST be
     * present so the nomem hostname-free loop has something real to release;
     * here every element is populated, plus a deliberate NULL hole to exercise
     * the per-element NULL guard. On a forced OOM the append's nomem branch must
     * free this whole structure -- `leaks` flags the orphans if the fix's
     * hostname-free is absent (TEST_OMIT_HOSTNAMES_FREE). */
    uint32_t hn_n = 3;
    char **temp_hostnames = nc_alloc(hn_n * sizeof(char *));
    {
        uint32_t hi;
        for (hi = 0; hi < hn_n; hi++) {
            if (hi == 1) {
                temp_hostnames[hi] = NULL;          /* NULL hole: guard path */
                continue;
            }
            const char *name = "reader-az1.example.internal";
            size_t len = strlen(name) + 1;
            temp_hostnames[hi] = nc_alloc(len);     /* same allocator family */
            memcpy(temp_hostnames[hi], name, len);
        }
    }

    make_addr(&cand, 99);

    /* Arm: let `fail_after` reallocs succeed, fail the next. With 8 reallocs in
     * the grow, fail_after=5 fails the 6th (last_connected) -- a true mid-
     * sequence partial OOM (5 arrays already grown, 3 not yet). */
    arm_realloc_fail_after(fail_after);
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
     * (3) NO dns->* pointer may dangle: every eager array must be readable at
     * indices [0, naddresses). On the fixed build this is true (failing
     * array untouched; grown arrays live). On the buggy build the early-grown
     * arrays still hold the FREED originals -> this read is a use-after-free
     * that libgmalloc traps; on a plain build the values are garbage/unmapped
     * and at minimum the leak + the readback mismatch below flag the breakage.
     *
     * We read addresses[] (the first realloc'd, hence freed earliest in the
     * buggy build) and confirm slot 0 still holds the family/port we seeded.
     * Touch every array so ASan/libgmalloc inspects them all.
     */
    {
        volatile uint32_t sink = 0;
        uint32_t k;
        for (k = 0; k < dns->naddresses; k++) {
            struct sockaddr_in *in =
                (struct sockaddr_in *)&dns->addresses[k].addr;       /* UAF read on buggy build */
            sink += in->sin_family;
            sink += dns->latencies[k];                                /* UAF read on buggy build */
            sink += (uint32_t)dns->last_latency_check[k];
            sink += dns->failure_counts[k];
            sink += (uint32_t)dns->last_seen[k];
            sink += (uint32_t)dns->last_connected[k];
            sink += (uint32_t)dns->request_counts[k];
            sink += dns->hostnames[k].len;
        }
        (void)sink;

        /* Slot 0 was seeded with AF_INET / port 6379 by make_dns_n. On the
         * fixed build the block is live and still holds that; on a corrupted
         * buggy build it will not (freed/overwritten) -- a plain-build failure
         * signal independent of the heap guard. */
        struct sockaddr_in *in0 = (struct sockaddr_in *)&dns->addresses[0].addr;
        CHECK(in0->sin_family == AF_INET,
              "addresses[0] not readable/intact after failed append "
              "(family=%d) -- dns->addresses dangles at a freed block",
              in0->sin_family);
        CHECK(ntohs(in0->sin_port) == 6379,
              "addresses[0] port corrupted after failed append (%u) -- "
              "dns->addresses dangles at a freed block",
              ntohs(in0->sin_port));
    }

    /*
     * (4) A SECOND append must still work after the failed one (the arrays are
     * consistent, so a retry succeeds). This catches a fix that left the struct
     * in a state where the next grow misbehaves. Only meaningful on the fixed
     * build -- on the buggy build the struct is already corrupt, so guard it.
     */
#ifndef TEST_REALLOC_BUGGY
    {
        struct sockinfo cand2;
        void *temp2 = nc_alloc(64);
        int rc2;
        make_addr(&cand2, 100);
        /* Success path does not free the temps (production frees once after the
         * loop), so pass NULL hostnames here -- this call exercises retry
         * consistency, not the nomem hostname-free. */
        rc2 = append_addr_grow(dns, &cand2, temp2, NULL, 0);   /* disarmed -> succeeds */
        CHECK(rc2 == NC_OK,
              "retry append after OOM failed (rc=%d) -- struct not consistent",
              rc2);
        CHECK(dns->naddresses == naddr_before + 1,
              "retry append did not grow naddresses (%u, expected %u)",
              dns->naddresses, naddr_before + 1);
        /* temp2 was freed by the successful path? No -- the success path does
         * NOT free the temp list (production frees it once after the loop).
         * Free it here so `leaks` stays clean. */
        nc_free(temp2);
    }
#endif

    free_dns(dns);

    /*
     * NOTE on the leak: on the buggy build, the grown blocks from the
     * successful reallocs are referenced only by append_addr_grow()'s locals,
     * which are gone. free_dns frees dns->* (the FREED originals on early
     * indices -> double-free, trapped by libgmalloc/leaks) and never sees the
     * orphaned grown blocks -> they leak. `leaks --atExit` reports them. On the
     * fixed build dns->* are the live blocks, free_dns frees them all, zero
     * leak.
     *
     * NOTE on the new_hostnames leak (THIS fix): temp_hostnames + its element
     * strings are owned solely by the append on a forced OOM. The fixed nomem
     * branch frees them (mirroring the success tail), so the default build is
     * leak-clean. The -DTEST_OMIT_HOSTNAMES_FREE build skips that free; the
     * array and its two non-NULL element strings are then never freed by anyone
     * (this function holds no other reference), so `leaks --atExit` reports
     * them -- the TDD red proving the error-path leak. We do NOT free
     * temp_hostnames here on purpose: the WHOLE point is that the append owns
     * that cleanup on the nomem path, exactly as production does.
     */
}

int
main(void)
{
    /*
     * Fail on the 6th of the 8 reallocs (5 succeed first): a genuine mid-
     * sequence partial OOM with arrays both grown and not-yet-grown. Also
     * exercise an early failure (2nd realloc) to cover the "only one array
     * grown" boundary.
     */
    test_realloc_failure_at(5);
    test_realloc_failure_at(1);

#ifdef TEST_REALLOC_BUGGY
    if (failures > 0) {
        printf("EXPECTED-FAIL (buggy-writeback build): %d assertion(s) -- "
               "this is the pre-fix realloc UAF/leak reproducing\n", failures);
        return 1;
    }
    /*
     * If the plain-build asserts did not catch it, the heap guard still might
     * have aborted the process before here (rc>128) -- but reaching this line
     * with failures==0 means neither fired, so the harness is not exercising
     * the bug.
     */
    fprintf(stderr,
            "UNEXPECTED: buggy build reported no dangling/leak via asserts -- "
            "rely on libgmalloc/leaks; treat as not-exercised\n");
    return 2;
#else
    if (failures == 0) {
        printf("OK: all-or-nothing realloc holds; no dangling dns->* and "
               "naddresses unchanged on forced OOM; no leak\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
#endif
}
