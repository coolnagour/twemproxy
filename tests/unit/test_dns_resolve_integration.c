/*
 * End-to-end integration test for the REAL DNS-resolution pipeline:
 *
 *     server_dns_resolve()  (src/nc_server.c)
 *         -> nc_resolve_multi_with_hostnames()  (src/nc_util.c)
 *             -> getaddrinfo()                   (libc)
 *
 * ---------------------------------------------------------------------------
 * WHY THIS TEST EXISTS (and why it is different from the others)
 * ---------------------------------------------------------------------------
 * The sibling tests in this suite drive small, isolated pieces of the resolver
 * (init/deinit, the single-struct remove, the first-resolution OOM path). The
 * accumulate / expire / remove MERGE that runs on the SECOND and later resolves
 * -- the logic where the round-2 memory-safety bugs lived (parallel-array
 * desync, the cap OOB, the realloc UAF) -- was only ever exercised by a MIRROR
 * (test_dns_resolve_oom.c re-implements the publish-count block), because
 * driving the real server_dns_resolve() needs a controllable DNS answer.
 *
 * This test removes the mirror gap. It intercepts getaddrinfo() with the
 * GNU-ld --wrap mechanism and feeds server_dns_resolve() a synthetic, fully
 * test-controlled address set, cycle by cycle. So every assertion below is over
 * the REAL struct server_dns that the REAL accumulate/expire/remove code built
 * and mutated -- not a copy of that logic. No network is touched.
 *
 * It also wraps nc_usec_now() so the "now" each resolve sees is deterministic.
 * That makes the EXPIRY case exact instead of a flaky wall-clock race: we can
 * advance the fake clock past dns_expiration_minutes between cycles and assert
 * that stale addresses are removed on the next resolve.
 *
 * ---------------------------------------------------------------------------
 * LINKER REQUIREMENT -- LINUX / GNU ld ONLY
 * ---------------------------------------------------------------------------
 * --wrap is a GNU ld feature. Apple's default linker (ld64 / the new ld-prime)
 * does NOT implement it, so this test cannot even LINK on macOS. tests/unit/
 * run.sh therefore GATES this test: it builds + runs it only where the linker
 * accepts --wrap, and prints a clean SKIPPED line on macOS. (On macOS the
 * accumulate/expire/remove logic is still covered by the test_dns_resolve_oom
 * mirror + the other server_dns tests; this integration test is the Linux/CI
 * superset that drives the real call.)
 *
 * Build/run: tests/unit/run.sh   (it appends -Wl,--wrap=getaddrinfo
 *            -Wl,--wrap=freeaddrinfo -Wl,--wrap=nc_usec_now on Linux).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <nc_core.h>
#include <nc_server.h>
#include <nc_string.h>
#include <nc_util.h>
#include <nc.h>

/* nc.c owns main(); stub nc_post_run for the linker (see sibling tests). */
void nc_post_run(struct instance *nci) { (void)nci; }

/*
 * Mirror of MAX_ADDRESSES_PER_SERVER (a file-local #define in src/nc_server.c).
 * server_dns_init() seeds dns->max_addresses from it. KEEP IN SYNC.
 */
#define TEST_MAX_ADDRESSES_PER_SERVER  16

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
 * Fake clock: --wrap=nc_usec_now.
 *
 * server_dns_resolve() stamps each address's last_seen with the resolve's
 * `now`, and expires an address when (now - last_seen) exceeds the threshold.
 * Driving `now` ourselves makes the expiry case deterministic.
 * ------------------------------------------------------------------------- */
static int64_t fake_now = 1000000000LL;   /* arbitrary positive epoch (usec) */

int64_t __wrap_nc_usec_now(void);
int64_t
__wrap_nc_usec_now(void)
{
    return fake_now;
}

static void
clock_advance_usec(int64_t delta)
{
    fake_now += delta;
}

/* ------------------------------------------------------------------------- *
 * getaddrinfo link seam: --wrap=getaddrinfo / --wrap=freeaddrinfo.
 *
 * The next __wrap_getaddrinfo() call answers from this plan. We build a real
 * addrinfo linked list of IPv4 entries with distinct addresses (base_ip + k),
 * each optionally carrying an ai_canonname, so the real
 * nc_resolve_multi_with_hostnames() copies family/addrlen/addr + the canonical
 * name exactly as it would from a live resolver.
 * ------------------------------------------------------------------------- */
struct addrinfo *__wrap_getaddrinfo(const char *node, const char *service,
                                    const struct addrinfo *hints,
                                    struct addrinfo **res);
void __wrap_freeaddrinfo(struct addrinfo *ai);

static struct {
    int      return_code;        /* what getaddrinfo returns (0 == success) */
    uint32_t count;              /* how many addrinfo nodes to synthesize */
    uint32_t base_ip;            /* host-order base IP; node k gets base_ip + k */
    bool     with_canonname;     /* attach ai_canonname to the FIRST node? */
    bool     garbage_res_on_err; /* on an error return, leave *res pointing at a
                                  * non-NULL SENTINEL (mimics glibc leaving *res
                                  * indeterminate on a positive EAI_* error)
                                  * instead of zeroing it. See ga_set_error(). */
    int      calls;              /* how many times the wrap was invoked */
} ga_plan;

/* The non-NULL "indeterminate" sentinel a real glibc getaddrinfo can leave in
 * *res on a positive-error return. It is NEVER allocated and NEVER freed -- the
 * contract is that the caller must not read or free *res on error. The FIXED
 * nc_resolve_multi_with_hostnames returns before it would ever touch this; the
 * BUGGY status<0 version walks it in the extraction loop and traps. */
#define GA_GARBAGE_RES  ((struct addrinfo *)(intptr_t)0xdeadbeefUL)

static void
ga_set(int return_code, uint32_t count, uint32_t base_ip, bool with_canonname)
{
    ga_plan.return_code      = return_code;
    ga_plan.count            = count;
    ga_plan.base_ip          = base_ip;
    ga_plan.with_canonname   = with_canonname;
    ga_plan.garbage_res_on_err = false;
}

/* Arm an ERROR return that also leaves *res at the non-NULL garbage sentinel,
 * exactly like glibc on a positive EAI_* error. Used by the load-bearing
 * portability case: under the fix this sentinel is never read. */
static void
ga_set_error_with_garbage_res(int return_code)
{
    ga_plan.return_code      = return_code;
    ga_plan.count            = 0;
    ga_plan.base_ip          = 0;
    ga_plan.with_canonname   = false;
    ga_plan.garbage_res_on_err = true;
}

struct addrinfo *
__wrap_getaddrinfo(const char *node, const char *service,
                   const struct addrinfo *hints, struct addrinfo **res)
{
    uint32_t k;
    struct addrinfo *head = NULL, *tail = NULL;
    int port;

    (void)node;
    (void)hints;
    ga_plan.calls++;

    if (ga_plan.return_code != 0) {
        /*
         * Error return. Two flavours of *res, both faithful to real resolvers:
         *
         *  - garbage_res_on_err == false: leave *res = NULL. This models the
         *    benign case and lets us assert the caller "returns an error and
         *    preserves prior state".
         *
         *  - garbage_res_on_err == true: leave *res at a NON-NULL garbage
         *    sentinel. This is what glibc actually does on a positive EAI_*
         *    error -- *res is INDETERMINATE, not NULL. The caller's contract is
         *    that it must NOT read or free *res on a nonzero return. The FIXED
         *    nc_resolve_multi_with_hostnames (status != 0) honours that and
         *    never touches the sentinel; the BUGGY version (status < 0) lets a
         *    positive error fall through and walks the sentinel in the
         *    extraction loop -> ASan/UBSan trap. This is what makes the
         *    portability case LOAD-BEARING rather than vacuous: with *res=NULL
         *    the buggy path would harmlessly read NULL and exit the loop,
         *    masking the bug.
         */
        *res = ga_plan.garbage_res_on_err ? GA_GARBAGE_RES : NULL;
        return (struct addrinfo *)(intptr_t)ga_plan.return_code;
    }

    port = service != NULL ? atoi(service) : 0;

    for (k = 0; k < ga_plan.count; k++) {
        struct addrinfo *node_ai = calloc(1, sizeof(*node_ai));
        struct sockaddr_in *sin  = calloc(1, sizeof(*sin));

        if (node_ai == NULL || sin == NULL) {
            /* Test-side OOM: free what we have and report a resolver failure. */
            free(node_ai);
            free(sin);
            __wrap_freeaddrinfo(head);
            *res = NULL;
            return (struct addrinfo *)(intptr_t)EAI_MEMORY;
        }

        sin->sin_family      = AF_INET;
        sin->sin_port        = htons((uint16_t)port);
        sin->sin_addr.s_addr = htonl(ga_plan.base_ip + k);

        node_ai->ai_family   = AF_INET;
        node_ai->ai_socktype = SOCK_STREAM;
        node_ai->ai_protocol = 0;
        node_ai->ai_addrlen  = sizeof(struct sockaddr_in);
        node_ai->ai_addr     = (struct sockaddr *)sin;
        node_ai->ai_canonname = NULL;
        node_ai->ai_next     = NULL;

        if (ga_plan.with_canonname && k == 0) {
            node_ai->ai_canonname = strdup("reader-canonical.example.internal");
        }

        if (head == NULL) {
            head = node_ai;
        } else {
            tail->ai_next = node_ai;
        }
        tail = node_ai;
    }

    *res = head;
    return 0;
}

void
__wrap_freeaddrinfo(struct addrinfo *ai)
{
    while (ai != NULL) {
        struct addrinfo *next = ai->ai_next;
        free(ai->ai_canonname);
        free(ai->ai_addr);
        free(ai);
        ai = next;
    }
}

/* ------------------------------------------------------------------------- *
 * Scaffolding: a minimally-valid struct server. owner is left NULL -- exactly
 * like test_dns_init_deinit.c / test_dns_resolve_oom.c -- so the stats calls in
 * server_dns_resolve() (all guarded by "server->owner != NULL &&
 * server->owner->ctx != NULL") and server_update_dynamic_connections() (guarded
 * by "pool == NULL") are clean no-ops. The code under test here is the
 * accumulate/expire/remove merge over the REAL struct server_dns, not the stats
 * plumbing.
 *
 * addrstr is a normal hostname (no leading '/'), so the resolver takes the
 * getaddrinfo() path -- which our --wrap intercepts.
 * ------------------------------------------------------------------------- */
static void
make_server(struct server *s)
{
    memset(s, 0, sizeof(*s));
    s->idx = 0;
    s->owner = NULL;                 /* no pool -> stats skipped, defaults used */
    s->port = 6379;
    s->is_dynamic = 1;
    s->dns = NULL;
    string_init(&s->pname);
    string_init(&s->name);
    string_init(&s->addrstr);
    string_copy(&s->pname,   (uint8_t *)"reader.example:6379", 19);
    string_copy(&s->name,    (uint8_t *)"reader.example",      14);
    string_copy(&s->addrstr, (uint8_t *)"reader.example",      14);
}

static void
free_server_strings(struct server *s)
{
    if (s->pname.data)   string_deinit(&s->pname);
    if (s->name.data)    string_deinit(&s->name);
    if (s->addrstr.data) string_deinit(&s->addrstr);
}

/* Host-order IP of the k-th synthetic address for a given base. */
#define IP_BASE  0x0A000001u    /* 10.0.0.1 */

/* Return the index of the live addr whose IPv4 host-order address == want, or
 * -1 if absent. Reads the REAL dns->addrs the production code built. */
static int
find_addr_idx(struct server_dns *dns, uint32_t want_host_order)
{
    uint32_t i;
    for (i = 0; i < dns->naddresses; i++) {
        struct sockaddr *sa = (struct sockaddr *)&dns->addrs[i].addr.addr;
        if (sa->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)sa;
            if (ntohl(sin->sin_addr.s_addr) == want_host_order) {
                return (int)i;
            }
        }
    }
    return -1;
}

int
main(void)
{
    struct server s;
    rstatus_t status;

    make_server(&s);

    /* --------------------------------------------------------------------- *
     * CASE 1: first resolve returns 3 addresses.
     * server_dns_init() runs the REAL first resolve internally. Expect a fully
     * populated dns: naddresses==3, addrs non-NULL, each addr has its IP and a
     * hostname string.
     * --------------------------------------------------------------------- */
    ga_set(0, 3, IP_BASE, /*with_canonname=*/true);
    status = server_dns_init(&s);

    CHECK(status == NC_OK, "server_dns_init returned %d (expected NC_OK)", status);
    CHECK(s.dns != NULL, "server_dns_init left dns NULL");
    if (s.dns == NULL) { fprintf(stderr, "fatal: no dns\n"); return 1; }

    CHECK(s.dns->naddresses == 3,
          "after first resolve naddresses=%u (expected 3)", s.dns->naddresses);
    CHECK(s.dns->addrs != NULL, "addrs NULL after a successful first resolve");
    CHECK(s.dns->max_addresses == TEST_MAX_ADDRESSES_PER_SERVER,
          "max_addresses=%u (expected %u)", s.dns->max_addresses,
          TEST_MAX_ADDRESSES_PER_SERVER);

    if (s.dns->addrs != NULL) {
        uint32_t i;
        for (i = 0; i < s.dns->naddresses; i++) {
            struct sockaddr *sa = (struct sockaddr *)&s.dns->addrs[i].addr.addr;
            CHECK(sa->sa_family == AF_INET,
                  "addr[%u] family=%d (expected AF_INET)", i, sa->sa_family);
            CHECK(s.dns->addrs[i].hostname.data != NULL &&
                  s.dns->addrs[i].hostname.len > 0,
                  "addr[%u] has no hostname string", i);
        }
        /* The three distinct IPs must all be present. */
        CHECK(find_addr_idx(s.dns, IP_BASE + 0) >= 0, "10.0.0.1 missing");
        CHECK(find_addr_idx(s.dns, IP_BASE + 1) >= 0, "10.0.0.2 missing");
        CHECK(find_addr_idx(s.dns, IP_BASE + 2) >= 0, "10.0.0.3 missing");
    }

    /*
     * Stamp recognisable per-address state on the original 3 so CASE 2 can prove
     * the accumulate path did NOT reset them (this is exactly what the
     * parallel-array desync bug corrupted: a new address shifting/zeroing the
     * fields of an existing one).
     */
    {
        uint32_t i;
        for (i = 0; i < s.dns->naddresses; i++) {
            s.dns->addrs[i].latency          = 4242 + i;
            s.dns->addrs[i].latency_measured = true;
            s.dns->addrs[i].failure_count    = 7 + i;
            s.dns->addrs[i].request_count    = 1000 + i;
            s.dns->addrs[i].health_score     = 55 + i;
        }
    }

    /* --------------------------------------------------------------------- *
     * CASE 2: second resolve returns a SUPERSET (same 3 + 1 new = 4).
     * Expect naddresses==4 and the original 3 structs intact (their stamped
     * fields preserved, NOT reset). Advance the clock a little (well under the
     * expiration threshold) so nothing expires.
     * --------------------------------------------------------------------- */
    clock_advance_usec(1000000LL);                 /* +1s (< 5min threshold) */
    ga_set(0, 4, IP_BASE, /*with_canonname=*/true);/* 10.0.0.1..10.0.0.4 */
    status = server_dns_resolve(&s);

    CHECK(status == NC_OK, "second resolve returned %d (expected NC_OK)", status);
    CHECK(s.dns->naddresses == 4,
          "after superset resolve naddresses=%u (expected 4)", s.dns->naddresses);

    {
        /* Each of the original three IPs must still be present AND keep its
         * stamped fields -- proving the merge updated last_seen in place and did
         * not clobber the struct. */
        uint32_t base;
        for (base = 0; base < 3; base++) {
            int idx = find_addr_idx(s.dns, IP_BASE + base);
            CHECK(idx >= 0, "original addr 10.0.0.%u vanished after merge", base + 1);
            if (idx >= 0) {
                struct dns_addr *a = &s.dns->addrs[idx];
                CHECK(a->latency == 4242 + base,
                      "addr 10.0.0.%u latency=%u (expected %u -- merge reset it)",
                      base + 1, a->latency, 4242 + base);
                CHECK(a->latency_measured,
                      "addr 10.0.0.%u latency_measured cleared by merge", base + 1);
                CHECK(a->failure_count == 7 + base,
                      "addr 10.0.0.%u failure_count=%u (expected %u)",
                      base + 1, a->failure_count, 7 + base);
                CHECK(a->request_count == (uint64_t)(1000 + base),
                      "addr 10.0.0.%u request_count=%" PRIu64 " (expected %u)",
                      base + 1, a->request_count, 1000 + base);
                CHECK(a->health_score == 55 + base,
                      "addr 10.0.0.%u health_score=%u (expected %u)",
                      base + 1, a->health_score, 55 + base);
            }
        }
        /* The genuinely new 4th address must have been appended. */
        CHECK(find_addr_idx(s.dns, IP_BASE + 3) >= 0,
              "new addr 10.0.0.4 not appended by the accumulate path");
    }

    /* --------------------------------------------------------------------- *
     * CASE 3: a resolve returning MORE than max_addresses must be CAPPED.
     * Ask for max_addresses + 8 brand-new IPs (a disjoint range so they are all
     * "new"). naddresses must clamp at max_addresses, with no overflow -- under
     * ASan this proves there is no out-of-bounds write into dns->addrs.
     * --------------------------------------------------------------------- */
    clock_advance_usec(1000000LL);                 /* +1s, still no expiry */
    ga_set(0, TEST_MAX_ADDRESSES_PER_SERVER + 8, 0x0B000001u /*11.0.0.1*/, false);
    status = server_dns_resolve(&s);

    CHECK(status == NC_OK, "over-cap resolve returned %d (expected NC_OK)", status);
    CHECK(s.dns->naddresses == TEST_MAX_ADDRESSES_PER_SERVER,
          "naddresses=%u after over-cap resolve (expected the cap %u)",
          s.dns->naddresses, TEST_MAX_ADDRESSES_PER_SERVER);
    CHECK(s.dns->naddresses <= s.dns->max_addresses,
          "naddresses %u exceeds max_addresses %u -- cap violated",
          s.dns->naddresses, s.dns->max_addresses);
    /* current_addr_idx must stay a valid index into the (capped) array. */
    CHECK(s.current_addr_idx < s.dns->naddresses,
          "current_addr_idx=%u out of range (naddresses=%u)",
          s.current_addr_idx, s.dns->naddresses);

    /* --------------------------------------------------------------------- *
     * CASE 4: EXPIRY. Re-resolve returning a SMALL, fixed set (just two of the
     * 11.0.0.x addresses), then advance the clock PAST the expiration threshold
     * and resolve that same small set again. Every address not in that small set
     * has a stale last_seen and must be expired; the survivors keep their fields
     * and current_addr_idx stays valid.
     *
     * Two thresholds matter here (this is the real contract in
     * server_dns_resolve): a NON-current stale address expires after 1x the
     * threshold, but the CURRENTLY-selected address gets 2x (a conservative
     * "don't yank the address we are actively using" rule). We don't control
     * which index is current, so to make the survivor count DETERMINISTIC we
     * advance past 2x the threshold -- then any address not re-seen expires
     * whether or not it is the current one, and only the re-seen set (which gets
     * last_seen = now) survives. Default threshold (no pool) is 5 min, so 2x is
     * 10 min; advance 11 min.
     * --------------------------------------------------------------------- */
    /* First, settle on a known small surviving set (2 addresses). */
    ga_set(0, 2, 0x0B000001u /*11.0.0.1, 11.0.0.2*/, false);
    status = server_dns_resolve(&s);
    CHECK(status == NC_OK, "pre-expiry resolve returned %d (expected NC_OK)", status);

    /* Tag the two survivors so we can prove their fields persist through expiry. */
    {
        int i1 = find_addr_idx(s.dns, 0x0B000001u);
        int i2 = find_addr_idx(s.dns, 0x0B000002u);
        CHECK(i1 >= 0 && i2 >= 0, "the two survivors are not both present pre-expiry");
        if (i1 >= 0) { s.dns->addrs[i1].latency = 31337; s.dns->addrs[i1].latency_measured = true; }
        if (i2 >= 0) { s.dns->addrs[i2].failure_count = 99; }
    }

    /* Now jump 11 minutes (> 2x the 5-min threshold) and resolve the SAME
     * 2-address set. Everything last seen 11 minutes ago that is NOT in this set
     * must expire -- including the current address (2x rule). */
    clock_advance_usec(11LL * 60LL * 1000000LL);   /* +11 min > 2x 5-min threshold */
    ga_set(0, 2, 0x0B000001u, false);
    status = server_dns_resolve(&s);

    CHECK(status == NC_OK, "expiry resolve returned %d (expected NC_OK)", status);
    CHECK(s.dns->naddresses == 2,
          "after expiry naddresses=%u (expected 2 survivors)", s.dns->naddresses);
    CHECK(s.current_addr_idx < s.dns->naddresses,
          "current_addr_idx=%u invalid after expiry (naddresses=%u)",
          s.current_addr_idx, s.dns->naddresses);

    {
        int i1 = find_addr_idx(s.dns, 0x0B000001u);
        int i2 = find_addr_idx(s.dns, 0x0B000002u);
        CHECK(i1 >= 0, "survivor 11.0.0.1 wrongly expired");
        CHECK(i2 >= 0, "survivor 11.0.0.2 wrongly expired");
        if (i1 >= 0) {
            CHECK(s.dns->addrs[i1].latency == 31337,
                  "survivor 11.0.0.1 latency=%u (expected 31337 -- expiry shuffle "
                  "corrupted its fields)", s.dns->addrs[i1].latency);
            CHECK(s.dns->addrs[i1].latency_measured,
                  "survivor 11.0.0.1 latency_measured cleared by expiry shuffle");
        }
        if (i2 >= 0) {
            CHECK(s.dns->addrs[i2].failure_count == 99,
                  "survivor 11.0.0.2 failure_count=%u (expected 99)",
                  s.dns->addrs[i2].failure_count);
        }
        /* The old 10.0.0.x set must all be gone. */
        CHECK(find_addr_idx(s.dns, IP_BASE + 0) < 0, "expired 10.0.0.1 still present");
        CHECK(find_addr_idx(s.dns, IP_BASE + 3) < 0, "expired 10.0.0.4 still present");
    }

    /* --------------------------------------------------------------------- *
     * CASE 5: getaddrinfo FAILURE. A failed resolve must be handled cleanly:
     * server_dns_resolve returns non-OK, does not crash, does not leak (the
     * temp arrays are freed on the error path), and the prior good state is
     * preserved unchanged.
     *
     * Three sub-cases, distinguished by what getaddrinfo leaves in *res:
     *
     *   5a -- NEGATIVE error code, *res = NULL. The benign baseline (glibc on a
     *         negative code). Returns error, prior state preserved.
     *   5b -- POSITIVE error code, *res = NULL. A platform that uses positive
     *         EAI_* codes but still zeroes *res. Returns error, prior state
     *         preserved.
     *   5c -- POSITIVE error code, *res = NON-NULL GARBAGE. This is the real
     *         glibc contract on a positive error: *res is INDETERMINATE, not
     *         NULL. This sub-case is the one that PROVES the status != 0 fix and
     *         is LOAD-BEARING:
     *           * fixed (status != 0): the positive error is caught, the
     *             function returns before it ever reads *res -> the garbage
     *             sentinel is never touched -> clean.
     *           * buggy (status < 0):  the positive error falls through, and the
     *             extraction loop walks the garbage `ai` (cai->ai_family etc.)
     *             -> ASan/UBSan trap / segfault -> the binary exits non-zero.
     *         5a/5b alone could NOT catch the bug -- with *res=NULL the buggy
     *         loop reads NULL and exits immediately, masking it. Only a
     *         non-NULL *res on a positive error exercises the wild walk.
     * --------------------------------------------------------------------- */
    {
        uint32_t saved_n = s.dns->naddresses;

        /* 5a: negative error code, *res = NULL. */
        clock_advance_usec(1000000LL);
        ga_set(EAI_FAIL, 0, 0, false);             /* EAI_FAIL is negative on glibc */
        status = server_dns_resolve(&s);
        CHECK(status != NC_OK,
              "resolve with a failing getaddrinfo returned NC_OK (expected error)");
        CHECK(s.dns->naddresses == saved_n,
              "naddresses changed to %u after a failed resolve (expected %u -- prior "
              "state must be preserved)", s.dns->naddresses, saved_n);
        CHECK(s.dns->addrs != NULL,
              "addrs went NULL after a failed resolve (prior state lost)");

        /* 5b: positive error code, *res = NULL. */
        clock_advance_usec(1000000LL);
        ga_set(3 /* a positive EAI_*-shaped value */, 0, 0, false);
        status = server_dns_resolve(&s);
        CHECK(status != NC_OK,
              "resolve with a positive getaddrinfo error (NULL *res) returned NC_OK");
        CHECK(s.dns->naddresses == saved_n,
              "naddresses changed to %u after a positive-error resolve (expected %u)",
              s.dns->naddresses, saved_n);
        CHECK(s.dns->addrs != NULL,
              "addrs went NULL after a positive-error resolve");

        /* 5c: positive error code AND non-NULL garbage *res -- the portability
         * proof. Under the fix this returns cleanly without reading the
         * sentinel; under the old status<0 bug the extraction loop walks
         * 0xdeadbeef and traps under ASan/UBSan. */
        clock_advance_usec(1000000LL);
        ga_set_error_with_garbage_res(3 /* positive EAI_*-shaped value */);
        status = server_dns_resolve(&s);
        CHECK(status != NC_OK,
              "resolve with a POSITIVE getaddrinfo error + garbage *res returned "
              "NC_OK -- the status<0 portability bug let the positive error fall "
              "through and walk the indeterminate addrinfo pointer");
        CHECK(s.dns->naddresses == saved_n,
              "naddresses changed to %u after the garbage-*res resolve (expected %u)",
              s.dns->naddresses, saved_n);
        CHECK(s.dns->addrs != NULL,
              "addrs went NULL after the garbage-*res resolve");
    }

    /* --------------------------------------------------------------------- *
     * CASE 6: FIRST-resolution over-cap. Case 3 drove the ACCUMULATE cap
     * (nc_server.c:1525, the per-append "drop the surplus" guard). The
     * FIRST-resolution branch has its OWN, separate clamp before the single
     * array alloc (nc_server.c:1418-1422): if the very first resolve returns
     * more than max_addresses, naddresses is clamped and only that many are
     * allocated/initialised. A fresh server whose first resolve returns >16
     * exercises that path (and ASan proves the clamped alloc has no OOB).
     * --------------------------------------------------------------------- */
    {
        struct server s2;
        make_server(&s2);

        ga_set(0, TEST_MAX_ADDRESSES_PER_SERVER + 5, 0x0C000001u /*12.0.0.1*/, false);
        rstatus_t st2 = server_dns_init(&s2);  /* runs the REAL first resolve */

        CHECK(st2 == NC_OK, "server_dns_init (over-cap first resolve) returned %d", st2);
        CHECK(s2.dns != NULL, "over-cap first resolve left dns NULL");
        if (s2.dns != NULL) {
            CHECK(s2.dns->naddresses == TEST_MAX_ADDRESSES_PER_SERVER,
                  "first-resolution naddresses=%u (expected the cap %u)",
                  s2.dns->naddresses, TEST_MAX_ADDRESSES_PER_SERVER);
            CHECK(s2.dns->naddresses <= s2.dns->max_addresses,
                  "first-resolution naddresses %u exceeds max_addresses %u",
                  s2.dns->naddresses, s2.dns->max_addresses);
            CHECK(s2.current_addr_idx < s2.dns->naddresses,
                  "current_addr_idx=%u out of range after over-cap first resolve "
                  "(naddresses=%u)", s2.current_addr_idx, s2.dns->naddresses);
            /* Each allocated slot must be a well-formed addr (ASan would already
             * trap an OOB; this also confirms the first cap entries are real). */
            CHECK(find_addr_idx(s2.dns, 0x0C000001u) >= 0, "12.0.0.1 missing");
            CHECK(find_addr_idx(s2.dns, 0x0C000001u + TEST_MAX_ADDRESSES_PER_SERVER - 1) >= 0,
                  "the 16th first-resolution address is missing");
        }

        server_dns_deinit(&s2);
        CHECK(s2.dns == NULL, "server_dns_deinit (s2) did not NULL server->dns");
        free_server_strings(&s2);
    }

    /* --------------------------------------------------------------------- *
     * Clean teardown -- REAL deinit must free the whole accumulated array (and
     * every per-addr hostname) with no leak / no double-free.
     * --------------------------------------------------------------------- */
    server_dns_deinit(&s);
    CHECK(s.dns == NULL, "server_dns_deinit did not NULL server->dns");
    free_server_strings(&s);

    if (failures == 0) {
        printf("OK: real server_dns_resolve drove first-resolve(3) -> "
               "accumulate-superset(4) -> accumulate-over-cap(clamped to %u) -> "
               "expiry(2 survivors, fields preserved) -> "
               "resolver-failure(neg-null + pos-null + pos-GARBAGE-res, state "
               "preserved); first-resolve-over-cap(clamped to %u); clean deinit\n",
               TEST_MAX_ADDRESSES_PER_SERVER, TEST_MAX_ADDRESSES_PER_SERVER);
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
}
