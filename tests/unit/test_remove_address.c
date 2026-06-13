/*
 * Standalone unit test for server_dns address removal (array-of-structs layout).
 *
 * Twemproxy has no C unit-test framework (tests/ is Python integration that
 * needs a live redis). This is a freestanding C test that links the real
 * nc_server.c object and drives server_dns_remove_address_at() directly, so we
 * exercise production code without a network.
 *
 * Background: struct server_dns used to hold ~11 PARALLEL per-address arrays,
 * and this test proved they all shifted in lock-step on a removal. After the
 * struct-of-arrays -> array-of-structs refactor there is a SINGLE dns_addr
 * array, so a removal is one struct shift and the whole "arrays desync" class is
 * gone. The behavioural contract that still matters -- and that this test still
 * asserts -- is:
 *   1. Removing a middle address preserves every SURVIVOR's fields and keeps
 *      them attached to the right address (we stamp an index marker into several
 *      fields and check order + values after the shift).
 *   2. The vacated tail slot is cleared (and its hostname struct string is not
 *      left aliasing a live slot's data pointer -> no double-free/leak).
 *   3. server->current_addr_idx still points at the SAME logical address after
 *      an earlier-indexed address is expired (the sibling bug; the production
 *      fixup is mirrored here).
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
 * stub satisfies the linker without affecting behaviour.
 */
void nc_post_run(struct instance *nci) { (void)nci; }

/* server_dns_remove_address_at() is the function under test; declared in nc_server.h. */

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
 * Encode the logical address index into the low byte of an IPv4 address so we
 * can detect a shifted-but-misaligned addr slot. addrs[k].addr for logical
 * index L is 10.0.0.(L+1).
 */
static void
set_addr_for_index(struct sockinfo *si, uint32_t logical)
{
    struct sockaddr_in *in = (struct sockaddr_in *)&si->addr;

    memset(si, 0, sizeof(*si));
    si->family = AF_INET;
    si->addrlen = sizeof(struct sockaddr_in);
    in->sin_family = AF_INET;
    in->sin_port = htons((uint16_t)(6379 + logical));
    in->sin_addr.s_addr = htonl(0x0A000000u | (logical + 1u)); /* 10.0.0.(L+1) */
}

static uint32_t
addr_index_of(struct dns_addr *a)
{
    struct sockaddr_in *in = (struct sockaddr_in *)&a->addr.addr;
    return (ntohl(in->sin_addr.s_addr) & 0xFFu) - 1u;
}

/*
 * Build a server_dns holding `n` addresses. Every field in each dns_addr is
 * stamped with a value derived from the logical index L so any misalignment
 * after a shift is detectable. One contiguous allocation now, sized to
 * max_addresses like production.
 */
static struct server_dns *
make_dns(uint32_t n)
{
    struct server_dns *dns = nc_zalloc(sizeof(*dns));
    uint32_t i;

    dns->max_addresses = 16;
    dns->naddresses = n;
    dns->next_zone_id = 1;
    dns->zones_assigned = true;
    dns->health_initialized = true;

    dns->addrs = nc_alloc(dns->max_addresses * sizeof(struct dns_addr));

    for (i = 0; i < n; i++) {
        char buf[64];
        struct dns_addr *a = &dns->addrs[i];

        memset(a, 0, sizeof(*a));
        set_addr_for_index(&a->addr, i);
        a->latency            = 1000u + i;          /* unique per index */
        a->latency_measured   = ((i % 2) == 0);     /* alternate so the bool shifts too */
        a->last_latency_check = 100000 + (int64_t)i;
        a->failure_count      = 10u + i;
        a->last_seen          = 200000 + (int64_t)i;
        a->last_connected     = 300000 + (int64_t)i;
        a->request_count      = 5000u + i;
        a->zone_id            = 20u + i;
        a->health_score       = 30u + i;
        a->last_health_check  = 400000 + (int64_t)i;

        string_init(&a->hostname);
        snprintf(buf, sizeof(buf), "host-%" PRIu32 ".example", i);
        string_copy(&a->hostname, (uint8_t *)buf, (uint32_t)strlen(buf));
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

/*
 * Assert that every surviving dns_addr slot still carries the field values that
 * were stamped for the logical address index sitting in addrs[k].addr. This is
 * the behavioural invariant that replaces "11 arrays stay aligned": after the
 * single struct shift, slot k must hold a COMPLETE, self-consistent address
 * record for whatever logical address now lives there.
 */
static void
assert_fields_intact(struct server_dns *dns)
{
    uint32_t k;
    for (k = 0; k < dns->naddresses; k++) {
        struct dns_addr *a = &dns->addrs[k];
        uint32_t L = addr_index_of(a);
        char expect[64];

        CHECK(a->latency == 1000u + L,
              "latency[%u]=%u expected %u (addr logical %u)",
              k, a->latency, 1000u + L, L);
        CHECK(a->latency_measured == ((L % 2) == 0),
              "latency_measured[%u]=%d expected %d (addr logical %u)",
              k, a->latency_measured, ((L % 2) == 0), L);
        CHECK(a->last_latency_check == 100000 + (int64_t)L,
              "last_latency_check[%u] misaligned (addr logical %u)", k, L);
        CHECK(a->failure_count == 10u + L,
              "failure_count[%u]=%u expected %u (addr logical %u)",
              k, a->failure_count, 10u + L, L);
        CHECK(a->last_seen == 200000 + (int64_t)L,
              "last_seen[%u] misaligned (addr logical %u)", k, L);
        CHECK(a->last_connected == 300000 + (int64_t)L,
              "last_connected[%u]=%" PRId64 " expected %" PRId64 " (addr logical %u)",
              k, a->last_connected, 300000 + (int64_t)L, L);
        CHECK(a->request_count == 5000u + L,
              "request_count[%u]=%" PRIu64 " expected %" PRIu64 " (addr logical %u)",
              k, a->request_count, (uint64_t)(5000u + L), L);
        CHECK(a->zone_id == 20u + L,
              "zone_id[%u]=%u expected %u (addr logical %u)",
              k, a->zone_id, 20u + L, L);
        CHECK(a->health_score == 30u + L,
              "health_score[%u]=%u expected %u (addr logical %u)",
              k, a->health_score, 30u + L, L);
        CHECK(a->last_health_check == 400000 + (int64_t)L,
              "last_health_check[%u] misaligned (addr logical %u)", k, L);

        snprintf(expect, sizeof(expect), "host-%" PRIu32 ".example", L);
        CHECK(a->hostname.data != NULL &&
              a->hostname.len == (uint32_t)strlen(expect) &&
              memcmp(a->hostname.data, expect, strlen(expect)) == 0,
              "hostname[%u]='%.*s' expected '%s' (addr logical %u)",
              k, (int)a->hostname.len,
              a->hostname.data ? (char *)a->hostname.data : "(null)",
              expect, L);
    }
}

/* Test 1: remove a middle address; survivors keep order + all their fields. */
static void
test_remove_middle(void)
{
    struct server_dns *dns = make_dns(4);

    /* Remove logical address 1 (the second of four). */
    server_dns_remove_address_at(dns, 1);

    CHECK(dns->naddresses == 3, "naddresses=%u expected 3", dns->naddresses);

    /* Surviving logical order must be 0,2,3 in slots 0,1,2. */
    CHECK(addr_index_of(&dns->addrs[0]) == 0, "slot0 logical=%u expected 0",
          addr_index_of(&dns->addrs[0]));
    CHECK(addr_index_of(&dns->addrs[1]) == 2, "slot1 logical=%u expected 2",
          addr_index_of(&dns->addrs[1]));
    CHECK(addr_index_of(&dns->addrs[2]) == 3, "slot2 logical=%u expected 3",
          addr_index_of(&dns->addrs[2]));

    assert_fields_intact(dns);

    /*
     * Tail-slot hygiene: the now-unused addrs[3].hostname must be cleared, not
     * left aliasing the data pointer that moved down to addrs[2].hostname. An
     * aliased tail would double-free in free_dns()/server_dns_deinit().
     */
    CHECK(dns->addrs[3].hostname.data == NULL && dns->addrs[3].hostname.len == 0,
          "tail addrs[3].hostname not cleared (data=%p len=%u) -> aliasing/double-free risk",
          (void *)dns->addrs[3].hostname.data, dns->addrs[3].hostname.len);

    free_dns(dns);
}

/* Test 2: removing the last address clears its slot and shrinks the array. */
static void
test_remove_last(void)
{
    struct server_dns *dns = make_dns(3);

    server_dns_remove_address_at(dns, 2);

    CHECK(dns->naddresses == 2, "naddresses=%u expected 2", dns->naddresses);
    CHECK(dns->addrs[2].hostname.data == NULL && dns->addrs[2].hostname.len == 0,
          "tail addrs[2].hostname not cleared after removing last");
    assert_fields_intact(dns);

    free_dns(dns);
}

/*
 * Test 3: the sibling bug. current_addr_idx must keep pointing at the SAME
 * logical address after an earlier-indexed address is expired.
 *
 * apply_current_idx_fixup() below MIRRORS the production fixup in the expiry
 * loop of server_dns_resolve() (src/nc_server.c, the block right after the
 * server_dns_remove_address_at() call) -- keep the two in sync:
 *   if (i < current_addr_idx) current_addr_idx--;
 *   else if (i == current_addr_idx && current_addr_idx >= naddresses)
 *           current_addr_idx = naddresses ? naddresses-1 : 0;
 */
static void
apply_current_idx_fixup(uint32_t *current_addr_idx, uint32_t i, uint32_t naddresses_after)
{
    if (i < *current_addr_idx) {
        (*current_addr_idx)--;
    } else if (i == *current_addr_idx) {
        if (*current_addr_idx >= naddresses_after) {
            *current_addr_idx = naddresses_after ? naddresses_after - 1 : 0;
        }
    }
}

static void
test_current_addr_idx_fixup(void)
{
    struct server_dns *dns = make_dns(4);
    uint32_t current_addr_idx = 3;            /* selected logical address 3 */
    uint32_t selected_logical;
    uint32_t i = 1;                           /* expire an earlier index */

    selected_logical = addr_index_of(&dns->addrs[current_addr_idx]);
    CHECK(selected_logical == 3, "precondition: selected logical=%u expected 3",
          selected_logical);

    server_dns_remove_address_at(dns, i);
    apply_current_idx_fixup(&current_addr_idx, i, dns->naddresses);

    CHECK(current_addr_idx < dns->naddresses,
          "current_addr_idx=%u out of range (naddresses=%u)",
          current_addr_idx, dns->naddresses);
    CHECK(addr_index_of(&dns->addrs[current_addr_idx]) == selected_logical,
          "current_addr_idx now points at logical %u, expected %u",
          addr_index_of(&dns->addrs[current_addr_idx]), selected_logical);

    free_dns(dns);

    /* Removing the current address itself must leave a valid (in-range) idx. */
    dns = make_dns(4);
    current_addr_idx = 3;
    i = 3;
    server_dns_remove_address_at(dns, i);
    apply_current_idx_fixup(&current_addr_idx, i, dns->naddresses);
    CHECK(current_addr_idx < dns->naddresses,
          "after removing current (last) addr, idx=%u out of range (naddresses=%u)",
          current_addr_idx, dns->naddresses);
    free_dns(dns);
}

/* Test 4: removing the only address empties the struct without leaking. */
static void
test_remove_only_address(void)
{
    struct server_dns *dns = make_dns(1);
    uint32_t current_addr_idx = 0;

    server_dns_remove_address_at(dns, 0);
    apply_current_idx_fixup(&current_addr_idx, 0, dns->naddresses);

    CHECK(dns->naddresses == 0, "naddresses=%u expected 0", dns->naddresses);
    CHECK(dns->addrs[0].hostname.data == NULL && dns->addrs[0].hostname.len == 0,
          "slot0 hostname not cleared after removing only address");
    /* idx stays in a defined state (0) even though the array is empty. */
    CHECK(current_addr_idx == 0, "current_addr_idx=%u expected 0", current_addr_idx);

    free_dns(dns);
}

int
main(void)
{
    test_remove_middle();
    test_remove_last();
    test_current_addr_idx_fixup();
    test_remove_only_address();

    if (failures == 0) {
        printf("OK: all server_dns_remove_address_at (AoS) tests passed\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
}
