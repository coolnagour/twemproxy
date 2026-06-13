/*
 * Standalone unit test for server_dns address removal.
 *
 * Twemproxy has no C unit-test framework (tests/ is Python integration that
 * needs a live redis). This is a freestanding C test that links the real
 * nc_server.c object and drives server_dns_remove_address_at() directly, so we exercise
 * production code without a network.
 *
 * What it proves:
 *   1. Removing a middle address shifts EVERY per-address parallel array in
 *      struct server_dns down in lock-step, so array[k] still describes
 *      addresses[k] for every surviving k.
 *   2. The vacated tail slot is cleared (and the tail hostname struct string is
 *      not left aliasing a live slot's data pointer -> no double-free/leak).
 *   3. The lazily-allocated arrays (zone_ids/health_scores/last_health_check)
 *      are shifted when present and left untouched when NULL.
 *   4. server->current_addr_idx still points at the SAME logical address after
 *      an earlier-indexed address is expired (the sibling bug).
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
 * can detect a shifted-but-misaligned addresses[] slot. addresses[k] for
 * logical index L is 10.0.0.(L+1).
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
addr_index_of(struct sockinfo *si)
{
    struct sockaddr_in *in = (struct sockaddr_in *)&si->addr;
    return (ntohl(in->sin_addr.s_addr) & 0xFFu) - 1u;
}

/*
 * Build a server_dns holding `n` addresses. Every parallel array slot for
 * logical index L is seeded with a value derived from L so any misalignment
 * after a shift is detectable. The lazily-allocated arrays are allocated to
 * max_addresses (16), mirroring production, when `with_lazy` is true.
 */
static struct server_dns *
make_dns(uint32_t n, bool with_lazy)
{
    struct server_dns *dns = nc_zalloc(sizeof(*dns));
    uint32_t i;

    dns->max_addresses = 16;
    dns->naddresses = n;
    dns->next_zone_id = 1;

    dns->addresses          = nc_alloc(n * sizeof(struct sockinfo));
    dns->latencies          = nc_alloc(n * sizeof(uint32_t));
    dns->last_latency_check = nc_alloc(n * sizeof(int64_t));
    dns->failure_counts     = nc_alloc(n * sizeof(uint32_t));
    dns->last_seen          = nc_alloc(n * sizeof(int64_t));
    dns->last_connected     = nc_alloc(n * sizeof(int64_t));
    dns->request_counts     = nc_alloc(n * sizeof(uint64_t));
    dns->hostnames          = nc_alloc(n * sizeof(struct string));

    if (with_lazy) {
        dns->zone_ids         = nc_calloc(dns->max_addresses, sizeof(uint32_t));
        dns->health_scores    = nc_calloc(dns->max_addresses, sizeof(uint32_t));
        dns->last_health_check = nc_calloc(dns->max_addresses, sizeof(int64_t));
    }

    for (i = 0; i < n; i++) {
        char buf[64];

        set_addr_for_index(&dns->addresses[i], i);
        dns->latencies[i]          = 1000u + i;          /* unique per index */
        dns->last_latency_check[i] = 100000 + (int64_t)i;
        dns->failure_counts[i]     = 10u + i;
        dns->last_seen[i]          = 200000 + (int64_t)i;
        dns->last_connected[i]     = 300000 + (int64_t)i;
        dns->request_counts[i]     = 5000u + i;

        string_init(&dns->hostnames[i]);
        snprintf(buf, sizeof(buf), "host-%" PRIu32 ".example", i);
        string_copy(&dns->hostnames[i], (uint8_t *)buf, (uint32_t)strlen(buf));

        if (with_lazy) {
            dns->zone_ids[i]          = 20u + i;
            dns->health_scores[i]     = 30u + i;
            dns->last_health_check[i] = 400000 + (int64_t)i;
        }
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
    nc_free(dns);
}

/*
 * Assert that every parallel array slot agrees with the logical address index
 * sitting in addresses[k]. This is the core alignment invariant.
 */
static void
assert_aligned(struct server_dns *dns)
{
    uint32_t k;
    for (k = 0; k < dns->naddresses; k++) {
        uint32_t L = addr_index_of(&dns->addresses[k]);
        char expect[64];

        CHECK(dns->latencies[k] == 1000u + L,
              "latencies[%u]=%u expected %u (addr logical %u)",
              k, dns->latencies[k], 1000u + L, L);
        CHECK(dns->last_latency_check[k] == 100000 + (int64_t)L,
              "last_latency_check[%u] misaligned (addr logical %u)", k, L);
        CHECK(dns->failure_counts[k] == 10u + L,
              "failure_counts[%u]=%u expected %u (addr logical %u)",
              k, dns->failure_counts[k], 10u + L, L);
        CHECK(dns->last_seen[k] == 200000 + (int64_t)L,
              "last_seen[%u] misaligned (addr logical %u)", k, L);
        CHECK(dns->last_connected[k] == 300000 + (int64_t)L,
              "last_connected[%u]=%" PRId64 " expected %" PRId64 " (addr logical %u)",
              k, dns->last_connected[k], 300000 + (int64_t)L, L);
        CHECK(dns->request_counts[k] == 5000u + L,
              "request_counts[%u]=%" PRIu64 " expected %" PRIu64 " (addr logical %u)",
              k, dns->request_counts[k], (uint64_t)(5000u + L), L);

        snprintf(expect, sizeof(expect), "host-%" PRIu32 ".example", L);
        CHECK(dns->hostnames[k].data != NULL &&
              dns->hostnames[k].len == (uint32_t)strlen(expect) &&
              memcmp(dns->hostnames[k].data, expect, strlen(expect)) == 0,
              "hostnames[%u]='%.*s' expected '%s' (addr logical %u)",
              k, (int)dns->hostnames[k].len,
              dns->hostnames[k].data ? (char *)dns->hostnames[k].data : "(null)",
              expect, L);

        if (dns->zone_ids) {
            CHECK(dns->zone_ids[k] == 20u + L,
                  "zone_ids[%u]=%u expected %u (addr logical %u)",
                  k, dns->zone_ids[k], 20u + L, L);
        }
        if (dns->health_scores) {
            CHECK(dns->health_scores[k] == 30u + L,
                  "health_scores[%u]=%u expected %u (addr logical %u)",
                  k, dns->health_scores[k], 30u + L, L);
        }
        if (dns->last_health_check) {
            CHECK(dns->last_health_check[k] == 400000 + (int64_t)L,
                  "last_health_check[%u] misaligned (addr logical %u)", k, L);
        }
    }
}

/* Test 1: remove a middle address with the lazy arrays present. */
static void
test_remove_middle_with_lazy(void)
{
    struct server_dns *dns = make_dns(4, true);

    /* Remove logical address 1 (the second of four). */
    server_dns_remove_address_at(dns, 1);

    CHECK(dns->naddresses == 3, "naddresses=%u expected 3", dns->naddresses);

    /* Surviving logical order must be 0,2,3 in slots 0,1,2. */
    CHECK(addr_index_of(&dns->addresses[0]) == 0, "slot0 logical=%u expected 0",
          addr_index_of(&dns->addresses[0]));
    CHECK(addr_index_of(&dns->addresses[1]) == 2, "slot1 logical=%u expected 2",
          addr_index_of(&dns->addresses[1]));
    CHECK(addr_index_of(&dns->addresses[2]) == 3, "slot2 logical=%u expected 3",
          addr_index_of(&dns->addresses[2]));

    assert_aligned(dns);

    /*
     * Tail-slot hygiene: the now-unused hostnames[3] must be cleared, not left
     * aliasing the data pointer that moved down to hostnames[2]. An aliased
     * tail would double-free in free_dns()/server_dns_deinit().
     */
    CHECK(dns->hostnames[3].data == NULL && dns->hostnames[3].len == 0,
          "tail hostnames[3] not cleared (data=%p len=%u) -> aliasing/double-free risk",
          (void *)dns->hostnames[3].data, dns->hostnames[3].len);

    free_dns(dns);
}

/* Test 2: remove a middle address when the lazy arrays are still NULL. */
static void
test_remove_middle_lazy_null(void)
{
    struct server_dns *dns = make_dns(4, false);

    CHECK(dns->zone_ids == NULL && dns->health_scores == NULL &&
          dns->last_health_check == NULL, "precondition: lazy arrays NULL");

    /* Must not crash on the NULL lazy arrays. */
    server_dns_remove_address_at(dns, 2);

    CHECK(dns->naddresses == 3, "naddresses=%u expected 3", dns->naddresses);
    CHECK(addr_index_of(&dns->addresses[0]) == 0, "slot0 logical mismatch");
    CHECK(addr_index_of(&dns->addresses[1]) == 1, "slot1 logical mismatch");
    CHECK(addr_index_of(&dns->addresses[2]) == 3, "slot2 logical mismatch");
    assert_aligned(dns);

    free_dns(dns);
}

/* Test 3: removing the last address clears its slot and shrinks the array. */
static void
test_remove_last(void)
{
    struct server_dns *dns = make_dns(3, true);

    server_dns_remove_address_at(dns, 2);

    CHECK(dns->naddresses == 2, "naddresses=%u expected 2", dns->naddresses);
    CHECK(dns->hostnames[2].data == NULL && dns->hostnames[2].len == 0,
          "tail hostnames[2] not cleared after removing last");
    assert_aligned(dns);

    free_dns(dns);
}

/*
 * Test 4: the sibling bug. current_addr_idx must keep pointing at the SAME
 * logical address after an earlier-indexed address is expired.
 *
 * apply_current_idx_fixup() below MIRRORS the production fixup in the expiry
 * loop of server_dns_resolve() (src/nc_server.c, the block right after the
 * server_dns_remove_address_at() call) -- keep the two in sync. The production
 * loop, when it calls server_dns_remove_address_at(dns, i), applies:
 *   if (i < current_addr_idx) current_addr_idx--;
 *   else if (i == current_addr_idx && current_addr_idx >= naddresses)
 *           current_addr_idx = naddresses ? naddresses-1 : 0;
 * This test models that fixup around the real removal and asserts the index
 * still resolves to the originally-selected logical address.
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
    struct server_dns *dns = make_dns(4, true);
    uint32_t current_addr_idx = 3;            /* selected logical address 3 */
    uint32_t selected_logical;
    uint32_t i = 1;                           /* expire an earlier index */

    selected_logical = addr_index_of(&dns->addresses[current_addr_idx]);
    CHECK(selected_logical == 3, "precondition: selected logical=%u expected 3",
          selected_logical);

    server_dns_remove_address_at(dns, i);
    apply_current_idx_fixup(&current_addr_idx, i, dns->naddresses);

    CHECK(current_addr_idx < dns->naddresses,
          "current_addr_idx=%u out of range (naddresses=%u)",
          current_addr_idx, dns->naddresses);
    CHECK(addr_index_of(&dns->addresses[current_addr_idx]) == selected_logical,
          "current_addr_idx now points at logical %u, expected %u",
          addr_index_of(&dns->addresses[current_addr_idx]), selected_logical);

    free_dns(dns);

    /* Removing the current address itself must leave a valid (in-range) idx. */
    dns = make_dns(4, true);
    current_addr_idx = 3;
    i = 3;
    server_dns_remove_address_at(dns, i);
    apply_current_idx_fixup(&current_addr_idx, i, dns->naddresses);
    CHECK(current_addr_idx < dns->naddresses,
          "after removing current (last) addr, idx=%u out of range (naddresses=%u)",
          current_addr_idx, dns->naddresses);
    free_dns(dns);
}

/* Test 5: removing the only address empties the struct without leaking. */
static void
test_remove_only_address(void)
{
    struct server_dns *dns = make_dns(1, true);
    uint32_t current_addr_idx = 0;

    server_dns_remove_address_at(dns, 0);
    apply_current_idx_fixup(&current_addr_idx, 0, dns->naddresses);

    CHECK(dns->naddresses == 0, "naddresses=%u expected 0", dns->naddresses);
    CHECK(dns->hostnames[0].data == NULL && dns->hostnames[0].len == 0,
          "slot0 hostname not cleared after removing only address");
    /* idx stays in a defined state (0) even though the array is empty. */
    CHECK(current_addr_idx == 0, "current_addr_idx=%u expected 0", current_addr_idx);

    free_dns(dns);
}

int
main(void)
{
    test_remove_middle_with_lazy();
    test_remove_middle_lazy_null();
    test_remove_last();
    test_current_addr_idx_fixup();
    test_remove_only_address();

    if (failures == 0) {
        printf("OK: all server_dns_remove_address_at alignment tests passed\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
}
