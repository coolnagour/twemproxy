/*
 * Standalone unit test for server_dns_apply() (perf-cpu plan Task 6): the
 * loop-side half of the old server_dns_resolve(), fed with an already-resolved
 * address set instead of calling getaddrinfo itself.
 *
 * Contract:
 *   1. First apply on an empty dns initializes the addr array (count, per-addr
 *      init state, last_resolved stamped).
 *   2. A later apply merges (accumulate path): a still-present address
 *      survives, and the function neither crashes nor shrinks below the
 *      surviving set within the expiration window.
 *   3. Apply takes ownership of the passed arrays on every path (the leaks
 *      run in the harness guards this).
 *
 * This is the half the async resolver's results feed on the loop thread; the
 * sync wrapper (server_dns_resolve = resolve + apply) is covered by the
 * pre-existing dns tests.
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
#include <nc_string.h>

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

static void
make_addr(struct sockinfo *si, uint32_t logical)
{
    struct sockaddr_in *in = (struct sockaddr_in *)&si->addr;

    memset(si, 0, sizeof(*si));
    si->family = AF_INET;
    si->addrlen = sizeof(struct sockaddr_in);
    in->sin_family = AF_INET;
    in->sin_port = htons(6379);
    in->sin_addr.s_addr = htonl(0x0A000000u | (logical & 0xFFu));
}

/* resolved-set fabrication: apply takes ownership, so heap-allocate */
static struct sockinfo *
make_addr_list(const uint32_t *logicals, uint32_t n)
{
    struct sockinfo *addrs = nc_alloc(n * sizeof(struct sockinfo));
    uint32_t i;

    for (i = 0; i < n; i++) {
        make_addr(&addrs[i], logicals[i]);
    }
    return addrs;
}

static char **
make_hostname_list(uint32_t n)
{
    char **names = nc_alloc(n * sizeof(char *));
    uint32_t i;

    for (i = 0; i < n; i++) {
        char buf[32];
        snprintf(buf, sizeof(buf), "cname-%"PRIu32".test", i);
        names[i] = strdup(buf);
    }
    return names;
}

int
main(void)
{
    struct server_pool pool;
    struct server server;
    struct server_dns *dns = nc_zalloc(sizeof(*dns));

    dns->max_addresses = 16;
    string_init(&dns->hostname);
    string_copy(&dns->hostname, (const uint8_t *)"reader.test", 11);

    memset(&pool, 0, sizeof(pool));
    memset(&server, 0, sizeof(server));
    pool.cross_az_surcharge_us = 0;
    pool.latency_band_factor = 3;
    pool.server_connections = 1;
    pool.max_server_connections = 8;
    pool.dynamic_server_connections = 1;
    pool.current_server_connections = 1;
    pool.dns_failure_threshold = 10;
    pool.dns_expiration_minutes = 3600000000LL;
    string_init(&pool.name);
    server.owner = &pool;
    server.dns = dns;
    server.is_dynamic = 1;
    string_set_text(&server.pname, "reader.test:6379");

    /* 1: first apply initializes */
    {
        const uint32_t logicals[2] = { 1, 2 };
        struct sockinfo *addrs = make_addr_list(logicals, 2);
        char **names = make_hostname_list(2);

        CHECK(server_dns_apply(&server, addrs, names, 2) == NC_OK,
              "first apply failed");
        CHECK(dns->naddresses == 2, "naddresses=%"PRIu32" expected 2",
              dns->naddresses);
        CHECK(dns->addrs != NULL, "addrs NULL after apply");
        CHECK(dns->addrs[0].latency_measured == false,
              "fresh addr marked measured");
        CHECK(dns->last_resolved > 0, "last_resolved not stamped");
    }

    /* 2: accumulate apply with one overlapping + one new address */
    {
        const uint32_t logicals[2] = { 2, 3 };
        struct sockinfo *addrs = make_addr_list(logicals, 2);
        char **names = make_hostname_list(2);

        CHECK(server_dns_apply(&server, addrs, names, 2) == NC_OK,
              "second apply failed");
        CHECK(dns->naddresses >= 2, "merge lost survivors: naddresses=%"PRIu32,
              dns->naddresses);
        CHECK(dns->naddresses <= dns->max_addresses,
              "merge exceeded cap: %"PRIu32, dns->naddresses);
    }

    /* teardown mirrors server_dns_deinit-style cleanup for the leaks run */
    {
        uint32_t i;
        for (i = 0; i < dns->naddresses; i++) {
            if (dns->addrs[i].hostname.data != NULL) {
                string_deinit(&dns->addrs[i].hostname);
            }
        }
        nc_free(dns->addrs);
        string_deinit(&dns->hostname);
        nc_free(dns);
    }

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("OK: server_dns_apply init + accumulate\n");
    return 0;
}
