/*
 * Standalone unit test for server_sample_request_rtt() (perf-cpu plan Task 2):
 * the response-path feed of per-request RTT into the replica latency EWMA.
 *
 * Contract:
 *   1. First valid sample on an unmeasured addr replaces the optimistic
 *      default outright and flips latency_measured.
 *   2. Later samples blend 90/10 in integer math (server_measure_latency).
 *   3. An out-of-range addr_idx is rejected without touching anything (a DNS
 *      refresh can shrink addrs while a response is in flight).
 *   4. A negative RTT is rejected (clock skew guard).
 *   5. Non-dynamic and NULL servers are rejected.
 *
 * Drives the REAL server_sample_request_rtt + server_measure_latency from
 * nc_server.c against a hand-built server/dns (no network).
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

static struct server_dns *
make_dns(uint32_t n)
{
    struct server_dns *dns = nc_zalloc(sizeof(*dns));
    uint32_t i;

    dns->max_addresses = 16;
    dns->naddresses = n;

    dns->addrs = nc_alloc(dns->max_addresses * sizeof(struct dns_addr));
    for (i = 0; i < n; i++) {
        struct dns_addr *a = &dns->addrs[i];
        memset(a, 0, sizeof(*a));
        a->latency = 10000;            /* optimistic default, not yet measured */
        a->latency_measured = false;
        a->health_score = 100;
        string_init(&a->hostname);
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

int
main(void)
{
    struct server server;
    struct server_dns *dns = make_dns(2);

    memset(&server, 0, sizeof(server));
    server.is_dynamic = 1;
    server.dns = dns;
    string_init(&server.pname);
    string_copy(&server.pname, (const uint8_t *)"test:6379", 9);

    /* 1: first valid sample replaces the default outright */
    CHECK(server_sample_request_rtt(&server, 0, 250) == NC_OK,
          "first sample rejected");
    CHECK(dns->addrs[0].latency == 250,
          "first sample latency=%"PRIu32" expected 250", dns->addrs[0].latency);
    CHECK(dns->addrs[0].latency_measured == true, "latency_measured not set");

    /* 2: second sample blends 90/10 */
    CHECK(server_sample_request_rtt(&server, 0, 1250) == NC_OK,
          "second sample rejected");
    CHECK(dns->addrs[0].latency == (250 * 9 + 1250) / 10,
          "ewma=%"PRIu32" expected %u", dns->addrs[0].latency,
          (250 * 9 + 1250) / 10);

    /* 3: out-of-range index rejected, nothing touched */
    CHECK(server_sample_request_rtt(&server, 7, 100) == NC_ERROR,
          "oob index accepted");

    /* 4: negative RTT rejected */
    CHECK(server_sample_request_rtt(&server, 1, -5) == NC_ERROR,
          "negative rtt accepted");
    CHECK(dns->addrs[1].latency_measured == false,
          "negative rtt mutated addr");

    /* 5: non-dynamic server rejected */
    server.is_dynamic = 0;
    CHECK(server_sample_request_rtt(&server, 0, 100) == NC_ERROR,
          "non-dynamic accepted");
    server.is_dynamic = 1;

    /* NULL server rejected */
    CHECK(server_sample_request_rtt(NULL, 0, 100) == NC_ERROR,
          "NULL server accepted");

    /* NULL addrs (transient first-resolution state) rejected */
    {
        struct sockinfo *saved = (struct sockinfo *)dns->addrs;
        struct dns_addr *saved_addrs = dns->addrs;
        (void)saved;
        dns->addrs = NULL;
        CHECK(server_sample_request_rtt(&server, 0, 100) == NC_ERROR,
              "NULL addrs accepted");
        dns->addrs = saved_addrs;
    }

    string_deinit(&server.pname);
    free_dns(dns);

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("OK: rtt sample guards + EWMA delegation\n");
    return 0;
}
