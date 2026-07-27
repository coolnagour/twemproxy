/*
 * Standalone unit test for the background DNS resolver (perf-cpu plan
 * Task 5): submit -> thread runs the real getaddrinfo wrapper -> poll the
 * result on the caller side.
 *
 * Contract:
 *   1. A submitted hostname ("localhost") resolves off-thread and the result
 *      surfaces via resolver_poll with the caller's server pointer, NC_OK
 *      status and at least one address.
 *   2. An empty result queue polls as NULL (non-blocking).
 *   3. resolver_destroy with a request still queued frees it without
 *      applying (no leak, no crash) and joins the thread.
 *
 * The server pointer is opaque to the resolver (never dereferenced by the
 * thread), so sentinel pointers stand in for real servers.
 *
 * Build/run: see tests/unit/run.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <nc_core.h>
#include <nc_server.h>
#include <nc_resolver.h>
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

int
main(void)
{
    struct resolver *r;
    struct resolver_result *res;
    struct string host;
    int i;

    r = resolver_create();
    CHECK(r != NULL, "resolver_create failed");
    if (r == NULL) {
        return 1;
    }

    string_init(&host);
    CHECK(string_copy(&host, (const uint8_t *)"localhost", 9) == NC_OK,
          "string_copy failed");

    CHECK(resolver_submit(r, (struct server *)0x1, &host, 6379, 16) == NC_OK,
          "submit failed");

    res = NULL;
    for (i = 0; i < 500 && res == NULL; i++) {
        res = resolver_poll(r);
        if (res == NULL) {
            usleep(10000);
        }
    }
    CHECK(res != NULL, "no result within 5s");
    if (res != NULL) {
        CHECK(res->server == (struct server *)0x1, "server pointer mismatch");
        CHECK(res->status == NC_OK, "resolve status %d", res->status);
        CHECK(res->naddresses >= 1, "no addresses resolved");
        CHECK(res->addrs != NULL, "addrs NULL on success");
        resolver_result_free(res);
    }

    /* empty poll returns NULL */
    CHECK(resolver_poll(r) == NULL, "poll on empty queue not NULL");

    /* a queued-but-unprocessed request must not leak on destroy */
    CHECK(resolver_submit(r, (struct server *)0x2, &host, 6379, 16) == NC_OK,
          "second submit failed");
    resolver_destroy(r);

    string_deinit(&host);

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("OK: resolver thread round trip + teardown\n");
    return 0;
}
