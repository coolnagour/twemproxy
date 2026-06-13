/*
 * Standalone unit test for the HTTP-aware stats endpoint (prod-hardening).
 *
 * Twemproxy has no C unit-test framework (tests/ is Python integration that
 * needs a live redis). This is a freestanding C test that links the real
 * nc_stats.c object and drives the production request-classification and
 * response-formatting helpers directly, so we exercise production code without
 * opening a socket. (A real end-to-end socket round-trip is covered by the
 * functional curl test in the task verification, not in this harness.)
 *
 * Background -- what changed and why
 * ----------------------------------
 * The stats server (src/nc_stats.c, port 22222) used to dump the aggregated
 * JSON document the instant a client connected, with NO HTTP framing at all
 * (effectively HTTP/0.9). `curl` chokes on that, and the container healthcheck
 * had to use a raw /dev/tcp byte-read hack. The stats server is now HTTP/1.1
 * aware: an HTTP request line gets a proper framed HTTP response (status line +
 * Content-Type + Content-Length + Connection: close + body), while a BARE
 * connect (a client that opens the socket and reads without sending a request
 * -- exactly what the legacy /dev/tcp healthcheck does) still gets the raw JSON
 * body promptly, for back-compat.
 *
 * The decision of "is this an HTTP request, and if so which path" and the
 * formatting of the response header are factored into two pure functions so the
 * branching logic is testable here without a network:
 *
 *   stats_request_classify(buf, len)          -> enum stats_request_kind
 *   stats_http_format_header(dst, dstsz, ...) -> int (bytes written, or -1)
 *
 * What this test proves (driving REAL production code):
 *   1. A bare connect (no bytes, or non-HTTP leading bytes) classifies as
 *      STATS_REQ_RAW  -> the back-compat path that emits raw JSON. This is the
 *      assertion that the healthcheck keeps working.
 *   2. "GET / HTTP/1.0" and "GET /stats HTTP/1.1" classify as
 *      STATS_REQ_HTTP_STATS -> serve the JSON over HTTP.
 *   3. "GET /health ..." classifies as STATS_REQ_HTTP_HEALTH.
 *   4. "HEAD /stats ..." classifies as STATS_REQ_HTTP_STATS_HEAD (headers, no
 *      body).
 *   5. An unknown path ("GET /nope ...") classifies as STATS_REQ_HTTP_NOTFOUND.
 *   6. A recognised method with a malformed request line classifies as
 *      STATS_REQ_HTTP_BADREQUEST (not as RAW -- once we have seen an HTTP
 *      method we owe the client an HTTP response, not a bare JSON dump).
 *   7. stats_http_format_header() emits a well-formed HTTP/1.1 status line and
 *      the required headers (Content-Type, Content-Length, Connection: close)
 *      terminated by a blank line, and reports overflow with -1.
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
#include <nc_stats.h>

/*
 * nc.c owns main() so it is excluded from the link; nc_signal.o references
 * nc_post_run() from there. The test never raises a fatal signal, so a no-op
 * stub satisfies the linker without affecting behaviour.
 */
void nc_post_run(struct instance *nci) { (void)nci; }

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

/* Classify a NUL-terminated literal as if it were the peeked socket bytes. */
static stats_request_kind_t
classify(const char *s)
{
    return stats_request_classify((const uint8_t *)s, strlen(s));
}

/*
 * (1) BARE connect: the legacy healthcheck opens the socket and reads without
 * writing anything -- len 0. Also any leading bytes that are not a known HTTP
 * method. Both must be RAW so the raw-JSON back-compat path fires.
 */
static void
test_bare_connect_is_raw(void)
{
    CHECK(stats_request_classify((const uint8_t *)"", 0) == STATS_REQ_RAW,
          "an empty (bare) connect must classify RAW so raw JSON is emitted");
    CHECK(classify("\r\n") == STATS_REQ_RAW,
          "leading CRLF with no method must classify RAW");
    CHECK(classify("hello world") == STATS_REQ_RAW,
          "arbitrary non-HTTP leading bytes must classify RAW");
    /* A lone "G" is the start of GET but is not yet a complete, recognisable
     * method token; with only this much data we must not mis-route. Treat a
     * partial/unrecognised token as RAW (the bare-connect default). */
    CHECK(classify("G") == STATS_REQ_RAW,
          "a single byte that is not a complete method must classify RAW");
}

/*
 * (2) GET / and GET /stats -> the stats JSON document.
 */
static void
test_get_stats_paths(void)
{
    CHECK(classify("GET / HTTP/1.0\r\n\r\n") == STATS_REQ_HTTP_STATS,
          "GET / must serve the stats JSON");
    CHECK(classify("GET /stats HTTP/1.1\r\nHost: x\r\n\r\n") == STATS_REQ_HTTP_STATS,
          "GET /stats must serve the stats JSON");
    /* trailing slash / query string on /stats still routes to stats */
    CHECK(classify("GET /stats?foo=bar HTTP/1.1\r\n\r\n") == STATS_REQ_HTTP_STATS,
          "GET /stats with a query string must still serve the stats JSON");
}

/* (3) GET /health -> health probe. */
static void
test_get_health(void)
{
    CHECK(classify("GET /health HTTP/1.0\r\n\r\n") == STATS_REQ_HTTP_HEALTH,
          "GET /health must classify as the health probe");
}

/* (4) HEAD /stats -> stats headers only (no body). */
static void
test_head_stats(void)
{
    CHECK(classify("HEAD /stats HTTP/1.1\r\n\r\n") == STATS_REQ_HTTP_STATS_HEAD,
          "HEAD /stats must classify as stats-head (headers, no body)");
    CHECK(classify("HEAD / HTTP/1.0\r\n\r\n") == STATS_REQ_HTTP_STATS_HEAD,
          "HEAD / must classify as stats-head");
}

/* (5) Unknown path under a known method -> 404. */
static void
test_unknown_path_is_notfound(void)
{
    CHECK(classify("GET /nope HTTP/1.1\r\n\r\n") == STATS_REQ_HTTP_NOTFOUND,
          "an unknown path must classify as NOTFOUND (404), not RAW");
    CHECK(classify("GET /metrics HTTP/1.1\r\n\r\n") == STATS_REQ_HTTP_NOTFOUND,
          "/metrics is not served yet -> NOTFOUND (leaves room for a future add)");
}

/*
 * (6) A recognised method but a malformed request line -> BADREQUEST. Once we
 * have committed to HTTP (we saw GET/HEAD), we must answer with HTTP, never fall
 * back to a bare JSON dump.
 */
static void
test_known_method_malformed_is_badrequest(void)
{
    CHECK(classify("GET\r\n") == STATS_REQ_HTTP_BADREQUEST,
          "GET with no path must be a 400, not RAW");
    CHECK(classify("GET noslash HTTP/1.0\r\n\r\n") == STATS_REQ_HTTP_BADREQUEST,
          "a path that does not begin with '/' must be a 400");
}

/*
 * (7) Header formatter: status line + required headers + blank-line terminator;
 * and overflow reporting.
 */
static void
test_format_header(void)
{
    char buf[256];
    int n = stats_http_format_header(buf, sizeof(buf), 200, "OK",
                                     "application/json", 123);
    CHECK(n > 0, "format_header must return a positive length on success");
    CHECK((size_t)n < sizeof(buf), "header must fit and be NUL-terminated");

    CHECK(strncmp(buf, "HTTP/1.1 200 OK\r\n", 17) == 0,
          "status line must be 'HTTP/1.1 200 OK'");
    CHECK(strstr(buf, "Content-Type: application/json\r\n") != NULL,
          "Content-Type header must be present");
    CHECK(strstr(buf, "Content-Length: 123\r\n") != NULL,
          "Content-Length header must carry the body length");
    CHECK(strstr(buf, "Connection: close\r\n") != NULL,
          "Connection: close header must be present");
    /* The header block must end with a blank line (CRLFCRLF). */
    CHECK(n >= 4 && strcmp(buf + n - 4, "\r\n\r\n") == 0,
          "header block must terminate with a blank line (CRLFCRLF)");

    /* A 404 status line with a different reason phrase. */
    n = stats_http_format_header(buf, sizeof(buf), 404, "Not Found",
                                 "text/plain", 0);
    CHECK(n > 0 && strncmp(buf, "HTTP/1.1 404 Not Found\r\n", 24) == 0,
          "404 status line must read 'HTTP/1.1 404 Not Found'");

    /* Overflow: a buffer far too small must report -1, never write past end. */
    char tiny[8];
    n = stats_http_format_header(tiny, sizeof(tiny), 200, "OK",
                                 "application/json", 123);
    CHECK(n < 0, "format_header into a too-small buffer must return -1");
}

int
main(void)
{
    test_bare_connect_is_raw();
    test_get_stats_paths();
    test_get_health();
    test_head_stats();
    test_unknown_path_is_notfound();
    test_known_method_malformed_is_badrequest();
    test_format_header();

    if (failures == 0) {
        printf("OK: all stats-http classification/format tests passed\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
}
