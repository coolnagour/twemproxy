/*
 * twemproxy - A fast and lightweight proxy for memcached protocol.
 * Copyright (C) 2011 Twitter, Inc.
 * Copyright (C) 2024-2025 coolnagour
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <nc_core.h>
#include <nc_server.h>
#include <nc_process.h>

static struct string pools_tag_key = string("pools");
static struct string servers_tag_key = string("servers");
static struct string server_latency_key = string("server_latency");
static struct string req_latency_key = string("request_latency");
static int64_t latency_buckets[] =  {
    1, 10, 20, 50, 100, 200, 500, 1000, 2000, 3000, INT64_MAX
};

#define NBUCKET (sizeof(latency_buckets)/sizeof(latency_buckets[0]))
struct stats_desc {
    char *name; /* stats name */
    char *desc; /* stats description */
};

#define DEFINE_ACTION(_name, _type, _desc) { .type = _type, .name = string(#_name) },
static struct stats_metric stats_pool_codec[] = {
    STATS_POOL_CODEC( DEFINE_ACTION )
};

static struct stats_metric stats_server_codec[] = {
    STATS_SERVER_CODEC( DEFINE_ACTION )
};
#undef DEFINE_ACTION

#define DEFINE_ACTION(_name, _type, _desc) { .name = #_name, .desc = _desc },
static struct stats_desc stats_pool_desc[] = {
    STATS_POOL_CODEC( DEFINE_ACTION )
};

static struct stats_desc stats_server_desc[] = {
    STATS_SERVER_CODEC( DEFINE_ACTION )
};
#undef DEFINE_ACTION

static rstatus_t stats_add_dns_hosts(struct stats *st, struct string *server_name);

/*
 * ---------------------------------------------------------------------------
 * HTTP-aware stats endpoint
 *
 * The stats port speaks two dialects on the same socket:
 *   - A proper HTTP/1.1 request (GET/HEAD ...) gets a framed HTTP response.
 *   - A BARE connect -- a client that opens the socket and reads without
 *     sending a request line -- gets the raw JSON document dumped on connect,
 *     exactly as the original twemproxy did. The container healthcheck relies
 *     on this: it opens a TCP socket and reads a byte without writing anything.
 *
 * The classification + header formatting are pure functions so they can be unit
 * tested without a socket (tests/unit/test_stats_http.c). The socket plumbing
 * that calls them lives in stats_serve_conn() below.
 * ---------------------------------------------------------------------------
 */

/*
 * Does `buf` (the first `len` peeked bytes) begin with the HTTP method token
 * `tok` (e.g. "GET") at a word boundary -- the literal token followed by a
 * non-alphabetic byte (space/CR/LF/tab) or end of buffer? Returns the token
 * length on a match, or 0 otherwise.
 *
 * The boundary check is what keeps "GETX..." or random bytes from looking like
 * GET, while still recognising a degenerate "GET\r\n" (no target) as an HTTP
 * GET so the caller can return 400 rather than dumping raw JSON. If `len` is
 * shorter than the token we cannot yet tell -- report no match (0) and let the
 * caller treat it as a bare connect.
 */
static size_t
stats_http_method_len(const uint8_t *buf, size_t len, const char *tok)
{
    size_t toklen = strlen(tok);
    uint8_t next;

    if (len < toklen) {
        return 0;
    }
    if (memcmp(buf, tok, toklen) != 0) {
        return 0;
    }
    if (len == toklen) {
        return toklen; /* token runs exactly to the end of the peeked bytes */
    }
    /* Require a non-alphabetic boundary so "GET" does not match "GETXY". */
    next = buf[toklen];
    if ((next >= 'A' && next <= 'Z') || (next >= 'a' && next <= 'z')) {
        return 0;
    }
    return toklen;
}

/*
 * Match the request target (path) at `p` (length `len`) against `want`
 * (e.g. "/stats"). A match is the exact path, or the path followed by a path
 * terminator: a space (end of target before the HTTP-version token), '?' (query
 * string), or end of buffer. This keeps "/stats" from matching "/statsx" while
 * still accepting "/stats?foo" and a bare "/stats".
 */
static bool
stats_http_path_is(const uint8_t *p, size_t len, const char *want)
{
    size_t wlen = strlen(want);

    if (len < wlen) {
        return false;
    }
    if (memcmp(p, want, wlen) != 0) {
        return false;
    }
    if (len == wlen) {
        return true; /* exact, path runs to end of the (already line-bounded) span */
    }
    {
        uint8_t c = p[wlen];
        return c == ' ' || c == '?' || c == '\t';
    }
}

stats_request_kind_t
stats_request_classify(const uint8_t *buf, size_t len)
{
    size_t mlen;
    bool is_head = false;
    const uint8_t *path;
    size_t path_len;
    size_t i;

    if (buf == NULL || len == 0) {
        return STATS_REQ_RAW; /* bare connect: legacy raw-JSON dump */
    }

    /* Identify the method token. Only GET and HEAD are recognised. Anything
     * else (including a partial token we cannot yet resolve) is a bare
     * connect. */
    mlen = stats_http_method_len(buf, len, "GET");
    if (mlen == 0) {
        mlen = stats_http_method_len(buf, len, "HEAD");
        if (mlen == 0) {
            return STATS_REQ_RAW;
        }
        is_head = true;
    }

    /* We have committed to HTTP. From here on, a malformed line is a 400 -- we
     * owe the client an HTTP response, never a bare JSON dump.
     *
     * Skip exactly the single space that separates the method from the target
     * (request-line grammar is METHOD SP target SP version). A missing space
     * (e.g. "GET\r\n") is malformed. */
    if (mlen >= len || buf[mlen] != ' ') {
        return STATS_REQ_HTTP_BADREQUEST;
    }
    mlen += 1; /* consume the single SP */

    path = buf + mlen;
    path_len = len - mlen;

    /* A well-formed target begins with '/'. No path, or a target that does not
     * start with '/', is malformed -> 400. */
    if (path_len == 0 || path[0] != '/') {
        return STATS_REQ_HTTP_BADREQUEST;
    }

    /* Bound the path scan to the request-line: stop at the first space (before
     * the HTTP-version token) or CR/LF. We only need to compare known literals,
     * and stats_http_path_is() handles the terminator, so this length cap is
     * just to keep us inside the line. */
    for (i = 0; i < path_len; i++) {
        if (path[i] == ' ' || path[i] == '\r' || path[i] == '\n') {
            break;
        }
    }
    path_len = i;

    if (stats_http_path_is(path, path_len, "/") ||
        stats_http_path_is(path, path_len, "/stats")) {
        return is_head ? STATS_REQ_HTTP_STATS_HEAD : STATS_REQ_HTTP_STATS;
    }

    if (!is_head && stats_http_path_is(path, path_len, "/health")) {
        return STATS_REQ_HTTP_HEALTH;
    }

    /* Known method, recognised-as-HTTP, but an unknown path -> 404. */
    return STATS_REQ_HTTP_NOTFOUND;
}

int
stats_http_format_header(char *dst, size_t dstsz, int status,
                         const char *reason, const char *content_type,
                         size_t content_length)
{
    int n;

    n = nc_snprintf(dst, dstsz,
                    "HTTP/1.1 %d %s\r\n"
                    "Content-Type: %s\r\n"
                    "Content-Length: %zu\r\n"
                    "Connection: close\r\n"
                    "\r\n",
                    status, reason, content_type, content_length);
    if (n < 0 || (size_t)n >= dstsz) {
        return -1;
    }
    return n;
}

/*
 * How long, at most, to wait for a client to send a request line before we
 * decide it is a BARE connect and dump the raw JSON. A real HTTP client (curl)
 * sends its request immediately after connect, so a short grace catches it; a
 * bare-connect client (the /dev/tcp healthcheck) never sends, so it waits this
 * long and then gets the raw body. Kept well under a second so the healthcheck
 * still gets its first byte promptly (its own timeout is seconds).
 */
#define STATS_HTTP_PEEK_MS 150

/* Largest request line we bother to peek at. We only need the method + path +
 * version; anything longer is still classified from this prefix. */
#define STATS_HTTP_PEEK_BUF 1024

/*
 * Send a framed HTTP/1.1 response: header block (status + content-type +
 * content-length + connection-close) followed by `body` (omitted for HEAD).
 */
static rstatus_t
stats_http_send(int sd, int status, const char *reason, const char *ctype,
                const uint8_t *body, size_t body_len, bool head_only)
{
    char header[256];
    int hlen;
    ssize_t n;

    hlen = stats_http_format_header(header, sizeof(header), status, reason,
                                    ctype, body_len);
    if (hlen < 0) {
        log_error("stats http header format failed (status %d)", status);
        return NC_ERROR;
    }

    n = nc_sendn(sd, header, (size_t)hlen);
    if (n < 0) {
        log_error("send stats http header on sd %d failed: %s", sd,
                  strerror(errno));
        return NC_ERROR;
    }

    if (head_only || body_len == 0) {
        return NC_OK;
    }

    n = nc_sendn(sd, body, body_len);
    if (n < 0) {
        log_error("send stats http body on sd %d failed: %s", sd,
                  strerror(errno));
        return NC_ERROR;
    }
    return NC_OK;
}

/*
 * Serve one accepted stats connection on `sd`, then close it. `body` is the
 * already-built JSON document (length `body_len`).
 *
 * Back-compat is the whole point of the peek dance: the legacy path is a client
 * that opens the socket and READS without sending anything (the container's
 * /dev/tcp byte-read healthcheck, and `nc -z` which just connects). Such a
 * client must still get bytes promptly. So:
 *
 *   1. Make the socket non-blocking and poll() up to STATS_HTTP_PEEK_MS for any
 *      inbound data. (Non-blocking + a bounded poll is what guarantees a bare
 *      connect never makes us hang waiting for a request that will never come.)
 *   2. If nothing arrives, or what arrives is not a recognised HTTP method,
 *      classify RAW and dump the JSON body exactly as the original code did.
 *   3. If an HTTP request line is present, drain the peeked bytes and reply with
 *      a proper framed HTTP response (200 JSON for / and /stats, 200 text "ok"
 *      for /health, 404 for an unknown path, 400 for a malformed line).
 *
 * We only ever PEEK to classify; the request bytes are then drained best-effort
 * before we respond. We do not parse headers or bodies -- the stats endpoint is
 * request-line addressed only.
 */
static void
stats_serve_conn(int sd, const uint8_t *body, size_t body_len)
{
    uint8_t peek[STATS_HTTP_PEEK_BUF];
    ssize_t pn = 0;
    stats_request_kind_t kind;
    struct pollfd pfd;

    /* Non-blocking so neither the poll fallback nor the peek can ever block on
     * a client that connected but will not send. */
    if (nc_set_nonblocking(sd) < 0) {
        log_warn("stats: set nonblocking on sd %d failed: %s -- serving raw",
                 sd, strerror(errno));
        /* Fall back to the legacy behaviour: just dump the raw body. */
        (void)nc_sendn(sd, body, body_len);
        close(sd);
        return;
    }

    pfd.fd = sd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    /* Wait briefly for a request line. EINTR just retries within the budget;
     * we do not loop on the clock because a single short wait is enough to tell
     * an HTTP client (sends immediately) from a bare connect (never sends). */
    if (poll(&pfd, 1, STATS_HTTP_PEEK_MS) > 0 && (pfd.revents & POLLIN)) {
        do {
            pn = recv(sd, peek, sizeof(peek), MSG_PEEK);
        } while (pn < 0 && errno == EINTR);
        if (pn < 0) {
            pn = 0; /* treat a peek error as "no request" -> raw */
        }
    }

    kind = stats_request_classify(peek, (size_t)pn);

    /*
     * Classification is done; the send helpers (nc_sendn) assume a BLOCKING
     * descriptor -- they loop on EINTR but not EAGAIN, so a large body on a slow
     * client would otherwise short-write on a non-blocking socket. Restore
     * blocking mode (the original accepted-socket behaviour) before any send. If
     * that fails we still try to send; a small body usually fits the send buffer
     * in one shot regardless.
     */
    (void)nc_set_blocking(sd);

    if (kind == STATS_REQ_RAW) {
        /* Legacy path: emit the raw JSON document, no HTTP framing. */
        (void)nc_sendn(sd, body, body_len);
        close(sd);
        return;
    }

    /*
     * HTTP path. Drain the request bytes we peeked at (best effort -- we do not
     * need them, but draining avoids an RST on close while data is unread). The
     * socket is blocking again now, so cap the drain to a single read of the
     * peeked length: we only need to clear what we saw, not loop on the client.
     */
    if (pn > 0) {
        uint8_t drain[STATS_HTTP_PEEK_BUF];
        ssize_t dn;
        do {
            dn = recv(sd, drain, (size_t)pn, 0);
        } while (dn < 0 && errno == EINTR);
        (void)dn;
    }

    switch (kind) {
    case STATS_REQ_HTTP_STATS:
        (void)stats_http_send(sd, 200, "OK", "application/json",
                              body, body_len, false);
        break;
    case STATS_REQ_HTTP_STATS_HEAD:
        (void)stats_http_send(sd, 200, "OK", "application/json",
                              body, body_len, true);
        break;
    case STATS_REQ_HTTP_HEALTH:
        (void)stats_http_send(sd, 200, "OK", "text/plain",
                              (const uint8_t *)"ok\n", 3, false);
        break;
    case STATS_REQ_HTTP_NOTFOUND:
        (void)stats_http_send(sd, 404, "Not Found", "text/plain",
                              (const uint8_t *)"not found\n", 10, false);
        break;
    case STATS_REQ_HTTP_BADREQUEST:
    default:
        (void)stats_http_send(sd, 400, "Bad Request", "text/plain",
                              (const uint8_t *)"bad request\n", 12, false);
        break;
    }

    close(sd);
}

void
stats_describe(void)
{
    uint32_t i;

    log_stderr("pool stats:");
    for (i = 0; i < NELEMS(stats_pool_desc); i++) {
        log_stderr("  %-20s\"%s\"", stats_pool_desc[i].name,
                   stats_pool_desc[i].desc);
    }

    log_stderr("");

    log_stderr("server stats:");
    for (i = 0; i < NELEMS(stats_server_desc); i++) {
        log_stderr("  %-20s\"%s\"", stats_server_desc[i].name,
                   stats_server_desc[i].desc);
    }

    log_stderr("");
    log_stderr("enhanced dynamic DNS & latency features:");
    log_stderr("  dns_addresses        \"# DNS resolved addresses for dynamic servers\"");
    log_stderr("  dns_resolves         \"# DNS resolution attempts\"");
    log_stderr("  dns_failures         \"# DNS resolution failures\"");
    log_stderr("  current_latency_us   \"current connection latency in microseconds\"");
    log_stderr("  last_dns_resolved_at \"timestamp when DNS was last resolved in usec\"");
    log_stderr("");
    log_stderr("cloud multi-zone optimizations:");
    log_stderr("  same_zone_selections \"# times same-zone server was selected\"");
    log_stderr("  cross_zone_selections \"# times cross-zone server was selected\"");
}

static void
stats_metric_init(struct stats_metric *stm)
{
    switch (stm->type) {
    case STATS_COUNTER:
        stm->value.counter = 0LL;
        break;

    case STATS_GAUGE:
        stm->value.counter = 0LL;
        break;

    case STATS_TIMESTAMP:
        stm->value.timestamp = 0LL;
        break;

    default:
        NOT_REACHED();
    }
}

static void
stats_metric_reset(struct array *stats_metric)
{
    uint32_t i, nmetric;

    nmetric = array_n(stats_metric);
    ASSERT(nmetric == STATS_POOL_NFIELD || nmetric == STATS_SERVER_NFIELD);

    for (i = 0; i < nmetric; i++) {
        struct stats_metric *stm = array_get(stats_metric, i);

        stats_metric_init(stm);
    }
}

static rstatus_t
stats_pool_metric_init(struct array *stats_metric)
{
    rstatus_t status;
    uint32_t i, nfield = STATS_POOL_NFIELD;

    status = array_init(stats_metric, nfield, sizeof(struct stats_metric));
    if (status != NC_OK) {
        return status;
    }

    for (i = 0; i < nfield; i++) {
        struct stats_metric *stm = array_push(stats_metric);

        /* initialize from pool codec first */
        *stm = stats_pool_codec[i];

        /* initialize individual metric */
        stats_metric_init(stm);
    }

    return NC_OK;
}

static rstatus_t
stats_server_metric_init(struct stats_server *sts)
{
    rstatus_t status;
    uint32_t i, nfield = STATS_SERVER_NFIELD;

    status = array_init(&sts->metric, nfield, sizeof(struct stats_metric));
    if (status != NC_OK) {
        return status;
    }

    for (i = 0; i < nfield; i++) {
        struct stats_metric *stm = array_push(&sts->metric);

        /* initialize from server codec first */
        *stm = stats_server_codec[i];

        /* initialize individual metric */
        stats_metric_init(stm);
    }

    return NC_OK;
}

static void
stats_metric_deinit(struct array *metric)
{
    uint32_t i, nmetric;

    nmetric = array_n(metric);
    for (i = 0; i < nmetric; i++) {
        array_pop(metric);
    }
    array_deinit(metric);
}

static void
stats_latency_reset(struct array *latency)
{
    uint32_t i;
    uint64_t *bucket;

    for (i = 0; i < NBUCKET; i++) {
        bucket = array_get(latency, i);
        *bucket = 0;
    }
}

static rstatus_t
stats_latency_init(struct array *latency)
{
    rstatus_t status;
    uint32_t i;

    status = array_init(latency, NBUCKET, sizeof(uint64_t));
    for (i = 0; i < NBUCKET; i++) {
        uint64_t *bucket = array_push(latency);
        *bucket = 0;
    }
    return status;
}

static void
stats_latency_deinit(struct array *latency)
{
    uint32_t i, buckets;

    buckets = array_n(latency);
    for (i = 0; i < buckets; i++) {
        array_pop(latency);
    }
    array_deinit(latency);
}

static rstatus_t
server_each_map_to_stats_server(void *elem, void *data)
{
    struct server *s = elem;
    struct stats_server *sts = array_push((struct array*)data);
    rstatus_t status;

    sts->name = s->name;
    array_null(&sts->metric);

    status = stats_server_metric_init(sts);
    if (status != NC_OK) {
        return status;
    }
    status = stats_latency_init(&sts->latency);
    if (status != NC_OK) {
        stats_metric_deinit(&sts->metric);
        return status;
    }

    log_debug(LOG_VVVERB, "init stats server '%.*s' with %"PRIu32" metric",
              sts->name.len, sts->name.data, array_n(&sts->metric));

    return NC_OK;

}

static rstatus_t
stats_server_map(struct array *stats_server, struct array *server, struct array *master)
{
    rstatus_t status;
    uint32_t nserver, nmaster;

    nserver = array_n(server);
    ASSERT(nserver != 0);
    nmaster = array_n(master);
    /* nmaster can be 0 */

    status = array_init(stats_server, nserver + nmaster, sizeof(struct stats_server));
    if (status != NC_OK) {
        return status;
    }

    status = array_each(server, server_each_map_to_stats_server, stats_server);
    if (status != NC_OK) {
        return status;
    }

    if (nmaster != 0) {
        status = array_each(master, server_each_map_to_stats_server, stats_server);
        if (status != NC_OK) {
            return status;
        }
    }

    log_debug(LOG_VVVERB, "map %"PRIu32" stats servers", nserver + master);

    return NC_OK;
}

static void
stats_server_unmap(struct array *stats_server)
{
    uint32_t i, nserver;

    nserver = array_n(stats_server);

    for (i = 0; i < nserver; i++) {
        struct stats_server *sts = array_pop(stats_server);
        stats_metric_deinit(&sts->metric);
        stats_latency_deinit(&sts->latency);
    }
    array_deinit(stats_server);

    log_debug(LOG_VVVERB, "unmap %"PRIu32" stats servers", nserver);
}

static rstatus_t
stats_pool_init(struct stats_pool *stp, struct server_pool *sp)
{
    rstatus_t status;

    stp->name = sp->name;
    array_null(&stp->metric);
    array_null(&stp->server);
    array_null(&stp->latency);

    status = stats_pool_metric_init(&stp->metric);
    if (status != NC_OK) {
        return status;
    }
    status = stats_latency_init(&stp->latency);
    if (status != NC_OK) {
        stats_metric_deinit(&stp->metric);
        return status;
    }

    status = stats_server_map(&stp->server, &sp->server, &sp->redis_master);
    if (status != NC_OK) {
        stats_metric_deinit(&stp->metric);
        stats_latency_deinit(&stp->latency);
        return status;
    }

    log_debug(LOG_VVVERB, "init stats pool '%.*s' with %"PRIu32" metric and "
              "%"PRIu32" server", stp->name.len, stp->name.data,
              array_n(&stp->metric), array_n(&stp->metric));

    return NC_OK;
}

static void
stats_pool_reset(struct array *stats_pool)
{
    uint32_t i, npool;

    npool = array_n(stats_pool);

    for (i = 0; i < npool; i++) {
        struct stats_pool *stp = array_get(stats_pool, i);
        uint32_t j, nserver;

        stats_metric_reset(&stp->metric);
        stats_latency_reset(&stp->latency);

        nserver = array_n(&stp->server);
        for (j = 0; j < nserver; j++) {
            struct stats_server *sts = array_get(&stp->server, j);
            stats_metric_reset(&sts->metric);
            stats_latency_reset(&sts->latency);
        }
    }
}

static rstatus_t
stats_pool_map(struct array *stats_pool, struct array *server_pool)
{
    rstatus_t status;
    uint32_t i, npool;

    npool = array_n(server_pool);
    ASSERT(npool != 0);

    status = array_init(stats_pool, npool, sizeof(struct stats_pool));
    if (status != NC_OK) {
        return status;
    }

    for (i = 0; i < npool; i++) {
        struct server_pool *sp = array_get(server_pool, i);
        struct stats_pool *stp = array_push(stats_pool);

        status = stats_pool_init(stp, sp);
        if (status != NC_OK) {
            return status;
        }
    }

    log_debug(LOG_VVVERB, "map %"PRIu32" stats pools", npool);

    return NC_OK;
}

static void
stats_pool_unmap(struct array *stats_pool)
{
    uint32_t i, npool;

    npool = array_n(stats_pool);

    for (i = 0; i < npool; i++) {
        struct stats_pool *stp = array_pop(stats_pool);
        stats_metric_deinit(&stp->metric);
        stats_latency_deinit(&stp->latency);
        stats_server_unmap(&stp->server);
    }
    array_deinit(stats_pool);

    log_debug(LOG_VVVERB, "unmap %"PRIu32" stats pool", npool);
}

static rstatus_t
stats_create_buf(struct stats *st)
{
    uint32_t int64_max_digits = 20;  /* INT64_MAX = 9223372036854775807 */
    uint32_t key_value_extra = 8;    /* "key": "value", */
    uint32_t pool_extra = 8;         /* '"pool_name": { ' + ' }' */
    uint32_t server_extra = 8;       /* '"server_name": { ' + ' }' */
    uint32_t pools_tag_extra = 14;   /* '"pools": { ' + ' }' */
    uint32_t servers_tag_extra = 16; /* '"servers": { ' + ' }' */
    uint32_t latency_extra = 8;      /* '"latency": [' + '], ' */
    size_t size = 0;
    uint32_t i;

    ASSERT(st->buf.data == NULL && st->buf.size == 0);

    /* header */
    size += 1;

    size += st->service_str.len;
    size += st->service.len;
    size += key_value_extra;

    size += st->source_str.len;
    size += st->source.len;
    size += key_value_extra;

    size += st->version_str.len;
    size += st->version.len;
    size += key_value_extra;

    size += st->uptime_str.len;
    size += int64_max_digits;
    size += key_value_extra;

    size += st->timestamp_str.len;
    size += int64_max_digits;
    size += key_value_extra;

    size += st->ntotal_conn_str.len;
    size += int64_max_digits;
    size += key_value_extra;

    size += st->ncurr_conn_str.len;
    size += int64_max_digits;
    size += key_value_extra;

    /* server pools */
    size += pools_tag_extra;
    for (i = 0; i < array_n(&st->sum); i++) {
        struct stats_pool *stp = array_get(&st->sum, i);
        uint32_t j;

        size += stp->name.len;
        size += pool_extra;

        for (j = 0; j < array_n(&stp->metric); j++) {
            struct stats_metric *stm = array_get(&stp->metric, j);

            size += stm->name.len;
            size += int64_max_digits;
            size += key_value_extra;
        }

        // server request latency
        // +1 for comma in array
        size += NBUCKET*(int64_max_digits+1)+latency_extra;

        /* servers per pool */
        size += servers_tag_extra;
        for (j = 0; j < array_n(&stp->server); j++) {
            struct stats_server *sts = array_get(&stp->server, j);
            uint32_t k;

            size += sts->name.len;
            size += server_extra;

            for (k = 0; k < array_n(&sts->metric); k++) {
                struct stats_metric *stm = array_get(&sts->metric, k);

                size += stm->name.len;
                size += int64_max_digits;
                size += key_value_extra;
            }
            // server request latency
            // +1 for comma in array
            size += NBUCKET*(int64_max_digits+1)+latency_extra;
        }
    }

    /* Add extra buffer space for DNS host information - allow for up to 10 servers with 16 addresses each */
    size += 25600; /* 25KB extra buffer: 10 servers * 16 addresses * 160 bytes per address */

    /* footer */
    size += 2;

    size = NC_ALIGN(size, NC_ALIGNMENT);

    st->buf.data = nc_alloc(size);
    if (st->buf.data == NULL) {
        log_error("create stats buffer of size %zu failed: %s", size,
                   strerror(errno));
        return NC_ENOMEM;
    }
    st->buf.size = size;

    log_debug(LOG_DEBUG, "stats buffer size %zu", size);

    return NC_OK;
}

static void
stats_destroy_buf(struct stats *st)
{
    if (st->buf.size != 0) {
        ASSERT(st->buf.data != NULL);
        nc_free(st->buf.data);
        st->buf.size = 0;
    }
}

static rstatus_t
stats_add_latency(struct stats *st, struct string *key, struct array *latency)
{
    struct stats_buffer *buf;
    uint8_t *pos;
    int n, room;
    uint32_t i;
    uint64_t *bucket;

    buf = &st->buf;
    pos = buf->data + buf->len;
    room = (int)(buf->size - buf->len - 1);
    n = nc_snprintf(pos, room, "\"%.*s\": [", key->len, key->data);
    for (i = 0; i < NBUCKET; i++) {
        bucket = array_get(latency, i);
        if (n >= room) {
            return NC_ERROR;
        }
        if (i == NBUCKET -1) {
            n += nc_snprintf(pos+n, room - n, "%"PRId64"], ", *bucket);
        } else {
            n += nc_snprintf(pos+n, room - n, "%"PRId64",", *bucket);
        }
    }
    buf->len += (size_t)n;
    return NC_OK;
}

static rstatus_t
stats_add_string(struct stats *st, struct string *key, struct string *val)
{
    struct stats_buffer *buf;
    uint8_t *pos;
    size_t room;
    int n;

    buf = &st->buf;
    pos = buf->data + buf->len;
    room = buf->size - buf->len - 1;

    n = nc_snprintf(pos, room, "\"%.*s\":\"%.*s\", ", key->len, key->data,
                    val->len, val->data);
    if (n < 0 || n >= (int)room) {
        return NC_ERROR;
    }

    buf->len += (size_t)n;

    return NC_OK;
}

static rstatus_t
stats_add_num(struct stats *st, struct string *key, int64_t val)
{
    struct stats_buffer *buf;
    uint8_t *pos;
    size_t room;
    int n;

    buf = &st->buf;
    pos = buf->data + buf->len;
    room = buf->size - buf->len - 1;

    n = nc_snprintf(pos, room, "\"%.*s\":%"PRId64", ", key->len, key->data,
                    val);
    if (n < 0 || n >= (int)room) {
        return NC_ERROR;
    }

    buf->len += (size_t)n;

    return NC_OK;
}

static rstatus_t
stats_add_header(struct stats *st)
{
    rstatus_t status;
    struct stats_buffer *buf;
    int64_t cur_ts, uptime;

    buf = &st->buf;
    buf->data[0] = '{';
    buf->len = 1;

    cur_ts = (int64_t)time(NULL);
    uptime = cur_ts - st->start_ts;

    status = stats_add_string(st, &st->service_str, &st->service);
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_string(st, &st->source_str, &st->source);
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_string(st, &st->version_str, &st->version);
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_num(st, &st->uptime_str, uptime);
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_num(st, &st->timestamp_str, cur_ts);
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_num(st, &st->pid_str, (int64_t)getpid());
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_num(st, &st->ntotal_conn_str, (int64_t)conn_ntotal_conn());
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_num(st, &st->ncurr_conn_str, conn_ncurr_conn());
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

static rstatus_t
stats_add_footer(struct stats *st)
{
    struct stats_buffer *buf;
    uint8_t *pos;

    buf = &st->buf;

    if (buf->len == buf->size) {
        return NC_ERROR;
    }

    /* overwrite the last byte and add a new byte */
    pos = buf->data + buf->len - 1;
    pos[0] = '}';
    pos[1] = '\n';
    buf->len += 1;

    return NC_OK;
}

static rstatus_t
stats_begin_nesting(struct stats *st, struct string *key)
{
    struct stats_buffer *buf;
    uint8_t *pos;
    size_t room;
    int n;

    buf = &st->buf;
    pos = buf->data + buf->len;
    room = buf->size - buf->len - 1;

    n = nc_snprintf(pos, room, "\"%.*s\": {", key->len, key->data);
    if (n < 0 || n >= (int)room) {
        return NC_ERROR;
    }

    buf->len += (size_t)n;

    return NC_OK;
}

static rstatus_t
stats_end_nesting(struct stats *st)
{
    struct stats_buffer *buf;
    uint8_t *pos;

    buf = &st->buf;
    pos = buf->data + buf->len;

    pos -= 2; /* go back by 2 bytes */

    switch (pos[0]) {
    case ',':
        /* overwrite last two bytes; len remains unchanged */
        ASSERT(pos[1] == ' ');
        pos[0] = '}';
        pos[1] = ',';
        break;

    case '}':
        if (buf->len == buf->size) {
            return NC_ERROR;
        }
        /* overwrite the last byte and add a new byte */
        ASSERT(pos[1] == ',');
        pos[1] = '}';
        pos[2] = ',';
        buf->len += 1;
        break;

    default:
        NOT_REACHED();
    }

    return NC_OK;
}

static rstatus_t
stats_copy_metric(struct stats *st, struct array *metric)
{
    rstatus_t status;
    uint32_t i;

    for (i = 0; i < array_n(metric); i++) {
        struct stats_metric *stm = array_get(metric, i);

        status = stats_add_num(st, &stm->name, stm->value.counter);
        if (status != NC_OK) {
            return status;
        }
    }

    return NC_OK;
}

static void
stats_aggregate_latency(struct array *dst, struct array *src)
{
    uint32_t i;
    uint64_t *bucket1;
    uint64_t *bucket2;

    for (i = 0; i < NBUCKET; i++) {
        bucket1 = array_get(src, i);
        bucket2 = array_get(dst, i);
        *bucket2 += *bucket1;
    }
}

static void
stats_aggregate_metric(struct array *dst, struct array *src)
{
    uint32_t i;

    for (i = 0; i < array_n(src); i++) {
        struct stats_metric *stm1, *stm2;

        stm1 = array_get(src, i);
        stm2 = array_get(dst, i);

        ASSERT(stm1->type == stm2->type);

        switch (stm1->type) {
        case STATS_COUNTER:
            stm2->value.counter += stm1->value.counter;
            break;

        case STATS_GAUGE:
            stm2->value.counter += stm1->value.counter;
            break;

        case STATS_TIMESTAMP:
            if (stm1->value.timestamp) {
                stm2->value.timestamp = stm1->value.timestamp;
            }
            break;

        default:
            NOT_REACHED();
        }
    }
}

static void
stats_aggregate(struct stats *st)
{
    uint32_t i;

    if (st->aggregate == 0) {
        log_debug(LOG_PVERB, "skip aggregate of shadow %p to sum %p as "
                  "generator is slow", st->shadow.elem, st->sum.elem);
        return;
    }

    log_debug(LOG_PVERB, "aggregate stats shadow %p to sum %p", st->shadow.elem,
              st->sum.elem);

    for (i = 0; i < array_n(&st->shadow); i++) {
        struct stats_pool *stp1, *stp2;
        uint32_t j;

        stp1 = array_get(&st->shadow, i);
        stp2 = array_get(&st->sum, i);
        stats_aggregate_metric(&stp2->metric, &stp1->metric);
        stats_aggregate_latency(&stp2->latency, &stp1->latency);

        for (j = 0; j < array_n(&stp1->server); j++) {
            struct stats_server *sts1, *sts2;

            sts1 = array_get(&stp1->server, j);
            sts2 = array_get(&stp2->server, j);
            stats_aggregate_metric(&sts2->metric, &sts1->metric);
            stats_aggregate_latency(&sts2->latency, &sts1->latency);
        }
    }

    st->aggregate = 0;
}

static rstatus_t
stats_make_rsp(struct stats *st)
{
    rstatus_t status;
    uint32_t i;

    status = stats_add_header(st);
    if (status != NC_OK) {
        return status;
    }

    status = stats_begin_nesting(st, &pools_tag_key);
    if (status != NC_OK) {
        return status;
    }
    for (i = 0; i < array_n(&st->sum); i++) {
        struct stats_pool *stp = array_get(&st->sum, i);
        uint32_t j;

        status = stats_begin_nesting(st, &stp->name);
        if (status != NC_OK) {
            return status;
        }

        /* copy pool metric from sum(c) to buffer */
        status = stats_copy_metric(st, &stp->metric);
        if (status != NC_OK) {
            return status;
        }

        /* copy pool latency from sum(c) to buffer */
        status = stats_add_latency(st, &req_latency_key, &stp->latency);
        if (status != NC_OK) {
            return status;
        }

        status = stats_begin_nesting(st, &servers_tag_key);
        if (status != NC_OK) {
            return status;
        }
        for (j = 0; j < array_n(&stp->server); j++) {
            struct stats_server *sts = array_get(&stp->server, j);

            status = stats_begin_nesting(st, &sts->name);
            if (status != NC_OK) {
                return status;
            }

            /* copy server metric from sum(c) to buffer */
            status = stats_copy_metric(st, &sts->metric);
            if (status != NC_OK) {
                return status;
            }

            status = stats_add_latency(st, &server_latency_key, &sts->latency);
            if (status != NC_OK) {
                return status;
            }

            /* Add DNS host information for dynamic servers */
            status = stats_add_dns_hosts(st, &sts->name);
            if (status != NC_OK) {
                return status;
            }

            status = stats_end_nesting(st);
            if (status != NC_OK) {
                return status;
            }
        }

        /* end nesting for server name*/
        status = stats_end_nesting(st);
        if (status != NC_OK) {
            return status;
        }

        /* end nesting for servers tag */
        status = stats_end_nesting(st);
        if (status != NC_OK) {
            return status;
        }
    }
    /* end nesting for pools tag */
    status = stats_end_nesting(st);
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_footer(st);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

static rstatus_t
stats_send_rsp(struct stats *st)
{
    rstatus_t status;
    int sd;

    status = stats_make_rsp(st);
    if (status != NC_OK) {
        return status;
    }

    sd = accept(st->sd, NULL, NULL);
    if (sd < 0) {
        log_error("accept on m %d failed: %s", st->sd, strerror(errno));
        return NC_ERROR;
    }

    log_debug(LOG_VERB, "serve stats on sd %d (%zu json bytes)", sd,
              st->buf.len);

    /* Classify the connection (HTTP request vs bare connect) and respond
     * accordingly. stats_serve_conn() closes sd. */
    stats_serve_conn(sd, st->buf.data, st->buf.len);

    return NC_OK;
}

void
stats_loop_callback(void *arg1, void *arg2)
{
    struct stats *st = arg1;
    int n = *((int *)arg2);

    /* aggregate stats from shadow (b) -> sum (c) */
    stats_aggregate(st);

    if (n == 0) {
        return;
    }

    /* send aggregate stats sum (c) to collector */
    stats_send_rsp(st);
}

static rstatus_t
stats_each_calc_shared_mem_size(void *elem, void *data)
{
    char *shared_mem = ((struct instance *)elem)->ctx->shared_mem;
    size_t *size = data;
    *size += strlen(shared_mem);
    /* use "," instead of "\0" */
    return NC_OK;
}

static rstatus_t
stats_each_shared_mem_aggregate(void *elem, void *data)
{
    char *shared_mem = ((struct instance *)elem)->ctx->shared_mem;
    struct stats_buffer *buf = data;
    size_t len = strlen(shared_mem);
    uint8_t  *pos = buf->data + buf->len;
    memcpy(pos, shared_mem, len);
    buf->len += len;
    pos[len-1] = ',';
    return NC_OK;
}

static rstatus_t
stats_master_send_resp(struct stats *st)
{
    rstatus_t status;
    int sd;
    struct stats_buffer buf;
    buf.len=0;
    buf.size=0;

    status = array_each(&master_nci->workers, stats_each_calc_shared_mem_size, &buf.size);
    if (status) {
        return NC_ERROR;
    }
    /* delete a "," and add "[","]","\0" */
    buf.size+=2;
    buf.data = nc_alloc(buf.size);
    if (buf.data == NULL) {
       log_error("new out buf for master to aggregate failed");
        return NC_ERROR;
    }

    buf.data[0] = '[';
    buf.len = 1;
    status = array_each(&master_nci->workers, stats_each_shared_mem_aggregate, &buf);
    if (status) {
        free(buf.data);
        return NC_ERROR;
    }
    buf.data[buf.len-1] = ']';
    buf.data[buf.len] = 0;

    sd = accept(st->sd, NULL, NULL);
    if (sd < 0) {
        log_error("accept on m %d failed: %s", st->sd, strerror(errno));
        free(buf.data);
        return NC_ERROR;
    }

    log_debug(LOG_VERB, "serve stats on sd %d (%zu json bytes)", sd, buf.len);

    /* Same classify-then-respond path as the worker. The aggregated document is
     * the per-worker array; HTTP clients get it framed, bare connects get it
     * raw. stats_serve_conn() closes sd. */
    stats_serve_conn(sd, buf.data, buf.len);

    free(buf.data);
    return NC_OK;
};

void
stats_master_loop_callback(void *arg1, void* arg2)
{
    struct stats *st = arg1;
    int n = *((int *)arg2);

    if (n == 0) {
        return;
    }

    /* master aggregate worker buf to collector */
    stats_master_send_resp(st);
}

static void *
stats_master_loop(void *arg)
{
    struct stats *st = arg;
    event_loop_stats(st->loop, arg);
    return NULL;
}

static void *
stats_worker_loop(void *arg)
{
    rstatus_t status;
    struct stats *st = arg;
    for (;;) {
        stats_aggregate(st);
        status = stats_make_rsp(st);
        if (status != NC_OK) {
            return NULL;
        }
        memcpy(st->owner->shared_mem, st->buf.data, st->buf.len);
        st->owner->shared_mem[st->buf.len] = 0;
        sleep((unsigned int)(st->interval/1000));
    }
}

static rstatus_t
stats_listen(struct stats *st)
{
    rstatus_t status;
    struct sockinfo si;

    status = nc_resolve(&st->addr, st->port, &si);
    if (status < 0) {
        return status;
    }

    st->sd = socket(si.family, SOCK_STREAM, 0);
    if (st->sd < 0) {
        log_error("socket failed: %s", strerror(errno));
        return NC_ERROR;
    }

    status = nc_set_reuseaddr(st->sd);
    if (status < 0) {
        log_error("set reuseaddr on m %d failed: %s", st->sd, strerror(errno));
        return NC_ERROR;
    }

    status = bind(st->sd, (struct sockaddr *)&si.addr, si.addrlen);
    if (status < 0) {
        log_error("bind on m %d to addr '%.*s:%u' failed: %s", st->sd,
                  st->addr.len, st->addr.data, st->port, strerror(errno));
        return NC_ERROR;
    }

    status = listen(st->sd, SOMAXCONN);
    if (status < 0) {
        log_error("listen on m %d failed: %s", st->sd, strerror(errno));
        return NC_ERROR;
    }

    log_debug(LOG_NOTICE, "m %d listening on '%.*s:%u'", st->sd,
              st->addr.len, st->addr.data, st->port);

    return NC_OK;
}

static rstatus_t
stats_start_aggregator(struct stats *st)
{
    rstatus_t status;

    if (!stats_enabled) {
        return NC_OK;
    }

    /* stats is worker when loop is null */
    if (st->loop != NULL) {
        status = stats_listen(st);
        if (status != NC_OK) {
            return status;
        }
    }

    if (st->loop != NULL) {
        status = pthread_create(&st->tid, NULL, stats_master_loop, st);
    } else {
        status = pthread_create(&st->tid, NULL, stats_worker_loop, st);
    }

    if (status < 0) {
        log_error("stats aggregator create failed: %s", strerror(status));
        return NC_ERROR;
    }

    return NC_OK;
}

static void
stats_stop_aggregator(struct stats *st)
{
    if (!stats_enabled) {
        return;
    }

    if (st->sd > 0) {
        close(st->sd);
    }
}

struct stats *
stats_create(uint16_t stats_port, char *stats_ip, int stats_interval,
             char *source, struct array *server_pool, stats_loop_t loop)
{
    rstatus_t status;
    struct stats *st;

    st = nc_alloc(sizeof(*st));
    if (st == NULL) {
        return NULL;
    }

    st->port = stats_port;
    st->interval = stats_interval;
    string_set_raw(&st->addr, stats_ip);

    st->start_ts = (int64_t)time(NULL);

    st->buf.len = 0;
    st->buf.data = NULL;
    st->buf.size = 0;

    array_null(&st->current);
    array_null(&st->shadow);
    array_null(&st->sum);

    st->tid = (pthread_t) -1;
    st->sd = -1;

    st->loop = loop;

    string_set_text(&st->service_str, "service");
    string_set_text(&st->service, "nutcracker");

    string_set_text(&st->source_str, "source");
    string_set_raw(&st->source, source);

    string_set_text(&st->version_str, "version");
    string_set_text(&st->version, NC_VERSION_STRING);

    string_set_text(&st->uptime_str, "uptime");
    string_set_text(&st->timestamp_str, "timestamp");

    string_set_text(&st->pid_str, "pid");

    string_set_text(&st->ntotal_conn_str, "total_connections");
    string_set_text(&st->ncurr_conn_str, "curr_connections");

    st->updated = 0;
    st->aggregate = 0;

    /* map server pool to current (a), shadow (b) and sum (c) */

    status = stats_pool_map(&st->current, server_pool);
    if (status != NC_OK) {
        goto error;
    }

    status = stats_pool_map(&st->shadow, server_pool);
    if (status != NC_OK) {
        goto error;
    }

    status = stats_pool_map(&st->sum, server_pool);
    if (status != NC_OK) {
        goto error;
    }

    status = stats_create_buf(st);
    if (status != NC_OK) {
        goto error;
    }

    status = stats_start_aggregator(st);
    if (status != NC_OK) {
        goto error;
    }

    return st;

error:
    stats_destroy(st);
    return NULL;
}

void
stats_destroy(struct stats *st)
{
    //worker's stats will destroy in worker processes;
    if (st == NULL) {
        return;
    }
    stats_stop_aggregator(st);
    stats_pool_unmap(&st->sum);
    stats_pool_unmap(&st->shadow);
    stats_pool_unmap(&st->current);
    stats_destroy_buf(st);
    nc_free(st);
}

void
stats_swap(struct stats *st)
{
    if (!stats_enabled) {
        return;
    }

    if (st->aggregate == 1) {
        log_debug(LOG_PVERB, "skip swap of current %p shadow %p as aggregator "
                  "is busy", st->current.elem, st->shadow.elem);
        return;
    }

    if (st->updated == 0) {
        log_debug(LOG_PVERB, "skip swap of current %p shadow %p as there is "
                  "nothing new", st->current.elem, st->shadow.elem);
        return;
    }

    log_debug(LOG_PVERB, "swap stats current %p shadow %p", st->current.elem,
              st->shadow.elem);

    array_swap(&st->current, &st->shadow);

    /*
     * Reset current (a) stats before giving it back to generator to keep
     * stats addition idempotent
     */
    stats_pool_reset(&st->current);
    st->updated = 0;

    st->aggregate = 1;
}

static struct stats_metric *
stats_pool_to_metric(struct context *ctx, struct server_pool *pool,
                     stats_pool_field_t fidx)
{
    struct stats *st;
    struct stats_pool *stp;
    struct stats_metric *stm;
    uint32_t pidx;

    pidx = pool->idx;

    st = ctx->stats;
    stp = array_get(&st->current, pidx);
    stm = array_get(&stp->metric, fidx);

    st->updated = 1;

    log_debug(LOG_VVVERB, "metric '%.*s' in pool %"PRIu32"", stm->name.len,
              stm->name.data, pidx);

    return stm;
}

void
_stats_pool_incr(struct context *ctx, struct server_pool *pool,
                 stats_pool_field_t fidx)
{
    struct stats_metric *stm;

    stm = stats_pool_to_metric(ctx, pool, fidx);

    ASSERT(stm->type == STATS_COUNTER || stm->type == STATS_GAUGE);
    stm->value.counter++;

    log_debug(LOG_VVVERB, "incr field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_pool_decr(struct context *ctx, struct server_pool *pool,
                 stats_pool_field_t fidx)
{
    struct stats_metric *stm;

    stm = stats_pool_to_metric(ctx, pool, fidx);

    ASSERT(stm->type == STATS_GAUGE);
    stm->value.counter--;

    log_debug(LOG_VVVERB, "decr field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_pool_incr_by(struct context *ctx, struct server_pool *pool,
                    stats_pool_field_t fidx, int64_t val)
{
    struct stats_metric *stm;

    stm = stats_pool_to_metric(ctx, pool, fidx);

    ASSERT(stm->type == STATS_COUNTER || stm->type == STATS_GAUGE);
    stm->value.counter += val;

    log_debug(LOG_VVVERB, "incr by field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_pool_decr_by(struct context *ctx, struct server_pool *pool,
                    stats_pool_field_t fidx, int64_t val)
{
    struct stats_metric *stm;

    stm = stats_pool_to_metric(ctx, pool, fidx);

    ASSERT(stm->type == STATS_GAUGE);
    stm->value.counter -= val;

    log_debug(LOG_VVVERB, "decr by field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_pool_set_ts(struct context *ctx, struct server_pool *pool,
                   stats_pool_field_t fidx, int64_t val)
{
    struct stats_metric *stm;

    stm = stats_pool_to_metric(ctx, pool, fidx);

    ASSERT(stm->type == STATS_TIMESTAMP);
    stm->value.timestamp = val;

    log_debug(LOG_VVVERB, "set ts field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.timestamp);
}

static struct stats_metric *
stats_server_to_metric(struct context *ctx, struct server *server,
                       stats_server_field_t fidx)
{
    struct stats *st;
    struct stats_pool *stp;
    struct stats_server *sts;
    struct stats_metric *stm;
    uint32_t pidx, sidx;

    sidx = server->idx;
    pidx = server->owner->idx;

    st = ctx->stats;
    stp = array_get(&st->current, pidx);
    sts = array_get(&stp->server, sidx);
    stm = array_get(&sts->metric, fidx);

    st->updated = 1;

    log_debug(LOG_VVVERB, "metric '%.*s' in pool %"PRIu32" server %"PRIu32"",
              stm->name.len, stm->name.data, pidx, sidx);

    return stm;
}

void
_stats_server_incr(struct context *ctx, struct server *server,
                   stats_server_field_t fidx)
{
    struct stats_metric *stm;

    stm = stats_server_to_metric(ctx, server, fidx);

    ASSERT(stm->type == STATS_COUNTER || stm->type == STATS_GAUGE);
    stm->value.counter++;

    log_debug(LOG_VVVERB, "incr field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_server_decr(struct context *ctx, struct server *server,
                   stats_server_field_t fidx)
{
    struct stats_metric *stm;

    stm = stats_server_to_metric(ctx, server, fidx);

    ASSERT(stm->type == STATS_GAUGE);
    stm->value.counter--;

    log_debug(LOG_VVVERB, "decr field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_server_incr_by(struct context *ctx, struct server *server,
                      stats_server_field_t fidx, int64_t val)
{
    struct stats_metric *stm;

    stm = stats_server_to_metric(ctx, server, fidx);

    ASSERT(stm->type == STATS_COUNTER || stm->type == STATS_GAUGE);
    stm->value.counter += val;

    log_debug(LOG_VVVERB, "incr by field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_server_decr_by(struct context *ctx, struct server *server,
                      stats_server_field_t fidx, int64_t val)
{
    struct stats_metric *stm;

    stm = stats_server_to_metric(ctx, server, fidx);

    ASSERT(stm->type == STATS_GAUGE);
    stm->value.counter -= val;

    log_debug(LOG_VVVERB, "decr by field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_server_set_ts(struct context *ctx, struct server *server,
                     stats_server_field_t fidx, int64_t val)
{
    struct stats_metric *stm;

    stm = stats_server_to_metric(ctx, server, fidx);

    ASSERT(stm->type == STATS_TIMESTAMP);
    stm->value.timestamp = val;

    log_debug(LOG_VVVERB, "set ts field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.timestamp);
}

void
_stats_server_set(struct context *ctx, struct server *server,
                  stats_server_field_t fidx, int64_t val)
{
    struct stats_metric *stm;

    stm = stats_server_to_metric(ctx, server, fidx);

    ASSERT(stm->type == STATS_GAUGE);
    stm->value.counter = val;

    log_debug(LOG_VVVERB, "set gauge field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_pool_record_latency(struct context *ctx, struct server_pool *pool, int64_t latency)
{
    struct stats *st;
    struct stats_pool *stp;
    uint32_t ind;
    uint64_t *counter;

    st = ctx->stats;
    stp = array_get(&st->current, pool->idx);
    for (ind = 0; latency > latency_buckets[ind]; ind++);
    counter = array_get(&stp->latency, ind);
    *counter += 1;
}

void
_stats_server_record_latency(struct context *ctx, struct server *server, int64_t latency)
{
    struct stats *st;
    struct stats_pool *stp;
    struct stats_server *sts;
    uint32_t ind, pidx, sidx;
    uint64_t *counter;

    sidx = server->idx;
    pidx = server->owner->idx;
    st = ctx->stats;
    stp = array_get(&st->current, pidx);
    sts = array_get(&stp->server, sidx);
    for (ind = 0; latency > latency_buckets[ind]; ind++);
    counter = array_get(&sts->latency, ind);
    *counter += 1;
}

void
stats_show_read_hosts(struct array *server_pool)
{
    uint32_t i, j, npool, nserver;
    struct server_pool *sp;
    struct server *server;
    char buffer[32768];  /* 32KB buffer to handle many DNS addresses */
    rstatus_t status;

    if (server_pool == NULL) {
        log_stderr("read hosts: server_pool is NULL");
        return;
    }

    npool = array_n(server_pool);
    log_stderr("");
    log_stderr("read hosts configuration:");

    for (i = 0; i < npool; i++) {
        sp = array_get(server_pool, i);
        nserver = array_n(&sp->server);
        
        log_stderr("  pool '%.*s':", sp->name.len, sp->name.data);
        log_stderr("    zone_aware: %s", sp->zone_aware ? "enabled" : "disabled");
        if (sp->zone_aware) {
            log_stderr("    zone_weight: %"PRIu32"%%", sp->zone_weight);
        }
        log_stderr("    dns_resolve_interval: %"PRId64" seconds", sp->dns_resolve_interval / 1000000);

        for (j = 0; j < nserver; j++) {
            server = array_get(&sp->server, j);
            
            if (server->is_dynamic && server->dns != NULL) {
                status = server_get_read_hosts_info(server, "read_hosts", buffer, sizeof(buffer));
                if (status == NC_OK) {
                    log_stderr("    server '%.*s':", server->pname.len, server->pname.data);
                    log_stderr("      type: dynamic DNS");
                    log_stderr("      hostname: %.*s", server->dns->hostname.len, server->dns->hostname.data);
                    log_stderr("      resolved_addresses: %"PRIu32, server->dns->naddresses);
                    log_stderr("      current_address_index: %"PRIu32, server->current_addr_idx);
                    if (server->dns->naddresses > 0 && server->current_addr_idx < server->dns->naddresses) {
                        log_stderr("      current_latency: %"PRIu32" microseconds",
                                   server->dns->addrs[server->current_addr_idx].latency);
                        log_stderr("      current_failures: %"PRIu32,
                                   server->dns->addrs[server->current_addr_idx].failure_count);
                    }
                } else {
                    log_stderr("    server '%.*s': failed to get read host info", 
                               server->pname.len, server->pname.data);
                }
            } else {
                log_stderr("    server '%.*s': static configuration", 
                           server->pname.len, server->pname.data);
            }
        }
        log_stderr("");
    }
}

/*
 * Append a literal byte run to the stats buffer with a hard bound. The document
 * keeps a 1-byte tail (room = size - len - 1) so callers can never write the
 * final byte; if the run does not fit we report truncation (NC_ERROR) rather
 * than writing a short, silently-corrupt value.
 */
static rstatus_t
stats_buf_append(struct stats *st, const char *src, size_t srclen)
{
    struct stats_buffer *buf = &st->buf;
    size_t room;

    /* Keep a 1-byte tail (room = size - len - 1). Guard the subtraction so a
     * already-full buffer cannot underflow to a huge unsigned room. */
    if (buf->len + 1 > buf->size) {
        return NC_ERROR;
    }
    room = buf->size - buf->len - 1;

    if (srclen > room) {
        return NC_ERROR;
    }
    memcpy(buf->data + buf->len, src, srclen);
    buf->len += srclen;
    return NC_OK;
}

/* The placeholder emitted when a server has no resolvable DNS host info. */
static rstatus_t
stats_add_dns_hosts_null(struct stats *st)
{
    static const char null_kv[] = "\"dns_hosts\": null, ";
    return stats_buf_append(st, null_kv, sizeof(null_kv) - 1);
}

static rstatus_t
stats_add_dns_hosts(struct stats *st, struct string *server_name)
{
    rstatus_t status;
    struct server *server;
    uint32_t i, j, npool, nserver;
    char buffer[32768];  /* 32KB scratch for the (pretty-printed) DNS fragment */
    const char *frag;
    size_t frag_len;

    /* Find the server object by name */
    server = NULL;
    npool = array_n(&st->owner->pool);

    for (i = 0; i < npool && server == NULL; i++) {
        struct server_pool *pool = array_get(&st->owner->pool, i);
        nserver = array_n(&pool->server);

        for (j = 0; j < nserver; j++) {
            struct server *s = array_get(&pool->server, j);

            /* Check if server_name matches the beginning of s->pname (ignoring weight suffix) */
            if (server_name->len <= s->pname.len &&
                memcmp(server_name->data, s->pname.data, server_name->len) == 0 &&
                (server_name->len == s->pname.len || s->pname.data[server_name->len] == ':')) {
                server = s;
                break;
            }
        }
    }

    /* If server not found, not dynamic, or never resolved, emit a null object */
    if (server == NULL || !server->is_dynamic || server->dns == NULL) {
        return stats_add_dns_hosts_null(st);
    }

    /*
     * Build the fragment with its final JSON key ("dns_hosts") directly -- no
     * post-hoc string rewrite of a "read_hosts" key at a magic byte offset. The
     * helper writes a pretty-printed object "  \"dns_hosts\": { ... }" into the
     * scratch buffer and guarantees NUL-termination within sizeof(buffer); on
     * overflow it returns NC_ERROR (no silent truncation).
     */
    status = server_get_read_hosts_info(server, "dns_hosts", buffer, sizeof(buffer));
    if (status != NC_OK) {
        return stats_add_dns_hosts_null(st);
    }

    /*
     * Splice the fragment in as "<key>": <value>. The fragment begins with the
     * indent the pretty-printer added ("  \"dns_hosts\": ..."); skip that
     * leading ASCII whitespace so the document reads "\"dns_hosts\": {...".
     * Everything from the key onward is copied verbatim under a hard length
     * bound, then the document's "key: value, " separator is appended. A
     * fragment too large for the remaining room is reported as truncation, not
     * written short.
     */
    frag = buffer;
    while (*frag == ' ' || *frag == '\t' || *frag == '\n' || *frag == '\r') {
        frag++;
    }
    frag_len = strlen(frag);

    status = stats_buf_append(st, frag, frag_len);
    if (status != NC_OK) {
        log_warn("stats buffer too small for dns_hosts fragment (%zu bytes)", frag_len);
        return status;
    }
    return stats_buf_append(st, ", ", 2);
}
