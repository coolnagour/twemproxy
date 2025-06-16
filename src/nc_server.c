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

#include <stdlib.h>
#include <unistd.h>

#include <nc_core.h>
#include <nc_server.h>
#include <nc_conf.h>
#include <nc_client.h>

static void
server_resolve(struct server *server, struct conn *conn)
{
    rstatus_t status;
    
    /* Check for dynamic DNS updates if enabled */
    if (server->is_dynamic && server->dns != NULL) {
        status = server_dns_check_update(server);
        if (status != NC_OK) {
            log_warn("dynamic DNS check failed for server '%.*s'", 
                     server->pname.len, server->pname.data);
        }
        
        /* Select best address based on latency */
        uint32_t best_idx = server_select_best_address(server);
        if (best_idx < server->dns->naddresses) {
            server->current_addr_idx = best_idx;
            server->info = server->dns->addresses[best_idx];
        }
    } else {
        /* Use traditional single-address resolution */
        status = nc_resolve(&server->addrstr, server->port, &server->info);
        if (status != NC_OK) {
            conn->err = EHOSTDOWN;
            conn->done = 1;
            return;
        }
    }

    conn->family = server->info.family;
    conn->addrlen = server->info.addrlen;
    conn->addr = (struct sockaddr *)&server->info.addr;
}

void
server_ref(struct conn *conn, void *owner)
{
    struct server *server = owner;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->owner == NULL);

    server_resolve(server, conn);

    server->ns_conn_q++;
    TAILQ_INSERT_TAIL(&server->s_conn_q, conn, conn_tqe);

    conn->owner = owner;

    log_debug(LOG_VVERB, "ref conn %p owner %p into '%.*s", conn, server,
              server->pname.len, server->pname.data);
}

void
server_unref(struct conn *conn)
{
    struct server *server;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->owner != NULL);

    server = conn->owner;
    conn->owner = NULL;

    ASSERT(server->ns_conn_q != 0);
    server->ns_conn_q--;
    TAILQ_REMOVE(&server->s_conn_q, conn, conn_tqe);

    log_debug(LOG_VVERB, "unref conn %p owner %p from '%.*s'", conn, server,
              server->pname.len, server->pname.data);
}

int
server_timeout(struct conn *conn)
{
    struct server *server;
    struct server_pool *pool;

    ASSERT(!conn->client && !conn->proxy);

    server = conn->owner;
    pool = server->owner;

    return pool->timeout;
}

bool
server_active(struct conn *conn)
{
    ASSERT(!conn->client && !conn->proxy);

    if (!TAILQ_EMPTY(&conn->imsg_q)) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    if (!TAILQ_EMPTY(&conn->omsg_q)) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    if (conn->rmsg != NULL) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    if (conn->smsg != NULL) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    log_debug(LOG_VVERB, "s %d is inactive", conn->sd);

    return false;
}

static rstatus_t
server_each_set_owner(void *elem, void *data)
{
    struct server *s = elem;
    struct server_pool *sp = data;

    s->owner = sp;

    return NC_OK;
}

rstatus_t
server_init(struct array *server, struct array *conf_server,
            struct server_pool *sp)
{
    rstatus_t status;
    uint32_t nserver;

    nserver = array_n(conf_server);
    ASSERT(nserver != 0);
    ASSERT(array_n(server) == 0);

    status = array_init(server, nserver, sizeof(struct server));
    if (status != NC_OK) {
        return status;
    }

    /* transform conf server to server */
    status = array_each(conf_server, conf_server_each_transform, server);
    if (status != NC_OK) {
        server_deinit(server);
        return status;
    }
    ASSERT(array_n(server) == nserver);

    /* set server owner */
    status = array_each(server, server_each_set_owner, sp);
    if (status != NC_OK) {
        server_deinit(server);
        return status;
    }

    log_debug(LOG_DEBUG, "init %"PRIu32" servers in pool %"PRIu32" '%.*s'",
              nserver, sp->idx, sp->name.len, sp->name.data);

    return NC_OK;
}

void
server_deinit(struct array *server)
{
    uint32_t i, nserver;

    for (i = 0, nserver = array_n(server); i < nserver; i++) {
        struct server *s;

        s = array_pop(server);
        ASSERT(TAILQ_EMPTY(&s->s_conn_q) && s->ns_conn_q == 0);
        
        /* Clean up dynamic DNS data */
        if (s->dns != NULL) {
            server_dns_deinit(s);
        }
    }
    array_deinit(server);
}

struct conn *
server_conn(struct server *server)
{
    struct server_pool *pool;
    struct conn *conn;

    pool = server->owner;

    /*
     * FIXME: handle multiple server connections per server and do load
     * balancing on it. Support multiple algorithms for
     * 'server_connections:' > 0 key
     */

    if (server->ns_conn_q < pool->server_connections) {
        return conn_get(server, false, pool->redis);
    }
    ASSERT(server->ns_conn_q == pool->server_connections);

    /*
     * Pick a server connection from the head of the queue and insert
     * it back into the tail of queue to maintain the lru order
     */
    conn = TAILQ_FIRST(&server->s_conn_q);
    ASSERT(!conn->client && !conn->proxy);

    TAILQ_REMOVE(&server->s_conn_q, conn, conn_tqe);
    TAILQ_INSERT_TAIL(&server->s_conn_q, conn, conn_tqe);

    return conn;
}

static rstatus_t
server_each_preconnect(void *elem, void *data)
{
    rstatus_t status;
    struct server *server;
    struct server_pool *pool;
    struct conn *conn;

    server = elem;
    pool = server->owner;

    conn = server_conn(server);
    if (conn == NULL) {
        return NC_ENOMEM;
    }

    status = server_connect(pool->ctx, server, conn);
    if (status != NC_OK) {
        log_warn("connect to server '%.*s' failed, ignored: %s",
                 server->pname.len, server->pname.data, strerror(errno));
        server_close(pool->ctx, conn);
    }

    return NC_OK;
}

static rstatus_t
server_each_disconnect(void *elem, void *data)
{
    struct server *server;
    struct server_pool *pool;

    server = elem;
    pool = server->owner;

    while (!TAILQ_EMPTY(&server->s_conn_q)) {
        struct conn *conn;

        ASSERT(server->ns_conn_q > 0);

        conn = TAILQ_FIRST(&server->s_conn_q);
        event_del_conn(pool->ctx->evb, conn);
        conn->close(pool->ctx, conn);
    }

    return NC_OK;
}

static void
server_failure(struct context *ctx, struct server *server)
{
    struct server *master;
    struct server_pool *pool = server->owner;
    int64_t now, next;
    rstatus_t status;

    if (!pool->auto_eject_hosts) {
        return;
    }
    /* redis master can't be rejected */
    if (pool->redis && array_n(&pool->redis_master) > 0) {
        master = (struct server *) array_get(&pool->redis_master, 0);
        if (server == master) {
            return;
        }
    }

    server->failure_count++;

    /* Track per-address failures for dynamic DNS servers */
    if (server->is_dynamic && server->dns != NULL && 
        server->current_addr_idx < server->dns->naddresses) {
        server->dns->failure_counts[server->current_addr_idx]++;
        
        log_debug(LOG_VERB, "server '%.*s' addr %"PRIu32" failure count %"PRIu32,
                  server->pname.len, server->pname.data, 
                  server->current_addr_idx, 
                  server->dns->failure_counts[server->current_addr_idx]);
    }

    log_debug(LOG_VERB, "server '%.*s' failure count %"PRIu32" limit %"PRIu32,
              server->pname.len, server->pname.data, server->failure_count,
              pool->server_failure_limit);

    if (server->failure_count < pool->server_failure_limit) {
        return;
    }

    now = nc_usec_now();
    if (now < 0) {
        return;
    }

    stats_server_set_ts(ctx, server, server_ejected_at, now);

    next = now + pool->server_retry_timeout;

    log_debug(LOG_INFO, "update pool %"PRIu32" '%.*s' to delete server '%.*s' "
              "for next %"PRIu32" secs", pool->idx, pool->name.len,
              pool->name.data, server->pname.len, server->pname.data,
              pool->server_retry_timeout / 1000 / 1000);

    stats_pool_incr(ctx, pool, server_ejects);

    server->failure_count = 0;
    server->next_retry = next;

    status = server_pool_run(pool);
    if (status != NC_OK) {
        log_error("updating pool %"PRIu32" '%.*s' failed: %s", pool->idx,
                  pool->name.len, pool->name.data, strerror(errno));
    }
}

static void
server_close_stats(struct context *ctx, struct server *server, err_t err,
                   unsigned eof, unsigned connected)
{
    if (connected) {
        stats_server_decr(ctx, server, server_connections);
    }

    if (eof) {
        stats_server_incr(ctx, server, server_eof);
        return;
    }

    switch (err) {
    case ETIMEDOUT:
        stats_server_incr(ctx, server, server_timedout);
        break;
    case EPIPE:
    case ECONNRESET:
    case ECONNABORTED:
    case ECONNREFUSED:
    case ENOTCONN:
    case ENETDOWN:
    case ENETUNREACH:
    case EHOSTDOWN:
    case EHOSTUNREACH:
    default:
        stats_server_incr(ctx, server, server_err);
        break;
    }
}

void
server_close(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    struct msg *msg, *nmsg; /* current and next message */
    struct conn *c_conn;    /* peer client connection */

    ASSERT(!conn->client && !conn->proxy);

    server_close_stats(ctx, conn->owner, conn->err, conn->eof,
                       conn->connected);

    conn->connected = false;

    if (conn->sd < 0) {
        server_failure(ctx, conn->owner);
        conn->unref(conn);
        conn_put(conn);
        return;
    }

    for (msg = TAILQ_FIRST(&conn->imsg_q); msg != NULL; msg = nmsg) {
        nmsg = TAILQ_NEXT(msg, s_tqe);

        /* dequeue the message (request) from server inq */
        conn->dequeue_inq(ctx, conn, msg);

        /*
         * Don't send any error response, if
         * 1. request is tagged as noreply or,
         * 2. client has already closed its connection
         */
        if (msg->swallow || msg->noreply) {
            log_debug(LOG_INFO, "close s %d swallow req %"PRIu64" len %"PRIu32
                      " type %d", conn->sd, msg->id, msg->mlen, msg->type);
            req_put(msg);
        } else {
            c_conn = msg->owner;
            ASSERT(c_conn->client && !c_conn->proxy);

            msg->done = 1;
            msg->error = 1;
            msg->err = conn->err;

            if (msg->frag_owner != NULL) {
                msg->frag_owner->nfrag_done++;
            }

            if (req_done(c_conn, TAILQ_FIRST(&c_conn->omsg_q))) {
                event_add_out(ctx->evb, msg->owner);
            }

            log_debug(LOG_INFO, "close s %d schedule error for req %"PRIu64" "
                      "len %"PRIu32" type %d from c %d%c %s", conn->sd, msg->id,
                      msg->mlen, msg->type, c_conn->sd, conn->err ? ':' : ' ',
                      conn->err ? strerror(conn->err): " ");
        }
    }
    ASSERT(TAILQ_EMPTY(&conn->imsg_q));

    for (msg = TAILQ_FIRST(&conn->omsg_q); msg != NULL; msg = nmsg) {
        nmsg = TAILQ_NEXT(msg, s_tqe);

        /* dequeue the message (request) from server outq */
        conn->dequeue_outq(ctx, conn, msg);

        if (msg->swallow) {
            log_debug(LOG_INFO, "close s %d swallow req %"PRIu64" len %"PRIu32
                      " type %d", conn->sd, msg->id, msg->mlen, msg->type);
            req_put(msg);
        } else {
            c_conn = msg->owner;
            ASSERT(c_conn->client && !c_conn->proxy);

            msg->done = 1;
            msg->error = 1;
            msg->err = conn->err;
            if (msg->frag_owner != NULL) {
                msg->frag_owner->nfrag_done++;
            }

            if (req_done(c_conn, TAILQ_FIRST(&c_conn->omsg_q))) {
                event_add_out(ctx->evb, msg->owner);
            }

            log_debug(LOG_INFO, "close s %d schedule error for req %"PRIu64" "
                      "len %"PRIu32" type %d from c %d%c %s", conn->sd, msg->id,
                      msg->mlen, msg->type, c_conn->sd, conn->err ? ':' : ' ',
                      conn->err ? strerror(conn->err): " ");
        }
    }
    ASSERT(TAILQ_EMPTY(&conn->omsg_q));

    msg = conn->rmsg;
    if (msg != NULL) {
        conn->rmsg = NULL;

        ASSERT(!msg->request);
        ASSERT(msg->peer == NULL);

        rsp_put(msg);

        log_debug(LOG_INFO, "close s %d discarding rsp %"PRIu64" len %"PRIu32" "
                  "in error", conn->sd, msg->id, msg->mlen);
    }

    ASSERT(conn->smsg == NULL);

    server_failure(ctx, conn->owner);

    conn->unref(conn);

    status = close(conn->sd);
    if (status < 0) {
        log_error("close s %d failed, ignored: %s", conn->sd, strerror(errno));
    }
    conn->sd = -1;

    conn_put(conn);
}

rstatus_t
server_connect(struct context *ctx, struct server *server, struct conn *conn)
{
    rstatus_t status;

    ASSERT(!conn->client && !conn->proxy);

    if (conn->err) {
      ASSERT(conn->done && conn->sd < 0);
      errno = conn->err;
      return NC_ERROR;
    }

    if (conn->sd > 0) {
        /* already connected on server connection */
        return NC_OK;
    }

    log_debug(LOG_VVERB, "connect to server '%.*s'", server->pname.len,
              server->pname.data);

    conn->sd = socket(conn->family, SOCK_STREAM, 0);
    if (conn->sd < 0) {
        log_error("socket for server '%.*s' failed: %s", server->pname.len,
                  server->pname.data, strerror(errno));
        status = NC_ERROR;
        goto error;
    }

    status = nc_set_nonblocking(conn->sd);
    if (status != NC_OK) {
        log_error("set nonblock on s %d for server '%.*s' failed: %s",
                  conn->sd, server->pname.len, server->pname.data,
                  strerror(errno));
        goto error;
    }

    if (server->pname.data[0] != '/') {
        status = nc_set_tcpnodelay(conn->sd);
        if (status != NC_OK) {
            log_warn("set tcpnodelay on s %d for server '%.*s' failed, ignored: %s",
                     conn->sd, server->pname.len, server->pname.data,
                     strerror(errno));
        }
    }

    status = event_add_conn(ctx->evb, conn);
    if (status != NC_OK) {
        log_error("event add conn s %d for server '%.*s' failed: %s",
                  conn->sd, server->pname.len, server->pname.data,
                  strerror(errno));
        goto error;
    }

    ASSERT(!conn->connecting && !conn->connected);

    /* Record connection start time for latency measurement */
    conn->connect_start_ts = nc_usec_now();

    status = connect(conn->sd, conn->addr, conn->addrlen);
    if (status != NC_OK) {
        if (errno == EINPROGRESS) {
            conn->connecting = 1;
            log_debug(LOG_DEBUG, "connecting on s %d to server '%.*s'",
                      conn->sd, server->pname.len, server->pname.data);
            return NC_OK;
        }

        event_del_conn(ctx->evb, conn);
        log_error("connect on s %d to server '%.*s' failed: %s", conn->sd,
                  server->pname.len, server->pname.data, strerror(errno));

        goto error;
    }

    ASSERT(!conn->connecting);
    conn->connected = 1;
    
    /* Measure connection latency for immediate connections */
    if (server->is_dynamic && server->dns != NULL && conn->connect_start_ts > 0) {
        int64_t latency = nc_usec_now() - conn->connect_start_ts;
        if (latency > 0) {
            server_measure_latency(server, server->current_addr_idx, latency);
        }
    }
    
    log_debug(LOG_INFO, "connected on s %d to server '%.*s'", conn->sd,
              server->pname.len, server->pname.data);

    return NC_OK;

error:
    conn->err = errno;
    return status;
}

void
server_connected(struct context *ctx, struct conn *conn)
{
    struct server *server = conn->owner;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->connecting && !conn->connected);

    stats_server_incr(ctx, server, server_connections);

    conn->connecting = 0;
    conn->connected = 1;

    /* Measure connection latency for async connections */
    if (server->is_dynamic && server->dns != NULL && conn->connect_start_ts > 0) {
        int64_t latency = nc_usec_now() - conn->connect_start_ts;
        if (latency > 0) {
            server_measure_latency(server, server->current_addr_idx, latency);
        }
    }

    conn->post_connect(ctx, conn, server);

    log_debug(LOG_INFO, "connected on s %d to server '%.*s'", conn->sd,
              server->pname.len, server->pname.data);
}

void
server_ok(struct context *ctx, struct conn *conn)
{
    struct server *server = conn->owner;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->connected);

    if (server->failure_count != 0) {
        log_debug(LOG_VERB, "reset server '%.*s' failure count from %"PRIu32
                  " to 0", server->pname.len, server->pname.data,
                  server->failure_count);
        server->failure_count = 0;
        server->next_retry = 0LL;
    }
}

static rstatus_t
server_pool_update(struct server_pool *pool)
{
    rstatus_t status;
    int64_t now;
    uint32_t pnlive_server; /* prev # live server */
    uint32_t i, nserver;

    if (!pool->auto_eject_hosts) {
        return NC_OK;
    }

    if (pool->next_rebuild == 0LL) {
        return NC_OK;
    }

    now = nc_usec_now();
    if (now < 0) {
        return NC_ERROR;
    }

    /* Check for dynamic DNS updates on all servers */
    nserver = array_n(&pool->server);
    for (i = 0; i < nserver; i++) {
        struct server *server;
        
        server = array_get(&pool->server, i);
        if (server->is_dynamic && server_should_resolve_dns(server)) {
            status = server_dns_check_update(server);
            if (status != NC_OK) {
                log_warn("DNS update failed for server '%.*s'",
                         server->pname.len, server->pname.data);
            }
        }
    }

    if (now <= pool->next_rebuild) {
        if (pool->nlive_server == 0) {
            errno = ECONNREFUSED;
            return NC_ERROR;
        }
        return NC_OK;
    }

    pnlive_server = pool->nlive_server;

    status = server_pool_run(pool);
    if (status != NC_OK) {
        log_error("updating pool %"PRIu32" with dist %d failed: %s", pool->idx,
                  pool->dist_type, strerror(errno));
        return status;
    }

    log_debug(LOG_INFO, "update pool %"PRIu32" '%.*s' to add %"PRIu32" servers",
              pool->idx, pool->name.len, pool->name.data,
              pool->nlive_server - pnlive_server);


    return NC_OK;
}

static uint32_t
server_pool_hash(struct server_pool *pool, uint8_t *key, uint32_t keylen)
{
    ASSERT(array_n(&pool->server) != 0);
    ASSERT(key != NULL);

    if (array_n(&pool->server) == 1) {
        return 0;
    }

    if (keylen == 0) {
        return 0;
    }

    return pool->key_hash((char *)key, keylen);
}

uint32_t
server_pool_idx(struct server_pool *pool, uint8_t *key, uint32_t keylen)
{
    uint32_t hash, idx;

    ASSERT(array_n(&pool->server) != 0);
    ASSERT(key != NULL);

    /*
     * If hash_tag: is configured for this server pool, we use the part of
     * the key within the hash tag as an input to the distributor. Otherwise
     * we use the full key
     */
    if (!string_empty(&pool->hash_tag)) {
        struct string *tag = &pool->hash_tag;
        uint8_t *tag_start, *tag_end;

        tag_start = nc_strchr(key, key + keylen, tag->data[0]);
        if (tag_start != NULL) {
            tag_end = nc_strchr(tag_start + 1, key + keylen, tag->data[1]);
            if ((tag_end != NULL) && (tag_end - tag_start > 1)) {
                key = tag_start + 1;
                keylen = (uint32_t)(tag_end - key);
            }
        }
    }

    switch (pool->dist_type) {
    case DIST_KETAMA:
        hash = server_pool_hash(pool, key, keylen);
        idx = ketama_dispatch(pool->continuum, pool->ncontinuum, hash);
        break;

    case DIST_MODULA:
        hash = server_pool_hash(pool, key, keylen);
        idx = modula_dispatch(pool->continuum, pool->ncontinuum, hash);
        break;

    case DIST_RANDOM:
        idx = random_dispatch(pool->continuum, pool->ncontinuum, 0);
        break;

    default:
        NOT_REACHED();
        return 0;
    }
    ASSERT(idx < array_n(&pool->server));
    return idx;
}

static struct server *
server_pool_server(struct server_pool *pool, uint8_t *key, uint32_t keylen)
{
    struct server *server;
    uint32_t idx;

    idx = server_pool_idx(pool, key, keylen);
    server = array_get(&pool->server, idx);

    log_debug(LOG_VERB, "key '%.*s' on dist %d maps to server '%.*s'", keylen,
              key, pool->dist_type, server->pname.len, server->pname.data);

    return server;
}

struct conn *
server_get_conn(struct context *ctx, struct server *srv)
{
    struct conn *conn;
    rstatus_t status;

    /* pick a connection to a given server */
    conn = server_conn(srv);
    if (conn == NULL) {
        return NULL;
    }

    status = server_connect(ctx, srv, conn);
    if (status != NC_OK) {
        server_close(ctx, conn);
        return NULL;
    }

    return conn;
}

struct conn *
server_pool_conn(struct context *ctx, struct server_pool *pool, uint8_t *key,
                 uint32_t keylen)
{
    rstatus_t status;
    struct server *server;

    status = server_pool_update(pool);
    if (status != NC_OK) {
        return NULL;
    }

    /* from a given {key, keylen} pick a server from pool */
    server = server_pool_server(pool, key, keylen);
    if (server == NULL) {
        return NULL;
    }
    return server_get_conn(ctx, server);
}

static rstatus_t
server_pool_each_preconnect(void *elem, void *data)
{
    rstatus_t status;
    struct server_pool *sp = elem;

    if (!sp->preconnect) {
        return NC_OK;
    }

    if (array_n(&sp->redis_master) > 0) {
        status = array_each(&sp->redis_master, server_each_preconnect, NULL);
        if (status != NC_OK) {
            return status;
        }
    }
    status = array_each(&sp->server, server_each_preconnect, NULL);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

rstatus_t
server_pool_preconnect(struct context *ctx)
{
    rstatus_t status;

    status = array_each(&ctx->pool, server_pool_each_preconnect, NULL);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

static rstatus_t
server_pool_each_disconnect(void *elem, void *data)
{
    rstatus_t status;
    struct server_pool *sp = elem;

    status = array_each(&sp->server, server_each_disconnect, NULL);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

void
server_pool_disconnect(struct context *ctx)
{
    array_each(&ctx->pool, server_pool_each_disconnect, NULL);
}

static rstatus_t
server_pool_each_set_owner(void *elem, void *data)
{
    struct server_pool *sp = elem;
    struct context *ctx = data;

    sp->ctx = ctx;

    return NC_OK;
}

static rstatus_t
server_pool_each_calc_connections(void *elem, void *data)
{
    struct server_pool *sp = elem;
    struct context *ctx = data;

    ctx->max_nsconn += sp->server_connections * array_n(&sp->server);
    ctx->max_nsconn += 1; /* pool listening socket */

    return NC_OK;
}

rstatus_t
server_pool_run(struct server_pool *pool)
{
    ASSERT(array_n(&pool->server) != 0);

    switch (pool->dist_type) {
    case DIST_KETAMA:
        return ketama_update(pool);

    case DIST_MODULA:
        return modula_update(pool);

    case DIST_RANDOM:
        return random_update(pool);

    default:
        NOT_REACHED();
        return NC_ERROR;
    }

    return NC_OK;
}

static rstatus_t
server_pool_each_run(void *elem, void *data)
{
    return server_pool_run(elem);
}

rstatus_t
server_pool_init(struct array *server_pool, struct array *conf_pool,
                 struct context *ctx)
{
    rstatus_t status;
    uint32_t npool;

    npool = array_n(conf_pool);
    ASSERT(npool != 0);
    ASSERT(array_n(server_pool) == 0);

    status = array_init(server_pool, npool, sizeof(struct server_pool));
    if (status != NC_OK) {
        return status;
    }

    /* transform conf pool to server pool */
    status = array_each(conf_pool, conf_pool_each_transform, server_pool);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }
    ASSERT(array_n(server_pool) == npool);

    /* set ctx as the server pool owner */
    status = array_each(server_pool, server_pool_each_set_owner, ctx);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    /* compute max server connections */
    ctx->max_nsconn = 0;
    status = array_each(server_pool, server_pool_each_calc_connections, ctx);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    /* update server pool continuum */
    status = array_each(server_pool, server_pool_each_run, NULL);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    log_debug(LOG_DEBUG, "init %"PRIu32" pools", npool);

    return NC_OK;
}

static void
server_pool_clients_disconnect(struct server_pool *sp)
{
    struct conn *conn, *nconn; /* current and next connection */

    if (sp == NULL || TAILQ_EMPTY(&sp->c_conn_q) || sp->nc_conn_q == 0) {
        return;
    }
    for (conn = TAILQ_FIRST(&sp->c_conn_q); conn != NULL;
         conn = nconn) {
        ASSERT(sp->nc_conn_q > 0);
        nconn = TAILQ_NEXT(conn, conn_tqe);
        client_close(sp->ctx, conn);
    }
    ASSERT(sp->nc_conn_q == 0);
}

void
server_pool_deinit(struct array *server_pool)
{
    uint32_t i, npool;

    for (i = 0, npool = array_n(server_pool); i < npool; i++) {
        struct server_pool *sp;

        sp = array_pop(server_pool);
        server_pool_clients_disconnect(sp);

        ASSERT(sp->p_conn == NULL);
        ASSERT(TAILQ_EMPTY(&sp->c_conn_q) && sp->nc_conn_q == 0);

        if (sp->continuum != NULL) {
            nc_free(sp->continuum);
            sp->ncontinuum = 0;
            sp->nserver_continuum = 0;
            sp->nlive_server = 0;
        }

        server_deinit(&sp->server);

        log_debug(LOG_DEBUG, "deinit pool %"PRIu32" '%.*s'", sp->idx,
                  sp->name.len, sp->name.data);
    }

    array_deinit(server_pool);

    log_debug(LOG_DEBUG, "deinit %"PRIu32" pools", npool);
}

/* 
 * Dynamic DNS and latency-based server selection implementation
 */

#define DNS_RESOLVE_INTERVAL_USEC    (30 * 1000000)  /* 30 seconds */
#define LATENCY_CHECK_INTERVAL_USEC  (5 * 1000000)   /* 5 seconds */
#define MAX_ADDRESSES_PER_SERVER     16
#define DEFAULT_LATENCY_USEC         (100 * 1000)    /* 100ms default */

rstatus_t
server_dns_init(struct server *server)
{
    struct server_dns *dns;
    struct server_pool *pool;
    
    ASSERT(server != NULL);
    
    if (server->dns != NULL) {
        return NC_OK; /* Already initialized */
    }
    
    dns = nc_alloc(sizeof(struct server_dns));
    if (dns == NULL) {
        return NC_ENOMEM;
    }
    
    pool = server->owner;
    
    /* Initialize DNS structure */
    string_init(&dns->hostname);
    dns->addresses = NULL;
    dns->naddresses = 0;
    dns->max_addresses = MAX_ADDRESSES_PER_SERVER;
    dns->last_resolved = 0;
    
    /* Use pool configuration or defaults */
    if (pool != NULL && pool->dns_resolve_interval > 0) {
        dns->resolve_interval = pool->dns_resolve_interval;
    } else {
        dns->resolve_interval = DNS_RESOLVE_INTERVAL_USEC;
    }
    
    dns->latencies = NULL;
    dns->last_latency_check = NULL;
    dns->failure_counts = NULL;
    dns->last_seen = NULL;
    dns->hostnames = NULL;
    
    /* Enhanced health and zone initialization */
    dns->health_scores = NULL;
    dns->last_health_check = NULL;
    dns->health_check_interval = pool ? pool->dns_health_check_interval : 30000000LL; /* use pool config or 30 seconds default */
    dns->consecutive_failures_limit = pool ? pool->dns_failure_threshold : 3;
    dns->zone_ids = NULL;
    dns->local_zone_id = 0;
    dns->next_zone_id = 1;
    dns->last_zone_analysis = 0;
    
    /* Copy hostname */
    rstatus_t status = string_copy(&dns->hostname, server->addrstr.data, server->addrstr.len);
    if (status != NC_OK) {
        nc_free(dns);
        return status;
    }
    
    server->dns = dns;
    server->current_addr_idx = 0;
    
    log_debug(LOG_VERB, "initialized dynamic DNS for server '%.*s' (resolve_interval: %"PRId64"s)", 
              server->pname.len, server->pname.data, dns->resolve_interval / 1000000);
    
    /* Perform initial DNS resolution */
    log_warn("🔍 performing initial DNS resolution for '%.*s'", 
              server->pname.len, server->pname.data);
    
    status = server_dns_resolve(server);
    if (status != NC_OK) {
        log_warn("initial DNS resolution failed for server '%.*s', will retry later",
                 server->pname.len, server->pname.data);
        /* Don't fail initialization - we'll retry on first connection */
    } else {
        log_warn("✅ initial DNS resolution successful for '%.*s' - found %"PRIu32" addresses", 
                  server->pname.len, server->pname.data, dns->naddresses);
        
        /* Zone detection will happen later after we have real latency measurements */
    }
    
    return NC_OK;
}

void
server_dns_deinit(struct server *server)
{
    struct server_dns *dns;
    
    ASSERT(server != NULL);
    
    dns = server->dns;
    if (dns == NULL) {
        return;
    }
    
    /* Free allocated memory */
    if (dns->addresses != NULL) {
        nc_free(dns->addresses);
    }
    
    if (dns->latencies != NULL) {
        nc_free(dns->latencies);
    }
    
    if (dns->last_latency_check != NULL) {
        nc_free(dns->last_latency_check);
    }
    
    if (dns->failure_counts != NULL) {
        nc_free(dns->failure_counts);
    }
    
    if (dns->last_seen != NULL) {
        nc_free(dns->last_seen);
    }
    
    if (dns->hostnames != NULL) {
        /* Free individual hostname strings */
        for (uint32_t i = 0; i < dns->naddresses; i++) {
            if (dns->hostnames[i].data != NULL) {
                string_deinit(&dns->hostnames[i]);
            }
        }
        nc_free(dns->hostnames);
    }
    
    /* Enhanced health and zone cleanup */
    if (dns->health_scores != NULL) {
        nc_free(dns->health_scores);
    }
    
    if (dns->last_health_check != NULL) {
        nc_free(dns->last_health_check);
    }
    
    if (dns->zone_ids != NULL) {
        nc_free(dns->zone_ids);
    }
    
    string_deinit(&dns->hostname);
    nc_free(dns);
    server->dns = NULL;
    
    log_debug(LOG_VERB, "deinitialized dynamic DNS for server '%.*s'",
              server->pname.len, server->pname.data);
}

rstatus_t
server_dns_resolve(struct server *server)
{
    struct server_dns *dns;
    struct server_pool *pool;
    rstatus_t status;
    uint32_t i, j;
    struct sockinfo *new_addresses = NULL;
    uint32_t new_naddresses = 0;
    int64_t now = nc_usec_now();
    int64_t expiration_threshold;
    
    ASSERT(server != NULL && server->dns != NULL);
    
    dns = server->dns;
    pool = server->owner;
    
    /* Calculate expiration threshold */
    expiration_threshold = pool ? pool->dns_expiration_minutes : (5 * 60000000LL); /* 5 minutes default */
    
    /* Resolve new addresses from DNS */
    if (server->owner != NULL && server->owner->ctx != NULL) {
        stats_server_incr(server->owner->ctx, server, dns_resolves);
    }
    
    status = nc_resolve_multi(&dns->hostname, server->port, &new_addresses, 
                              &new_naddresses, dns->max_addresses);
    if (status != NC_OK) {
        if (server->owner != NULL && server->owner->ctx != NULL) {
            stats_server_incr(server->owner->ctx, server, dns_failures);
        }
        log_error("failed to resolve '%.*s': %s", 
                  dns->hostname.len, dns->hostname.data, strerror(errno));
        return status;
    }
    
    log_warn("DNS resolved '%.*s' to %"PRIu32" new addresses",
              dns->hostname.len, dns->hostname.data, new_naddresses);
    
    /* If this is the first resolution, just use the new addresses */
    if (dns->addresses == NULL || dns->naddresses == 0) {
        dns->addresses = new_addresses;
        dns->naddresses = new_naddresses;
        
        /* Allocate tracking arrays */
        dns->latencies = nc_alloc(dns->naddresses * sizeof(uint32_t));
        dns->last_latency_check = nc_alloc(dns->naddresses * sizeof(int64_t));
        dns->failure_counts = nc_alloc(dns->naddresses * sizeof(uint32_t));
        dns->last_seen = nc_alloc(dns->naddresses * sizeof(int64_t));
        dns->hostnames = nc_alloc(dns->naddresses * sizeof(struct string));
        
        if (dns->latencies == NULL || dns->last_latency_check == NULL || 
            dns->failure_counts == NULL || dns->last_seen == NULL || dns->hostnames == NULL) {
            return NC_ENOMEM;
        }
        
        /* Initialize data for all addresses */
        for (i = 0; i < dns->naddresses; i++) {
            dns->latencies[i] = DEFAULT_LATENCY_USEC;
            dns->last_latency_check[i] = 0;
            dns->failure_counts[i] = 0;
            dns->last_seen[i] = now;
            
            /* Initialize hostname with reverse DNS lookup */
            string_init(&dns->hostnames[i]);
            server_reverse_dns_lookup(server, i);
        }
        
        dns->last_resolved = now;
        log_warn("initialized with %"PRIu32" addresses for '%.*s'",
                  dns->naddresses, dns->hostname.len, dns->hostname.data);
        return NC_OK;
    }
    
    /* Accumulative DNS resolution: merge new addresses with existing ones */
    
    /* First, mark existing addresses that are still in the new response */
    for (i = 0; i < new_naddresses; i++) {
        bool found = false;
        for (j = 0; j < dns->naddresses; j++) {
            /* Compare IP addresses properly based on address family */
            struct sockaddr *existing_addr = (struct sockaddr *)&dns->addresses[j].addr;
            struct sockaddr *new_addr = (struct sockaddr *)&new_addresses[i].addr;
            
            if (existing_addr->sa_family == new_addr->sa_family) {
                bool addresses_match = false;
                
                if (existing_addr->sa_family == AF_INET) {
                    struct sockaddr_in *existing_in = (struct sockaddr_in *)existing_addr;
                    struct sockaddr_in *new_in = (struct sockaddr_in *)new_addr;
                    addresses_match = (existing_in->sin_addr.s_addr == new_in->sin_addr.s_addr &&
                                     existing_in->sin_port == new_in->sin_port);
                } else if (existing_addr->sa_family == AF_INET6) {
                    struct sockaddr_in6 *existing_in6 = (struct sockaddr_in6 *)existing_addr;
                    struct sockaddr_in6 *new_in6 = (struct sockaddr_in6 *)new_addr;
                    addresses_match = (memcmp(&existing_in6->sin6_addr, &new_in6->sin6_addr, 
                                            sizeof(existing_in6->sin6_addr)) == 0 &&
                                     existing_in6->sin6_port == new_in6->sin6_port);
                }
                
                if (addresses_match) {
                    /* Address still exists, update last_seen */
                    dns->last_seen[j] = now;
                    found = true;
                    
                    char addr_str[INET6_ADDRSTRLEN];
                    if (existing_addr->sa_family == AF_INET) {
                        struct sockaddr_in *addr_in = (struct sockaddr_in *)existing_addr;
                        inet_ntop(AF_INET, &addr_in->sin_addr, addr_str, sizeof(addr_str));
                    } else if (existing_addr->sa_family == AF_INET6) {
                        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)existing_addr;
                        inet_ntop(AF_INET6, &addr_in6->sin6_addr, addr_str, sizeof(addr_str));
                    } else {
                        strcpy(addr_str, "unknown");
                    }
                    log_debug(LOG_VERB, "found existing address %s at index %"PRIu32" for '%.*s'", 
                             addr_str, j, dns->hostname.len, dns->hostname.data);
                    
                    break;
                }
            }
        }
        
        if (!found) {
            /* This is a new address, add it to our list */
            /* Reallocate arrays to accommodate new address */
            uint32_t new_size = dns->naddresses + 1;
            
            struct sockinfo *new_addr_array = nc_realloc(dns->addresses, new_size * sizeof(struct sockinfo));
            uint32_t *new_latencies = nc_realloc(dns->latencies, new_size * sizeof(uint32_t));
            int64_t *new_last_latency_check = nc_realloc(dns->last_latency_check, new_size * sizeof(int64_t));
            uint32_t *new_failure_counts = nc_realloc(dns->failure_counts, new_size * sizeof(uint32_t));
            int64_t *new_last_seen = nc_realloc(dns->last_seen, new_size * sizeof(int64_t));
            struct string *new_hostnames = nc_realloc(dns->hostnames, new_size * sizeof(struct string));
            
            if (new_addr_array == NULL || new_latencies == NULL || 
                new_last_latency_check == NULL || new_failure_counts == NULL ||
                new_last_seen == NULL || new_hostnames == NULL) {
                log_error("failed to allocate memory for new DNS address");
                if (new_addresses) nc_free(new_addresses);
                return NC_ENOMEM;
            }
            
            dns->addresses = new_addr_array;
            dns->latencies = new_latencies;
            dns->last_latency_check = new_last_latency_check;
            dns->failure_counts = new_failure_counts;
            dns->last_seen = new_last_seen;
            dns->hostnames = new_hostnames;
            
            /* Add the new address */
            memcpy(&dns->addresses[dns->naddresses], &new_addresses[i], sizeof(struct sockinfo));
            dns->latencies[dns->naddresses] = DEFAULT_LATENCY_USEC;
            dns->last_latency_check[dns->naddresses] = 0;
            dns->failure_counts[dns->naddresses] = 0;
            dns->last_seen[dns->naddresses] = now;
            
            /* Initialize hostname for new address */
            string_init(&dns->hostnames[dns->naddresses]);
            server_reverse_dns_lookup(server, dns->naddresses);
            
            dns->naddresses++;
            
            char addr_str[INET6_ADDRSTRLEN];
            struct sockaddr *addr = (struct sockaddr *)&new_addresses[i].addr;
            if (addr->sa_family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
                inet_ntop(AF_INET, &addr_in->sin_addr, addr_str, sizeof(addr_str));
            } else if (addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
                inet_ntop(AF_INET6, &addr_in6->sin6_addr, addr_str, sizeof(addr_str));
            } else {
                strcpy(addr_str, "unknown");
            }
            log_warn("added new address %s for '%.*s' (total addresses: %"PRIu32")", 
                     addr_str, dns->hostname.len, dns->hostname.data, dns->naddresses);
        }
    }
    
    /* Now expire old addresses that haven't been seen recently */
    uint32_t removed_count = 0;
    for (i = 0; i < dns->naddresses; ) {
        int64_t time_since_seen = now - dns->last_seen[i];
        bool should_expire = false;
        
        /* Expire address if it hasn't been seen in DNS for expiration_threshold time */
        /* For currently active address (current_addr_idx), also require failure threshold */
        /* For inactive addresses, just time-based expiration is sufficient */
        if (time_since_seen > expiration_threshold) {
            if (i == server->current_addr_idx) {
                /* Current address: require both time and failure thresholds */
                should_expire = (dns->failure_counts[i] > (pool ? pool->dns_failure_threshold : 3));
            } else {
                /* Non-current address: time-based expiration only */
                should_expire = true;
            }
        }
        
        if (should_expire) {
            
            char addr_str[INET6_ADDRSTRLEN];
            struct sockaddr *addr = (struct sockaddr *)&dns->addresses[i].addr;
            if (addr->sa_family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
                inet_ntop(AF_INET, &addr_in->sin_addr, addr_str, sizeof(addr_str));
            } else {
                strcpy(addr_str, "unknown");
            }
            
            if (i == server->current_addr_idx) {
                log_warn("expiring current address %s for '%.*s' (not seen for %"PRId64"s, %"PRIu32" failures > threshold)",
                         addr_str, dns->hostname.len, dns->hostname.data, 
                         time_since_seen / 1000000, dns->failure_counts[i]);
            } else {
                log_warn("expiring inactive address %s for '%.*s' (not seen for %"PRId64"s)",
                         addr_str, dns->hostname.len, dns->hostname.data, 
                         time_since_seen / 1000000);
            }
            
            /* Clean up hostname for removed address */
            if (dns->hostnames[i].data != NULL) {
                string_deinit(&dns->hostnames[i]);
            }
            
            /* Remove this address by shifting everything down */
            for (j = i; j < dns->naddresses - 1; j++) {
                memcpy(&dns->addresses[j], &dns->addresses[j + 1], sizeof(struct sockinfo));
                dns->latencies[j] = dns->latencies[j + 1];
                dns->last_latency_check[j] = dns->last_latency_check[j + 1];
                dns->failure_counts[j] = dns->failure_counts[j + 1];
                dns->last_seen[j] = dns->last_seen[j + 1];
                dns->hostnames[j] = dns->hostnames[j + 1]; /* Move string structure */
            }
            dns->naddresses--;
            removed_count++;
            /* Don't increment i since we shifted everything down */
        } else {
            i++;
        }
    }
    
    if (removed_count > 0) {
        log_warn("expired %"PRIu32" addresses for '%.*s', %"PRIu32" addresses remaining",
                 removed_count, dns->hostname.len, dns->hostname.data, dns->naddresses);
    }
    
    /* Free the temporary new_addresses array */
    if (new_addresses) {
        nc_free(new_addresses);
    }
    
    dns->last_resolved = now;
    
    /* Update DNS stats */
    if (server->owner != NULL && server->owner->ctx != NULL) {
        stats_server_set_ts(server->owner->ctx, server, last_dns_resolved_at, dns->last_resolved);
        stats_server_set(server->owner->ctx, server, dns_addresses, dns->naddresses);
    }
    
    log_warn("DNS resolution complete for '%.*s': %"PRIu32" total addresses",
              dns->hostname.len, dns->hostname.data, dns->naddresses);
    
    return NC_OK;
}

rstatus_t
server_dns_check_update(struct server *server)
{
    struct server_dns *dns;
    int64_t now;
    
    ASSERT(server != NULL);
    
    dns = server->dns;
    if (dns == NULL) {
        return NC_ERROR;
    }
    
    now = nc_usec_now();
    if (now < 0) {
        return NC_ERROR;
    }
    
    /* Check if we need to re-resolve DNS */
    if (dns->last_resolved == 0 || 
        (now - dns->last_resolved) > dns->resolve_interval) {
        return server_dns_resolve(server);
    }
    
    return NC_OK;
}

rstatus_t
server_reverse_dns_lookup(struct server *server, uint32_t addr_idx)
{
    struct server_dns *dns;
    struct sockaddr *addr;
    char hostname[NI_MAXHOST];
    int status;
    
    ASSERT(server != NULL);
    
    dns = server->dns;
    if (dns == NULL || addr_idx >= dns->naddresses) {
        return NC_ERROR;
    }
    
    addr = (struct sockaddr *)&dns->addresses[addr_idx].addr;
    
    /* Perform reverse DNS lookup */
    status = getnameinfo(addr, dns->addresses[addr_idx].addrlen, 
                        hostname, sizeof(hostname), 
                        NULL, 0, NI_NAMEREQD);
                        
    if (status == 0) {
        /* Successfully got hostname */
        rstatus_t str_status = string_copy(&dns->hostnames[addr_idx], hostname, strlen(hostname));
        if (str_status == NC_OK) {
            log_debug(LOG_VERB, "reverse DNS for addr %"PRIu32": %s", addr_idx, hostname);
        }
        return str_status;
    } else {
        /* Reverse DNS failed, use IP address as fallback */
        char addr_str[INET6_ADDRSTRLEN];
        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &addr_in->sin_addr, addr_str, sizeof(addr_str));
        } else if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, addr_str, sizeof(addr_str));
        } else {
            strcpy(addr_str, "unknown");
        }
        
        rstatus_t str_status = string_copy(&dns->hostnames[addr_idx], addr_str, strlen(addr_str));
        log_debug(LOG_VERB, "reverse DNS failed for addr %"PRIu32", using IP: %s", addr_idx, addr_str);
        return str_status;
    }
}

uint32_t
server_select_best_address(struct server *server)
{
    struct server_dns *dns;
    struct server_pool *pool;
    uint32_t i, best_idx = 0;
    uint32_t best_latency = UINT32_MAX;
    uint32_t best_failures = UINT32_MAX;
    uint32_t healthy_count = 0;
    uint32_t *healthy_servers;
    uint32_t rand_val, selected_idx;
    
    ASSERT(server != NULL);
    
    dns = server->dns;
    pool = server->owner;
    if (dns == NULL || dns->naddresses == 0) {
        return 0;
    }
    
    
    /* Allocate array to track healthy servers */
    healthy_servers = nc_alloc(dns->naddresses * sizeof(uint32_t));
    if (healthy_servers == NULL) {
        return 0;
    }
    
    /* Zone detection based on latency if enabled */
    if (pool->zone_aware) {
        server_detect_zones_by_latency(server);
    }
    
    /* Cache endpoint discovery (always enabled for cache services) */
    server_discover_cache_endpoints(server);
    
    /* Find best address and collect all healthy servers */
    for (i = 0; i < dns->naddresses; i++) {
        /* Enhanced health checking */
        if (!server_is_healthy(server, i)) {
            log_debug(LOG_VVERB, "skipping unhealthy server address %"PRIu32, i);
            continue;
        }
        
        /* Track this as a healthy server */
        healthy_servers[healthy_count] = i;
        healthy_count++;
        
        /* Calculate zone-aware weight if zone awareness is enabled */
        uint32_t effective_latency = dns->latencies[i];
        if (pool->zone_aware) {
            uint32_t zone_weight = server_calculate_zone_weight(server, i);
            /* Lower latency value = better, so reduce by weight bonus */
            if (zone_weight > 100) {
                uint32_t bonus = zone_weight - 100;
                effective_latency = (effective_latency > bonus * 1000) ? 
                                   (effective_latency - bonus * 1000) : 0;
            }
            log_debug(LOG_VVERB, "🌍 zone-aware latency for addr %"PRIu32": %"PRIu32"us -> %"PRIu32"us (weight: %"PRIu32")", 
                      i, dns->latencies[i], effective_latency, zone_weight);
        }
        
        /* Check if this is the best server */
        if (effective_latency < best_latency || 
            (effective_latency == best_latency && dns->failure_counts[i] < best_failures)) {
            best_latency = effective_latency;
            best_failures = dns->failure_counts[i];
            best_idx = i;
        }
    }
    
    if (healthy_count == 0) {
        nc_free(healthy_servers);
        return 0;
    }
    
    if (healthy_count == 1) {
        /* Only one healthy server, use it */
        nc_free(healthy_servers);
        log_debug(LOG_INFO, "only one healthy server: address %"PRIu32" for '%.*s' (latency: %"PRIu32"us)",
                  best_idx, server->pname.len, server->pname.data, dns->latencies[best_idx]);
        return best_idx;
    }
    
    /* Zone-aware server selection with high preference for same-zone servers */
    if (pool->zone_aware && dns->zone_ids != NULL) {
        uint32_t same_zone_count = 0;
        uint32_t *same_zone_servers = nc_alloc(dns->naddresses * sizeof(uint32_t));
        uint32_t *other_zone_servers = nc_alloc(dns->naddresses * sizeof(uint32_t));
        uint32_t other_zone_count = 0;
        
        if (same_zone_servers == NULL || other_zone_servers == NULL) {
            if (same_zone_servers) nc_free(same_zone_servers);
            if (other_zone_servers) nc_free(other_zone_servers);
            nc_free(healthy_servers);
            return best_idx;
        }
        
        /* Separate servers by zone */
        for (i = 0; i < healthy_count; i++) {
            uint32_t idx = healthy_servers[i];
            if (dns->zone_ids[idx] == dns->local_zone_id) {
                same_zone_servers[same_zone_count] = idx;
                same_zone_count++;
            } else {
                other_zone_servers[other_zone_count] = idx;
                other_zone_count++;
            }
        }
        
        log_debug(LOG_VERB, "🌍 zone routing for '%.*s': %"PRIu32" same-zone, %"PRIu32" other-zone servers (zone_weight: %"PRIu32"%%)", 
                  server->pname.len, server->pname.data, same_zone_count, other_zone_count, pool->zone_weight);
        
        /* Apply zone-aware routing: zone_weight% preference for same-zone servers */
        rand_val = (uint32_t)rand() % 100;
        
        if (same_zone_count > 0 && rand_val < pool->zone_weight) {
            /* Select from same-zone servers */
            selected_idx = same_zone_servers[rand() % same_zone_count];
            stats_server_incr(pool->ctx, server, same_zone_selections);
            stats_server_set(pool->ctx, server, current_latency_us, dns->latencies[selected_idx]);
            
            nc_free(healthy_servers);
            nc_free(same_zone_servers);
            nc_free(other_zone_servers);
            
            log_debug(LOG_INFO, "→ selected SAME-ZONE address %"PRIu32" for '%.*s' (latency: %"PRIu32"us, zone: %"PRIu32", rand: %"PRIu32" < %"PRIu32"%%)",
                      selected_idx, server->pname.len, server->pname.data, 
                      dns->latencies[selected_idx], dns->zone_ids[selected_idx], rand_val, pool->zone_weight);
            return selected_idx;
        }
        
        /* Select from all healthy servers (distributed) */
        if (healthy_count > 0) {
            selected_idx = healthy_servers[rand() % healthy_count];
            
            if (dns->zone_ids[selected_idx] != dns->local_zone_id) {
                stats_server_incr(pool->ctx, server, cross_zone_selections);
            } else {
                stats_server_incr(pool->ctx, server, same_zone_selections);
            }
            stats_server_set(pool->ctx, server, current_latency_us, dns->latencies[selected_idx]);
            
            nc_free(healthy_servers);
            nc_free(same_zone_servers);
            nc_free(other_zone_servers);
            
            log_debug(LOG_INFO, "→ selected DISTRIBUTED address %"PRIu32" for '%.*s' (latency: %"PRIu32"us, zone: %"PRIu32", rand: %"PRIu32" >= %"PRIu32"%%)",
                      selected_idx, server->pname.len, server->pname.data, 
                      dns->latencies[selected_idx], dns->zone_ids[selected_idx], rand_val, pool->zone_weight);
            return selected_idx;
        }
        
        nc_free(same_zone_servers);
        nc_free(other_zone_servers);
    } else {
        /* No zone awareness - just pick the lowest latency server */
        if (healthy_count > 0) {
            selected_idx = best_idx;
            stats_server_set(pool->ctx, server, current_latency_us, dns->latencies[best_idx]);
            
            log_debug(LOG_INFO, "→ selected LOWEST-LATENCY address %"PRIu32" for '%.*s' (latency: %"PRIu32"us)",
                      best_idx, server->pname.len, server->pname.data, dns->latencies[best_idx]);
        }
    }
    
    /* Fallback cleanup and return */
    nc_free(healthy_servers);
    return best_idx;
}

rstatus_t
server_measure_latency(struct server *server, uint32_t addr_idx, int64_t latency)
{
    struct server_dns *dns;
    
    ASSERT(server != NULL);
    
    dns = server->dns;
    if (dns == NULL || addr_idx >= dns->naddresses) {
        return NC_ERROR;
    }
    
    /* Update latency with exponential moving average */
    uint32_t old_latency = dns->latencies[addr_idx];
    if (dns->latencies[addr_idx] == DEFAULT_LATENCY_USEC) {
        dns->latencies[addr_idx] = (uint32_t)latency;
        log_debug(LOG_INFO, "⏱️  initial latency for '%.*s' addr %"PRIu32": %"PRIu32"us",
                  server->pname.len, server->pname.data, addr_idx, dns->latencies[addr_idx]);
    } else {
        /* 90% old value, 10% new value */
        dns->latencies[addr_idx] = (dns->latencies[addr_idx] * 9 + (uint32_t)latency) / 10;
        log_debug(LOG_VERB, "⏱️  updated latency for '%.*s' addr %"PRIu32": %"PRIu32"us → %"PRIu32"us (new: %"PRId64"us)",
                  server->pname.len, server->pname.data, addr_idx, old_latency, dns->latencies[addr_idx], latency);
    }
    
    dns->last_latency_check[addr_idx] = nc_usec_now();
    
    return NC_OK;
}

bool
server_should_resolve_dns(struct server *server)
{
    struct server_dns *dns;
    int64_t now;
    
    if (server == NULL || !server->is_dynamic || server->dns == NULL) {
        return false;
    }
    
    dns = server->dns;
    now = nc_usec_now();
    
    return (dns->last_resolved == 0 || 
            (now - dns->last_resolved) > dns->resolve_interval);
}

/* 
 * Get detailed read host information for stats/debugging 
 */
rstatus_t
server_get_read_hosts_info(struct server *server, char *buffer, size_t buffer_size)
{
    struct server_dns *dns;
    struct server_pool *pool;
    size_t written = 0;
    uint32_t i;
    
    if (server == NULL || buffer == NULL || buffer_size == 0) {
        return NC_ERROR;
    }
    
    dns = server->dns;
    pool = server->owner;
    
    if (!server->is_dynamic || dns == NULL) {
        written = snprintf(buffer, buffer_size, 
            "  \"read_hosts\": {\n"
            "    \"type\": \"static\",\n"
            "    \"hostname\": \"%.*s\",\n"
            "    \"addresses\": 1\n"
            "  }", 
            server->addrstr.len, server->addrstr.data);
        return (written < buffer_size) ? NC_OK : NC_ERROR;
    }
    
    /* Dynamic DNS server */
    uint32_t zones_detected = (dns->zone_ids != NULL) ? (dns->next_zone_id - 1) : 0;
    uint32_t same_zone_count = 0, cross_zone_count = 0;
    
    /* Count servers by zone type */
    if (pool->zone_aware && dns->zone_ids != NULL) {
        for (i = 0; i < dns->naddresses; i++) {
            if (dns->zone_ids[i] == dns->local_zone_id) {
                same_zone_count++;
            } else {
                cross_zone_count++;
            }
        }
    }
    
    written = snprintf(buffer, buffer_size,
        "  \"read_hosts\": {\n"
        "    \"type\": \"dynamic\",\n"
        "    \"hostname\": \"%.*s\",\n"
        "    \"dns_resolve_interval\": %"PRId64",\n"
        "    \"last_resolved\": %"PRId64",\n"
        "    \"addresses\": %"PRIu32",\n"
        "    \"current_address\": %"PRIu32",\n"
        "    \"zone_aware\": %s,\n"
        "    \"zone_weight_percent\": %"PRIu32",\n"
        "    \"zones_detected\": %"PRIu32",\n"
        "    \"same_zone_servers\": %"PRIu32",\n"
        "    \"cross_zone_servers\": %"PRIu32",\n"
        "    \"address_details\": [\n",
        dns->hostname.len, dns->hostname.data,
        dns->resolve_interval / 1000000, /* convert to seconds */
        dns->last_resolved,
        dns->naddresses,
        server->current_addr_idx,
        pool->zone_aware ? "true" : "false",
        pool->zone_weight,
        zones_detected,
        same_zone_count,
        cross_zone_count);
    
    if (written >= buffer_size) return NC_ERROR;
    
    /* Add details for each address */
    for (i = 0; i < dns->naddresses; i++) {
        char addr_str[INET6_ADDRSTRLEN];
        struct sockaddr *addr = (struct sockaddr *)&dns->addresses[i].addr;
        size_t addr_written;
        
        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &addr_in->sin_addr, addr_str, sizeof(addr_str));
        } else if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, addr_str, sizeof(addr_str));
        } else {
            strcpy(addr_str, "unknown");
        }
        
        /* Calculate zone weight for this address */
        uint32_t zone_weight = server_calculate_zone_weight(server, i);
        uint32_t zone_id = (dns->zone_ids != NULL) ? dns->zone_ids[i] : 0;
        const char* zone_type = (pool->zone_aware && dns->zone_ids != NULL && zone_id == dns->local_zone_id) ? "same-az" : "cross-az";
        bool is_healthy = server_is_healthy(server, i);
        
        /* Calculate seconds since last seen in DNS */
        int64_t now = nc_usec_now();
        int64_t seconds_since_last_seen = (now > 0 && dns->last_seen[i] > 0) ? 
                                          (now - dns->last_seen[i]) / 1000000 : -1;
        
        /* Get hostname for this address */
        const char *hostname_str = (dns->hostnames[i].data != NULL) ? 
                                   (const char *)dns->hostnames[i].data : "unknown";
        
        addr_written = snprintf(buffer + written, buffer_size - written,
            "      {\n"
            "        \"index\": %"PRIu32",\n"
            "        \"ip\": \"%s\",\n"
            "        \"hostname\": \"%s\",\n"
            "        \"latency_us\": %"PRIu32",\n"
            "        \"failures\": %"PRIu32",\n"
            "        \"zone_id\": %"PRIu32",\n"
            "        \"zone_type\": \"%s\",\n"
            "        \"zone_weight\": %"PRIu32",\n"
            "        \"healthy\": %s,\n"
            "        \"current\": %s,\n"
            "        \"seconds_since_last_seen\": %"PRId64"\n"
            "      }%s\n",
            i, addr_str, hostname_str, dns->latencies[i], dns->failure_counts[i],
            zone_id, zone_type, zone_weight, 
            is_healthy ? "true" : "false",
            (i == server->current_addr_idx) ? "true" : "false",
            seconds_since_last_seen,
            (i < dns->naddresses - 1) ? "," : "");
        
        written += addr_written;
        if (written >= buffer_size) return NC_ERROR;
    }
    
    {
        size_t final_written = snprintf(buffer + written, buffer_size - written,
            "    ]\n"
            "  }");
        written += final_written;
    }
    
    return (written < buffer_size) ? NC_OK : NC_ERROR;
}

/*
 * Cloud-agnostic functions for enhanced multi-zone integration
 */

/* 
 * Detect zones based on latency clustering
 */
rstatus_t
server_detect_zones_by_latency(struct server *server)
{
    struct server_dns *dns;
    int64_t now;
    uint32_t i;
    uint32_t min_latency, max_latency, avg_latency, total_latency;
    uint32_t low_latency_threshold;
    uint32_t healthy_count = 0;
    
    if (server == NULL || !server->is_dynamic || server->dns == NULL) {
        log_debug(LOG_VVERB, "❌ Zone detection skipped: server=%p, is_dynamic=%d, dns=%p", 
                  server, server ? server->is_dynamic : 0, server ? server->dns : NULL);
        return NC_ERROR;
    }
    
    dns = server->dns;
    now = nc_usec_now();
    
    log_debug(LOG_INFO, "🌍 Zone detection called for '%.*s' with %"PRIu32" addresses", 
              server->pname.len, server->pname.data, dns->naddresses);
    
    /* Rate limit zone analysis - check every 2 minutes max */
    if ((now - dns->last_zone_analysis) < 120000000LL) {
        log_debug(LOG_VVERB, "⏱️  Zone analysis rate limited (last: %"PRId64", now: %"PRId64")", 
                  dns->last_zone_analysis, now);
        return NC_OK;
    }
    
    dns->last_zone_analysis = now;
    
    if (dns->naddresses == 0) {
        return NC_OK;
    }
    
    /* Initialize zone_ids array if needed */
    if (dns->zone_ids == NULL) {
        dns->zone_ids = nc_calloc(dns->max_addresses, sizeof(uint32_t));
        if (dns->zone_ids == NULL) {
            return NC_ERROR;
        }
    }
    
    /* Calculate latency statistics for healthy servers only */
    min_latency = UINT32_MAX;
    max_latency = 0;
    total_latency = 0;
    
    for (i = 0; i < dns->naddresses; i++) {
        if (dns->failure_counts[i] <= 2) { /* Only consider healthy servers */
            healthy_count++;
            total_latency += dns->latencies[i];
            if (dns->latencies[i] < min_latency) {
                min_latency = dns->latencies[i];
            }
            if (dns->latencies[i] > max_latency) {
                max_latency = dns->latencies[i];
            }
        }
    }
    
    if (healthy_count == 0) {
        return NC_OK;
    }
    
    avg_latency = total_latency / healthy_count;
    
    /* 
     * Auto-detect low latency threshold using statistical outlier detection:
     * Servers with latency <= (min + 25% of range) are considered "local zone"
     * This groups the lowest latency servers together automatically
     */
    uint32_t latency_range = max_latency - min_latency;
    low_latency_threshold = min_latency + (latency_range / 4); /* 25% above minimum */
    
    /* Ensure threshold is reasonable - at least allow servers within 10ms of minimum */
    uint32_t min_threshold = min_latency + 10000; /* 10ms */
    if (low_latency_threshold < min_threshold) {
        low_latency_threshold = min_threshold;
    }
    
    /* Assign zone IDs based on statistical grouping */
    dns->local_zone_id = 1; /* Local zone is always 1 */
    dns->next_zone_id = 2;
    
    for (i = 0; i < dns->naddresses; i++) {
        if (dns->failure_counts[i] > 2) {
            dns->zone_ids[i] = 99; /* Unhealthy zone */
            continue;
        }
        
        if (dns->latencies[i] <= low_latency_threshold) {
            /* Local zone - statistically low latency group */
            dns->zone_ids[i] = dns->local_zone_id;
            log_debug(LOG_VERB, "🌍 addr %"PRIu32" assigned to LOCAL zone %"PRIu32" (latency: %"PRIu32"us, threshold: %"PRIu32"us)", 
                      i, dns->zone_ids[i], dns->latencies[i], low_latency_threshold);
        } else {
            /* Remote zone - higher latency */
            dns->zone_ids[i] = dns->next_zone_id;
            log_debug(LOG_VERB, "🌍 addr %"PRIu32" assigned to REMOTE zone %"PRIu32" (latency: %"PRIu32"us, threshold: %"PRIu32"us)", 
                      i, dns->zone_ids[i], dns->latencies[i], low_latency_threshold);
        }
    }
    
    /* Increment next_zone_id only if we actually assigned remote zones */
    for (i = 0; i < dns->naddresses; i++) {
        if (dns->zone_ids[i] == dns->next_zone_id) {
            dns->next_zone_id++;
            break;
        }
    }
    
    log_debug(LOG_INFO, "🌍 auto-detected %"PRIu32" zones for server '%.*s' (low-latency threshold: %"PRIu32"us, range: %"PRIu32"us)", 
              dns->next_zone_id - 1, server->pname.len, server->pname.data, low_latency_threshold, latency_range);
    
    return NC_OK;
}

/*
 * Assign zone ID to a specific address based on latency analysis
 */
uint32_t
server_assign_zone_id(struct server *server, uint32_t addr_idx)
{
    struct server_dns *dns;
    
    if (server == NULL || !server->is_dynamic || server->dns == NULL || 
        addr_idx >= server->dns->naddresses) {
        return 0;
    }
    
    dns = server->dns;
    
    /* Ensure zone detection has been run */
    if (dns->zone_ids == NULL) {
        server_detect_zones_by_latency(server);
    }
    
    if (dns->zone_ids != NULL && addr_idx < dns->naddresses) {
        return dns->zone_ids[addr_idx];
    }
    
    return 0;
}

/*
 * Calculate zone-aware weight for server selection
 */
uint32_t
server_calculate_zone_weight(struct server *server, uint32_t addr_idx)
{
    struct server_dns *dns;
    struct server_pool *pool;
    uint32_t base_weight = 100;
    uint32_t zone_bonus = 0;
    
    if (server == NULL || !server->is_dynamic || server->dns == NULL ||
        addr_idx >= server->dns->naddresses) {
        return base_weight;
    }
    
    dns = server->dns;
    pool = server->owner;
    
    /* If zone awareness is disabled, return base weight */
    if (!pool->zone_aware) {
        return base_weight;
    }
    
    /* Get zone ID for this address */
    uint32_t addr_zone_id = server_assign_zone_id(server, addr_idx);
    
    /* Give bonus weight to same-zone servers */
    if (addr_zone_id != 0 && addr_zone_id == dns->local_zone_id) {
        zone_bonus = pool->zone_weight;
        log_debug(LOG_VERB, "🌍 same-zone bonus: +%"PRIu32" weight for addr %"PRIu32" (zone: %"PRIu32")", 
                  zone_bonus, addr_idx, addr_zone_id);
    }
    
    return base_weight + zone_bonus;
}

/*
 * Enhanced health check for a specific address
 */
rstatus_t
server_health_check(struct server *server, uint32_t addr_idx)
{
    struct server_dns *dns;
    struct server_pool *pool;
    int64_t now;
    uint32_t failures;
    uint32_t latency;
    
    if (server == NULL || !server->is_dynamic || server->dns == NULL ||
        addr_idx >= server->dns->naddresses) {
        return NC_ERROR;
    }
    
    dns = server->dns;
    pool = server->owner;
    now = nc_usec_now();
    
    /* Initialize health arrays if needed */
    if (dns->health_scores == NULL) {
        dns->health_scores = nc_calloc(dns->max_addresses, sizeof(uint32_t));
        dns->last_health_check = nc_calloc(dns->max_addresses, sizeof(int64_t));
        dns->health_check_interval = 30000000LL; /* 30 seconds */
        dns->consecutive_failures_limit = pool->dns_failure_threshold;
        
        if (dns->health_scores == NULL || dns->last_health_check == NULL) {
            return NC_ERROR;
        }
        uint32_t i;
        /* Initialize all health scores to 100 (healthy) */
        for (i = 0; i < dns->max_addresses; i++) {
            dns->health_scores[i] = 100;
        }
    }
    
    /* Check if health check is due */
    if ((now - dns->last_health_check[addr_idx]) < dns->health_check_interval) {
        return NC_OK;
    }
    
    dns->last_health_check[addr_idx] = now;
    
    failures = dns->failure_counts[addr_idx];
    latency = dns->latencies[addr_idx];
    
    /* Calculate health score based on failures and latency */
    uint32_t health_score = 100;
    
    /* Reduce score based on failure rate */
    if (failures > 0) {
        health_score -= (failures * 20); /* -20 points per failure */
    }
    
    /* Reduce score for high latency (>100ms = unhealthy) */
    if (latency > 100000) { /* 100ms in microseconds */
        health_score -= ((latency - 100000) / 10000); /* -1 point per 10ms over 100ms */
    }
    
    /* Ensure score doesn't go below 0 */
    if (health_score > 100) health_score = 0; /* Handle underflow */
    
    /* Update health score with exponential moving average */
    dns->health_scores[addr_idx] = (dns->health_scores[addr_idx] * 7 + health_score * 3) / 10;
    
    log_debug(LOG_VERB, "🏥 health check addr %"PRIu32": failures=%"PRIu32", latency=%"PRIu32"us, score=%"PRIu32,
              addr_idx, failures, latency, dns->health_scores[addr_idx]);
    
    return NC_OK;
}

/*
 * Check if a server address is healthy
 */
bool
server_is_healthy(struct server *server, uint32_t addr_idx)
{
    struct server_dns *dns;
    
    if (server == NULL || !server->is_dynamic || server->dns == NULL ||
        addr_idx >= server->dns->naddresses) {
        return true; /* Assume healthy if we can't check */
    }
    
    dns = server->dns;
    
    /* Perform health check if needed */
    server_health_check(server, addr_idx);
    
    /* Consider healthy if health score > 30 and failures < limit */
    bool is_healthy = (dns->health_scores != NULL && dns->health_scores[addr_idx] > 30) &&
                     (dns->failure_counts[addr_idx] < dns->consecutive_failures_limit);
    
    log_debug(LOG_VVERB, "🏥 health status addr %"PRIu32": %s (score=%"PRIu32", failures=%"PRIu32")",
              addr_idx, is_healthy ? "healthy" : "unhealthy",
              dns->health_scores ? dns->health_scores[addr_idx] : 0,
              dns->failure_counts[addr_idx]);
    
    return is_healthy;
}

/*
 * Discover managed cache service endpoints (cloud-agnostic)
 */
rstatus_t
server_discover_cache_endpoints(struct server *server)
{
    struct server_dns *dns;
    struct server_pool *pool;
    
    if (server == NULL || !server->is_dynamic || server->dns == NULL) {
        return NC_ERROR;
    }
    
    dns = server->dns;
    pool = server->owner;
    
    /* Cache endpoint discovery (always enabled for cache services) */
    
    /* Check if hostname looks like a managed cache service endpoint */
    if (dns->hostname.len > 20 && 
        (strstr((char*)dns->hostname.data, ".cache.") != NULL ||
         strstr((char*)dns->hostname.data, ".redis.") != NULL ||
         strstr((char*)dns->hostname.data, ".memcache.") != NULL ||
         strstr((char*)dns->hostname.data, "cluster") != NULL)) {
        
        log_debug(LOG_INFO, "🔍 cache mode: enhanced discovery for '%.*s'",
                  dns->hostname.len, dns->hostname.data);
        
        /* Cache-specific DNS resolution with shorter intervals for managed services */
        if (dns->resolve_interval > 15000000LL) { /* If > 15 seconds */
            dns->resolve_interval = 15000000LL; /* Set to 15 seconds for managed cache */
            log_debug(LOG_INFO, "🔍 adjusted DNS interval to 15s for managed cache endpoint");
        }
        
        /* Try to detect read replica endpoints */
        if (strstr((char*)dns->hostname.data, "-ro") != NULL || 
            strstr((char*)dns->hostname.data, "read") != NULL ||
            strstr((char*)dns->hostname.data, "replica") != NULL) {
            log_debug(LOG_INFO, "🔍 detected managed cache read replica endpoint");
        }
    }
    
    return NC_OK;
}
