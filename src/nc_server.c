/*
 * twemproxy - A fast and lightweight proxy for memcached protocol.
 * Copyright (C) 2011 Twitter, Inc.
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
    
    /* Enhanced health and zone initialization */
    dns->health_scores = NULL;
    dns->last_health_check = NULL;
    dns->health_check_interval = 30000000LL; /* 30 seconds */
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
    rstatus_t status;
    uint32_t i;
    
    ASSERT(server != NULL && server->dns != NULL);
    
    dns = server->dns;
    
    /* Free existing data */
    if (dns->addresses != NULL) {
        nc_free(dns->addresses);
        dns->addresses = NULL;
    }
    if (dns->latencies != NULL) {
        nc_free(dns->latencies);
        dns->latencies = NULL;
    }
    if (dns->last_latency_check != NULL) {
        nc_free(dns->last_latency_check);
        dns->last_latency_check = NULL;
    }
    if (dns->failure_counts != NULL) {
        nc_free(dns->failure_counts);
        dns->failure_counts = NULL;
    }
    
    /* Resolve all addresses */
    stats_server_incr(server->owner->ctx, server, dns_resolves);
    status = nc_resolve_multi(&dns->hostname, server->port, &dns->addresses, 
                              &dns->naddresses, dns->max_addresses);
    if (status != NC_OK) {
        stats_server_incr(server->owner->ctx, server, dns_failures);
        log_error("failed to resolve '%.*s': %s", 
                  dns->hostname.len, dns->hostname.data, strerror(errno));
        return status;
    }
    
    /* Update DNS stats */
    stats_server_set_ts(server->owner->ctx, server, last_dns_resolved_at, dns->last_resolved);
    stats_server_set(server->owner->ctx, server, dns_addresses, dns->naddresses);
    
    /* Allocate latency and failure tracking arrays */
    dns->latencies = nc_alloc(dns->naddresses * sizeof(uint32_t));
    dns->last_latency_check = nc_alloc(dns->naddresses * sizeof(int64_t));
    dns->failure_counts = nc_alloc(dns->naddresses * sizeof(uint32_t));
    
    if (dns->latencies == NULL || dns->last_latency_check == NULL || 
        dns->failure_counts == NULL) {
        return NC_ENOMEM;
    }
    
    /* Initialize latency data */
    for (i = 0; i < dns->naddresses; i++) {
        dns->latencies[i] = DEFAULT_LATENCY_USEC;
        dns->last_latency_check[i] = 0;
        dns->failure_counts[i] = 0;
    }
    
    dns->last_resolved = nc_usec_now();
    
    log_debug(LOG_INFO, "resolved '%.*s' to %"PRIu32" addresses",
              dns->hostname.len, dns->hostname.data, dns->naddresses);
    
    /* Log all discovered addresses with their initial latencies */
    for (i = 0; i < dns->naddresses; i++) {
        char addr_str[INET6_ADDRSTRLEN];
        struct sockaddr *addr = (struct sockaddr *)&dns->addresses[i].addr;
        
        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &addr_in->sin_addr, addr_str, sizeof(addr_str));
        } else if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, addr_str, sizeof(addr_str));
        } else {
            strcpy(addr_str, "unknown");
        }
        
        log_debug(LOG_INFO, "  address[%"PRIu32"]: %s (latency: %"PRIu32"us, failures: %"PRIu32")",
                  i, addr_str, dns->latencies[i], dns->failure_counts[i]);
    }
    
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
    
    /* If latency routing is disabled, just pick first healthy address */
    if (!pool->latency_routing) {
        for (i = 0; i < dns->naddresses; i++) {
            if (dns->failure_counts[i] <= 3) {
                return i;
            }
        }
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
    
    /* Cache endpoint discovery if enabled */
    if (pool->cache_mode) {
        server_discover_cache_endpoints(server);
    }
    
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
    
    /* Log all healthy servers with their latencies for selection visibility */
    log_debug(LOG_VERB, "server selection for '%.*s': %"PRIu32" healthy servers, weight: %"PRIu32"%%",
              server->pname.len, server->pname.data, healthy_count, pool->latency_weight);
    for (i = 0; i < healthy_count; i++) {
        uint32_t idx = healthy_servers[i];
        log_debug(LOG_VVERB, "  candidate[%"PRIu32"]: latency=%"PRIu32"us, failures=%"PRIu32"%s",
                  idx, dns->latencies[idx], dns->failure_counts[idx],
                  (idx == best_idx) ? " [FASTEST]" : "");
    }
    
    /* Apply weighted routing: latency_weight% to best server, remainder split among all others */
    rand_val = (uint32_t)rand() % 100;
    
    if (rand_val < pool->latency_weight) {
        /* Send to best server */
        stats_server_incr(pool->ctx, server, latency_fastest_sel);
        stats_server_set(pool->ctx, server, current_latency_us, dns->latencies[best_idx]);
        nc_free(healthy_servers);
        log_debug(LOG_INFO, "→ selected FASTEST address %"PRIu32" for '%.*s' (latency: %"PRIu32"us, rand: %"PRIu32" < %"PRIu32"%%)",
                  best_idx, server->pname.len, server->pname.data, 
                  dns->latencies[best_idx], rand_val, pool->latency_weight);
        return best_idx;
    }
    
    /* Distribute remaining traffic equally among all other healthy servers */
    uint32_t other_servers_count = 0;
    uint32_t *other_servers = nc_alloc(dns->naddresses * sizeof(uint32_t));
    if (other_servers == NULL) {
        nc_free(healthy_servers);
        return best_idx; /* Fallback to best server */
    }
    
    /* Collect all healthy servers except the best one */
    for (i = 0; i < healthy_count; i++) {
        if (healthy_servers[i] != best_idx) {
            other_servers[other_servers_count] = healthy_servers[i];
            other_servers_count++;
        }
    }
    
    if (other_servers_count == 0) {
        /* No other servers available, use best */
        nc_free(healthy_servers);
        nc_free(other_servers);
        return best_idx;
    }
    
    /* Randomly select from other servers with equal probability */
    selected_idx = other_servers[rand() % other_servers_count];
    
    stats_server_incr(pool->ctx, server, latency_distributed_sel);
    stats_server_set(pool->ctx, server, current_latency_us, dns->latencies[selected_idx]);
    
    log_debug(LOG_INFO, "→ selected DISTRIBUTED address %"PRIu32" for '%.*s' (latency: %"PRIu32"us, rand: %"PRIu32" >= %"PRIu32"%%, %"PRIu32" alternatives)",
              selected_idx, server->pname.len, server->pname.data, 
              dns->latencies[selected_idx], rand_val, pool->latency_weight, other_servers_count);
    
    nc_free(healthy_servers);
    nc_free(other_servers);
    return selected_idx;
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
    written = snprintf(buffer, buffer_size,
        "  \"read_hosts\": {\n"
        "    \"type\": \"dynamic\",\n"
        "    \"hostname\": \"%.*s\",\n"
        "    \"latency_routing\": %s,\n"
        "    \"latency_weight\": %"PRIu32",\n"
        "    \"dns_resolve_interval\": %"PRId64",\n"
        "    \"last_resolved\": %"PRId64",\n"
        "    \"addresses\": %"PRIu32",\n"
        "    \"current_address\": %"PRIu32",\n"
        "    \"address_details\": [\n",
        dns->hostname.len, dns->hostname.data,
        pool->latency_routing ? "true" : "false",
        pool->latency_weight,
        dns->resolve_interval / 1000000, /* convert to seconds */
        dns->last_resolved,
        dns->naddresses,
        server->current_addr_idx);
    
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
        
        addr_written = snprintf(buffer + written, buffer_size - written,
            "      {\n"
            "        \"index\": %"PRIu32",\n"
            "        \"ip\": \"%s\",\n"
            "        \"latency_us\": %"PRIu32",\n"
            "        \"failures\": %"PRIu32",\n"
            "        \"current\": %s\n"
            "      }%s\n",
            i, addr_str, dns->latencies[i], dns->failure_counts[i],
            (i == server->current_addr_idx) ? "true" : "false",
            (i < dns->naddresses - 1) ? "," : "");
        
        written += addr_written;
        if (written >= buffer_size) return NC_ERROR;
    }
    
    addr_written = snprintf(buffer + written, buffer_size - written,
        "    ]\n"
        "  }");
    written += addr_written;
    
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
    struct server_pool *pool;
    int64_t now;
    uint32_t i, j;
    uint32_t threshold;
    
    if (server == NULL || !server->is_dynamic || server->dns == NULL) {
        return NC_ERROR;
    }
    
    dns = server->dns;
    pool = server->owner;
    now = nc_usec_now();
    threshold = pool->zone_latency_threshold;
    
    /* Rate limit zone analysis - check every 2 minutes max */
    if ((now - dns->last_zone_analysis) < 120000000LL) {
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
    
    /* Find the server with lowest latency (assume it's in our local zone) */
    uint32_t min_latency = UINT32_MAX;
    uint32_t local_addr_idx = 0;
    
    for (i = 0; i < dns->naddresses; i++) {
        if (dns->latencies[i] < min_latency && dns->failure_counts[i] <= 2) {
            min_latency = dns->latencies[i];
            local_addr_idx = i;
        }
    }
    
    /* Assign zone IDs based on latency clustering */
    dns->local_zone_id = 1; /* Local zone is always 1 */
    dns->next_zone_id = 2;
    
    for (i = 0; i < dns->naddresses; i++) {
        uint32_t latency_diff = (dns->latencies[i] > min_latency) ? 
                               (dns->latencies[i] - min_latency) : 0;
        
        if (latency_diff <= threshold) {
            /* Same zone - low latency difference */
            dns->zone_ids[i] = dns->local_zone_id;
            log_debug(LOG_VERB, "🌍 addr %"PRIu32" assigned to LOCAL zone %"PRIu32" (latency diff: %"PRIu32"us)", 
                      i, dns->zone_ids[i], latency_diff);
        } else {
            /* Different zone - check if we can group with existing zones */
            uint32_t assigned_zone = 0;
            
            for (j = 0; j < i; j++) {
                if (dns->zone_ids[j] > dns->local_zone_id) {
                    uint32_t other_latency_diff = (dns->latencies[j] > min_latency) ? 
                                                  (dns->latencies[j] - min_latency) : 0;
                    
                    /* If latencies are similar, group them in the same zone */
                    if (abs((int)latency_diff - (int)other_latency_diff) <= (threshold / 2)) {
                        assigned_zone = dns->zone_ids[j];
                        break;
                    }
                }
            }
            
            if (assigned_zone == 0) {
                /* Create new zone */
                assigned_zone = dns->next_zone_id++;
            }
            
            dns->zone_ids[i] = assigned_zone;
            log_debug(LOG_VERB, "🌍 addr %"PRIu32" assigned to REMOTE zone %"PRIu32" (latency diff: %"PRIu32"us)", 
                      i, dns->zone_ids[i], latency_diff);
        }
    }
    
    log_debug(LOG_INFO, "🌍 detected %"PRIu32" zones for server '%.*s' (threshold: %"PRIu32"us)", 
              dns->next_zone_id - 1, server->pname.len, server->pname.data, threshold);
    
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
        
        /* Initialize all health scores to 100 (healthy) */
        for (uint32_t i = 0; i < dns->max_addresses; i++) {
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
    
    /* Only proceed if cache mode is enabled */
    if (!pool->cache_mode) {
        return NC_OK;
    }
    
    /* Check if hostname looks like a managed cache service endpoint */
    if (dns->hostname.len > 20 && 
        (nc_strstr(dns->hostname.data, ".cache.") != NULL ||
         nc_strstr(dns->hostname.data, ".redis.") != NULL ||
         nc_strstr(dns->hostname.data, ".memcache.") != NULL ||
         nc_strstr(dns->hostname.data, "cluster") != NULL)) {
        
        log_debug(LOG_INFO, "🔍 cache mode: enhanced discovery for '%.*s'",
                  dns->hostname.len, dns->hostname.data);
        
        /* Cache-specific DNS resolution with shorter intervals for managed services */
        if (dns->resolve_interval > 15000000LL) { /* If > 15 seconds */
            dns->resolve_interval = 15000000LL; /* Set to 15 seconds for managed cache */
            log_debug(LOG_INFO, "🔍 adjusted DNS interval to 15s for managed cache endpoint");
        }
        
        /* Try to detect read replica endpoints */
        if (nc_strstr(dns->hostname.data, "-ro") != NULL || 
            nc_strstr(dns->hostname.data, "read") != NULL ||
            nc_strstr(dns->hostname.data, "replica") != NULL) {
            log_debug(LOG_INFO, "🔍 detected managed cache read replica endpoint");
        }
    }
    
    return NC_OK;
}
