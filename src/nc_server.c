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
#include <arpa/inet.h>  /* inet_ntop/inet_pton -- not transitively guaranteed off _GNU_SOURCE */

#include <nc_core.h>
#include <nc_server.h>
#include <nc_conf.h>
#include <nc_client.h>

/* Forward declarations */
static void server_update_dynamic_connections(struct server *server);

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
            conn->addr_idx = best_idx;  /* Track which address this connection uses */
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
        if (!conn->lifetime_expired) {
            server_failure(ctx, conn->owner);
        }
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

    if (!conn->lifetime_expired) {
        server_failure(ctx, conn->owner);
    }

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
            server_measure_latency(server, conn->addr_idx, latency);
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
            server_measure_latency(server, conn->addr_idx, latency);
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
    
    /* Improve health score for successful operations on dynamic DNS servers */
    if (server->is_dynamic && server->dns != NULL) {
        uint32_t addr_idx = conn->addr_idx;
        if (addr_idx < server->dns->naddresses && server->dns->health_scores != NULL) {
            /* Gradually improve health score for successful operations */
            if (server->dns->health_scores[addr_idx] < 90) {
                server->dns->health_scores[addr_idx] += 5;
                if (server->dns->health_scores[addr_idx] > 100) {
                    server->dns->health_scores[addr_idx] = 100;
                }
            }
            /* Reset failure count for this specific address */
            server->dns->failure_counts[addr_idx] = 0;
        }
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
#define DEFAULT_LATENCY_USEC         100             /* 0.1ms default - very optimistic to prioritize new servers */

rstatus_t
server_dns_init(struct server *server)
{
    struct server_dns *dns;
    struct server_pool *pool;
    
    ASSERT(server != NULL);
    
    if (server->dns != NULL) {
        return NC_OK; /* Already initialized */
    }
    
    /*
     * nc_zalloc (not nc_alloc): zero the whole struct up front so EVERY pointer
     * field starts NULL even if a later code path forgets one. The explicit NULL
     * inits below are kept for documentation, but the zalloc is the belt-and-
     * braces guarantee -- without it, if the FIRST DNS resolve fails the dns is
     * only partially populated, and server_dns_deinit() would nc_free() an
     * uninitialised pointer (e.g. last_connected / request_counts) -> wild free.
     */
    dns = nc_zalloc(sizeof(struct server_dns));
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
    dns->last_connected = NULL;
    dns->request_counts = NULL;
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
    
    if (dns->last_connected != NULL) {
        nc_free(dns->last_connected);
    }
    
    if (dns->request_counts != NULL) {
        nc_free(dns->request_counts);
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

/*
 * Remove the address at index i from a server_dns, shifting EVERY per-address
 * parallel array down by one so array[k] keeps describing addresses[k] for all
 * surviving k. The vacated tail slot is zeroed.
 *
 * All the parallel arrays in struct server_dns are indexed by the same address
 * index, so they must move together. The earlier bug shifted only six of them
 * (addresses/latencies/last_latency_check/failure_counts/last_seen/hostnames),
 * leaving last_connected, request_counts, zone_ids, health_scores and
 * last_health_check pointing at the wrong address. This helper is the single
 * place that owns the shift.
 *
 * zone_ids, health_scores and last_health_check are allocated lazily (NULL
 * until zone/health analysis first runs) and are sized to max_addresses, so
 * they are guarded with NULL checks.
 *
 * Reuse invariant: the tail-clear at index naddresses-1 assumes every shifted
 * array is allocated to at least naddresses entries. The eagerly-grown arrays
 * are sized to naddresses; the lazy arrays satisfy this via max_addresses=16.
 * Future changes that alter the naddresses<->max_addresses relationship (fix #3
 * cap-on-accumulate, fix #4 realloc-safety) MUST preserve it.
 *
 * The caller is responsible for any server->current_addr_idx fixup, since this
 * function only sees the dns struct.
 */
void
server_dns_remove_address_at(struct server_dns *dns, uint32_t i)
{
    uint32_t j, last;

    ASSERT(dns != NULL);
    ASSERT(i < dns->naddresses);

    /*
     * Free the hostname string being removed before it is overwritten by the
     * shift, otherwise its backing buffer leaks.
     */
    if (dns->hostnames[i].data != NULL) {
        string_deinit(&dns->hostnames[i]);
    }

    for (j = i; j + 1 < dns->naddresses; j++) {
        memcpy(&dns->addresses[j], &dns->addresses[j + 1], sizeof(struct sockinfo));
        dns->latencies[j]          = dns->latencies[j + 1];
        dns->last_latency_check[j] = dns->last_latency_check[j + 1];
        dns->failure_counts[j]     = dns->failure_counts[j + 1];
        dns->last_seen[j]          = dns->last_seen[j + 1];
        dns->last_connected[j]     = dns->last_connected[j + 1];
        dns->request_counts[j]     = dns->request_counts[j + 1];
        dns->hostnames[j]          = dns->hostnames[j + 1]; /* move struct string */

        if (dns->zone_ids != NULL) {
            dns->zone_ids[j] = dns->zone_ids[j + 1];
        }
        if (dns->health_scores != NULL) {
            dns->health_scores[j] = dns->health_scores[j + 1];
        }
        if (dns->last_health_check != NULL) {
            dns->last_health_check[j] = dns->last_health_check[j + 1];
        }
    }

    /*
     * Clear the now-unused tail slot. hostnames[last] still holds a copy of the
     * struct string that was moved down to hostnames[last-1]; re-initialise it
     * so its data pointer is not aliased (and so a later resolve or
     * server_dns_deinit cannot double-free it). Zero the other tail slots too
     * so stale values never leak into a regrown array.
     */
    last = dns->naddresses - 1;
    memset(&dns->addresses[last], 0, sizeof(struct sockinfo));
    dns->latencies[last]          = 0;
    dns->last_latency_check[last] = 0;
    dns->failure_counts[last]     = 0;
    dns->last_seen[last]          = 0;
    dns->last_connected[last]     = 0;
    dns->request_counts[last]     = 0;
    string_init(&dns->hostnames[last]);
    if (dns->zone_ids != NULL) {
        dns->zone_ids[last] = 0;
    }
    if (dns->health_scores != NULL) {
        dns->health_scores[last] = 0;
    }
    if (dns->last_health_check != NULL) {
        dns->last_health_check[last] = 0;
    }

    dns->naddresses--;
}

/*
 * Free the temporary, parallel hostname array produced by
 * nc_resolve_multi_with_hostnames(): each captured per-element canonical
 * string, then the array itself. NULL-safe (both the array and each element).
 * Every exit path of server_dns_resolve() that owns new_hostnames calls this
 * with the same element count, so the frees stay identical and the paths are
 * mutually exclusive (no double-free).
 */
static void
free_hostnames_temp(char **hostnames, uint32_t n)
{
    uint32_t i;

    if (hostnames == NULL) {
        return;
    }
    for (i = 0; i < n; i++) {
        if (hostnames[i] != NULL) {
            nc_free(hostnames[i]);
        }
    }
    nc_free(hostnames);
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
    
    char **new_hostnames = NULL;
    status = nc_resolve_multi_with_hostnames(&dns->hostname, server->port, &new_addresses, 
                                           &new_hostnames, &new_naddresses, dns->max_addresses);
    if (status != NC_OK) {
        if (server->owner != NULL && server->owner->ctx != NULL) {
            stats_server_incr(server->owner->ctx, server, dns_failures);
        }
        log_error("failed to resolve '%.*s': %s", 
                  dns->hostname.len, dns->hostname.data, strerror(errno));
        
        /* Clean up allocated memory on error */
        if (new_addresses) {
            nc_free(new_addresses);
        }
        free_hostnames_temp(new_hostnames, new_naddresses);

        return status;
    }
    
    log_warn("DNS resolved '%.*s' to %"PRIu32" new addresses",
              dns->hostname.len, dns->hostname.data, new_naddresses);
    
    /* If this is the first resolution, just use the new addresses */
    if (dns->addresses == NULL || dns->naddresses == 0) {
        dns->addresses = new_addresses;
        dns->naddresses = new_naddresses;
        
        /* Update dynamic server connections after initial DNS resolution */
        server_update_dynamic_connections(server);
        
        /*
         * Validate address count before allocation to prevent excessive memory
         * usage. Clamp to max_addresses (the same cap the accumulate path uses,
         * and the size the lazy arrays are allocated to) so the two paths share
         * one source of truth -- a literal here would silently desync if
         * MAX_ADDRESSES_PER_SERVER is ever bumped.
         */
        if (dns->naddresses > dns->max_addresses) {
            log_error("DNS returned excessive address count %"PRIu32" for '%.*s', limiting to %"PRIu32,
                      dns->naddresses, server->pname.len, server->pname.data, dns->max_addresses);
            dns->naddresses = dns->max_addresses;
        }
        
        /* Allocate tracking arrays */
        dns->latencies = nc_alloc(dns->naddresses * sizeof(uint32_t));
        dns->last_latency_check = nc_alloc(dns->naddresses * sizeof(int64_t));
        dns->failure_counts = nc_alloc(dns->naddresses * sizeof(uint32_t));
        dns->last_seen = nc_alloc(dns->naddresses * sizeof(int64_t));
        dns->last_connected = nc_alloc(dns->naddresses * sizeof(int64_t));
        dns->request_counts = nc_alloc(dns->naddresses * sizeof(uint64_t));
        dns->hostnames = nc_alloc(dns->naddresses * sizeof(struct string));
        
        if (dns->latencies == NULL || dns->last_latency_check == NULL ||
            dns->failure_counts == NULL || dns->last_seen == NULL ||
            dns->last_connected == NULL || dns->request_counts == NULL || dns->hostnames == NULL) {
            /*
             * First-resolution alloc failure: some tracking arrays may have
             * been allocated before one nc_alloc() returned NULL. Free each
             * (NULL-safe) and reset to NULL so the half-built dns is clean for
             * a later server_dns_deinit(). Do NOT touch dns->hostnames element
             * strings -- the per-element string_init loop below has not run, so
             * that array's contents are uninitialized; free only the raw array.
             * The temporary new_hostnames list is still ours; free it via the
             * shared helper.
             */
            if (dns->latencies != NULL)          { nc_free(dns->latencies);          dns->latencies = NULL; }
            if (dns->last_latency_check != NULL)  { nc_free(dns->last_latency_check);  dns->last_latency_check = NULL; }
            if (dns->failure_counts != NULL)      { nc_free(dns->failure_counts);      dns->failure_counts = NULL; }
            if (dns->last_seen != NULL)           { nc_free(dns->last_seen);           dns->last_seen = NULL; }
            if (dns->last_connected != NULL)      { nc_free(dns->last_connected);      dns->last_connected = NULL; }
            if (dns->request_counts != NULL)      { nc_free(dns->request_counts);      dns->request_counts = NULL; }
            if (dns->hostnames != NULL)           { nc_free(dns->hostnames);           dns->hostnames = NULL; }
            /*
             * CRITICAL: revert the adoption too. We set dns->addresses =
             * new_addresses and dns->naddresses = new_naddresses above. If we
             * leave those set while the parallel tracking arrays are NULL, the
             * dns is INCONSISTENT: naddresses > 0 but latencies/last_connected/
             * etc. are NULL, so the next client request or DNS tick that indexes
             * a parallel array NULL-derefs. Roll the adoption all the way back to
             * an EMPTY, self-consistent dns (addresses NULL, naddresses 0).
             * new_addresses lives in dns->addresses now, so nc_free(dns->addresses)
             * releases it -- do not also free new_addresses separately.
             * last_resolved is NOT set on this path (it is only assigned after
             * the init loop below), so it stays at its prior value -- 0 for a
             * genuine first resolve -- and server_dns_resolve_due() reports the
             * server as due, so the very next tick retries the resolve cleanly.
             */
            if (dns->addresses != NULL) { nc_free(dns->addresses); dns->addresses = NULL; }
            dns->naddresses = 0;
            free_hostnames_temp(new_hostnames, new_naddresses);
            return NC_ENOMEM;
        }

        /* Initialize data for all addresses */
        for (i = 0; i < dns->naddresses; i++) {
            dns->latencies[i] = DEFAULT_LATENCY_USEC;
            dns->last_latency_check[i] = 0;
            dns->failure_counts[i] = 0;
            dns->last_seen[i] = now;
            dns->last_connected[i] = 0;
            dns->request_counts[i] = 0;
            
            /* Initialize hostname from the captured canonical name */
            string_init(&dns->hostnames[i]);
            if (new_hostnames != NULL && new_hostnames[i] != NULL) {
                char *canonical_name = new_hostnames[i];
                
                /* Validate hostname for security */
                size_t name_len = strlen(canonical_name);
                if (name_len > 255 || name_len == 0) {
                    log_warn("Invalid hostname length %zu for addr %"PRIu32", using default", name_len, i);
                    string_copy(&dns->hostnames[i], dns->hostname.data, dns->hostname.len);
                } else {
                    bool valid = true;
                    for (size_t j = 0; j < name_len; j++) {
                        char c = canonical_name[j];
                        if (!isalnum(c) && c != '-' && c != '.' && c != '_') {
                            valid = false;
                            break;
                        }
                    }
                    
                    if (valid) {
                        string_copy(&dns->hostnames[i], canonical_name, name_len);
                        log_warn("captured canonical hostname for addr %"PRIu32": %s", i, canonical_name);
                    } else {
                        log_warn("Invalid hostname characters for addr %"PRIu32", using default", i);
                        string_copy(&dns->hostnames[i], dns->hostname.data, dns->hostname.len);
                    }
                }
            } else {
                string_copy(&dns->hostnames[i], dns->hostname.data, dns->hostname.len);
                log_warn("no canonical name for addr %"PRIu32", using original: %.*s", 
                         i, dns->hostname.len, dns->hostname.data);
            }
        }
        
        dns->last_resolved = now;
        log_warn("initialized with %"PRIu32" addresses for '%.*s'",
                  dns->naddresses, dns->hostname.len, dns->hostname.data);
        
        /* Clean up temporary hostname array */
        free_hostnames_temp(new_hostnames, new_naddresses);

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

            /*
             * Cap the accumulate-append at max_addresses (16). The eager
             * arrays below are realloc-grown per new address, but the lazy
             * arrays (zone_ids/health_scores/last_health_check) are calloc'd
             * ONCE to max_addresses and never grown. Letting naddresses pass
             * max_addresses would make later zone/health indexing of those
             * lazy arrays write/read out of bounds (heap corruption). It also
             * breaks the naddresses <= max_addresses invariant that
             * server_dns_remove_address_at() relies on for its tail-clear.
             * A rotating reader endpoint can yield >16 distinct IPs over the
             * accumulation window; drop the surplus with a warning. For our
             * deployment (<=5 replicas) 16 is ample.
             */
            if (dns->naddresses >= dns->max_addresses) {
                log_warn("DNS address cap %"PRIu32" reached for '%.*s', "
                         "ignoring new address", dns->max_addresses,
                         dns->hostname.len, dns->hostname.data);
                continue;
            }

            /*
             * Grow the 8 eager parallel arrays, ALL-OR-NOTHING.
             *
             * realloc(p,n) frees/relocates the old block on success but returns
             * NULL and leaves the ORIGINAL p valid on failure. So we realloc
             * each array straight back into its dns-> field, checking each
             * before the next: on any failure we goto nomem WITHOUT bumping
             * dns->naddresses. The failed array's dns->X is unchanged (old block
             * intact); the already-grown arrays were written back (valid, just
             * larger than naddresses); the rest are still at the old size. Since
             * naddresses is not incremented, every array's allocation is >=
             * naddresses, so no dns-> pointer dangles at a freed block and
             * nothing is leaked (fix #2's helper invariant still holds). The
             * next resolve simply reallocs again.
             *
             * The earlier bug realloc'd into LOCALS and wrote them back only
             * after a combined NULL-check; a later NULL then returned with every
             * already-grown dns-> array pointing at the block realloc had freed
             * (use-after-free) and the grown blocks leaked.
             */
            uint32_t new_size = dns->naddresses + 1;
            void *p;

            p = nc_realloc(dns->addresses, new_size * sizeof(*dns->addresses));
            if (p == NULL) goto nomem; dns->addresses = p;
            p = nc_realloc(dns->latencies, new_size * sizeof(*dns->latencies));
            if (p == NULL) goto nomem; dns->latencies = p;
            p = nc_realloc(dns->last_latency_check, new_size * sizeof(*dns->last_latency_check));
            if (p == NULL) goto nomem; dns->last_latency_check = p;
            p = nc_realloc(dns->failure_counts, new_size * sizeof(*dns->failure_counts));
            if (p == NULL) goto nomem; dns->failure_counts = p;
            p = nc_realloc(dns->last_seen, new_size * sizeof(*dns->last_seen));
            if (p == NULL) goto nomem; dns->last_seen = p;
            p = nc_realloc(dns->last_connected, new_size * sizeof(*dns->last_connected));
            if (p == NULL) goto nomem; dns->last_connected = p;
            p = nc_realloc(dns->request_counts, new_size * sizeof(*dns->request_counts));
            if (p == NULL) goto nomem; dns->request_counts = p;
            p = nc_realloc(dns->hostnames, new_size * sizeof(*dns->hostnames));
            if (p == NULL) goto nomem; dns->hostnames = p;

            /* Add the new address */
            memcpy(&dns->addresses[dns->naddresses], &new_addresses[i], sizeof(struct sockinfo));
            dns->latencies[dns->naddresses] = DEFAULT_LATENCY_USEC;
            dns->last_latency_check[dns->naddresses] = 0;
            dns->failure_counts[dns->naddresses] = 0;
            dns->last_seen[dns->naddresses] = now;
            dns->last_connected[dns->naddresses] = 0;
            dns->request_counts[dns->naddresses] = 0;
            
            /* Initialize hostname for new address from captured canonical name */
            string_init(&dns->hostnames[dns->naddresses]);
            if (new_hostnames != NULL && i < new_naddresses && new_hostnames[i] != NULL) {
                char *canonical_name = new_hostnames[i];
                string_copy(&dns->hostnames[dns->naddresses], canonical_name, strlen(canonical_name));
                log_warn("using canonical hostname for new addr: %s", canonical_name);
            } else {
                string_copy(&dns->hostnames[dns->naddresses], dns->hostname.data, dns->hostname.len);
                log_warn("no canonical name for new addr, using original hostname");
            }
            
            dns->naddresses++;
            
            /* Update dynamic server connections after adding new address */
            server_update_dynamic_connections(server);
            
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
            
            /* Force immediate zone re-analysis for new servers */
            if (pool && pool->zone_aware) {
                dns->last_zone_analysis = 0; /* Reset to force immediate re-analysis */
                log_warn("🌍 forcing zone re-analysis for new server %s", addr_str);
            }

            /* Append done; advance to the next resolved address. */
            continue;

        nomem:
            /*
             * A grow realloc failed. dns->naddresses was NOT incremented, so
             * every dns-> array is still allocated to >= naddresses (the failed
             * one to its old size, the already-grown ones one larger) -- no
             * dangling pointer, no leak. Free BOTH temporary lists the success
             * tail frees: the resolved-address list AND the parallel hostname
             * array (via free_hostnames_temp, same as every other exit). The
             * paths are mutually exclusive returns, so no double-free. Bail.
             */
            log_error("failed to allocate memory for new DNS address");
            if (new_addresses) nc_free(new_addresses);
            free_hostnames_temp(new_hostnames, new_naddresses);
            return NC_ENOMEM;
        }
    }

    /* Now expire old addresses that haven't been seen recently */
    uint32_t removed_count = 0;
    for (i = 0; i < dns->naddresses; ) {
        int64_t time_since_seen = now - dns->last_seen[i];
        bool should_expire = false;
        
        /* Expire address if it hasn't been seen in DNS for expiration_threshold time */
        /* For inactive addresses, time-based expiration is sufficient */
        /* For currently active address, use a longer threshold but still expire if not seen in DNS */
        if (time_since_seen > expiration_threshold) {
            if (i == server->current_addr_idx) {
                /* Current address: use 2x expiration threshold to be more conservative */
                should_expire = (time_since_seen > (2 * expiration_threshold));
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
                log_warn("🕐 expiring current address %s for '%.*s' (not seen in DNS for %"PRId64"s, exceeds 2x threshold)",
                         addr_str, dns->hostname.len, dns->hostname.data, 
                         time_since_seen / 1000000);
            } else {
                log_warn("🕐 expiring inactive address %s for '%.*s' (not seen in DNS for %"PRId64"s)",
                         addr_str, dns->hostname.len, dns->hostname.data, 
                         time_since_seen / 1000000);
            }
            
            /* Remove this address, shifting every parallel array down. */
            server_dns_remove_address_at(dns, i);
            removed_count++;

            /*
             * Keep server->current_addr_idx pointing at the same logical
             * address. Removing an address at index i < current_addr_idx
             * shifts the selected address down one, so the index must follow.
             * If the selected address itself was removed (i == current), the
             * selection re-runs on next use; just keep the index in range.
             *
             * This rule is mirrored by apply_current_idx_fixup() in
             * tests/unit/test_remove_address.c -- keep the two in sync.
             */
            if (i < server->current_addr_idx) {
                server->current_addr_idx--;
            } else if (i == server->current_addr_idx &&
                       server->current_addr_idx >= dns->naddresses) {
                server->current_addr_idx = (dns->naddresses > 0) ?
                                           dns->naddresses - 1 : 0;
            }
            /* Don't increment i since we shifted everything down */
        } else {
            i++;
        }
    }
    
    if (removed_count > 0) {
        log_warn("expired %"PRIu32" addresses for '%.*s', %"PRIu32" addresses remaining",
                 removed_count, dns->hostname.len, dns->hostname.data, dns->naddresses);
    }
    
    /* Free the temporary arrays */
    if (new_addresses) {
        nc_free(new_addresses);
    }
    free_hostnames_temp(new_hostnames, new_naddresses);

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
    
    /* Check if current server is still healthy - if not, force immediate re-selection */
    if (server->current_addr_idx < dns->naddresses && 
        !server_is_healthy(server, server->current_addr_idx)) {
        log_warn("🚨 CURRENT server addr %"PRIu32" is now UNHEALTHY for '%.*s' - forcing re-selection", 
                 server->current_addr_idx, server->pname.len, server->pname.data);
    }
    
    /* Find best address and collect all healthy servers */
    for (i = 0; i < dns->naddresses; i++) {
        /* Enhanced health checking */
        if (!server_is_healthy(server, i)) {
            if (i == server->current_addr_idx) {
                log_warn("⚠️  current server addr %"PRIu32" marked unhealthy for '%.*s'", 
                         i, server->pname.len, server->pname.data);
            }
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
        log_error("🚨 NO HEALTHY SERVERS found for '%.*s' - all %"PRIu32" addresses are unhealthy!", 
                  server->pname.len, server->pname.data, dns->naddresses);
        nc_free(healthy_servers);
        return 0;
    }
    
    /* If current server is unhealthy, it should NOT be in healthy_servers list */
    /* This ensures we ALWAYS switch away from unhealthy current servers */
    bool current_is_healthy = false;
    for (i = 0; i < healthy_count; i++) {
        if (healthy_servers[i] == server->current_addr_idx) {
            current_is_healthy = true;
            break;
        }
    }
    
    if (!current_is_healthy && server->current_addr_idx < dns->naddresses) {
        log_warn("🔄 current server addr %"PRIu32" excluded from healthy list - will force switch", 
                 server->current_addr_idx);
    }
    
    if (healthy_count == 1) {
        /* Only one healthy server, use it */
        nc_free(healthy_servers);
        log_debug(LOG_INFO, "only one healthy server: address %"PRIu32" for '%.*s' (latency: %"PRIu32"us)",
                  best_idx, server->pname.len, server->pname.data, dns->latencies[best_idx]);
        return best_idx;
    }
    
    /* Zone-aware server selection with high preference for same-zone servers */
    if (pool->zone_aware && dns->zone_ids != NULL && dns->naddresses > 0) {
        uint32_t same_zone_count = 0;
        uint32_t *same_zone_servers = nc_alloc(dns->naddresses * sizeof(uint32_t));
        uint32_t *other_zone_servers = nc_alloc(dns->naddresses * sizeof(uint32_t));
        uint32_t other_zone_count = 0;
        
        if (same_zone_servers == NULL || other_zone_servers == NULL) {
            log_error("Failed to allocate zone server arrays for %"PRIu32" addresses", dns->naddresses);
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
        
        /* Aggressive prioritization of untested servers */
        uint32_t untested_server = UINT32_MAX;
        for (i = 0; i < healthy_count; i++) {
            uint32_t idx = healthy_servers[i];
            /* If latency is still default (untested) */
            if (dns->latencies[idx] == DEFAULT_LATENCY_USEC) {
                int64_t now = nc_usec_now();
                int64_t time_since_seen = (now > 0 && dns->last_seen[idx] > 0) ? 
                                          (now - dns->last_seen[idx]) : 0;
                /* Prioritize any untested server discovered recently (within 2 minutes) */
                if (time_since_seen < 120000000LL) {
                    untested_server = idx;
                    /* Get the CNAME for this specific address */
                    const char *cname_str = "unknown";
                    if (dns->hostnames != NULL && idx < dns->naddresses && dns->hostnames[idx].data != NULL) {
                        cname_str = (const char *)dns->hostnames[idx].data;
                    }
                    
                    log_warn("🚀 AGGRESSIVE: prioritizing untested CNAME '%s' (addr %"PRIu32") for '%.*s' (latency=%"PRIu32"μs, discovered %"PRId64"s ago)", 
                             cname_str, idx, server->pname.len, server->pname.data, 
                             dns->latencies[idx], time_since_seen / 1000000);
                    break;
                }
            }
        }
        
        /* If we found an untested server, use it immediately to get real latency measurement */
        if (untested_server != UINT32_MAX) {
            stats_server_set(pool->ctx, server, current_latency_us, dns->latencies[untested_server]);
            nc_free(healthy_servers);
            nc_free(same_zone_servers);
            nc_free(other_zone_servers);
            return untested_server;
        }
        
        /* Periodically probe other servers to refresh their latency measurements */
        /* This prevents servers from getting "stuck" with old high latency readings */
        /* Use server-specific counter to avoid thread safety issues */
        if (dns->last_zone_analysis == 0) {
            dns->last_zone_analysis = nc_usec_now(); /* Initialize probe counter base */
        }
        uint32_t probe_counter = (uint32_t)((nc_usec_now() - dns->last_zone_analysis) / 1000000); /* Seconds since init */
        
        /* Every 5th selection (~5-10 seconds with typical traffic), probe a different server */
        if (probe_counter % 5 == 0 && healthy_count > 1) {
            uint32_t probe_idx = UINT32_MAX;
            int64_t now = nc_usec_now();
            
            /* Find servers that haven't been measured recently */
            for (i = 0; i < healthy_count; i++) {
                uint32_t idx = healthy_servers[i];
                if (idx != server->current_addr_idx) { /* Don't probe current server */
                    int64_t time_since_latency_check = (now > 0 && dns->last_latency_check[idx] > 0) ? 
                                                       (now - dns->last_latency_check[idx]) : LLONG_MAX;
                    /* If latency hasn't been checked in 5+ minutes, probe this server */
                    if (time_since_latency_check > 300000000LL) { /* 5 minutes */
                        probe_idx = idx;
                        /* Get the CNAME for this specific address */
                        const char *cname_str = "unknown";
                        if (dns->hostnames != NULL && idx < dns->naddresses && dns->hostnames[idx].data != NULL) {
                            cname_str = (const char *)dns->hostnames[idx].data;
                        }
                        
                        log_warn("🔄 probing CNAME '%s' (addr %"PRIu32") for '%.*s' (latency not checked for %"PRId64"s)", 
                                 cname_str, idx, server->pname.len, server->pname.data, 
                                 time_since_latency_check / 1000000);
                        break;
                    }
                }
            }
            
            if (probe_idx != UINT32_MAX) {
                stats_server_set(pool->ctx, server, current_latency_us, dns->latencies[probe_idx]);
                nc_free(healthy_servers);
                nc_free(same_zone_servers);
                nc_free(other_zone_servers);
                return probe_idx;
            }
        }
        
        /* Apply zone-aware routing: zone_weight% preference for same-zone servers */
        /* random() is seeded once unconditionally at process startup in
         * nc_pre_run() (src/nc.c), so it is seeded here for every pool regardless
         * of distribution -- better distribution than rand() and not the
         * unseeded, lock-stepped default sequence. (srandom() also runs on the
         * distribution:random hashing path in hashkit/nc_random.c, but that does
         * not cover distribution:ketama, which is why the startup seed exists.) */
        rand_val = (uint32_t)random() % 100;
        
        /* Occasionally (~5% of time) probe a random server to refresh latency measurements */
        if (rand_val >= 95 && healthy_count > 1) {
            uint32_t random_probe = healthy_servers[random() % healthy_count];
            if (random_probe != server->current_addr_idx) {
                log_debug(LOG_INFO, "🎲 random latency probe: selecting addr %"PRIu32" for '%.*s' (current latency: %"PRIu32"μs)", 
                          random_probe, server->pname.len, server->pname.data, dns->latencies[random_probe]);
                
                stats_server_set(pool->ctx, server, current_latency_us, dns->latencies[random_probe]);
                nc_free(healthy_servers);
                nc_free(same_zone_servers);
                nc_free(other_zone_servers);
                return random_probe;
            }
        }
        
        if (same_zone_count > 0 && rand_val < pool->zone_weight) {
            /* Select from same-zone servers */
            selected_idx = same_zone_servers[random() % same_zone_count];
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
            selected_idx = healthy_servers[random() % healthy_count];
            
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

static void
server_update_dynamic_connections(struct server *server)
{
    struct server_pool *pool;
    struct server_dns *dns;
    
    if (server == NULL || !server->is_dynamic) {
        return;
    }
    
    pool = server->owner;
    dns = server->dns;
    
    if (pool == NULL || dns == NULL || !pool->dynamic_server_connections) {
        return;
    }
    
    /* Calculate optimal connections: min(dns_addresses, max_server_connections) */
    uint32_t optimal_connections = dns->naddresses;
    if (optimal_connections > pool->max_server_connections) {
        optimal_connections = pool->max_server_connections;
    }
    
    /* Ensure at least 1 connection */
    if (optimal_connections < 1) {
        optimal_connections = 1;
    }
    
    /* Update current_server_connections if it changed */
    if (pool->current_server_connections != optimal_connections) {
        uint32_t old_connections = pool->current_server_connections;
        pool->current_server_connections = optimal_connections;
        
        log_warn("📈 dynamic server_connections updated for '%.*s': %"PRIu32" → %"PRIu32" (dns_addresses: %"PRIu32")",
                 server->pname.len, server->pname.data, 
                 old_connections, optimal_connections, dns->naddresses);
    }
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
    
    /*
     * Update latency with an exponential moving average.
     *
     * The stored field stays uint32_t, but the math is done in uint64_t and
     * saturated to UINT32_MAX. A timed-out replica reports a very large latency;
     * the old 32-bit `old * 9 + new` overflowed and wrapped to a SMALL value,
     * which then mis-classified a slow/dead replica as fast and corrupted
     * zone selection. Clamp the sample to [0, UINT32_MAX] first (negative is
     * nonsensical), then never let the EWMA wrap.
     */
    uint32_t old_latency = dns->latencies[addr_idx];
    uint64_t sample = (latency < 0) ? 0 :
                      ((uint64_t)latency > UINT32_MAX ? UINT32_MAX : (uint64_t)latency);
    if (dns->latencies[addr_idx] == DEFAULT_LATENCY_USEC) {
        dns->latencies[addr_idx] = (uint32_t)sample; /* sample already <= UINT32_MAX */
        log_debug(LOG_INFO, "⏱️  initial latency for '%.*s' addr %"PRIu32": %"PRIu32"us",
                  server->pname.len, server->pname.data, addr_idx, dns->latencies[addr_idx]);
    } else {
        /* 90% old value, 10% new value -- computed in 64-bit, saturated. */
        uint64_t ewma = ((uint64_t)dns->latencies[addr_idx] * 9 + sample) / 10;
        if (ewma > UINT32_MAX) {
            ewma = UINT32_MAX;
        }
        dns->latencies[addr_idx] = (uint32_t)ewma;
        log_debug(LOG_VERB, "⏱️  updated latency for '%.*s' addr %"PRIu32": %"PRIu32"us → %"PRIu32"us (new: %"PRId64"us)",
                  server->pname.len, server->pname.data, addr_idx, old_latency, dns->latencies[addr_idx], latency);
    }
    
    dns->last_latency_check[addr_idx] = nc_usec_now();
    dns->last_connected[addr_idx] = nc_usec_now();
    
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
        "    \"current_server_connections\": %"PRIu32",\n"
        "    \"max_server_connections\": %"PRIu32",\n"
        "    \"dynamic_server_connections\": %s,\n"
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
        cross_zone_count,
        pool->current_server_connections,
        pool->max_server_connections,
        pool->dynamic_server_connections ? "true" : "false");
    


    if (written >= buffer_size) {
        log_warn("🚨 BUFFER OVERFLOW: Stats buffer too small! written=%zu, buffer_size=%zu", written, buffer_size);
        return NC_ERROR;
    }
    
    
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
        
        /* Calculate seconds since last seen in DNS and last used for connection */
        int64_t now = nc_usec_now();
        int64_t last_seen_in_dns_lookup = (now > 0 && dns->last_seen[i] > 0) ? 
                                           (now - dns->last_seen[i]) / 1000000 : -1;
        int64_t last_chosen_for_connection = (now > 0 && dns->last_connected[i] > 0) ? 
                                              (now - dns->last_connected[i]) / 1000000 : -1;
        
        /* Get hostname for this address */
        const char *cname_str = "unknown";
        if (dns->hostnames != NULL && i < dns->naddresses && dns->hostnames[i].data != NULL) {
            cname_str = (const char *)dns->hostnames[i].data;
        } else {
            log_warn("hostname missing for addr %"PRIu32": hostnames=%p, i=%"PRIu32", naddresses=%"PRIu32, 
                     i, dns->hostnames, i, dns->naddresses);
        }
        
        addr_written = snprintf(buffer + written, buffer_size - written,
            "      {\n"
            "        \"index\": %"PRIu32",\n"
            "        \"ip\": \"%s\",\n"
            "        \"cname\": \"%s\",\n"
            "        \"latency_us\": %"PRIu32",\n"
            "        \"failures\": %"PRIu32",\n"
            "        \"zone_id\": %"PRIu32",\n"
            "        \"zone_type\": \"%s\",\n"
            "        \"zone_weight\": %"PRIu32",\n"
            "        \"healthy\": %s,\n"
            "        \"current\": %s,\n"
            "        \"last_seen_in_dns_lookup\": %"PRId64",\n"
            "        \"last_chosen_for_connection\": %"PRId64",\n"
            "        \"requests\": %"PRIu64"\n"
            "      }%s\n",
            i, addr_str, cname_str, dns->latencies[i], dns->failure_counts[i],
            zone_id, zone_type, zone_weight, 
            is_healthy ? "true" : "false",
            (i == server->current_addr_idx) ? "true" : "false",
            last_seen_in_dns_lookup,
            last_chosen_for_connection,
            dns->request_counts[i],
            (i < dns->naddresses - 1) ? "," : "");
        
        written += addr_written;
        
        
        if (written >= buffer_size) {
            log_warn("🚨 BUFFER OVERFLOW: After address %"PRIu32", buffer exceeded! written=%zu, buffer_size=%zu", 
                     i, written, buffer_size);
            return NC_ERROR;
        }
    }
    
    {
        size_t final_written = snprintf(buffer + written, buffer_size - written,
            "    ]\n"
            "  }");
        written += final_written;
        
    }
    
    if (written >= buffer_size) {
        log_warn("🚨 FINAL BUFFER OVERFLOW: Stats generation failed! written=%zu, buffer_size=%zu", 
                 written, buffer_size);
        return NC_ERROR;
    }
    
    return NC_OK;
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
        if (dns->failure_counts[i] <= dns->consecutive_failures_limit) { /* Only consider healthy servers */
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
     * Percentage-based zone detection: servers within 10% of minimum latency are "same-az"
     * This approach scales automatically to any latency environment
     */
    uint32_t percentage_threshold = min_latency + (min_latency / 10); /* 10% above minimum */
    
    /* Fallback to range-based for very small latencies where 10% might be too small */
    uint32_t latency_range = max_latency - min_latency;
    uint32_t range_threshold = min_latency + (latency_range / 6); /* 15% of range */
    
    /* Use the larger of the two thresholds to ensure meaningful separation */
    low_latency_threshold = (percentage_threshold > range_threshold) ? 
                           percentage_threshold : range_threshold;
    
    /* Assign zone IDs based on statistical grouping */
    dns->local_zone_id = 1; /* Local zone is always 1 */
    dns->next_zone_id = 2;
    
    for (i = 0; i < dns->naddresses; i++) {
        if (dns->failure_counts[i] > dns->consecutive_failures_limit) {
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

        /*
         * All-or-nothing + self-healing. The pair is indexed in lock-step
         * below (last_health_check[addr_idx], then health_scores[addr_idx]). If
         * one calloc succeeded and the other returned NULL, leaving the live one
         * set would make the next call skip this init block (health_scores !=
         * NULL) and then deref the NULL partner -> crash. So on any partial
         * failure free BOTH, NULL BOTH, and bail; the next call sees both NULL
         * and retries the init cleanly.
         */
        if (dns->health_scores == NULL || dns->last_health_check == NULL) {
            if (dns->health_scores != NULL)     { nc_free(dns->health_scores);     dns->health_scores = NULL; }
            if (dns->last_health_check != NULL) { nc_free(dns->last_health_check); dns->last_health_check = NULL; }
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
        health_score -= (failures * 20); 
    }
    
    /* Reduce score for high latency (>100ms = unhealthy) */
    if (latency > 100000) { /* 100ms in microseconds */
        health_score -= ((latency - 100000) / 10000); /* -1 point per 10ms over 100ms */
    }
    
    /* Ensure score doesn't go below 0 - handle underflow properly */
    if (health_score > 10000 || health_score == UINT32_MAX) health_score = 0;
    
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
    
    /* Check if address hasn't been seen in DNS recently */
    int64_t now = nc_usec_now();
    int64_t time_since_seen = (now > 0 && dns->last_seen[addr_idx] > 0) ? 
                              (now - dns->last_seen[addr_idx]) : 0;
    struct server_pool *pool = server->owner;
    int64_t stale_threshold = pool ? pool->dns_expiration_minutes : (5 * 60000000LL); /* Use config or 5 minutes default */
    
     /* Consider healthy if health score > 30, failures < limit, and recently seen in DNS */
    bool is_healthy = (dns->health_scores != NULL && dns->health_scores[addr_idx] > 30) &&
                     (dns->failure_counts[addr_idx] < dns->consecutive_failures_limit) &&
                     (time_since_seen < stale_threshold);
    
    if (time_since_seen >= stale_threshold) {
        log_debug(LOG_INFO, "🕐 marking addr %"PRIu32" as unhealthy: not seen in DNS for %"PRId64" seconds",
                  addr_idx, time_since_seen / 1000000);
    }
    
    log_debug(LOG_VVERB, "🏥 health status addr %"PRIu32": %s (score=%"PRIu32", failures=%"PRIu32", last_seen=%"PRId64"s ago)",
              addr_idx, is_healthy ? "healthy" : "unhealthy",
              dns->health_scores ? dns->health_scores[addr_idx] : 0,
              dns->failure_counts[addr_idx],
              time_since_seen / 1000000);
    
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
        /*
         * No "-ro"/"read"/"replica" hostname sniffing here: it only ever logged
         * a cosmetic line and had zero routing effect. Read-vs-write routing is
         * now driven solely by the explicit dynamic_endpoint flag (see
         * conf_server / fix dropping the unsafe -ro auto-detection), so keying
         * off a substring of the hostname would be misleading.
         */
    }

    return NC_OK;
}
