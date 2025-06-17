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
#include <arpa/inet.h>
#include <nc_core.h>
#include <nc_conf.h>
#include <nc_server.h>
#include <nc_proxy.h>
#include <nc_process.h>

static uint32_t ctx_id; /* context generation */

static void
adjust_openfiles_limit(rlim_t maxfiles) {
    // Note: we just improve the open files to a higher num,
    // while the twemproxy didn't support max client connections now.
    struct rlimit limit;
    rlim_t old_limit, best_limit = maxfiles, decr_step = 16;
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0 || best_limit <= limit.rlim_cur) {
        return;
    }
    old_limit = limit.rlim_cur;
    while(best_limit > old_limit) {
        limit.rlim_cur = best_limit;
        limit.rlim_max = best_limit;
        if (setrlimit(RLIMIT_NOFILE,&limit) != -1) break;
        /* We failed to set file limit to 'bestlimit'. Try with a
         * smaller limit decrementing by a few FDs per iteration. */
        if (best_limit < decr_step) break;
        best_limit -= decr_step;
    }
}

static rstatus_t
core_calc_connections(struct context *ctx)
{
    int status;
    struct rlimit limit;

    adjust_openfiles_limit((rlim_t)ctx->cf->global.max_openfiles);
    status = getrlimit(RLIMIT_NOFILE, &limit);
    if (status < 0) {
        log_error("getrlimit failed: %s", strerror(errno));
        return NC_ERROR;
    }

    ctx->max_nfd = (uint32_t)limit.rlim_cur;
    ctx->max_ncconn = ctx->max_nfd - ctx->max_nsconn - RESERVED_FDS;
    log_warn("max fds %"PRIu32" max client conns %"PRIu32" "
              "max server conns %"PRIu32"", ctx->max_nfd, ctx->max_ncconn,
              ctx->max_nsconn);

    return NC_OK;
}

struct context *
core_ctx_create(struct instance *nci) {
    rstatus_t status;
    struct context *ctx;

    ctx = nc_alloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->id = nci->id;
    ctx->cf = NULL;
    ctx->stats = NULL;
    ctx->evb = NULL;
    array_null(&ctx->pool);
    ctx->max_timeout = nci->stats_interval;
    ctx->timeout = ctx->max_timeout;
    ctx->max_nfd = 0;
    ctx->max_ncconn = 0;
    ctx->max_nsconn = 0;
    ctx->shared_mem = NULL;

    /* parse and create configuration */
    ctx->cf = conf_create(nci->conf_filename);
    if (ctx->cf == NULL) {
        nc_free(ctx);
        return NULL;
    }

    /* initialize server pool from configuration */
    status = server_pool_init(&ctx->pool, &ctx->cf->pool, ctx);
    if (status != NC_OK) {
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    /*
     * Get rlimit and calculate max client connections after we have
     * calculated max server connections
     */
    status = core_calc_connections(ctx);
    if (status != NC_OK) {
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    log_debug(LOG_VVERB, "created ctx %p id %"PRIu32"", ctx, ctx->id);
    return ctx;
}

static stats_loop_t
get_loop_callback(char role, int processes)
{
    if (role == ROLE_MASTER) {
        if (processes >= 1) {
            return stats_master_loop_callback;
        } else {
            return stats_loop_callback;
        }
    }
    return NULL;
}

rstatus_t
core_init_stats(struct instance *nci)
{
    stats_loop_t loop;
    struct context *ctx;
    ctx = nci->ctx;

    loop = get_loop_callback(nci->role, nci->ctx->cf->global.worker_processes);
    /* create stats per server pool */
    ctx->stats = stats_create(nci->stats_port, nci->stats_addr, nci->stats_interval,
                              nci->hostname, &ctx->pool, loop);
    if (ctx->stats == NULL) {
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NC_ERROR;
    }
    ctx->stats->owner = ctx;

    return NC_OK;
}

rstatus_t
core_init_listener(struct instance *nci)
{
    rstatus_t status;
    struct context *ctx;
    ctx = nci->ctx;

    /* initialize proxy per server pool */
    status = proxy_init(ctx);
    if (status != NC_OK) {
        proxy_deinit(ctx);
        server_pool_disconnect(ctx);
        event_base_destroy(ctx->evb);
        stats_destroy(ctx->stats);
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NC_ERROR;
    }
    return NC_OK;
}

rstatus_t
core_init_instance(struct instance *nci){
    rstatus_t status;
    struct context *ctx;
    ctx = nci->ctx;

    /* initialize event handling for client, proxy and server */
    ctx->evb = event_base_create(EVENT_SIZE, &core_core);
    if (ctx->evb == NULL) {
        stats_destroy(ctx->stats);
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NC_ERROR;
    }

    /* preconnect? servers in server pool */
    status = server_pool_preconnect(ctx);
    if (status != NC_OK) {
        server_pool_disconnect(ctx);
        event_base_destroy(ctx->evb);
        stats_destroy(ctx->stats);
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return status;
    }

    // add proxy listening sockets to event base
    status = proxy_post_init(ctx);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

void
core_ctx_destroy(struct context *ctx)
{
    log_debug(LOG_VVERB, "destroy ctx %p id %"PRIu32"", ctx, ctx->id);
    proxy_deinit(ctx);
    server_pool_disconnect(ctx);
    server_pool_deinit(&ctx->pool);
    conf_destroy(ctx->cf);
    stats_destroy(ctx->stats);
    if (ctx->shared_mem != NULL) {
        nc_shared_mem_free(ctx->shared_mem, SHARED_MEMORY_SIZE);
    }
    event_base_destroy(ctx->evb);
    nc_free(ctx);
}

struct context *
core_start(struct instance *nci)
{
    rstatus_t status;
    struct context *ctx;

    mbuf_init(nci);
    msg_init();
    conn_init();

    ctx = core_ctx_create(nci);
    if (ctx != NULL) {
        nci->ctx = ctx;
        if (ctx->cf->global.worker_processes < 1) {
            status = nc_single_process_cycle(nci);
        } else {
            status = nc_multi_processes_cycle(nci);
        }
        if (status == NC_OK) {
            return ctx;
        }
    }

    conn_deinit();
    msg_deinit();
    mbuf_deinit();

    return NULL;
}

void
core_stop(struct context *ctx)
{
    conn_deinit();
    msg_deinit();
    mbuf_deinit();
    core_ctx_destroy(ctx);
}

static rstatus_t
core_recv(struct context *ctx, struct conn *conn)
{
    rstatus_t status;

    status = conn->recv(ctx, conn);
    if (status != NC_OK) {
        log_debug(LOG_INFO, "recv on %c %d failed: %s",
                  conn->client ? 'c' : (conn->proxy ? 'p' : 's'), conn->sd,
                  strerror(errno));
    }

    return status;
}

static rstatus_t
core_send(struct context *ctx, struct conn *conn)
{
    rstatus_t status;

    status = conn->send(ctx, conn);
    if (status != NC_OK) {
        log_debug(LOG_INFO, "send on %c %d failed: status: %d errno: %d %s",
                  conn->client ? 'c' : (conn->proxy ? 'p' : 's'), conn->sd,
                  status, errno, strerror(errno));
    }

    return status;
}

static void
core_close(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    char type, *addrstr;

    ASSERT(conn->sd > 0);

    if (conn->client) {
        type = 'c';
        addrstr = nc_unresolve_peer_desc(conn->sd);
    } else {
        type = conn->proxy ? 'p' : 's';
        addrstr = nc_unresolve_addr(conn->addr, conn->addrlen);
    }
    log_debug(LOG_NOTICE, "close %c %d '%s' on event %04"PRIX32" eof %d done "
              "%d rb %zu sb %zu%c %s", type, conn->sd, addrstr, conn->events,
              conn->eof, conn->done, conn->recv_bytes, conn->send_bytes,
              conn->err ? ':' : ' ', conn->err ? strerror(conn->err) : "");

    status = event_del_conn(ctx->evb, conn);
    if (status < 0) {
        log_warn("event del conn %c %d failed, ignored: %s",
                 type, conn->sd, strerror(errno));
    }

    conn->close(ctx, conn);
}

static void
core_error(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    char type = conn->client ? 'c' : (conn->proxy ? 'p' : 's');

    status = nc_get_soerror(conn->sd);
    if (status < 0) {
        log_warn("get soerr on %c %d failed, ignored: %s", type, conn->sd,
                  strerror(errno));
    }
    conn->err = errno;

    core_close(ctx, conn);
}

static void
core_dns_maintenance(struct context *ctx)
{
    uint32_t i, j, k, npool, nserver;
    static int64_t last_dns_check = 0;
    static int64_t last_forced_probe = 0;
    int64_t now;
    
    now = nc_usec_now();
    if (now < 0) {
        return;
    }
    
    /* Rate limit DNS checks to every 5 seconds */
    if ((now - last_dns_check) < 5000000LL) {
        return;
    }
    
    last_dns_check = now;
    
    /* Check all server pools for dynamic DNS servers */
    npool = array_n(&ctx->pool);
    for (i = 0; i < npool; i++) {
        struct server_pool *pool = array_get(&ctx->pool, i);
        
        nserver = array_n(&pool->server);
        for (j = 0; j < nserver; j++) {
            struct server *server = array_get(&pool->server, j);
            
            if (server->is_dynamic && server->dns != NULL) {
                /* Check if DNS resolution is needed */
                if (server_should_resolve_dns(server)) {
                    rstatus_t status = server_dns_check_update(server);
                    if (status == NC_OK) {
                        log_warn("🔄 periodic DNS update successful for '%.*s'",
                                  server->pname.len, server->pname.data);
                    } else {
                        log_warn("⚠️  periodic DNS update failed for '%.*s'",
                                  server->pname.len, server->pname.data);
                    }
                }
                
                /* FORCED PROBING: Periodic forced probing every 10 seconds to ensure all servers get tested */
                if ((now - last_forced_probe) >= 10000000LL) { /* 10 seconds */
                    struct server_dns *dns = server->dns;
                    bool found_untested = false;
                    
                    /* Look for servers with default latency (untested) */
                    for (k = 0; k < dns->naddresses; k++) {
                        if (dns->latencies[k] == 100) { /* DEFAULT_LATENCY_USEC */
                            char addr_str[INET6_ADDRSTRLEN];
                            
                            /* Convert address to string for logging */
                            if (dns->addresses[k].family == AF_INET) {
                                struct sockaddr_in *sin = (struct sockaddr_in *)&dns->addresses[k].addr;
                                inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
                            } else if (dns->addresses[k].family == AF_INET6) {
                                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&dns->addresses[k].addr;
                                inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
                            } else {
                                snprintf(addr_str, sizeof(addr_str), "unknown");
                            }
                            
                            log_warn("🚀 FORCED PROBE: Found untested server %s (addr_idx %"PRIu32") for '%.*s' - initiating connection to measure latency",
                                     addr_str, k, server->pname.len, server->pname.data);
                            
                            /* Force test this server by temporarily setting it as current */
                            uint32_t old_current = server->current_addr_idx;
                            server->current_addr_idx = k;
                            server->info = dns->addresses[k];
                            
                            /* Try to establish a test connection */
                            struct conn *test_conn = server_conn(server);
                            if (test_conn != NULL) {
                                rstatus_t connect_status = server_connect(ctx, server, test_conn);
                                if (connect_status == NC_OK) {
                                    log_warn("✅ FORCED PROBE: Successfully connected to %s (addr_idx %"PRIu32") for '%.*s'",
                                             addr_str, k, server->pname.len, server->pname.data);
                                    /* Connection successful - latency will be measured in the connection callback */
                                    server_close(ctx, test_conn);
                                } else {
                                    log_warn("❌ FORCED PROBE: Failed to connect to %s (addr_idx %"PRIu32") for '%.*s' - marking with high latency",
                                             addr_str, k, server->pname.len, server->pname.data);
                                    /* Connection failed - set a high latency to indicate failure */
                                    dns->latencies[k] = 500000; /* 500ms - high latency for failed connection */
                                    server_close(ctx, test_conn);
                                }
                            } else {
                                log_warn("❌ FORCED PROBE: Could not create test connection for %s (addr_idx %"PRIu32")",
                                         addr_str, k);
                                dns->latencies[k] = 500000; /* 500ms - high latency for failed connection */
                            }
                            
                            /* Restore original current address */
                            server->current_addr_idx = old_current;
                            if (old_current < dns->naddresses) {
                                server->info = dns->addresses[old_current];
                            }
                            
                            found_untested = true;
                            break; /* Only test one server per maintenance cycle */
                        }
                    }
                    
                    if (found_untested) {
                        last_forced_probe = now;
                        log_warn("🔄 FORCED PROBE: Completed probe cycle for '%.*s' - next probe in 10 seconds",
                                 server->pname.len, server->pname.data);
                    }
                }
            }
        }
    }
}

static void
core_timeout(struct context *ctx)
{
    for (;;) {
        struct msg *msg;
        struct conn *conn;
        int64_t now, then;

        msg = msg_tmo_min();
        if (msg == NULL) {
            ctx->timeout = ctx->max_timeout;
            return;
        }

        /* skip over req that are in-error or done */

        if (msg->error || msg->done) {
            msg_tmo_delete(msg);
            continue;
        }

        /*
         * timeout expired req and all the outstanding req on the timing
         * out server
         */

        conn = msg->tmo_rbe.data;
        then = msg->tmo_rbe.key;

        now = nc_msec_now();
        if (now < then) {
            int delta = (int)(then - now);
            ctx->timeout = MIN(delta, ctx->max_timeout);
            return;
        }

        log_debug(LOG_INFO, "req %"PRIu64" on s %d timedout", msg->id, conn->sd);

        msg_tmo_delete(msg);
        conn->err = ETIMEDOUT;

        core_close(ctx, conn);
    }
}

rstatus_t
core_core(void *evb, void *arg, uint32_t events)
{
    rstatus_t status;
    struct conn *conn = arg;
    struct context *ctx;

    if (conn->owner == NULL) {
        log_warn("conn is already unrefed!");
        return NC_OK;
    }

    ctx = conn_to_ctx(conn);

    log_debug(LOG_VVERB, "event %04"PRIX32" on %c %d", events,
              conn->client ? 'c' : (conn->proxy ? 'p' : 's'), conn->sd);

    conn->events = events;

    /* error takes precedence over read | write */
    if (events & EVENT_ERR) {
        core_error(ctx, conn);
        return NC_ERROR;
    }

    /* read takes precedence over write */
    if (events & EVENT_READ) {
        status = core_recv(ctx, conn);
        /* Don't close the proxy conn, even accept error */
        if ((status != NC_OK && conn->proxy != 1) || conn->done || conn->err) {
            core_close(ctx, conn);
            return NC_ERROR;
        }
    }

    if (events & EVENT_WRITE) {
        status = core_send(ctx, conn);
        if (status != NC_OK || conn->done || conn->err) {
            core_close(ctx, conn);
            return NC_ERROR;
        }
    }

    return NC_OK;
}

rstatus_t
core_loop(struct context *ctx)
{
    int nsd;

    nsd = event_wait(ctx->evb, ctx->timeout);
    if (nsd < 0) {
        return nsd;
    }

    core_timeout(ctx);
    
    /* Periodic DNS maintenance for dynamic servers */
    core_dns_maintenance(ctx);

    stats_swap(ctx->stats);

    return NC_OK;
}
