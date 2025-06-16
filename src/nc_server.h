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

#ifndef _NC_SERVER_H_
#define _NC_SERVER_H_

#include <nc_core.h>

/*
 * server_pool is a collection of servers and their continuum. Each
 * server_pool is the owner of a single proxy connection and one or
 * more client connections. server_pool itself is owned by the current
 * context.
 *
 * Each server is the owner of one or more server connections. server
 * itself is owned by the server_pool.
 *
 *  +-------------+
 *  |             |<---------------------+
 *  |             |<------------+        |
 *  |             |     +-------+--+-----+----+--------------+
 *  |   pool 0    |+--->|          |          |              |
 *  |             |     | server 0 | server 1 | ...     ...  |
 *  |             |     |          |          |              |--+
 *  |             |     +----------+----------+--------------+  |
 *  +-------------+                                             //
 *  |             |
 *  |             |
 *  |             |
 *  |   pool 1    |
 *  |             |
 *  |             |
 *  |             |
 *  +-------------+
 *  |             |
 *  |             |
 *  .             .
 *  .    ...      .
 *  .             .
 *  |             |
 *  |             |
 *  +-------------+
 *            |
 *            |
 *            //
 */

typedef uint32_t (*hash_t)(const char *, size_t);

struct continuum {
    uint32_t index;  /* server index */
    uint32_t value;  /* hash value */
};

struct server_dns {
    struct string      hostname;          /* Original hostname */
    struct sockinfo    *addresses;       /* Array of resolved IPs */
    uint32_t           naddresses;        /* Number of resolved IPs */
    uint32_t           max_addresses;     /* Maximum addresses allocated */
    int64_t            last_resolved;     /* Last DNS resolution time */
    int64_t            resolve_interval;  /* DNS re-resolution interval (usec) */
    uint32_t           *latencies;        /* Latency for each address (usec) */
    int64_t            *last_latency_check; /* Last latency measurement */
    uint32_t           *failure_counts;   /* Failure count per address */
    
    /* Enhanced health monitoring */
    uint32_t           *health_scores;    /* Rolling health score per address (0-100) */
    int64_t            *last_health_check; /* Last health check timestamp */
    uint32_t           health_check_interval; /* Health check frequency (usec) */
    uint32_t           consecutive_failures_limit; /* Max failures before marking unhealthy */
    
    /* Zone detection fields (latency-based) */
    uint32_t           *zone_ids;         /* Zone ID for each address (based on latency clustering) */
    uint32_t           local_zone_id;     /* Current instance zone ID */
    uint32_t           next_zone_id;      /* Next zone ID to assign */
    int64_t            last_zone_analysis; /* Last zone analysis timestamp */
};

struct server {
    uint32_t           idx;           /* server index */
    struct server_pool *owner;        /* owner pool */

    struct string      pname;         /* hostname:port:weight (ref in conf_server) */
    struct string      name;          /* hostname:port or [name] (ref in conf_server) */
    struct string      addrstr;       /* hostname (ref in conf_server) */
    uint16_t           port;          /* port */
    uint32_t           weight;        /* weight */
    struct sockinfo    info;          /* server socket info */

    uint32_t           ns_conn_q;     /* # server connection */
    struct conn_tqh    s_conn_q;      /* server connection q */

    int64_t            next_retry;    /* next retry time in usec */
    uint32_t           failure_count; /* # consecutive failures */
    
    /* Dynamic DNS and latency-based selection */
    struct server_dns  *dns;          /* Dynamic DNS info */
    uint32_t           current_addr_idx; /* Currently selected address index */
    unsigned           is_dynamic:1;  /* Is this a dynamic DNS server? */
};

struct server_pool {
    uint32_t           idx;                  /* pool index */
    struct context     *ctx;                 /* owner context */

    struct conn        *p_conn;              /* proxy connection (listener) */
    uint32_t           nc_conn_q;            /* # client connection */
    struct conn_tqh    c_conn_q;             /* client connection q */

    struct array       server;               /* server[] */
    struct array       redis_master;         /* server[] */
    uint32_t           ncontinuum;           /* # continuum points */
    uint32_t           nserver_continuum;    /* # servers - live and dead on continuum (const) */
    struct continuum   *continuum;           /* continuum */
    uint32_t           nlive_server;         /* # live server */
    int64_t            next_rebuild;         /* next distribution rebuild time in usec */

    struct string      name;                 /* pool name (ref in conf_pool) */
    struct string      addrstr;              /* pool address - hostname:port (ref in conf_pool) */
    uint16_t           port;                 /* port */
    struct sockinfo    info;                 /* listen socket info */
    mode_t             perm;                 /* socket permission */
    int                dist_type;            /* distribution type (dist_type_t) */
    int                key_hash_type;        /* key hash type (hash_type_t) */
    hash_t             key_hash;             /* key hasher */
    struct string      hash_tag;             /* key hash tag (ref in conf_pool) */
    int                timeout;              /* timeout in msec */
    int                backlog;              /* listen backlog */
    int                redis_db;             /* redis database to connect to */
    uint32_t           client_connections;   /* maximum # client connection */
    uint32_t           server_connections;   /* maximum # server connection */
    int64_t            server_retry_timeout; /* server retry timeout in usec */
    uint32_t           server_failure_limit; /* server failure limit */
    struct string      redis_auth;           /* redis_auth password (matches requirepass on redis) */
    unsigned           require_auth;         /* require_auth? */
    unsigned           auto_eject_hosts:1;   /* auto_eject_hosts? */
    unsigned           preconnect:1;         /* preconnect? */
    unsigned           redis:1;              /* redis? */
    unsigned           tcpkeepalive:1;       /* tcpkeepalive? */
    unsigned           latency_routing:1;    /* enable latency-based routing? */
    
    /* Dynamic DNS and latency routing configuration */
    int64_t            dns_resolve_interval; /* DNS re-resolution interval (usec) */
    uint32_t           latency_weight;       /* percentage of traffic to lowest latency server (0-100) */
    
    /* Cloud-agnostic configuration */
    unsigned           zone_aware:1;         /* enable zone-aware routing? */
    uint32_t           zone_weight;          /* extra weight for same-zone servers (0-100) */
    uint32_t           zone_latency_threshold; /* latency threshold for zone detection (usec) */
    unsigned           cache_mode:1;         /* managed cache service mode? */
    unsigned           connection_pooling:1; /* enable connection pooling? */
    uint32_t           connection_warming;   /* pre-warm connections count */
    int64_t            connection_idle_timeout; /* close idle connections (usec) */
    
    /* TLS/Security */
    unsigned           tls_enabled:1;        /* enable TLS? */
    unsigned           tls_verify_peer:1;    /* verify TLS peer certificates? */
    
    /* Enhanced DNS settings */
    uint32_t           dns_failure_threshold; /* failures before marking server unhealthy */
    int64_t            dns_cache_negative_ttl; /* negative DNS cache TTL (usec) */
};

void server_ref(struct conn *conn, void *owner);
void server_unref(struct conn *conn);
int server_timeout(struct conn *conn);
bool server_active(struct conn *conn);
rstatus_t server_init(struct array *server, struct array *conf_server, struct server_pool *sp);
void server_deinit(struct array *server);
struct conn *server_conn(struct server *server);
struct conn *server_get_conn(struct context *ctx, struct server *srv);
rstatus_t server_connect(struct context *ctx, struct server *server, struct conn *conn);
void server_close(struct context *ctx, struct conn *conn);
void server_connected(struct context *ctx, struct conn *conn);
void server_ok(struct context *ctx, struct conn *conn);

/* Dynamic DNS and latency functions */
rstatus_t server_dns_init(struct server *server);
void server_dns_deinit(struct server *server);
rstatus_t server_dns_resolve(struct server *server);
rstatus_t server_dns_check_update(struct server *server);
uint32_t server_select_best_address(struct server *server);
rstatus_t server_measure_latency(struct server *server, uint32_t addr_idx, int64_t latency);
bool server_should_resolve_dns(struct server *server);
rstatus_t server_get_read_hosts_info(struct server *server, char *buffer, size_t buffer_size);

/* Cloud-agnostic zone and health functions */
rstatus_t server_detect_zones_by_latency(struct server *server);
uint32_t server_assign_zone_id(struct server *server, uint32_t addr_idx);
uint32_t server_calculate_zone_weight(struct server *server, uint32_t addr_idx);
rstatus_t server_health_check(struct server *server, uint32_t addr_idx);
bool server_is_healthy(struct server *server, uint32_t addr_idx);
rstatus_t server_discover_cache_endpoints(struct server *server);

uint32_t server_pool_idx(struct server_pool *pool, uint8_t *key, uint32_t keylen);
struct conn *server_pool_conn(struct context *ctx, struct server_pool *pool, uint8_t *key, uint32_t keylen);
rstatus_t server_pool_run(struct server_pool *pool);
rstatus_t server_pool_preconnect(struct context *ctx);
void server_pool_disconnect(struct context *ctx);
rstatus_t server_pool_init(struct array *server_pool, struct array *conf_pool, struct context *ctx);
void server_pool_deinit(struct array *server_pool);

#endif
