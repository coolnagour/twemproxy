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

/*
 * One resolved address and everything we track about it.
 *
 * This used to be ~11 PARALLEL arrays inside struct server_dns, all indexed by
 * the same address index. That layout had a whole bug class: any code that
 * shifted or grew the addresses had to touch every array in lock-step, and a
 * missed array silently desynced (index i pointed at a different address in
 * different arrays) or leaked / double-freed. Folding the per-address state into
 * one struct deletes that class: there is a single array, so a shift is one
 * memmove and a grow is one realloc -- nothing can fall out of step.
 *
 * `addrs` is allocated once to cover up to max_addresses entries; naddresses is
 * how many are live. Every field below lives in this struct (the old lazy-vs-
 * eager split is gone -- zone_id / health_score / last_health_check are no
 * longer allocated separately).
 */
struct dns_addr {
    struct sockinfo addr;               /* resolved IP + port */
    struct string   hostname;           /* canonical hostname for this addr (reverse DNS) */
    uint32_t        latency;            /* EWMA connect latency (usec) */
    bool            latency_measured;   /* false until the first real measurement
                                         * (replaces DEFAULT_LATENCY_USEC-as-sentinel) */
    int64_t         last_latency_check;  /* last latency measurement timestamp */
    uint32_t        failure_count;       /* consecutive failures for this addr */
    int64_t         last_seen;           /* last time this addr was returned by DNS */
    int64_t         last_connected;      /* last time this addr was used to connect */
    uint64_t        request_count;       /* requests sent to this addr */
    uint32_t        zone_id;             /* zone ID (latency clustering); 0 = unassigned */
    uint32_t        health_score;        /* rolling health score (0-100) */
    int64_t         last_health_check;   /* last health check timestamp */
};

struct server_dns {
    struct string      hostname;          /* Original hostname */
    struct dns_addr    *addrs;            /* Array of resolved addresses (AoS) */
    uint32_t           naddresses;        /* Number of resolved IPs (live entries in addrs) */
    uint32_t           max_addresses;     /* Maximum addresses (cap; addrs is sized to this) */
    int64_t            last_resolved;     /* Last DNS resolution time */
    int64_t            resolve_interval;  /* DNS re-resolution interval (usec) */

    /* Enhanced health monitoring */
    bool               health_initialized; /* has the first health check run? (was: health_scores != NULL) */
    uint32_t           health_check_interval; /* Health check frequency (usec) */
    uint32_t           consecutive_failures_limit; /* Max failures before marking unhealthy */

    /* Zone detection fields (latency-based) */
    bool               zones_assigned;    /* have we run zone analysis at least once? (was: zone_ids != NULL) */
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
    /* Dynamic DNS configuration */
    int64_t            dns_resolve_interval; /* DNS re-resolution interval (usec) */
    
    /* Cloud-agnostic configuration */
    unsigned           zone_aware:1;         /* enable zone-aware routing? */
    uint32_t           zone_weight;          /* extra weight for same-zone servers (0-100) */
    int64_t            connection_max_lifetime; /* force close connections after max lifetime (usec) */

    /* Dynamic connection scaling */
    unsigned           dynamic_server_connections:1; /* enable dynamic server_connections scaling? */
    uint32_t           max_server_connections;       /* maximum server_connections limit */
    uint32_t           current_server_connections;   /* current effective server_connections */

    /* Enhanced DNS settings */
    uint32_t           dns_failure_threshold; /* failures before marking server unhealthy */
    int64_t            dns_expiration_minutes; /* expire addresses after N minutes (usec) */
    int64_t            dns_health_check_interval; /* health check interval (usec) */
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
void server_dns_remove_address_at(struct server_dns *dns, uint32_t i);
uint32_t server_select_best_address(struct server *server);

/*
 * Latency-weighted read selection helpers (pure, allocation-free, integer-only).
 * Exposed (non-static) so the unit tests drive the REAL production code.
 *
 * server_weighted_pick: return one element of idxs[0..count) with probability
 *   proportional to 1/(eff_latency[k] + LATENCY_FLOOR_US), where eff_latency[k]
 *   is the effective latency of idxs[k]. Two passes, uint64 accumulator, integer
 *   math, no heap, no floats. Uses random() (the process-seeded PRNG) -- does NOT
 *   seed it. count==0 returns 0 (no valid index). If every weight is 0, falls
 *   back to a uniform pick.
 */
uint32_t server_weighted_pick(const uint32_t *eff_latency, const uint32_t *idxs,
                              uint32_t count);
rstatus_t server_measure_latency(struct server *server, uint32_t addr_idx, int64_t latency);
bool server_should_resolve_dns(struct server *server);
rstatus_t server_get_read_hosts_info(struct server *server, const char *key, char *buffer, size_t buffer_size);

/* Cloud-agnostic zone and health functions */
rstatus_t server_detect_zones_by_latency(struct server *server);
uint32_t server_assign_zone_id(struct server *server, uint32_t addr_idx);
uint32_t server_calculate_zone_weight(struct server *server, uint32_t addr_idx);
rstatus_t server_health_check(struct server *server, uint32_t addr_idx);
bool server_is_healthy(struct server *server, uint32_t addr_idx);

uint32_t server_pool_idx(struct server_pool *pool, uint8_t *key, uint32_t keylen);
struct conn *server_pool_conn(struct context *ctx, struct server_pool *pool, uint8_t *key, uint32_t keylen);
rstatus_t server_pool_run(struct server_pool *pool);
rstatus_t server_pool_preconnect(struct context *ctx);
void server_pool_disconnect(struct context *ctx);
rstatus_t server_pool_init(struct array *server_pool, struct array *conf_pool, struct context *ctx);
void server_pool_deinit(struct array *server_pool);

#endif
