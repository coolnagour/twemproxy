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

#ifndef _NC_CONF_H_
#define _NC_CONF_H_

#include <unistd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <yaml.h>

#include <nc_core.h>
#include <hashkit/nc_hashkit.h>

#define CONF_OK             (void *) NULL
#define CONF_ERROR          (void *) "has an invalid value"

#define CONF_SECTION_ROOT_DEPTH  2
#define CONF_POOL_MAX_DEPTH      (CONF_SECTION_ROOT_DEPTH + 1)
#define CONF_GLOBAL_MAX_DEPTH    CONF_SECTION_ROOT_DEPTH

#define CONF_DEFAULT_ARGS       3
#define CONF_DEFAULT_POOL       8
#define CONF_DEFAULT_SERVERS    8

#define CONF_UNSET_NUM  -1
#define CONF_UNSET_PTR  NULL
#define CONF_UNSET_HASH (hash_type_t) -1
#define CONF_UNSET_DIST (dist_type_t) -1

#define CONF_DEFAULT_HASH                    HASH_FNV1A_64
#define CONF_DEFAULT_DIST                    DIST_KETAMA
#define CONF_DEFAULT_TIMEOUT                 -1
#define CONF_DEFAULT_LISTEN_BACKLOG          512
#define CONF_DEFAULT_CLIENT_CONNECTIONS      2048
#define CONF_DEFAULT_REDIS                   false
#define CONF_DEFAULT_REDIS_DB                0
#define CONF_DEFAULT_PRECONNECT              false
#define CONF_DEFAULT_AUTO_EJECT_HOSTS        false
#define CONF_DEFAULT_SERVER_RETRY_TIMEOUT    30 * 1000      /* in msec */
#define CONF_DEFAULT_SERVER_FAILURE_LIMIT    2
#define CONF_DEFAULT_SERVER_CONNECTIONS      1
#define CONF_DEFAULT_KETAMA_PORT             11211
#define CONF_DEFAULT_TCPKEEPALIVE            false
#define CONF_DEFAULT_WORKER_PROCESSES        4
#define CONF_DEFAULT_WORKER_SHUTDOWN_TIMEOUT 30
#define CONF_DEFAULT_MAX_OPENFILES           102400
#define CONF_DEFAULT_USER                    "nobody"
#define CONF_DEFAULT_GROUP                   "nobody"
#define CONF_DEFAULT_DNS_RESOLVE_INTERVAL    30         /* in seconds */

/* Cloud-agnostic defaults */
#define CONF_DEFAULT_ZONE_AWARE              false
#define CONF_DEFAULT_ZONE_WEIGHT             25         /* extra weight for same-zone servers */
#define CONF_DEFAULT_CONNECTION_POOLING      false
#define CONF_DEFAULT_CONNECTION_WARMING      0
#define CONF_DEFAULT_CONNECTION_IDLE_TIMEOUT 300        /* in seconds */
#define CONF_DEFAULT_CONNECTION_MAX_LIFETIME 900        /* in seconds (15 minutes) */
#define CONF_DEFAULT_TLS_ENABLED             false
#define CONF_DEFAULT_TLS_VERIFY_PEER         true
#define CONF_DEFAULT_DNS_FAILURE_THRESHOLD   3
#define CONF_DEFAULT_DNS_CACHE_NEGATIVE_TTL  30         /* in seconds */
#define CONF_DEFAULT_DNS_EXPIRATION_MINUTES  5          /* expire addresses after 5 minutes */
#define CONF_DEFAULT_DNS_HEALTH_CHECK_INTERVAL 30       /* health check interval in seconds */
#define CONF_DEFAULT_DYNAMIC_SERVER_CONNECTIONS false    /* disabled by default */
#define CONF_DEFAULT_MAX_SERVER_CONNECTIONS     10       /* maximum server connections limit */

struct conf_listen {
    struct string   pname;   /* listen: as "hostname:port" */
    struct string   name;    /* hostname:port */
    int             port;    /* port */
    mode_t          perm;    /* socket permissions */
    struct sockinfo info;    /* listen socket info */
    unsigned        valid:1; /* valid? */
};

struct conf_server {
    struct string   pname;      /* server: as "hostname:port:weight" */
    struct string   name;       /* hostname:port or [name] */
    struct string   addrstr;    /* hostname */
    int             port;       /* port */
    int             weight;     /* weight */
    struct sockinfo info;       /* connect socket info */
    unsigned        valid:1;    /* valid? */
};

struct conf_pool {
    struct string      name;                  /* pool name (root node) */
    struct conf_listen listen;                /* listen: */
    hash_type_t        hash;                  /* hash: */
    struct string      hash_tag;              /* hash_tag: */
    dist_type_t        distribution;          /* distribution: */
    int                timeout;               /* timeout: */
    int                backlog;               /* backlog: */
    int                client_connections;    /* client_connections: */
    int                tcpkeepalive;          /* tcpkeepalive: */
    int                redis;                 /* redis: */
    struct string      redis_auth;            /* redis_auth: redis auth password (matches requirepass on redis) */
    struct array       redis_master;          /* redis master */
    int                redis_db;              /* redis_db: redis db */
    int                preconnect;            /* preconnect: */
    int                auto_eject_hosts;      /* auto_eject_hosts: */
    int                server_connections;    /* server_connections: */
    int                server_retry_timeout;  /* server_retry_timeout: in msec */
    int                server_failure_limit;  /* server_failure_limit: */
    struct array       server;                /* servers: conf_server[] */
    int                dns_resolve_interval;  /* dns_resolve_interval: DNS re-resolution interval in seconds */
    
    /* Cloud-agnostic configuration */
    int                zone_aware;            /* zone_aware: enable zone-aware routing */
    int                zone_weight;           /* zone_weight: extra weight for same-zone servers */
    int                connection_pooling;    /* connection_pooling: enable connection pooling */
    int                connection_warming;    /* connection_warming: pre-warm connections count */
    int                connection_idle_timeout; /* connection_idle_timeout: idle timeout in seconds */
    int                connection_max_lifetime; /* connection_max_lifetime: max lifetime in seconds */
    int                tls_enabled;           /* tls_enabled: enable TLS */
    int                tls_verify_peer;       /* tls_verify_peer: verify TLS peer certificates */
    int                dns_failure_threshold; /* dns_failure_threshold: failures before unhealthy */
    int                dns_cache_negative_ttl; /* dns_cache_negative_ttl: negative DNS cache TTL */
    int                dns_expiration_minutes; /* dns_expiration_minutes: expire addresses after N minutes */
    int                dns_health_check_interval; /* dns_health_check_interval: health check interval in seconds */
    int                dynamic_server_connections; /* dynamic_server_connections: enable dynamic scaling */
    int                max_server_connections;     /* max_server_connections: maximum connections limit */
    
    unsigned           valid:1;               /* valid? */
};

struct conf_global {
    int           worker_processes; // number of worker processes
    int           worker_shutdown_timeout; // number of seconds that worker would be quit after signal terminate was received
    int           max_openfiles; // max number of open files
    struct string user;
    struct string group;
    uid_t         uid;
    gid_t         gid;
};

struct conf {
    char               *fname;           /* file name (ref in argv[]) */
    FILE               *fh;              /* file handle */
    struct array       arg;              /* string[] (parsed {key, value} pairs) */
    struct array       pool;             /* conf_pool[] (parsed pools) */
    struct conf_global global;           // global conf
    uint32_t           depth;            /* parsed tree depth */
    yaml_parser_t      parser;           /* yaml parser */
    yaml_event_t       event;            /* yaml event */
    yaml_token_t       token;            /* yaml token */
    unsigned           seq:1;            /* sequence? */
    unsigned           valid_parser:1;   /* valid parser? */
    unsigned           valid_event:1;    /* valid event? */
    unsigned           valid_token:1;    /* valid token? */
    unsigned           sound:1;          /* sound? */
    unsigned           parsed:1;         /* parsed? */
    unsigned           valid:1;          /* valid? */
};

struct command {
    struct string name;
    char          *(*set)(struct conf *cf, struct command *cmd, void *data);
    int           offset;
};

#define null_command { null_string, NULL, 0 }

char *conf_set_string(struct conf *cf, struct command *cmd, void *conf);
char *conf_set_listen(struct conf *cf, struct command *cmd, void *conf);
char *conf_add_server(struct conf *cf, struct command *cmd, void *conf);
char *conf_set_num(struct conf *cf, struct command *cmd, void *conf);
char *conf_set_worker_processes(struct conf *cf, struct command *cmd, void *conf);
char *conf_set_bool(struct conf *cf, struct command *cmd, void *conf);
char *conf_set_hash(struct conf *cf, struct command *cmd, void *conf);
char *conf_set_distribution(struct conf *cf, struct command *cmd, void *conf);
char *conf_set_hashtag(struct conf *cf, struct command *cmd, void *conf);
char *conf_set_master(struct conf *cf, struct command *cmd, void *conf);

rstatus_t conf_server_each_transform(void *elem, void *data);
rstatus_t conf_pool_each_transform(void *elem, void *data);

struct conf *conf_create(char *filename);
void conf_destroy(struct conf *cf);

#endif
