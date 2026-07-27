#ifndef _NC_RESOLVER_H_
#define _NC_RESOLVER_H_

#include <nc_core.h>

/*
 * Background DNS resolver. getaddrinfo can block for seconds on resolver
 * trouble; running it on the event loop stalls every in-flight request on
 * the worker. One thread per process runs ONLY the resolve; results are
 * applied on the loop thread (resolver_poll from core_dns_maintenance), so
 * server/pool structs are never touched off-loop. The server pointer rides
 * along as an opaque key -- the thread never dereferences it.
 */

struct resolver;

struct resolver_result {
    struct server            *server;      /* loop-side key; thread never derefs */
    struct sockinfo          *addrs;       /* malloc'd by the resolve */
    char                    **hostnames;   /* malloc'd by the resolve */
    uint32_t                  naddresses;
    rstatus_t                 status;
    STAILQ_ENTRY(resolver_result) next;
};

struct resolver *resolver_create(void);
void             resolver_destroy(struct resolver *r);
rstatus_t        resolver_submit(struct resolver *r, struct server *server,
                                 const struct string *hostname, int port,
                                 uint32_t max_addresses);
struct resolver_result *resolver_poll(struct resolver *r);
void             resolver_result_free(struct resolver_result *res);

#endif
