#include <pthread.h>
#include <unistd.h>

#include <nc_core.h>
#include <nc_server.h>
#include <nc_resolver.h>

struct resolver_req {
    struct server  *server;
    struct string   hostname;      /* owned copy; the thread reads only this */
    int             port;
    uint32_t        max_addresses;
    STAILQ_ENTRY(resolver_req) next;
};

STAILQ_HEAD(resolver_reqq, resolver_req);
STAILQ_HEAD(resolver_resq, resolver_result);

struct resolver {
    pthread_t             tid;
    pthread_mutex_t       mtx;
    pthread_cond_t        cv;          /* signals: request queued or stopping */
    struct resolver_reqq  reqq;
    struct resolver_resq  resq;
    int                   stop;
};

static void
resolver_req_free(struct resolver_req *req)
{
    string_deinit(&req->hostname);
    nc_free(req);
}

void
resolver_result_free(struct resolver_result *res)
{
    if (res == NULL) {
        return;
    }
    if (res->addrs != NULL) {
        nc_free(res->addrs);
    }
    free_hostnames_temp(res->hostnames, res->naddresses);
    nc_free(res);
}

static void *
resolver_loop(void *arg)
{
    struct resolver *r = arg;

    pthread_mutex_lock(&r->mtx);
    for (;;) {
        struct resolver_req *req;
        struct resolver_result *res;

        while (!r->stop && STAILQ_EMPTY(&r->reqq)) {
            pthread_cond_wait(&r->cv, &r->mtx);
        }
        if (r->stop) {
            break;
        }
        req = STAILQ_FIRST(&r->reqq);
        STAILQ_REMOVE_HEAD(&r->reqq, next);
        pthread_mutex_unlock(&r->mtx);

        res = nc_zalloc(sizeof(*res));
        if (res != NULL) {
            res->server = req->server;
            res->status = nc_resolve_multi_with_hostnames(&req->hostname,
                                                          req->port,
                                                          &res->addrs,
                                                          &res->hostnames,
                                                          &res->naddresses,
                                                          req->max_addresses);
        }
        resolver_req_free(req);

        pthread_mutex_lock(&r->mtx);
        if (res != NULL) {
            STAILQ_INSERT_TAIL(&r->resq, res, next);
        }
    }
    pthread_mutex_unlock(&r->mtx);
    return NULL;
}

struct resolver *
resolver_create(void)
{
    struct resolver *r;

    r = nc_zalloc(sizeof(*r));
    if (r == NULL) {
        return NULL;
    }
    STAILQ_INIT(&r->reqq);
    STAILQ_INIT(&r->resq);
    if (pthread_mutex_init(&r->mtx, NULL) != 0) {
        nc_free(r);
        return NULL;
    }
    if (pthread_cond_init(&r->cv, NULL) != 0) {
        pthread_mutex_destroy(&r->mtx);
        nc_free(r);
        return NULL;
    }
    if (pthread_create(&r->tid, NULL, resolver_loop, r) != 0) {
        pthread_cond_destroy(&r->cv);
        pthread_mutex_destroy(&r->mtx);
        nc_free(r);
        return NULL;
    }
    return r;
}

void
resolver_destroy(struct resolver *r)
{
    struct resolver_req *req;
    struct resolver_result *res;

    if (r == NULL) {
        return;
    }
    pthread_mutex_lock(&r->mtx);
    r->stop = 1;
    pthread_cond_signal(&r->cv);
    pthread_mutex_unlock(&r->mtx);
    pthread_join(r->tid, NULL);

    while ((req = STAILQ_FIRST(&r->reqq)) != NULL) {
        STAILQ_REMOVE_HEAD(&r->reqq, next);
        resolver_req_free(req);
    }
    while ((res = STAILQ_FIRST(&r->resq)) != NULL) {
        STAILQ_REMOVE_HEAD(&r->resq, next);
        resolver_result_free(res);
    }
    pthread_cond_destroy(&r->cv);
    pthread_mutex_destroy(&r->mtx);
    nc_free(r);
}

rstatus_t
resolver_submit(struct resolver *r, struct server *server,
                const struct string *hostname, int port,
                uint32_t max_addresses)
{
    struct resolver_req *req;

    req = nc_zalloc(sizeof(*req));
    if (req == NULL) {
        return NC_ENOMEM;
    }
    string_init(&req->hostname);
    if (string_copy(&req->hostname, hostname->data, hostname->len) != NC_OK) {
        nc_free(req);
        return NC_ENOMEM;
    }
    req->server = server;
    req->port = port;
    req->max_addresses = max_addresses;

    pthread_mutex_lock(&r->mtx);
    STAILQ_INSERT_TAIL(&r->reqq, req, next);
    pthread_cond_signal(&r->cv);
    pthread_mutex_unlock(&r->mtx);
    return NC_OK;
}

struct resolver_result *
resolver_poll(struct resolver *r)
{
    struct resolver_result *res;

    pthread_mutex_lock(&r->mtx);
    res = STAILQ_FIRST(&r->resq);
    if (res != NULL) {
        STAILQ_REMOVE_HEAD(&r->resq, next);
    }
    pthread_mutex_unlock(&r->mtx);
    return res;
}
