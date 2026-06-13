/*
 * Standalone unit test for the connection-max-lifetime sweep's quiescence
 * guard (fix #1 of the prod-hardening campaign).
 *
 * Twemproxy has no C unit-test framework (tests/ is Python integration that
 * needs a live redis). This is a freestanding C test that links the real
 * nc_core.c + nc_server.c objects and drives the production close-decision
 * predicate directly, so we exercise production code without a network or an
 * event loop.
 *
 * The bug
 * -------
 * nc_core.c's core_dns_maintenance() runs a periodic sweep that force-closes a
 * server connection once (now - conn->connect_start_ts) > connection_max_lifetime
 * -- REGARDLESS of whether the connection has in-flight requests. On a
 * single-process sidecar with server_connections:1, when the only connection to
 * a backend expires it drops every in-flight request at once -> periodic spikes
 * of failed Redis requests every connection_max_lifetime seconds.
 *
 * The fix
 * -------
 * Only recycle a connection that is BOTH expired AND quiescent. Quiescence is
 * the existing server_active(conn) predicate (imsg_q / omsg_q empty and
 * rmsg / smsg NULL). A still-busy expired connection is left for the next sweep
 * tick, which retires it once its queues drain.
 *
 * What this test proves (driving REAL production code):
 *   1. A conn that is expired + QUIESCENT -> the real predicate says recycle.
 *   2. A conn that is expired + BUSY (non-empty imsg_q / omsg_q, or rmsg / smsg
 *      set) -> the real predicate says DO NOT recycle. This is the regression
 *      the fix introduces; it is the assertion that fails pre-fix.
 *   3. A conn that is NOT expired -> not recycled regardless of activity.
 *   4. connect_start_ts == 0 (never stamped) -> not recycled.
 *
 * Fidelity / red->green
 * ---------------------
 * The default build calls the REAL production decision function
 * core_conn_lifetime_should_recycle() from nc_core.c, which itself calls the
 * REAL server_active() from nc_server.c. That is the highest-fidelity level the
 * sweep can be tested at without a live event base + real sockets (the sweep's
 * core_close() needs event_del_conn() + a real fd).
 *
 * To produce the TDD red, the -DTEST_PREFIX_NO_QUIESCENCE_GUARD build replaces
 * the real predicate with a faithful mirror of the PRE-fix decision (expiry
 * only, no quiescence check). Under that build the "expired + BUSY" case is
 * (wrongly) recycled, so test_busy_expired_is_kept() fails -> non-zero exit.
 * This mirrors how test_address_cap (-DTEST_NO_CAP) and test_realloc_safety
 * (-DTEST_REALLOC_BUGGY) stage their red builds in this same suite.
 *
 * Build/run: see tests/unit/run.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <nc_core.h>
#include <nc_server.h>
#include <nc_string.h>
#include <nc.h>

/*
 * nc.c owns main() so it is excluded from the link; nc_signal.o references
 * nc_post_run() from there. The test never raises a fatal signal, so a no-op
 * stub satisfies the linker without affecting behaviour.
 */
void nc_post_run(struct instance *nci) { (void)nci; }

static int failures = 0;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);              \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n");                                             \
        }                                                                      \
    } while (0)

#ifdef TEST_PREFIX_NO_QUIESCENCE_GUARD
/*
 * Faithful mirror of the PRE-fix decision in core_dns_maintenance(): a
 * connection is recycled purely on lifetime expiry, with NO quiescence check.
 * This reproduces the dropped-in-flight bug. Keep this in lock-step with the
 * old condition at src/nc_core.c (connect_start_ts>0 && now-ts > max_lifetime).
 */
static bool
decide_recycle(struct conn *conn, struct server_pool *pool, int64_t now)
{
    return conn->connect_start_ts > 0 &&
           (now - conn->connect_start_ts) > pool->connection_max_lifetime;
}
#else
/* Default: drive the REAL production predicate from nc_core.c. */
#define decide_recycle(conn, pool, now) \
    core_conn_lifetime_should_recycle((conn), (pool), (now))
#endif

/*
 * Build a bare server connection on the heap with the fields the predicate
 * reads. We deliberately do NOT open a socket or wire an event base: the
 * predicate only inspects connect_start_ts and the in-flight queues, so a
 * minimal conn is sufficient and keeps the test heap-clean.
 *
 * imsg_q / omsg_q are initialised empty; rmsg / smsg NULL. client / proxy are
 * cleared so server_active()'s ASSERT(!client && !proxy) holds.
 */
static struct conn *
make_server_conn(int64_t connect_start_ts)
{
    struct conn *conn = nc_zalloc(sizeof(*conn));

    conn->sd = 7;                     /* arbitrary non-zero, never used for I/O */
    conn->client = 0;
    conn->proxy = 0;
    conn->connect_start_ts = connect_start_ts;
    conn->active = server_active;     /* mirror conn_get_server() wiring */

    TAILQ_INIT(&conn->imsg_q);
    TAILQ_INIT(&conn->omsg_q);
    conn->rmsg = NULL;
    conn->smsg = NULL;

    return conn;
}

/*
 * A throwaway msg used only to make a queue non-empty. We never run it through
 * the real msg lifecycle; it just needs to be linkable onto a TAILQ. Allocated
 * with nc_zalloc and freed by the caller so the run stays leak-clean.
 */
static struct msg *
make_dummy_msg(void)
{
    struct msg *msg = nc_zalloc(sizeof(*msg));
    return msg;
}

/* now() far enough ahead that a ts-of-1 connection is well past any lifetime. */
static const int64_t NOW = 1000LL * 1000LL * 1000LL; /* 1e9 usec */

/* A pool whose max lifetime is 900s, mirroring the default (900s * 1e6 usec). */
static struct server_pool *
make_pool_900s(void)
{
    struct server_pool *pool = nc_zalloc(sizeof(*pool));
    pool->connection_max_lifetime = 900LL * 1000000LL; /* 900s in usec */
    return pool;
}

/* (a) expired + QUIESCENT -> MUST be recycled. */
static void
test_quiescent_expired_is_recycled(void)
{
    struct server_pool *pool = make_pool_900s();
    struct conn *conn = make_server_conn(/*connect_start_ts=*/1);

    CHECK((NOW - conn->connect_start_ts) > pool->connection_max_lifetime,
          "precondition: conn must be past max lifetime");
    CHECK(!server_active(conn), "precondition: a fresh conn must be quiescent");

    CHECK(decide_recycle(conn, pool, NOW),
          "expired + quiescent conn must be recycled");

    nc_free(conn);
    nc_free(pool);
}

/*
 * (b) expired + BUSY -> MUST NOT be recycled. This is the in-flight-drop
 * regression the fix prevents. Pre-fix (no quiescence guard) it IS recycled,
 * so this assertion fails -> red. Exercised across all four "busy" signals.
 */
static void
test_busy_expired_is_kept(void)
{
    struct server_pool *pool = make_pool_900s();

    /* busy via outstanding-request queue (omsg_q): a request sent, awaiting
     * its reply -- the exact in-flight state we must not drop. */
    {
        struct conn *conn = make_server_conn(/*connect_start_ts=*/1);
        struct msg *m = make_dummy_msg();
        TAILQ_INSERT_TAIL(&conn->omsg_q, m, s_tqe);

        CHECK(server_active(conn), "precondition: omsg_q non-empty => active");
        CHECK(!decide_recycle(conn, pool, NOW),
              "expired conn with an outstanding request must NOT be recycled "
              "(would drop the in-flight reply)");

        TAILQ_REMOVE(&conn->omsg_q, m, s_tqe);
        nc_free(m);
        nc_free(conn);
    }

    /* busy via incoming-request queue (imsg_q). */
    {
        struct conn *conn = make_server_conn(/*connect_start_ts=*/1);
        struct msg *m = make_dummy_msg();
        TAILQ_INSERT_TAIL(&conn->imsg_q, m, s_tqe);

        CHECK(server_active(conn), "precondition: imsg_q non-empty => active");
        CHECK(!decide_recycle(conn, pool, NOW),
              "expired conn with a queued request must NOT be recycled");

        TAILQ_REMOVE(&conn->imsg_q, m, s_tqe);
        nc_free(m);
        nc_free(conn);
    }

    /* busy via in-progress receive (rmsg set). */
    {
        struct conn *conn = make_server_conn(/*connect_start_ts=*/1);
        struct msg *m = make_dummy_msg();
        conn->rmsg = m;

        CHECK(server_active(conn), "precondition: rmsg set => active");
        CHECK(!decide_recycle(conn, pool, NOW),
              "expired conn mid-receive must NOT be recycled");

        conn->rmsg = NULL;
        nc_free(m);
        nc_free(conn);
    }

    /* busy via in-progress send (smsg set). */
    {
        struct conn *conn = make_server_conn(/*connect_start_ts=*/1);
        struct msg *m = make_dummy_msg();
        conn->smsg = m;

        CHECK(server_active(conn), "precondition: smsg set => active");
        CHECK(!decide_recycle(conn, pool, NOW),
              "expired conn mid-send must NOT be recycled");

        conn->smsg = NULL;
        nc_free(m);
        nc_free(conn);
    }

    nc_free(pool);
}

/* (c) NOT expired (young conn) -> never recycled, busy or not. */
static void
test_young_conn_is_kept(void)
{
    struct server_pool *pool = make_pool_900s();

    /* connect_start_ts only 10s before now: well within the 900s lifetime. */
    int64_t young_ts = NOW - 10LL * 1000000LL;

    /* quiescent young conn */
    {
        struct conn *conn = make_server_conn(young_ts);
        CHECK((NOW - conn->connect_start_ts) <= pool->connection_max_lifetime,
              "precondition: young conn within lifetime");
        CHECK(!decide_recycle(conn, pool, NOW),
              "young quiescent conn must NOT be recycled");
        nc_free(conn);
    }

    /* busy young conn -- still kept (and would be kept pre-fix too). */
    {
        struct conn *conn = make_server_conn(young_ts);
        struct msg *m = make_dummy_msg();
        TAILQ_INSERT_TAIL(&conn->omsg_q, m, s_tqe);
        CHECK(!decide_recycle(conn, pool, NOW),
              "young busy conn must NOT be recycled");
        TAILQ_REMOVE(&conn->omsg_q, m, s_tqe);
        nc_free(m);
        nc_free(conn);
    }

    nc_free(pool);
}

/* (d) connect_start_ts == 0 (never stamped) -> never recycled. */
static void
test_unstamped_conn_is_kept(void)
{
    struct server_pool *pool = make_pool_900s();
    struct conn *conn = make_server_conn(/*connect_start_ts=*/0);

    CHECK(!decide_recycle(conn, pool, NOW),
          "conn with connect_start_ts==0 must NOT be recycled");

    nc_free(conn);
    nc_free(pool);
}

int
main(void)
{
    test_quiescent_expired_is_recycled();
    test_busy_expired_is_kept();
    test_young_conn_is_kept();
    test_unstamped_conn_is_kept();

    if (failures == 0) {
        printf("OK: all connection-lifetime quiescence-guard tests passed\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
}
