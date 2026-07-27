/*
 * Standalone unit test for the deferred-send flush queue (perf-cpu plan
 * Tasks 3+4):
 *
 *   conn_pend_flush / conn_unpend_flush -- idempotent membership of a conn in
 *   the per-context flush queue.
 *
 *   conn_send_pending -- true iff the conn still has sendable-but-unsent
 *   data: smsg set, a server conn with a non-empty imsg_q (send_done only
 *   dequeues fully-sent msgs, so a partial write stays at the head), or a
 *   client conn whose omsg_q head request is done.
 *
 *   core_flush_drain -- pop-head drain: sends once per pended conn, clears
 *   the queue, skips err/done conns (their armed READ event owns the close)
 *   and connecting conns (their armed connect EPOLLOUT owns the first send).
 *
 * Fabricated ctx/conns, stub conn->send; the happy paths exercised here never
 * reach event_add_out/core_close, so no event base is needed.
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
#include <nc_conf.h>
#include <nc_string.h>

/* nc.c owns main(); stub nc_post_run for the linker (see sibling tests). */
void nc_post_run(struct instance *nci) { (void)nci; }

static int failures = 0;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);               \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n");                                             \
        }                                                                      \
    } while (0)

static int sends;

static rstatus_t
stub_send(struct context *ctx, struct conn *conn)
{
    (void)ctx; (void)conn;
    sends++;
    return NC_OK;
}

static void
conn_reset(struct conn *c)
{
    memset(c, 0, sizeof(*c));
    TAILQ_INIT(&c->imsg_q);
    TAILQ_INIT(&c->omsg_q);
    c->send = stub_send;
}

int
main(void)
{
    struct context ctx;
    struct conn a, b;
    struct msg m;

    memset(&ctx, 0, sizeof(ctx));
    TAILQ_INIT(&ctx.flush_connq);
    conn_reset(&a);
    conn_reset(&b);
    memset(&m, 0, sizeof(m));

    /* pend is idempotent: double-pend keeps one entry, FIFO order kept */
    conn_pend_flush(&ctx, &a);
    conn_pend_flush(&ctx, &a);
    conn_pend_flush(&ctx, &b);
    CHECK(a.in_flushq == 1 && b.in_flushq == 1, "flags not set");
    CHECK(TAILQ_FIRST(&ctx.flush_connq) == &a, "head not a");
    CHECK(TAILQ_NEXT(&a, flush_tqe) == &b, "second not b");
    CHECK(TAILQ_NEXT(&b, flush_tqe) == NULL, "tail not b");

    /* unpend from the middle is safe and idempotent */
    conn_unpend_flush(&ctx, &a);
    conn_unpend_flush(&ctx, &a);
    CHECK(a.in_flushq == 0, "a flag not cleared");
    CHECK(TAILQ_FIRST(&ctx.flush_connq) == &b, "head not b after unpend");

    conn_unpend_flush(&ctx, &b);
    CHECK(TAILQ_EMPTY(&ctx.flush_connq), "queue not empty");

    /* send_pending: empty server conn -> false; msg on imsg_q -> true */
    CHECK(conn_send_pending(&a) == false, "empty server conn pending");
    TAILQ_INSERT_TAIL(&a.imsg_q, &m, s_tqe);
    CHECK(conn_send_pending(&a) == true, "queued server conn not pending");
    TAILQ_REMOVE(&a.imsg_q, &m, s_tqe);

    /* smsg set -> true regardless of queues */
    a.smsg = &m;
    CHECK(conn_send_pending(&a) == true, "smsg conn not pending");
    a.smsg = NULL;

    /* proxy conn never pends sends */
    a.proxy = 1;
    a.smsg = NULL;
    CHECK(conn_send_pending(&a) == false, "proxy conn pending");
    a.proxy = 0;

    /* drain: calls conn->send once per pended conn, clears the queue */
    sends = 0;
    conn_pend_flush(&ctx, &a);
    conn_pend_flush(&ctx, &b);
    core_flush_drain(&ctx);
    CHECK(sends == 2, "drain sends=%d expected 2", sends);
    CHECK(TAILQ_EMPTY(&ctx.flush_connq), "queue not drained");
    CHECK(a.in_flushq == 0 && b.in_flushq == 0, "flags not cleared by drain");

    /* connecting conns are skipped (their armed connect EPOLLOUT sends) */
    sends = 0;
    a.connecting = 1;
    conn_pend_flush(&ctx, &a);
    core_flush_drain(&ctx);
    CHECK(sends == 0, "connecting conn was sent");
    CHECK(TAILQ_EMPTY(&ctx.flush_connq), "connecting conn left queued");
    a.connecting = 0;

    /* err conns are skipped (their armed READ event closes them) */
    sends = 0;
    a.err = 1;
    conn_pend_flush(&ctx, &a);
    core_flush_drain(&ctx);
    CHECK(sends == 0, "err conn was sent");
    a.err = 0;

    /* done conns are skipped the same way */
    sends = 0;
    a.done = 1;
    conn_pend_flush(&ctx, &a);
    core_flush_drain(&ctx);
    CHECK(sends == 0, "done conn was sent");
    a.done = 0;

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("OK: flush queue pend/unpend/pending/drain semantics\n");
    return 0;
}
