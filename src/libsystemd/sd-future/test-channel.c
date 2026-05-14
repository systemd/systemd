/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-future.h"

#include "tests.h"

/* Items are integers encoded as void* via INT_TO_PTR — no allocation needed. The destroy
 * callback just increments a global counter so tests can verify the channel handed every
 * orphan back. */

static unsigned destroyed_count;

static void int_destroy(void *p) {
        destroyed_count++;
}

static void reset_destroy_counter(void) {
        destroyed_count = 0;
}

/* try_push/try_pop on an open channel: items come out in FIFO order, and nothing is
 * destroyed because every push is paired with a pop. */
TEST(channel_try_push_pop_fifo) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 4, int_destroy, &c));

        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(2)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(3)));

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 1);
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 2);
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 3);

        ASSERT_ERROR(sd_channel_try_pop(c, &p), ENODATA);   /* empty */
        ASSERT_EQ(destroyed_count, 0u);
}

/* try_push returns -ENOBUFS when the buffer is full and there's no receiver to hand the
 * item to. The pushed item stays with the caller. */
TEST(channel_try_push_full) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));

        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(10)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(20)));
        ASSERT_ERROR(sd_channel_try_push(c, INT_TO_PTR(30)), ENOBUFS);
}

/* try_pop returns -ENODATA on an empty open channel. */
TEST(channel_try_pop_empty) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));

        void *p;
        ASSERT_ERROR(sd_channel_try_pop(c, &p), ENODATA);
}

/* After close, try_push fails with -EPIPE, and try_pop drains buffered items first and
 * only then returns -EPIPE. The destroy callback isn't called for items the caller
 * received (they own the value). */
TEST(channel_close_drain_then_epipe) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 4, int_destroy, &c));

        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(2)));
        ASSERT_OK(sd_channel_close(c));

        ASSERT_ERROR(sd_channel_try_push(c, INT_TO_PTR(99)), EPIPE);

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 1);
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 2);
        ASSERT_ERROR(sd_channel_try_pop(c, &p), EPIPE);

        ASSERT_EQ(destroyed_count, 0u);
}

/* Items remaining in the buffer when the last channel ref is dropped are handed back to
 * the destroy callback. */
TEST(channel_unref_drains_through_destroy) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 4, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(2)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(3)));

        c = sd_channel_unref(c);
        ASSERT_EQ(destroyed_count, 3u);
}

/* recv on a channel with a buffered item resolves immediately with 0; recv_get extracts
 * the value and the channel doesn't destroy it. */
TEST(channel_recv_immediate) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(42)));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_channel_recv(c, &f));
        ASSERT_EQ(sd_future_state(f), SD_FUTURE_RESOLVED);
        ASSERT_OK_ZERO(sd_future_result(f));

        void *p;
        ASSERT_OK(sd_channel_recv_get(f, &p));
        ASSERT_EQ(PTR_TO_INT(p), 42);

        /* Second extraction returns -ESTALE. */
        ASSERT_ERROR(sd_channel_recv_get(f, &p), ESTALE);
        ASSERT_EQ(destroyed_count, 0u);
}

/* recv on an empty closed channel returns -EPIPE directly without allocating a future. */
TEST(channel_recv_closed_empty) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));
        ASSERT_OK(sd_channel_close(c));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_ERROR(sd_channel_recv(c, &f), EPIPE);
        ASSERT_NULL(f);
}

/* send on a non-full channel resolves immediately with 0; the item flows through normally
 * and isn't destroyed. */
TEST(channel_send_immediate) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_channel_send(c, INT_TO_PTR(7), &f));
        ASSERT_EQ(sd_future_state(f), SD_FUTURE_RESOLVED);
        ASSERT_OK_ZERO(sd_future_result(f));

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 7);
        ASSERT_EQ(destroyed_count, 0u);
}

/* send on a closed channel returns -EPIPE directly without allocating a future. The caller
 * retains ownership of the item since the channel never accepted it. */
TEST(channel_send_closed) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));
        ASSERT_OK(sd_channel_close(c));

        sd_future *f = NULL;
        ASSERT_ERROR(sd_channel_send(c, INT_TO_PTR(1), &f), EPIPE);
        ASSERT_NULL(f);
        ASSERT_EQ(destroyed_count, 0u);
}

/* recv future dropped before extraction: a value that was delivered into the receiver
 * but never harvested must go back through the channel's destroy callback. */
TEST(channel_recv_dropped_value_destroyed) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(5)));

        sd_future *f = NULL;
        ASSERT_OK(sd_channel_recv(c, &f));
        ASSERT_EQ(sd_future_state(f), SD_FUTURE_RESOLVED);

        /* Drop without recv_get. */
        f = sd_future_unref(f);
        ASSERT_EQ(destroyed_count, 1u);
}

/* Direct handoff: a receive future created on an empty channel parks; a subsequent push
 * resolves the receiver's future without ever touching the buffer. */
TEST(channel_direct_handoff_push_to_recv) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));

        _cleanup_(sd_future_unrefp) sd_future *recv = NULL;
        ASSERT_OK(sd_channel_recv(c, &recv));
        ASSERT_EQ(sd_future_state(recv), SD_FUTURE_PENDING);

        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(123)));
        ASSERT_EQ(sd_future_state(recv), SD_FUTURE_RESOLVED);
        ASSERT_OK_ZERO(sd_future_result(recv));

        void *p;
        ASSERT_OK(sd_channel_recv_get(recv, &p));
        ASSERT_EQ(PTR_TO_INT(p), 123);
        ASSERT_EQ(destroyed_count, 0u);
}

/* Sender promotion: a full channel with a parked sender. When a receiver pops one item,
 * the parked sender's item is promoted into the now-vacant buffer slot and the sender's
 * future resolves with 0. */
TEST(channel_sender_promotion) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));

        /* Fill the buffer. */
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(2)));

        /* Send a third item — must park because the buffer is full. */
        _cleanup_(sd_future_unrefp) sd_future *send_f = NULL;
        ASSERT_OK(sd_channel_send(c, INT_TO_PTR(3), &send_f));
        ASSERT_EQ(sd_future_state(send_f), SD_FUTURE_PENDING);

        /* Pop one — the parked sender should now resolve and item 3 ends up in the buffer. */
        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 1);
        ASSERT_EQ(sd_future_state(send_f), SD_FUTURE_RESOLVED);
        ASSERT_OK_ZERO(sd_future_result(send_f));

        /* Drain the rest. */
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 2);
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 3);
        ASSERT_EQ(destroyed_count, 0u);
}

/* close while a receiver is pending resolves it with -EPIPE. */
TEST(channel_close_wakes_pending_recv) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));

        _cleanup_(sd_future_unrefp) sd_future *recv = NULL;
        ASSERT_OK(sd_channel_recv(c, &recv));
        ASSERT_EQ(sd_future_state(recv), SD_FUTURE_PENDING);

        ASSERT_OK(sd_channel_close(c));
        ASSERT_EQ(sd_future_state(recv), SD_FUTURE_RESOLVED);
        ASSERT_ERROR(sd_future_result(recv), EPIPE);
}

/* close while a sender is parked resolves it with -EPIPE; the parked item flows back
 * through destroy. */
TEST(channel_close_wakes_pending_send) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 1, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));

        sd_future *send_f = NULL;
        ASSERT_OK(sd_channel_send(c, INT_TO_PTR(2), &send_f));
        ASSERT_EQ(sd_future_state(send_f), SD_FUTURE_PENDING);

        ASSERT_OK(sd_channel_close(c));
        ASSERT_EQ(sd_future_state(send_f), SD_FUTURE_RESOLVED);
        ASSERT_ERROR(sd_future_result(send_f), EPIPE);

        send_f = sd_future_unref(send_f);
        ASSERT_EQ(destroyed_count, 1u);  /* the parked item 2 */
}

/* Cancel a parked receiver: future resolves with -ECANCELED, and the channel forgets
 * about it (a subsequent push goes into the buffer, not to the cancelled receiver). */
TEST(channel_cancel_pending_recv) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));

        _cleanup_(sd_future_unrefp) sd_future *recv = NULL;
        ASSERT_OK(sd_channel_recv(c, &recv));
        ASSERT_EQ(sd_future_state(recv), SD_FUTURE_PENDING);

        ASSERT_OK(sd_future_cancel(recv));
        ASSERT_EQ(sd_future_state(recv), SD_FUTURE_RESOLVED);
        ASSERT_ERROR(sd_future_result(recv), ECANCELED);

        /* Push afterwards: must end up in the buffer, not delivered to the cancelled recv. */
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(99)));

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 99);
        ASSERT_EQ(destroyed_count, 0u);
}

/* Cancel a parked sender: future resolves with -ECANCELED and the channel destroys the
 * unsent item. The channel itself stays open and a fresh send works. */
TEST(channel_cancel_pending_send) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 1, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));

        sd_future *parked = NULL;
        ASSERT_OK(sd_channel_send(c, INT_TO_PTR(2), &parked));
        ASSERT_EQ(sd_future_state(parked), SD_FUTURE_PENDING);

        ASSERT_OK(sd_future_cancel(parked));
        ASSERT_EQ(sd_future_state(parked), SD_FUTURE_RESOLVED);
        ASSERT_ERROR(sd_future_result(parked), ECANCELED);

        parked = sd_future_unref(parked);
        ASSERT_EQ(destroyed_count, 1u);  /* the cancelled-and-unsent item */

        /* Channel still works. */
        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(3)));
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
}

/* Cancel a parked receiver: ops->cancel removes it from recv_pending and resolves with
 * -ECANCELED. A subsequent push lands in the buffer rather than scribbling on freed memory. */
TEST(channel_drop_pending_recv) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));

        sd_future *recv = NULL;
        ASSERT_OK(sd_channel_recv(c, &recv));
        ASSERT_EQ(sd_future_state(recv), SD_FUTURE_PENDING);

        /* Cancel before unref: under the resolved-at-free invariant, an explicit cancel is
         * required to drive a pending future to RESOLVED. cancel_unref is the non-fiber form —
         * channel cancel resolves synchronously. */
        recv = sd_future_cancel_unref(recv);

        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(7)));

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 7);
}

/* Fiber convenience: a producer fiber pushes a few items, a consumer fiber pops them.
 * Their event-loop interleaving exercises the suspend/await paths of sd_channel_push /
 * sd_channel_pop. */
typedef struct PushPopState {
        sd_channel *channel;
        int sent[3];
        int received[3];
        size_t n_received;
} PushPopState;

static int producer_fiber(void *userdata) {
        PushPopState *s = ASSERT_PTR(userdata);
        for (size_t i = 0; i < ELEMENTSOF(s->sent); i++) {
                int r = sd_channel_push(s->channel, INT_TO_PTR(s->sent[i]));
                if (r < 0)
                        return r;
        }
        return 0;
}

static int consumer_fiber(void *userdata) {
        PushPopState *s = ASSERT_PTR(userdata);
        while (s->n_received < ELEMENTSOF(s->received)) {
                void *p;
                int r = sd_channel_pop(s->channel, &p);
                if (r < 0)
                        return r;
                s->received[s->n_received++] = PTR_TO_INT(p);
        }
        return 0;
}

TEST(channel_fiber_push_pop_fifo) {
        reset_destroy_counter();

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        /* Capacity 1 forces the producer to park between sends — exercises send-future
         * suspension and the receive-side promotion path. */
        ASSERT_OK(sd_channel_new(e, 1, int_destroy, &c));

        PushPopState s = {
                .channel = c,
                .sent = { 10, 20, 30 },
        };

        _cleanup_(sd_future_unrefp) sd_future *prod = NULL, *cons = NULL;
        ASSERT_OK(sd_fiber_new(e, "producer", producer_fiber, &s, NULL, &prod));
        ASSERT_OK(sd_fiber_new(e, "consumer", consumer_fiber, &s, NULL, &cons));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(prod));
        ASSERT_OK_ZERO(sd_future_result(cons));

        ASSERT_EQ(s.n_received, ELEMENTSOF(s.received));
        ASSERT_EQ(s.received[0], 10);
        ASSERT_EQ(s.received[1], 20);
        ASSERT_EQ(s.received[2], 30);
        ASSERT_EQ(destroyed_count, 0u);
}

/* pop_latest collapses a backlog into the most recent item, freeing intermediates through
 * the channel's destroy callback. */
typedef struct PopLatestState {
        sd_channel *channel;
        int got;
} PopLatestState;

static int pop_latest_fiber(void *userdata) {
        PopLatestState *s = ASSERT_PTR(userdata);
        void *p;
        int r = sd_channel_pop_latest(s->channel, &p);
        if (r < 0)
                return r;
        s->got = PTR_TO_INT(p);
        return 0;
}

TEST(channel_pop_latest_drains_to_freshest) {
        reset_destroy_counter();

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 4, int_destroy, &c));

        /* Pre-load four items. */
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(10)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(20)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(30)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(40)));

        PopLatestState s = { .channel = c };
        _cleanup_(sd_future_unrefp) sd_future *fiber = NULL;
        ASSERT_OK(sd_fiber_new(e, "pop-latest", pop_latest_fiber, &s, NULL, &fiber));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(fiber));

        ASSERT_EQ(s.got, 40);                /* freshest item */
        ASSERT_EQ(destroyed_count, 3u);      /* 10, 20, 30 destroyed; 40 handed back */
}

/* recv_get on a successfully-completed send future degrades to -ESTALE: the future is
 * resolved with 0 but its waiter has no item (it was moved into the channel buffer), so
 * the "already extracted" branch fires. Not a hard type error, but a recoverable one. */
TEST(channel_recv_get_on_send_future_returns_estale) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));

        _cleanup_(sd_future_unrefp) sd_future *send_f = NULL;
        ASSERT_OK(sd_channel_send(c, INT_TO_PTR(1), &send_f));
        ASSERT_EQ(sd_future_state(send_f), SD_FUTURE_RESOLVED);

        void *p;
        ASSERT_ERROR(sd_channel_recv_get(send_f, &p), ESTALE);

        /* The item is still in the channel — drain it so the destroy count stays 0. */
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(destroyed_count, 0u);
}

/* Slot lifecycle: a producer-side resource attached via sd_channel_set_slot must have its
 * destroy callback invoked exactly once when the channel is closed, before any pending
 * waiters are woken up. */
static unsigned slot_destroyed_count;

static void slot_destroy_track(void *p) {
        ASSERT_NOT_NULL(p);
        slot_destroyed_count++;
}

TEST(channel_slot_destroyed_on_close) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        slot_destroyed_count = 0;

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));

        ASSERT_OK(sd_channel_set_slot(c, INT_TO_PTR(0xABCD), slot_destroy_track));

        ASSERT_OK(sd_channel_close(c));
        ASSERT_EQ(slot_destroyed_count, 1u);

        /* Idempotent: a second close (or the unref below) must not invoke destroy again. */
        ASSERT_OK(sd_channel_close(c));
        ASSERT_EQ(slot_destroyed_count, 1u);
}

/* If close is never called explicitly, the final unref still runs slot destroy — otherwise
 * the producer source would dangle on a freed channel. */
TEST(channel_slot_destroyed_on_unref) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        slot_destroyed_count = 0;

        sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));

        ASSERT_OK(sd_channel_set_slot(c, INT_TO_PTR(0xABCD), slot_destroy_track));

        c = sd_channel_unref(c);
        ASSERT_EQ(slot_destroyed_count, 1u);
}

/* Replacing a slot destroys the previous one before installing the new one. */
TEST(channel_slot_replace) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        slot_destroyed_count = 0;

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));

        ASSERT_OK(sd_channel_set_slot(c, INT_TO_PTR(0xAAAA), slot_destroy_track));
        ASSERT_OK(sd_channel_set_slot(c, INT_TO_PTR(0xBBBB), slot_destroy_track));
        ASSERT_EQ(slot_destroyed_count, 1u);  /* the first slot was destroyed */

        ASSERT_OK(sd_channel_set_slot(c, NULL, NULL));  /* clear; destroys the second */
        ASSERT_EQ(slot_destroyed_count, 2u);
}

/* set_slot on a closed channel fails with -EPIPE so callers don't leak resources by
 * handing ownership to a channel that will never trigger destroy. */
TEST(channel_slot_set_after_close) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        slot_destroyed_count = 0;

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));
        ASSERT_OK(sd_channel_close(c));

        ASSERT_ERROR(sd_channel_set_slot(c, INT_TO_PTR(0xABCD), slot_destroy_track), EPIPE);
        ASSERT_EQ(slot_destroyed_count, 0u);
}

/* Fiber blocked on sd_channel_pop wakes with -EPIPE when the channel is closed from
 * outside. */
static int blocked_pop_fiber(void *userdata) {
        sd_channel *c = ASSERT_PTR(userdata);
        void *p;
        return sd_channel_pop(c, &p);
}

static int close_after_idle(sd_event_source *src, void *userdata) {
        sd_channel *c = ASSERT_PTR(userdata);
        return sd_channel_close(c);
}

TEST(channel_fiber_pop_close_wakeup) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, int_destroy, &c));

        _cleanup_(sd_future_unrefp) sd_future *fiber = NULL;
        ASSERT_OK(sd_fiber_new(e, "blocked-pop", blocked_pop_fiber, c, NULL, &fiber));

        /* Defer source runs after the fiber has had a chance to suspend on the pop. */
        _cleanup_(sd_event_source_unrefp) sd_event_source *src = NULL;
        ASSERT_OK(sd_event_add_defer(e, &src, close_after_idle, c));
        ASSERT_OK(sd_event_source_set_priority(src, 100));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(fiber), EPIPE);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
