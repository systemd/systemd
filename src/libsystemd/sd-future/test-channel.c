/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-future.h"

#include "tests.h"

static unsigned destroyed_count;

static void int_destroy(void *p) {
        destroyed_count++;
}

static void reset_destroy_counter(void) {
        destroyed_count = 0;
}

TEST(channel_try_push_pop_fifo) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 4, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

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

        ASSERT_ERROR(sd_channel_try_pop(c, &p), ENODATA);
        ASSERT_EQ(destroyed_count, 0u);
}

TEST(channel_try_push_full) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(10)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(20)));
        ASSERT_ERROR(sd_channel_try_push(c, INT_TO_PTR(30)), ENOBUFS);
        ASSERT_EQ(destroyed_count, 0u);
}

TEST(channel_try_pop_empty) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        void *p;
        ASSERT_ERROR(sd_channel_try_pop(c, &p), ENODATA);
}

TEST(channel_close_drain_then_epipe) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 4, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

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

TEST(channel_unref_drains_through_destroy) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 4, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(2)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(3)));

        c = sd_channel_unref(c);
        ASSERT_EQ(destroyed_count, 3u);
}

TEST(channel_recv_immediate) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(42)));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_channel_recv(c, &f));
        ASSERT_EQ(sd_future_state(f), SD_FUTURE_RESOLVED);
        ASSERT_OK_ZERO(sd_future_result(f));

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_recv_get(f, &p));
        ASSERT_EQ(PTR_TO_INT(p), 42);

        ASSERT_ERROR(sd_channel_recv_get(f, &p), ESTALE);
        ASSERT_EQ(destroyed_count, 0u);
}

TEST(channel_recv_closed_empty) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK(sd_channel_close(c));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_ERROR(sd_channel_recv(c, &f), EPIPE);
        ASSERT_NULL(f);
}

TEST(channel_send_immediate) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_channel_send(c, INT_TO_PTR(7), &f));
        ASSERT_EQ(sd_future_state(f), SD_FUTURE_RESOLVED);
        ASSERT_OK_ZERO(sd_future_result(f));

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 7);
        ASSERT_EQ(destroyed_count, 0u);
}

TEST(channel_send_closed) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK(sd_channel_close(c));

        sd_future *f = NULL;
        ASSERT_ERROR(sd_channel_send(c, INT_TO_PTR(1), &f), EPIPE);
        ASSERT_NULL(f);
        ASSERT_EQ(destroyed_count, 1u);
}

TEST(channel_recv_dropped_value_destroyed) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(5)));

        sd_future *f = NULL;
        ASSERT_OK(sd_channel_recv(c, &f));
        ASSERT_EQ(sd_future_state(f), SD_FUTURE_RESOLVED);

        /* The item was never taken with sd_channel_recv_get(), so freeing the future destroys it. */
        f = sd_future_unref(f);
        ASSERT_EQ(destroyed_count, 1u);
}

TEST(channel_direct_handoff_push_to_recv) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        _cleanup_(sd_future_unrefp) sd_future *recv = NULL;
        ASSERT_OK(sd_channel_recv(c, &recv));
        ASSERT_EQ(sd_future_state(recv), SD_FUTURE_PENDING);

        void *p;
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_channel_recv_get(recv, &p)), EBUSY);

        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(123)));
        ASSERT_EQ(sd_future_state(recv), SD_FUTURE_RESOLVED);
        ASSERT_OK_ZERO(sd_future_result(recv));

        ASSERT_OK_POSITIVE(sd_channel_recv_get(recv, &p));
        ASSERT_EQ(PTR_TO_INT(p), 123);
        ASSERT_EQ(destroyed_count, 0u);
}

TEST(channel_sender_promotion) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(2)));

        _cleanup_(sd_future_unrefp) sd_future *send_f = NULL;
        ASSERT_OK(sd_channel_send(c, INT_TO_PTR(3), &send_f));
        ASSERT_EQ(sd_future_state(send_f), SD_FUTURE_PENDING);

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 1);
        ASSERT_EQ(sd_future_state(send_f), SD_FUTURE_RESOLVED);
        ASSERT_OK_ZERO(sd_future_result(send_f));

        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 2);
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 3);
        ASSERT_EQ(destroyed_count, 0u);
}

TEST(channel_close_wakes_pending_recv) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        _cleanup_(sd_future_unrefp) sd_future *recv = NULL;
        ASSERT_OK(sd_channel_recv(c, &recv));
        ASSERT_EQ(sd_future_state(recv), SD_FUTURE_PENDING);

        ASSERT_OK(sd_channel_close(c));
        ASSERT_EQ(sd_future_state(recv), SD_FUTURE_RESOLVED);
        ASSERT_ERROR(sd_future_result(recv), EPIPE);
}

TEST(channel_close_wakes_pending_send) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 1, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));

        sd_future *send_f = NULL;
        ASSERT_OK(sd_channel_send(c, INT_TO_PTR(2), &send_f));
        ASSERT_EQ(sd_future_state(send_f), SD_FUTURE_PENDING);

        ASSERT_OK(sd_channel_close(c));
        ASSERT_EQ(sd_future_state(send_f), SD_FUTURE_RESOLVED);
        ASSERT_ERROR(sd_future_result(send_f), EPIPE);

        /* The rejected send still owns item 2, so freeing its future destroys it. */
        send_f = sd_future_unref(send_f);
        ASSERT_EQ(destroyed_count, 1u);
}

TEST(channel_cancel_pending_recv) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        _cleanup_(sd_future_unrefp) sd_future *recv = NULL;
        ASSERT_OK(sd_channel_recv(c, &recv));
        ASSERT_EQ(sd_future_state(recv), SD_FUTURE_PENDING);

        ASSERT_OK(sd_future_cancel(recv));
        ASSERT_EQ(sd_future_state(recv), SD_FUTURE_RESOLVED);
        ASSERT_ERROR(sd_future_result(recv), ECANCELED);

        /* The cancelled receive future must not get this item. */
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(99)));

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 99);
        ASSERT_EQ(destroyed_count, 0u);
}

TEST(channel_cancel_pending_send) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 1, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));

        sd_future *parked = NULL;
        ASSERT_OK(sd_channel_send(c, INT_TO_PTR(2), &parked));
        ASSERT_EQ(sd_future_state(parked), SD_FUTURE_PENDING);

        ASSERT_OK(sd_future_cancel(parked));
        ASSERT_EQ(sd_future_state(parked), SD_FUTURE_RESOLVED);
        ASSERT_ERROR(sd_future_result(parked), ECANCELED);

        parked = sd_future_unref(parked);
        ASSERT_EQ(destroyed_count, 1u);

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(3)));
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
}

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
        /* With capacity 1, the producer has to wait for the consumer after every push. */
        ASSERT_OK(sd_channel_new(e, 1, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

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

/* Send futures and receive futures share channel_ops, so sd_channel_recv_get() accepts a send future.
 * The item of a completed send is in the buffer, so the call fails with -ESTALE. */
TEST(channel_recv_get_on_send_future_returns_estale) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        _cleanup_(sd_future_unrefp) sd_future *send_f = NULL;
        ASSERT_OK(sd_channel_send(c, INT_TO_PTR(1), &send_f));
        ASSERT_EQ(sd_future_state(send_f), SD_FUTURE_RESOLVED);

        void *p;
        ASSERT_ERROR(sd_channel_recv_get(send_f, &p), ESTALE);

        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(destroyed_count, 0u);
}

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
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        ASSERT_OK(sd_channel_set_slot(c, INT_TO_PTR(0xABCD), slot_destroy_track));

        ASSERT_OK(sd_channel_close(c));
        ASSERT_EQ(slot_destroyed_count, 1u);

        ASSERT_OK(sd_channel_close(c));
        ASSERT_EQ(slot_destroyed_count, 1u);
}

/* The slot usually owns the event source that pushes into the channel. If the last unref didn't
 * destroy the slot, that source would push into a freed channel. */
TEST(channel_slot_destroyed_on_unref) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        slot_destroyed_count = 0;

        sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        ASSERT_OK(sd_channel_set_slot(c, INT_TO_PTR(0xABCD), slot_destroy_track));

        c = sd_channel_unref(c);
        ASSERT_EQ(slot_destroyed_count, 1u);
}

TEST(channel_slot_replace) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        slot_destroyed_count = 0;

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        ASSERT_OK(sd_channel_set_slot(c, INT_TO_PTR(0xAAAA), slot_destroy_track));
        ASSERT_OK(sd_channel_set_slot(c, INT_TO_PTR(0xBBBB), slot_destroy_track));
        ASSERT_EQ(slot_destroyed_count, 1u);

        ASSERT_OK(sd_channel_set_slot(c, NULL, NULL));
        ASSERT_EQ(slot_destroyed_count, 2u);
}

TEST(channel_slot_set_after_close) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        slot_destroyed_count = 0;

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK(sd_channel_close(c));

        ASSERT_ERROR(sd_channel_set_slot(c, INT_TO_PTR(0xABCD), slot_destroy_track), EPIPE);
        ASSERT_EQ(slot_destroyed_count, 0u);
}

static void slot_destroy_unref_channel(void *p) {
        sd_channel_unref(p);
}

TEST(channel_slot_destroy_drops_last_ref) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK(sd_channel_set_slot(c, c, slot_destroy_unref_channel));
        ASSERT_OK(sd_channel_close(c));

        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK(sd_channel_set_slot(c, c, slot_destroy_unref_channel));
        ASSERT_OK(sd_channel_set_slot(c, NULL, NULL));
}

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
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        _cleanup_(sd_future_unrefp) sd_future *fiber = NULL;
        ASSERT_OK(sd_fiber_new(e, "blocked-pop", blocked_pop_fiber, c, NULL, &fiber));

        /* Priority 100 makes the close run after the fiber has suspended in sd_channel_pop(). */
        _cleanup_(sd_event_source_unrefp) sd_event_source *src = NULL;
        ASSERT_OK(sd_event_add_defer(e, &src, close_after_idle, c));
        ASSERT_OK(sd_event_source_set_priority(src, 100));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(fiber), EPIPE);
}

TEST(channel_overflow_drop_oldest_try_push) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_DROP_OLDEST, int_destroy, &c));

        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(2)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(3)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(4)));
        ASSERT_EQ(destroyed_count, 2u);

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 3);
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 4);
        ASSERT_ERROR(sd_channel_try_pop(c, &p), ENODATA);
        ASSERT_EQ(destroyed_count, 2u);
}

TEST(channel_overflow_drop_latest_try_push) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_DROP_LATEST, int_destroy, &c));

        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(2)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(3)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(4)));
        ASSERT_EQ(destroyed_count, 2u);

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 1);
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 2);
        ASSERT_ERROR(sd_channel_try_pop(c, &p), ENODATA);
        ASSERT_EQ(destroyed_count, 2u);
}

TEST(channel_overflow_send_never_parks) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        static const struct {
                sd_channel_overflow_t policy;
                int survivor;
        } cases[] = {
                { SD_CHANNEL_OVERFLOW_DROP_OLDEST, 2 },
                { SD_CHANNEL_OVERFLOW_DROP_LATEST, 1 },
        };

        FOREACH_ELEMENT(i, cases) {
                reset_destroy_counter();

                _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
                ASSERT_OK(sd_channel_new(e, 1, i->policy, int_destroy, &c));
                ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));

                _cleanup_(sd_future_unrefp) sd_future *send_f = NULL;
                ASSERT_OK(sd_channel_send(c, INT_TO_PTR(2), &send_f));
                ASSERT_EQ(sd_future_state(send_f), SD_FUTURE_RESOLVED);
                ASSERT_OK_ZERO(sd_future_result(send_f));
                ASSERT_EQ(destroyed_count, 1u);

                void *p;
                ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
                ASSERT_EQ(PTR_TO_INT(p), i->survivor);
        }
}

TEST(channel_overflow_drop_oldest_latest_wins) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 1, SD_CHANNEL_OVERFLOW_DROP_OLDEST, int_destroy, &c));

        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(2)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(3)));
        ASSERT_EQ(destroyed_count, 2u);

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 3);
        ASSERT_ERROR(sd_channel_try_pop(c, &p), ENODATA);
        ASSERT_EQ(destroyed_count, 2u);
}

TEST(channel_new_conflated) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new_conflated(e, int_destroy, &c));

        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(2)));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(3)));
        ASSERT_EQ(destroyed_count, 2u);

        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 3);
        ASSERT_ERROR(sd_channel_try_pop(c, &p), ENODATA);
        ASSERT_EQ(destroyed_count, 2u);
}

TEST(channel_new_invalid) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        sd_channel *c = NULL;
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_channel_new(e, 0, SD_CHANNEL_OVERFLOW_WAIT, NULL, &c)), EINVAL);
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_channel_new(e, 1, (sd_channel_overflow_t) 3, NULL, &c)), EINVAL);

        /* No default event loop exists, so SD_EVENT_DEFAULT does not resolve to one. */
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(
                        sd_channel_new(SD_EVENT_DEFAULT, 1, SD_CHANNEL_OVERFLOW_WAIT, NULL, &c)), ENOPKG);
        ASSERT_NULL(c);
}

TEST(channel_null_item) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 1, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_channel_try_push(c, NULL)), EINVAL);

        sd_future *f = NULL;
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_channel_send(c, NULL, &f)), EINVAL);
        ASSERT_NULL(f);
}

typedef struct FiberOp {
        sd_channel *channel;
        void *item;
        int result;
        int yield_result;
} FiberOp;

static int push_fiber(void *userdata) {
        FiberOp *op = ASSERT_PTR(userdata);

        op->result = sd_channel_push(op->channel, op->item);
        op->yield_result = sd_fiber_yield();
        return 0;
}

static int pop_fiber(void *userdata) {
        FiberOp *op = ASSERT_PTR(userdata);

        op->result = sd_channel_pop(op->channel, &op->item);
        op->yield_result = sd_fiber_yield();
        return 0;
}

static void run_until_awaiting(sd_event *e, sd_future *fiber) {
        while (!sd_fiber_get_awaiting(fiber))
                ASSERT_OK(sd_event_run(e, 0));
}

TEST(channel_push_closed) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 1, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK(sd_channel_close(c));

        FiberOp op = { .channel = c, .item = INT_TO_PTR(1) };
        _cleanup_(sd_future_unrefp) sd_future *fiber = NULL;
        ASSERT_OK(sd_fiber_new(e, "push", push_fiber, &op, NULL, &fiber));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(op.result, EPIPE);
        ASSERT_EQ(destroyed_count, 1u);
}

TEST(channel_push_closed_while_waiting) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 1, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));

        FiberOp op = { .channel = c, .item = INT_TO_PTR(2) };
        _cleanup_(sd_future_unrefp) sd_future *fiber = NULL;
        ASSERT_OK(sd_fiber_new(e, "push", push_fiber, &op, NULL, &fiber));
        run_until_awaiting(e, fiber);

        ASSERT_OK(sd_channel_close(c));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(op.result, EPIPE);
        ASSERT_EQ(destroyed_count, 1u);
}

TEST(channel_push_cancelled_while_waiting) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 1, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));

        FiberOp op = { .channel = c, .item = INT_TO_PTR(2) };
        _cleanup_(sd_future_unrefp) sd_future *fiber = NULL;
        ASSERT_OK(sd_fiber_new(e, "push", push_fiber, &op, NULL, &fiber));
        run_until_awaiting(e, fiber);

        ASSERT_OK(sd_future_cancel(fiber));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(op.result, ECANCELED);
        ASSERT_EQ(destroyed_count, 1u);
}

TEST(channel_push_cancelled_after_send) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 1, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));

        FiberOp op = { .channel = c, .item = INT_TO_PTR(2) };
        _cleanup_(sd_future_unrefp) sd_future *fiber = NULL;
        ASSERT_OK(sd_fiber_new(e, "push", push_fiber, &op, NULL, &fiber));
        run_until_awaiting(e, fiber);

        /* The pop moves item 2 into the buffer before the fiber wakes up from the cancellation. */
        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 1);
        ASSERT_OK(sd_future_cancel(fiber));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(op.result);
        ASSERT_ERROR(op.yield_result, ECANCELED);
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 2);
        ASSERT_EQ(destroyed_count, 0u);
}

TEST(channel_pop_cancelled_after_delivery) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 1, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));

        FiberOp op = { .channel = c };
        _cleanup_(sd_future_unrefp) sd_future *fiber = NULL;
        ASSERT_OK(sd_fiber_new(e, "pop", pop_fiber, &op, NULL, &fiber));
        run_until_awaiting(e, fiber);

        /* The push hands item 5 to the fiber before the fiber wakes up from the cancellation. */
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(5)));
        ASSERT_OK(sd_future_cancel(fiber));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(op.result);
        ASSERT_ERROR(op.yield_result, ECANCELED);
        ASSERT_EQ(PTR_TO_INT(op.item), 5);
        ASSERT_EQ(destroyed_count, 0u);
}

static int interrupted_push_pop_fiber(void *userdata) {
        sd_channel *c = ASSERT_PTR(userdata);
        void *p;

        /* The channel holds an item and has room for another, so sd_channel_pop() and sd_channel_push()
         * would not suspend. The queued cancellation must still make each call fail without moving an
         * item. */
        ASSERT_OK(sd_fiber_resume(sd_fiber_get_current(), -ECANCELED));
        ASSERT_ERROR(sd_channel_pop(c, &p), ECANCELED);

        ASSERT_OK(sd_fiber_resume(sd_fiber_get_current(), -ECANCELED));
        ASSERT_ERROR(sd_channel_push(c, INT_TO_PTR(2)), ECANCELED);
        return 0;
}

TEST(channel_push_pop_interrupted) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        reset_destroy_counter();

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        ASSERT_OK(sd_channel_new(e, 2, SD_CHANNEL_OVERFLOW_WAIT, int_destroy, &c));
        ASSERT_OK_POSITIVE(sd_channel_try_push(c, INT_TO_PTR(1)));

        _cleanup_(sd_future_unrefp) sd_future *fiber = NULL;
        ASSERT_OK(sd_fiber_new(e, "interrupted", interrupted_push_pop_fiber, c, NULL, &fiber));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(fiber));

        /* The push destroyed item 2, and item 1 is still in the buffer. */
        ASSERT_EQ(destroyed_count, 1u);
        void *p;
        ASSERT_OK_POSITIVE(sd_channel_try_pop(c, &p));
        ASSERT_EQ(PTR_TO_INT(p), 1);
        ASSERT_ERROR(sd_channel_try_pop(c, &p), ENODATA);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
