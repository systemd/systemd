/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "bus-future.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "log.h"

typedef struct BusFuture {
        sd_bus_slot *slot;
        sd_bus_message *reply;
} BusFuture;

static void* bus_future_alloc(void) {
        return new0(BusFuture, 1);
}

static void bus_future_free(sd_future *f) {
        BusFuture *bf = ASSERT_PTR(sd_future_get_private(f));
        sd_bus_slot_unref(bf->slot);
        sd_bus_message_unref(bf->reply);
        free(bf);
}

static int bus_future_cancel(sd_future *f) {
        BusFuture *bf = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));

        bf->slot = sd_bus_slot_unref(bf->slot);
        return sd_future_resolve(f, -ECANCELED);
}

static const sd_future_ops bus_future_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = bus_future_alloc,
        .free = bus_future_free,
        .cancel = bus_future_cancel,
};

static int bus_future_handler(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        sd_future *f = ASSERT_PTR(userdata);
        BusFuture *bf = ASSERT_PTR(sd_future_get_private(f));
        int r;

        /* Resolve with 0 on a success reply and -errno (derived from the D-Bus error name) on a
         * method error reply, so a caller awaiting the future learns about call failures from the
         * resolution value alone. The reply itself is always stashed in bf->reply so
         * future_get_bus_reply() can hand back the detailed sd_bus_error (name + message) on
         * top of the bare errno. Cancellation surfaces as -ECANCELED via bus_future_cancel(),
         * with bf->reply left NULL — callers can distinguish "got an error reply" from "no reply
         * will arrive" by whether future_get_bus_reply() can produce a message. */
        bf->slot = sd_bus_slot_unref(bf->slot);
        bf->reply = sd_bus_message_ref(m);

        r = sd_bus_message_is_method_error(m, NULL) ? -sd_bus_message_get_errno(m) : 0;
        return sd_future_resolve(f, r);
}

int bus_call_future(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_future **ret) {
        int r;

        assert(bus);
        assert(m);
        assert(ret);

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        r = sd_future_new(&bus_future_ops, &f);
        if (r < 0)
                return r;

        BusFuture *bf = sd_future_get_private(f);

        r = sd_bus_call_async(bus, &bf->slot, m, bus_future_handler, f, usec);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return 0;
}

int future_get_bus_reply(sd_future *f, sd_bus_error *reterr_error, sd_bus_message **ret_reply) {
        BusFuture *bf = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        sd_bus_message *reply = ASSERT_PTR(bf->reply);

        assert(sd_future_get_ops(f) == &bus_future_ops);
        assert(sd_future_state(f) == SD_FUTURE_RESOLVED);

        if (sd_bus_message_is_method_error(reply, NULL)) {
                if (reterr_error)
                        return sd_bus_error_copy(reterr_error, sd_bus_message_get_error(reply));
                return -sd_bus_message_get_errno(reply);
        }

        if (reply->n_fds > 0 && !sd_bus_message_get_bus(reply)->accept_fd)
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INCONSISTENT_MESSAGE,
                                        "Reply message contained file descriptors which I couldn't accept. Sorry.");

        if (reterr_error)
                *reterr_error = SD_BUS_ERROR_NULL;
        if (ret_reply)
                *ret_reply = sd_bus_message_ref(reply);

        return 1;
}

static void bus_signal_channel_item_destroy(void *p) {
        sd_bus_message_unref(p);
}

static void bus_signal_channel_slot_destroy(void *p) {
        sd_bus_slot_unref(p);
}

static int bus_signal_channel_handler(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        sd_channel *c = ASSERT_PTR(userdata);
        int r;

        /* Take a fresh ref for the channel — sd-bus retains ownership of `m` for the duration
         * of the callback only. The channel's destroy callback will drop this ref whether the
         * message is consumed or freed with the channel. */
        sd_bus_message *ref = sd_bus_message_ref(m);
        r = sd_channel_try_push(c, ref);
        if (r >= 0)
                return 0;

        sd_bus_message_unref(ref);
        if (r == -ENOBUFS)
                log_warning("Bus signal channel full, dropping signal.");
        else
                log_warning_errno(r, "Failed to enqueue bus signal, dropping: %m");
        return 0;
}

static int bus_signal_channel_install_handler(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        sd_channel *c = ASSERT_PTR(userdata);

        /* If AddMatch fails the subscription is dead — close the channel so consumers see
         * -EPIPE on the next pop instead of waiting forever. close() runs slot_destroy too,
         * cleaning up the (already-broken) slot we're about to forget about. */
        if (sd_bus_message_is_method_error(m, /* name= */ NULL)) {
                log_warning("AddMatch failed for bus signal channel: %s",
                            sd_bus_message_get_error(m)->message);
                sd_channel_close(c);
        }
        return 0;
}

int bus_signal_channel_new(
                sd_bus *bus,
                const char *sender,
                const char *path,
                const char *interface,
                const char *member,
                size_t capacity,
                sd_channel **ret) {

        int r;

        assert(bus);
        assert(ret);

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        r = sd_channel_new(sd_bus_get_event(bus), capacity, bus_signal_channel_item_destroy, &c);
        if (r < 0)
                return r;

        /* The match callback's userdata is a borrowed channel pointer. Safe because the
         * channel owns the slot (set_slot below) — when the channel is freed it tears down
         * the slot first, so no callback can fire on a dangling channel. */
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        r = sd_bus_match_signal_async(bus, &slot, sender, path, interface, member,
                                      bus_signal_channel_handler,
                                      bus_signal_channel_install_handler,
                                      c);
        if (r < 0)
                return r;

        /* Hand the slot to the channel. From here on, dropping the channel (close or final
         * unref) is what unsubscribes. */
        r = sd_channel_set_slot(c, slot, bus_signal_channel_slot_destroy);
        if (r < 0)
                return r;

        TAKE_PTR(slot);

        *ret = TAKE_PTR(c);
        return 0;
}

int bus_call_suspend(
                sd_bus *bus,
                sd_bus_message *m,
                uint64_t usec,
                sd_bus_error *reterr_error,
                sd_bus_message **ret_reply) {

        int r;

        assert(bus);
        assert(m);
        assert(sd_fiber_is_running());

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *f = NULL;
        r = bus_call_future(bus, m, usec, &f);
        if (r < 0)
                return sd_bus_error_set_errno(reterr_error, r);

        r = sd_fiber_suspend();

        /* If the future isn't resolved, the suspend was interrupted before a reply arrived (fiber
         * cancelled, fiber-wide SD_FIBER_TIMEOUT scope expired, …). There's no reply to extract,
         * so surface the resume error directly. When the future is resolved, future_get_bus_reply()
         * recovers either the reply or the detailed sd_bus_error from the error reply. */
        if (sd_future_state(f) != SD_FUTURE_RESOLVED)
                return sd_bus_error_set_errno(reterr_error, r);

        return future_get_bus_reply(f, reterr_error, ret_reply);
}
