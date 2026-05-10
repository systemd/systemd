/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "bus-future.h"
#include "bus-internal.h"
#include "bus-message.h"

typedef struct BusFuture {
        sd_bus_slot *slot;
        sd_bus_message *reply;
} BusFuture;

static void* bus_future_alloc(void) {
        return new0(BusFuture, 1);
}

static void bus_future_free(sd_future *f) {
        BusFuture *bf = sd_future_get_private(f);
        sd_bus_slot_unref(bf->slot);
        sd_bus_message_unref(bf->reply);
        free(bf);
}

static int bus_future_cancel(sd_future *f) {
        BusFuture *bf = ASSERT_PTR(sd_future_get_private(f));

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

        /* Resolve with 0 on any reply (including error replies). The reply itself carries
         * success/error information via future_get_bus_reply(); the future's resolution result is
         * reserved for cancellation (-ECANCELED), so callers can distinguish "got a reply" from
         * "no reply will arrive". */
        bf->slot = sd_bus_slot_unref(bf->slot);
        bf->reply = sd_bus_message_ref(m);
        return sd_future_resolve(f, 0);
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
        assert(f);
        assert(sd_future_get_ops(f) == &bus_future_ops);
        assert(sd_future_state(f) == SD_FUTURE_RESOLVED);

        BusFuture *bf = ASSERT_PTR(sd_future_get_private(f));
        sd_bus_message *reply = ASSERT_PTR(bf->reply);

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

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *call = NULL;
        r = bus_call_future(bus, m, usec, &call);
        if (r < 0)
                return r;

        r = sd_fiber_suspend();
        if (r < 0)
                return r;

        return future_get_bus_reply(call, reterr_error, ret_reply);
}
