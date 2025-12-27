/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-future.h"

#include "fiber.h"
#include "fiber-def.h"

int sd_bus_call_suspend(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_bus_error *reterr_error, sd_bus_message **ret_reply) {
        Fiber *f = ASSERT_PTR(fiber_get_current());
        int r;

        assert(bus);
        assert(m);

        _cleanup_(sd_future_unrefp) sd_future *call = NULL;
        r = sd_bus_call_future(bus, m, usec, &call);
        if (r < 0)
                return r;

        r = sd_future_set_callback(call, fiber_resume, f);
        if (r < 0)
                return r;

        r = fiber_suspend();
        if (r < 0)
                return r;

        sd_bus_message *reply;
        r = sd_future_bus_reply(call, &reply);
        if (r < 0)
                return r;

        if (sd_bus_message_is_method_error(reply, NULL)) {
                if (reterr_error)
                        sd_bus_error_copy(reterr_error, sd_bus_message_get_error(reply));
                return -sd_bus_message_get_errno(reply);
        }

        if (reterr_error)
                *reterr_error = SD_BUS_ERROR_NULL;
        if (ret_reply)
                *ret_reply = sd_bus_message_ref(reply);

        return 0;
}
