/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-common-errors.h"
#include "bus-locator.h"
#include "main-func.h"
#include "tests.h"

static int on_remove_reply(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        int *result = ASSERT_PTR(userdata);
        const sd_bus_error *e;

        e = sd_bus_message_get_error(m);
        if (e)
                log_error("Removing home failed: %s", e->message);

        *result = e ? -1 : 1;
        return 0;
}

static int run(int argc, char **argv) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *username = NULL;
        int remove_result = 0;

        /* This is a regression test for the following bug:
         * https://github.com/systemd/systemd/pull/44837
         * It is run as part of TEST-46-HOMED
         */

        test_setup_logging(LOG_DEBUG);
        ASSERT_OK(sd_bus_open_system(&bus));

        ASSERT_EQ(argc, 2);
        username = argv[1];

        /* Release the home while it is being removed. The release is queued until the removal is complete,
         * and must then get a reply instead of being left waiting until the call times out. */
        ASSERT_OK(bus_call_method_async(bus, /* ret_slot= */ NULL, bus_home_mgr, "RemoveHome",
                                        on_remove_reply, &remove_result, "s", username));
        ASSERT_OK(sd_bus_flush(bus));

        (void) bus_call_method(bus, bus_home_mgr, "ReleaseHome", &error, /* ret_reply= */ NULL, "s", username);
        ASSERT_TRUE(sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_HOME));

        /* Wait for the removal itself to complete */
        while (remove_result == 0) {
                if (ASSERT_OK(sd_bus_process(bus, /* ret= */ NULL)) > 0)
                        continue;

                ASSERT_OK(sd_bus_wait(bus, UINT64_MAX));
        }

        ASSERT_EQ(remove_result, 1);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
