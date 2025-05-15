/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-locator.h"
#include "main-func.h"
#include "tests.h"

static int run(int argc, char **argv) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *ref = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *username = NULL;

        /* This is a regression test for the following bug:
         * https://github.com/systemd/systemd/pull/31896
         * It is run as part of TEST-46-HOMED
         */

        test_setup_logging(LOG_DEBUG);
        assert_se(sd_bus_open_system(&bus) >= 0);

        assert_se(argc == 2);
        username = argv[1];

        assert_se(bus_call_method(bus, bus_home_mgr, "RefHomeUnrestricted", NULL, &ref, "sb", username, true) >= 0);

        assert_se(bus_call_method_async(bus, NULL, bus_home_mgr, "AuthenticateHome", NULL, NULL, "ss", username, "{}") >= 0);
        assert_se(sd_bus_flush(bus) >= 0);

        (void) bus_call_method(bus, bus_home_mgr, "ReleaseHome", &error, NULL, "s", username);
        assert_se(!sd_bus_error_has_name(&error, SD_BUS_ERROR_NO_REPLY)); /* Make sure we didn't crash */

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
