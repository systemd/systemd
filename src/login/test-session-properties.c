/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Usage:
 * ./test-session-properties <SESSION-OBJECT-PATH>
 * e.g.,
 * ./test-session-properties /org/freedesktop/login1/session/_32
 */

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-locator.h"
#include "string-util.h"
#include "tests.h"

static BusLocator session;

/* Tests org.freedesktop.logind.Session SetType */
TEST(set_type) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char* types[] = {"tty", "x11", "wayland", "mir", "web"};
        _cleanup_free_ char *type = NULL, *type2 = NULL;

        assert_se(sd_bus_open_system(&bus) >= 0);

        /* Default type is set */
        assert_se(bus_get_property_string(bus, &session, "Type", NULL, &type) >= 0);
        assert_se(streq(type, "tty"));

        /* Type can only be set by the session controller (which we're not ATM) */
        assert_se(bus_call_method(bus, &session, "SetType", &error, NULL, "s", "x11") < 0);
        assert_se(sd_bus_error_has_name(&error, BUS_ERROR_NOT_IN_CONTROL));

        assert_se(bus_call_method(bus, &session, "TakeControl", NULL, NULL, "b", true) >= 0);

        /* All defined session types can be set */
        for (size_t i = 0; i < ELEMENTSOF(types); i++) {
                type = mfree(type);
                assert_se(bus_call_method(bus, &session, "SetType", NULL, NULL, "s", types[i]) >= 0);
                assert_se(bus_get_property_string(bus, &session, "Type", NULL, &type) >= 0);
                assert_se(streq(type, types[i]));
        }

        /* An unknown type is rejected */
        sd_bus_error_free(&error);
        assert_se(bus_call_method(bus, &session, "SetType", &error, NULL, "s", "hello") < 0);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS));
        assert_se(bus_get_property_string(bus, &session, "Type", NULL, &type2) >= 0);

        /* Type is reset to the original value when we release control of the session */
        assert_se(!streq(type, "tty"));
        assert_se(bus_call_method(bus, &session, "ReleaseControl", NULL, NULL, "") >= 0);
        type = mfree(type);
        assert_se(bus_get_property_string(bus, &session, "Type", NULL, &type) >= 0);
        assert_se(streq(type, "tty"));
}

/* Tests org.freedesktop.logind.Session SetDisplay */
TEST(set_display) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *display = NULL;

        assert_se(sd_bus_open_system(&bus) >= 0);

        /* Display is unset by default */
        assert_se(bus_get_property_string(bus, &session, "Display", NULL, &display) >= 0);
        assert_se(isempty(display));

        /* Display can only be set by the session controller (which we're not ATM) */
        assert_se(bus_call_method(bus, &session, "SetDisplay", &error, NULL, "s", ":0") < 0);
        assert_se(sd_bus_error_has_name(&error, BUS_ERROR_NOT_IN_CONTROL));

        assert_se(bus_call_method(bus, &session, "TakeControl", NULL, NULL, "b", true) >= 0);

        /* Display can only be set on a graphical session */
        assert_se(bus_call_method(bus, &session, "SetType", NULL, NULL, "s", "tty") >= 0);
        sd_bus_error_free(&error);
        assert_se(bus_call_method(bus, &session, "SetDisplay", &error, NULL, "s", ":0") < 0);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_NOT_SUPPORTED));

        assert_se(bus_call_method(bus, &session, "SetType", NULL, NULL, "s", "x11") >= 0);

        /* Non-empty display can be set */
        assert_se(bus_call_method(bus, &session, "SetDisplay", NULL, NULL, "s", ":0") >= 0);
        display = mfree(display);
        assert_se(bus_get_property_string(bus, &session, "Display", NULL, &display) >= 0);
        assert_se(streq(display, ":0"));

        /* Empty display can be set too */
        assert_se(bus_call_method(bus, &session, "SetDisplay", NULL, NULL, "s", "") >= 0);
        display = mfree(display);
        assert_se(bus_get_property_string(bus, &session, "Display", NULL, &display) >= 0);
        assert_se(isempty(display));
}

static int intro(void) {
        if (saved_argc <= 1)
                return EXIT_FAILURE;

        session = (BusLocator) {
                .destination = "org.freedesktop.login1",
                .path = saved_argv[1],
                .interface = "org.freedesktop.login1.Session",
        };

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
