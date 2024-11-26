/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Usage:
 * ./test-session-properties <SESSION-OBJECT-PATH> [<TTY>]
 * e.g.,
 * ./test-session-properties /org/freedesktop/login1/session/_32 /dev/tty2
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-locator.h"
#include "path-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "tests.h"

static const char *arg_tty = NULL;

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
        FOREACH_ELEMENT(i, types) {
                type = mfree(type);
                assert_se(bus_call_method(bus, &session, "SetType", NULL, NULL, "s", *i) >= 0);
                assert_se(bus_get_property_string(bus, &session, "Type", NULL, &type) >= 0);
                assert_se(streq(type, *i));
        }

        /* An unknown type is rejected */
        sd_bus_error_free(&error);
        assert_se(bus_call_method(bus, &session, "SetType", &error, NULL, "s", "hello") < 0);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS));
        assert_se(bus_get_property_string(bus, &session, "Type", NULL, &type2) >= 0);

        /* Type is reset to the original value when we release control of the session */
        assert_se(!streq(type, "tty"));
        assert_se(bus_call_method(bus, &session, "ReleaseControl", NULL, NULL, NULL) >= 0);
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

/* Tests org.freedesktop.logind.Session SetTTY */
TEST(set_tty) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *tty = NULL;
        int fd;

        if (!arg_tty)
                return;

        fd = open(arg_tty, O_RDWR|O_CLOEXEC|O_NOCTTY);
        assert_se(fd >= 0);

        assert_se(sd_bus_open_system(&bus) >= 0);

        /* tty can only be set by the session controller (which we're not ATM) */
        assert_se(bus_call_method(bus, &session, "SetTTY", &error, NULL, "h", fd) < 0);
        assert_se(sd_bus_error_has_name(&error, BUS_ERROR_NOT_IN_CONTROL));

        assert_se(bus_call_method(bus, &session, "TakeControl", NULL, NULL, "b", true) >= 0);

        /* tty can be set */
        assert_se(bus_call_method(bus, &session, "SetTTY", NULL, NULL, "h", fd) >= 0);
        tty = mfree(tty);
        assert_se(bus_get_property_string(bus, &session, "TTY", NULL, &tty) >= 0);
        assert_se(streq(tty, "tty2"));
}

/* Tests org.freedesktop.logind.Session SetIdleHint */
TEST(set_idle_hint) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int idle_hint;
        time_t stamp, idle_since1, idle_since2;

        assert_se(sd_bus_open_system(&bus) >= 0);

        /* Idle hint is not set by default */
        assert_se(bus_get_property_trivial(bus, &session, "IdleHint", NULL, 'b', &idle_hint) >= 0);
        assert_se(!idle_hint);

        assert_se(bus_call_method(bus, &session, "TakeControl", NULL, NULL, "b", true) >= 0);

        /* Idle hint can only be set on a graphical session */
        assert_se(bus_call_method(bus, &session, "SetType", NULL, NULL, "s", "tty") >= 0);
        assert_se(bus_call_method(bus, &session, "SetIdleHint", &error, NULL, "b", true) < 0);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_NOT_SUPPORTED));

        assert_se(bus_call_method(bus, &session, "SetType", NULL, NULL, "s", "x11") >= 0);

        stamp = now(CLOCK_MONOTONIC);

        /* Idle hint can be set */
        assert_se(bus_call_method(bus, &session, "SetIdleHint", NULL, NULL, "b", true) >= 0);
        assert_se(bus_get_property_trivial(bus, &session, "IdleHint", NULL, 'b', &idle_hint) >= 0);
        assert_se(idle_hint);
        assert_se(bus_get_property_trivial(bus, &session, "IdleSinceHintMonotonic", NULL, 't', &idle_since1) >= 0);
        assert_se(idle_since1 >= stamp);

        /* Repeated setting doesn't change anything */
        assert_se(bus_call_method(bus, &session, "SetIdleHint", NULL, NULL, "b", true) >= 0);
        assert_se(bus_get_property_trivial(bus, &session, "IdleHint", NULL, 'b', &idle_hint) >= 0);
        assert_se(idle_hint);
        assert_se(bus_get_property_trivial(bus, &session, "IdleSinceHintMonotonic", NULL, 't', &idle_since2) >= 0);
        assert_se(idle_since2 == idle_since1);

        /* Idle hint can be unset */
        assert_se(bus_call_method(bus, &session, "SetIdleHint", NULL, NULL, "b", false) >= 0);
        assert_se(bus_get_property_trivial(bus, &session, "IdleHint", NULL, 'b', &idle_hint) >= 0);
        assert_se(!idle_hint);
}

static int intro(void) {
        if (saved_argc <= 1)
                return EXIT_FAILURE;

        session = (BusLocator) {
                .destination = "org.freedesktop.login1",
                .path = saved_argv[1],
                .interface = "org.freedesktop.login1.Session",
        };

        if (saved_argc > 2)
                arg_tty = saved_argv[2];

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
