/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Usage:
 * ./test-session-properties <SESSION-OBJECT-PATH> [<TTY>]
 * e.g.,
 * ./test-session-properties /org/freedesktop/login1/session/_32 /dev/tty2
 */

#include <fcntl.h>

#include "sd-bus.h"
#include "sd-device.h"

#include "alloc-util.h"
#include "argv-util.h"
#include "bus-common-errors.h"
#include "bus-locator.h"
#include "device-util.h"
#include "tests.h"
#include "time-util.h"

static const char *arg_tty = NULL;

static BusLocator session;

/* Tests org.freedesktop.logind.Session SetType */
TEST(set_type) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char* types[] = {"tty", "x11", "wayland", "mir", "web"};
        _cleanup_free_ char *type = NULL, *type2 = NULL;

        ASSERT_OK(sd_bus_open_system(&bus));

        /* Default type is set */
        ASSERT_OK(bus_get_property_string(bus, &session, "Type", /* reterr_error= */ NULL, &type));
        ASSERT_STREQ(type, "tty");

        /* Type can only be set by the session controller (which we're not ATM) */
        ASSERT_FAIL(bus_call_method(bus, &session, "SetType", &error, /* ret_reply= */ NULL, "s", "x11"));
        ASSERT_TRUE(sd_bus_error_has_name(&error, BUS_ERROR_NOT_IN_CONTROL));

        ASSERT_OK(bus_call_method(bus, &session, "TakeControl", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "b", true));

        /* All defined session types can be set */
        FOREACH_ELEMENT(i, types) {
                type = mfree(type);
                ASSERT_OK(bus_call_method(bus, &session, "SetType", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "s", *i));
                ASSERT_OK(bus_get_property_string(bus, &session, "Type", /* reterr_error= */ NULL, &type));
                ASSERT_STREQ(type, *i);
        }

        /* An unknown type is rejected */
        sd_bus_error_free(&error);
        ASSERT_FAIL(bus_call_method(bus, &session, "SetType", &error, /* ret_reply= */ NULL, "s", "hello"));
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS));
        ASSERT_OK(bus_get_property_string(bus, &session, "Type", /* reterr_error= */ NULL, &type2));

        /* Type is reset to the original value when we release control of the session */
        ASSERT_NOT_STREQ(type, "tty");
        ASSERT_OK(bus_call_method(bus, &session, "ReleaseControl", /* reterr_error= */ NULL, /* ret_reply= */ NULL, /* types= */ NULL));
        type = mfree(type);
        ASSERT_OK(bus_get_property_string(bus, &session, "Type", /* reterr_error= */ NULL, &type));
        ASSERT_STREQ(type, "tty");
}

/* Tests org.freedesktop.logind.Session SetDisplay */
TEST(set_display) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *display = NULL;

        ASSERT_OK(sd_bus_open_system(&bus));

        /* Display is unset by default */
        ASSERT_OK(bus_get_property_string(bus, &session, "Display", /* reterr_error= */ NULL, &display));
        ASSERT_STREQ(display, "");

        /* Display can only be set by the session controller (which we're not ATM) */
        ASSERT_FAIL(bus_call_method(bus, &session, "SetDisplay", &error, /* ret_reply= */ NULL, "s", ":0"));
        ASSERT_TRUE(sd_bus_error_has_name(&error, BUS_ERROR_NOT_IN_CONTROL));

        ASSERT_OK(bus_call_method(bus, &session, "TakeControl", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "b", true));

        /* Display can only be set on a graphical session */
        ASSERT_OK(bus_call_method(bus, &session, "SetType", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "s", "tty"));
        sd_bus_error_free(&error);
        ASSERT_FAIL(bus_call_method(bus, &session, "SetDisplay", &error, /* ret_reply= */ NULL, "s", ":0"));
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_NOT_SUPPORTED));

        ASSERT_OK(bus_call_method(bus, &session, "SetType", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "s", "x11"));

        /* Non-empty display can be set */
        ASSERT_OK(bus_call_method(bus, &session, "SetDisplay", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "s", ":0"));
        display = mfree(display);
        ASSERT_OK(bus_get_property_string(bus, &session, "Display", /* reterr_error= */ NULL, &display));
        ASSERT_STREQ(display, ":0");

        /* Empty display can be set too */
        ASSERT_OK(bus_call_method(bus, &session, "SetDisplay", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "s", ""));
        display = mfree(display);
        ASSERT_OK(bus_get_property_string(bus, &session, "Display", /* reterr_error= */ NULL, &display));
        ASSERT_STREQ(display, "");
}

/* Tests org.freedesktop.logind.Session SetTTY */
TEST(set_tty) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *tty = NULL;
        int fd;

        if (!arg_tty)
                return;

        fd = ASSERT_OK_ERRNO(open(arg_tty, O_RDWR|O_CLOEXEC|O_NOCTTY));

        ASSERT_OK(sd_bus_open_system(&bus));

        /* tty can only be set by the session controller (which we're not ATM) */
        ASSERT_FAIL(bus_call_method(bus, &session, "SetTTY", &error, /* ret_reply= */ NULL, "h", fd));
        ASSERT_TRUE(sd_bus_error_has_name(&error, BUS_ERROR_NOT_IN_CONTROL));

        ASSERT_OK(bus_call_method(bus, &session, "TakeControl", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "b", true));

        /* tty can be set */
        ASSERT_OK(bus_call_method(bus, &session, "SetTTY", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "h", fd));
        tty = mfree(tty);
        ASSERT_OK(bus_get_property_string(bus, &session, "TTY", /* reterr_error= */ NULL, &tty));
        ASSERT_STREQ(tty, "tty2");
}

/* Tests org.freedesktop.logind.Session SetIdleHint */
TEST(set_idle_hint) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int idle_hint;
        time_t stamp, idle_since1, idle_since2;

        ASSERT_OK(sd_bus_open_system(&bus));

        /* Idle hint is not set by default */
        ASSERT_OK(bus_get_property_trivial(bus, &session, "IdleHint", /* reterr_error= */ NULL, 'b', &idle_hint));
        ASSERT_FALSE(idle_hint);

        ASSERT_OK(bus_call_method(bus, &session, "TakeControl", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "b", true));

        /* Idle hint can only be set on a graphical session */
        ASSERT_OK(bus_call_method(bus, &session, "SetType", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "s", "tty"));
        ASSERT_FAIL(bus_call_method(bus, &session, "SetIdleHint", &error, /* ret_reply= */ NULL, "b", true));
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_NOT_SUPPORTED));

        ASSERT_OK(bus_call_method(bus, &session, "SetType", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "s", "x11"));

        stamp = now(CLOCK_MONOTONIC);

        /* Idle hint can be set */
        ASSERT_OK(bus_call_method(bus, &session, "SetIdleHint", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "b", true));
        ASSERT_OK(bus_get_property_trivial(bus, &session, "IdleHint", /* reterr_error= */ NULL, 'b', &idle_hint));
        ASSERT_TRUE(idle_hint);
        ASSERT_OK(bus_get_property_trivial(bus, &session, "IdleSinceHintMonotonic", /* reterr_error= */ NULL, 't', &idle_since1));
        ASSERT_GE(idle_since1, stamp);

        /* Repeated setting doesn't change anything */
        ASSERT_OK(bus_call_method(bus, &session, "SetIdleHint", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "b", true));
        ASSERT_OK(bus_get_property_trivial(bus, &session, "IdleHint", /* reterr_error= */ NULL, 'b', &idle_hint));
        ASSERT_TRUE(idle_hint);
        ASSERT_OK(bus_get_property_trivial(bus, &session, "IdleSinceHintMonotonic", /* reterr_error= */ NULL, 't', &idle_since2));
        ASSERT_EQ(idle_since2, idle_since1);

        /* Idle hint can be unset */
        ASSERT_OK(bus_call_method(bus, &session, "SetIdleHint", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "b", false));
        ASSERT_OK(bus_get_property_trivial(bus, &session, "IdleHint", /* reterr_error= */ NULL, 'b', &idle_hint));
        ASSERT_FALSE(idle_hint);
}

/* Takes the first device matching subsystem/sysname that this session is allowed to take,
 * returning its devnum in *ret. */
static bool take_first_available_device(sd_bus *bus, const char *subsystem, const char *sysname, dev_t *ret) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;

        assert(bus);
        assert(subsystem);
        assert(sysname);
        assert(ret);

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, subsystem, /* match= */ true));
        ASSERT_OK(sd_device_enumerator_add_match_sysname(e, sysname));

        FOREACH_DEVICE(e, d) {
                dev_t devnum;

                if (sd_device_get_devnum(d, &devnum) < 0)
                        continue;

                /* Take it once; skip devices that aren't takeable for this session. */
                if (bus_call_method(bus, &session, "TakeDevice", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "uu",
                                    (uint32_t) major(devnum), (uint32_t) minor(devnum)) < 0)
                        continue;

                *ret = devnum;
                return true;
        }

        return false;
}

/* Tests org.freedesktop.logind.Session TakeDevice/ReleaseDevice: a duplicate TakeDevice for a
 * device the caller already holds must be rejected without tearing down the live device. */
TEST(take_device) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        dev_t found_dev = 0;

        ASSERT_OK(sd_bus_open_system(&bus));
        ASSERT_OK(bus_call_method(bus, &session, "TakeControl", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "b", true));

        /* Take a device on the session's seat. Input event devices (e.g. the ACPI power button and
         * the keyboard) and DRM cards belong to the seat and can be taken by its controller. */
        if (!take_first_available_device(bus, "input", "event*", &found_dev) &&
            !take_first_available_device(bus, "drm", "card*", &found_dev)) {
                log_notice("No takeable seat device found, skipping %s.", __func__);
                ASSERT_OK(bus_call_method(bus, &session, "ReleaseControl", /* reterr_error= */ NULL, /* ret_reply= */ NULL, /* types= */ NULL));
                return;
        }

        /* A duplicate TakeDevice must be rejected with 'device already taken' ... */
        ASSERT_FAIL(bus_call_method(bus, &session, "TakeDevice", &error, /* ret_reply= */ NULL, "uu",
                                    (uint32_t) major(found_dev), (uint32_t) minor(found_dev)));
        ASSERT_TRUE(sd_bus_error_has_name(&error, BUS_ERROR_DEVICE_IS_TAKEN));

        /* ... and must NOT tear down the original entry. */
        ASSERT_OK(bus_call_method(bus, &session, "ReleaseDevice", /* reterr_error= */ NULL, /* ret_reply= */ NULL, "uu",
                                  (uint32_t) major(found_dev), (uint32_t) minor(found_dev)));

        ASSERT_OK(bus_call_method(bus, &session, "ReleaseControl", /* reterr_error= */ NULL, /* ret_reply= */ NULL, /* types= */ NULL));
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
