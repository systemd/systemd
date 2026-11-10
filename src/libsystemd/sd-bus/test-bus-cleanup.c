/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-bus.h"

#include "bus-internal.h"
#include "bus-message.h"
#include "process-util.h"
#include "tests.h"

TEST(bus_new) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;

        ASSERT_OK_ZERO(sd_bus_new(&bus));
        ASSERT_EQ(bus->n_ref, 1U);
}

TEST(bus_fork) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        int r;

        ASSERT_OK_ZERO(sd_bus_new(&bus));
        ASSERT_EQ(bus->n_ref, 1U);

        /* Check that after a fork the cleanup functions return NULL */
        r = pidref_safe_fork("(bus-fork-test)", FORK_WAIT|FORK_LOG, /* ret= */ NULL);
        if (r == 0) {
                ASSERT_NOT_NULL(bus);
                ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_bus_is_ready(bus), ECHILD));
                ASSERT_NULL(sd_bus_flush_close_unref(bus));
                ASSERT_NULL(sd_bus_close_unref(bus));
                ASSERT_NULL(sd_bus_unref(bus));
                sd_bus_close(bus);
                ASSERT_EQ(bus->n_ref, 1U);
                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(r);
        ASSERT_EQ(bus->n_ref, 1U);
}

TEST(bus_negotiate_closed) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;

        ASSERT_OK_ZERO(sd_bus_new(&bus));

        ASSERT_OK(sd_bus_negotiate_timestamp(bus, false));
        ASSERT_OK(sd_bus_negotiate_creds(bus, false, SD_BUS_CREDS_PID));

        bus_set_state(bus, BUS_CLOSING);
        ASSERT_ERROR(sd_bus_negotiate_timestamp(bus, true), ENOTCONN);
        ASSERT_ERROR(sd_bus_negotiate_creds(bus, true, SD_BUS_CREDS_PID), ENOTCONN);

        sd_bus_close(bus);
        ASSERT_ERROR(sd_bus_negotiate_timestamp(bus, true), ENOTCONN);
        ASSERT_ERROR(sd_bus_negotiate_creds(bus, true, SD_BUS_CREDS_PID), ENOTCONN);

        /* The rejected calls must not have mutated the bus. */
        ASSERT_FALSE(bus->attach_timestamp);
        ASSERT_FALSE(bus->creds_mask & SD_BUS_CREDS_PID);
}

static int test_bus_open(sd_bus **ret) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = sd_bus_open_user(&bus);
        if (IN_SET(r, -ECONNREFUSED, -ENOENT, -ENOMEDIUM)) {
                r = sd_bus_open_system(&bus);
                if (IN_SET(r, -ECONNREFUSED, -ENOENT))
                        return r;
        }

        ASSERT_OK(r);
        ASSERT_GE(bus->n_ref, 1U); /* we send a hello message when opening, so the count is above 1 */

        if (ret)
                *ret = TAKE_PTR(bus);
        return 0;
}

TEST(bus_new_method_call) {
        sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        r = test_bus_open(&bus);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to connect to bus");

        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "a.service.name", "/an/object/path", "an.interface.name", "AMethodName"));

        ASSERT_EQ(m->n_ref, 1U); /* We hold the only reference to the message */
        ASSERT_GE(bus->n_ref, 2U);
        sd_bus_flush_close_unref(bus);
        ASSERT_EQ(m->n_ref, 1U);
}

TEST(bus_new_signal) {
        sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        r = test_bus_open(&bus);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to connect to bus");

        ASSERT_OK(sd_bus_message_new_signal(bus, &m, "/an/object/path", "an.interface.name", "Name"));

        ASSERT_EQ(m->n_ref, 1U); /* We hold the only reference to the message */
        ASSERT_GE(bus->n_ref, 2U);
        sd_bus_flush_close_unref(bus);
        ASSERT_EQ(m->n_ref, 1U);
}

DEFINE_TEST_MAIN(LOG_INFO);
