/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-bus.h"

#include "bus-internal.h"
#include "bus-message.h"
#include "process-util.h"
#include "tests.h"

static bool use_system_bus = false;

static void test_bus_new(void) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;

        ASSERT_OK_ZERO(sd_bus_new(&bus));
        ASSERT_EQ(bus->n_ref, 1U);
}

static void test_bus_fork(void) {
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

static int test_bus_open(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = sd_bus_open_user(&bus);
        if (IN_SET(r, -ECONNREFUSED, -ENOENT, -ENOMEDIUM)) {
                r = sd_bus_open_system(&bus);
                if (IN_SET(r, -ECONNREFUSED, -ENOENT))
                        return r;
                use_system_bus = true;
        }

        ASSERT_OK(r);
        ASSERT_GE(bus->n_ref, 1U); /* we send a hello message when opening, so the count is above 1 */

        return 0;
}

static void test_bus_new_method_call(void) {
        sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

        ASSERT_OK(use_system_bus ? sd_bus_open_system(&bus) : sd_bus_open_user(&bus));

        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "a.service.name", "/an/object/path", "an.interface.name", "AMethodName"));

        ASSERT_EQ(m->n_ref, 1U); /* We hold the only reference to the message */
        ASSERT_GE(bus->n_ref, 2U);
        sd_bus_flush_close_unref(bus);
        ASSERT_EQ(m->n_ref, 1U);
}

static void test_bus_new_signal(void) {
        sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

        ASSERT_OK(use_system_bus ? sd_bus_open_system(&bus) : sd_bus_open_user(&bus));

        ASSERT_OK(sd_bus_message_new_signal(bus, &m, "/an/object/path", "an.interface.name", "Name"));

        ASSERT_EQ(m->n_ref, 1U); /* We hold the only reference to the message */
        ASSERT_GE(bus->n_ref, 2U);
        sd_bus_flush_close_unref(bus);
        ASSERT_EQ(m->n_ref, 1U);
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_INFO);

        test_bus_new();
        test_bus_fork();

        if (test_bus_open() < 0)
                return log_tests_skipped("Failed to connect to bus");

        test_bus_new_method_call();
        test_bus_new_signal();

        return EXIT_SUCCESS;
}
