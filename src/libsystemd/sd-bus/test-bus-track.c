/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "tests.h"

static bool track_cb_called_x = false;
static bool track_cb_called_y = false;
static bool track_destroy_called_z = false;

static int track_cb_x(sd_bus_track *t, void *userdata) {

        log_error("TRACK CB X");

        ASSERT_FALSE(track_cb_called_x);
        track_cb_called_x = true;

        /* This means b's name disappeared. Let's now disconnect, to make sure the track handling on disconnect works
         * as it should. */

        ASSERT_OK_ERRNO(shutdown(sd_bus_get_fd(sd_bus_track_get_bus(t)), SHUT_RDWR));
        return 1;
}

static int track_cb_y(sd_bus_track *t, void *userdata) {

        log_error("TRACK CB Y");

        ASSERT_FALSE(track_cb_called_y);
        track_cb_called_y = true;

        /* We got disconnected, let's close everything */

        ASSERT_OK(sd_event_exit(sd_bus_get_event(sd_bus_track_get_bus(t)), EXIT_SUCCESS));

        return 0;
}

static int track_cb_z(sd_bus_track *t, void *userdata) {
        assert_not_reached();
}

static void track_destroy_z(void *userdata) {
        track_destroy_called_z = true;
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_bus_track_unrefp) sd_bus_track *x = NULL, *y = NULL, *z = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *a = NULL, *b = NULL;
        bool use_system_bus = false;
        const char *unique;
        int r;

        test_setup_logging(LOG_INFO);

        ASSERT_OK(sd_event_default(&event));

        r = sd_bus_open_user(&a);
        if (IN_SET(r, -ECONNREFUSED, -ENOENT, -ENOMEDIUM)) {
                r = sd_bus_open_system(&a);
                if (IN_SET(r, -ECONNREFUSED, -ENOENT))
                        return log_tests_skipped("Failed to connect to bus");
                use_system_bus = true;
        }
        ASSERT_OK(r);

        ASSERT_OK(sd_bus_attach_event(a, event, SD_EVENT_PRIORITY_NORMAL));

        if (use_system_bus)
                ASSERT_OK(sd_bus_open_system(&b));
        else
                ASSERT_OK(sd_bus_open_user(&b));

        ASSERT_OK(sd_bus_attach_event(b, event, SD_EVENT_PRIORITY_NORMAL));

        /* Watch b's name from a */
        ASSERT_OK(sd_bus_track_new(a, &x, track_cb_x, /* userdata= */ NULL));

        ASSERT_OK(sd_bus_get_unique_name(b, &unique));

        ASSERT_OK(sd_bus_track_add_name(x, unique));

        /* Watch's a's own name from a */
        ASSERT_OK(sd_bus_track_new(a, &y, track_cb_y, /* userdata= */ NULL));

        ASSERT_OK(sd_bus_get_unique_name(a, &unique));

        ASSERT_OK(sd_bus_track_add_name(y, unique));

        /* Basic tests. */
        ASSERT_OK(sd_bus_track_new(a, &z, track_cb_z, /* userdata= */ NULL));

        /* non-recursive case */
        ASSERT_OK(sd_bus_track_set_recursive(z, false));
        ASSERT_OK_EQ(sd_bus_track_get_recursive(z), 0);
        ASSERT_NULL(sd_bus_track_contains(z, unique));
        ASSERT_OK_EQ(sd_bus_track_count_name(z, unique), 0);
        ASSERT_OK_EQ(sd_bus_track_remove_name(z, unique), 0);
        ASSERT_OK(sd_bus_track_add_name(z, unique));
        ASSERT_OK(sd_bus_track_add_name(z, unique));
        ASSERT_OK(sd_bus_track_add_name(z, unique));
        ASSERT_ERROR(sd_bus_track_set_recursive(z, true), EBUSY);
        ASSERT_NOT_NULL(sd_bus_track_contains(z, unique));
        ASSERT_OK_EQ(sd_bus_track_count_name(z, unique), 1);
        ASSERT_OK_EQ(sd_bus_track_remove_name(z, unique), 1);
        ASSERT_NULL(sd_bus_track_contains(z, unique));
        ASSERT_OK_EQ(sd_bus_track_count_name(z, unique), 0);
        ASSERT_OK_EQ(sd_bus_track_remove_name(z, unique), 0);

        /* recursive case */
        ASSERT_OK(sd_bus_track_set_recursive(z, true));
        ASSERT_OK_EQ(sd_bus_track_get_recursive(z), 1);
        ASSERT_NULL(sd_bus_track_contains(z, unique));
        ASSERT_OK_EQ(sd_bus_track_count_name(z, unique), 0);
        ASSERT_OK_EQ(sd_bus_track_remove_name(z, unique), 0);
        ASSERT_OK(sd_bus_track_add_name(z, unique));
        ASSERT_OK(sd_bus_track_add_name(z, unique));
        ASSERT_OK(sd_bus_track_add_name(z, unique));
        ASSERT_ERROR(sd_bus_track_set_recursive(z, false), EBUSY);
        ASSERT_NOT_NULL(sd_bus_track_contains(z, unique));
        ASSERT_OK_EQ(sd_bus_track_count_name(z, unique), 3);
        ASSERT_OK_EQ(sd_bus_track_remove_name(z, unique), 1);
        ASSERT_NOT_NULL(sd_bus_track_contains(z, unique));
        ASSERT_OK_EQ(sd_bus_track_count_name(z, unique), 2);
        ASSERT_OK_EQ(sd_bus_track_remove_name(z, unique), 1);
        ASSERT_NOT_NULL(sd_bus_track_contains(z, unique));
        ASSERT_OK_EQ(sd_bus_track_count_name(z, unique), 1);
        ASSERT_OK_EQ(sd_bus_track_remove_name(z, unique), 1);
        ASSERT_NULL(sd_bus_track_contains(z, unique));
        ASSERT_OK_EQ(sd_bus_track_count_name(z, unique), 0);
        ASSERT_OK_EQ(sd_bus_track_remove_name(z, unique), 0);

        ASSERT_OK(sd_bus_track_set_destroy_callback(z, track_destroy_z));
        z = sd_bus_track_unref(z);
        ASSERT_TRUE(track_destroy_called_z);

        /* Now make b's name disappear */
        sd_bus_close(b);

        ASSERT_OK(sd_event_loop(event));

        ASSERT_TRUE(track_cb_called_x);
        ASSERT_TRUE(track_cb_called_y);

        return 0;
}
