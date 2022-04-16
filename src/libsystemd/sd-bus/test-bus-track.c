/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/socket.h>

#include "sd-bus.h"

#include "macro.h"
#include "tests.h"

static bool track_cb_called_x = false;
static bool track_cb_called_y = false;
static bool track_destroy_called_z = false;

static int track_cb_x(sd_bus_track *t, void *userdata) {

        log_error("TRACK CB X");

        assert_se(!track_cb_called_x);
        track_cb_called_x = true;

        /* This means b's name disappeared. Let's now disconnect, to make sure the track handling on disconnect works
         * as it should. */

        assert_se(shutdown(sd_bus_get_fd(sd_bus_track_get_bus(t)), SHUT_RDWR) >= 0);
        return 1;
}

static int track_cb_y(sd_bus_track *t, void *userdata) {

        log_error("TRACK CB Y");

        assert_se(!track_cb_called_y);
        track_cb_called_y = true;

        /* We got disconnected, let's close everything */

        assert_se(sd_event_exit(sd_bus_get_event(sd_bus_track_get_bus(t)), EXIT_SUCCESS) >= 0);

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

        assert_se(sd_event_default(&event) >= 0);

        r = sd_bus_open_user(&a);
        if (IN_SET(r, -ECONNREFUSED, -ENOENT, -ENOMEDIUM)) {
                r = sd_bus_open_system(&a);
                if (IN_SET(r, -ECONNREFUSED, -ENOENT))
                        return log_tests_skipped("Failed to connect to bus");
                use_system_bus = true;
        }
        assert_se(r >= 0);

        assert_se(sd_bus_attach_event(a, event, SD_EVENT_PRIORITY_NORMAL) >= 0);

        if (use_system_bus)
                assert_se(sd_bus_open_system(&b) >= 0);
        else
                assert_se(sd_bus_open_user(&b) >= 0);

        assert_se(sd_bus_attach_event(b, event, SD_EVENT_PRIORITY_NORMAL) >= 0);

        /* Watch b's name from a */
        assert_se(sd_bus_track_new(a, &x, track_cb_x, NULL) >= 0);

        assert_se(sd_bus_get_unique_name(b, &unique) >= 0);

        assert_se(sd_bus_track_add_name(x, unique) >= 0);

        /* Watch's a's own name from a */
        assert_se(sd_bus_track_new(a, &y, track_cb_y, NULL) >= 0);

        assert_se(sd_bus_get_unique_name(a, &unique) >= 0);

        assert_se(sd_bus_track_add_name(y, unique) >= 0);

        /* Basic tests. */
        assert_se(sd_bus_track_new(a, &z, track_cb_z, NULL) >= 0);

        /* non-recursive case */
        assert_se(sd_bus_track_set_recursive(z, false) >= 0);
        assert_se(sd_bus_track_get_recursive(z) == 0);
        assert_se(!sd_bus_track_contains(z, unique));
        assert_se(sd_bus_track_count_name(z, unique) == 0);
        assert_se(sd_bus_track_remove_name(z, unique) == 0);
        assert_se(sd_bus_track_add_name(z, unique) >= 0);
        assert_se(sd_bus_track_add_name(z, unique) >= 0);
        assert_se(sd_bus_track_add_name(z, unique) >= 0);
        assert_se(sd_bus_track_set_recursive(z, true) == -EBUSY);
        assert_se(sd_bus_track_contains(z, unique));
        assert_se(sd_bus_track_count_name(z, unique) == 1);
        assert_se(sd_bus_track_remove_name(z, unique) == 1);
        assert_se(!sd_bus_track_contains(z, unique));
        assert_se(sd_bus_track_count_name(z, unique) == 0);
        assert_se(sd_bus_track_remove_name(z, unique) == 0);

        /* recursive case */
        assert_se(sd_bus_track_set_recursive(z, true) >= 0);
        assert_se(sd_bus_track_get_recursive(z) == 1);
        assert_se(!sd_bus_track_contains(z, unique));
        assert_se(sd_bus_track_count_name(z, unique) == 0);
        assert_se(sd_bus_track_remove_name(z, unique) == 0);
        assert_se(sd_bus_track_add_name(z, unique) >= 0);
        assert_se(sd_bus_track_add_name(z, unique) >= 0);
        assert_se(sd_bus_track_add_name(z, unique) >= 0);
        assert_se(sd_bus_track_set_recursive(z, false) == -EBUSY);
        assert_se(sd_bus_track_contains(z, unique));
        assert_se(sd_bus_track_count_name(z, unique) == 3);
        assert_se(sd_bus_track_remove_name(z, unique) == 1);
        assert_se(sd_bus_track_contains(z, unique));
        assert_se(sd_bus_track_count_name(z, unique) == 2);
        assert_se(sd_bus_track_remove_name(z, unique) == 1);
        assert_se(sd_bus_track_contains(z, unique));
        assert_se(sd_bus_track_count_name(z, unique) == 1);
        assert_se(sd_bus_track_remove_name(z, unique) == 1);
        assert_se(!sd_bus_track_contains(z, unique));
        assert_se(sd_bus_track_count_name(z, unique) == 0);
        assert_se(sd_bus_track_remove_name(z, unique) == 0);

        assert_se(sd_bus_track_set_destroy_callback(z, track_destroy_z) >= 0);
        z = sd_bus_track_unref(z);
        assert_se(track_destroy_called_z);

        /* Now make b's name disappear */
        sd_bus_close(b);

        assert_se(sd_event_loop(event) >= 0);

        assert_se(track_cb_called_x);
        assert_se(track_cb_called_y);

        return 0;
}
