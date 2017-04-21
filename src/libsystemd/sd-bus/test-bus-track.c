/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "sd-bus.h"

#include "macro.h"

static bool track_cb_called_x = false;
static bool track_cb_called_y = false;

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
        int r;

        log_error("TRACK CB Y");

        assert_se(!track_cb_called_y);
        track_cb_called_y = true;

        /* We got disconnected, let's close everything */

        r = sd_event_exit(sd_bus_get_event(sd_bus_track_get_bus(t)), EXIT_SUCCESS);
        assert_se(r >= 0);

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_bus_track_unrefp) sd_bus_track *x = NULL, *y = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *a = NULL, *b = NULL;
        const char *unique;
        int r;

        r = sd_event_default(&event);
        assert_se(r >= 0);

        r = sd_bus_open_system(&a);
        if (IN_SET(r, -ECONNREFUSED, -ENOENT)) {
                log_info("Failed to connect to bus, skipping tests.");
                return EXIT_TEST_SKIP;
        }
        assert_se(r >= 0);

        r = sd_bus_attach_event(a, event, SD_EVENT_PRIORITY_NORMAL);
        assert_se(r >= 0);

        r = sd_bus_open_system(&b);
        assert_se(r >= 0);

        r = sd_bus_attach_event(b, event, SD_EVENT_PRIORITY_NORMAL);
        assert_se(r >= 0);

        /* Watch b's name from a */
        r = sd_bus_track_new(a, &x, track_cb_x, NULL);
        assert_se(r >= 0);

        r = sd_bus_get_unique_name(b, &unique);
        assert_se(r >= 0);

        r = sd_bus_track_add_name(x, unique);
        assert_se(r >= 0);

        /* Watch's a's own name from a */
        r = sd_bus_track_new(a, &y, track_cb_y, NULL);
        assert_se(r >= 0);

        r = sd_bus_get_unique_name(a, &unique);
        assert_se(r >= 0);

        r = sd_bus_track_add_name(y, unique);
        assert_se(r >= 0);

        /* Now make b's name disappear */
        sd_bus_close(b);

        r = sd_event_loop(event);
        assert_se(r >= 0);

        assert_se(track_cb_called_x);
        assert_se(track_cb_called_y);

        return 0;
}
