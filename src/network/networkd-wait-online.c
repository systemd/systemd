/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include "sd-event.h"
#include "event-util.h"
#include "sd-daemon.h"
#include "sd-network.h"
#include "network-util.h"

#include "util.h"

static bool all_configured(void) {
        _cleanup_free_ unsigned *indices = NULL;
        bool one_ready = false;
        int r, n, i;

        n = sd_network_get_ifindices(&indices);
        if (n <= 0)
                return false;

        for (i = 0; i < n; i++) {
                _cleanup_free_ char *state = NULL;

                r = sd_network_get_link_state(indices[i], &state);
                if (r == -EUNATCH)
                        continue;
                if (r < 0 || !streq(state, "configured"))
                        return false;

                one_ready = true;
        }

        return one_ready;
}

static int event_handler(sd_event_source *s, int fd, uint32_t revents,
                         void *userdata) {
        sd_event *event = userdata;

        assert(event);

        if (all_configured())
                sd_event_exit(event, 0);

        return 1;
}

int main(int argc, char *argv[]) {
        _cleanup_event_unref_ sd_event *event = NULL;
        _cleanup_event_source_unref_ sd_event_source *event_source = NULL;
        _cleanup_network_monitor_unref_ sd_network_monitor *monitor = NULL;
        int r, fd, events;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto out;
        }

        r = sd_network_monitor_new(NULL, &monitor);
        if (r < 0) {
                log_error("Could not create monitor: %s", strerror(-r));
                goto out;
        }

        r = sd_event_new(&event);
        if (r < 0) {
                log_error("Could not create event: %s", strerror(-r));
                goto out;
        }

        fd = sd_network_monitor_get_fd(monitor);
        if (fd < 0) {
                log_error("Could not get monitor fd: %s", strerror(-r));
                goto out;
        }

        events = sd_network_monitor_get_events(monitor);
        if (events < 0) {
                log_error("Could not get monitor events: %s", strerror(-r));
                goto out;
        }

        r = sd_event_add_io(event, &event_source, fd, events, &event_handler,
                            event);
        if (r < 0) {
                log_error("Could not add io event source: %s", strerror(-r));
                goto out;
        }

        if (all_configured()) {
                r = 0;
                goto out;
        }

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Waiting for network connections...");

        r = sd_event_loop(event);
        if (r < 0) {
                log_error("Event loop failed: %s", strerror(-r));
                goto out;
        }

out:
        sd_notify(false,
                  "STATUS=All interfaces configured...");

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
