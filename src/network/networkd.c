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

#include "capability.h"
#include "sd-event.h"
#include "sd-daemon.h"

#include "networkd.h"

int main(int argc, char *argv[]) {
        _cleanup_manager_free_ Manager *m = NULL;
        const char *user = "systemd-network";
        uid_t uid;
        gid_t gid;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto out;
        }

        r = get_user_creds(&user, &uid, &gid, NULL, NULL);
        if (r < 0) {
                log_error("Cannot resolve user name %s: %s", user, strerror(-r));
                goto out;
        }

        /* Always create the directories people can create inotify
         * watches in. */
        r = mkdir_safe_label("/run/systemd/netif", 0755, uid, gid);
        if (r < 0)
                log_error("Could not create runtime directory: %s",
                          strerror(-r));

        r = mkdir_safe_label("/run/systemd/netif/links", 0755, uid, gid);
        if (r < 0)
                log_error("Could not create runtime directory 'links': %s",
                          strerror(-r));

        r = mkdir_safe_label("/run/systemd/netif/leases", 0755, uid, gid);
        if (r < 0)
                log_error("Could not create runtime directory 'leases': %s",
                          strerror(-r));

        r = drop_privileges(uid, gid,
                            (1ULL << CAP_NET_ADMIN) |
                            (1ULL << CAP_NET_BIND_SERVICE) |
                            (1ULL << CAP_NET_BROADCAST) |
                            (1ULL << CAP_NET_RAW));
        if (r < 0)
                goto out;

        r = manager_new(&m);
        if (r < 0) {
                log_error("Could not create manager: %s", strerror(-r));
                goto out;
        }

        r = manager_udev_listen(m);
        if (r < 0) {
                log_error("Could not connect to udev: %s", strerror(-r));
                goto out;
        }

        r = manager_rtnl_listen(m);
        if (r < 0) {
                log_error("Could not connect to rtnl: %s", strerror(-r));
                goto out;
        }

        r = manager_bus_listen(m);
        if (r < 0) {
                log_error("Could not connect to system bus: %s", strerror(-r));
                goto out;
        }

        r = manager_load_config(m);
        if (r < 0) {
                log_error("Could not load configuration files: %s", strerror(-r));
                goto out;
        }

        r = manager_rtnl_enumerate_links(m);
        if (r < 0) {
                log_error("Could not enumerate links: %s", strerror(-r));
                goto out;
        }

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        r = sd_event_loop(m->event);
        if (r < 0) {
                log_error("Event loop failed: %s", strerror(-r));
                goto out;
        }

out:
        sd_notify(false,
                  "STATUS=Shutting down...");

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
