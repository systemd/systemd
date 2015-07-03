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

#include "sd-daemon.h"
#include "capability.h"
#include "signal-util.h"
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
                log_error_errno(r, "Cannot resolve user name %s: %m", user);
                goto out;
        }

        /* Always create the directories people can create inotify
         * watches in. */
        r = mkdir_safe_label("/run/systemd/netif", 0755, uid, gid);
        if (r < 0)
                log_warning_errno(r, "Could not create runtime directory: %m");

        r = mkdir_safe_label("/run/systemd/netif/links", 0755, uid, gid);
        if (r < 0)
                log_warning_errno(r, "Could not create runtime directory 'links': %m");

        r = mkdir_safe_label("/run/systemd/netif/leases", 0755, uid, gid);
        if (r < 0)
                log_warning_errno(r, "Could not create runtime directory 'leases': %m");

        r = mkdir_safe_label("/run/systemd/netif/lldp", 0755, uid, gid);
        if (r < 0)
                log_warning_errno(r, "Could not create runtime directory 'lldp': %m");

        r = drop_privileges(uid, gid,
                            (1ULL << CAP_NET_ADMIN) |
                            (1ULL << CAP_NET_BIND_SERVICE) |
                            (1ULL << CAP_NET_BROADCAST) |
                            (1ULL << CAP_NET_RAW));
        if (r < 0)
                goto out;

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        r = manager_new(&m);
        if (r < 0) {
                log_error_errno(r, "Could not create manager: %m");
                goto out;
        }

        r = manager_connect_bus(m);
        if (r < 0) {
                log_error_errno(r, "Could not connect to bus: %m");
                goto out;
        }

        r = manager_load_config(m);
        if (r < 0) {
                log_error_errno(r, "Could not load configuration files: %m");
                goto out;
        }

        r = manager_rtnl_enumerate_links(m);
        if (r < 0) {
                log_error_errno(r, "Could not enumerate links: %m");
                goto out;
        }

        r = manager_rtnl_enumerate_addresses(m);
        if (r < 0) {
                log_error_errno(r, "Could not enumerate addresses: %m");
                goto out;
        }

        log_info("Enumeration completed");

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        r = manager_run(m);
        if (r < 0) {
                log_error_errno(r, "Event loop failed: %m");
                goto out;
        }

out:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Shutting down...");

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
