/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen <teg@jklm.no>

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
#include "sd-daemon.h"

#include "resolved.h"

#include "mkdir.h"
#include "capability.h"

int main(int argc, char *argv[]) {
        _cleanup_manager_free_ Manager *m = NULL;
        const char *user = "systemd-resolve";
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

        /* Always create the directory where resolv.conf will live */
        r = mkdir_safe_label("/run/systemd/resolve", 0755, uid, gid);
        if (r < 0) {
                log_error("Could not create runtime directory: %s",
                          strerror(-r));
                goto out;
        }

        r = drop_privileges(uid, gid, 0);
        if (r < 0)
                goto out;

        r = manager_new(&m);
        if (r < 0) {
                log_error("Could not create manager: %s", strerror(-r));
                goto out;
        }

        r = manager_network_monitor_listen(m);
        if (r < 0) {
                log_error("Could not listen for network events: %s", strerror(-r));
                goto out;
        }

        /* write out default resolv.conf to avoid a
         * dangling symlink */
        r = manager_update_resolv_conf(m);
        if (r < 0) {
                log_error("Could not create resolv.conf: %s", strerror(-r));
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
