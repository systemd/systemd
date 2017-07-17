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

#include "sd-daemon.h"
#include "sd-event.h"

#include "capability-util.h"
#include "mkdir.h"
#include "resolved-conf.h"
#include "resolved-manager.h"
#include "resolved-resolv-conf.h"
#include "selinux-util.h"
#include "signal-util.h"

int main(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        if (geteuid() == 0) {
                log_error("This program must be run under an unprivileged user"
                          " with the following capabilities: CAP_NET_RAW"
                          " CAP_NET_BIND_SERVICE CAP_SETPCAP");
                r = -EINVAL;
                goto finish;
        }

        r = mac_selinux_init();
        if (r < 0) {
                log_error_errno(r, "SELinux setup failed: %m");
                goto finish;
        }

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, SIGUSR1, SIGUSR2, -1) >= 0);

        r = manager_new(&m);
        if (r < 0) {
                log_error_errno(r, "Could not create manager: %m");
                goto finish;
        }

        r = manager_start(m);
        if (r < 0) {
                log_error_errno(r, "Failed to start manager: %m");
                goto finish;
        }

        /* Write finish default resolv.conf to avoid a dangling symlink */
        (void) manager_write_resolv_conf(m);

        /* Let's drop the remaining caps now */
        r = capability_bounding_set_drop(0, true);
        if (r < 0) {
                log_error_errno(r, "Failed to drop remaining caps: %m");
                goto finish;
        }

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        r = sd_event_loop(m->event);
        if (r < 0) {
                log_error_errno(r, "Event loop failed: %m");
                goto finish;
        }

        sd_event_get_exit_code(m->event, &r);

finish:
        /* systemd-nspawn checks for private resolv.conf to decide whether
           or not to mount it into the container. So just delete it. */
        (void) unlink(PRIVATE_RESOLV_CONF);

        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Shutting down...");

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
