/***
  This file is part of systemd.

  Copyright 2017 Felipe Sateler

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

#include <errno.h>
#include <sys/prctl.h>

#include "bus-util.h"
#include "bus-error.h"
#include "log.h"
#include "process-util.h"
#include "sd-bus.h"
#include "signal-util.h"

static int start_default_target(void) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = bus_connect_system_systemd(&bus);
        if (r < 0) {
                log_error_errno(r, "Failed to get D-Bus connection: %m");
                return false;
        }

        log_info("Starting default target");

        /* Start these units only if we can replace base.target with it */
        r = sd_bus_call_method(bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "StartUnit",
                               &error,
                               NULL,
                               "ss", "default.target", "isolate");

        if (r < 0)
                log_error("Failed to start default target: %s", bus_error_message(&error, r));

        return r;
}

static void fork_wait(const char* const cmdline[]) {
        pid_t pid;

        pid = fork();
        if (pid < 0) {
                log_error_errno(errno, "fork(): %m");
                return;
        }
        if (pid == 0) {

                /* Child */

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();
                assert_se(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);

                execv(cmdline[0], (char**) cmdline);
                log_error_errno(errno, "Failed to execute %s: %m", cmdline[0]);
                _exit(EXIT_FAILURE); /* Operational error */
        }

        wait_for_terminate_and_warn(cmdline[0], pid, false);
}

static void print_mode(const char* mode) {
        printf("You are in %s mode. After logging in, type \"journalctl -xb\" to view\n"
                "system logs, \"systemctl reboot\" to reboot, \"systemctl default\" or ^D to boot\n"
                "into default mode.\n", mode);
        fflush(stdout);
}

int main(int argc, char *argv[]) {
        static const char* const sulogin_cmdline[] = {SULOGIN, NULL};
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        print_mode(argc > 1 ? argv[1] : "");

        fork_wait(sulogin_cmdline);

        r = start_default_target();

        return r >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
