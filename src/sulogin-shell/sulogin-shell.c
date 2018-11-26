/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2017 Felipe Sateler
***/

#include <errno.h>
#include <sys/prctl.h>

#include "bus-util.h"
#include "bus-error.h"
#include "def.h"
#include "env-util.h"
#include "log.h"
#include "process-util.h"
#include "sd-bus.h"
#include "signal-util.h"

static int reload_manager(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        log_info("Reloading system manager configuration");

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "Reload");
        if (r < 0)
                return bus_log_create_error(r);

        /* Note we use an extra-long timeout here. This is because a reload or reexec means generators are rerun which
         * are timed out after DEFAULT_TIMEOUT_USEC. Let's use twice that time here, so that the generators can have
         * their timeout, and for everything else there's the same time budget in place. */

        r = sd_bus_call(bus, m, DEFAULT_TIMEOUT_USEC * 2, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to reload daemon: %s", bus_error_message(&error, r));

        return 0;
}

static int start_default_target(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

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
                return log_error_errno(r, "Failed to start default target: %s", bus_error_message(&error, r));

        return 0;
}

static int fork_wait(const char* const cmdline[]) {
        pid_t pid;
        int r;

        r = safe_fork("(sulogin)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */
                execv(cmdline[0], (char**) cmdline);
                log_error_errno(errno, "Failed to execute %s: %m", cmdline[0]);
                _exit(EXIT_FAILURE); /* Operational error */
        }

        return wait_for_terminate_and_check(cmdline[0], pid, WAIT_LOG_ABNORMAL);
}

static void print_mode(const char* mode) {
        printf("You are in %s mode. After logging in, type \"journalctl -xb\" to view\n"
                "system logs, \"systemctl reboot\" to reboot, \"systemctl default\" or \"exit\"\n"
                "to boot into default mode.\n", mode);
        fflush(stdout);
}

int main(int argc, char *argv[]) {
        const char* sulogin_cmdline[] = {
                SULOGIN,
                NULL,             /* --force */
                NULL
        };
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        log_setup_service();

        print_mode(argc > 1 ? argv[1] : "");

        if (getenv_bool("SYSTEMD_SULOGIN_FORCE") > 0)
                /* allows passwordless logins if root account is locked. */
                sulogin_cmdline[1] = "--force";

        (void) fork_wait(sulogin_cmdline);

        r = bus_connect_system_systemd(&bus);
        if (r < 0) {
                log_warning_errno(r, "Failed to get D-Bus connection: %m");
                r = 0;
        } else {
                (void) reload_manager(bus);

                r = start_default_target(bus);
        }

        return r >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
