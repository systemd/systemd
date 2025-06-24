/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2017 Felipe Sateler
***/

#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "env-util.h"
#include "initrd-util.h"
#include "log.h"
#include "main-func.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "special.h"
#include "string-util.h"
#include "unit-def.h"

static int target_is_inactive(sd_bus *bus, const char *target) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *path = NULL, *state = NULL;
        int r;

        path = unit_dbus_path_from_name(target);
        if (!path)
                return log_oom();

        r = sd_bus_get_property_string(bus,
                                       "org.freedesktop.systemd1",
                                       path,
                                       "org.freedesktop.systemd1.Unit",
                                       "ActiveState",
                                       &error,
                                       &state);
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve unit state: %s", bus_error_message(&error, r));

        return streq_ptr(state, "inactive");
}

static int start_target(sd_bus *bus, const char *target) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        log_info("Starting %s", target);

        /* Start this unit only if we can replace basic.target with it */
        r = bus_call_method(
                        bus,
                        bus_systemd_mgr,
                        "StartUnit",
                        &error,
                        NULL,
                        "ss", target, "isolate");

        if (r < 0)
                return log_error_errno(r, "Failed to start %s: %s", target, bus_error_message(&error, r));

        return 0;
}

static int fork_wait(const char* const cmdline[]) {
        pid_t pid;
        int r;

        r = safe_fork("(sulogin)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
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
               "system logs, \"systemctl reboot\" to reboot, or \"exit\"\n" "to continue bootup.\n", mode);
        fflush(stdout);
}

static int run(int argc, char *argv[]) {
        const char* sulogin_cmdline[] = {
                SULOGIN,
                NULL,             /* --force */
                NULL
        };
        bool force = false;
        int r;

        log_setup();

        print_mode(argc > 1 ? argv[1] : "");

        if (getenv_bool("SYSTEMD_SULOGIN_FORCE") > 0)
                force = true;

        if (!force) {
                /* We look the argument in the kernel cmdline under the same name as the environment variable
                 * to express that this is not supported at the same level as the regular kernel cmdline
                 * switches. */
                r = proc_cmdline_get_bool("SYSTEMD_SULOGIN_FORCE", /* flags = */ 0, &force);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse SYSTEMD_SULOGIN_FORCE from kernel command line, ignoring: %m");
        }

        if (force)
                /* allows passwordless logins if root account is locked. */
                sulogin_cmdline[1] = "--force";

        for (;;) {
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                (void) fork_wait(sulogin_cmdline);

                r = bus_connect_system_systemd(&bus);
                if (r < 0) {
                        log_warning_errno(r, "Failed to get D-Bus connection: %m");
                        goto fallback;
                }

                log_info("Reloading system manager configuration.");
                r = bus_service_manager_reload(bus);
                if (r < 0)
                        goto fallback;

                const char *target = in_initrd() ? SPECIAL_INITRD_TARGET : SPECIAL_DEFAULT_TARGET;

                r = target_is_inactive(bus, target);
                if (r < 0)
                        goto fallback;
                if (!r) {
                        log_warning("%s is not inactive. Please review the %s setting.", target, target);
                        goto fallback;
                }

                if (start_target(bus, target) >= 0)
                        break;

        fallback:
                log_warning("Fallback to the single-user shell.");
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
