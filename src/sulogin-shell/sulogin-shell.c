/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2017 Felipe Sateler
***/

#include <errno.h>
#include <sys/prctl.h>

#include "sd-bus.h"

#include "bus-locator.h"
#include "bus-util.h"
#include "bus-error.h"
#include "constants.h"
#include "env-util.h"
#include "initrd-util.h"
#include "log.h"
#include "main-func.h"
#include "process-util.h"
#include "signal-util.h"
#include "special.h"
#include "unit-def.h"

static int reload_manager(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        log_info("Reloading system manager configuration");

        r = bus_message_new_method_call(
                        bus,
                        &m,
                        bus_systemd_mgr,
                        "Reload");
        if (r < 0)
                return bus_log_create_error(r);

        /* Reloading the daemon may take long, hence set a longer timeout here */
        r = sd_bus_call(bus, m, DAEMON_RELOAD_TIMEOUT_SEC, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to reload daemon: %s", bus_error_message(&error, r));

        return 0;
}

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
               "system logs, \"systemctl reboot\" to reboot, or \"exit\"\n" "to continue bootup.\n", mode);
        fflush(stdout);
}

static int run(int argc, char *argv[]) {
        const char* sulogin_cmdline[] = {
                SULOGIN,
                NULL,             /* --force */
                NULL
        };
        int r;

        log_setup();

        print_mode(argc > 1 ? argv[1] : "");

        if (getenv_bool("SYSTEMD_SULOGIN_FORCE") > 0)
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

                if (reload_manager(bus) < 0)
                        goto fallback;

                const char *target = in_initrd() ? SPECIAL_INITRD_TARGET : SPECIAL_DEFAULT_TARGET;

                r = target_is_inactive(bus, target);
                if (r < 0)
                        goto fallback;
                if (!r) {
                        log_warning("%s is not inactive. Please review the %s setting.\n", target, target);
                        goto fallback;
                }

                if (start_target(bus, target) >= 0)
                        break;

        fallback:
                log_warning("Fallback to the single-user shell.\n");
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
