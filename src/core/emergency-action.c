/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/reboot.h>

#include "bus-error.h"
#include "bus-util.h"
#include "emergency-action.h"
#include "raw-reboot.h"
#include "reboot-util.h"
#include "special.h"
#include "string-table.h"
#include "terminal-util.h"
#include "virt.h"

static const char* const emergency_action_table[_EMERGENCY_ACTION_MAX] = {
        [EMERGENCY_ACTION_NONE] =               "none",
        [EMERGENCY_ACTION_REBOOT] =             "reboot",
        [EMERGENCY_ACTION_REBOOT_FORCE] =       "reboot-force",
        [EMERGENCY_ACTION_REBOOT_IMMEDIATE] =   "reboot-immediate",
        [EMERGENCY_ACTION_POWEROFF] =           "poweroff",
        [EMERGENCY_ACTION_POWEROFF_FORCE] =     "poweroff-force",
        [EMERGENCY_ACTION_POWEROFF_IMMEDIATE] = "poweroff-immediate",
        [EMERGENCY_ACTION_EXIT] =               "exit",
        [EMERGENCY_ACTION_EXIT_FORCE] =         "exit-force",
};

static void log_and_status(Manager *m, bool warn, const char *message, const char *reason) {
        log_full(warn ? LOG_WARNING : LOG_DEBUG, "%s: %s", message, reason);
        if (warn)
                manager_status_printf(m, STATUS_TYPE_EMERGENCY,
                                      ANSI_HIGHLIGHT_RED "  !!  " ANSI_NORMAL,
                                      "%s: %s", message, reason);
}

void emergency_action(
                Manager *m,
                EmergencyAction action,
                EmergencyActionFlags options,
                const char *reboot_arg,
                int exit_status,
                const char *reason) {

        Unit *u;

        assert(m);
        assert(action >= 0);
        assert(action < _EMERGENCY_ACTION_MAX);

        /* Is the special shutdown target active or queued? If so, we are in shutdown state */
        if (IN_SET(action, EMERGENCY_ACTION_REBOOT, EMERGENCY_ACTION_POWEROFF, EMERGENCY_ACTION_EXIT)) {
                u = manager_get_unit(m, SPECIAL_SHUTDOWN_TARGET);
                if (u && unit_active_or_pending(u)) {
                        log_notice("Shutdown is already active. Skipping emergency action request %s.",
                                   emergency_action_table[action]);
                        return;
                }
        }

        if (action == EMERGENCY_ACTION_NONE)
                return;

        if (FLAGS_SET(options, EMERGENCY_ACTION_IS_WATCHDOG) && !m->service_watchdogs) {
                log_warning("Watchdog disabled! Not acting on: %s", reason);
                return;
        }

        bool warn = FLAGS_SET(options, EMERGENCY_ACTION_WARN);

        switch (action) {

        case EMERGENCY_ACTION_REBOOT:
                log_and_status(m, warn, "Rebooting", reason);

                (void) update_reboot_parameter_and_warn(reboot_arg, true);
                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_REBOOT_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                break;

        case EMERGENCY_ACTION_REBOOT_FORCE:
                log_and_status(m, warn, "Forcibly rebooting", reason);

                (void) update_reboot_parameter_and_warn(reboot_arg, true);
                m->objective = MANAGER_REBOOT;

                break;

        case EMERGENCY_ACTION_REBOOT_IMMEDIATE:
                log_and_status(m, warn, "Rebooting immediately", reason);

                sync();

                if (!isempty(reboot_arg)) {
                        log_info("Rebooting with argument '%s'.", reboot_arg);
                        (void) raw_reboot(LINUX_REBOOT_CMD_RESTART2, reboot_arg);
                        log_warning_errno(errno, "Failed to reboot with parameter, retrying without: %m");
                }

                log_info("Rebooting.");
                (void) reboot(RB_AUTOBOOT);
                break;

        case EMERGENCY_ACTION_EXIT:

                if (exit_status >= 0)
                        m->return_value = exit_status;

                if (MANAGER_IS_USER(m) || detect_container() > 0) {
                        log_and_status(m, warn, "Exiting", reason);
                        (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_EXIT_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                        break;
                }

                log_notice("Doing \"poweroff\" action instead of an \"exit\" emergency action.");
                _fallthrough_;

        case EMERGENCY_ACTION_POWEROFF:
                log_and_status(m, warn, "Powering off", reason);
                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_POWEROFF_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                break;

        case EMERGENCY_ACTION_EXIT_FORCE:

                if (exit_status >= 0)
                        m->return_value = exit_status;

                if (MANAGER_IS_USER(m) || detect_container() > 0) {
                        log_and_status(m, warn, "Exiting immediately", reason);
                        m->objective = MANAGER_EXIT;
                        break;
                }

                log_notice("Doing \"poweroff-force\" action instead of an \"exit-force\" emergency action.");
                _fallthrough_;

        case EMERGENCY_ACTION_POWEROFF_FORCE:
                log_and_status(m, warn, "Forcibly powering off", reason);
                m->objective = MANAGER_POWEROFF;
                break;

        case EMERGENCY_ACTION_POWEROFF_IMMEDIATE:
                log_and_status(m, warn, "Powering off immediately", reason);

                sync();

                log_info("Powering off.");
                (void) reboot(RB_POWER_OFF);
                break;

        default:
                assert_not_reached();
        }
}

DEFINE_STRING_TABLE_LOOKUP(emergency_action, EmergencyAction);

int parse_emergency_action(
                const char *value,
                bool system,
                EmergencyAction *ret) {

        EmergencyAction x;

        x = emergency_action_from_string(value);
        if (x < 0)
                return -EINVAL;

        if (!system && x != EMERGENCY_ACTION_NONE && x < _EMERGENCY_ACTION_FIRST_USER_ACTION)
                return -EOPNOTSUPP;

        *ret = x;
        return 0;
}
