/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/reboot.h>

#include "bus-error.h"
#include "bus-util.h"
#include "emergency-action.h"
#include "raw-reboot.h"
#include "reboot-util.h"
#include "special.h"
#include "string-table.h"
#include "terminal-util.h"

static void log_and_status(Manager *m, const char *message, const char *reason) {
        log_warning("%s: %s", message, reason);
        manager_status_printf(m, STATUS_TYPE_EMERGENCY,
                              ANSI_HIGHLIGHT_RED "  !!  " ANSI_NORMAL,
                              "%s: %s", message, reason);
}

int emergency_action(
                Manager *m,
                EmergencyAction action,
                const char *reboot_arg,
                const char *reason) {

        assert(m);
        assert(action >= 0);
        assert(action < _EMERGENCY_ACTION_MAX);

        if (action == EMERGENCY_ACTION_NONE)
                return -ECANCELED;

        if (!m->service_watchdogs) {
                log_warning("Watchdog disabled! Not acting on: %s", reason);
                return -ECANCELED;
        }

        if (!MANAGER_IS_SYSTEM(m)) {
                /* Downgrade all options to simply exiting if we run
                 * in user mode */

                log_warning("Exiting: %s", reason);
                m->exit_code = MANAGER_EXIT;
                return -ECANCELED;
        }

        switch (action) {

        case EMERGENCY_ACTION_REBOOT:
                log_and_status(m, "Rebooting", reason);

                (void) update_reboot_parameter_and_warn(reboot_arg);
                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_REBOOT_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL);

                break;

        case EMERGENCY_ACTION_REBOOT_FORCE:
                log_and_status(m, "Forcibly rebooting", reason);

                (void) update_reboot_parameter_and_warn(reboot_arg);
                m->exit_code = MANAGER_REBOOT;

                break;

        case EMERGENCY_ACTION_REBOOT_IMMEDIATE:
                log_and_status(m, "Rebooting immediately", reason);

                sync();

                if (!isempty(reboot_arg)) {
                        log_info("Rebooting with argument '%s'.", reboot_arg);
                        (void) raw_reboot(LINUX_REBOOT_CMD_RESTART2, reboot_arg);
                        log_warning_errno(errno, "Failed to reboot with parameter, retrying without: %m");
                }

                log_info("Rebooting.");
                (void) reboot(RB_AUTOBOOT);
                break;

        case EMERGENCY_ACTION_POWEROFF:
                log_and_status(m, "Powering off", reason);
                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_POWEROFF_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL);
                break;

        case EMERGENCY_ACTION_POWEROFF_FORCE:
                log_and_status(m, "Forcibly powering off", reason);
                m->exit_code = MANAGER_POWEROFF;
                break;

        case EMERGENCY_ACTION_POWEROFF_IMMEDIATE:
                log_and_status(m, "Powering off immediately", reason);

                sync();

                log_info("Powering off.");
                (void) reboot(RB_POWER_OFF);
                break;

        default:
                assert_not_reached("Unknown emergency action");
        }

        return -ECANCELED;
}

static const char* const emergency_action_table[_EMERGENCY_ACTION_MAX] = {
        [EMERGENCY_ACTION_NONE] = "none",
        [EMERGENCY_ACTION_REBOOT] = "reboot",
        [EMERGENCY_ACTION_REBOOT_FORCE] = "reboot-force",
        [EMERGENCY_ACTION_REBOOT_IMMEDIATE] = "reboot-immediate",
        [EMERGENCY_ACTION_POWEROFF] = "poweroff",
        [EMERGENCY_ACTION_POWEROFF_FORCE] = "poweroff-force",
        [EMERGENCY_ACTION_POWEROFF_IMMEDIATE] = "poweroff-immediate"
};
DEFINE_STRING_TABLE_LOOKUP(emergency_action, EmergencyAction);
