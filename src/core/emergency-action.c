/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "ansi-color.h"
#include "emergency-action.h"
#include "manager.h"
#include "reboot-util.h"
#include "special.h"
#include "string-table.h"
#include "string-util.h"
#include "virt.h"

static const char* const emergency_action_table[_EMERGENCY_ACTION_MAX] = {
        [EMERGENCY_ACTION_NONE]               = "none",
        [EMERGENCY_ACTION_EXIT]               = "exit",
        [EMERGENCY_ACTION_EXIT_FORCE]         = "exit-force",
        [EMERGENCY_ACTION_REBOOT]             = "reboot",
        [EMERGENCY_ACTION_REBOOT_FORCE]       = "reboot-force",
        [EMERGENCY_ACTION_REBOOT_IMMEDIATE]   = "reboot-immediate",
        [EMERGENCY_ACTION_POWEROFF]           = "poweroff",
        [EMERGENCY_ACTION_POWEROFF_FORCE]     = "poweroff-force",
        [EMERGENCY_ACTION_POWEROFF_IMMEDIATE] = "poweroff-immediate",
        [EMERGENCY_ACTION_SOFT_REBOOT]        = "soft-reboot",
        [EMERGENCY_ACTION_SOFT_REBOOT_FORCE]  = "soft-reboot-force",
        [EMERGENCY_ACTION_KEXEC]              = "kexec",
        [EMERGENCY_ACTION_KEXEC_FORCE]        = "kexec-force",
        [EMERGENCY_ACTION_HALT]               = "halt",
        [EMERGENCY_ACTION_HALT_FORCE]         = "halt-force",
        [EMERGENCY_ACTION_HALT_IMMEDIATE]     = "halt-immediate",
};

static void log_and_status(
                Manager *m,
                EmergencyAction action,
                EmergencyActionFlags flags,
                const char *message,
                const char *reason) {

        assert(m);
        assert(message);
        assert(reason);

        log_full(FLAGS_SET(flags, EMERGENCY_ACTION_WARN) ? LOG_WARNING : LOG_DEBUG,
                 "%s: %s", message, reason);

        bool do_sleep = FLAGS_SET(flags, EMERGENCY_ACTION_WARN|EMERGENCY_ACTION_SLEEP_5S) &&
                IN_SET(action,
                       EMERGENCY_ACTION_EXIT_FORCE,
                       EMERGENCY_ACTION_REBOOT_FORCE, EMERGENCY_ACTION_REBOOT_IMMEDIATE,
                       EMERGENCY_ACTION_POWEROFF_FORCE, EMERGENCY_ACTION_POWEROFF_IMMEDIATE,
                       EMERGENCY_ACTION_SOFT_REBOOT_FORCE,
                       EMERGENCY_ACTION_KEXEC_FORCE);

        if (FLAGS_SET(flags, EMERGENCY_ACTION_WARN))
                manager_status_printf(
                                m,
                                STATUS_TYPE_EMERGENCY,
                                ANSI_HIGHLIGHT_RED "  !!  " ANSI_NORMAL,
                                "%s: %s%s", message, reason,
                                do_sleep ? ", proceeding in 5s" : "");

        /* Optionally sleep for 5s so that the user can see this output, before we actually execute the
         * operation. Do this only if we immediately execute an operation, i.e. when there's no event loop to
         * feed anymore. */
        if (do_sleep)
                (void) sleep(5);
}

void emergency_action(
                Manager *m,
                EmergencyAction action,
                EmergencyActionFlags flags,
                const char *reboot_arg,
                int exit_status,
                const char *reason) {

        Unit *u;

        assert(m);
        assert(action >= 0);
        assert(action < _EMERGENCY_ACTION_MAX);
        assert((flags & ~_EMERGENCY_ACTION_FLAGS_MAX) == 0);
        assert(reason);

        if (action == EMERGENCY_ACTION_NONE)
                return;

        /* Is the special shutdown target active or queued? If so, we are in shutdown state */
        if (IN_SET(action,
                   EMERGENCY_ACTION_REBOOT,
                   EMERGENCY_ACTION_SOFT_REBOOT,
                   EMERGENCY_ACTION_POWEROFF,
                   EMERGENCY_ACTION_EXIT,
                   EMERGENCY_ACTION_KEXEC,
                   EMERGENCY_ACTION_HALT)) {
                u = manager_get_unit(m, SPECIAL_SHUTDOWN_TARGET);
                if (u && unit_active_or_pending(u)) {
                        log_notice("Shutdown is already active. Skipping emergency action request %s.",
                                   emergency_action_table[action]);
                        return;
                }
        }

        if (FLAGS_SET(flags, EMERGENCY_ACTION_IS_WATCHDOG) && !m->service_watchdogs) {
                log_warning("Watchdog disabled! Not acting on: %s", reason);
                return;
        }

        switch (action) {

        case EMERGENCY_ACTION_REBOOT:
                log_and_status(m, action, flags, "Rebooting", reason);

                (void) update_reboot_parameter_and_warn(reboot_arg, true);
                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_REBOOT_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                break;

        case EMERGENCY_ACTION_REBOOT_FORCE:
                log_and_status(m, action, flags, "Forcibly rebooting", reason);

                (void) update_reboot_parameter_and_warn(reboot_arg, true);
                m->objective = MANAGER_REBOOT;
                break;

        case EMERGENCY_ACTION_REBOOT_IMMEDIATE:
                log_and_status(m, action, flags, "Rebooting immediately", reason);

                sync();

                if (!isempty(reboot_arg)) {
                        log_info("Rebooting with argument '%s'.", reboot_arg);
                        (void) raw_reboot(LINUX_REBOOT_CMD_RESTART2, reboot_arg);
                        log_warning_errno(errno, "Failed to reboot with parameter, retrying without: %m");
                }

                log_info("Rebooting.");
                (void) reboot(RB_AUTOBOOT);
                break;

        case EMERGENCY_ACTION_SOFT_REBOOT:
                log_and_status(m, action, flags, "Soft-rebooting", reason);

                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_SOFT_REBOOT_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                break;

        case EMERGENCY_ACTION_SOFT_REBOOT_FORCE:
                log_and_status(m, action, flags, "Forcibly soft-rebooting", reason);

                m->objective = MANAGER_SOFT_REBOOT;
                break;

        case EMERGENCY_ACTION_EXIT:

                if (exit_status >= 0)
                        m->return_value = exit_status;

                if (MANAGER_IS_USER(m) || detect_container() > 0) {
                        log_and_status(m, action, flags, "Exiting", reason);
                        (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_EXIT_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                        break;
                }

                log_notice("Doing \"poweroff\" action instead of an \"exit\" emergency action.");
                _fallthrough_;

        case EMERGENCY_ACTION_POWEROFF:
                log_and_status(m, action, flags, "Powering off", reason);
                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_POWEROFF_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                break;

        case EMERGENCY_ACTION_EXIT_FORCE:

                if (exit_status >= 0)
                        m->return_value = exit_status;

                if (MANAGER_IS_USER(m) || detect_container() > 0) {
                        log_and_status(m, action, flags, "Exiting immediately", reason);
                        m->objective = MANAGER_EXIT;
                        break;
                }

                log_notice("Doing \"poweroff-force\" action instead of an \"exit-force\" emergency action.");
                _fallthrough_;

        case EMERGENCY_ACTION_POWEROFF_FORCE:
                log_and_status(m, action, flags, "Forcibly powering off", reason);
                m->objective = MANAGER_POWEROFF;
                break;

        case EMERGENCY_ACTION_POWEROFF_IMMEDIATE:
                log_and_status(m, action, flags, "Powering off immediately", reason);

                sync();

                log_info("Powering off.");
                (void) reboot(RB_POWER_OFF);
                break;

        case EMERGENCY_ACTION_KEXEC:
                log_and_status(m, action, flags, "Executing kexec", reason);
                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_KEXEC_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                break;

        case EMERGENCY_ACTION_KEXEC_FORCE:
                log_and_status(m, action, flags, "Forcibly executing kexec", reason);
                m->objective = MANAGER_KEXEC;
                break;

        case EMERGENCY_ACTION_HALT:
                log_and_status(m, action, flags, "Halting", reason);
                (void) manager_add_job_by_name_and_warn(m, JOB_START, SPECIAL_HALT_TARGET, JOB_REPLACE_IRREVERSIBLY, NULL, NULL);
                break;

        case EMERGENCY_ACTION_HALT_FORCE:
                log_and_status(m, action, flags, "Forcibly halting", reason);
                m->objective = MANAGER_HALT;
                break;

        case EMERGENCY_ACTION_HALT_IMMEDIATE:
                log_and_status(m, action, flags, "Halting immediately", reason);

                sync();

                log_info("Halting.");
                (void) reboot(RB_HALT_SYSTEM);
                break;

        default:
                assert_not_reached();
        }
}

DEFINE_STRING_TABLE_LOOKUP(emergency_action, EmergencyAction);

int parse_emergency_action(
                const char *value,
                RuntimeScope runtime_scope,
                EmergencyAction *ret) {

        EmergencyAction x;

        x = emergency_action_from_string(value);
        if (x < 0)
                return -EINVAL;

        if (runtime_scope != RUNTIME_SCOPE_SYSTEM && x > _EMERGENCY_ACTION_LAST_USER_ACTION)
                return -EOPNOTSUPP;

        *ret = x;
        return 0;
}
