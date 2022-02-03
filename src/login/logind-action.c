/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "conf-parser.h"
#include "format-util.h"
#include "logind-action.h"
#include "logind-dbus.h"
#include "logind-session-dbus.h"
#include "process-util.h"
#include "special.h"
#include "string-table.h"
#include "terminal-util.h"
#include "user-util.h"

static const ActionTableItem action_table[_HANDLE_ACTION_MAX] = {
        [HANDLE_POWEROFF] = {
                HANDLE_POWEROFF,
                SPECIAL_POWEROFF_TARGET,
                INHIBIT_SHUTDOWN,
                "org.freedesktop.login1.power-off",
                "org.freedesktop.login1.power-off-multiple-sessions",
                "org.freedesktop.login1.power-off-ignore-inhibit",
                _SLEEP_OPERATION_INVALID,
                SD_MESSAGE_SHUTDOWN_STR,
                "System is powering down",
                "power-off",
                },
        [HANDLE_REBOOT] = {
                HANDLE_REBOOT,
                SPECIAL_REBOOT_TARGET,
                INHIBIT_SHUTDOWN,
                "org.freedesktop.login1.reboot",
                "org.freedesktop.login1.reboot-multiple-sessions",
                "org.freedesktop.login1.reboot-ignore-inhibit",
                _SLEEP_OPERATION_INVALID,
                SD_MESSAGE_SHUTDOWN_STR,
                "System is rebooting",
                "reboot",
                },
        [HANDLE_HALT]  = {
                HANDLE_HALT,
                SPECIAL_HALT_TARGET,
                INHIBIT_SHUTDOWN,
                "org.freedesktop.login1.halt",
                "org.freedesktop.login1.halt-multiple-sessions",
                "org.freedesktop.login1.halt-ignore-inhibit",
                _SLEEP_OPERATION_INVALID,
                SD_MESSAGE_SHUTDOWN_STR,
                "System is halting",
                "halt",
                },
        [HANDLE_KEXEC]  = {
                HANDLE_KEXEC,
                SPECIAL_KEXEC_TARGET,
                INHIBIT_SHUTDOWN,
                "org.freedesktop.login1.reboot",
                "org.freedesktop.login1.reboot-multiple-sessions",
                "org.freedesktop.login1.reboot-ignore-inhibit",
                _SLEEP_OPERATION_INVALID,
                SD_MESSAGE_SHUTDOWN_STR,
                "System is rebooting with kexec",
                "kexec",
                },
        [HANDLE_SUSPEND]  = {
                HANDLE_SUSPEND,
                SPECIAL_SUSPEND_TARGET,
                INHIBIT_SLEEP,
                "org.freedesktop.login1.suspend",
                "org.freedesktop.login1.suspend-multiple-sessions",
                "org.freedesktop.login1.suspend-ignore-inhibit",
                SLEEP_SUSPEND,
                },
        [HANDLE_HIBERNATE]  = {
                HANDLE_HIBERNATE,
                SPECIAL_HIBERNATE_TARGET,
                INHIBIT_SLEEP,
                "org.freedesktop.login1.hibernate",
                "org.freedesktop.login1.hibernate-multiple-sessions",
                "org.freedesktop.login1.hibernate-ignore-inhibit",
                SLEEP_HIBERNATE,
                },
        [HANDLE_HYBRID_SLEEP]  = {
                HANDLE_HYBRID_SLEEP,
                SPECIAL_HYBRID_SLEEP_TARGET,
                INHIBIT_SLEEP,
                "org.freedesktop.login1.hibernate",
                "org.freedesktop.login1.hibernate-multiple-sessions",
                "org.freedesktop.login1.hibernate-ignore-inhibit",
                SLEEP_HYBRID_SLEEP,
                },
        [HANDLE_SUSPEND_THEN_HIBERNATE]  = {
                HANDLE_SUSPEND_THEN_HIBERNATE,
                SPECIAL_SUSPEND_THEN_HIBERNATE_TARGET,
                INHIBIT_SLEEP,
                "org.freedesktop.login1.hibernate",
                "org.freedesktop.login1.hibernate-multiple-sessions",
                "org.freedesktop.login1.hibernate-ignore-inhibit",
                SLEEP_SUSPEND_THEN_HIBERNATE,
                },
        [HANDLE_FACTORY_RESET]  = {
                HANDLE_FACTORY_RESET,
                SPECIAL_FACTORY_RESET_TARGET,
                _INHIBIT_WHAT_INVALID,
                NULL,
                NULL,
                NULL,
                _SLEEP_OPERATION_INVALID,
                SD_MESSAGE_FACTORY_RESET_STR,
                "System is performing factory reset",
                NULL
                },
};

const char* manager_target_for_action(HandleAction handle) {
        assert(handle >= 0);
        assert(handle < (ssize_t) ELEMENTSOF(action_table));

        return action_table[handle].target;
}

const ActionTableItem* manager_item_for_handle(HandleAction handle) {
        assert(handle >= 0);
        assert(handle < (ssize_t) ELEMENTSOF(action_table));

        return &action_table[handle];
}

int manager_handle_action(
                Manager *m,
                InhibitWhat inhibit_key,
                HandleAction handle,
                bool ignore_inhibited,
                bool is_edge) {

        static const char * const message_table[_HANDLE_ACTION_MAX] = {
                [HANDLE_POWEROFF] = "Powering Off...",
                [HANDLE_REBOOT] = "Rebooting...",
                [HANDLE_HALT] = "Halting...",
                [HANDLE_KEXEC] = "Rebooting via kexec...",
                [HANDLE_SUSPEND] = "Suspending...",
                [HANDLE_HIBERNATE] = "Hibernating...",
                [HANDLE_HYBRID_SLEEP] = "Hibernating and suspending...",
                [HANDLE_SUSPEND_THEN_HIBERNATE] = "Suspending, then hibernating...",
                [HANDLE_FACTORY_RESET] = "Performing factory reset...",
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        InhibitWhat inhibit_operation;
        Inhibitor *offending = NULL;
        bool supported;
        int r;

        assert(m);

        /* If the key handling is turned off, don't do anything */
        if (handle == HANDLE_IGNORE) {
                log_debug("Handling of %s (%s) is disabled, taking no action.",
                          inhibit_key == 0 ? "idle timeout" : inhibit_what_to_string(inhibit_key),
                          is_edge ? "edge" : "level");
                return 0;
        }

        if (inhibit_key == INHIBIT_HANDLE_LID_SWITCH) {
                /* If the last system suspend or startup is too close,
                 * let's not suspend for now, to give USB docking
                 * stations some time to settle so that we can
                 * properly watch its displays. */
                if (m->lid_switch_ignore_event_source) {
                        log_debug("Ignoring lid switch request, system startup or resume too close.");
                        return 0;
                }
        }

        /* If the key handling is inhibited, don't do anything */
        if (inhibit_key > 0) {
                if (manager_is_inhibited(m, inhibit_key, INHIBIT_BLOCK, NULL, true, false, 0, NULL)) {
                        log_debug("Refusing %s operation, %s is inhibited.",
                                  handle_action_to_string(handle),
                                  inhibit_what_to_string(inhibit_key));
                        return 0;
                }
        }

        /* Locking is handled differently from the rest. */
        if (handle == HANDLE_LOCK) {
                if (!is_edge)
                        return 0;

                log_info("Locking sessions...");
                session_send_lock_all(m, true);
                return 1;
        }

        if (handle == HANDLE_SUSPEND)
                supported = can_sleep(SLEEP_SUSPEND) > 0;
        else if (handle == HANDLE_HIBERNATE)
                supported = can_sleep(SLEEP_HIBERNATE) > 0;
        else if (handle == HANDLE_HYBRID_SLEEP)
                supported = can_sleep(SLEEP_HYBRID_SLEEP) > 0;
        else if (handle == HANDLE_SUSPEND_THEN_HIBERNATE)
                supported = can_sleep(SLEEP_SUSPEND_THEN_HIBERNATE) > 0;
        else if (handle == HANDLE_KEXEC)
                supported = access(KEXEC, X_OK) >= 0;
        else
                supported = true;

        if (!supported && IN_SET(handle, HANDLE_HIBERNATE, HANDLE_HYBRID_SLEEP, HANDLE_SUSPEND_THEN_HIBERNATE)) {
                supported = can_sleep(SLEEP_SUSPEND) > 0;
                if (supported) {
                        log_notice("Requested %s operation is not supported, using regular suspend instead.",
                                   handle_action_to_string(handle));
                        handle = HANDLE_SUSPEND;
                }
        }

        if (!supported)
                return log_warning_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                         "Requested %s operation not supported, ignoring.", handle_action_to_string(handle));

        if (m->delayed_action)
                return log_debug_errno(SYNTHETIC_ERRNO(EALREADY),
                                       "Action already in progress (%s), ignoring requested %s operation.",
                                       inhibit_what_to_string(m->delayed_action->inhibit_what),
                                       handle_action_to_string(handle));

        inhibit_operation = manager_item_for_handle(handle)->inhibit_what;

        /* If the actual operation is inhibited, warn and fail */
        if (!ignore_inhibited &&
            manager_is_inhibited(m, inhibit_operation, INHIBIT_BLOCK, NULL, false, false, 0, &offending)) {
                _cleanup_free_ char *comm = NULL, *u = NULL;

                (void) get_process_comm(offending->pid, &comm);
                u = uid_to_name(offending->uid);

                /* If this is just a recheck of the lid switch then don't warn about anything */
                log_full(is_edge ? LOG_ERR : LOG_DEBUG,
                         "Refusing %s operation, %s is inhibited by UID "UID_FMT"/%s, PID "PID_FMT"/%s.",
                         handle_action_to_string(handle),
                         inhibit_what_to_string(inhibit_operation),
                         offending->uid, strna(u),
                         offending->pid, strna(comm));

                return is_edge ? -EPERM : 0;
        }

        log_info("%s", message_table[handle]);

        r = bus_manager_shutdown_or_sleep_now_or_later(m, manager_item_for_handle(handle), &error);
        if (r < 0)
                return log_error_errno(r, "Failed to execute %s operation: %s",
                                       handle_action_to_string(handle),
                                       bus_error_message(&error, r));

        return 1;
}

static const char* const handle_action_table[_HANDLE_ACTION_MAX] = {
        [HANDLE_IGNORE] = "ignore",
        [HANDLE_POWEROFF] = "poweroff",
        [HANDLE_REBOOT] = "reboot",
        [HANDLE_HALT] = "halt",
        [HANDLE_KEXEC] = "kexec",
        [HANDLE_SUSPEND] = "suspend",
        [HANDLE_HIBERNATE] = "hibernate",
        [HANDLE_HYBRID_SLEEP] = "hybrid-sleep",
        [HANDLE_SUSPEND_THEN_HIBERNATE] = "suspend-then-hibernate",
        [HANDLE_FACTORY_RESET] = "factory-reset",
        [HANDLE_LOCK] = "lock",
};

DEFINE_STRING_TABLE_LOOKUP(handle_action, HandleAction);
DEFINE_CONFIG_PARSE_ENUM(config_parse_handle_action, handle_action, HandleAction, "Failed to parse handle action setting");
