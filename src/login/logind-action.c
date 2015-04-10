/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <unistd.h>

#include "conf-parser.h"
#include "special.h"
#include "sleep-config.h"
#include "bus-util.h"
#include "bus-error.h"
#include "logind-action.h"
#include "formats-util.h"
#include "process-util.h"
#include "terminal-util.h"

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
                [HANDLE_HYBRID_SLEEP] = "Hibernating and suspending..."
        };

        static const char * const target_table[_HANDLE_ACTION_MAX] = {
                [HANDLE_POWEROFF] = SPECIAL_POWEROFF_TARGET,
                [HANDLE_REBOOT] = SPECIAL_REBOOT_TARGET,
                [HANDLE_HALT] = SPECIAL_HALT_TARGET,
                [HANDLE_KEXEC] = SPECIAL_KEXEC_TARGET,
                [HANDLE_SUSPEND] = SPECIAL_SUSPEND_TARGET,
                [HANDLE_HIBERNATE] = SPECIAL_HIBERNATE_TARGET,
                [HANDLE_HYBRID_SLEEP] = SPECIAL_HYBRID_SLEEP_TARGET
        };

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        InhibitWhat inhibit_operation;
        Inhibitor *offending = NULL;
        bool supported;
        int r;

        assert(m);

        /* If the key handling is turned off, don't do anything */
        if (handle == HANDLE_IGNORE) {
                log_debug("Refusing operation, as it is turned off.");
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
                        log_debug("Refusing operation, %s is inhibited.", inhibit_what_to_string(inhibit_key));
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
                supported = can_sleep("suspend") > 0;
        else if (handle == HANDLE_HIBERNATE)
                supported = can_sleep("hibernate") > 0;
        else if (handle == HANDLE_HYBRID_SLEEP)
                supported = can_sleep("hybrid-sleep") > 0;
        else if (handle == HANDLE_KEXEC)
                supported = access(KEXEC, X_OK) >= 0;
        else
                supported = true;

        if (!supported) {
                log_warning("Requested operation not supported, ignoring.");
                return -EOPNOTSUPP;
        }

        if (m->action_what) {
                log_debug("Action already in progress, ignoring.");
                return -EALREADY;
        }

        inhibit_operation = handle == HANDLE_SUSPEND || handle == HANDLE_HIBERNATE || handle == HANDLE_HYBRID_SLEEP ? INHIBIT_SLEEP : INHIBIT_SHUTDOWN;

        /* If the actual operation is inhibited, warn and fail */
        if (!ignore_inhibited &&
            manager_is_inhibited(m, inhibit_operation, INHIBIT_BLOCK, NULL, false, false, 0, &offending)) {
                _cleanup_free_ char *comm = NULL, *u = NULL;

                get_process_comm(offending->pid, &comm);
                u = uid_to_name(offending->uid);

                /* If this is just a recheck of the lid switch then don't warn about anything */
                if (!is_edge) {
                        log_debug("Refusing operation, %s is inhibited by UID "UID_FMT"/%s, PID "PID_FMT"/%s.",
                                  inhibit_what_to_string(inhibit_operation),
                                  offending->uid, strna(u),
                                  offending->pid, strna(comm));
                        return 0;
                }

                log_error("Refusing operation, %s is inhibited by UID "UID_FMT"/%s, PID "PID_FMT"/%s.",
                          inhibit_what_to_string(inhibit_operation),
                          offending->uid, strna(u),
                          offending->pid, strna(comm));

                warn_melody();
                return -EPERM;
        }

        log_info("%s", message_table[handle]);

        r = bus_manager_shutdown_or_sleep_now_or_later(m, target_table[handle], inhibit_operation, &error);
        if (r < 0) {
                log_error("Failed to execute operation: %s", bus_error_message(&error, r));
                return r;
        }

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
        [HANDLE_LOCK] = "lock"
};

DEFINE_STRING_TABLE_LOOKUP(handle_action, HandleAction);
DEFINE_CONFIG_PARSE_ENUM(config_parse_handle_action, handle_action, HandleAction, "Failed to parse handle action setting");
