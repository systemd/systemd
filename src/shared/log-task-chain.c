/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "alloc-util.h"
#include "format-util.h"
#include "log-task-chain.h"
#include "log.h"
#include "process-util.h"

void log_task_chain_msg(sd_bus_message *message, const char *special_action_string) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        pid_t pid;

        assert(message);
        assert(special_action_string);

        if (sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID|SD_BUS_CREDS_AUGMENT|SD_BUS_CREDS_COMM, &creds) < 0)
                return;

        /* We need at least the PID, otherwise there's nothing to log, the rest is optional */
        if (sd_bus_creds_get_pid(creds, &pid) < 0)
                return;

        log_task_chain_pid(pid, special_action_string);
}

void log_task_chain_pid(pid_t pid, const char *special_action_string) {
        pid_t ppid;
        uid_t uid;

        int saved_facility = log_get_facility();
        log_set_facility(LOG_AUTHPRIV);

        if (pid_is_valid(pid)) {
                log_debug("Action %s was requested, task chain is printed below:", special_action_string);
                log_debug("%10s %10s %-64s", "PID", "UID", "CMDLINE");

                do {
                        _cleanup_free_ char *cmdline = NULL;
                        if (pid == 1)
                                ppid = 0;
                        else if (get_process_ppid(pid, &ppid) < 0) {
                                log_error("Could not obtain PPID information for process "PID_FMT".", pid);
                                return;
                        }

                        if (get_process_uid(pid, &uid) < 0) {
                                log_error("Could not obtain UID information for process "PID_FMT".", pid);
                                return;
                        }

                        if (get_process_cmdline(pid, (size_t)64, 0, &cmdline) < 0) {
                                log_error("Could not obtain command line information for process "PID_FMT".", pid);
                                return;
                        }

                        log_debug("%10"PID_PRI" %10"PRIu32" %-64s%-3s", pid, uid, cmdline, 
                                   strlen(cmdline) > 64 ? "(+)" : "");

                        pid = ppid;
                } while (ppid > 0);

        } else
                log_error("Could not write task chain: PID "PID_FMT" was invalid.", pid);

        log_set_facility(saved_facility);
}
