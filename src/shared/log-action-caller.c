/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "alloc-util.h"
#include "format-util.h"
#include "log-action-caller.h"
#include "log.h"
#include "process-util.h"

static void print_task_chain_info(pid_t pid) {
        char *sshd_info_buf = NULL, *systemd_child_name = NULL;
        const size_t isize = 64, csize = 32;
        pid_t ppid, first_sshd_pid = 0, systemd_child_pid = 0, orig_pid = pid;
        uint32_t counter = 0;
        int r;

        sshd_info_buf = alloca_safe(isize);
        systemd_child_name = alloca_safe(csize);

        if (pid_is_valid(pid)) {
                do {
                        _cleanup_free_ char *comm;

                        if (pid > 1) {
                                if (get_process_ppid(pid, &ppid) < 0) {
                                        log_error("Could not obtain PPID information for process "PID_FMT".", pid);
                                        return;
                                }
                        } else 
                                ppid = 0;

                        if (get_process_comm(pid, &comm) < 0) {
                                log_error("Could not obtain command for process "PID_FMT".", pid);
                                return;
                        }

                        counter++;

                        if (first_sshd_pid == 0 && streq(comm, "sshd"))
                                first_sshd_pid = pid;

                        if (ppid == 1) {
                                strncpy(systemd_child_name, comm, csize);
                                systemd_child_pid = pid;
                        }
                                
                        pid = ppid;

                } while (ppid > 0);
        } else
                log_error("Could not obtain action caller information: PID "PID_FMT" was invalid.", orig_pid);

        if (first_sshd_pid > 0)
                r = snprintf(sshd_info_buf, isize, "at least one sshd present (PID "PID_FMT")", first_sshd_pid);
        else
                r = snprintf(sshd_info_buf, isize, "%s", "no sshd found");

        assert((size_t) r < isize);

        log_info("Task chain info for PID "PID_FMT": %u tasks, systemd child was %s (PID "PID_FMT"), %s.", 
                 orig_pid, counter, systemd_child_name, systemd_child_pid, sshd_info_buf);
}

void log_action_caller_msg(sd_bus_message *message, const char *special_action_string) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        pid_t pid, ppid;
        uid_t uid, loginuid;
        _cleanup_free_ char *parent_comm = NULL;
        const char *session = NULL, *unit = NULL, *comm = NULL;

        assert(message);
        assert(special_action_string);

        if (sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID|SD_BUS_CREDS_AUGMENT|SD_BUS_CREDS_COMM|SD_BUS_CREDS_UID|\
            SD_BUS_CREDS_AUDIT_LOGIN_UID|SD_BUS_CREDS_PPID|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_SESSION, &creds) < 0)
                return;

        /* We need at least the PID, otherwise there's nothing to log, the rest is optional */
        if (sd_bus_creds_get_pid(creds, &pid) < 0)
                return;

        if (sd_bus_creds_get_comm(creds, &comm) < 0)
                return;

        if (sd_bus_creds_get_uid(creds, &uid) < 0)
                return;        
        
        if (sd_bus_creds_get_ppid(creds, &ppid) < 0)
                return;   

        if (get_process_comm(ppid, &parent_comm) < 0)
                return;     
                
        if (sd_bus_creds_get_audit_login_uid(creds, &loginuid) < 0)
                return;        
        
        if (sd_bus_creds_get_session(creds, &session) < 0)
                return;

        if (sd_bus_creds_get_unit(creds, &unit) < 0)
                return;

        // log stuff
        log_info("Action %s was requested by PID "PID_FMT" (%s), UID "UID_FMT", login UID "UID_FMT", PPID "PID_FMT" (%s), session %s, unit %s.", 
                         special_action_string, pid, comm, uid, loginuid, ppid, parent_comm, session, unit);

        print_task_chain_info(pid);
}

void log_action_caller_pid(pid_t pid, const char *special_action_string) {
        pid_t ppid;
        uid_t uid, loginuid;
        _cleanup_free_ char *comm;
        _cleanup_free_ char *parent_comm;

        assert(special_action_string);

        if (pid_is_valid(pid)) {

                if (get_process_ppid(pid, &ppid) < 0) {
                        log_error("Could not obtain PPID information for process "PID_FMT".", pid);
                        return;
                }

                if (get_process_uid(pid, &uid) < 0) {
                        log_error("Could not obtain UID information for process "PID_FMT".", pid);
                        return;
                }

                if (get_process_loginuid(pid, &loginuid) < 0) {
                        log_error("Could not obtain login UID information for process "PID_FMT".", pid);
                        return;
                }

                if (get_process_comm(pid, &comm) < 0) {
                        log_error("Could not obtain command for process "PID_FMT".", pid);
                        return;
                }

                if (get_process_comm(ppid, &parent_comm) < 0) {
                        log_error("Could not obtain command for parent process "PID_FMT".", ppid);
                        return;
                }

                log_info("Action %s was requested by PID "PID_FMT" (%s), UID "UID_FMT", login UID "UID_FMT", PPID "PID_FMT" (%s).", 
                         special_action_string, pid, comm, uid, loginuid, ppid, parent_comm);

                print_task_chain_info(pid);

        } else
                log_error("Could not obtain action caller information: PID "PID_FMT" was invalid.", pid);

}
