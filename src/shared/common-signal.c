/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <malloc.h>
#include <sys/signalfd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "common-signal.h"
#include "format-util.h"
#include "log.h"
#include "memstream-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"

int sigrtmin18_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        struct sigrtmin18_info *info = userdata;
        _cleanup_free_ char *comm = NULL;

        assert(s);
        assert(si);

        if (!si_code_from_process(si->ssi_code)) {
                log_notice("Received control signal %s with unexpected .si_code %i, ignoring.", signal_to_string(si->ssi_signo), si->ssi_code);
                return 0;
        }

        (void) pid_get_comm(si->ssi_pid, &comm);

        if (si->ssi_code != SI_QUEUE) {
                log_notice("Received control signal %s from process " PID_FMT " (%s) without command value, ignoring.",
                           signal_to_string(si->ssi_signo),
                           (pid_t) si->ssi_pid,
                           strna(comm));
                return 0;
        }

        log_debug("Received control signal %s from process " PID_FMT " (%s) with command 0x%08x.",
                  signal_to_string(si->ssi_signo),
                  (pid_t) si->ssi_pid,
                  strna(comm),
                  (unsigned) si->ssi_int);

        switch (si->ssi_int) {

        case _COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE..._COMMON_SIGNAL_COMMAND_LOG_LEVEL_END:
                log_set_max_level(si->ssi_int - _COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE);
                break;

        case COMMON_SIGNAL_COMMAND_CONSOLE:
                log_set_target_and_open(LOG_TARGET_CONSOLE);
                break;
        case COMMON_SIGNAL_COMMAND_JOURNAL:
                log_set_target_and_open(LOG_TARGET_JOURNAL);
                break;
        case COMMON_SIGNAL_COMMAND_KMSG:
                log_set_target_and_open(LOG_TARGET_KMSG);
                break;
        case COMMON_SIGNAL_COMMAND_NULL:
                log_set_target_and_open(LOG_TARGET_NULL);
                break;

        case COMMON_SIGNAL_COMMAND_MEMORY_PRESSURE:
                if (info && info->memory_pressure_handler)
                        return info->memory_pressure_handler(s, info->memory_pressure_userdata);

                sd_event_trim_memory();
                break;

        case COMMON_SIGNAL_COMMAND_MALLOC_INFO: {
                _cleanup_(memstream_done) MemStream m = {};
                FILE *f;

                f = memstream_init(&m);
                if (!f) {
                        log_oom();
                        break;
                }

                if (malloc_info(0, f) < 0) {
                        log_error_errno(errno, "Failed to invoke malloc_info(): %m");
                        break;
                }

                (void) memstream_dump(LOG_INFO, &m);
                break;
        }

        default:
                log_notice("Received control signal %s with unknown command 0x%08x, ignoring.",
                           signal_to_string(si->ssi_signo), (unsigned) si->ssi_int);
        }

        return 0;
}
