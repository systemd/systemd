/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "analyze.h"
#include "analyze-unit-gdb.h"
#include "bus-error.h"
#include "bus-util.h"
#include "log.h"
#include "pidref.h"
#include "process-util.h"
#include "runtime-scope.h"
#include "signal-util.h"
#include "strv.h"
#include "unit-def.h"
#include "unit-name.h"

int verb_unit_gdb(int argc, char *argv[], void *userdata) {
        static const struct sigaction sa = {
                .sa_sigaction = sigterm_process_group_handler,
                .sa_flags = SA_SIGINFO,
        };

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *unit = NULL;
        int r;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot spawn a debugger for a remote service.");

        r = unit_name_mangle_with_suffix(argv[1], "as unit", UNIT_NAME_MANGLE_WARN, ".service", &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle name '%s': %m", argv[1]);

        r = acquire_bus(&bus, /* use_full_bus= */ NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        _cleanup_free_ char *object = unit_dbus_path_from_name(unit);
        if (!object)
                return log_oom();

        r = sd_bus_get_property(
                        bus,
                        "org.freedesktop.systemd1",
                        object,
                        "org.freedesktop.systemd1.Service",
                        "MainPID",
                        &error,
                        &reply,
                        "u");
        if (r < 0)
                return log_error_errno(r, "Failed to get the main PID of %s: %s", unit, bus_error_message(&error, r));

        pid_t pid;
        r = sd_bus_message_read(reply, "u", &pid);
        if (r < 0)
                return log_error_errno(r, "Failed to read the main PID of %s from reply: %m", unit);
        if (pid == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "Unit %s has no MainPID (hint: inactive?)", unit);

        if (!arg_debugger) {
                arg_debugger = strdup(secure_getenv("SYSTEMD_DEBUGGER") ?: "gdb");
                if (!arg_debugger)
                        return log_oom();
        }

        if (!STR_IN_SET(arg_debugger, "gdb", "lldb"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "The debugger must be either 'gdb' or 'lldb'.");

        _cleanup_strv_free_ char **debugger_call = NULL;
        r = strv_extend(&debugger_call, arg_debugger);
        if (r < 0)
                return log_oom();

        if (streq(arg_debugger, "gdb")) {
                r = strv_extendf(&debugger_call, "--pid=" PID_FMT, pid);
                if (r < 0)
                        return log_oom();

                if (arg_root) {
                        _cleanup_free_ char *sysroot_cmd = strjoin("set sysroot ", arg_root);
                        r = strv_extend_many(&debugger_call, "-iex", sysroot_cmd);
                        if (r < 0)
                                return log_oom();
                }

        } else if (streq(arg_debugger, "lldb")) {
                r = strv_extendf(&debugger_call, "--attach-pid=" PID_FMT, pid);
                if (r < 0)
                        return log_oom();

                if (arg_root) {
                        _cleanup_free_ char *sysroot_cmd = strjoin("platform select --sysroot ", arg_root, " host");
                        r = strv_extend_many(&debugger_call, "-O", sysroot_cmd);
                        if (r < 0)
                                return log_oom();
                }
        } else
                assert_not_reached();

        r = strv_extend_strv(&debugger_call, arg_debugger_args, /* filter_duplicates = */ false);
        if (r < 0)
                return log_oom();

        /* Don't interfere with debugger and its handling of SIGINT. */
        (void) ignore_signals(SIGINT);
        (void) sigaction(SIGTERM, &sa, NULL);

        _cleanup_free_ char *fork_name = strjoin("(", debugger_call[0], ")");
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork(fork_name, FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL, &pidref);
        if (r < 0)
                return log_error_errno(r, "Fork failed: %m");

        if (r == 0) {
                (void) execvp(debugger_call[0], debugger_call);
                log_error_errno(errno, "Failed to invoke '%s': %m", debugger_call[0]);
                _exit(EXIT_FAILURE);
        }

        return pidref_wait_for_terminate_and_check(
                        debugger_call[0],
                        &pidref,
                        WAIT_LOG_ABNORMAL|WAIT_LOG_NON_ZERO_EXIT_STATUS);
}
