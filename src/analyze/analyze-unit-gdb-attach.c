/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "analyze.h"
#include "analyze-unit-gdb-attach.h"
#include "bus-error.h"
#include "bus-util.h"
#include "fd-util.h"
#include "log.h"
#include "namespace-util.h"
#include "process-util.h"
#include "runtime-scope.h"
#include "signal-util.h"
#include "strv.h"
#include "unit-def.h"
#include "unit-name.h"

static void sigterm_handler(int signal, siginfo_t *info, void *ucontext) {
        assert(signal == SIGTERM);
        assert(info);

        /* If the sender is not us, propogate the signal to all processes in
         * the same process group */
        if (si_code_from_process(info->si_code) &&
            pid_is_valid(info->si_pid) &&
            info->si_pid != getpid_cached())
                (void) kill(0, signal);
}

int verb_unit_gdb_attach(int argc, char *argv[], void *userdata) {
        static const struct sigaction sa = {
                .sa_sigaction = sigterm_handler,
                .sa_flags = SA_SIGINFO,
        };

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *unit = NULL;
        int r;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot spawn a unit shell for a remote service");

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

        if (!arg_debugger) {
                char *env_debugger;

                env_debugger = getenv("SYSTEMD_DEBUGGER");
                if (env_debugger)
                        arg_debugger = env_debugger;
                else
                        arg_debugger = "gdb";
        }

        _cleanup_strv_free_ char **debugger_call = NULL;
        r = strv_extend(&debugger_call, arg_debugger);
        if (r < 0)
                return log_oom();

        _cleanup_free_ char *pid_str = NULL;
        r = asprintf(&pid_str, "%d", pid);
        if (r < 0)
                return log_oom();

        if (streq(arg_debugger, "gdb")) {
                r = strv_extend_many(&debugger_call, "--pid", pid_str);
                       if (r < 0)
                               return log_oom();
        }

        if (streq(arg_debugger, "lldb")) {
                r = strv_extend_many(&debugger_call, "--attach-pid", pid_str);
                       if (r < 0)
                               return log_oom();
        }

        if (arg_root) {
                if (streq(arg_debugger, "gdb")) {
                        r = strv_extend_many(&debugger_call, "--pid", pid_str);
                               if (r < 0)
                                       return log_oom();

                        const char *sysroot_cmd;
                        sysroot_cmd = strjoina("set sysroot ", arg_root);

                        r = strv_extend_many(&debugger_call, "-iex", sysroot_cmd);
                        if (r < 0)
                                return log_oom();
                } else if (streq(arg_debugger, "lldb")) {
                        r = strv_extend_many(&debugger_call, "--attach-pid", pid_str);
                               if (r < 0)
                                       return log_oom();

                        const char *sysroot_cmd;
                        sysroot_cmd = strjoina("platform select --sysroot ", arg_root, " host");

                        r = strv_extend_many(&debugger_call, "-O", sysroot_cmd);
                        if (r < 0)
                                return log_oom();
                }
        }

        /* Don't interfere with debugger and its handling of SIGINT. */
        (void) ignore_signals(SIGINT);
        (void) sigaction(SIGTERM, &sa, NULL);

        const char *fork_name = strjoina("(", debugger_call[0], ")");
        pid_t child;
        r = safe_fork(fork_name, FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL, &child);
        if (r < 0)
                return log_error_errno(r, "Failed to fork: %m");

        if (r == 0) {
                r = execvp(debugger_call[0], debugger_call);
                if (r < 0)
                        log_error_errno(errno, "Failed to invoke '%s': %m", debugger_call[0]);
                _exit(EXIT_FAILURE);
        }

        return wait_for_terminate_and_check(
                        debugger_call[0],
                        child,
                        WAIT_LOG_ABNORMAL|WAIT_LOG_NON_ZERO_EXIT_STATUS);
}
