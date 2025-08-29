/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "analyze.h"
#include "analyze-unit-gdb-start.h"
#include "bus-error.h"
#include "bus-util.h"
#include "bus-locator.h"
#include "bus-wait-for-units.h"
#include "bus-wait-for-jobs.h"
#include "log.h"
#include "pidref.h"
#include "process-util.h"
#include "runtime-scope.h"
#include "signal-util.h"
#include "strv.h"
#include "unit.h"
#include "unit-name.h"

static int start_and_wait_unit(
                sd_bus *bus,
                const char *method,
                const char *name,
                const char *mode,
                sd_bus_error *error,
                BusWaitForJobs *w) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *path;
        int r;

        assert(method);
        assert(name);
        assert(mode);
        assert(error);

        log_debug("%s dbus call org.freedesktop.systemd1.Manager %s(%s, %s)",
                  "Executing", method, name, mode);

        r = bus_call_method(bus, bus_systemd_mgr, method, error, &reply, "ss", name, mode);
        if (r < 0)
                return log_error_errno(r, "Failed to start %s: %s", name, bus_error_message(error, r));

        r = sd_bus_message_read(reply, "o", &path);
        if (r < 0)
                return bus_log_parse_error(r);
        if (w) {
                log_debug("Adding %s to the set", path);
                r = bus_wait_for_jobs_add(w, path);
                if (r < 0)
                        return log_error_errno(r, "Failed to watch job for %s: %m", name);
        }

        r = bus_wait_for_jobs_one(w, path, /* flags= */ BUS_WAIT_JOBS_LOG_ERROR, /* extra_args= */ NULL);
        if (r < 0)
                return r;

        return 0;
}

int verb_unit_gdb_start(int argc, char *argv[], void *userdata) {
        static const struct sigaction sa = {
                .sa_sigaction = sigterm_process_group_handler,
                .sa_flags = SA_SIGINFO,
        };

        _cleanup_free_ char *unit = NULL;
        int r;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot spawn a debugger for a remote service");

        r = unit_name_mangle_with_suffix(argv[1], "as unit", UNIT_NAME_MANGLE_WARN, ".service", &unit);
        if (r < 0)
                return log_error_errno(r, "Cannot mangle unit name: %m");

        if (!arg_debugger) {
                arg_debugger = strdup(secure_getenv("SYSTEMD_DEBUGGER") ?: "gdb");
                if (!arg_debugger)
                        return log_oom();
        }

        if (!STR_IN_SET(arg_debugger, "gdb", "lldb"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "The debugger must be either 'gdb' or 'lldb'");

        _cleanup_strv_free_ char **debugger_call = NULL;
        r = strv_extend(&debugger_call, arg_debugger);
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
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                int b;

                b = acquire_bus(&bus, /* use_full_bus= */ NULL);
                if (b < 0)
                        return bus_log_connect_error(b, arg_transport, arg_runtime_scope);

                b = sd_bus_message_new_method_call(bus, &reply, "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "SetUnitProperties");
                if (b < 0)
                        return log_error_errno(b, "Failed to create SetUnitProperties message: %m");

                b = sd_bus_message_append(reply, "sb", unit);
                if (b < 0)
                        return log_error_errno(b, "Failed to append unit name: %m");

                b = sd_bus_message_open_container(reply, 'a', "(sv)");
                if (b < 0)
                        return log_error_errno(b, "Failed to open properties container: %m");

                b = sd_bus_message_append(reply, "(sv)", "DebugWait", "b", true);
                if (b < 0)
                        return log_error_errno(b, "Failed to append append DebugWait: %m");

                b = sd_bus_message_close_container(reply);
                if (b < 0)
                        return log_error_errno(b, "Failed to close property container: %m");

                b = sd_bus_call(bus, reply, 0, &error, NULL);
                if (b < 0)
                        return log_error_errno(b, "Failed to set unit properties for %s: %s", unit, bus_error_message(&error, b));

                _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
                b = bus_wait_for_jobs_new(bus, &w);
                if (b < 0)
                        return log_error_errno(b, "Could not watch jobs: %m");

                b = start_and_wait_unit(bus, "RestartUnit", unit, "replace", &error, w);
                if (b < 0)
                        return log_error_errno(b, "Failed to  start and wait %s: %m", unit);

                pid_t pid;
                _cleanup_free_ char *object = unit_dbus_path_from_name(unit);
                if (!object)
                        return log_oom();

                b = sd_bus_get_property(
                                bus,
                                "org.freedesktop.systemd1",
                                object,
                                "org.freedesktop.systemd1.Service",
                                "MainPID",
                                &error,
                                &reply,
                                "u");
                if (b < 0)
                        return log_error_errno(b, "Failed to get the main PID of %s: %s", unit, bus_error_message(&error, b));

                b = sd_bus_message_read(reply, "u", &pid);
                if (b < 0)
                        return log_error_errno(b, "Failed to read the main PID of %s from reply: %m", unit);

                if (streq(arg_debugger, "gdb")) {
                        b = strv_extendf(&debugger_call, "--pid=" PID_FMT, pid);
                        if (b < 0)
                                return log_oom();

                        if (arg_root) {
                                _cleanup_free_ char *sysroot_cmd = strjoin("set sysroot ", arg_root);
                                b = strv_extend_many(&debugger_call, "-iex", sysroot_cmd);
                                if (b < 0)
                                        return log_oom();
                        }

                } else if (streq(arg_debugger, "lldb")) {
                        b = strv_extendf(&debugger_call, "--attach-pid=" PID_FMT, pid);
                        if (b < 0)
                                return log_oom();

                        if (arg_root) {
                                _cleanup_free_ char *sysroot_cmd = strjoin("platform select --sysroot ", arg_root, " host");
                                b = strv_extend_many(&debugger_call, "-O", sysroot_cmd);
                                if (b < 0)
                                        return log_oom();
                        }

                } else
                        assert_not_reached();

                (void) execvp(debugger_call[0], debugger_call);
                log_error_errno(errno, "Failed to invoke '%s': %m", debugger_call[0]);
                _exit(EXIT_FAILURE);
        }

        return pidref_wait_for_terminate_and_check(
                        debugger_call[0],
                        &pidref,
                        WAIT_LOG_ABNORMAL|WAIT_LOG_NON_ZERO_EXIT_STATUS);
}
