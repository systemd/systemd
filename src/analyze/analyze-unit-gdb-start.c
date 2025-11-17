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
#include "bus-map-properties.h"
#include "bus-wait-for-units.h"
#include "bus-wait-for-jobs.h"
#include "log.h"
#include "manager.h"
#include "pidref.h"
#include "process-util.h"
#include "runtime-scope.h"
#include "service.h"
#include "signal-util.h"
#include "strv.h"
#include "unit.h"
#include "unit-name.h"

static int is_exec_status_info_defined(
                sd_bus *bus _unused_,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error _unused_,
                void *userdata _unused_) {
        int r;

        assert(m);

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sasbttttuii)");
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_STRUCT, "sasbttttuii");
        if (r < 0)
                return bus_log_parse_error(r);

        if (r > 0 && STR_IN_SET(member, "ExecCondition", "ExecStartPre", "ExecStartPost", "ExecStopPost"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "'ExecCondition', 'ExecStartPre', 'ExecStartPost' 'ExecStopPost' are not allowed");

        r = sd_bus_message_skip(m, "sasbttttuii");
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
}

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

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        r = acquire_bus(&bus, /* use_full_bus= */ NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        _cleanup_free_ char *object = unit_dbus_path_from_name(unit);
        if (!object)
                return log_oom();

        r = sd_bus_get_property(
                        bus, "org.freedesktop.systemd1",
                        object, "org.freedesktop.systemd1.Service",
                        "Type", &error, &reply, "s");
        if (r < 0)
                return log_error_errno(r, "Failed to get the 'Type' of %s: %s", unit, bus_error_message(&error, r));

        const char *service_type;
        r = sd_bus_message_read(reply, "s", &service_type);
        if (r < 0)
                return log_error_errno(r, "Failed to read the service 'Type' of %s from reply: %m", unit);

        if (STR_IN_SET(service_type, "notify-reload", "oneshot"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Service type '%s' is not allowed", service_type);

        static const struct bus_properties_map exec_command_map[] = {
                { "ExecCondition",      "a(sasbttttuii)",       is_exec_status_info_defined,    0 },
                { "ExecStartPre",       "a(sasbttttuii)",       is_exec_status_info_defined,    0 },
                { "ExecStartPost",      "a(sasbttttuii)",       is_exec_status_info_defined,    0 },
                { "ExecStopPost",       "a(sasbttttuii)",       is_exec_status_info_defined,    0 },
                {}
        };

        _cleanup_(exec_command_freep) ExecCommand *c = new(ExecCommand, 1);
        if (!c)
                return log_oom();

        r = bus_map_all_properties(
                        bus,
                        "org.freedesktop.systemd1",
                        object,
                        exec_command_map,
                        BUS_MAP_BOOLEAN_AS_BOOL,
                        &error,
                        &reply,
                        &c);
        if (r < 0)
                return log_error_errno(r, "Failed to get properties: %s", bus_error_message(&error, r));

        r = sd_bus_message_new_method_call(
                        bus, &reply,
                        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager", "SetUnitProperties");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(reply, "sba(sv)", unit, true, 1, "DebugWait", "b", true);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, reply, 0, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to set unit properties for %s: %s", unit, bus_error_message(&error, r));

        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch jobs: %m");

        r = start_and_wait_unit(bus, "RestartUnit", unit, "replace", &error, w);
        if (r < 0)
                return log_error_errno(r, "Failed to  start and wait %s: %m", unit);

        pid_t pid;
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

        r = sd_bus_message_read(reply, "u", &pid);
        if (r < 0)
                return log_error_errno(r, "Failed to read the main PID of %s from reply: %m", unit);

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

        /* Don't interfere with debugger and its handling of SIGINT. */
        (void) ignore_signals(SIGINT);
        (void) sigaction(SIGTERM, &sa, NULL);

        _cleanup_free_ char *fork_name = strjoin("(", debugger_call[0], ")");
        if (!fork_name)
                return log_oom();

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork(fork_name, FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_LOG, &pidref);
        if (r < 0)
                return r;

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
