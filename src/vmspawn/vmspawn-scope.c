/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "macro-fundamental.h"
#include "macro.h"
#include "process-util.h"
#include "random-util.h"
#include "strv.h"
#include "unit-def.h"
#include "unit-name.h"
#include "vmspawn-scope.h"

int start_transient_scope(sd_bus *bus, const char *machine_name, char **ret_scope) {
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *unmangled = NULL, *scope = NULL, *description = NULL;
        const char *object;
        int r;

        /* Creates a transient scope unit which tracks the lifetime of the current process */

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch job: %m");

        if (asprintf(&unmangled, "sd-vmspawn-%"PRIu32"-%s", random_u32(), machine_name) < 0)
                return log_oom();

        r = unit_name_mangle_with_suffix(unmangled, "as scope name", 0, ".scope", &scope);
        if (r < 0)
                return r;

        description = strjoin("Virtual Machine ", machine_name);
        if (!description)
                return log_oom();

        r = bus_call_method(bus, bus_systemd_mgr, "StartTransientUnit", &error, &reply,
                            "ssa(sv)a(sa(sv))",
                            /* ss - name, mode */
                            scope, "fail",
                            /* a(sv) - properties */
                            3,
                            "Description", "s",  description,
                            "AddRef",      "b",  1,
                            "PIDs",        "au", 1, getpid_cached(),
                            /* a(sa(sv)) - aux (empty) */
                            0);
        if (r < 0)
                return log_error_errno(r, "Failed to start transient scope unit: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, /* quiet */ false, NULL);
        if (r < 0)
                return r;

        if (ret_scope)
                *ret_scope = TAKE_PTR(scope);

        return 0;
}

static int message_add_commands(sd_bus_message *m, const char *exec_type, char ***commands, size_t n_commands) {
        int r;

        assert(m);
        assert(exec_type);
        assert(commands || n_commands == 0);

        /* A small helper for adding an ExecStart / ExecStopPost / etc.. property to an sd_bus_message */

        r = sd_bus_message_open_container(m, 'r', "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", exec_type);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', "a(sasb)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(sasb)");
        if (r < 0)
                return bus_log_create_error(r);

        FOREACH_ARRAY(cmd, commands, n_commands) {
                char **cmdline = *cmd;

                r = sd_bus_message_open_container(m, 'r', "sasb");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", cmdline[0]);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_strv(m, cmdline);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "b", 0);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return 0;
}

/* NOTE: this function should really take cmdline as `const char * const *` but cannot until sd_bus_message_append_str does as well */
int run_command_bound_to_scope(sd_bus *bus, const char *scope, const char *service_name, char **cmdline,
                               char **cleanup_cmdline, char **extra_properties) {
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_free_ char *description = NULL, *unit_name = NULL;
        const char *object;
        int r;

        /*
         * Runs a command in transient service unit bound to the given scope.
         *
         * `cmdline` is forwarded to the unit's ExecStart property.
         * `cleanup_cmdline` is forwarded to the unit's ExecStopPost property.
         *
         * `extra_properties` is used to set any extra properties this unit should have.
         * The format is the same as in unit files, e.g. Requires=other-unit.socket
         */

        assert(bus);
        assert(service_name);
        assert(scope);
        assert(cmdline);

        r = unit_name_mangle_with_suffix(service_name, "as service", 0, ".service", &unit_name);
        if (r < 0)
                return r;

        description = strv_join(cmdline, " ");
        if (!description)
                return log_oom();

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch job: %m");

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "ss", unit_name, "fail");
        if (r < 0)
                return bus_log_create_error(r);

        /* Properties */
        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "(sv)(sv)(sv)(sv)",
                                  "Description", "s", description,
                                  "AddRef", "b", 1,
                                  "BindsTo", "as", 1, scope,
                                  "CollectMode", "s",     "inactive-or-failed");
        if (r < 0)
                return bus_log_create_error(r);

        r = message_add_commands(m, "ExecStart", &cmdline, 1);
        if (r < 0)
                return r;

        if (cleanup_cmdline) {
                r = message_add_commands(m, "ExecStopPost", &cleanup_cmdline, 1);
                if (r < 0)
                        return r;
        }

        if (extra_properties) {
                r = bus_append_unit_property_assignment_many(m, UNIT_SERVICE, extra_properties);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        /* Empty aux */
        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to start %s as transient unit: %s", cmdline[0], bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, /* quiet */ false, NULL);
        if (r < 0)
                return r;

        return 0;
}

/* NOTE: this function should really take cmdline as `const char * const *` but cannot until sd_bus_message_append_str does as well */
int attach_command_to_socket_in_scope(sd_bus *bus, const char *scope, const char *unit_name, const char *socket_path,
                                      int socket_type, char **cmdline, char **cleanup_cmdline, char **extra_properties) {
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_free_ char *service_desc = NULL, *service_name = NULL, *socket_name = NULL, *socket_desc = NULL;
        const char *object, *socket_type_str;
        int r;

        /*
         * Starts a socket/service unit pair bound to the given scope.
         *
         * The socket unit listens on `socket_path` with the for connections of type `socket_type`.
         * When a connection to the socket is initiated the service is started to and passed the socket's file descriptor as fd 3.
         *
         * `cmdline` is forwarded to the service unit's ExecStart property.
         * `cleanup_cmdline` is forwarded to the service unit's ExecStopPost property.
         *
         * `extra_properties` is used to set any extra properties this service unit should have.
         * The format is the same as in unit files, e.g. Requires=other-unit.socket
         */

        assert(bus);
        assert(scope);
        assert(unit_name);
        assert(socket_path);
        assert(cmdline);
        assert_return(IN_SET(socket_type, SOCK_STREAM, SOCK_SEQPACKET, SOCK_DGRAM), -EOPNOTSUPP);

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch job: %m");

        r = unit_name_mangle_with_suffix(unit_name, "as socket", 0, ".socket", &socket_name);
        if (r < 0)
                return r;

        r = unit_name_change_suffix(socket_name, ".service", &service_name);
        if (r < 0)
                return r;

        service_desc = strv_join(cmdline, " ");
        if (!service_desc)
                return log_oom();

        socket_desc = strjoin("socket: ", socket_path);
        if (!socket_desc)
                return log_oom();

        switch (socket_type) {
        case SOCK_STREAM:
                socket_type_str = "Stream";
                break;
        case SOCK_DGRAM:
                socket_type_str = "Datagram";
                break;
        case SOCK_SEQPACKET:
                socket_type_str = "SequentialPacket";
                break;
        default:
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Invalid socket type: %d", socket_type);
        }

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "ssa(sv)",
                                  /* ss - name, mode */
                                  socket_name, "fail",
                                  /* a(sv) - Properties */
                                  5,
                                  "Description", "s",     socket_desc,
                                  "AddRef",      "b",     1,
                                  "BindsTo",     "as",    1, scope,
                                  "Listen",      "a(ss)", 1, socket_type_str, socket_path,
                                  "CollectMode", "s",     "inactive-or-failed");
        if (r < 0)
                return bus_log_create_error(r);

        /* aux */
        r = sd_bus_message_open_container(m, 'a', "(sa(sv))");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'r', "sa(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", service_name);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "(sv)(sv)(sv)(sv)",
                                  "Description", "s",  service_desc,
                                  "AddRef",      "b",  1,
                                  "BindsTo",     "as", 1, scope,
                                  "CollectMode", "s",  "inactive-or-failed");
        if (r < 0)
                return bus_log_create_error(r);

        r = message_add_commands(m, "ExecStart", &cmdline, 1);
        if (r < 0)
                return r;

        if (cleanup_cmdline) {
                r = message_add_commands(m, "ExecStopPost", &cleanup_cmdline, 1);
                if (r < 0)
                        return r;
        }

        if (extra_properties) {
                r = bus_append_unit_property_assignment_many(m, UNIT_SERVICE, extra_properties);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to start %s as transient unit: %s", cmdline[0], bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, /* quiet */ false, NULL);
        if (r < 0)
                return r;

        return 0;
}
