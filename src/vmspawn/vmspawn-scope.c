/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "escape.h"
#include "log.h"
#include "pidref.h"
#include "random-util.h"
#include "socket-util.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit-def.h"
#include "vmspawn-scope.h"

static int append_controller_property(sd_bus *bus, sd_bus_message *m) {
        const char *unique;
        int r;

        assert(bus);
        assert(m);

        r = sd_bus_get_unique_name(bus, &unique);
        if (r < 0)
                return log_error_errno(r, "Failed to get unique name: %m");

        r = sd_bus_message_append(m, "(sv)", "Controller", "s", unique);
        if (r < 0)
                return bus_log_create_error(r);

        return 0;
}

int allocate_scope(
                sd_bus *bus,
                const char *machine_name,
                const PidRef *pid,
                const char *slice,
                char **properties,
                bool allow_pidfd,
                char **ret_scope) {

        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL, *m = NULL;
        _cleanup_free_ char *scope = NULL, *description = NULL;
        const char *object;
        int r;

        assert(bus);
        assert(machine_name);

        /* Creates a transient scope unit which tracks the lifetime of the current process */

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch job: %m");

        r = unit_name_mangle_with_suffix(machine_name, "as machine name", /* flags= */ 0, ".scope", &scope);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle scope name: %m");

        description = strjoin("Virtual Machine ", machine_name);
        if (!description)
                return log_oom();

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "ss", /* name */ scope, /* mode */ "fail");
        if (r < 0)
                return bus_log_create_error(r);

        /* Properties */
        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = bus_append_scope_pidref(m, pid, allow_pidfd);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "(sv)(sv)(sv)(sv)",
                                  "Description", "s",  description,
                                  "CollectMode", "s",  "inactive-or-failed",
                                  "AddRef",      "b",  1,
                                  "Slice",       "s", isempty(slice) ? SPECIAL_MACHINE_SLICE : slice);
        if (r < 0)
                return bus_log_create_error(r);

        r = append_controller_property(bus, m);
        if (r < 0)
                return r;

        r = bus_append_unit_property_assignment_many(m, UNIT_SCOPE, properties);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        /* No auxiliary units */
        r = sd_bus_message_append(
                        m,
                        "a(sa(sv))",
                        0);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0) {
                /* If this failed with a property we couldn't write, this is quite likely because the server
                 * doesn't support PIDFDs yet, let's try without. */
                if (allow_pidfd &&
                    sd_bus_error_has_names(&error, SD_BUS_ERROR_UNKNOWN_PROPERTY, SD_BUS_ERROR_PROPERTY_READ_ONLY))
                        return allocate_scope(
                                        bus,
                                        machine_name,
                                        pid,
                                        slice,
                                        properties,
                                        /* allow_pidfd= */ false,
                                        ret_scope);

                return log_error_errno(r, "Failed to start transient scope unit: %s", bus_error_message(&error, r));
        }

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(
                        w,
                        object,
                        BUS_WAIT_JOBS_LOG_ERROR,
                        /* extra_args= */ NULL);
        if (r < 0)
                return r;

        if (ret_scope)
                *ret_scope = TAKE_PTR(scope);

        return 0;
}

int terminate_scope(
                sd_bus *bus,
                const char *machine_name) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *scope = NULL;
        int r;

        r = unit_name_mangle_with_suffix(machine_name, "to terminate", /* flags= */ 0, ".scope", &scope);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle scope name: %m");

        r = bus_call_method(bus, bus_systemd_mgr, "AbandonScope", &error, /* ret_reply= */ NULL, "s", scope);
        if (r < 0) {
                log_debug_errno(r, "Failed to abandon scope '%s', ignoring: %s", scope, bus_error_message(&error, r));
                sd_bus_error_free(&error);
        }

        r = bus_call_method(
                        bus,
                        bus_systemd_mgr,
                        "KillUnit",
                        &error,
                        NULL,
                        "ssi",
                        scope,
                        "all",
                        (int32_t) SIGKILL);
        if (r < 0) {
                log_debug_errno(r, "Failed to SIGKILL scope '%s', ignoring: %s", scope, bus_error_message(&error, r));
                sd_bus_error_free(&error);
        }

        r = bus_call_method(bus, bus_systemd_mgr, "UnrefUnit", &error, /* ret_reply= */ NULL, "s", scope);
        if (r < 0)
                log_debug_errno(r, "Failed to drop reference to scope '%s', ignoring: %s", scope, bus_error_message(&error, r));

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

void socket_service_pair_done(SocketServicePair *p) {
        assert(p);

        p->exec_start_pre = strv_free(p->exec_start_pre);
        p->exec_start = strv_free(p->exec_start);
        p->exec_stop_post = strv_free(p->exec_stop_post);
        p->unit_name_prefix = mfree(p->unit_name_prefix);
        p->listen_address = mfree(p->listen_address);
        p->socket_type = 0;
}

int start_socket_service_pair(sd_bus *bus, const char *scope, SocketServicePair *p) {
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_free_ char *service_desc = NULL, *service_name = NULL, *socket_name = NULL;
        const char *object, *socket_type_str;
        int r;

        /* Starts a socket/service unit pair bound to the given scope. */

        assert(bus);
        assert(scope);
        assert(p);
        assert(p->unit_name_prefix);
        assert(p->exec_start);
        assert(p->listen_address);

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch job: %m");

        socket_name = strjoin(p->unit_name_prefix, ".socket");
        if (!socket_name)
                return log_oom();

        service_name = strjoin(p->unit_name_prefix, ".service");
        if (!service_name)
                return log_oom();

        service_desc = quote_command_line(p->exec_start, SHELL_ESCAPE_EMPTY);
        if (!service_desc)
                return log_oom();

        socket_type_str = socket_address_type_to_string(p->socket_type);
        if (!socket_type_str)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Invalid socket type: %d", p->socket_type);

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "ssa(sv)",
                                  /* ss - name, mode */
                                  socket_name, "fail",
                                  /* a(sv) - Properties */
                                  5,
                                  "Description", "s",     p->listen_address,
                                  "AddRef",      "b",     true,
                                  "BindsTo",     "as",    1, scope,
                                  "Listen",      "a(ss)", 1, socket_type_str, p->listen_address,
                                  "CollectMode", "s",     "inactive-or-failed",
                                  "RemoveOnStop", "b",    true);
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

        if (p->exec_start_pre) {
                r = message_add_commands(m, "ExecStartPre", &p->exec_start_pre, 1);
                if (r < 0)
                        return r;
        }

        r = message_add_commands(m, "ExecStart", &p->exec_start, 1);
        if (r < 0)
                return r;

        if (p->exec_stop_post) {
                r = message_add_commands(m, "ExecStopPost", &p->exec_stop_post, 1);
                if (r < 0)
                        return r;
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
                return log_error_errno(r, "Failed to start %s as transient unit: %s", p->exec_start[0], bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        return bus_wait_for_jobs_one(w, object, /* quiet */ false, NULL);
}
