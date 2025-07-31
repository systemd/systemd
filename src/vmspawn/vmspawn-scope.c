/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "event-util.h"
#include "log.h"
#include "pidref.h"
#include "special.h"
#include "string-util.h"
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
                sd_event_source **auxiliary,
                size_t n_auxiliary,
                const char *scope,
                const char *slice,
                char **properties,
                bool allow_pidfd) {

        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL, *m = NULL;
        _cleanup_free_ char *description = NULL;
        const char *object;
        int r;

        assert(bus);
        assert(machine_name);

        /* Creates a transient scope unit which tracks the lifetime of the current process */

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch job: %m");

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

        FOREACH_ARRAY(aux, auxiliary, n_auxiliary) {
                PidRef pidref;

                r = event_source_get_child_pidref(*aux, &pidref);
                if (r < 0)
                        return log_error_errno(r, "Could not get pidref for event source: %m");

                r = bus_append_scope_pidref(m, &pidref, allow_pidfd);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_append(m, "(sv)(sv)(sv)(sv)",
                                  "Description", "s", description,
                                  "CollectMode", "s", "inactive-or-failed",
                                  "AddRef",      "b", 1,
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
                                        auxiliary,
                                        n_auxiliary,
                                        scope,
                                        slice,
                                        properties,
                                        /* allow_pidfd= */ false);

                return log_error_errno(r, "Failed to start transient scope unit: %s", bus_error_message(&error, r));
        }

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        return bus_wait_for_jobs_one(
                        w,
                        object,
                        BUS_WAIT_JOBS_LOG_ERROR,
                        /* extra_args= */ NULL);
}

int terminate_scope(sd_bus *bus, const char *scope) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

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
