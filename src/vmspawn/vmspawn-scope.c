/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "log.h"
#include "pidref.h"
#include "random-util.h"
#include "string-util.h"
#include "vmspawn-scope.h"

int start_transient_scope(sd_bus *bus, const char *machine_name, bool allow_pidfd, char **ret_scope) {
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

        if (asprintf(&scope, "machine-%"PRIu64"-%s.scope", random_u64(), machine_name) < 0)
                return log_oom();

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

        r = sd_bus_message_append(m, "(sv)(sv)(sv)",
                                  "Description", "s",  description,
                                  "AddRef",      "b",  1,
                                  "CollectMode", "s",  "inactive-or-failed");
        if (r < 0)
                return bus_log_create_error(r);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_set_self(&pidref);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate PID reference: %m");

        r = bus_append_scope_pidref(m, &pidref, allow_pidfd);
        if (r < 0)
                return bus_log_create_error(r);

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
                        return start_transient_scope(bus, machine_name, false, ret_scope);

                return log_error_errno(r, "Failed to start transient scope unit: %s", bus_error_message(&error, r));
        }

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
