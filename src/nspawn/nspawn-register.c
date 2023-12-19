/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "nspawn-register.h"
#include "nspawn-settings.h"
#include "special.h"
#include "stat-util.h"
#include "strv.h"

static int append_machine_properties(
                sd_bus_message *m,
                CustomMount *mounts,
                unsigned n_mounts,
                int kill_signal,
                bool coredump_receive) {

        unsigned j;
        int r;

        assert(m);

        r = sd_bus_message_append(m, "(sv)", "DevicePolicy", "s", "closed");
        if (r < 0)
                return bus_log_create_error(r);

        /* If you make changes here, also make sure to update systemd-nspawn@.service, to keep the device policies in
         * sync regardless if we are run with or without the --keep-unit switch. */
        r = sd_bus_message_append(m, "(sv)", "DeviceAllow", "a(ss)", 2,
                                  /* Allow the container to
                                   * access and create the API
                                   * device nodes, so that
                                   * PrivateDevices= in the
                                   * container can work
                                   * fine */
                                  "/dev/net/tun", "rwm",
                                  /* Allow the container
                                   * access to ptys. However,
                                   * do not permit the
                                   * container to ever create
                                   * these device nodes. */
                                  "char-pts", "rw");
        if (r < 0)
                return bus_log_create_error(r);

        for (j = 0; j < n_mounts; j++) {
                CustomMount *cm = mounts + j;

                if (cm->type != CUSTOM_MOUNT_BIND)
                        continue;

                r = is_device_node(cm->source);
                if (r == -ENOENT) {
                        /* The bind source might only appear as the image is put together, hence don't complain */
                        log_debug_errno(r, "Bind mount source %s not found, ignoring: %m", cm->source);
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to stat %s: %m", cm->source);

                if (r) {
                        r = sd_bus_message_append(m, "(sv)", "DeviceAllow", "a(ss)", 1,
                                                  cm->source, cm->read_only ? "r" : "rw");
                        if (r < 0)
                                return log_error_errno(r, "Failed to append message arguments: %m");
                }
        }

        if (kill_signal != 0) {
                r = sd_bus_message_append(m, "(sv)", "KillSignal", "i", kill_signal);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "(sv)", "KillMode", "s", "mixed");
                if (r < 0)
                        return bus_log_create_error(r);
        }

        if (coredump_receive) {
                r = sd_bus_message_append(m, "(sv)", "CoredumpReceive", "b", true);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        return 0;
}

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

static int can_set_coredump_receive(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error e = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *path = NULL;
        int b, r;

        assert(bus);

        path = unit_dbus_path_from_name(SPECIAL_INIT_SCOPE);
        if (!path)
                return log_oom();

        r = sd_bus_get_property_trivial(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Scope",
                        "CoredumpReceive",
                        &e,
                        'b', &b);
        if (r < 0 && !sd_bus_error_has_names(&e, SD_BUS_ERROR_UNKNOWN_PROPERTY, SD_BUS_ERROR_PROPERTY_READ_ONLY))
                log_warning_errno(r, "Failed to determine if CoredumpReceive= can be set, assuming it cannot be: %s",
                                  bus_error_message(&e, r));

        return r >= 0;
}

int register_machine(
                sd_bus *bus,
                const char *machine_name,
                pid_t pid,
                const char *directory,
                sd_id128_t uuid,
                int local_ifindex,
                const char *slice,
                CustomMount *mounts,
                unsigned n_mounts,
                int kill_signal,
                char **properties,
                sd_bus_message *properties_message,
                bool keep_unit,
                const char *service,
                StartMode start_mode) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);

        if (keep_unit) {
                r = bus_call_method(
                                bus,
                                bus_machine_mgr,
                                "RegisterMachineWithNetwork",
                                &error,
                                NULL,
                                "sayssusai",
                                machine_name,
                                SD_BUS_MESSAGE_APPEND_ID128(uuid),
                                service,
                                "container",
                                (uint32_t) pid,
                                strempty(directory),
                                local_ifindex > 0 ? 1 : 0, local_ifindex);
        } else {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m,  bus_machine_mgr, "CreateMachineWithNetwork");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "sayssusai",
                                machine_name,
                                SD_BUS_MESSAGE_APPEND_ID128(uuid),
                                service,
                                "container",
                                (uint32_t) pid,
                                strempty(directory),
                                local_ifindex > 0 ? 1 : 0, local_ifindex);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'a', "(sv)");
                if (r < 0)
                        return bus_log_create_error(r);

                if (!isempty(slice)) {
                        r = sd_bus_message_append(m, "(sv)", "Slice", "s", slice);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                r = append_controller_property(bus, m);
                if (r < 0)
                        return r;

                r = append_machine_properties(
                                m,
                                mounts,
                                n_mounts,
                                kill_signal,
                                start_mode == START_BOOT && can_set_coredump_receive(bus) > 0);
                if (r < 0)
                        return r;

                if (properties_message) {
                        r = sd_bus_message_copy(m, properties_message, true);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                r = bus_append_unit_property_assignment_many(m, UNIT_SERVICE, properties);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, 0, &error, NULL);
        }
        if (r < 0)
                return log_error_errno(r, "Failed to register machine: %s", bus_error_message(&error, r));

        return 0;
}

int unregister_machine(
                sd_bus *bus,
                const char *machine_name) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);

        r = bus_call_method(bus, bus_machine_mgr, "UnregisterMachine", &error, NULL, "s", machine_name);
        if (r < 0)
                log_debug("Failed to unregister machine: %s", bus_error_message(&error, r));

        return 0;
}

int allocate_scope(
                sd_bus *bus,
                const char *machine_name,
                pid_t pid,
                const char *slice,
                CustomMount *mounts,
                unsigned n_mounts,
                int kill_signal,
                char **properties,
                sd_bus_message *properties_message,
                bool allow_pidfd,
                StartMode start_mode) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *scope = NULL;
        const char *description, *object;
        int r;

        assert(bus);

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch job: %m");

        r = unit_name_mangle_with_suffix(machine_name, "as machine name", 0, ".scope", &scope);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle scope name: %m");

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "ss", scope, "fail");
        if (r < 0)
                return bus_log_create_error(r);

        /* Properties */
        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        description = strjoina("Container ", machine_name);

        if (allow_pidfd) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                r = pidref_set_pid(&pidref, pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate PID reference: %m");

                r = bus_append_scope_pidref(m, &pidref);
        } else
                r = sd_bus_message_append(m, "(sv)", "PIDs", "au", 1, pid);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "(sv)(sv)(sv)(sv)(sv)",
                                  "Description", "s", description,
                                  "Delegate", "b", 1,
                                  "CollectMode", "s", "inactive-or-failed",
                                  "AddRef", "b", 1,
                                  "Slice", "s", isempty(slice) ? SPECIAL_MACHINE_SLICE : slice);
        if (r < 0)
                return bus_log_create_error(r);

        r = append_controller_property(bus, m);
        if (r < 0)
                return r;

        if (properties_message) {
                r = sd_bus_message_copy(m, properties_message, true);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = append_machine_properties(
                        m,
                        mounts,
                        n_mounts,
                        kill_signal,
                        start_mode == START_BOOT && can_set_coredump_receive(bus) > 0);
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
                        return allocate_scope(bus, machine_name, pid, slice, mounts, n_mounts, kill_signal, properties, properties_message, /* allow_pidfd= */ false, start_mode);

                return log_error_errno(r, "Failed to allocate scope: %s", bus_error_message(&error, r));
        }

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, BUS_WAIT_JOBS_LOG_ERROR, NULL);
        if (r < 0)
                return r;

        return 0;
}

int terminate_scope(
                sd_bus *bus,
                const char *machine_name) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *scope = NULL;
        int r;

        r = unit_name_mangle_with_suffix(machine_name, "to terminate", 0, ".scope", &scope);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle scope name: %m");

        r = bus_call_method(bus, bus_systemd_mgr, "AbandonScope", &error, NULL, "s", scope);
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

        r = bus_call_method(bus, bus_systemd_mgr, "UnrefUnit", &error, NULL, "s", scope);
        if (r < 0)
                log_debug_errno(r, "Failed to drop reference to scope '%s', ignoring: %s", scope, bus_error_message(&error, r));

        return 0;
}
