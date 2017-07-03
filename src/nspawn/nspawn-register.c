/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "nspawn-register.h"
#include "stat-util.h"
#include "strv.h"
#include "util.h"

static int append_machine_properties(
                sd_bus_message *m,
                CustomMount *mounts,
                unsigned n_mounts,
                int kill_signal,
                char **properties) {

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

        return 0;
}

int register_machine(
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
                bool keep_unit,
                const char *service) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to open system bus: %m");

        if (keep_unit) {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
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

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "CreateMachineWithNetwork");
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

                r = append_machine_properties(
                                m,
                                mounts,
                                n_mounts,
                                kill_signal,
                                properties);
                if (r < 0)
                        return r;

                r = bus_append_unit_property_assignment_many(m, properties);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, 0, &error, NULL);
        }

        if (r < 0) {
                log_error("Failed to register machine: %s", bus_error_message(&error, r));
                return r;
        }

        return 0;
}

int terminate_machine(pid_t pid) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        const char *path;
        int r;

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to open system bus: %m");

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        "GetMachineByPID",
                        &error,
                        &reply,
                        "u",
                        (uint32_t) pid);
        if (r < 0) {
                /* Note that the machine might already have been
                 * cleaned up automatically, hence don't consider it a
                 * failure if we cannot get the machine object. */
                log_debug("Failed to get machine: %s", bus_error_message(&error, r));
                return 0;
        }

        r = sd_bus_message_read(reply, "o", &path);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.machine1",
                        path,
                        "org.freedesktop.machine1.Machine",
                        "Terminate",
                        &error,
                        NULL,
                        NULL);
        if (r < 0) {
                log_debug("Failed to terminate machine: %s", bus_error_message(&error, r));
                return 0;
        }

        return 0;
}

int allocate_scope(
                const char *machine_name,
                pid_t pid,
                const char *slice,
                CustomMount *mounts,
                unsigned n_mounts,
                int kill_signal,
                char **properties) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *scope = NULL;
        const char *description, *object;
        int r;

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to open system bus: %m");

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch job: %m");

        r = unit_name_mangle_with_suffix(machine_name, UNIT_NAME_NOGLOB, ".scope", &scope);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle scope name: %m");

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
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

        r = sd_bus_message_append(m, "(sv)(sv)(sv)(sv)",
                                  "PIDs", "au", 1, pid,
                                  "Description", "s", description,
                                  "Delegate", "b", 1,
                                  "Slice", "s", isempty(slice) ? "machine.slice" : slice);
        if (r < 0)
                return bus_log_create_error(r);

        r = append_machine_properties(
                        m,
                        mounts,
                        n_mounts,
                        kill_signal,
                        properties);
        if (r < 0)
                return r;

        r = bus_append_unit_property_assignment_many(m, properties);
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
                log_error("Failed to allocate scope: %s", bus_error_message(&error, r));
                return r;
        }

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, false);
        if (r < 0)
                return r;

        return 0;
}
