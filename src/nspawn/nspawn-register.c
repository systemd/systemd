/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
#include "bus-util.h"
#include "nspawn-register.h"
#include "stat-util.h"
#include "strv.h"
#include "util.h"

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

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
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
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
                char **i;
                unsigned j;

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

                r = sd_bus_message_append(m, "(sv)", "TasksMax", "t", 8192);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "(sv)", "DevicePolicy", "s", "strict");
                if (r < 0)
                        return bus_log_create_error(r);

                /* If you make changes here, also make sure to update
                 * systemd-nspawn@.service, to keep the device
                 * policies in sync regardless if we are run with or
                 * without the --keep-unit switch. */
                r = sd_bus_message_append(m, "(sv)", "DeviceAllow", "a(ss)", 9,
                                          /* Allow the container to
                                           * access and create the API
                                           * device nodes, so that
                                           * PrivateDevices= in the
                                           * container can work
                                           * fine */
                                          "/dev/null", "rwm",
                                          "/dev/zero", "rwm",
                                          "/dev/full", "rwm",
                                          "/dev/random", "rwm",
                                          "/dev/urandom", "rwm",
                                          "/dev/tty", "rwm",
                                          "/dev/net/tun", "rwm",
                                          /* Allow the container
                                           * access to ptys. However,
                                           * do not permit the
                                           * container to ever create
                                           * these device nodes. */
                                          "/dev/pts/ptmx", "rw",
                                          "char-pts", "rw");
                if (r < 0)
                        return bus_log_create_error(r);

                for (j = 0; j < n_mounts; j++) {
                        CustomMount *cm = mounts + j;

                        if (cm->type != CUSTOM_MOUNT_BIND)
                                continue;

                        r = is_device_node(cm->source);
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

                STRV_FOREACH(i, properties) {
                        r = sd_bus_message_open_container(m, 'r', "sv");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = bus_append_unit_property_assignment(m, *i);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_close_container(m);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

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
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
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
