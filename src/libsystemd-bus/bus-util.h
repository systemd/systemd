/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include "sd-event.h"
#include "sd-bus.h"
#include "hashmap.h"
#include "time-util.h"
#include "util.h"

typedef enum BusTransport {
        BUS_TRANSPORT_LOCAL,
        BUS_TRANSPORT_REMOTE,
        BUS_TRANSPORT_CONTAINER,
        _BUS_TRANSPORT_MAX,
        _BUS_TRANSPORT_INVALID = -1
} BusTransport;

typedef int (*bus_property_set_t) (sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata);

struct bus_properties_map {
        const char *member;
        const char *signature;
        bus_property_set_t set;
        size_t offset;
};

int bus_map_id128(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata);

int bus_map_all_properties(sd_bus *bus,
                           const char *destination,
                           const char *path,
                           const struct bus_properties_map *map,
                           void *userdata);

int bus_async_unregister_and_quit(sd_event *e, sd_bus *bus, const char *name);

int bus_event_loop_with_idle(sd_event *e, sd_bus *bus, const char *name, usec_t timeout);
int bus_property_get_tristate(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, sd_bus_error *error, void *userdata);

int bus_verify_polkit(sd_bus *bus, sd_bus_message *m, const char *action, bool interactive, bool *_challenge, sd_bus_error *e);

int bus_verify_polkit_async(sd_bus *bus, Hashmap **registry, sd_bus_message *m, const char *action, bool interactive, sd_bus_error *error, sd_bus_message_handler_t callback, void *userdata);
void bus_verify_polkit_async_registry_free(sd_bus *bus, Hashmap *registry);

int bus_open_system_systemd(sd_bus **_bus);
int bus_open_user_systemd(sd_bus **_bus);

int bus_open_transport(BusTransport transport, const char *host, bool user, sd_bus **bus);
int bus_open_transport_systemd(BusTransport transport, const char *host, bool user, sd_bus **bus);

int bus_print_property(const char *name, sd_bus_message *property, bool all);
int bus_print_all_properties(sd_bus *bus, const char *dest, const char *path, char **filter, bool all);

int bus_property_get_bool(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, sd_bus_error *error, void *userdata);
int bus_property_get_uid(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, sd_bus_error *error, void *userdata);

#define bus_property_get_gid bus_property_get_uid
#define bus_property_get_pid bus_property_get_uid

int bus_log_parse_error(int r);
int bus_log_create_error(int r);

typedef struct UnitInfo {
        const char *id;
        const char *description;
        const char *load_state;
        const char *active_state;
        const char *sub_state;
        const char *following;
        const char *unit_path;
        uint32_t job_id;
        const char *job_type;
        const char *job_path;
} UnitInfo;

int bus_parse_unit_info(sd_bus_message *message, UnitInfo *u);

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_bus*, sd_bus_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_bus_message*, sd_bus_message_unref);

#define _cleanup_bus_unref_ _cleanup_(sd_bus_unrefp)
#define _cleanup_bus_message_unref_ _cleanup_(sd_bus_message_unrefp)
#define _cleanup_bus_error_free_ _cleanup_(sd_bus_error_free)

#define BUS_DEFINE_PROPERTY_GET_ENUM(function, name, type)              \
        int function(sd_bus *bus,                                       \
                     const char *path,                                  \
                     const char *interface,                             \
                     const char *property,                              \
                     sd_bus_message *reply,                             \
                     sd_bus_error *error,                               \
                     void *userdata) {                                  \
                                                                        \
                const char *value;                                      \
                type *field = userdata;                                 \
                int r;                                                  \
                                                                        \
                assert(bus);                                            \
                assert(reply);                                          \
                assert(field);                                          \
                                                                        \
                value = strempty(name##_to_string(*field));             \
                                                                        \
                r = sd_bus_message_append_basic(reply, 's', value);     \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                return 1;                                               \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

#define BUS_ERROR_NO_SUCH_UNIT "org.freedesktop.systemd1.NoSuchUnit"
#define BUS_ERROR_LOAD_FAILED "org.freedesktop.systemd1.LoadFailed"
#define BUS_ERROR_JOB_FAILED "org.freedesktop.systemd1.JobFailed"

#define BUS_ERROR_NO_SUCH_MACHINE "org.freedesktop.machine1.NoSuchMachine"
#define BUS_ERROR_NO_MACHINE_FOR_PID "org.freedesktop.machine1.NoMachineForPID"
#define BUS_ERROR_MACHINE_EXISTS "org.freedesktop.machine1.MachineExists"

#define BUS_ERROR_NO_SUCH_SESSION "org.freedesktop.login1.NoSuchSession"
#define BUS_ERROR_NO_SESSION_FOR_PID "org.freedesktop.login1.NoSessionForPID"
#define BUS_ERROR_NO_SUCH_USER "org.freedesktop.login1.NoSuchUser"
#define BUS_ERROR_NO_USER_FOR_PID "org.freedesktop.login1.NoUserForPID"
#define BUS_ERROR_NO_SUCH_SEAT "org.freedesktop.login1.NoSuchSeat"
#define BUS_ERROR_SESSION_NOT_ON_SEAT "org.freedesktop.login1.SessionNotOnSeat"
#define BUS_ERROR_NOT_IN_CONTROL "org.freedesktop.login1.NotInControl"
#define BUS_ERROR_DEVICE_IS_TAKEN "org.freedesktop.login1.DeviceIsTaken"
#define BUS_ERROR_DEVICE_NOT_TAKEN "org.freedesktop.login1.DeviceNotTaken"
#define BUS_ERROR_OPERATION_IN_PROGRESS "org.freedesktop.login1.OperationInProgress"
#define BUS_ERROR_SLEEP_VERB_NOT_SUPPORTED "org.freedesktop.login1.SleepVerbNotSupported"
