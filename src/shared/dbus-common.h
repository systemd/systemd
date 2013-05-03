/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <dbus/dbus.h>
#include <inttypes.h>
#include <sys/types.h>

#include "macro.h"

#ifndef DBUS_ERROR_UNKNOWN_OBJECT
#define DBUS_ERROR_UNKNOWN_OBJECT "org.freedesktop.DBus.Error.UnknownObject"
#endif

#ifndef DBUS_ERROR_UNKNOWN_INTERFACE
#define DBUS_ERROR_UNKNOWN_INTERFACE "org.freedesktop.DBus.Error.UnknownInterface"
#endif

#ifndef DBUS_ERROR_UNKNOWN_PROPERTY
#define DBUS_ERROR_UNKNOWN_PROPERTY "org.freedesktop.DBus.Error.UnknownProperty"
#endif

#ifndef DBUS_ERROR_PROPERTY_READ_ONLY
#define DBUS_ERROR_PROPERTY_READ_ONLY "org.freedesktop.DBus.Error.PropertyReadOnly"
#endif

#define BUS_PROPERTIES_INTERFACE                                        \
        " <interface name=\"org.freedesktop.DBus.Properties\">\n"       \
        "  <method name=\"Get\">\n"                                     \
        "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"    \
        "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"     \
        "   <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"       \
        "  </method>\n"                                                 \
        "  <method name=\"GetAll\">\n"                                  \
        "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"    \
        "   <arg name=\"properties\" direction=\"out\" type=\"a{sv}\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"Set\">\n"                                     \
        "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"    \
        "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"     \
        "   <arg name=\"value\" direction=\"in\" type=\"v\"/>\n"        \
        "  </method>\n"                                                 \
        "  <signal name=\"PropertiesChanged\">\n"                       \
        "   <arg type=\"s\" name=\"interface\"/>\n"                     \
        "   <arg type=\"a{sv}\" name=\"changed_properties\"/>\n"        \
        "   <arg type=\"as\" name=\"invalidated_properties\"/>\n"       \
        "  </signal>\n"                                                 \
        " </interface>\n"

#define BUS_INTROSPECTABLE_INTERFACE                                    \
        " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"   \
        "  <method name=\"Introspect\">\n"                              \
        "   <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"        \
        "  </method>\n"                                                 \
        " </interface>\n"

#define BUS_PEER_INTERFACE                                              \
        "<interface name=\"org.freedesktop.DBus.Peer\">\n"              \
        " <method name=\"Ping\"/>\n"                                    \
        " <method name=\"GetMachineId\">\n"                             \
        "  <arg type=\"s\" name=\"machine_uuid\" direction=\"out\"/>\n" \
        " </method>\n"                                                  \
        "</interface>\n"

#define BUS_GENERIC_INTERFACES_LIST             \
        "org.freedesktop.DBus.Properties\0"     \
        "org.freedesktop.DBus.Introspectable\0" \
        "org.freedesktop.DBus.Peer\0"

int bus_check_peercred(DBusConnection *c);

int bus_connect(DBusBusType t, DBusConnection **_bus, bool *private_bus, DBusError *error);

int bus_connect_system_ssh(const char *user, const char *host, DBusConnection **_bus, DBusError *error);
int bus_connect_system_polkit(DBusConnection **_bus, DBusError *error);

const char *bus_error_message(const DBusError *error);
const char *bus_error(const DBusError *e, int r);

typedef int (*BusPropertyCallback)(DBusMessageIter *iter, const char *property, void *data);
typedef int (*BusPropertySetCallback)(DBusMessageIter *iter, const char *property, void *data);

typedef struct BusProperty {
        const char *property;            /* name of the property */
        BusPropertyCallback append;      /* Function that is called to serialize this property */
        const char *signature;
        const uint16_t offset;           /* Offset from BusBoundProperties::base address to the property data.
                                          * uint16_t is sufficient, because we have no structs too big.
                                          * -Werror=overflow will catch it if this does not hold. */
        bool indirect;                   /* data is indirect, ie. not base+offset, but *(base+offset) */
        BusPropertySetCallback set;      /* Optional: Function that is called to set this property */
} BusProperty;

typedef struct BusBoundProperties {
        const char *interface;           /* interface of the properties */
        const BusProperty *properties;   /* array of properties, ended by a NULL-filled element */
        const void *const base;          /* base pointer to which the offset must be added to reach data */
} BusBoundProperties;

dbus_bool_t bus_maybe_send_reply (DBusConnection   *c,
                                  DBusMessage *message,
                                  DBusMessage *reply);

DBusHandlerResult bus_send_error_reply(
                DBusConnection *c,
                DBusMessage *message,
                DBusError *bus_error,
                int error);

DBusHandlerResult bus_default_message_handler(
                DBusConnection *c,
                DBusMessage *message,
                const char *introspection,
                const char *interfaces,
                const BusBoundProperties *bound_properties);

int bus_property_append_string(DBusMessageIter *i, const char *property, void *data);
int bus_property_append_strv(DBusMessageIter *i, const char *property, void *data);
int bus_property_append_bool(DBusMessageIter *i, const char *property, void *data);
int bus_property_append_tristate_false(DBusMessageIter *i, const char *property, void *data);
int bus_property_append_int32(DBusMessageIter *i, const char *property, void *data);
int bus_property_append_uint32(DBusMessageIter *i, const char *property, void *data);
int bus_property_append_uint64(DBusMessageIter *i, const char *property, void *data);
int bus_property_append_size(DBusMessageIter *i, const char *property, void *data);
int bus_property_append_ul(DBusMessageIter *i, const char *property, void *data);
int bus_property_append_long(DBusMessageIter *i, const char *property, void *data);

#define bus_property_append_int bus_property_append_int32
#define bus_property_append_pid bus_property_append_uint32
#define bus_property_append_uid bus_property_append_uint32
#define bus_property_append_gid bus_property_append_uint32
#define bus_property_append_mode bus_property_append_uint32
#define bus_property_append_unsigned bus_property_append_uint32
#define bus_property_append_usec bus_property_append_uint64

int bus_property_set_uint64(DBusMessageIter *i, const char *property, void *data);
#define bus_property_set_usec bus_property_set_uint64

#define DEFINE_BUS_PROPERTY_APPEND_ENUM(function,name,type)             \
        int function(DBusMessageIter *i, const char *property, void *data) { \
                const char *value;                                      \
                type *field = data;                                     \
                                                                        \
                assert(i);                                              \
                assert(property);                                       \
                                                                        \
                value = strempty(name##_to_string(*field));             \
                                                                        \
                if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &value)) \
                        return -ENOMEM;                                 \
                                                                        \
                return 0;                                               \
        }

#define DEFINE_BUS_PROPERTY_SET_ENUM(function,name,type)                \
        int function(DBusMessageIter *i, const char *property, void *data) { \
                const char *value;                                      \
                type f, *field = data;                                  \
                                                                        \
                assert(i);                                              \
                assert(property);                                       \
                                                                        \
                dbus_message_iter_get_basic(i, &value);                 \
                                                                        \
                f = name##_from_string(value);                          \
                if (f < 0)                                              \
                        return f;                                       \
                                                                        \
                *field = f;                                             \
                return 0;                                               \
        }

const char *bus_errno_to_dbus(int error) _const_;

DBusMessage* bus_properties_changed_new(const char *path, const char *interface, const char *properties);
DBusMessage* bus_properties_changed_one_new(const char *path, const char *interface, const char *property);

uint32_t bus_flags_to_events(DBusWatch *bus_watch) _pure_;
unsigned bus_events_to_flags(uint32_t events) _const_;

int bus_parse_strv(DBusMessage *m, char ***_l);
int bus_parse_strv_iter(DBusMessageIter *iter, char ***_l);
int bus_parse_strv_pairs_iter(DBusMessageIter *iter, char ***_l);

struct unit_info {
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
};

int bus_parse_unit_info(DBusMessageIter *iter, struct unit_info *u);

int bus_append_strv_iter(DBusMessageIter *iter, char **l);

int bus_iter_get_basic_and_next(DBusMessageIter *iter, int type, void *data, bool next);

int generic_print_property(const char *name, DBusMessageIter *iter, bool all);

void bus_async_unregister_and_exit(DBusConnection *bus, const char *name);

DBusHandlerResult bus_exit_idle_filter(DBusConnection *bus, DBusMessage *m, void *userdata);

pid_t bus_get_unix_process_id(DBusConnection *connection, const char *name, DBusError *error);

bool bus_error_is_no_service(const DBusError *error);
int bus_method_call_with_reply(DBusConnection *bus,
                               const char *destination,
                               const char *path,
                               const char *interface,
                               const char *method,
                               DBusMessage **return_reply,
                               DBusError *return_error,
                               int first_arg_type, ...);

const char *bus_message_get_sender_with_fallback(DBusMessage *m);

void bus_message_unrefp(DBusMessage **reply);

#define _cleanup_dbus_message_unref_ __attribute__((cleanup(bus_message_unrefp)))
#define _cleanup_dbus_error_free_ __attribute__((cleanup(dbus_error_free)))
