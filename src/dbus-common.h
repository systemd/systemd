/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foodbuscommonhfoo
#define foodbuscommonhfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <dbus/dbus.h>

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

typedef int (*BusPropertyCallback)(DBusMessageIter *iter, const char *property, void *data);
typedef int (*BusPropertySetCallback)(DBusMessageIter *iter, const char *property);

typedef struct BusProperty {
        const char *interface;           /* interface of the property */
        const char *property;            /* name of the property */
        BusPropertyCallback append;      /* Function that is called to serialize this property */
        const char *signature;
        const void *data;                /* The data of this property */
        BusPropertySetCallback set;      /* Optional: Function that is called to set this property */
} BusProperty;

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
                const BusProperty *properties);

int bus_property_append_string(DBusMessageIter *i, const char *property, void *data);
int bus_property_append_strv(DBusMessageIter *i, const char *property, void *data);
int bus_property_append_bool(DBusMessageIter *i, const char *property, void *data);
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

#define DEFINE_BUS_PROPERTY_APPEND_ENUM(function,name,type)             \
        int function(DBusMessageIter *i, const char *property, void *data) { \
                const char *value;                                      \
                type *field = data;                                     \
                                                                        \
                assert(i);                                              \
                assert(property);                                       \
                                                                        \
                value = name##_to_string(*field);                       \
                                                                        \
                if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &value)) \
                        return -ENOMEM;                                 \
                                                                        \
                return 0;                                               \
        }

const char *bus_errno_to_dbus(int error);

DBusMessage* bus_properties_changed_new(const char *path, const char *interface, const char *properties);

uint32_t bus_flags_to_events(DBusWatch *bus_watch);
unsigned bus_events_to_flags(uint32_t events);

int bus_parse_strv(DBusMessage *m, char ***_l);
int bus_parse_strv_iter(DBusMessageIter *iter, char ***_l);

#endif
