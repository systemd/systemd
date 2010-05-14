/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foodbusunithfoo
#define foodbusunithfoo

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

#include "manager.h"

#define BUS_UNIT_INTERFACE \
        " <interface name=\"org.freedesktop.systemd1.Unit\">"           \
        "  <method name=\"Start\">"                                     \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>"           \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>"           \
        "  </method>"                                                   \
        "  <method name=\"Stop\">"                                      \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>"           \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>"           \
        "  </method>"                                                   \
        "  <method name=\"Restart\">"                                   \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>"           \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>"           \
        "  </method>"                                                   \
        "  <method name=\"Reload\">"                                    \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>"           \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>"           \
        "  </method>"                                                   \
        "  <signal name=\"Changed\"/>"                                  \
        "  <property name=\"Id\" type=\"s\" access=\"read\"/>"          \
        "  <property name=\"Names\" type=\"as\" access=\"read\"/>"      \
        "  <property name=\"Description\" type=\"s\" access=\"read\"/>" \
        "  <property name=\"LoadState\" type=\"s\" access=\"read\"/>"   \
        "  <property name=\"ActiveState\" type=\"s\" access=\"read\"/>" \
        "  <property name=\"SubState\" type=\"s\" access=\"read\"/>"    \
        "  <property name=\"FragmentPath\" type=\"s\" access=\"read\"/>" \
        "  <property name=\"InactiveExitTimestamp\" type=\"t\" access=\"read\"/>" \
        "  <property name=\"ActiveEnterTimestamp\" type=\"t\" access=\"read\"/>" \
        "  <property name=\"ActiveExitTimestamp\" type=\"t\" access=\"read\"/>" \
        "  <property name=\"InactiveEnterTimestamp\" type=\"t\" access=\"read\"/>" \
        "  <property name=\"CanReload\" type=\"b\" access=\"read\"/>"   \
        "  <property name=\"CanStart\" type=\"b\" access=\"read\"/>"    \
        "  <property name=\"Job\" type=\"(uo)\" access=\"read\"/>"      \
        "  <property name=\"RecursiveStop\" type=\"b\" access=\"read\"/>" \
        "  <property name=\"StopWhenUneeded\" type=\"b\" access=\"read\"/>" \
        "  <property name=\"DefaultControlGroup\" type=\"s\" access=\"read\"/>" \
        "  <property name=\"ControlGroups\" type=\"as\" access=\"read\"/>" \
        " </interface>"

#define BUS_UNIT_PROPERTIES \
        { "org.freedesktop.systemd1.Unit", "Id",                   bus_property_append_string,     "s",    u->meta.id                      }, \
        { "org.freedesktop.systemd1.Unit", "Names",                bus_unit_append_names,          "as",   u                               }, \
        { "org.freedesktop.systemd1.Unit", "Description",          bus_unit_append_description,    "s",    u                               }, \
        { "org.freedesktop.systemd1.Unit", "LoadState",            bus_unit_append_load_state,     "s",    &u->meta.load_state             }, \
        { "org.freedesktop.systemd1.Unit", "ActiveState",          bus_unit_append_active_state,   "s",    u                               }, \
        { "org.freedesktop.systemd1.Unit", "SubState",             bus_unit_append_sub_state,      "s",    u                               }, \
        { "org.freedesktop.systemd1.Unit", "FragmentPath",         bus_property_append_string,     "s",    u->meta.fragment_path           }, \
        { "org.freedesktop.systemd1.Unit", "InactiveExitTimestamp",bus_property_append_uint64,     "t",    &u->meta.inactive_exit_timestamp}, \
        { "org.freedesktop.systemd1.Unit", "ActiveEnterTimestamp", bus_property_append_uint64,     "t",    &u->meta.active_enter_timestamp }, \
        { "org.freedesktop.systemd1.Unit", "ActiveExitTimestamp",  bus_property_append_uint64,     "t",    &u->meta.active_exit_timestamp  }, \
        { "org.freedesktop.systemd1.Unit", "InActiveEnterTimestamp",bus_property_append_uint64,    "t",    &u->meta.inactive_enter_timestamp}, \
        { "org.freedesktop.systemd1.Unit", "CanStart",             bus_unit_append_can_start,      "b",    u                               }, \
        { "org.freedesktop.systemd1.Unit", "CanReload",            bus_unit_append_can_reload,     "b",    u                               }, \
        { "org.freedesktop.systemd1.Unit", "Job",                  bus_unit_append_job,            "(uo)", u                               }, \
        { "org.freedesktop.systemd1.Unit", "RecursiveStop",        bus_property_append_bool,       "b",    &u->meta.recursive_stop         }, \
        { "org.freedesktop.systemd1.Unit", "StopWhenUneeded",      bus_property_append_bool,       "b",    &u->meta.stop_when_unneeded     }, \
        { "org.freedesktop.systemd1.Unit", "DefaultControlGroup",  bus_unit_append_default_cgroup, "s",    u                               }, \
        { "org.freedesktop.systemd1.Unit", "ControlGroups",        bus_unit_append_cgroups,        "as",   u                               }

int bus_unit_append_names(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_description(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_load_state(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_active_state(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_sub_state(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_can_start(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_can_reload(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_job(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_default_cgroup(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_cgroups(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_kill_mode(Manager *m, DBusMessageIter *i, const char *property, void *data);

void bus_unit_send_change_signal(Unit *u);
void bus_unit_send_removed_signal(Unit *u);

extern const DBusObjectPathVTable bus_unit_vtable;

#endif
