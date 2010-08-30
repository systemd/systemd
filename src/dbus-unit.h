/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
        " <interface name=\"org.freedesktop.systemd1.Unit\">\n"         \
        "  <method name=\"Start\">\n"                                   \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"Stop\">\n"                                    \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"Reload\">\n"                                  \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"Restart\">\n"                                 \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"TryRestart\">\n"                              \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"ReloadOrRestart\">\n"                         \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"ReloadOrTryRestart\">\n"                      \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"ResetMaintenance\"/>\n"                       \
        "  <property name=\"Id\" type=\"s\" access=\"read\"/>\n"        \
        "  <property name=\"Names\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"Following\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"Requires\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"RequiresOverridable\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Requisite\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"RequisiteOverridable\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Wants\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"RequiredBy\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"RequiredByOverridable\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"WantedBy\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Conflicts\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"ConflictedBy\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Before\" type=\"as\" access=\"read\"/>\n"   \
        "  <property name=\"After\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"OnFailure\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"Description\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"LoadState\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"ActiveState\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"SubState\" type=\"s\" access=\"read\"/>\n"  \
        "  <property name=\"FragmentPath\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"InactiveExitTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"ActiveEnterTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"ActiveExitTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"InactiveEnterTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"CanReload\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"CanStart\" type=\"b\" access=\"read\"/>\n"  \
        "  <property name=\"CanStop\" type=\"b\" access=\"read\"/>\n"   \
        "  <property name=\"CanIsolate\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"Job\" type=\"(uo)\" access=\"read\"/>\n"    \
        "  <property name=\"RecursiveStop\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"StopWhenUneeded\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"RefuseManualStart\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"RefuseManualStop\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"DefaultDependencies\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"DefaultControlGroup\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"ControlGroups\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"NeedDaemonReload\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"JobTimeoutUSec\" type=\"t\" access=\"read\"/>\n" \
        " </interface>\n"

#define BUS_UNIT_PROPERTIES \
        { "org.freedesktop.systemd1.Unit", "Id",                   bus_property_append_string,     "s",    u->meta.id                        }, \
        { "org.freedesktop.systemd1.Unit", "Names",                bus_unit_append_names,          "as",   u                                 }, \
        { "org.freedesktop.systemd1.Unit", "Following",            bus_unit_append_following,      "s",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "Requires",             bus_unit_append_dependencies,   "as",   u->meta.dependencies[UNIT_REQUIRES] }, \
        { "org.freedesktop.systemd1.Unit", "RequiresOverridable",  bus_unit_append_dependencies,   "as",   u->meta.dependencies[UNIT_REQUIRES_OVERRIDABLE] }, \
        { "org.freedesktop.systemd1.Unit", "Requisite",            bus_unit_append_dependencies,   "as",   u->meta.dependencies[UNIT_REQUISITE] }, \
        { "org.freedesktop.systemd1.Unit", "RequisiteOverridable", bus_unit_append_dependencies,   "as",   u->meta.dependencies[UNIT_REQUISITE_OVERRIDABLE] }, \
        { "org.freedesktop.systemd1.Unit", "Wants",                bus_unit_append_dependencies,   "as",   u->meta.dependencies[UNIT_WANTS]  }, \
        { "org.freedesktop.systemd1.Unit", "RequiredBy",           bus_unit_append_dependencies,   "as",   u->meta.dependencies[UNIT_REQUIRED_BY] }, \
        { "org.freedesktop.systemd1.Unit", "RequiredByOverridable",bus_unit_append_dependencies,   "as",   u->meta.dependencies[UNIT_REQUIRED_BY_OVERRIDABLE] }, \
        { "org.freedesktop.systemd1.Unit", "WantedBy",             bus_unit_append_dependencies,   "as",   u->meta.dependencies[UNIT_WANTED_BY] }, \
        { "org.freedesktop.systemd1.Unit", "Conflicts",            bus_unit_append_dependencies,   "as",   u->meta.dependencies[UNIT_CONFLICTS] }, \
        { "org.freedesktop.systemd1.Unit", "ConflictedBy",         bus_unit_append_dependencies,   "as",   u->meta.dependencies[UNIT_CONFLICTED_BY] }, \
        { "org.freedesktop.systemd1.Unit", "Before",               bus_unit_append_dependencies,   "as",   u->meta.dependencies[UNIT_BEFORE] }, \
        { "org.freedesktop.systemd1.Unit", "After",                bus_unit_append_dependencies,   "as",   u->meta.dependencies[UNIT_AFTER]  }, \
        { "org.freedesktop.systemd1.Unit", "OnFailure",            bus_unit_append_dependencies,   "as",   u->meta.dependencies[UNIT_ON_FAILURE] }, \
        { "org.freedesktop.systemd1.Unit", "Description",          bus_unit_append_description,    "s",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "LoadState",            bus_unit_append_load_state,     "s",    &u->meta.load_state               }, \
        { "org.freedesktop.systemd1.Unit", "ActiveState",          bus_unit_append_active_state,   "s",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "SubState",             bus_unit_append_sub_state,      "s",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "FragmentPath",         bus_property_append_string,     "s",    u->meta.fragment_path             }, \
        { "org.freedesktop.systemd1.Unit", "InactiveExitTimestamp",bus_property_append_uint64,     "t",    &u->meta.inactive_exit_timestamp.realtime  }, \
        { "org.freedesktop.systemd1.Unit", "ActiveEnterTimestamp", bus_property_append_uint64,     "t",    &u->meta.active_enter_timestamp.realtime }, \
        { "org.freedesktop.systemd1.Unit", "ActiveExitTimestamp",  bus_property_append_uint64,     "t",    &u->meta.active_exit_timestamp.realtime    }, \
        { "org.freedesktop.systemd1.Unit", "InactiveEnterTimestamp",bus_property_append_uint64,    "t",    &u->meta.inactive_enter_timestamp.realtime }, \
        { "org.freedesktop.systemd1.Unit", "CanStart",             bus_unit_append_can_start,      "b",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "CanStop",              bus_unit_append_can_stop,       "b",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "CanReload",            bus_unit_append_can_reload,     "b",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "CanIsolate",           bus_unit_append_can_isolate,    "b",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "Job",                  bus_unit_append_job,            "(uo)", u                                 }, \
        { "org.freedesktop.systemd1.Unit", "RecursiveStop",        bus_property_append_bool,       "b",    &u->meta.recursive_stop           }, \
        { "org.freedesktop.systemd1.Unit", "StopWhenUneeded",      bus_property_append_bool,       "b",    &u->meta.stop_when_unneeded       }, \
        { "org.freedesktop.systemd1.Unit", "RefuseManualStart",    bus_property_append_bool,       "b",    &u->meta.refuse_manual_start      }, \
        { "org.freedesktop.systemd1.Unit", "RefuseManualStop",     bus_property_append_bool,       "b",    &u->meta.refuse_manual_stop       }, \
        { "org.freedesktop.systemd1.Unit", "AllowIsolate",         bus_property_append_bool,       "b",    &u->meta.allow_isolate            }, \
        { "org.freedesktop.systemd1.Unit", "DefaultDependencies",  bus_property_append_bool,       "b",    &u->meta.default_dependencies     }, \
        { "org.freedesktop.systemd1.Unit", "DefaultControlGroup",  bus_unit_append_default_cgroup, "s",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "ControlGroups",        bus_unit_append_cgroups,        "as",   u                                 }, \
        { "org.freedesktop.systemd1.Unit", "NeedDaemonReload",     bus_unit_append_need_daemon_reload, "b", u                                }, \
        { "org.freedesktop.systemd1.Unit", "JobTimeoutUSec",       bus_property_append_usec,       "t",    &u->meta.job_timeout              }

int bus_unit_append_names(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_following(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_dependencies(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_description(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_load_state(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_active_state(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_sub_state(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_can_start(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_can_stop(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_can_reload(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_can_isolate(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_job(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_default_cgroup(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_cgroups(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_need_daemon_reload(Manager *m, DBusMessageIter *i, const char *property, void *data);

void bus_unit_send_change_signal(Unit *u);
void bus_unit_send_removed_signal(Unit *u);

extern const DBusObjectPathVTable bus_unit_vtable;

extern const char bus_unit_interface[];

#endif
