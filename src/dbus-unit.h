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
        "  <method name=\"Kill\">\n"                                    \
        "   <arg name=\"who\" type=\"s\" direction=\"in\"/>\n"          \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"signal\" type=\"i\" direction=\"in\"/>\n"       \
        "  </method>\n"                                                 \
        "  <method name=\"ResetFailed\"/>\n"                            \
        "  <property name=\"Id\" type=\"s\" access=\"read\"/>\n"        \
        "  <property name=\"Names\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"Following\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"Requires\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"RequiresOverridable\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Requisite\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"RequisiteOverridable\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Wants\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"BindTo\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"RequiredBy\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"RequiredByOverridable\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"WantedBy\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"BoundBy\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Conflicts\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"ConflictedBy\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Before\" type=\"as\" access=\"read\"/>\n"   \
        "  <property name=\"After\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"OnFailure\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"Triggers\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"TriggeredBy\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"PropagateReloadTo\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"PropagateReloadFrom\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Description\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"LoadState\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"ActiveState\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"SubState\" type=\"s\" access=\"read\"/>\n"  \
        "  <property name=\"FragmentPath\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"UnitFileState\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"InactiveExitTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"InactiveExitTimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"ActiveEnterTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"ActiveEnterTimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"ActiveExitTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"ActiveExitTimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"InactiveEnterTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"InactiveEnterTimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"CanStart\" type=\"b\" access=\"read\"/>\n"  \
        "  <property name=\"CanStop\" type=\"b\" access=\"read\"/>\n"   \
        "  <property name=\"CanReload\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"CanIsolate\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"Job\" type=\"(uo)\" access=\"read\"/>\n"    \
        "  <property name=\"StopWhenUnneeded\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"RefuseManualStart\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"RefuseManualStop\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"AllowIsolate\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"DefaultDependencies\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"OnFailureIsolate\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"IgnoreOnIsolate\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"IgnoreOnSnapshot\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"DefaultControlGroup\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"ControlGroup\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"ControlGroupAttributes\" type=\"a(sss)\" access=\"read\"/>\n" \
        "  <property name=\"NeedDaemonReload\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"JobTimeoutUSec\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"ConditionTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"ConditionTimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"ConditionResult\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"LoadError\" type=\"(ss)\" access=\"read\"/>\n" \
        " </interface>\n"

#define BUS_UNIT_INTERFACES_LIST                \
        BUS_GENERIC_INTERFACES_LIST             \
        "org.freedesktop.systemd1.Unit\0"

#define BUS_UNIT_PROPERTIES \
        { "org.freedesktop.systemd1.Unit", "Id",                   bus_property_append_string,     "s",    u->id                        }, \
        { "org.freedesktop.systemd1.Unit", "Names",                bus_unit_append_names,          "as",   u                                 }, \
        { "org.freedesktop.systemd1.Unit", "Following",            bus_unit_append_following,      "s",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "Requires",             bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_REQUIRES] }, \
        { "org.freedesktop.systemd1.Unit", "RequiresOverridable",  bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_REQUIRES_OVERRIDABLE] }, \
        { "org.freedesktop.systemd1.Unit", "Requisite",            bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_REQUISITE] }, \
        { "org.freedesktop.systemd1.Unit", "RequisiteOverridable", bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_REQUISITE_OVERRIDABLE] }, \
        { "org.freedesktop.systemd1.Unit", "Wants",                bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_WANTS]  }, \
        { "org.freedesktop.systemd1.Unit", "BindTo",               bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_BIND_TO]  }, \
        { "org.freedesktop.systemd1.Unit", "RequiredBy",           bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_REQUIRED_BY] }, \
        { "org.freedesktop.systemd1.Unit", "RequiredByOverridable",bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_REQUIRED_BY_OVERRIDABLE] }, \
        { "org.freedesktop.systemd1.Unit", "WantedBy",             bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_WANTED_BY] }, \
        { "org.freedesktop.systemd1.Unit", "BoundBy",              bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_BOUND_BY]  }, \
        { "org.freedesktop.systemd1.Unit", "Conflicts",            bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_CONFLICTS] }, \
        { "org.freedesktop.systemd1.Unit", "ConflictedBy",         bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_CONFLICTED_BY] }, \
        { "org.freedesktop.systemd1.Unit", "Before",               bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_BEFORE] }, \
        { "org.freedesktop.systemd1.Unit", "After",                bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_AFTER]  }, \
        { "org.freedesktop.systemd1.Unit", "OnFailure",            bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_ON_FAILURE] }, \
        { "org.freedesktop.systemd1.Unit", "Triggers",             bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_TRIGGERS] }, \
        { "org.freedesktop.systemd1.Unit", "TriggeredBy",          bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_TRIGGERED_BY] }, \
        { "org.freedesktop.systemd1.Unit", "PropagateReloadTo",    bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_PROPAGATE_RELOAD_TO] }, \
        { "org.freedesktop.systemd1.Unit", "PropagateReloadFrom",  bus_unit_append_dependencies,   "as",   u->dependencies[UNIT_PROPAGATE_RELOAD_FROM] }, \
        { "org.freedesktop.systemd1.Unit", "Description",          bus_unit_append_description,    "s",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "LoadState",            bus_unit_append_load_state,     "s",    &u->load_state               }, \
        { "org.freedesktop.systemd1.Unit", "ActiveState",          bus_unit_append_active_state,   "s",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "SubState",             bus_unit_append_sub_state,      "s",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "FragmentPath",         bus_property_append_string,     "s",    u->fragment_path             }, \
        { "org.freedesktop.systemd1.Unit", "UnitFileState",        bus_unit_append_file_state,     "s",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "InactiveExitTimestamp",bus_property_append_usec,       "t",    &u->inactive_exit_timestamp.realtime }, \
        { "org.freedesktop.systemd1.Unit", "InactiveExitTimestampMonotonic",bus_property_append_usec, "t", &u->inactive_exit_timestamp.monotonic }, \
        { "org.freedesktop.systemd1.Unit", "ActiveEnterTimestamp", bus_property_append_usec,       "t",    &u->active_enter_timestamp.realtime }, \
        { "org.freedesktop.systemd1.Unit", "ActiveEnterTimestampMonotonic", bus_property_append_usec, "t", &u->active_enter_timestamp.monotonic }, \
        { "org.freedesktop.systemd1.Unit", "ActiveExitTimestamp",  bus_property_append_usec,       "t",    &u->active_exit_timestamp.realtime }, \
        { "org.freedesktop.systemd1.Unit", "ActiveExitTimestampMonotonic",  bus_property_append_usec, "t", &u->active_exit_timestamp.monotonic }, \
        { "org.freedesktop.systemd1.Unit", "InactiveEnterTimestamp",bus_property_append_usec,      "t",    &u->inactive_enter_timestamp.realtime }, \
        { "org.freedesktop.systemd1.Unit", "InactiveEnterTimestampMonotonic",bus_property_append_usec,"t", &u->inactive_enter_timestamp.monotonic }, \
        { "org.freedesktop.systemd1.Unit", "CanStart",             bus_unit_append_can_start,      "b",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "CanStop",              bus_unit_append_can_stop,       "b",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "CanReload",            bus_unit_append_can_reload,     "b",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "CanIsolate",           bus_unit_append_can_isolate,    "b",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "Job",                  bus_unit_append_job,            "(uo)", u                                 }, \
        { "org.freedesktop.systemd1.Unit", "StopWhenUnneeded",     bus_property_append_bool,       "b",    &u->stop_when_unneeded       }, \
        { "org.freedesktop.systemd1.Unit", "RefuseManualStart",    bus_property_append_bool,       "b",    &u->refuse_manual_start      }, \
        { "org.freedesktop.systemd1.Unit", "RefuseManualStop",     bus_property_append_bool,       "b",    &u->refuse_manual_stop       }, \
        { "org.freedesktop.systemd1.Unit", "AllowIsolate",         bus_property_append_bool,       "b",    &u->allow_isolate            }, \
        { "org.freedesktop.systemd1.Unit", "DefaultDependencies",  bus_property_append_bool,       "b",    &u->default_dependencies     }, \
        { "org.freedesktop.systemd1.Unit", "OnFailureIsolate",     bus_property_append_bool,       "b",    &u->on_failure_isolate       }, \
        { "org.freedesktop.systemd1.Unit", "IgnoreOnIsolate",      bus_property_append_bool,       "b",    &u->ignore_on_isolate        }, \
        { "org.freedesktop.systemd1.Unit", "IgnoreOnSnapshot",     bus_property_append_bool,       "b",    &u->ignore_on_snapshot       }, \
        { "org.freedesktop.systemd1.Unit", "DefaultControlGroup",  bus_unit_append_default_cgroup, "s",    u                                 }, \
        { "org.freedesktop.systemd1.Unit", "ControlGroup",         bus_unit_append_cgroups,        "as",   u                                 }, \
        { "org.freedesktop.systemd1.Unit", "ControlGroupAttributes", bus_unit_append_cgroup_attrs, "a(sss)", u                               }, \
        { "org.freedesktop.systemd1.Unit", "NeedDaemonReload",     bus_unit_append_need_daemon_reload, "b", u                                }, \
        { "org.freedesktop.systemd1.Unit", "JobTimeoutUSec",       bus_property_append_usec,       "t",    &u->job_timeout              }, \
        { "org.freedesktop.systemd1.Unit", "ConditionTimestamp",   bus_property_append_usec,       "t",    &u->condition_timestamp.realtime }, \
        { "org.freedesktop.systemd1.Unit", "ConditionTimestampMonotonic", bus_property_append_usec,"t",    &u->condition_timestamp.monotonic }, \
        { "org.freedesktop.systemd1.Unit", "ConditionResult",      bus_property_append_bool,       "b",    &u->condition_result         }, \
        { "org.freedesktop.systemd1.Unit", "LoadError",            bus_unit_append_load_error,     "(ss)", u                                 }

int bus_unit_append_names(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_following(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_dependencies(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_description(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_load_state(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_active_state(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_sub_state(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_file_state(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_can_start(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_can_stop(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_can_reload(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_can_isolate(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_job(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_default_cgroup(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_cgroups(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_cgroup_attrs(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_need_daemon_reload(DBusMessageIter *i, const char *property, void *data);
int bus_unit_append_load_error(DBusMessageIter *i, const char *property, void *data);

void bus_unit_send_change_signal(Unit *u);
void bus_unit_send_removed_signal(Unit *u);

extern const DBusObjectPathVTable bus_unit_vtable;

extern const char bus_unit_interface[];

#endif
