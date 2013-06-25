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

#include "manager.h"
#include "dbus-common.h"

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
        "   <arg name=\"signal\" type=\"i\" direction=\"in\"/>\n"       \
        "  </method>\n"                                                 \
        "  <method name=\"ResetFailed\"/>\n"                            \
        "  <method name=\"SetProperties\">\n"                           \
        "   <arg name=\"runtime\" type=\"b\" direction=\"in\"/>\n"      \
        "   <arg name=\"properties\" type=\"a(sv)\" direction=\"in\"/>\n" \
        "  </method>\n"                                                 \
        "  <property name=\"Id\" type=\"s\" access=\"read\"/>\n"        \
        "  <property name=\"Names\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"Following\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"Requires\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"RequiresOverridable\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Requisite\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"RequisiteOverridable\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Wants\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"BindsTo\" type=\"as\" access=\"read\"/>\n"  \
        "  <property name=\"PartOf\" type=\"as\" access=\"read\"/>\n"   \
        "  <property name=\"RequiredBy\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"RequiredByOverridable\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"WantedBy\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"BoundBy\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"ConsistsOf\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Conflicts\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"ConflictedBy\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Before\" type=\"as\" access=\"read\"/>\n"   \
        "  <property name=\"After\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"OnFailure\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"Triggers\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"TriggeredBy\" type=\"as\" access=\"read\"/>\n"    \
        "  <property name=\"PropagatesReloadTo\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"ReloadPropagatedFrom\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"RequiresMountsFor\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Description\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"SourcePath\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"DropInPaths\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"Documentation\" type=\"as\" access=\"read\"/>\n" \
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
        "  <property name=\"NeedDaemonReload\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"JobTimeoutUSec\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"ConditionTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"ConditionTimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"ConditionResult\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"Conditions\" type=\"a(sbbsi)\" access=\"read\"/>\n" \
        "  <property name=\"LoadError\" type=\"(ss)\" access=\"read\"/>\n" \
        "  <property name=\"Transient\" type=\"b\" access=\"read\"/>\n" \
        " </interface>\n"

#define BUS_UNIT_CGROUP_INTERFACE                                       \
        "  <property name=\"Slice\" type=\"s\" access=\"read\"/>\n"     \
        "  <property name=\"ControlGroup\" type=\"s\" access=\"read\"/>\n"

#define BUS_UNIT_INTERFACES_LIST                \
        BUS_GENERIC_INTERFACES_LIST             \
        "org.freedesktop.systemd1.Unit\0"

extern const BusProperty bus_unit_properties[];
extern const BusProperty bus_unit_cgroup_properties[];

void bus_unit_send_change_signal(Unit *u);
void bus_unit_send_removed_signal(Unit *u);

DBusHandlerResult bus_unit_queue_job(DBusConnection *connection, DBusMessage *message, Unit *u, JobType type, JobMode mode, bool reload_if_possible);

int bus_unit_set_properties(Unit *u, DBusMessageIter *i, UnitSetPropertiesMode mode, bool commit, DBusError *error);

extern const DBusObjectPathVTable bus_unit_vtable;

extern const char bus_unit_interface[];
