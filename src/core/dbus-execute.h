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

#define BUS_EXEC_STATUS_INTERFACE(prefix)                               \
        "  <property name=\"" prefix "StartTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"" prefix "StartTimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"" prefix "ExitTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"" prefix "ExitTimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"" prefix "PID\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"" prefix "Code\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"" prefix "Status\" type=\"i\" access=\"read\"/>\n"

#define BUS_EXEC_CONTEXT_INTERFACE                                      \
        "  <property name=\"Environment\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"EnvironmentFiles\" type=\"a(sb)\" access=\"read\"/>\n" \
        "  <property name=\"UMask\" type=\"u\" access=\"read\"/>\n"     \
        "  <property name=\"LimitCPU\" type=\"t\" access=\"read\"/>\n"  \
        "  <property name=\"LimitFSIZE\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitDATA\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitSTACK\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitCORE\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitRSS\" type=\"t\" access=\"read\"/>\n"  \
        "  <property name=\"LimitNOFILE\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitAS\" type=\"t\" access=\"read\"/>\n"   \
        "  <property name=\"LimitNPROC\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitMEMLOCK\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitLOCKS\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitSIGPENDING\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitMSGQUEUE\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitNICE\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitRTPRIO\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitRTTIME\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"WorkingDirectory\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"RootDirectory\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"OOMScoreAdjust\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"Nice\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"IOScheduling\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"CPUSchedulingPolicy\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"CPUSchedulingPriority\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"CPUAffinity\" type=\"ay\" access=\"read\"/>\n" \
        "  <property name=\"TimerSlackNSec\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"CPUSchedulingResetOnFork\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"NonBlocking\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"StandardInput\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"StandardOutput\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"StandardError\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"TTYPath\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"TTYReset\" type=\"b\" access=\"read\"/>\n"   \
        "  <property name=\"TTYVHangup\" type=\"b\" access=\"read\"/>\n"   \
        "  <property name=\"TTYVTDisallocate\" type=\"b\" access=\"read\"/>\n"   \
        "  <property name=\"SyslogPriority\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"SyslogIdentifier\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"SyslogLevelPrefix\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"Capabilities\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"SecureBits\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"CapabilityBoundingSet\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"User\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Group\" type=\"s\" access=\"read\"/>\n"     \
        "  <property name=\"SupplementaryGroups\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"TCPWrapName\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"PAMName\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"ReadWriteDirectories\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"ReadOnlyDirectories\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"InaccessibleDirectories\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"MountFlags\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"PrivateTmp\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"PrivateNetwork\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"SameProcessGroup\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"UtmpIdentifier\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"IgnoreSIGPIPE\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"NoNewPrivileges\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"SystemCallFilter\" type=\"au\" access=\"read\"/>\n"

#define BUS_EXEC_COMMAND_INTERFACE(name)                             \
        "  <property name=\"" name "\" type=\"a(sasbttuii)\" access=\"read\"/>\n"

extern const BusProperty bus_exec_context_properties[];

#define BUS_EXEC_COMMAND_PROPERTY(name, command, indirect)             \
        { name, bus_execute_append_command, "a(sasbttttuii)", (command), (indirect), NULL }

int bus_execute_append_command(DBusMessageIter *u, const char *property, void *data);
