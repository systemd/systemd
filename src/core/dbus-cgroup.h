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

#include <dbus/dbus.h>

#include "manager.h"
#include "dbus-common.h"
#include "cgroup.h"

#define BUS_CGROUP_CONTEXT_INTERFACE                                    \
        "  <property name=\"CPUAccounting\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"CPUShares\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"BlockIOAccounting\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"BlockIOWeight\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"BlockIODeviceWeight\" type=\"a(st)\" access=\"read\"/>\n" \
        "  <property name=\"BlockIOReadBandwidth=\" type=\"a(st)\" access=\"read\"/>\n" \
        "  <property name=\"BlockIOWriteBandwidth=\" type=\"a(st)\" access=\"read\"/>\n" \
        "  <property name=\"MemoryAccounting\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"MemoryLimit\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"DevicePolicy\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"DeviceAllow\" type=\"a(ss)\" access=\"read\"/>\n"

extern const BusProperty bus_cgroup_context_properties[];

int bus_cgroup_set_property(Unit *u, CGroupContext *c, const char *name, DBusMessageIter *i, UnitSetPropertiesMode mode, DBusError *error);
