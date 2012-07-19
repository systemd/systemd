/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#define BUS_KILL_CONTEXT_INTERFACE                                      \
        "  <property name=\"KillMode\" type=\"s\" access=\"read\"/>\n"  \
        "  <property name=\"KillSignal\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"SendSIGKILL\" type=\"b\" access=\"read\"/>\n"

#define BUS_KILL_COMMAND_INTERFACE(name)                                \
        "  <property name=\"" name "\" type=\"a(sasbttuii)\" access=\"read\"/>\n"

extern const BusProperty bus_kill_context_properties[];

int bus_kill_append_mode(DBusMessageIter *i, const char *property, void *data);
