/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "unit.h"
#include "busname.h"
#include "dbus-unit.h"
#include "dbus-busname.h"
#include "bus-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, busname_result, BusNameResult);

const sd_bus_vtable bus_busname_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Name", "s", NULL, offsetof(BusName, name), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimeoutUSec", "t", bus_property_get_usec, offsetof(BusName, timeout_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ControlPID", "u", bus_property_get_pid, offsetof(BusName, control_pid), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(BusName, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Activating", "b", bus_property_get_bool, offsetof(BusName, activating), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("AcceptFileDescriptors", "b", bus_property_get_bool, offsetof(BusName, accept_fd), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};
