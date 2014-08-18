/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Daniel Mack

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

#include "special.h"
#include "bus-kernel.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "service.h"
#include "bus-common.h"

static const char* const bus_policy_access_table[_BUS_POLICY_ACCESS_MAX] = {
        [BUS_POLICY_ACCESS_SEE] = "see",
        [BUS_POLICY_ACCESS_TALK] = "talk",
        [BUS_POLICY_ACCESS_OWN] = "own",
};

DEFINE_STRING_TABLE_LOOKUP(bus_policy_access, BusPolicyAccess);
