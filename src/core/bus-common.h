/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

#include "macro.h"

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

typedef enum BusPolicyAccess {
        BUS_POLICY_ACCESS_SEE,
        BUS_POLICY_ACCESS_TALK,
        BUS_POLICY_ACCESS_OWN,
        _BUS_POLICY_ACCESS_MAX,
        _BUS_POLICY_ACCESS_INVALID = -1
} BusPolicyAccess;

const char* bus_policy_access_to_string(BusPolicyAccess i) _const_;
BusPolicyAccess bus_policy_access_from_string(const char *s) _pure_;
