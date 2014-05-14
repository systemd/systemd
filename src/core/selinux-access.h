/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Dan Walsh

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

#include "sd-bus.h"
#include "bus-error.h"
#include "bus-util.h"

void selinux_access_free(void);

int selinux_generic_access_check(sd_bus_message *message, const char *path, const char *permission, sd_bus_error *error);

#ifdef HAVE_SELINUX

#define selinux_access_check(message, permission, error) \
        selinux_generic_access_check((message), NULL, (permission), (error))

#define selinux_unit_access_check(unit, message, permission, error) \
        ({                                                              \
                Unit *_unit = (unit);                                   \
                selinux_generic_access_check((message), _unit->fragment_path ?: _unit->fragment_path, (permission), (error)); \
        })

#else

#define selinux_access_check(message, permission, error) 0
#define selinux_unit_access_check(unit, message, permission, error) 0

#endif
