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

int selinux_access_check(sd_bus *bus, sd_bus_message *message, const char *path, const char *permission, sd_bus_error *error);

#ifdef HAVE_SELINUX

#define SELINUX_ACCESS_CHECK(bus, message, permission)                  \
        do {                                                            \
                _cleanup_bus_error_free_ sd_bus_error _error = SD_BUS_ERROR_NULL; \
                sd_bus_message *_m = (message);                         \
                sd_bus *_b = (bus);                                     \
                int _r;                                                 \
                _r = selinux_access_check(_b, _m, NULL, (permission), &_error); \
                if (_r < 0)                                             \
                        return sd_bus_reply_method_errno(_m, _r, &_error); \
        } while (false)

#define SELINUX_UNIT_ACCESS_CHECK(unit, bus, message, permission)       \
        do {                                                            \
                _cleanup_bus_error_free_ sd_bus_error _error = SD_BUS_ERROR_NULL; \
                sd_bus_message *_m = (message);                         \
                sd_bus *_b = (bus);                                     \
                Unit *_u = (unit);                                      \
                int _r;                                                 \
                _r = selinux_access_check(_b, _m, _u->source_path ?: _u->fragment_path, (permission), &_error); \
                if (_r < 0)                                             \
                        return sd_bus_reply_method_errno(_m, _r, &_error); \
        } while (false)

#else

#define SELINUX_ACCESS_CHECK(bus, message, permission) do { } while (false)
#define SELINUX_UNIT_ACCESS_CHECK(unit, bus, message, permission) do { } while (false)

#endif
