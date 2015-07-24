/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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
#include "proxy.h"

int synthetic_driver_send(sd_bus *b, sd_bus_message *m);

int synthetic_reply_method_return(sd_bus_message *call, const char *types, ...);
int synthetic_reply_method_return_strv(sd_bus_message *call, char **l);

int synthetic_reply_method_error(sd_bus_message *call, const sd_bus_error *e);
int synthetic_reply_method_errorf(sd_bus_message *call, const char *name, const char *format, ...) _sd_printf_(3, 4);
int synthetic_reply_method_errno(sd_bus_message *call, int error, const sd_bus_error *p);
int synthetic_reply_method_errnof(sd_bus_message *call, int error, const char *format, ...) _sd_printf_(3, 4);

int synthesize_name_acquired(Proxy *p, sd_bus *a, sd_bus *b, sd_bus_message *m);
