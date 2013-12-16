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

#include <stdbool.h>

#include "sd-bus.h"
#include "macro.h"

struct name_error_mapping {
        const char* name;
        int code;
};
typedef struct name_error_mapping name_error_mapping;

const name_error_mapping* bus_error_mapping_lookup(const char *str, unsigned int len);

bool bus_error_is_dirty(sd_bus_error *e);

const char *bus_error_message(const sd_bus_error *e, int error);

int bus_error_setfv(sd_bus_error *e, const char *name, const char *format, va_list ap) _printf_(3,0);
int bus_error_set_errnofv(sd_bus_error *e, int error, const char *format, va_list ap) _printf_(3,0);
