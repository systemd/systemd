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

#include <stdbool.h>

#include "macro.h"

/* Manager status */

typedef enum ShowStatus {
        _SHOW_STATUS_UNSET = -2,
        SHOW_STATUS_AUTO = -1,
        SHOW_STATUS_NO = 0,
        SHOW_STATUS_YES = 1,
        SHOW_STATUS_TEMPORARY = 2,
} ShowStatus;

int parse_show_status(const char *v, ShowStatus *ret);

int status_vprintf(const char *status, bool ellipse, bool ephemeral, const char *format, va_list ap) _printf_(4,0);
int status_printf(const char *status, bool ellipse, bool ephemeral, const char *format, ...) _printf_(4,5);
