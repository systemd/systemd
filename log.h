/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foologhfoo
#define foologhfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <syslog.h>

#include "macro.h"

void log_meta(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *format, ...) _printf_attr(5,6);

#define log_debug(...)   log_meta(LOG_DEBUG,   __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_info(...)    log_meta(LOG_INFO,    __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_notice(...)  log_meta(LOG_NOTICE,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_warning(...) log_meta(LOG_WARNING, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_error(...)   log_meta(LOG_ERR,     __FILE__, __LINE__, __func__, __VA_ARGS__)

#endif
