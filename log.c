/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

#include "log.h"

void log_meta(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *format, ...) {

        const char *prefix, *suffix;
        va_list ap;
        int saved_errno = errno;

        if (LOG_PRI(level) <= LOG_ERR) {
                prefix = "\x1B[1;31m";
                suffix = "\x1B[0m";
        } else {
                prefix = "";
                suffix = "";
        }

        va_start(ap, format);

        fprintf(stderr, "(%s:%u) %s", file, line, prefix);
        vfprintf(stderr, format, ap);
        fprintf(stderr, "%s\n", suffix);

        va_end(ap);

        errno = saved_errno;
}
