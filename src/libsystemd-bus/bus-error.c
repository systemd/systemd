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

#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "util.h"

#include "sd-bus.h"
#include "bus-error.h"

bool bus_error_is_dirty(sd_bus_error *e) {
        if (!e)
                return 0;

        return e->name || e->message || e->need_free;
}

void sd_bus_error_free(sd_bus_error *e) {
        if (!e)
                return;

        if (e->need_free) {
                free((void*) e->name);
                free((void*) e->message);
        }

        e->name = e->message = NULL;
        e->need_free = false;
}

int sd_bus_error_set(sd_bus_error *e, const char *name, const char *format, ...) {
        char *n, *m = NULL;
        va_list ap;
        int r;

        if (!e)
                return 0;
        if (bus_error_is_dirty(e))
                return -EINVAL;
        if (!name)
                return -EINVAL;

        n = strdup(name);
        if (!n)
                return -ENOMEM;

        if (format) {
                va_start(ap, format);
                r = vasprintf(&m, format, ap);
                va_end(ap);

                if (r < 0) {
                        free(n);
                        return -ENOMEM;
                }
        }

        e->name = n;
        e->message = m;
        e->need_free = true;

        return 0;
}

int sd_bus_error_copy(sd_bus_error *dest, const sd_bus_error *e) {
        char *x, *y = NULL;

        if (!dest)
                return 0;
        if (bus_error_is_dirty(dest))
                return -EINVAL;
        if (!sd_bus_error_is_set(e))
                return 0;

        x = strdup(e->name);
        if (!x)
                return -ENOMEM;

        if (e->message) {
                y = strdup(e->message);
                if (!y) {
                        free(x);
                        return -ENOMEM;
                }
        }

        dest->name = x;
        dest->message = y;
        dest->need_free = true;
        return 0;
}

void sd_bus_error_set_const(sd_bus_error *e, const char *name, const char *message) {
        if (!e)
                return;
        if (bus_error_is_dirty(e))
                return;

        e->name = name;
        e->message = message;
        e->need_free = false;
}

int sd_bus_error_is_set(const sd_bus_error *e) {
        if (!e)
                return 0;

        return !!e->name;
}

int sd_bus_error_has_name(const sd_bus_error *e, const char *name) {
        if (!e)
                return 0;

        return streq_ptr(e->name, name);
}

int bus_error_to_errno(const sd_bus_error* e) {

        /* Better replce this with a gperf table */

        if (!e->name)
                return -EIO;

        if (streq(e->name, "org.freedesktop.DBus.Error.NoMemory"))
                return -ENOMEM;

        if (streq(e->name, "org.freedesktop.DBus.Error.AuthFailed") ||
            streq(e->name, "org.freedesktop.DBus.Error.AccessDenied"))
                return -EPERM;

        return -EIO;
}

int bus_error_from_errno(sd_bus_error *e, int error) {
        if (!e)
                return error;

        if (error == -ENOMEM)
                sd_bus_error_set_const(e, "org.freedesktop.DBus.Error.NoMemory", strerror(-error));
        else if (error == -EPERM || error == -EACCES)
                sd_bus_error_set_const(e, "org.freedesktop.DBus.Error.AccessDenied", strerror(-error));
        else
                sd_bus_error_set_const(e, "org.freedesktop.DBus.Error.Failed", "Operation failed");

        return error;
}

const char *bus_error_message(const sd_bus_error *e, int error) {
        if (e && e->message)
                return e->message;

        return strerror(error);
}
