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

_public_ void sd_bus_error_free(sd_bus_error *e) {
        if (!e)
                return;

        if (e->need_free) {
                free((void*) e->name);
                free((void*) e->message);
        }

        e->name = e->message = NULL;
        e->need_free = false;
}

_public_ int sd_bus_error_set(sd_bus_error *e, const char *name, const char *message) {
        char *n, *m = NULL;

        if (!e)
                return 0;

        assert_return(!bus_error_is_dirty(e), -EINVAL);
        assert_return(name, -EINVAL);

        n = strdup(name);
        if (!n)
                return -ENOMEM;

        if (message) {
                m = strdup(message);
                if (!m)
                        return -ENOMEM;
        }

        e->name = n;
        e->message = m;
        e->need_free = true;

        return sd_bus_error_get_errno(e);
}

int bus_error_setfv(sd_bus_error *e, const char *name, const char *format, va_list ap) {
        char *n, *m = NULL;
        int r;

        if (!e)
                return 0;

        assert_return(!bus_error_is_dirty(e), -EINVAL);
        assert_return(name, -EINVAL);

        n = strdup(name);
        if (!n)
                return -ENOMEM;

        if (format) {
                r = vasprintf(&m, format, ap);
                if (r < 0) {
                        free(n);
                        return -ENOMEM;
                }
        }

        e->name = n;
        e->message = m;
        e->need_free = true;

        return sd_bus_error_get_errno(e);
}

_public_ int sd_bus_error_setf(sd_bus_error *e, const char *name, const char *format, ...) {

        if (format) {
                int r;
                va_list ap;

                va_start(ap, format);
                r = bus_error_setfv(e, name, format, ap);
                va_end(ap);

                return r;
        }

        return sd_bus_error_set(e, name, NULL);
}

_public_ int sd_bus_error_copy(sd_bus_error *dest, const sd_bus_error *e) {
        char *x, *y = NULL;

        if (!dest)
                return 0;
        if (!sd_bus_error_is_set(e))
                return 0;

        assert_return(!bus_error_is_dirty(dest), -EINVAL);

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
        return sd_bus_error_get_errno(e);
}

_public_ int sd_bus_error_set_const(sd_bus_error *e, const char *name, const char *message) {
        if (!e)
                return 0;

        assert_return(!bus_error_is_dirty(e), -EINVAL);
        assert_return(name, -EINVAL);

        *e = SD_BUS_ERROR_MAKE_CONST(name, message);
        return sd_bus_error_get_errno(e);
}

_public_ int sd_bus_error_is_set(const sd_bus_error *e) {
        if (!e)
                return 0;

        return !!e->name;
}

_public_ int sd_bus_error_has_name(const sd_bus_error *e, const char *name) {
        if (!e)
                return 0;

        return streq_ptr(e->name, name);
}

_public_ int sd_bus_error_get_errno(const sd_bus_error* e) {

        /* Better replce this with a gperf table */

        if (!e)
                return EIO;

        if (!e->name)
                return EIO;

        if (streq(e->name, SD_BUS_ERROR_NO_MEMORY))
                return ENOMEM;

        if (streq(e->name, SD_BUS_ERROR_SERVICE_UNKNOWN))
                return EHOSTUNREACH;

        if (streq(e->name, SD_BUS_ERROR_NAME_HAS_NO_OWNER))
                return ENXIO;

        if (streq(e->name, SD_BUS_ERROR_NO_REPLY) ||
            streq(e->name, SD_BUS_ERROR_TIMEOUT) ||
            streq(e->name, "org.freedesktop.DBus.Error.TimedOut"))
                return ETIMEDOUT;

        if (streq(e->name, SD_BUS_ERROR_IO_ERROR))
                return EIO;

        if (streq(e->name, SD_BUS_ERROR_BAD_ADDRESS))
                return EADDRNOTAVAIL;

        if (streq(e->name, SD_BUS_ERROR_NOT_SUPPORTED))
                return ENOTSUP;

        if (streq(e->name, SD_BUS_ERROR_LIMITS_EXCEEDED))
                return ENOBUFS;

        if (streq(e->name, SD_BUS_ERROR_ACCESS_DENIED) ||
            streq(e->name, SD_BUS_ERROR_AUTH_FAILED))
                return EACCES;

        if (streq(e->name, SD_BUS_ERROR_NO_SERVER))
                return EHOSTDOWN;

        if (streq(e->name, SD_BUS_ERROR_NO_NETWORK))
                return ENONET;

        if (streq(e->name, SD_BUS_ERROR_ADDRESS_IN_USE))
                return EADDRINUSE;

        if (streq(e->name, SD_BUS_ERROR_DISCONNECTED))
                return ECONNRESET;

        if (streq(e->name, SD_BUS_ERROR_INVALID_ARGS) ||
            streq(e->name, SD_BUS_ERROR_INVALID_SIGNATURE) ||
            streq(e->name, "org.freedesktop.DBus.Error.MatchRuleInvalid") ||
            streq(e->name, "org.freedesktop.DBus.Error.InvalidFileContent"))
                return EINVAL;

        if (streq(e->name, SD_BUS_ERROR_FILE_NOT_FOUND) ||
            streq(e->name, "org.freedesktop.DBus.Error.MatchRuleNotFound"))
                return ENOENT;

        if (streq(e->name, SD_BUS_ERROR_FILE_EXISTS))
                return EEXIST;

        if (streq(e->name, SD_BUS_ERROR_UNKNOWN_METHOD) ||
            streq(e->name, SD_BUS_ERROR_UNKNOWN_OBJECT) ||
            streq(e->name, SD_BUS_ERROR_UNKNOWN_INTERFACE) ||
            streq(e->name, SD_BUS_ERROR_UNKNOWN_PROPERTY))
                return EBADR;

        if (streq(e->name, SD_BUS_ERROR_PROPERTY_READ_ONLY))
                return EROFS;

        if (streq(e->name, SD_BUS_ERROR_UNIX_PROCESS_ID_UNKNOWN) ||
            streq(e->name, "org.freedesktop.DBus.Error.SELinuxSecurityContextUnknown"))
                return ESRCH;

        if (streq(e->name, SD_BUS_ERROR_INCONSISTENT_MESSAGE))
                return EBADMSG;

        if (streq(e->name, "org.freedesktop.DBus.Error.ObjectPathInUse"))
                return EBUSY;

        return EIO;
}

static int bus_error_set_strerror_or_const(sd_bus_error *e, const char *name, int error, const char *fallback) {
        size_t k = 64;
        char *n = NULL, *m = NULL;

        if (error < 0)
                error = -error;

        if (!e)
                return -error;

        assert_return(!bus_error_is_dirty(e), -EINVAL);
        assert_return(name, -EINVAL);

        for (;;) {
                char *x;

                m = new(char, k);
                if (!m)
                        goto use_fallback;

                errno = 0;
                x = strerror_r(error, m, k);
                if (errno == ERANGE || strlen(x) >= k - 1) {
                        free(m);
                        k *= 2;
                        continue;
                }

                if (!x || errno) {
                        free(m);
                        goto use_fallback;
                }


                if (x != m) {
                        free(m);
                        sd_bus_error_set_const(e, name, x);
                        return -error;
                }

                break;
        }


        n = strdup(name);
        if (!n) {
                free(m);
                goto use_fallback;
        }

        e->name = n;
        e->message = m;
        e->need_free = true;

        return -error;

use_fallback:
        sd_bus_error_set_const(e, name, fallback);
        return -error;
}

static sd_bus_error map_from_errno(int error) {

        if (error < 0)
                error = -error;

        switch (error) {

        case ENOMEM:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NO_NETWORK, "Out of memory");

        case EPERM:
        case EACCES:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_ACCESS_DENIED, "Access denied");

        case EINVAL:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid argument");

        case ESRCH:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_UNIX_PROCESS_ID_UNKNOWN, "No such process");

        case ENOENT:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_FILE_NOT_FOUND, "File not found");

        case EEXIST:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_FILE_EXISTS, "File exists");

        case ETIMEDOUT:
        case ETIME:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_TIMEOUT, "Timed out");

        case EIO:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_IO_ERROR, "Input/output error");

        case ENETRESET:
        case ECONNABORTED:
        case ECONNRESET:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_DISCONNECTED, "Disconnected");

        case ENOTSUP:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NOT_SUPPORTED, "Not supported");

        case EADDRNOTAVAIL:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_BAD_ADDRESS, "Address not available");

        case ENOBUFS:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_LIMITS_EXCEEDED, "Limits exceeded");

        case EADDRINUSE:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_ADDRESS_IN_USE, "Address in use");

        case EBADMSG:
                return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INCONSISTENT_MESSAGE, "Inconsistent message");
        }

        return SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_FAILED, "Operation failed");
}

_public_ int sd_bus_error_set_errno(sd_bus_error *e, int error) {
        sd_bus_error x;

        x = map_from_errno(error);

        return bus_error_set_strerror_or_const(e, x.name, error, x.message);
}

int bus_error_set_errnofv(sd_bus_error *e, int error, const char *format, va_list ap) {
        sd_bus_error x;
        int r;

        if (error < 0)
                error = -error;

        if (!e)
                return -error;

        assert_return(!bus_error_is_dirty(e), -EINVAL);

        x = map_from_errno(error);

        if (format) {
                char *n, *m;

                r = vasprintf(&m, format, ap);
                if (r < 0)
                        goto fallback;

                n = strdup(x.name);
                if (!n) {
                        free(m);
                        goto fallback;
                }

                e->name = n;
                e->message = m;
                e->need_free = true;
                return -error;
        }

fallback:
        return bus_error_set_strerror_or_const(e, x.name, error, x.message);
}

_public_ int sd_bus_error_set_errnof(sd_bus_error *e, int error, const char *format, ...) {
        int r;

        if (error < 0)
                error = -error;

        if (!e)
                return -error;

        assert_return(!bus_error_is_dirty(e), -EINVAL);

        if (format) {
                va_list ap;

                va_start(ap, format);
                r = bus_error_set_errnofv(e, error, format, ap);
                va_end(ap);

                return r;
        }

        return sd_bus_error_set_errno(e, error);
}

const char *bus_error_message(const sd_bus_error *e, int error) {

        if (e) {
                /* Sometimes the D-Bus server is a little bit too verbose with
                 * its error messages, so let's override them here */
                if (sd_bus_error_has_name(e, SD_BUS_ERROR_ACCESS_DENIED))
                        return "Access denied";

                if (e->message)
                        return e->message;
        }

        if (error < 0)
                error = -error;

        return strerror(error);
}
