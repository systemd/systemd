/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2013 Daniel Mack
  Copyright 2014 Kay Sievers

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

#include <stddef.h>

#include "util.h"
#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-util.h"
#include "synthesize.h"

int synthetic_driver_send(sd_bus *b, sd_bus_message *m) {
        int r;

        assert(b);
        assert(m);

        r = bus_message_append_sender(m, "org.freedesktop.DBus");
        if (r < 0)
                return r;

        r = bus_seal_synthetic_message(b, m);
        if (r < 0)
                return r;

        return sd_bus_send(b, m, NULL);
}

int synthetic_reply_method_error(sd_bus_message *call, const sd_bus_error *e) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(call);

        if (call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        r = sd_bus_message_new_method_error(call, &m, e);
        if (r < 0)
                return r;

        return synthetic_driver_send(call->bus, m);
}

int synthetic_reply_method_errorf(sd_bus_message *call, const char *name, const char *format, ...) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        va_list ap;

        va_start(ap, format);
        bus_error_setfv(&error, name, format, ap);
        va_end(ap);

        return synthetic_reply_method_error(call, &error);
}

int synthetic_reply_method_errno(sd_bus_message *call, int error, const sd_bus_error *p) {
        _cleanup_bus_error_free_ sd_bus_error berror = SD_BUS_ERROR_NULL;

        assert(call);

        if (call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        if (sd_bus_error_is_set(p))
                return synthetic_reply_method_error(call, p);

        sd_bus_error_set_errno(&berror, error);

        return synthetic_reply_method_error(call, &berror);
}

int synthetic_reply_method_errnof(sd_bus_message *call, int error, const char *format, ...) {
        _cleanup_bus_error_free_ sd_bus_error berror = SD_BUS_ERROR_NULL;
        va_list ap;

        assert(call);

        if (call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        va_start(ap, format);
        sd_bus_error_set_errnofv(&berror, error, format, ap);
        va_end(ap);

        return synthetic_reply_method_error(call, &berror);
}

int synthetic_reply_method_return(sd_bus_message *call, const char *types, ...) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(call);

        if (call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        r = sd_bus_message_new_method_return(call, &m);
        if (r < 0)
                return r;

        if (!isempty(types)) {
                va_list ap;

                va_start(ap, types);
                r = bus_message_append_ap(m, types, ap);
                va_end(ap);
                if (r < 0)
                        return r;
        }

        return synthetic_driver_send(call->bus, m);
}

int synthetic_reply_method_return_strv(sd_bus_message *call, char **l) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(call);

        if (call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        r = sd_bus_message_new_method_return(call, &m);
        if (r < 0)
                return synthetic_reply_method_errno(call, r, NULL);

        r = sd_bus_message_append_strv(m, l);
        if (r < 0)
                return synthetic_reply_method_errno(call, r, NULL);

        return synthetic_driver_send(call->bus, m);
}

int synthesize_name_acquired(sd_bus *a, sd_bus *b, sd_bus_message *m) {
        _cleanup_bus_message_unref_ sd_bus_message *n = NULL;
        const char *name, *old_owner, *new_owner;
        int r;

        assert(a);
        assert(b);
        assert(m);

        /* If we get NameOwnerChanged for our own name, we need to
         * synthesize NameLost/NameAcquired, since socket clients need
         * that, even though it is obsoleted on kdbus */

        if (!a->is_kernel)
                return 0;

        if (!sd_bus_message_is_signal(m, "org.freedesktop.DBus", "NameOwnerChanged") ||
            !streq_ptr(m->path, "/org/freedesktop/DBus") ||
            !streq_ptr(m->sender, "org.freedesktop.DBus"))
                return 0;

        r = sd_bus_message_read(m, "sss", &name, &old_owner, &new_owner);
        if (r < 0)
                return r;

        r = sd_bus_message_rewind(m, true);
        if (r < 0)
                return r;

        if (streq(old_owner, a->unique_name)) {

                r = sd_bus_message_new_signal(
                                b,
                                &n,
                                "/org/freedesktop/DBus",
                                "org.freedesktop.DBus",
                                "NameLost");

        } else if (streq(new_owner, a->unique_name)) {

                r = sd_bus_message_new_signal(
                                b,
                                &n,
                                "/org/freedesktop/DBus",
                                "org.freedesktop.DBus",
                                "NameAcquired");
        } else
                return 0;

        if (r < 0)
                return r;

        r = sd_bus_message_append(n, "s", name);
        if (r < 0)
                return r;

        r = bus_message_append_sender(n, "org.freedesktop.DBus");
        if (r < 0)
                return r;

        r = bus_seal_synthetic_message(b, n);
        if (r < 0)
                return r;

        return sd_bus_send(b, n, NULL);
}
