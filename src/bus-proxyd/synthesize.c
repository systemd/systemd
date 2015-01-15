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

#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>

#include "log.h"
#include "util.h"
#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-util.h"
#include "strv.h"
#include "def.h"
#include "bus-control.h"
#include "synthesize.h"

static int synthetic_driver_send(sd_bus *b, sd_bus_message *m) {
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

int synthetic_reply_return_strv(sd_bus_message *call, char **l) {
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
