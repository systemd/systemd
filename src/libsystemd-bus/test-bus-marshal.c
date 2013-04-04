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

#include <assert.h>
#include <stdlib.h>
#include <byteswap.h>

#ifdef HAVE_GLIB
#include <gio/gio.h>
#endif

#include <dbus.h>

#include "log.h"
#include "util.h"

#include "sd-bus.h"
#include "bus-message.h"

int main(int argc, char *argv[]) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r, boolean;
        const char *x, *y, *z, *a, *b, *c, *d;
        uint8_t u, v;
        void *buffer = NULL;
        size_t sz;
        char *h;

        r = sd_bus_message_new_method_call(NULL, "foobar.waldo", "/", "foobar.waldo", "Piep", &m);
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "s", "a string");
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "s", NULL);
        assert_se(r < 0);

        r = sd_bus_message_append(m, "as", 2, "string #1", "string #2");
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "sass", "foobar", 5, "foo", "bar", "waldo", "piep", "pap", "after");
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "a{yv}", 2, 3, "s", "foo", 5, "s", "waldo");
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "ba(ss)", 255, 3, "aaa", "1", "bbb", "2", "ccc", "3");
        assert_se(r >= 0);

        r = sd_bus_message_open_container(m, 'a', "s");
        assert_se(r >= 0);

        r = sd_bus_message_append_basic(m, 's', "foobar");
        assert_se(r >= 0);

        r = sd_bus_message_append_basic(m, 's', "waldo");
        assert_se(r >= 0);

        r = sd_bus_message_close_container(m);
        assert_se(r >= 0);

        r = bus_message_seal(m, 4711);
        assert_se(r >= 0);

        bus_message_dump(m);

        r = bus_message_get_blob(m, &buffer, &sz);
        assert_se(r >= 0);

        h = hexmem(buffer, sz);
        assert_se(h);

        log_info("message size = %lu, contents =\n%s", (unsigned long) sz, h);
        free(h);

#ifdef HAVE_GLIB
        {
                GDBusMessage *g;
                char *p;

#if !defined(GLIB_VERSION_2_36)
                g_type_init();
#endif

                g = g_dbus_message_new_from_blob(buffer, sz, 0, NULL);
                p = g_dbus_message_print(g, 0);
                log_info("%s", p);
                g_free(p);
                g_object_unref(g);
        }
#endif

        {
                DBusMessage *w;
                DBusError error;

                dbus_error_init(&error);

                w = dbus_message_demarshal(buffer, sz, &error);
                if (!w) {
                        log_error("%s", error.message);
                } else
                        dbus_message_unref(w);
        }

        m = sd_bus_message_unref(m);

        r = bus_message_from_malloc(buffer, sz, NULL, 0, NULL, NULL, &m);
        assert_se(r >= 0);

        bus_message_dump(m);

        assert_se(sd_bus_message_rewind(m, true) >= 0);

        r = sd_bus_message_read(m, "sas", &x, 2, &y, &z);
        assert_se(r > 0);
        assert_se(streq(x, "a string"));
        assert_se(streq(y, "string #1"));
        assert_se(streq(z, "string #2"));

        r = sd_bus_message_read(m, "sass", &x, 5, &y, &z, &a, &b, &c, &d);
        assert_se(r > 0);
        assert_se(streq(x, "foobar"));
        assert_se(streq(y, "foo"));
        assert_se(streq(z, "bar"));
        assert_se(streq(a, "waldo"));
        assert_se(streq(b, "piep"));
        assert_se(streq(c, "pap"));
        assert_se(streq(d, "after"));

        r = sd_bus_message_read(m, "a{yv}", 2, &u, "s", &x, &v, "s", &y);
        assert_se(r > 0);
        assert_se(u == 3);
        assert_se(streq(x, "foo"));
        assert_se(v == 5);
        assert_se(streq(y, "waldo"));

        r = sd_bus_message_read(m, "ba(ss)", &boolean, 3, &x, &y, &a, &b, &c, &d);
        assert_se(r > 0);
        assert_se(boolean);
        assert_se(streq(x, "aaa"));
        assert_se(streq(y, "1"));
        assert_se(streq(a, "bbb"));
        assert_se(streq(b, "2"));
        assert_se(streq(c, "ccc"));
        assert_se(streq(d, "3"));

        r = sd_bus_message_read(m, "as", 2, &x, &y);
        assert_se(r > 0);
        assert_se(streq(x, "foobar"));
        assert_se(streq(y, "waldo"));

        r = sd_bus_message_peek_type(m, NULL, NULL);
        assert_se(r == 0);

        return 0;
}
