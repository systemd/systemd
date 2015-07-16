/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 David Herrmann <dh.herrmann@gmail.com>

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
#include <fcntl.h>
#include <stdlib.h>

#include "util.h"
#include "log.h"

#include "sd-bus.h"
#include "bus-kernel.h"
#include "bus-util.h"
#include "bus-dump.h"

typedef struct {
        const char *sender;
        int matched_acquired;
} TestProxyMatch;

static int test_proxy_acquired(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        TestProxyMatch *match = userdata;
        const char *name;
        int r;

        r = sd_bus_message_read(m, "s", &name);
        assert_se(r >= 0);

        if (!streq_ptr(match->sender, name))
                return 0;

        ++match->matched_acquired;
        return 1;
}

static void test_proxy_matched(void) {
        _cleanup_bus_flush_close_unref_ sd_bus *a = NULL;
        TestProxyMatch match = {};
        int r;

        /* open bus 'a' */

        r = sd_bus_new(&a);
        assert_se(r >= 0);

        r = sd_bus_set_address(a, "unix:path=/var/run/dbus/system_bus_socket");
        assert_se(r >= 0);

        r = sd_bus_set_bus_client(a, true);
        assert_se(r >= 0);

        r = sd_bus_start(a);
        assert_se(r >= 0);

        r = sd_bus_add_match(a, NULL,
                             "type='signal',"
                             "member='NameAcquired'",
                             test_proxy_acquired, &match);
        assert_se(r >= 0);

        r = sd_bus_get_unique_name(a, &match.sender);
        assert_se(r >= 0);

        /* barrier to guarantee proxy/dbus-daemon handled the previous data  */
        r = sd_bus_call_method(a,
                               "org.freedesktop.DBus",
                               "/org/freedesktop/DBus",
                               "org.freedesktop.DBus",
                               "GetId",
                               NULL, NULL, NULL);
        assert_se(r >= 0);

        /* now we can be sure the Name* signals were sent */
        do {
                r = sd_bus_process(a, NULL);
        } while (r > 0);
        assert_se(r == 0);

        assert_se(match.matched_acquired == 1);
}

int main(int argc, char **argv) {
        if (access("/var/run/dbus/system_bus_socket", F_OK) < 0)
                return EXIT_TEST_SKIP;

        log_parse_environment();

        test_proxy_matched();

        return EXIT_SUCCESS;
}
