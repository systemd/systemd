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

#include "util.h"
#include "log.h"

#include "sd-bus.h"
#include "bus-message.h"
#include "bus-error.h"
#include "bus-kernel.h"
#include "bus-util.h"

static void test_one(
                const char *path,
                const char *interface,
                const char *member,
                const char *arg0,
                const char *match,
                bool good) {

        _cleanup_close_ int bus_ref = -1;
        _cleanup_free_ char *name = NULL, *bus_name = NULL, *address = NULL;
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        sd_bus *a, *b;
        int r;

        assert_se(asprintf(&name, "deine-mutter-%u", (unsigned) getpid()) >= 0);

        bus_ref = bus_kernel_create_bus(name, false, &bus_name);
        if (bus_ref == -ENOENT)
                exit(EXIT_TEST_SKIP);

        assert_se(bus_ref >= 0);

        address = strappend("kernel:path=", bus_name);
        assert_se(address);

        r = sd_bus_new(&a);
        assert_se(r >= 0);

        r = sd_bus_new(&b);
        assert_se(r >= 0);

        r = sd_bus_set_address(a, address);
        assert_se(r >= 0);

        r = sd_bus_set_address(b, address);
        assert_se(r >= 0);

        r = sd_bus_start(a);
        assert_se(r >= 0);

        r = sd_bus_start(b);
        assert_se(r >= 0);

        log_debug("match");
        r = sd_bus_add_match(b, NULL, match, NULL, NULL);
        assert_se(r >= 0);

        log_debug("signal");
        r = sd_bus_emit_signal(a, path, interface, member, "s", arg0);
        assert_se(r >= 0);

        r = sd_bus_process(b, &m);
        assert_se(r >= 0 && (good == !!m));

        sd_bus_unref(a);
        sd_bus_unref(b);
}

int main(int argc, char *argv[]) {
        log_set_max_level(LOG_DEBUG);

        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "", true);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path='/foo/bar/waldo'", true);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path='/foo/bar/waldo/tuut'", false);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "interface='waldo.com'", true);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "member='Piep'", true);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "member='Pi_ep'", false);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "arg0='foobar'", true);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "arg0='foo_bar'", false);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path='/foo/bar/waldo',interface='waldo.com',member='Piep',arg0='foobar'", true);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path='/foo/bar/waldo',interface='waldo.com',member='Piep',arg0='foobar2'", false);

        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path='/foo/bar/waldo'", true);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path='/foo/bar'", false);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path='/foo'", false);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path='/'", false);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path='/foo/bar/waldo/quux'", false);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path_namespace='/foo/bar/waldo'", true);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path_namespace='/foo/bar'", true);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path_namespace='/foo'", true);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path_namespace='/'", true);
        test_one("/foo/bar/waldo", "waldo.com", "Piep", "foobar", "path_namespace='/quux'", false);

        return 0;
}
