/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Daniel Mack

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

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/poll.h>
#include <stddef.h>
#include <getopt.h>

#include "log.h"
#include "util.h"
#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-util.h"
#include "bus-internal.h"
#include "build.h"
#include "strv.h"
#include "def.h"
#include "capability.h"

#include <bus-proxyd/bus-policy.h>

static int make_name_request(sd_bus *bus,
                             const char *name,
                             sd_bus_message **ret) {

        int r;
        sd_bus_message *m = NULL;

        r = sd_bus_message_new_method_call(bus, &m, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName");
        if (r < 0)
                return r;

        r = sd_bus_message_append_basic(m, 's', name);
        if (r < 0)
                return r;

        m->sealed = 1;
        sd_bus_message_rewind(m, true);

        *ret = m;
        return 0;
}

int main(int argc, char *argv[]) {

        Policy p = {};
        sd_bus_message *m;
        struct ucred ucred = {};
        _cleanup_bus_close_unref_ sd_bus *bus = NULL;;

        assert_se(sd_bus_default_system(&bus) >= 0);

        /* Fake pid for policy checks */
        ucred.pid = 1;

        /* Ownership tests */
        assert_se(policy_load(&p, STRV_MAKE("test/bus-policy/ownerships.conf")) == 0);

        assert_se(make_name_request(bus, "org.test.test1", &m) == 0);
        ucred.uid = 0;
        assert_se(policy_check(&p, m, &ucred) == true);
        ucred.uid = 1;
        assert_se(policy_check(&p, m, &ucred) == true);
        assert_se(sd_bus_message_unref(m) == 0);

        assert_se(make_name_request(bus, "org.test.test2", &m) == 0);
        ucred.uid = 0;
        assert_se(policy_check(&p, m, &ucred) == true);
        ucred.uid = 1;
        assert_se(policy_check(&p, m, &ucred) == false);
        assert_se(sd_bus_message_unref(m) == 0);

        assert_se(make_name_request(bus, "org.test.test3", &m) == 0);
        ucred.uid = 0;
        assert_se(policy_check(&p, m, &ucred) == false);
        ucred.uid = 1;
        assert_se(policy_check(&p, m, &ucred) == false);
        assert_se(sd_bus_message_unref(m) == 0);

        assert_se(make_name_request(bus, "org.test.test4", &m) == 0);
        ucred.uid = 0;
        assert_se(policy_check(&p, m, &ucred) == false);
        ucred.uid = 1;
        assert_se(policy_check(&p, m, &ucred) == true);
        assert_se(sd_bus_message_unref(m) == 0);

        policy_free(&p);

        /* Signal test */
        assert_se(policy_load(&p, STRV_MAKE("test/bus-policy/signals.conf")) == 0);

        assert_se(sd_bus_message_new_signal(bus, &m, "/an/object/path", "bli.bla.blubb", "Name") == 0);
        ucred.uid = 0;
        assert_se(policy_check(&p, m, &ucred) == true);

        ucred.uid = 1;
        assert_se(policy_check(&p, m, &ucred) == false);
        assert_se(sd_bus_message_unref(m) == 0);

        policy_free(&p);

        /* Method calls */
        assert_se(policy_load(&p, STRV_MAKE("test/bus-policy/methods.conf")) == 0);

        ucred.uid = 0;
        assert_se(sd_bus_message_new_method_call(bus, &m, "org.foo.bar", "/an/object/path", "bli.bla.blubb", "Member") == 0);
        assert_se(policy_check(&p, m, &ucred) == false);

        assert_se(sd_bus_message_new_method_call(bus, &m, "org.test.test1", "/an/object/path", "bli.bla.blubb", "Member") == 0);
        assert_se(policy_check(&p, m, &ucred) == false);

        bus->is_kernel = 1;
        assert_se(sd_bus_message_new_method_call(bus, &m, "org.test.test1", "/an/object/path", "org.test.int1", "Member") == 0);
        assert_se(policy_check(&p, m, &ucred) == true);

        assert_se(sd_bus_message_new_method_call(bus, &m, "org.test.test1", "/an/object/path", "org.test.int2", "Member") == 0);
        assert_se(policy_check(&p, m, &ucred) == true);

        policy_free(&p);

        /* User and groups */
        assert_se(policy_load(&p, STRV_MAKE("test/bus-policy/hello.conf")) == 0);
        assert_se(sd_bus_message_new_method_call(bus, &m, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello") == 0);
        policy_dump(&p);

        ucred.uid = 0;
        assert_se(policy_check(&p, m, &ucred) == true);

        ucred.uid = 1;
        assert_se(policy_check(&p, m, &ucred) == false);

        ucred.uid = 0;
        ucred.gid = 1;
        assert_se(policy_check(&p, m, &ucred) == false);

        policy_free(&p);


        return EXIT_SUCCESS;
}
