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

#include <errno.h>
#include <stddef.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-xml-policy.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static int test_policy_load(Policy *p, const char *name) {
        _cleanup_free_ char *path = NULL;
        int r = 0;

        path = strjoin(TEST_DIR, "/bus-policy/", name, NULL);
        assert_se(path);

        if (access(path, R_OK) == 0)
                r = policy_load(p, STRV_MAKE(path));
        else
                r = -ENOENT;

        return r;
}

static int show_policy(const char *fn) {
        Policy p = {};
        int r;

        r = policy_load(&p, STRV_MAKE(fn));
        if (r < 0) {
                log_error_errno(r, "Failed to load policy %s: %m", fn);
                return r;
        }

        policy_dump(&p);
        policy_free(&p);

        return 0;
}

int main(int argc, char *argv[]) {

        Policy p = {};

        printf("Showing session policy BEGIN\n");
        show_policy("/etc/dbus-1/session.conf");
        printf("Showing session policy END\n");

        printf("Showing system policy BEGIN\n");
        show_policy("/etc/dbus-1/system.conf");
        printf("Showing system policy END\n");

        /* Ownership tests */
        assert_se(test_policy_load(&p, "ownerships.conf") == 0);

        assert_se(policy_check_own(&p, 0, 0, "org.test.test1") == true);
        assert_se(policy_check_own(&p, 1, 0, "org.test.test1") == true);

        assert_se(policy_check_own(&p, 0, 0, "org.test.test2") == true);
        assert_se(policy_check_own(&p, 1, 0, "org.test.test2") == false);

        assert_se(policy_check_own(&p, 0, 0, "org.test.test3") == false);
        assert_se(policy_check_own(&p, 1, 0, "org.test.test3") == false);

        assert_se(policy_check_own(&p, 0, 0, "org.test.test4") == false);
        assert_se(policy_check_own(&p, 1, 0, "org.test.test4") == true);

        policy_free(&p);

        /* Signaltest */
        assert_se(test_policy_load(&p, "signals.conf") == 0);

        assert_se(policy_check_one_send(&p, 0, 0, SD_BUS_MESSAGE_SIGNAL, "bli.bla.blubb", NULL, "/an/object/path", NULL) == true);
        assert_se(policy_check_one_send(&p, 1, 0, SD_BUS_MESSAGE_SIGNAL, "bli.bla.blubb", NULL, "/an/object/path", NULL) == false);

        policy_free(&p);

        /* Method calls */
        assert_se(test_policy_load(&p, "methods.conf") == 0);
        policy_dump(&p);

        assert_se(policy_check_one_send(&p, 0, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test1", "/an/object/path", "bli.bla.blubb", "Member") == false);
        assert_se(policy_check_one_send(&p, 0, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test1", "/an/object/path", "bli.bla.blubb", "Member") == false);
        assert_se(policy_check_one_send(&p, 0, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test1", "/an/object/path", "org.test.int1", "Member") == true);
        assert_se(policy_check_one_send(&p, 0, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test1", "/an/object/path", "org.test.int2", "Member") == true);

        assert_se(policy_check_one_recv(&p, 0, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test3", "/an/object/path", "org.test.int3", "Member111") == true);

        policy_free(&p);

        /* User and groups */
        assert_se(test_policy_load(&p, "hello.conf") == 0);
        policy_dump(&p);

        assert_se(policy_check_hello(&p, 0, 0) == true);
        assert_se(policy_check_hello(&p, 1, 0) == false);
        assert_se(policy_check_hello(&p, 0, 1) == false);

        policy_free(&p);

        /* dbus1 test file: ownership */

        assert_se(test_policy_load(&p, "check-own-rules.conf") >= 0);
        policy_dump(&p);

        assert_se(policy_check_own(&p, 0, 0, "org.freedesktop") == false);
        assert_se(policy_check_own(&p, 0, 0, "org.freedesktop.ManySystem") == false);
        assert_se(policy_check_own(&p, 0, 0, "org.freedesktop.ManySystems") == true);
        assert_se(policy_check_own(&p, 0, 0, "org.freedesktop.ManySystems.foo") == true);
        assert_se(policy_check_own(&p, 0, 0, "org.freedesktop.ManySystems.foo.bar") == true);
        assert_se(policy_check_own(&p, 0, 0, "org.freedesktop.ManySystems2") == false);
        assert_se(policy_check_own(&p, 0, 0, "org.freedesktop.ManySystems2.foo") == false);
        assert_se(policy_check_own(&p, 0, 0, "org.freedesktop.ManySystems2.foo.bar") == false);

        policy_free(&p);

        /* dbus1 test file: many rules */

        assert_se(test_policy_load(&p, "many-rules.conf") >= 0);
        policy_dump(&p);
        policy_free(&p);

        /* dbus1 test file: generic test */

        assert_se(test_policy_load(&p, "test.conf") >= 0);
        policy_dump(&p);

        assert_se(policy_check_own(&p, 0, 0, "org.foo.FooService") == true);
        assert_se(policy_check_own(&p, 0, 0, "org.foo.FooService2") == false);
        assert_se(policy_check_one_send(&p, 0, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test1", "/an/object/path", "org.test.int2", "Member") == false);
        assert_se(policy_check_one_send(&p, 0, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test1", "/an/object/path", "org.foo.FooBroadcastInterface", "Member") == true);
        assert_se(policy_check_one_recv(&p, 0, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.foo.FooService", "/an/object/path", "org.foo.FooBroadcastInterface", "Member") == true);
        assert_se(policy_check_one_recv(&p, 0, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.foo.FooService", "/an/object/path", "org.foo.FooBroadcastInterface2", "Member") == false);
        assert_se(policy_check_one_recv(&p, 0, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.foo.FooService2", "/an/object/path", "org.foo.FooBroadcastInterface", "Member") == false);

        assert_se(policy_check_own(&p, 100, 0, "org.foo.FooService") == false);
        assert_se(policy_check_own(&p, 100, 0, "org.foo.FooService2") == false);
        assert_se(policy_check_one_send(&p, 100, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test1", "/an/object/path", "org.test.int2", "Member") == false);
        assert_se(policy_check_one_send(&p, 100, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test1", "/an/object/path", "org.foo.FooBroadcastInterface", "Member") == false);
        assert_se(policy_check_one_recv(&p, 100, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.foo.FooService", "/an/object/path", "org.foo.FooBroadcastInterface", "Member") == true);
        assert_se(policy_check_one_recv(&p, 100, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.foo.FooService", "/an/object/path", "org.foo.FooBroadcastInterface2", "Member") == false);
        assert_se(policy_check_one_recv(&p, 100, 0, SD_BUS_MESSAGE_METHOD_CALL, "org.foo.FooService2", "/an/object/path", "org.foo.FooBroadcastInterface", "Member") == false);

        policy_free(&p);

        return EXIT_SUCCESS;
}
