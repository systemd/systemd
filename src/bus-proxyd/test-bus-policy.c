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
#include "build.h"
#include "strv.h"
#include "def.h"
#include "capability.h"

#include <bus-proxyd/bus-policy.h>

static int test_policy_load(Policy *p, const char *name)
{
        _cleanup_free_ char *path = NULL;
        int r = 0;

        path = strjoin(TEST_DIR, "/bus-policy/", name, NULL);
        assert_se(path);

        if (access(path, R_OK) == 0)
                policy_load(p, STRV_MAKE(path));
        else
                r = -ENOENT;

        return r;
}

int main(int argc, char *argv[]) {

        Policy p = {};
        struct ucred ucred = {};

        /* Ownership tests */
        assert_se(test_policy_load(&p, "ownerships.conf") == 0);

        ucred.uid = 0;
        assert_se(policy_check_own(&p, &ucred, "org.test.test1") == true);
        ucred.uid = 1;
        assert_se(policy_check_own(&p, &ucred, "org.test.test1") == true);

        ucred.uid = 0;
        assert_se(policy_check_own(&p, &ucred, "org.test.test2") == true);
        ucred.uid = 1;
        assert_se(policy_check_own(&p, &ucred, "org.test.test2") == false);

        ucred.uid = 0;
        assert_se(policy_check_own(&p, &ucred, "org.test.test3") == false);
        ucred.uid = 1;
        assert_se(policy_check_own(&p, &ucred, "org.test.test3") == false);

        ucred.uid = 0;
        assert_se(policy_check_own(&p, &ucred, "org.test.test4") == false);
        ucred.uid = 1;
        assert_se(policy_check_own(&p, &ucred, "org.test.test4") == true);

        policy_free(&p);

        /* Signaltest */
        assert_se(test_policy_load(&p, "signals.conf") == 0);

        ucred.uid = 0;
        assert_se(policy_check_send(&p, &ucred, SD_BUS_MESSAGE_SIGNAL, "bli.bla.blubb", NULL, "/an/object/path", NULL) == true);

        ucred.uid = 1;
        assert_se(policy_check_send(&p, &ucred, SD_BUS_MESSAGE_SIGNAL, "bli.bla.blubb", NULL, "/an/object/path", NULL) == false);

        policy_free(&p);

        /* Method calls */
        assert_se(test_policy_load(&p, "methods.conf") == 0);
        policy_dump(&p);

        ucred.uid = 0;

        assert_se(policy_check_send(&p, &ucred, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test1", "/an/object/path", "bli.bla.blubb", "Member") == false);
        assert_se(policy_check_send(&p, &ucred, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test1", "/an/object/path", "bli.bla.blubb", "Member") == false);
        assert_se(policy_check_send(&p, &ucred, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test1", "/an/object/path", "org.test.int1", "Member") == true);
        assert_se(policy_check_send(&p, &ucred, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test1", "/an/object/path", "org.test.int2", "Member") == true);

        assert_se(policy_check_recv(&p, &ucred, SD_BUS_MESSAGE_METHOD_CALL, "org.test.test3", "/an/object/path", "org.test.int3", "Member111") == true);

        policy_free(&p);

        /* User and groups */
        assert_se(test_policy_load(&p, "hello.conf") == 0);
        policy_dump(&p);

        ucred.uid = 0;
        assert_se(policy_check_hello(&p, &ucred) == true);

        ucred.uid = 1;
        assert_se(policy_check_hello(&p, &ucred) == false);

        ucred.uid = 0;
        ucred.gid = 1;
        assert_se(policy_check_hello(&p, &ucred) == false);

        policy_free(&p);

        return EXIT_SUCCESS;
}
