/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-internal.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static void test_one_address(sd_bus *b,
                             const char *host,
                             int result, const char *expected) {
        int r;

        r = bus_set_address_system_remote(b, host);
        log_info("\"%s\" → %d, \"%s\"", host, r, strna(r >= 0 ? b->address : NULL));
        assert_se(r == result);
        if (r >= 0)
                assert_se(streq_ptr(b->address, expected));
}

TEST(bus_set_address_system_remote) {
        _cleanup_(sd_bus_unrefp) sd_bus *b = NULL;

        assert_se(sd_bus_new(&b) >= 0);
        if (!strv_isempty(saved_argv + 1)) {
                STRV_FOREACH(a, saved_argv + 1)
                        test_one_address(b, *a, 0, NULL);
                return;
        };

        test_one_address(b, "host",
                         0, "unixexec:path=ssh,argv1=-xT,argv2=--,argv3=host,argv4=systemd-stdio-bridge");
        test_one_address(b, "host:123",
                         0, "unixexec:path=ssh,argv1=-xT,argv2=-p,argv3=123,argv4=--,argv5=host,argv6=systemd-stdio-bridge");
        test_one_address(b, "host:123:123",
                         -EINVAL, NULL);
        test_one_address(b, "host:",
                         -EINVAL, NULL);
        test_one_address(b, "user@host",
                         0, "unixexec:path=ssh,argv1=-xT,argv2=--,argv3=user%40host,argv4=systemd-stdio-bridge");
        test_one_address(b, "user@host@host",
                         -EINVAL, NULL);
        test_one_address(b, "[::1]",
                         0, "unixexec:path=ssh,argv1=-xT,argv2=--,argv3=%3a%3a1,argv4=systemd-stdio-bridge");
        test_one_address(b, "user@[::1]",
                         0, "unixexec:path=ssh,argv1=-xT,argv2=--,argv3=user%40%3a%3a1,argv4=systemd-stdio-bridge");
        test_one_address(b, "user@[::1]:99",
                         0, "unixexec:path=ssh,argv1=-xT,argv2=-p,argv3=99,argv4=--,argv5=user%40%3a%3a1,argv6=systemd-stdio-bridge");
        test_one_address(b, "user@[::1]:",
                         -EINVAL, NULL);
        test_one_address(b, "user@[::1:",
                         -EINVAL, NULL);
        test_one_address(b, "user@",
                         -EINVAL, NULL);
        test_one_address(b, "user@@",
                         -EINVAL, NULL);
}

DEFINE_TEST_MAIN(LOG_INFO);
