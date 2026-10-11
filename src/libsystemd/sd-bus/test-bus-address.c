/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/wait.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"

#include "argv-util.h"
#include "bus-internal.h"
#include "io-util.h"
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

TEST(unixexec_errno) {
        static const struct {
                const char *notification;
                int expected;
        } cases[] = {
                { "ERRNO=3", -ESRCH },
                { "READY=1%0aERRNO=13", -EACCES },
                { "ERRNO=0", -ENOTCONN },
                { "ERRNO=-3", -ENOTCONN },
                { "ERRNO=invalid", -ENOTCONN },
                { "READY=1", -ENOTCONN },
                { "ERRNO=4096", -ENOTCONN },
                { "spoof", -ENOTCONN },
        };

        FOREACH_ELEMENT(c, cases) {
                _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
                _cleanup_free_ char *address = NULL;
                const char *unique;

                address = strjoin("unixexec:path=/proc/self/exe,argv1=--notify-test,argv2=", c->notification);
                ASSERT_NOT_NULL(address);
                ASSERT_OK(sd_bus_new(&bus));
                ASSERT_OK(sd_bus_set_address(bus, address));
                ASSERT_OK(sd_bus_set_bus_client(bus, true));
                ASSERT_OK(sd_bus_start(bus));
                ASSERT_ERROR(sd_bus_get_unique_name(bus, &unique), -c->expected);
        }
}

static int intro(void) {
        if (strv_length(saved_argv) == 3 && streq(saved_argv[1], "--notify-test")) {
                char byte;

                /* Wait for the initial authentication write before closing the transport, so sd_bus_start()
                 * cannot race with our exit and fail with EPIPE. */
                ASSERT_OK(loop_read_exact(STDIN_FILENO, &byte, sizeof(byte), /* do_poll= */ true));

                if (streq(saved_argv[2], "spoof")) {
                        pid_t pid;

                        pid = fork();
                        ASSERT_GE(pid, 0);
                        if (pid == 0) {
                                ASSERT_OK_POSITIVE(sd_notify(/* unset_environment= */ false, "ERRNO=3"));
                                _exit(EXIT_SUCCESS);
                        }
                        ASSERT_EQ(waitpid(pid, NULL, 0), pid);
                } else
                        ASSERT_OK_POSITIVE(sd_notify(/* unset_environment= */ false, saved_argv[2]));
                _exit(EXIT_FAILURE);
        }

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
