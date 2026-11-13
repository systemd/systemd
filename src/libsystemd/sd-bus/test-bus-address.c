/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"

#include "argv-util.h"
#include "bus-internal.h"
#include "fd-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "log.h"
#include "process-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_one_address(sd_bus *b,
                             const char *host,
                             int result, const char *expected) {
        int r;

        r = bus_set_address_system_remote(b, host);
        log_info("\"%s\" → %d, \"%s\"", host, r, strna(r >= 0 ? b->address : NULL));
        ASSERT_EQ(r, result);
        if (r >= 0)
                ASSERT_STREQ(b->address, expected);
}

TEST(bus_set_address_system_remote) {
        _cleanup_(sd_bus_unrefp) sd_bus *b = NULL;

        ASSERT_OK(sd_bus_new(&b));
        if (!strv_isempty(saved_argv + 1)) {
                STRV_FOREACH(a, saved_argv + 1)
                        test_one_address(b, *a, /* result= */ 0, /* expected= */ NULL);
                return;
        };

        test_one_address(b, "host",
                         /* result= */ 0, "unixexec:path=ssh,argv1=-xT,argv2=--,argv3=host,argv4=systemd-stdio-bridge");
        test_one_address(b, "host:123",
                         /* result= */ 0, "unixexec:path=ssh,argv1=-xT,argv2=-p,argv3=123,argv4=--,argv5=host,argv6=systemd-stdio-bridge");
        test_one_address(b, "host:123:123",
                         -EINVAL, /* expected= */ NULL);
        test_one_address(b, "host:",
                         -EINVAL, /* expected= */ NULL);
        test_one_address(b, "user@host",
                         /* result= */ 0, "unixexec:path=ssh,argv1=-xT,argv2=--,argv3=user%40host,argv4=systemd-stdio-bridge");
        test_one_address(b, "user@host@host",
                         -EINVAL, /* expected= */ NULL);
        test_one_address(b, "[::1]",
                         /* result= */ 0, "unixexec:path=ssh,argv1=-xT,argv2=--,argv3=%3a%3a1,argv4=systemd-stdio-bridge");
        test_one_address(b, "user@[::1]",
                         /* result= */ 0, "unixexec:path=ssh,argv1=-xT,argv2=--,argv3=user%40%3a%3a1,argv4=systemd-stdio-bridge");
        test_one_address(b, "user@[::1]:99",
                         /* result= */ 0, "unixexec:path=ssh,argv1=-xT,argv2=-p,argv3=99,argv4=--,argv5=user%40%3a%3a1,argv6=systemd-stdio-bridge");
        test_one_address(b, "user@[::1]:",
                         -EINVAL, /* expected= */ NULL);
        test_one_address(b, "user@[::1:",
                         -EINVAL, /* expected= */ NULL);
        test_one_address(b, "user@",
                         -EINVAL, /* expected= */ NULL);
        test_one_address(b, "user@@",
                         -EINVAL, /* expected= */ NULL);
}

static int transport_error_callback(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        int *error = ASSERT_PTR(userdata);

        *error = -sd_bus_message_get_errno(m);
        return 1;
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
                { "malformed", -ESRCH },
        };

        unsigned mode;
        FOREACH_ELEMENT(c, cases)
                FOREACH_ARGUMENT(mode, 0U, 1U, 2U) {
                        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
                        _cleanup_free_ char *address = NULL, *notify_dir = NULL, *notify_path = NULL;
                        struct stat st;
                        const char *unique;

                        address = strjoin("unixexec:path=/proc/self/exe,argv1=--notify-test,argv2=", c->notification);
                        ASSERT_NOT_NULL(address);
                        ASSERT_OK(sd_bus_new(&bus));
                        ASSERT_OK(sd_bus_set_address(bus, address));
                        ASSERT_OK(sd_bus_set_bus_client(bus, true));
                        ASSERT_OK(sd_bus_start(bus));
                        notify_dir = strdup(bus->busexec_notify_dir);
                        notify_path = strdup(bus->busexec_notify_path);
                        ASSERT_NOT_NULL(notify_dir);
                        ASSERT_NOT_NULL(notify_path);
                        ASSERT_OK_ERRNO(stat(notify_dir, &st));
                        ASSERT_EQ(st.st_mode & 0777U, 0700U);

                        if (mode == 2) {
                                int error = -EINPROGRESS;

                                ASSERT_OK(sd_bus_call_method_async(bus, /* ret_slot= */ NULL,
                                                                  "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                                                  "org.freedesktop.DBus", "ListNames",
                                                                  transport_error_callback, &error, /* types= */ NULL));
                                while (error == -EINPROGRESS) {
                                        int r = sd_bus_process(bus, /* ret= */ NULL);
                                        ASSERT_OK(r);
                                        if (r == 0)
                                                ASSERT_OK(sd_bus_wait(bus, USEC_PER_SEC));
                                }
                                ASSERT_EQ(error, c->expected == -ENOTCONN ? -ECONNRESET : c->expected);
                        } else if (mode == 1)
                                ASSERT_ERROR(sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                                                "org.freedesktop.DBus", "ListNames",
                                                                /* reterr_error= */ NULL, /* ret_reply= */ NULL,
                                                                /* types= */ NULL), -c->expected);
                        else
                                ASSERT_ERROR(sd_bus_get_unique_name(bus, &unique), -c->expected);
                        sd_bus_close(bus);
                        ASSERT_ERROR_ERRNO(access(notify_path, F_OK), ENOENT);
                        ASSERT_ERROR_ERRNO(access(notify_dir, F_OK), ENOENT);
                }
}

TEST(unixexec_notify_unavailable) {
        _cleanup_(rmdir_and_freep) char *long_dir = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-bus-notify-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-XXXXXX", &long_dir));

        FOREACH_STRING(tmp, "/proc", long_dir) {
                int r = ASSERT_OK(pidref_safe_fork("(test-notify-unavailable)", FORK_WAIT, /* ret= */ NULL));
                if (r > 0)
                        continue;

                _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
                const char *unique;

                ASSERT_OK_ERRNO(setenv("TMPDIR", tmp, /* overwrite= */ true));
                ASSERT_OK_ERRNO(setenv("NOTIFY_SOCKET", "/unrelated-supervisor", /* overwrite= */ true));
                ASSERT_OK(sd_bus_new(&bus));
                ASSERT_OK(sd_bus_set_address(bus, "unixexec:path=/proc/self/exe,argv1=--notify-test,argv2=no-notify"));
                ASSERT_OK(sd_bus_set_bus_client(bus, true));
                ASSERT_OK(sd_bus_start(bus));
                ASSERT_LT(bus->busexec_notify_fd, 0);
                ASSERT_NULL(bus->busexec_notify_path);
                ASSERT_NULL(bus->busexec_notify_dir);
                ASSERT_ERROR(sd_bus_get_unique_name(bus, &unique), ENOTCONN);
                sd_bus_close(bus);
                _exit(EXIT_SUCCESS);
        }
}

TEST(unixexec_notify_cleanup_on_kill) {
        _cleanup_close_pair_ int pipe_fds[2] = EBADF_PAIR;
        _cleanup_free_ char *notify_dir = NULL;
        PidRef child = PIDREF_NULL;
        char buffer[PATH_MAX];
        size_t n = 0;
        int r;

        ASSERT_OK_ERRNO(pipe2(pipe_fds, O_CLOEXEC));
        r = pidref_safe_fork("(test-bus-notify-cleanup)", /* flags= */ 0, &child);
        ASSERT_OK(r);
        if (r == 0) {
                _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;

                pipe_fds[0] = safe_close(pipe_fds[0]);
                ASSERT_OK(sd_bus_new(&bus));
                ASSERT_OK(sd_bus_set_address(bus, "unixexec:path=/proc/self/exe,argv1=--notify-test,argv2=wait"));
                ASSERT_OK(sd_bus_set_bus_client(bus, true));
                ASSERT_OK(sd_bus_start(bus));
                ASSERT_NOT_NULL(bus->busexec_notify_dir);
                ASSERT_OK_ERRNO(write(pipe_fds[1], bus->busexec_notify_dir, strlen(bus->busexec_notify_dir)));
                ASSERT_OK_ERRNO(write(pipe_fds[1], "\n", 1));
                for (;;)
                        pause();
        }

        pipe_fds[1] = safe_close(pipe_fds[1]);
        for (;;) {
                char c;

                ASSERT_EQ(read(pipe_fds[0], &c, 1), 1);
                if (c == '\n')
                        break;
                ASSERT_LT(n, sizeof(buffer) - 1);
                buffer[n++] = c;
        }
        buffer[n] = 0;
        notify_dir = strdup(buffer);
        ASSERT_NOT_NULL(notify_dir);
        ASSERT_OK_ERRNO(access(notify_dir, F_OK));

        ASSERT_OK(pidref_kill(&child, SIGKILL));
        ASSERT_OK(pidref_wait_for_terminate(&child, /* ret_si= */ NULL));
        pidref_done(&child);

        usec_t until = usec_add(now(CLOCK_MONOTONIC), USEC_PER_SEC);
        while (access(notify_dir, F_OK) >= 0 && now(CLOCK_MONOTONIC) < until)
                (void) sleep_usec(10 * USEC_PER_MSEC);
        ASSERT_ERROR_ERRNO(access(notify_dir, F_OK), ENOENT);
}

static int intro(void) {
        if (strv_length(saved_argv) == 3 && streq(saved_argv[1], "--notify-test")) {
                char byte;

                /* Wait for the initial authentication write before closing the transport, so sd_bus_start()
                 * cannot race with our exit and fail with EPIPE. */
                ASSERT_OK(loop_read_exact(STDIN_FILENO, &byte, sizeof(byte), /* do_poll= */ true));

                if (streq(saved_argv[2], "no-notify"))
                        ASSERT_NULL(getenv("NOTIFY_SOCKET"));
                else if (streq(saved_argv[2], "spoof")) {
                        pid_t pid;

                        pid = fork();
                        ASSERT_GE(pid, 0);
                        if (pid == 0) {
                                ASSERT_OK_POSITIVE(sd_notify(/* unset_environment= */ false, "ERRNO=3"));
                                _exit(EXIT_SUCCESS);
                        }
                        ASSERT_EQ(waitpid(pid, NULL, 0), pid);
                } else if (streq(saved_argv[2], "malformed")) {
                        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
                        union sockaddr_union sa;
                        int size;

                        ASSERT_OK_ERRNO(fd);
                        ASSERT_OK(size = sockaddr_un_set_path(&sa.un, ASSERT_PTR(getenv("NOTIFY_SOCKET"))));
                        static const char malformed[] = "ERRNO=13\0ERRNO=3";
                        ASSERT_EQ(sendto(fd, malformed, sizeof(malformed) - 1, 0, &sa.sa, size),
                                  (ssize_t) sizeof(malformed) - 1);
                        ASSERT_OK_POSITIVE(sd_notify(/* unset_environment= */ false, "ERRNO=3"));
                } else if (streq(saved_argv[2], "wait")) {
                        while (read(STDIN_FILENO, &byte, sizeof(byte)) > 0)
                                ;
                        _exit(EXIT_SUCCESS);
                } else
                        ASSERT_OK_POSITIVE(sd_notify(/* unset_environment= */ false, saved_argv[2]));
                _exit(EXIT_FAILURE);
        }

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
