/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <unistd.h>

#include "sd-bus.h"

#include "bus-dump.h"
#include "fd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "socket-util.h"
#include "tests.h"
#include "user-util.h"

static bool gid_list_contained(const gid_t *a, size_t n, const gid_t *b, size_t m) {
        ASSERT_TRUE(a || n == 0);
        ASSERT_TRUE(b || m == 0);

        /* Checks if every entry in a[] is also in b[] */

        for (size_t i = 0; i < n; i++) {
                size_t j;

                for (j = 0; j < m; j++)
                        if (a[i] == b[j])
                                break;

                if (j >= m)
                        return false;
        }

        return true;
}

static bool gid_list_same(const gid_t *a, size_t n, const gid_t *b, size_t m) {
        return gid_list_contained(a, n, b, m) &&
                gid_list_contained(b, m, a, n);
}

static void* server(void *p) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_close_ int listen_fd = PTR_TO_INT(p), fd = -EBADF;
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *c = NULL;
        _cleanup_free_ char *our_comm = NULL;
        sd_id128_t id;
        int r;

        ASSERT_OK(sd_id128_randomize(&id));

        ASSERT_OK_ERRNO(fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC|SOCK_NONBLOCK));

        ASSERT_OK(sd_bus_new(&bus));
        ASSERT_OK(sd_bus_set_fd(bus, fd, fd));
        TAKE_FD(fd);
        ASSERT_OK(sd_bus_set_server(bus, true, id));
        ASSERT_OK(sd_bus_negotiate_creds(bus, 1, SD_BUS_CREDS_EUID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_PID|SD_BUS_CREDS_COMM|SD_BUS_CREDS_DESCRIPTION|SD_BUS_CREDS_PIDFD|SD_BUS_CREDS_SUPPLEMENTARY_GIDS));
        ASSERT_OK(sd_bus_start(bus));
        ASSERT_OK(sd_bus_get_owner_creds(bus, SD_BUS_CREDS_EUID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_PID|SD_BUS_CREDS_COMM|SD_BUS_CREDS_DESCRIPTION|SD_BUS_CREDS_PIDFD|SD_BUS_CREDS_SUPPLEMENTARY_GIDS, &c));

        bus_creds_dump(c, /* f= */ NULL, /* terse= */ false);

        uid_t u;
        ASSERT_OK(sd_bus_creds_get_euid(c, &u));
        ASSERT_EQ(u, getuid());

        gid_t g;
        ASSERT_OK(sd_bus_creds_get_egid(c, &g));
        ASSERT_EQ(g, getgid());

        pid_t pid;
        ASSERT_OK(sd_bus_creds_get_pid(c, &pid));
        ASSERT_EQ(pid, getpid_cached());

        int pidfd = -EBADF;
        if (sd_bus_creds_get_pidfd_dup(c, &pidfd) >= 0) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                ASSERT_OK(pidref_set_pidfd_take(&pidref, pidfd));
                ASSERT_TRUE(pidref_is_self(&pidref));
        }

        const gid_t *gl = NULL;
        int n = sd_bus_creds_get_supplementary_gids(c, &gl);

        if (n >= 0) {
                _cleanup_free_ gid_t *gg = NULL;
                ASSERT_OK(r = getgroups_alloc(&gg));
                ASSERT_TRUE(gid_list_same(gl, n, gg, r));
        }

        const char *comm;
        ASSERT_OK(sd_bus_creds_get_comm(c, &comm));
        ASSERT_OK(pid_get_comm(0, &our_comm));
        ASSERT_STREQ(comm, our_comm);

        const char *description;
        ASSERT_OK(sd_bus_creds_get_description(c, &description));
        ASSERT_STREQ(description, "wuffwuff");

        for (;;) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                ASSERT_OK(r = sd_bus_process(bus, &m));

                if (r == 0) {
                        ASSERT_OK(sd_bus_wait(bus, UINT64_MAX));
                        continue;
                }

                if (m && sd_bus_message_is_method_call(m, "foo.foo", "Foo") > 0) {
                        ASSERT_OK(sd_bus_reply_method_return(m, "s", "bar"));
                        break;
                }
        }

        return NULL;
}

static void* client(void *p) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *z;

        ASSERT_OK(sd_bus_new(&bus));
        ASSERT_OK(sd_bus_set_description(bus, "wuffwuff"));
        ASSERT_OK(sd_bus_set_address(bus, p));
        ASSERT_OK(sd_bus_start(bus));

        ASSERT_OK(sd_bus_call_method(bus, "foo.foo", "/foo", "foo.foo", "Foo", NULL, &reply, "s", "foo"));

        ASSERT_OK(sd_bus_message_read(reply, "s", &z));
        ASSERT_STREQ(z, "bar");

        return NULL;
}

TEST(description) {
        _cleanup_free_ char *a = NULL;
        _cleanup_close_ int fd = -EBADF;
        union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
        };
        socklen_t salen;
        pthread_t s, c;

        ASSERT_OK_ERRNO(fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0));
        ASSERT_OK_ERRNO(bind(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path))); /* force auto-bind */
        ASSERT_OK_ERRNO(listen(fd, 1));

        salen = sizeof(sa);
        ASSERT_OK_ERRNO(getsockname(fd, &sa.sa, &salen));
        ASSERT_GE(salen, offsetof(struct sockaddr_un, sun_path));
        ASSERT_EQ(sa.un.sun_path[0], 0);

        ASSERT_OK(asprintf(&a, "unix:abstract=%s", sa.un.sun_path + 1));

        ASSERT_OK(-pthread_create(&s, NULL, server, INT_TO_PTR(fd)));
        TAKE_FD(fd);

        ASSERT_OK(-pthread_create(&c, NULL, client, a));

        ASSERT_OK(-pthread_join(s, NULL));
        ASSERT_OK(-pthread_join(c, NULL));
}

DEFINE_TEST_MAIN(LOG_INFO);
