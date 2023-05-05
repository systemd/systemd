/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <unistd.h>

#include "sd-bus.h"

#include "fd-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "tests.h"

static void *server(void *p) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_close_ int listen_fd = PTR_TO_INT(p), fd = -EBADF;
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *c = NULL;
        _cleanup_free_ char *our_comm = NULL;
        sd_id128_t id;
        int r;

        assert_se(sd_id128_randomize(&id) >= 0);

        fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC|SOCK_NONBLOCK);
        assert_se(fd >= 0);

        assert_se(sd_bus_new(&bus) >= 0);
        assert_se(sd_bus_set_fd(bus, fd, fd) >= 0);
        TAKE_FD(fd);
        assert_se(sd_bus_set_server(bus, true, id) >= 0);
        assert_se(sd_bus_negotiate_creds(bus, 1, SD_BUS_CREDS_EUID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_PID|SD_BUS_CREDS_COMM|SD_BUS_CREDS_DESCRIPTION) >= 0);

        assert_se(sd_bus_start(bus) >= 0);

        assert_se(sd_bus_get_owner_creds(bus, SD_BUS_CREDS_EUID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_PID|SD_BUS_CREDS_COMM|SD_BUS_CREDS_DESCRIPTION, &c) >= 0);

        uid_t u;
        assert_se(sd_bus_creds_get_euid(c, &u) >= 0);
        assert_se(u == getuid());

        gid_t g;
        assert_se(sd_bus_creds_get_egid(c, &g) >= 0);
        assert_se(g == getgid());

        pid_t pid;
        assert_se(sd_bus_creds_get_pid(c, &pid) >= 0);
        assert_se(pid == getpid_cached());

        const char *comm;
        assert_se(sd_bus_creds_get_comm(c, &comm) >= 0);
        assert_se(get_process_comm(0, &our_comm) >= 0);
        assert_se(streq_ptr(comm, our_comm));

        const char *description;
        assert_se(sd_bus_creds_get_description(c, &description) >= 0);
        assert_se(streq_ptr(description, "wuffwuff"));

        for (;;) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = sd_bus_process(bus, &m);
                assert_se(r >= 0);

                if (r == 0) {
                        assert_se(sd_bus_wait(bus, UINT64_MAX) >= 0);
                        continue;
                }

                if (sd_bus_message_is_method_call(m, "foo.foo", "Foo") > 0) {
                        assert_se(sd_bus_reply_method_return(m, "s", "bar") >= 0);
                        break;
                }
        }

        return NULL;
}

static void* client(void *p) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *z;

        assert_se(sd_bus_new(&bus) >= 0);
        assert_se(sd_bus_set_description(bus, "wuffwuff") >= 0);
        assert_se(sd_bus_set_address(bus, p) >= 0);
        assert_se(sd_bus_start(bus) >= 0);

        assert_se(sd_bus_call_method(bus, "foo.foo", "/foo", "foo.foo", "Foo", NULL, &reply, "s", "foo") >= 0);

        assert_se(sd_bus_message_read(reply, "s", &z) >= 0);
        assert_se(streq_ptr(z, "bar"));

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

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        assert_se(fd >= 0);

        assert_se(bind(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path)) >= 0); /* force auto-bind */

        assert_se(listen(fd, 1) >= 0);

        salen = sizeof(sa);
        assert_se(getsockname(fd, &sa.sa, &salen) >= 0);
        assert_se(salen >= offsetof(struct sockaddr_un, sun_path));
        assert_se(sa.un.sun_path[0] == 0);

        assert_se(asprintf(&a, "unix:abstract=%s", sa.un.sun_path + 1) >= 0);

        assert_se(pthread_create(&s, NULL, server, INT_TO_PTR(fd)) == 0);
        TAKE_FD(fd);

        assert_se(pthread_create(&c, NULL, client, a) == 0);

        assert_se(pthread_join(s, NULL) == 0);
        assert_se(pthread_join(c, NULL) == 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
