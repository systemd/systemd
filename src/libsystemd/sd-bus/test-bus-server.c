/* SPDX-License-Identifier: LGPL-2.1+ */

#include <pthread.h>
#include <stdlib.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "macro.h"
#include "stdio-util.h"
#include "util.h"

struct context {
        int fds[2];

        bool client_negotiate_unix_fds;
        bool server_negotiate_unix_fds;

        bool client_anonymous_auth;
        bool server_anonymous_auth;
};

static void *server(void *p) {
        struct context *c = p;
        sd_bus *bus = NULL;
        sd_id128_t id;
        bool quit = false;
        int r;

        assert_se(sd_id128_randomize(&id) >= 0);

        assert_se(sd_bus_new(&bus) >= 0);
        assert_se(sd_bus_set_fd(bus, c->fds[0], c->fds[0]) >= 0);
        assert_se(sd_bus_set_server(bus, 1, id) >= 0);
        assert_se(sd_bus_set_anonymous(bus, c->server_anonymous_auth) >= 0);
        assert_se(sd_bus_negotiate_fds(bus, c->server_negotiate_unix_fds) >= 0);
        assert_se(sd_bus_start(bus) >= 0);

        while (!quit) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;

                r = sd_bus_process(bus, &m);
                if (r < 0) {
                        log_error_errno(r, "Failed to process requests: %m");
                        goto fail;
                }

                if (r == 0) {
                        r = sd_bus_wait(bus, (uint64_t) -1);
                        if (r < 0) {
                                log_error_errno(r, "Failed to wait: %m");
                                goto fail;
                        }

                        continue;
                }

                if (!m)
                        continue;

                log_info("Got message! member=%s", strna(sd_bus_message_get_member(m)));

                if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "Exit")) {

                        assert_se((sd_bus_can_send(bus, 'h') >= 1) ==
                                  (c->server_negotiate_unix_fds && c->client_negotiate_unix_fds));

                        r = sd_bus_message_new_method_return(m, &reply);
                        if (r < 0) {
                                log_error_errno(r, "Failed to allocate return: %m");
                                goto fail;
                        }

                        quit = true;

                } else if (sd_bus_message_is_method_call(m, NULL, NULL)) {
                        r = sd_bus_message_new_method_error(
                                        m,
                                        &reply,
                                        &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_UNKNOWN_METHOD, "Unknown method."));
                        if (r < 0) {
                                log_error_errno(r, "Failed to allocate return: %m");
                                goto fail;
                        }
                }

                if (reply) {
                        r = sd_bus_send(bus, reply, NULL);
                        if (r < 0) {
                                log_error_errno(r, "Failed to send reply: %m");
                                goto fail;
                        }
                }
        }

        r = 0;

fail:
        if (bus) {
                sd_bus_flush(bus);
                sd_bus_unref(bus);
        }

        return INT_TO_PTR(r);
}

static int client(struct context *c) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert_se(sd_bus_new(&bus) >= 0);
        assert_se(sd_bus_set_fd(bus, c->fds[1], c->fds[1]) >= 0);
        assert_se(sd_bus_negotiate_fds(bus, c->client_negotiate_unix_fds) >= 0);
        assert_se(sd_bus_set_anonymous(bus, c->client_anonymous_auth) >= 0);
        assert_se(sd_bus_start(bus) >= 0);

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.systemd.test",
                        "Exit");
        if (r < 0)
                return log_error_errno(r, "Failed to allocate method call: %m");

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to issue method call: %s", bus_error_message(&error, -r));

        return 0;
}

static int test_one(bool client_negotiate_unix_fds, bool server_negotiate_unix_fds,
                    bool client_anonymous_auth, bool server_anonymous_auth) {

        struct context c;
        pthread_t s;
        void *p;
        int r, q;

        zero(c);

        assert_se(socketpair(AF_UNIX, SOCK_STREAM, 0, c.fds) >= 0);

        c.client_negotiate_unix_fds = client_negotiate_unix_fds;
        c.server_negotiate_unix_fds = server_negotiate_unix_fds;
        c.client_anonymous_auth = client_anonymous_auth;
        c.server_anonymous_auth = server_anonymous_auth;

        r = pthread_create(&s, NULL, server, &c);
        if (r != 0)
                return -r;

        r = client(&c);

        q = pthread_join(s, &p);
        if (q != 0)
                return -q;

        if (r < 0)
                return r;

        if (PTR_TO_INT(p) < 0)
                return PTR_TO_INT(p);

        return 0;
}

static void client_send_early_fd(struct context *c) {
        char str_uid[DECIMAL_STR_MAX(uid_t) + 1];
        _cleanup_free_ char *s = NULL, *hex_uid = NULL;
        struct cmsghdr *cmsg;
        struct msghdr msg;
        ssize_t k;
        int l;

        /* send AUTH */

        xsprintf(str_uid, UID_FMT, geteuid());
        hex_uid = hexmem(str_uid, strlen(str_uid));
        assert_se(hex_uid);

        l = asprintf(&s, "%cAUTH EXTERNAL %s\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n", 0, hex_uid);
        assert_se(l >= 0);

        msg = (struct msghdr){};
        msg.msg_iov = &(struct iovec){ .iov_base = s, .iov_len = l };
        msg.msg_iovlen = 1;

        k = sendmsg(c->fds[1], &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
        assert_se(k == l);

        s = mfree(s);

        /* send 'Exit' method call with random FD */

        l = asprintf(&s, "%c%c%c%c%c%c%c%c%c%c%c%c" "%c%c%c%c"
                         "%c" "%co%c" "%c%c%c%c" "/%c" "%c%c%c%c%c%c"
                         "%c" "%cs%c" "%c%c%c%c" "org.freedesktop.systemd.test%c" "%c%c%c"
                         "%c" "%cs%c" "%c%c%c%c" "Exit%c" "%c%c%c"
                         "%c" "%cu%c" "%c%c%c%c"
                         "%s",
                         /* fixed header */
                         'l',           /* little endian */
                         1,             /* method call */
                         0,             /* no flags */
                         1,             /* protocol version */
                         0, 0, 0, 0,    /* body size */
                         1, 0, 0, 0,    /* serial */
                         /* dynamic header */
                         80, 0, 0, 0,   /* total array length */
                         1,             /* PATH */
                                1, 0,                   /* signature length+terminator */
                                1, 0, 0, 0, 0,          /* path length+terminator */
                                0, 0, 0, 0, 0, 0,       /* padding */
                         2,             /* INTERFACE */
                                1, 0,                   /* signature length+terminator */
                                28, 0, 0, 0, 0,         /* interface length+terminator */
                                0, 0, 0,                /* padding */
                         3,             /* MEMBER */
                                1, 0,                   /* signature length+terminator */
                                4, 0, 0, 0, 0,          /* member length+terminator */
                                0, 0, 0,                /* padding */
                         9,             /* UNIX_FDS */
                                1, 0,                   /* signature length+terminator */
                                1, 0, 0, 0,             /* # unix FDs */
                         ""
                    );
        assert_se(l >= 0);

        msg = (struct msghdr){};
        msg.msg_iov = &(struct iovec){ .iov_base = s, .iov_len = l };
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg = alloca(CMSG_SPACE(sizeof(int)));
        msg.msg_controllen = cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        *(int *)CMSG_DATA(cmsg) = c->fds[1];

        k = sendmsg(c->fds[1], &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
        assert_se(k == l);
}

static int test_early_fd(void) {
        struct context c;
        void *p;

        /*
         * This test sends the SASL authentication plus a full dbus-message with file-descriptors before scheduling
         * the sd-bus server. The server must be able to deal with such messages, and we verify it does not fail.
         */

        zero(c);

        assert_se(socketpair(AF_UNIX, SOCK_STREAM, 0, c.fds) >= 0);

        c.client_negotiate_unix_fds = true;
        c.server_negotiate_unix_fds = true;
        c.client_anonymous_auth = false;
        c.server_anonymous_auth = true;

        client_send_early_fd(&c);
        p = server(&c);
        assert(!p);

        return 0;
}

int main(int argc, char *argv[]) {
        int r;

        r = test_one(true, true, false, false);
        assert_se(r >= 0);

        r = test_one(true, false, false, false);
        assert_se(r >= 0);

        r = test_one(false, true, false, false);
        assert_se(r >= 0);

        r = test_one(false, false, false, false);
        assert_se(r >= 0);

        r = test_one(true, true, true, true);
        assert_se(r >= 0);

        r = test_one(true, true, false, true);
        assert_se(r >= 0);

        r = test_one(true, true, true, false);
        assert_se(r == -EPERM);

        r = test_early_fd();
        assert_se(r >= 0);

        return EXIT_SUCCESS;
}
