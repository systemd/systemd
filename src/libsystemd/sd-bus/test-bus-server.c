/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <sys/socket.h>

#include "sd-bus.h"

#include "log.h"
#include "memory-util.h"
#include "string-util.h"
#include "tests.h"

struct context {
        int fds[2];

        bool client_negotiate_unix_fds;
        bool server_negotiate_unix_fds;

        bool client_anonymous_auth;
        bool server_anonymous_auth;
};

static int _server(struct context *c) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_id128_t id;
        bool quit = false;
        int r;

        ASSERT_OK(sd_id128_randomize(&id));

        ASSERT_OK(sd_bus_new(&bus));
        ASSERT_OK(sd_bus_set_fd(bus, c->fds[0], c->fds[0]));
        ASSERT_OK(sd_bus_set_server(bus, 1, id));
        ASSERT_OK(sd_bus_set_anonymous(bus, c->server_anonymous_auth));
        ASSERT_OK(sd_bus_negotiate_fds(bus, c->server_negotiate_unix_fds));
        ASSERT_OK(sd_bus_start(bus));

        while (!quit) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;

                r = sd_bus_process(bus, &m);
                if (r < 0)
                        return log_error_errno(r, "Failed to process requests: %m");

                if (r == 0) {
                        ASSERT_OK(sd_bus_wait(bus, UINT64_MAX));
                        continue;
                }

                if (!m)
                        continue;

                log_info("Got message! member=%s", strna(sd_bus_message_get_member(m)));

                if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "Exit")) {

                        ASSERT_EQ(sd_bus_can_send(bus, 'h') >= 1,
                                  c->server_negotiate_unix_fds && c->client_negotiate_unix_fds);

                        ASSERT_OK(sd_bus_message_new_method_return(m, &reply));

                        quit = true;

                } else if (sd_bus_message_is_method_call(m, NULL, NULL))
                        ASSERT_OK(sd_bus_message_new_method_error(
                                        m,
                                        &reply,
                                        &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_UNKNOWN_METHOD, "Unknown method.")));

                if (reply)
                        ASSERT_OK(sd_bus_send(bus, reply, NULL));
        }

        return 0;
}

static void* server(void *p) {
        return INT_TO_PTR(_server(p));
}

static int client(struct context *c) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

        ASSERT_OK(sd_bus_new(&bus));
        ASSERT_OK(sd_bus_set_fd(bus, c->fds[1], c->fds[1]));
        ASSERT_OK(sd_bus_negotiate_fds(bus, c->client_negotiate_unix_fds));
        ASSERT_OK(sd_bus_set_anonymous(bus, c->client_anonymous_auth));
        ASSERT_OK(sd_bus_start(bus));

        ASSERT_OK(sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.systemd.test",
                        "Exit"));

        return sd_bus_call(bus, m, 0, &error, &reply);
}

static int test_one(bool client_negotiate_unix_fds, bool server_negotiate_unix_fds,
                    bool client_anonymous_auth, bool server_anonymous_auth) {

        struct context c;
        pthread_t s;
        void *p;
        int r, q;

        zero(c);

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM, 0, c.fds));

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

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        ASSERT_OK(test_one(true, true, false, false));
        ASSERT_OK(test_one(true, false, false, false));
        ASSERT_OK(test_one(false, true, false, false));
        ASSERT_OK(test_one(false, false, false, false));
        ASSERT_OK(test_one(true, true, true, true));
        ASSERT_OK(test_one(true, true, false, true));
        ASSERT_ERROR(test_one(true, true, true, false), EPERM);

        return EXIT_SUCCESS;
}
