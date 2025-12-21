/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-future.h"

#include "errno-util.h"
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

static int server(void *userdata) {
        struct context *c = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_id128_t id;
        bool quit = false;
        int r;

        ASSERT_OK(sd_id128_randomize(&id));

        ASSERT_OK(sd_bus_new(&bus));
        ASSERT_OK(sd_bus_set_description(bus, "server"));
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

static int client(void *userdata) {
        struct context *c = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

        ASSERT_OK(sd_bus_new(&bus));
        ASSERT_OK(sd_bus_set_description(bus, "client"));
        ASSERT_OK(sd_bus_set_fd(bus, c->fds[1], c->fds[1]));
        ASSERT_OK(sd_bus_attach_event(bus, sd_fiber_get_event(), 0));
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

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f_server = NULL, *f_client = NULL;
        struct context c;
        int r = 0;

        zero(c);

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM, 0, c.fds));

        c.client_negotiate_unix_fds = client_negotiate_unix_fds;
        c.server_negotiate_unix_fds = server_negotiate_unix_fds;
        c.client_anonymous_auth = client_anonymous_auth;
        c.server_anonymous_auth = server_anonymous_auth;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        ASSERT_OK(sd_future_new_fiber(e, "server", server, &c, /* destroy= */ NULL, &f_server));
        ASSERT_OK(sd_future_new_fiber(e, "client", client, &c, /* destroy= */ NULL, &f_client));

        ASSERT_OK(sd_event_loop(e));

        RET_GATHER(r, sd_future_result(f_client));
        RET_GATHER(r, sd_future_result(f_server));

        return r;
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        ASSERT_OK(test_one(true, true, false, false));
        ASSERT_OK(test_one(true, false, false, false));
        ASSERT_OK(test_one(false, true, false, false));
        ASSERT_OK(test_one(false, false, false, false));
        ASSERT_OK(test_one(true, true, true, true));
        ASSERT_OK(test_one(true, true, false, true));
        ASSERT_ERROR(test_one(true, true, true, false), EACCES);

        return EXIT_SUCCESS;
}
