/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <pthread.h>
#include <stdlib.h>

#include "sd-bus.h"

#include "bus-internal.h"
#include "bus-util.h"
#include "log.h"
#include "macro.h"
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
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;

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

                        assert_se((sd_bus_can_send(bus, 'h') >= 1) == (c->server_negotiate_unix_fds && c->client_negotiate_unix_fds));

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
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_bus_unref_ sd_bus *bus = NULL;
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
        if (r < 0) {
                log_error("Failed to issue method call: %s", bus_error_message(&error, -r));
                return r;
        }

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

        return EXIT_SUCCESS;
}
