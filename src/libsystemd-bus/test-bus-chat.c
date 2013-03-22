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

#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

#include "sd-bus.h"
#include "bus-message.h"
#include "bus-error.h"

static int server_init(sd_bus **_bus) {
        sd_bus *bus = NULL;
        sd_id128_t id;
        int r;

        assert(_bus);

        r = sd_bus_open_user(&bus);
        if (r < 0) {
                log_error("Failed to connect to user bus: %s", strerror(-r));
                goto fail;
        }

        r = sd_bus_get_peer(bus, &id);
        if (r < 0) {
                log_error("Failed to get peer ID: %s", strerror(-r));
                goto fail;
        }

        log_info("Peer ID is " SD_ID128_FORMAT_STR ".", SD_ID128_FORMAT_VAL(id));
        log_info("Can send file handles: %i", sd_bus_can_send(bus, 'h'));
        log_info("Unique ID: %s", strna(sd_bus_get_unique_name(bus)));

        r = sd_bus_request_name(bus, "org.freedesktop.systemd.test", 0);
        if (r < 0) {
                log_error("Failed to acquire name: %s", strerror(-r));
                goto fail;
        }

        *_bus = bus;
        return 0;

fail:
        if (bus)
                sd_bus_unref(bus);

        return r;
}

static int server(sd_bus *bus) {
        int r;
        bool client1_gone = false, client2_gone = false;

        while (!client1_gone || !client2_gone) {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;

                r = sd_bus_process(bus, &m);
                if (r < 0) {
                        log_error("Failed to process requests: %s", strerror(-r));
                        goto fail;
                }

                if (r == 0) {
                        r = sd_bus_wait(bus, (uint64_t) -1);
                        if (r < 0) {
                                log_error("Failed to wait: %s", strerror(-r));
                                goto fail;
                        }

                        continue;
                }

                if (!m)
                        continue;

                log_info("Got message! %s", strna(sd_bus_message_get_member(m)));
                /* bus_message_dump(m); */
                /* sd_bus_message_rewind(m, true); */

                if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "LowerCase")) {
                        const char *hello;
                        _cleanup_free_ char *lowercase = NULL;

                        r = sd_bus_message_read(m, "s", &hello);
                        if (r < 0) {
                                log_error("Failed to get parameter: %s", strerror(-r));
                                goto fail;
                        }

                        r = sd_bus_message_new_method_return(bus, m, &reply);
                        if (r < 0) {
                                log_error("Failed to allocate return: %s", strerror(-r));
                                goto fail;
                        }

                        lowercase = strdup(hello);
                        if (!lowercase) {
                                r = log_oom();
                                goto fail;
                        }

                        ascii_strlower(lowercase);

                        r = sd_bus_message_append(reply, "s", lowercase);
                        if (r < 0) {
                                log_error("Failed to append message: %s", strerror(-r));
                                goto fail;
                        }
                } else if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "ExitClient1")) {

                        r = sd_bus_message_new_method_return(bus, m, &reply);
                        if (r < 0) {
                                log_error("Failed to allocate return: %s", strerror(-r));
                                goto fail;
                        }

                        client1_gone = true;
                } else if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "ExitClient2")) {

                        r = sd_bus_message_new_method_return(bus, m, &reply);
                        if (r < 0) {
                                log_error("Failed to allocate return: %s", strerror(-r));
                                goto fail;
                        }

                        client2_gone = true;
                } else if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "Slow")) {

                        r = sd_bus_message_new_method_return(bus, m, &reply);
                        if (r < 0) {
                                log_error("Failed to allocate return: %s", strerror(-r));
                                goto fail;
                        }

                        sleep(1);
                } else if (sd_bus_message_is_method_call(m, NULL, NULL)) {
                        const sd_bus_error e = SD_BUS_ERROR_INIT_CONST("org.freedesktop.DBus.Error.UnknownMethod", "Unknown method.");

                        r = sd_bus_message_new_method_error(bus, m, &e, &reply);
                        if (r < 0) {
                                log_error("Failed to allocate return: %s", strerror(-r));
                                goto fail;
                        }
                }

                if (reply) {
                        r = sd_bus_send(bus, reply, NULL);
                        if (r < 0) {
                                log_error("Failed to send reply: %s", strerror(-r));
                                goto fail;
                        }

                        /* log_info("Sent"); */
                        /* bus_message_dump(reply); */
                        /* sd_bus_message_rewind(reply, true); */
                }
        }

        r = 0;

fail:
        if (bus) {
                sd_bus_flush(bus);
                sd_bus_unref(bus);
        }

        return r;
}

static void* client1(void*p) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        sd_bus *bus = NULL;
        sd_bus_error error = SD_BUS_ERROR_INIT;
        const char *hello;
        int r;

        r = sd_bus_open_user(&bus);
        if (r < 0) {
                log_error("Failed to connect to user bus: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_message_new_method_call(
                        bus,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.systemd.test",
                        "LowerCase",
                        &m);
        if (r < 0) {
                log_error("Failed to allocate method call: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_message_append(m, "s", "HELLO");
        if (r < 0) {
                log_error("Failed to append string: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_send_with_reply_and_block(bus, m, 0, &error, &reply);
        if (r < 0) {
                log_error("Failed to issue method call: %s", bus_error_message(&error, -r));
                goto finish;
        }

        r = sd_bus_message_read(reply, "s", &hello);
        if (r < 0) {
                log_error("Failed to get string: %s", strerror(-r));
                goto finish;
        }

        assert(streq(hello, "hello"));

        r = 0;

finish:
        if (bus) {
                _cleanup_bus_message_unref_ sd_bus_message *q;

                r = sd_bus_message_new_method_call(
                                bus,
                                "org.freedesktop.systemd.test",
                                "/",
                                "org.freedesktop.systemd.test",
                                "ExitClient1",
                                &q);
                if (r < 0) {
                        log_error("Failed to allocate method call: %s", strerror(-r));
                        goto finish;
                }

                sd_bus_send(bus, q, NULL);
                sd_bus_flush(bus);
                sd_bus_unref(bus);
        }

        sd_bus_error_free(&error);
        return INT_TO_PTR(r);
}

static int quit_callback(sd_bus *b, int ret, sd_bus_message *m, void *userdata) {
        bool *x = userdata;

        log_error("Quit callback: %s", strerror(ret));

        *x = 1;
        return 1;
}

static void* client2(void*p) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        sd_bus *bus = NULL;
        sd_bus_error error = SD_BUS_ERROR_INIT;
        bool quit = false;
        const char *mid;
        int r;

        r = sd_bus_open_user(&bus);
        if (r < 0) {
                log_error("Failed to connect to user bus: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_message_new_method_call(
                        bus,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.DBus.Peer",
                        "GetMachineId",
                        &m);
        if (r < 0) {
                log_error("Failed to allocate method call: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_send_with_reply_and_block(bus, m, 0, &error, &reply);
        if (r < 0) {
                log_error("Failed to issue method call: %s", bus_error_message(&error, -r));
                goto finish;
        }

        r = sd_bus_message_read(reply, "s", &mid);
        if (r < 0) {
                log_error("Failed to parse machine ID: %s", strerror(-r));
                goto finish;
        }

        log_info("Machine ID is %s.", mid);

        sd_bus_message_unref(m);
        m = NULL;

        r = sd_bus_message_new_method_call(
                        bus,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.systemd.test",
                        "Slow",
                        &m);
        if (r < 0) {
                log_error("Failed to allocate method call: %s", strerror(-r));
                goto finish;
        }

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_send_with_reply_and_block(bus, m, 200 * USEC_PER_MSEC, &error, &reply);
        if (r < 0)
                log_info("Failed to issue method call: %s", bus_error_message(&error, -r));
        else
                log_info("Slow call succeed.");

        sd_bus_message_unref(m);
        m = NULL;

        r = sd_bus_message_new_method_call(
                        bus,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.systemd.test",
                        "Slow",
                        &m);
        if (r < 0) {
                log_error("Failed to allocate method call: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_send_with_reply(bus, m, quit_callback, &quit, 200 * USEC_PER_MSEC, NULL);
        if (r < 0) {
                log_info("Failed to issue method call: %s", bus_error_message(&error, -r));
                goto finish;
        }

        while (!quit) {
                r = sd_bus_process(bus, NULL);
                if (r < 0) {
                        log_error("Failed to process requests: %s", strerror(-r));
                        goto finish;
                }
                if (r == 0) {
                        r = sd_bus_wait(bus, (uint64_t) -1);
                        if (r < 0) {
                                log_error("Failed to wait: %s", strerror(-r));
                                goto finish;
                        }
                }
        }

        r = 0;

finish:
        if (bus) {
                _cleanup_bus_message_unref_ sd_bus_message *q;

                r = sd_bus_message_new_method_call(
                                bus,
                                "org.freedesktop.systemd.test",
                                "/",
                                "org.freedesktop.systemd.test",
                                "ExitClient2",
                                &q);
                if (r < 0) {
                        log_error("Failed to allocate method call: %s", strerror(-r));
                        goto finish;
                }

                sd_bus_send(bus, q, NULL);
                sd_bus_flush(bus);
                sd_bus_unref(bus);
        }

        sd_bus_error_free(&error);
        return INT_TO_PTR(r);
}

int main(int argc, char *argv[]) {
        pthread_t c1, c2;
        sd_bus *bus;
        void *p;
        int q, r;

        r = server_init(&bus);
        if (r < 0)
                return EXIT_FAILURE;

        log_info("Initialized...");

        r = pthread_create(&c1, NULL, client1, bus);
        if (r != 0)
                return EXIT_FAILURE;

        r = pthread_create(&c2, NULL, client2, bus);
        if (r != 0)
                return EXIT_FAILURE;

        r = server(bus);

        q = pthread_join(c1, &p);
        if (q != 0)
                return EXIT_FAILURE;
        q = pthread_join(c2, &p);
        if (q != 0)
                return EXIT_FAILURE;
        if (r < 0)
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}
