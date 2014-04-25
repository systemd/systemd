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
#include <fcntl.h>

#include "log.h"
#include "util.h"
#include "macro.h"

#include "sd-bus.h"
#include "bus-message.h"
#include "bus-error.h"
#include "bus-match.h"
#include "bus-internal.h"
#include "bus-util.h"

static int match_callback(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        log_info("Match triggered! interface=%s member=%s", strna(sd_bus_message_get_interface(m)), strna(sd_bus_message_get_member(m)));
        return 0;
}

static int object_callback(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        int r;

        assert(bus);

        if (sd_bus_message_is_method_error(m, NULL))
                return 0;

        if (sd_bus_message_is_method_call(m, "org.object.test", "Foobar")) {
                log_info("Invoked Foobar() on %s", sd_bus_message_get_path(m));

                r = sd_bus_reply_method_return(m, NULL);
                if (r < 0) {
                        log_error("Failed to send reply: %s", strerror(-r));
                        return r;
                }

                return 1;
        }

        return 0;
}

static int server_init(sd_bus **_bus) {
        sd_bus *bus = NULL;
        sd_id128_t id;
        int r;
        const char *unique;

        assert(_bus);

        r = sd_bus_open_user(&bus);
        if (r < 0) {
                log_error("Failed to connect to user bus: %s", strerror(-r));
                goto fail;
        }

        r = sd_bus_get_server_id(bus, &id);
        if (r < 0) {
                log_error("Failed to get server ID: %s", strerror(-r));
                goto fail;
        }

        r = sd_bus_get_unique_name(bus, &unique);
        if (r < 0) {
                log_error("Failed to get unique name: %s", strerror(-r));
                goto fail;
        }

        log_info("Peer ID is " SD_ID128_FORMAT_STR ".", SD_ID128_FORMAT_VAL(id));
        log_info("Unique ID: %s", unique);
        log_info("Can send file handles: %i", sd_bus_can_send(bus, 'h'));

        r = sd_bus_request_name(bus, "org.freedesktop.systemd.test", 0);
        if (r < 0) {
                log_error("Failed to acquire name: %s", strerror(-r));
                goto fail;
        }

        r = sd_bus_add_fallback(bus, NULL, "/foo/bar", object_callback, NULL);
        if (r < 0) {
                log_error("Failed to add object: %s", strerror(-r));
                goto fail;
        }

        r = sd_bus_add_match(bus, NULL, "type='signal',interface='foo.bar',member='Notify'", match_callback, NULL);
        if (r < 0) {
                log_error("Failed to add match: %s", strerror(-r));
                goto fail;
        }

        r = sd_bus_add_match(bus, NULL, "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged'", match_callback, NULL);
        if (r < 0) {
                log_error("Failed to add match: %s", strerror(-r));
                goto fail;
        }

        bus_match_dump(&bus->match_callbacks, 0);

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
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
                pid_t pid = 0;
                const char *label = NULL;

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

                sd_bus_creds_get_pid(sd_bus_message_get_creds(m), &pid);
                sd_bus_creds_get_selinux_context(sd_bus_message_get_creds(m), &label);
                log_info("Got message! member=%s pid="PID_FMT" label=%s",
                         strna(sd_bus_message_get_member(m)),
                         pid,
                         strna(label));
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

                        lowercase = strdup(hello);
                        if (!lowercase) {
                                r = log_oom();
                                goto fail;
                        }

                        ascii_strlower(lowercase);

                        r = sd_bus_reply_method_return(m, "s", lowercase);
                        if (r < 0) {
                                log_error("Failed to send reply: %s", strerror(-r));
                                goto fail;
                        }
                } else if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "ExitClient1")) {

                        r = sd_bus_reply_method_return(m, NULL);
                        if (r < 0) {
                                log_error("Failed to send reply: %s", strerror(-r));
                                goto fail;
                        }

                        client1_gone = true;
                } else if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "ExitClient2")) {

                        r = sd_bus_reply_method_return(m, NULL);
                        if (r < 0) {
                                log_error("Failed to send reply: %s", strerror(-r));
                                goto fail;
                        }

                        client2_gone = true;
                } else if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "Slow")) {

                        sleep(1);

                        r = sd_bus_reply_method_return(m, NULL);
                        if (r < 0) {
                                log_error("Failed to send reply: %s", strerror(-r));
                                goto fail;
                        }

                } else if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "FileDescriptor")) {
                        int fd;
                        static const char x = 'X';

                        r = sd_bus_message_read(m, "h", &fd);
                        if (r < 0) {
                                log_error("Failed to get parameter: %s", strerror(-r));
                                goto fail;
                        }

                        log_info("Received fd=%d", fd);

                        if (write(fd, &x, 1) < 0) {
                                log_error("Failed to write to fd: %m");
                                safe_close(fd);
                                goto fail;
                        }

                        r = sd_bus_reply_method_return(m, NULL);
                        if (r < 0) {
                                log_error("Failed to send reply: %s", strerror(-r));
                                goto fail;
                        }

                } else if (sd_bus_message_is_method_call(m, NULL, NULL)) {

                        r = sd_bus_reply_method_error(
                                        m,
                                        &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_UNKNOWN_METHOD, "Unknown method."));
                        if (r < 0) {
                                log_error("Failed to send reply: %s", strerror(-r));
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

        return r;
}

static void* client1(void*p) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        sd_bus *bus = NULL;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *hello;
        int r;
        int pp[2] = { -1, -1 };
        char x;

        r = sd_bus_open_user(&bus);
        if (r < 0) {
                log_error("Failed to connect to user bus: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.systemd.test",
                        "LowerCase",
                        &error,
                        &reply,
                        "s",
                        "HELLO");
        if (r < 0) {
                log_error("Failed to issue method call: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_message_read(reply, "s", &hello);
        if (r < 0) {
                log_error("Failed to get string: %s", strerror(-r));
                goto finish;
        }

        assert(streq(hello, "hello"));

        if (pipe2(pp, O_CLOEXEC|O_NONBLOCK) < 0) {
                log_error("Failed to allocate pipe: %m");
                r = -errno;
                goto finish;
        }

        log_info("Sending fd=%d", pp[1]);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.systemd.test",
                        "FileDescriptor",
                        &error,
                        NULL,
                        "h",
                        pp[1]);
        if (r < 0) {
                log_error("Failed to issue method call: %s", strerror(-r));
                goto finish;
        }

        errno = 0;
        if (read(pp[0], &x, 1) <= 0) {
                log_error("Failed to read from pipe: %s", errno ? strerror(errno) : "early read");
                goto finish;
        }

        r = 0;

finish:
        if (bus) {
                _cleanup_bus_message_unref_ sd_bus_message *q;

                r = sd_bus_message_new_method_call(
                                bus,
                                &q,
                                "org.freedesktop.systemd.test",
                                "/",
                                "org.freedesktop.systemd.test",
                                "ExitClient1");
                if (r < 0)
                        log_error("Failed to allocate method call: %s", strerror(-r));
                else
                        sd_bus_send(bus, q, NULL);

                sd_bus_flush(bus);
                sd_bus_unref(bus);
        }

        sd_bus_error_free(&error);

        safe_close_pair(pp);

        return INT_TO_PTR(r);
}

static int quit_callback(sd_bus *b, sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        bool *x = userdata;

        log_error("Quit callback: %s", strerror(sd_bus_message_get_errno(m)));

        *x = 1;
        return 1;
}

static void* client2(void*p) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        sd_bus *bus = NULL;
        sd_bus_error error = SD_BUS_ERROR_NULL;
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
                        &m,
                        "org.freedesktop.systemd.test",
                        "/foo/bar/waldo/piep",
                        "org.object.test",
                        "Foobar");
        if (r < 0) {
                log_error("Failed to allocate method call: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_send(bus, m, NULL);
        if (r < 0) {
                log_error("Failed to issue method call: %s", bus_error_message(&error, -r));
                goto finish;
        }

        sd_bus_message_unref(m);
        m = NULL;

        r = sd_bus_message_new_signal(
                        bus,
                        &m,
                        "/foobar",
                        "foo.bar",
                        "Notify");
        if (r < 0) {
                log_error("Failed to allocate signal: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_send(bus, m, NULL);
        if (r < 0) {
                log_error("Failed to issue signal: %s", bus_error_message(&error, -r));
                goto finish;
        }

        sd_bus_message_unref(m);
        m = NULL;

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.DBus.Peer",
                        "GetMachineId");
        if (r < 0) {
                log_error("Failed to allocate method call: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_call(bus, m, 0, &error, &reply);
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
                        &m,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.systemd.test",
                        "Slow");
        if (r < 0) {
                log_error("Failed to allocate method call: %s", strerror(-r));
                goto finish;
        }

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_call(bus, m, 200 * USEC_PER_MSEC, &error, &reply);
        if (r < 0)
                log_info("Failed to issue method call: %s", bus_error_message(&error, -r));
        else
                log_info("Slow call succeed.");

        sd_bus_message_unref(m);
        m = NULL;

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.systemd.test",
                        "Slow");
        if (r < 0) {
                log_error("Failed to allocate method call: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_call_async(bus, NULL, m, quit_callback, &quit, 200 * USEC_PER_MSEC);
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
                                &q,
                                "org.freedesktop.systemd.test",
                                "/",
                                "org.freedesktop.systemd.test",
                                "ExitClient2");
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
        if (r < 0) {
                log_info("Failed to connect to bus, skipping tests.");
                return EXIT_TEST_SKIP;
        }

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
        if (PTR_TO_INT(p) < 0)
                return EXIT_FAILURE;

        q = pthread_join(c2, &p);
        if (q != 0)
                return EXIT_FAILURE;
        if (PTR_TO_INT(p) < 0)
                return EXIT_FAILURE;

        if (r < 0)
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}
