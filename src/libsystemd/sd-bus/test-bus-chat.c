/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-internal.h"
#include "bus-match.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"
#include "tests.h"

static int match_callback(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        log_info("Match triggered! destination=%s interface=%s member=%s",
                 strna(sd_bus_message_get_destination(m)),
                 strna(sd_bus_message_get_interface(m)),
                 strna(sd_bus_message_get_member(m)));
        return 0;
}

static int object_callback(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        int r;

        if (sd_bus_message_is_method_error(m, NULL))
                return 0;

        if (sd_bus_message_is_method_call(m, "org.object.test", "Foobar")) {
                log_info("Invoked Foobar() on %s", sd_bus_message_get_path(m));

                r = sd_bus_reply_method_return(m, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to send reply: %m");

                return 1;
        }

        return 0;
}

static int server_init(sd_bus **ret_bus) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        const char *unique, *desc;
        sd_id128_t id;
        int r;

        assert_se(ret_bus);

        r = sd_bus_open_user_with_description(&bus, "my bus!");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to user bus: %m");

        r = sd_bus_get_bus_id(bus, &id);
        if (r < 0)
                return log_error_errno(r, "Failed to get server ID: %m");

        r = sd_bus_get_unique_name(bus, &unique);
        if (r < 0)
                return log_error_errno(r, "Failed to get unique name: %m");

        assert_se(sd_bus_get_description(bus, &desc) >= 0);
        assert_se(streq(desc, "my bus!"));

        log_info("Peer ID is " SD_ID128_FORMAT_STR ".", SD_ID128_FORMAT_VAL(id));
        log_info("Unique ID: %s", unique);
        log_info("Can send file handles: %i", sd_bus_can_send(bus, 'h'));

        r = sd_bus_request_name(bus, "org.freedesktop.systemd.test", 0);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire name: %m");

        r = sd_bus_add_fallback(bus, NULL, "/foo/bar", object_callback, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add object: %m");

        r = sd_bus_match_signal(bus, NULL, NULL, NULL, "foo.bar", "Notify", match_callback, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request match: %m");

        r = sd_bus_match_signal(bus, NULL, NULL, NULL, "foo.bar", "NotifyTo", match_callback, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request match: %m");

        r = sd_bus_add_match(bus, NULL, "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged'", match_callback, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add match: %m");

        bus_match_dump(stdout, &bus->match_callbacks, 0);

        *ret_bus = TAKE_PTR(bus);
        return 0;
}

static int server(sd_bus *_bus) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = ASSERT_PTR(_bus);
        bool client1_gone = false, client2_gone = false;
        int r;

        while (!client1_gone || !client2_gone) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
                pid_t pid = 0;
                const char *label = NULL;

                r = sd_bus_process(bus, &m);
                if (r < 0)
                        return log_error_errno(r, "Failed to process requests: %m");
                if (r == 0) {
                        r = sd_bus_wait(bus, UINT64_MAX);
                        if (r < 0)
                                return log_error_errno(r, "Failed to wait: %m");

                        continue;
                }
                if (!m)
                        continue;

                r = sd_bus_query_sender_creds(m, SD_BUS_CREDS_AUGMENT | SD_BUS_CREDS_PID | SD_BUS_CREDS_SELINUX_CONTEXT, &creds);
                if (r < 0)
                        log_debug_errno(r, "Failed to query sender credentials, ignoring: %m");
                else {
                        r = sd_bus_creds_get_pid(creds, &pid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get sender pid: %m");

                        (void) sd_bus_creds_get_selinux_context(creds, &label);
                }

                log_info("Got message! member=%s pid="PID_FMT" label=%s",
                         strna(sd_bus_message_get_member(m)),
                         pid,
                         strna(label));

                /* sd_bus_message_dump(m); */
                /* sd_bus_message_rewind(m, true); */

                if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "LowerCase")) {
                        const char *hello;
                        _cleanup_free_ char *lowercase = NULL;

                        r = sd_bus_message_read(m, "s", &hello);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get parameter: %m");

                        lowercase = strdup(hello);
                        if (!lowercase)
                                return log_oom();

                        ascii_strlower(lowercase);

                        r = sd_bus_reply_method_return(m, "s", lowercase);
                        if (r < 0)
                                return log_error_errno(r, "Failed to send reply: %m");

                } else if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "ExitClient1")) {

                        r = sd_bus_reply_method_return(m, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to send reply: %m");

                        client1_gone = true;
                } else if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "ExitClient2")) {

                        r = sd_bus_reply_method_return(m, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to send reply: %m");

                        client2_gone = true;
                } else if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "Slow")) {

                        sleep(1);

                        r = sd_bus_reply_method_return(m, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to send reply: %m");

                } else if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "FileDescriptor")) {
                        int fd;
                        static const char x = 'X';

                        r = sd_bus_message_read(m, "h", &fd);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get parameter: %m");

                        log_info("Received fd=%d", fd);

                        if (write(fd, &x, 1) < 0) {
                                r = log_error_errno(errno, "Failed to write to fd: %m");
                                safe_close(fd);
                                return r;
                        }

                        r = sd_bus_reply_method_return(m, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to send reply: %m");

                } else if (sd_bus_message_is_method_call(m, NULL, NULL)) {

                        r = sd_bus_reply_method_error(
                                        m,
                                        &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_UNKNOWN_METHOD, "Unknown method."));
                        if (r < 0)
                                return log_error_errno(r, "Failed to send reply: %m");
                }
        }

        return 0;
}

static void* client1(void *p) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *hello;
        int r;
        _cleanup_close_pair_ int pp[2] = EBADF_PAIR;
        char x;

        r = sd_bus_open_user(&bus);
        if (r < 0) {
                log_error_errno(r, "Failed to connect to user bus: %m");
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
                log_error_errno(r, "Failed to issue method call: %m");
                goto finish;
        }

        r = sd_bus_message_read(reply, "s", &hello);
        if (r < 0) {
                log_error_errno(r, "Failed to get string: %m");
                goto finish;
        }

        assert_se(streq(hello, "hello"));

        if (pipe2(pp, O_CLOEXEC|O_NONBLOCK) < 0) {
                r = log_error_errno(errno, "Failed to allocate pipe: %m");
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
                log_error_errno(r, "Failed to issue method call: %m");
                goto finish;
        }

        errno = 0;
        if (read(pp[0], &x, 1) <= 0) {
                log_error("Failed to read from pipe: %s", STRERROR_OR_EOF(errno));
                goto finish;
        }

        r = 0;

finish:
        if (bus) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *q = NULL;

                r = sd_bus_message_new_method_call(
                                bus,
                                &q,
                                "org.freedesktop.systemd.test",
                                "/",
                                "org.freedesktop.systemd.test",
                                "ExitClient1");
                if (r < 0)
                        log_error_errno(r, "Failed to allocate method call: %m");
                else
                        sd_bus_send(bus, q, NULL);

        }

        return INT_TO_PTR(r);
}

static int quit_callback(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        bool *x = userdata;

        log_error_errno(sd_bus_message_get_errno(m), "Quit callback: %m");

        *x = 1;
        return 1;
}

static void* client2(void *p) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        bool quit = false;
        const char *mid;
        int r;

        r = sd_bus_open_user(&bus);
        if (r < 0) {
                log_error_errno(r, "Failed to connect to user bus: %m");
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
                log_error_errno(r, "Failed to allocate method call: %m");
                goto finish;
        }

        r = sd_bus_send(bus, m, NULL);
        if (r < 0) {
                log_error("Failed to issue method call: %s", bus_error_message(&error, r));
                goto finish;
        }

        m = sd_bus_message_unref(m);

        r = sd_bus_message_new_signal(
                        bus,
                        &m,
                        "/foobar",
                        "foo.bar",
                        "Notify");
        if (r < 0) {
                log_error_errno(r, "Failed to allocate signal: %m");
                goto finish;
        }

        r = sd_bus_send(bus, m, NULL);
        if (r < 0) {
                log_error("Failed to issue signal: %s", bus_error_message(&error, r));
                goto finish;
        }

        m = sd_bus_message_unref(m);

        r = sd_bus_message_new_signal_to(
                        bus,
                        &m,
                        "org.freedesktop.systemd.test",
                        "/foobar",
                        "foo.bar",
                        "NotifyTo");
        if (r < 0) {
                log_error_errno(r, "Failed to allocate signal to: %m");
                goto finish;
        }

        r = sd_bus_send(bus, m, NULL);
        if (r < 0) {
                log_error("Failed to issue signal to: %s", bus_error_message(&error, r));
                goto finish;
        }

        m = sd_bus_message_unref(m);

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.DBus.Peer",
                        "GetMachineId");
        if (r < 0) {
                log_error_errno(r, "Failed to allocate method call: %m");
                goto finish;
        }

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0) {
                log_error("Failed to issue method call: %s", bus_error_message(&error, r));
                goto finish;
        }

        r = sd_bus_message_read(reply, "s", &mid);
        if (r < 0) {
                log_error_errno(r, "Failed to parse machine ID: %m");
                goto finish;
        }

        log_info("Machine ID is %s.", mid);

        m = sd_bus_message_unref(m);

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.systemd.test",
                        "Slow");
        if (r < 0) {
                log_error_errno(r, "Failed to allocate method call: %m");
                goto finish;
        }

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call(bus, m, 200 * USEC_PER_MSEC, &error, &reply);
        if (r < 0)
                log_debug("Failed to issue method call: %s", bus_error_message(&error, r));
        else {
                r = log_error_errno(SYNTHETIC_ERRNO(ENOANO), "Slow call unexpectedly succeeded.");
                goto finish;
        }

        m = sd_bus_message_unref(m);

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd.test",
                        "/",
                        "org.freedesktop.systemd.test",
                        "Slow");
        if (r < 0) {
                log_error_errno(r, "Failed to allocate method call: %m");
                goto finish;
        }

        r = sd_bus_call_async(bus, NULL, m, quit_callback, &quit, 200 * USEC_PER_MSEC);
        if (r < 0) {
                log_info("Failed to issue method call: %s", bus_error_message(&error, r));
                goto finish;
        }

        while (!quit) {
                r = sd_bus_process(bus, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to process requests: %m");
                        goto finish;
                }
                if (r == 0) {
                        r = sd_bus_wait(bus, UINT64_MAX);
                        if (r < 0) {
                                log_error_errno(r, "Failed to wait: %m");
                                goto finish;
                        }
                }
        }

        r = 0;

finish:
        if (bus) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *q = NULL;

                r = sd_bus_message_new_method_call(
                                bus,
                                &q,
                                "org.freedesktop.systemd.test",
                                "/",
                                "org.freedesktop.systemd.test",
                                "ExitClient2");
                if (r < 0) {
                        log_error_errno(r, "Failed to allocate method call: %m");
                        goto finish;
                }

                (void) sd_bus_send(bus, q, NULL);
        }

        return INT_TO_PTR(r);
}

int main(int argc, char *argv[]) {
        pthread_t c1, c2;
        sd_bus *bus;
        void *p;
        int q, r;

        test_setup_logging(LOG_INFO);

        r = server_init(&bus);
        if (r < 0)
                return log_tests_skipped("Failed to connect to bus");

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
