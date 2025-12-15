/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <pthread.h>
#include <sys/resource.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-internal.h"
#include "bus-match.h"
#include "bus-message.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "memfd-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"

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

static int server_init(sd_bus **ret) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        const char *unique, *desc;
        sd_id128_t id;
        int r;

        assert(ret);

        r = sd_bus_open_user_with_description(&bus, "my bus!");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to user bus: %m");

        r = sd_bus_get_bus_id(bus, &id);
        if (r < 0)
                return log_error_errno(r, "Failed to get server ID: %m");

        r = sd_bus_get_unique_name(bus, &unique);
        if (r < 0)
                return log_error_errno(r, "Failed to get unique name: %m");

        ASSERT_OK(sd_bus_get_description(bus, &desc));
        ASSERT_STREQ(desc, "my bus!");

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

        *ret = TAKE_PTR(bus);
        return 0;
}

static int server(sd_bus *bus) {
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

        ASSERT_STREQ(hello, "hello");

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

static ino_t get_inode(int fd) {
        struct stat st;
        assert_se(fstat(fd, &st) >= 0);
        return st.st_ino;
}

static int get_one_message(sd_bus *bus, sd_bus_message **m) {
        int r;

        assert (m);

        while (!*m) {
                r = sd_bus_wait(bus, UINT64_MAX);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait: %m");
                r = sd_bus_process(bus, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to process requests: %m");
        }

        return 0;
}

TEST(ctrunc) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *recvd = NULL, *sent = NULL;
        struct rlimit orig_rl, new_rl;
        const char *unique;
        const int n_fds_to_send = 64;
        ino_t memfd_st_ino[n_fds_to_send];
        int r;

        /* Connect to the session bus and eat the NamedAcquired message */
        r = sd_bus_open_user(&bus);
        if (r < 0)
                return (void) log_error_errno(r, "Cannot connect to bus: %m");
        ASSERT_OK(get_one_message(bus, &recvd));
        recvd = sd_bus_message_unref(recvd);

        if (!sd_bus_can_send(bus, 'h'))
                return (void) log_error("Bus does not support fd passing: %m");

        /* We will create a message with 64 fds in it and set a fd limit of 128 and try to receive it.  We'll
         * hold on to that message after we send it and then attempt to receive it back. Since various other
         * fds will be open, with both copies of the message, we'll definitely hit the limit of 128.
         */
        ASSERT_OK(sd_bus_get_unique_name(bus, &unique));
        ASSERT_OK(sd_bus_message_new_method_call(bus, &sent, unique, "/", "org.freedesktop.systemd.test", "SendFds"));
        ASSERT_OK(sd_bus_message_open_container(sent, SD_BUS_TYPE_ARRAY, "h"));

        /* Create a series of memfds, appending each to the message */
        for (int i = 0; i < n_fds_to_send; i++) {
                _cleanup_close_ int memfd = memfd_create_wrapper("ctrunc-test", 0);
                ASSERT_OK(memfd);
                memfd_st_ino[i] = get_inode(memfd);
                ASSERT_OK(sd_bus_message_append(sent, "h", memfd));
        }
        ASSERT_OK(sd_bus_message_close_container(sent));

        /* Send the message - keep 'sent' alive to hold the duplicated fd references */
        ASSERT_OK(sd_bus_send(bus, sent, NULL));

        /* Now turn down the fd limit, receive the message, and turn it back up again */
        ASSERT_OK_ERRNO(getrlimit(RLIMIT_NOFILE, &orig_rl));
        new_rl.rlim_cur = n_fds_to_send * 2;
        new_rl.rlim_max = orig_rl.rlim_max;
        ASSERT_OK_ERRNO(setrlimit(RLIMIT_NOFILE, &new_rl));

        /* The very first message should be the one we expect */
        ASSERT_OK(get_one_message(bus, &recvd));
        ASSERT_TRUE(sd_bus_message_is_method_call(recvd, "org.freedesktop.systemd.test", "SendFds"));

        /* This needs to succeed or the following tests are going to be unhappy... */
        ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &orig_rl), 0);

        /* Try to read all the fds. We expect at least one to fail with -EBADMSG due to
         * truncation, and all subsequent reads must also fail with -EBADMSG. */
        int i;
        ASSERT_OK(sd_bus_message_enter_container(recvd, SD_BUS_TYPE_ARRAY, "h"));
        for (i = 0; i < n_fds_to_send; i++) {
                int fd; /* weakly owned: the fd belongs to the message */
                r = sd_bus_message_read_basic(recvd, 'h', &fd);
                if (r == -EBADMSG)
                        /* Good!  We were expecting this! */
                        break;
                ASSERT_OK(r);
                ASSERT_EQ(get_inode(fd), memfd_st_ino[i]);
        }

        /* Make sure we successfully sent at least one fd but not all of them */
        ASSERT_GT(i, 0);
        ASSERT_LT(i, n_fds_to_send);
        log_info("fds truncated at %i", i);

        /* At this point we're stuck.  We can call sd_bus_message_read_basic() as often as we want, but we
         * won't be able to make progress and won't be able to close the array or read anything else in the
         * message.
         */
        for (i = 0; i < 2 * n_fds_to_send; i++) {
                int fd; /* weakly owned: the fd belongs to the message */
                ASSERT_ERROR(sd_bus_message_read_basic(recvd, 'h', &fd), EBADMSG);
        }
        ASSERT_ERROR(sd_bus_message_exit_container(recvd), EBUSY);
        recvd = sd_bus_message_unref(recvd);

        /* Send the message again without the fd limits to make sure the connection still works */
        ASSERT_OK(sd_bus_send(bus, sent, NULL));
        ASSERT_OK(get_one_message(bus, &recvd));
        ASSERT_TRUE(sd_bus_message_is_method_call(recvd, "org.freedesktop.systemd.test", "SendFds"));

        /* Read all the fds. */
        ASSERT_EQ(sd_bus_message_enter_container(recvd, SD_BUS_TYPE_ARRAY, "h"), 1);
        for (i = 0; i < n_fds_to_send; i++) {
                int fd; /* weakly owned: the fd belongs to the message */
                ASSERT_OK(sd_bus_message_read_basic(recvd, 'h', &fd));
                ASSERT_EQ(get_inode(fd), memfd_st_ino[i]);
        }
        ASSERT_OK(sd_bus_message_exit_container(recvd));

        log_info("MSG_CTRUNC test passed");
}

TEST(chat) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        pthread_t c1, c2;
        void *p;
        int r;

        test_setup_logging(LOG_INFO);

        r = server_init(&bus);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to connect to bus: %m");

        log_info("Initialized...");

        ASSERT_OK(-pthread_create(&c1, NULL, client1, NULL));
        ASSERT_OK(-pthread_create(&c2, NULL, client2, NULL));

        r = server(bus);

        ASSERT_OK(-pthread_join(c1, &p));
        ASSERT_OK(PTR_TO_INT(p));
        ASSERT_OK(-pthread_join(c2, &p));
        ASSERT_OK(PTR_TO_INT(p));
        ASSERT_OK(r);
}

DEFINE_TEST_MAIN(LOG_INFO);
