/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-future.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "fd-util.h"
#include "fs-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "socket-util.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

static int method_foobar(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        log_info("Got Foobar() call.");

        ASSERT_OK(sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), 0));
        return sd_bus_reply_method_return(m, NULL);
}

static int method_exit(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        log_info("Got Exit() call");

        ASSERT_OK(sd_bus_reply_method_return(m, NULL));
        /* Simulate D-Bus going away to test the bus_exit_now() path with exit_on_disconnect set */
        bus_enter_closing(sd_bus_message_get_bus(m), EXIT_FAILURE);
        return 0;
}

static const sd_bus_vtable vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Foobar", NULL, NULL, method_foobar, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Exit", NULL, NULL, method_exit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END,
};

static int server(void *userdata) {
        _cleanup_free_ char *suffixed = NULL, *suffixed_basename = NULL, *suffixed2 = NULL, *d = NULL;
        _cleanup_close_ int fd = -EBADF;
        union sockaddr_union u;
        const char *path = ASSERT_PTR(userdata);
        int r;

        log_debug("Initializing server");

        /* Let's play some games, by slowly creating the socket directory, and renaming it in the middle */
        ASSERT_OK(sd_fiber_sleep(100 * USEC_PER_MSEC));

        ASSERT_OK(mkdir_parents(path, 0755));
        ASSERT_OK(sd_fiber_sleep(100 * USEC_PER_MSEC));

        ASSERT_OK(path_extract_directory(path, &d));
        ASSERT_OK(asprintf(&suffixed, "%s.%" PRIx64, d, random_u64()));
        ASSERT_OK_ERRNO(rename(d, suffixed));
        ASSERT_OK(sd_fiber_sleep(100 * USEC_PER_MSEC));

        ASSERT_OK(asprintf(&suffixed2, "%s.%" PRIx64, d, random_u64()));
        ASSERT_OK_ERRNO(symlink(suffixed2, d));
        ASSERT_OK(sd_fiber_sleep(100 * USEC_PER_MSEC));

        ASSERT_OK(path_extract_filename(suffixed, &suffixed_basename));
        ASSERT_OK_ERRNO(symlink(suffixed_basename, suffixed2));
        ASSERT_OK(sd_fiber_sleep(100 * USEC_PER_MSEC));

        socklen_t sa_len;
        r = sockaddr_un_set_path(&u.un, path);
        ASSERT_OK(r);
        sa_len = r;

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        ASSERT_OK_ERRNO(fd);

        ASSERT_OK_ERRNO(bind(fd, &u.sa, sa_len));
        ASSERT_OK(sd_fiber_sleep(100 * USEC_PER_MSEC));

        ASSERT_OK_ERRNO(listen(fd, SOMAXCONN_DELUXE));
        ASSERT_OK(sd_fiber_sleep(100 * USEC_PER_MSEC));

        ASSERT_OK(touch(path));
        ASSERT_OK(sd_fiber_sleep(100 * USEC_PER_MSEC));

        log_debug("Initialized server");

        for (;;) {
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _cleanup_(sd_event_unrefp) sd_event *event = NULL;
                sd_id128_t id;
                int bus_fd, code;

                ASSERT_OK(sd_id128_randomize(&id));

                ASSERT_OK(sd_event_new(&event));

                ASSERT_OK(bus_fd = sd_fiber_accept(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC));

                log_debug("Accepted server connection");

                ASSERT_OK(sd_bus_new(&bus));
                ASSERT_OK(sd_bus_set_exit_on_disconnect(bus, true));
                ASSERT_OK(sd_bus_set_description(bus, "server"));
                ASSERT_OK(sd_bus_set_fd(bus, bus_fd, bus_fd));
                ASSERT_OK(sd_bus_set_server(bus, true, id));
                /* ASSERT_OK(sd_bus_set_anonymous(bus, true)); */

                ASSERT_OK(sd_bus_attach_event(bus, event, 0));

                ASSERT_OK(sd_bus_add_object_vtable(bus, NULL, "/foo", "foo.TestInterface", vtable, NULL));

                ASSERT_OK(sd_bus_start(bus));

                ASSERT_OK(sd_event_loop(event));

                ASSERT_OK(sd_event_get_exit_code(event, &code));

                if (code > 0)
                        break;
        }

        log_debug("Server done");

        return 0;
}

static int client1(void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        const char *path = ASSERT_PTR(userdata), *t;

        log_debug("Initializing client1");

        ASSERT_OK(sd_bus_new(&bus));
        ASSERT_OK(sd_bus_set_description(bus, "client1"));

        t = strjoina("unix:path=", path);
        ASSERT_OK(sd_bus_set_address(bus, t));
        ASSERT_OK(sd_bus_set_watch_bind(bus, true));
        ASSERT_OK(sd_bus_start(bus));

        ASSERT_OK(sd_bus_call_method(bus, "foo.bar", "/foo", "foo.TestInterface", "Foobar", &error, NULL, NULL));

        log_debug("Client1 done");

        return 0;
}

static int client2(void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        const char *path = ASSERT_PTR(userdata), *t;

        log_debug("Initializing client2");

        ASSERT_OK(sd_bus_new(&bus));
        ASSERT_OK(sd_bus_set_description(bus, "client2"));

        t = strjoina("unix:path=", path);
        ASSERT_OK(sd_bus_set_address(bus, t));
        ASSERT_OK(sd_bus_set_watch_bind(bus, true));
        ASSERT_OK(sd_bus_attach_event(bus, sd_fiber_get_event(), 0));
        ASSERT_OK(sd_bus_start(bus));

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        ASSERT_OK(sd_bus_call_method(bus, "foo.bar", "/foo", "foo.TestInterface", "Foobar", NULL, &m, NULL));

        ASSERT_OK_ZERO(sd_bus_message_is_method_error(m, NULL));
        log_debug("Client2 done");

        return 0;
}

typedef struct RequestExitArgs {
        const char *path;
        sd_future *client1;
        sd_future *client2;
} RequestExitArgs;

static int request_exit(void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        RequestExitArgs *args = ASSERT_PTR(userdata);
        const char *t;

        /* Wait for all client fibers to complete before requesting exit */
        ASSERT_OK(sd_fiber_await(args->client1));
        ASSERT_OK(sd_fiber_await(args->client2));

        ASSERT_OK(sd_bus_new(&bus));

        t = strjoina("unix:path=", args->path);
        ASSERT_OK(sd_bus_set_address(bus, t));
        ASSERT_OK(sd_bus_set_watch_bind(bus, true));
        ASSERT_OK(sd_bus_set_description(bus, "request-exit"));
        ASSERT_OK(sd_bus_start(bus));

        ASSERT_OK(sd_bus_call_method(bus, "foo.bar", "/foo", "foo.TestInterface", "Exit", NULL, NULL, NULL));

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f_server = NULL, *f_client1 = NULL, *f_client2 = NULL, *f_exit = NULL;
        char *path;

        test_setup_logging(LOG_DEBUG);

        /* We use /dev/shm here rather than /tmp, since some weird distros might set up /tmp as some weird fs that
         * doesn't support inotify properly. */
        ASSERT_OK(mkdtemp_malloc("/dev/shm/systemd-watch-bind-XXXXXX", &d));

        path = strjoina(d, "/this/is/a/socket");

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        ASSERT_OK(sd_future_new_fiber(e, "server", server, path, /* destroy= */ NULL, &f_server));

        ASSERT_OK(sd_future_new_fiber(e, "client-1", client1, path, /* destroy= */ NULL, &f_client1));
        ASSERT_OK(sd_future_new_fiber(e, "client-2", client2, path, /* destroy= */ NULL, &f_client2));

        RequestExitArgs args = {
                .path = path,
                .client1 = f_client1,
                .client2 = f_client2,
        };
        ASSERT_OK(sd_future_new_fiber(e, "request-exit", request_exit, &args, /* destroy= */ NULL, &f_exit));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK(sd_future_result(f_client1));
        ASSERT_OK(sd_future_result(f_client2));
        ASSERT_OK(sd_future_result(f_exit));
        ASSERT_OK(sd_future_result(f_server));

        return EXIT_SUCCESS;
}
