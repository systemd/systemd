/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"
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

static void* thread_server(void *p) {
        _cleanup_free_ char *suffixed = NULL, *suffixed_basename = NULL, *suffixed2 = NULL, *d = NULL;
        _cleanup_close_ int fd = -EBADF;
        union sockaddr_union u;
        const char *path = p;
        int r;

        log_debug("Initializing server");

        /* Let's play some games, by slowly creating the socket directory, and renaming it in the middle */
        usleep_safe(100 * USEC_PER_MSEC);

        ASSERT_OK(mkdir_parents(path, 0755));
        usleep_safe(100 * USEC_PER_MSEC);

        ASSERT_OK(path_extract_directory(path, &d));
        ASSERT_OK(asprintf(&suffixed, "%s.%" PRIx64, d, random_u64()));
        ASSERT_OK_ERRNO(rename(d, suffixed));
        usleep_safe(100 * USEC_PER_MSEC);

        ASSERT_OK(asprintf(&suffixed2, "%s.%" PRIx64, d, random_u64()));
        ASSERT_OK_ERRNO(symlink(suffixed2, d));
        usleep_safe(100 * USEC_PER_MSEC);

        ASSERT_OK(path_extract_filename(suffixed, &suffixed_basename));
        ASSERT_OK_ERRNO(symlink(suffixed_basename, suffixed2));
        usleep_safe(100 * USEC_PER_MSEC);

        socklen_t sa_len;
        r = sockaddr_un_set_path(&u.un, path);
        ASSERT_OK(r);
        sa_len = r;

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        ASSERT_OK_ERRNO(fd);

        ASSERT_OK_ERRNO(bind(fd, &u.sa, sa_len));
        usleep_safe(100 * USEC_PER_MSEC);

        ASSERT_OK_ERRNO(listen(fd, SOMAXCONN_DELUXE));
        usleep_safe(100 * USEC_PER_MSEC);

        ASSERT_OK(touch(path));
        usleep_safe(100 * USEC_PER_MSEC);

        log_debug("Initialized server");

        for (;;) {
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _cleanup_(sd_event_unrefp) sd_event *event = NULL;
                sd_id128_t id;
                int bus_fd, code;

                ASSERT_OK(sd_id128_randomize(&id));

                ASSERT_OK(sd_event_new(&event));

                bus_fd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
                ASSERT_OK_ERRNO(bus_fd);

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

        return NULL;
}

static void* thread_client1(void *p) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        const char *path = p, *t;

        log_debug("Initializing client1");

        ASSERT_OK(sd_bus_new(&bus));
        ASSERT_OK(sd_bus_set_description(bus, "client1"));

        t = strjoina("unix:path=", path);
        ASSERT_OK(sd_bus_set_address(bus, t));
        ASSERT_OK(sd_bus_set_watch_bind(bus, true));
        ASSERT_OK(sd_bus_start(bus));

        ASSERT_OK(sd_bus_call_method(bus, "foo.bar", "/foo", "foo.TestInterface", "Foobar", &error, NULL, NULL));

        log_debug("Client1 done");

        return NULL;
}

static int client2_callback(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        ASSERT_OK_ZERO(sd_bus_message_is_method_error(m, NULL));
        ASSERT_OK(sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), 0));
        return 0;
}

static void* thread_client2(void *p) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        const char *path = p, *t;

        log_debug("Initializing client2");

        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK(sd_bus_new(&bus));
        ASSERT_OK(sd_bus_set_description(bus, "client2"));

        t = strjoina("unix:path=", path);
        ASSERT_OK(sd_bus_set_address(bus, t));
        ASSERT_OK(sd_bus_set_watch_bind(bus, true));
        ASSERT_OK(sd_bus_attach_event(bus, event, 0));
        ASSERT_OK(sd_bus_start(bus));

        ASSERT_OK(sd_bus_call_method_async(bus, NULL, "foo.bar", "/foo", "foo.TestInterface", "Foobar", client2_callback, NULL, NULL));

        ASSERT_OK(sd_event_loop(event));

        log_debug("Client2 done");

        return NULL;
}

static void request_exit(const char *path) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        const char *t;

        ASSERT_OK(sd_bus_new(&bus));

        t = strjoina("unix:path=", path);
        ASSERT_OK(sd_bus_set_address(bus, t));
        ASSERT_OK(sd_bus_set_watch_bind(bus, true));
        ASSERT_OK(sd_bus_set_description(bus, "request-exit"));
        ASSERT_OK(sd_bus_start(bus));

        ASSERT_OK(sd_bus_call_method(bus, "foo.bar", "/foo", "foo.TestInterface", "Exit", NULL, NULL, NULL));
}

int main(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        pthread_t server, client1, client2;
        char *path;

        test_setup_logging(LOG_DEBUG);

        /* We use /dev/shm here rather than /tmp, since some weird distros might set up /tmp as some weird fs that
         * doesn't support inotify properly. */
        ASSERT_OK(mkdtemp_malloc("/dev/shm/systemd-watch-bind-XXXXXX", &d));

        path = strjoina(d, "/this/is/a/socket");

        ASSERT_OK(-pthread_create(&server, NULL, thread_server, path));
        ASSERT_OK(-pthread_create(&client1, NULL, thread_client1, path));
        ASSERT_OK(-pthread_create(&client2, NULL, thread_client2, path));

        ASSERT_OK(-pthread_join(client1, NULL));
        ASSERT_OK(-pthread_join(client2, NULL));

        request_exit(path);

        ASSERT_OK(-pthread_join(server, NULL));

        return 0;
}
