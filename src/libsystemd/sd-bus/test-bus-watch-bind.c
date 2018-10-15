/* SPDX-License-Identifier: LGPL-2.1+ */

#include <pthread.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "socket-util.h"
#include "string-util.h"

static int method_foobar(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        log_info("Got Foobar() call.");

        assert_se(sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), 0) >= 0);
        return sd_bus_reply_method_return(m, NULL);
}

static int method_exit(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        log_info("Got Exit() call");
        assert_se(sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), 1) >= 0);
        return sd_bus_reply_method_return(m, NULL);
}

static const sd_bus_vtable vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Foobar", NULL, NULL, method_foobar, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Exit", NULL, NULL, method_exit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END,
};

static void* thread_server(void *p) {
        _cleanup_free_ char *suffixed = NULL, *suffixed2 = NULL, *d = NULL;
        _cleanup_close_ int fd = -1;
        union sockaddr_union u = {};
        const char *path = p;
        int salen;

        log_debug("Initializing server");

        /* Let's play some games, by slowly creating the socket directory, and renaming it in the middle */
        (void) usleep(100 * USEC_PER_MSEC);

        assert_se(mkdir_parents(path, 0755) >= 0);
        (void) usleep(100 * USEC_PER_MSEC);

        d = dirname_malloc(path);
        assert_se(d);
        assert_se(asprintf(&suffixed, "%s.%" PRIx64, d, random_u64()) >= 0);
        assert_se(rename(d, suffixed) >= 0);
        (void) usleep(100 * USEC_PER_MSEC);

        assert_se(asprintf(&suffixed2, "%s.%" PRIx64, d, random_u64()) >= 0);
        assert_se(symlink(suffixed2, d) >= 0);
        (void) usleep(100 * USEC_PER_MSEC);

        assert_se(symlink(basename(suffixed), suffixed2) >= 0);
        (void) usleep(100 * USEC_PER_MSEC);

        salen = sockaddr_un_set_path(&u.un, path);
        assert_se(salen >= 0);

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        assert_se(fd >= 0);

        assert_se(bind(fd, &u.sa, salen) >= 0);
        usleep(100 * USEC_PER_MSEC);

        assert_se(listen(fd, SOMAXCONN) >= 0);
        usleep(100 * USEC_PER_MSEC);

        assert_se(touch(path) >= 0);
        usleep(100 * USEC_PER_MSEC);

        log_debug("Initialized server");

        for (;;) {
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _cleanup_(sd_event_unrefp) sd_event *event = NULL;
                sd_id128_t id;
                int bus_fd, code;

                assert_se(sd_id128_randomize(&id) >= 0);

                assert_se(sd_event_new(&event) >= 0);

                bus_fd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
                assert_se(bus_fd >= 0);

                log_debug("Accepted server connection");

                assert_se(sd_bus_new(&bus) >= 0);
                assert_se(sd_bus_set_description(bus, "server") >= 0);
                assert_se(sd_bus_set_fd(bus, bus_fd, bus_fd) >= 0);
                assert_se(sd_bus_set_server(bus, true, id) >= 0);
                /* assert_se(sd_bus_set_anonymous(bus, true) >= 0); */

                assert_se(sd_bus_attach_event(bus, event, 0) >= 0);

                assert_se(sd_bus_add_object_vtable(bus, NULL, "/foo", "foo.TestInterface", vtable, NULL) >= 0);

                assert_se(sd_bus_start(bus) >= 0);

                assert_se(sd_event_loop(event) >= 0);

                assert_se(sd_event_get_exit_code(event, &code) >= 0);

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
        int r;

        log_debug("Initializing client1");

        assert_se(sd_bus_new(&bus) >= 0);
        assert_se(sd_bus_set_description(bus, "client1") >= 0);

        t = strjoina("unix:path=", path);
        assert_se(sd_bus_set_address(bus, t) >= 0);
        assert_se(sd_bus_set_watch_bind(bus, true) >= 0);
        assert_se(sd_bus_start(bus) >= 0);

        r = sd_bus_call_method(bus, "foo.bar", "/foo", "foo.TestInterface", "Foobar", &error, NULL, NULL);
        assert_se(r >= 0);

        log_debug("Client1 done");

        return NULL;
}

static int client2_callback(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        assert_se(sd_bus_message_is_method_error(m, NULL) == 0);
        assert_se(sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), 0) >= 0);
        return 0;
}

static void* thread_client2(void *p) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        const char *path = p, *t;

        log_debug("Initializing client2");

        assert_se(sd_event_new(&event) >= 0);
        assert_se(sd_bus_new(&bus) >= 0);
        assert_se(sd_bus_set_description(bus, "client2") >= 0);

        t = strjoina("unix:path=", path);
        assert_se(sd_bus_set_address(bus, t) >= 0);
        assert_se(sd_bus_set_watch_bind(bus, true) >= 0);
        assert_se(sd_bus_attach_event(bus, event, 0) >= 0);
        assert_se(sd_bus_start(bus) >= 0);

        assert_se(sd_bus_call_method_async(bus, NULL, "foo.bar", "/foo", "foo.TestInterface", "Foobar", client2_callback, NULL, NULL) >= 0);

        assert_se(sd_event_loop(event) >= 0);

        log_debug("Client2 done");

        return NULL;
}

static void request_exit(const char *path) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        const char *t;

        assert_se(sd_bus_new(&bus) >= 0);

        t = strjoina("unix:path=", path);
        assert_se(sd_bus_set_address(bus, t) >= 0);
        assert_se(sd_bus_set_watch_bind(bus, true) >= 0);
        assert_se(sd_bus_set_description(bus, "request-exit") >= 0);
        assert_se(sd_bus_start(bus) >= 0);

        assert_se(sd_bus_call_method(bus, "foo.bar", "/foo", "foo.TestInterface", "Exit", NULL, NULL, NULL) >= 0);
}

int main(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        pthread_t server, client1, client2;
        char *path;

        log_set_max_level(LOG_DEBUG);

        /* We use /dev/shm here rather than /tmp, since some weird distros might set up /tmp as some weird fs that
         * doesn't support inotify properly. */
        assert_se(mkdtemp_malloc("/dev/shm/systemd-watch-bind-XXXXXX", &d) >= 0);

        path = strjoina(d, "/this/is/a/socket");

        assert_se(pthread_create(&server, NULL, thread_server, path) == 0);
        assert_se(pthread_create(&client1, NULL, thread_client1, path) == 0);
        assert_se(pthread_create(&client2, NULL, thread_client2, path) == 0);

        assert_se(pthread_join(client1, NULL) == 0);
        assert_se(pthread_join(client2, NULL) == 0);

        request_exit(path);

        assert_se(pthread_join(server, NULL) == 0);

        return 0;
}
