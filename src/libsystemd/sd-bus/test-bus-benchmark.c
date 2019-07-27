/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/wait.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-kernel.h"
#include "bus-util.h"
#include "def.h"
#include "fd-util.h"
#include "missing_resource.h"
#include "time-util.h"
#include "util.h"

#define MAX_SIZE (2*1024*1024)

static usec_t arg_loop_usec = 100 * USEC_PER_MSEC;

typedef enum Type {
        TYPE_LEGACY,
        TYPE_DIRECT,
} Type;

static void server(sd_bus *b, size_t *result) {
        int r;

        for (;;) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = sd_bus_process(b, &m);
                assert_se(r >= 0);

                if (r == 0)
                        assert_se(sd_bus_wait(b, USEC_INFINITY) >= 0);
                if (!m)
                        continue;

                if (sd_bus_message_is_method_call(m, "benchmark.server", "Ping"))
                        assert_se(sd_bus_reply_method_return(m, NULL) >= 0);
                else if (sd_bus_message_is_method_call(m, "benchmark.server", "Work")) {
                        const void *p;
                        size_t sz;

                        /* Make sure the mmap is mapped */
                        assert_se(sd_bus_message_read_array(m, 'y', &p, &sz) > 0);

                        r = sd_bus_reply_method_return(m, NULL);
                        assert_se(r >= 0);
                } else if (sd_bus_message_is_method_call(m, "benchmark.server", "Exit")) {
                        uint64_t res;
                        assert_se(sd_bus_message_read(m, "t", &res) > 0);

                        *result = res;
                        return;

                } else if (!sd_bus_message_is_signal(m, NULL, NULL))
                        assert_not_reached("Unknown method");
        }
}

static void transaction(sd_bus *b, size_t sz, const char *server_name) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        uint8_t *p;

        assert_se(sd_bus_message_new_method_call(b, &m, server_name, "/", "benchmark.server", "Work") >= 0);
        assert_se(sd_bus_message_append_array_space(m, 'y', sz, (void**) &p) >= 0);

        memset(p, 0x80, sz);

        assert_se(sd_bus_call(b, m, 0, NULL, &reply) >= 0);
}

static void client_bisect(const char *address, const char *server_name) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *x = NULL;
        size_t lsize, rsize, csize;
        sd_bus *b;
        int r;

        r = sd_bus_new(&b);
        assert_se(r >= 0);

        r = sd_bus_set_address(b, address);
        assert_se(r >= 0);

        r = sd_bus_start(b);
        assert_se(r >= 0);

        r = sd_bus_call_method(b, server_name, "/", "benchmark.server", "Ping", NULL, NULL, NULL);
        assert_se(r >= 0);

        lsize = 1;
        rsize = MAX_SIZE;

        printf("SIZE\tCOPY\tMEMFD\n");

        for (;;) {
                usec_t t;
                unsigned n_copying, n_memfd;

                csize = (lsize + rsize) / 2;

                if (csize <= lsize)
                        break;

                if (csize <= 0)
                        break;

                printf("%zu\t", csize);

                b->use_memfd = 0;

                t = now(CLOCK_MONOTONIC);
                for (n_copying = 0;; n_copying++) {
                        transaction(b, csize, server_name);
                        if (now(CLOCK_MONOTONIC) >= t + arg_loop_usec)
                                break;
                }
                printf("%u\t", (unsigned) ((n_copying * USEC_PER_SEC) / arg_loop_usec));

                b->use_memfd = -1;

                t = now(CLOCK_MONOTONIC);
                for (n_memfd = 0;; n_memfd++) {
                        transaction(b, csize, server_name);
                        if (now(CLOCK_MONOTONIC) >= t + arg_loop_usec)
                                break;
                }
                printf("%u\n", (unsigned) ((n_memfd * USEC_PER_SEC) / arg_loop_usec));

                if (n_copying == n_memfd)
                        break;

                if (n_copying > n_memfd)
                        lsize = csize;
                else
                        rsize = csize;
        }

        b->use_memfd = 1;
        assert_se(sd_bus_message_new_method_call(b, &x, server_name, "/", "benchmark.server", "Exit") >= 0);
        assert_se(sd_bus_message_append(x, "t", csize) >= 0);
        assert_se(sd_bus_send(b, x, NULL) >= 0);

        sd_bus_unref(b);
}

static void client_chart(Type type, const char *address, const char *server_name, int fd) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *x = NULL;
        size_t csize;
        sd_bus *b;
        int r;

        r = sd_bus_new(&b);
        assert_se(r >= 0);

        if (type == TYPE_DIRECT) {
                r = sd_bus_set_fd(b, fd, fd);
                assert_se(r >= 0);
        } else {
                r = sd_bus_set_address(b, address);
                assert_se(r >= 0);

                r = sd_bus_set_bus_client(b, true);
                assert_se(r >= 0);
        }

        r = sd_bus_start(b);
        assert_se(r >= 0);

        r = sd_bus_call_method(b, server_name, "/", "benchmark.server", "Ping", NULL, NULL, NULL);
        assert_se(r >= 0);

        switch (type) {
        case TYPE_LEGACY:
                printf("SIZE\tLEGACY\n");
                break;
        case TYPE_DIRECT:
                printf("SIZE\tDIRECT\n");
                break;
        }

        for (csize = 1; csize <= MAX_SIZE; csize *= 2) {
                usec_t t;
                unsigned n_memfd;

                printf("%zu\t", csize);

                t = now(CLOCK_MONOTONIC);
                for (n_memfd = 0;; n_memfd++) {
                        transaction(b, csize, server_name);
                        if (now(CLOCK_MONOTONIC) >= t + arg_loop_usec)
                                break;
                }

                printf("%u\n", (unsigned) ((n_memfd * USEC_PER_SEC) / arg_loop_usec));
        }

        b->use_memfd = 1;
        assert_se(sd_bus_message_new_method_call(b, &x, server_name, "/", "benchmark.server", "Exit") >= 0);
        assert_se(sd_bus_message_append(x, "t", csize) >= 0);
        assert_se(sd_bus_send(b, x, NULL) >= 0);

        sd_bus_unref(b);
}

int main(int argc, char *argv[]) {
        enum {
                MODE_BISECT,
                MODE_CHART,
        } mode = MODE_BISECT;
        Type type = TYPE_LEGACY;
        int i, pair[2] = { -1, -1 };
        _cleanup_free_ char *address = NULL, *server_name = NULL;
        _cleanup_close_ int bus_ref = -1;
        const char *unique;
        cpu_set_t cpuset;
        size_t result;
        sd_bus *b;
        pid_t pid;
        int r;

        for (i = 1; i < argc; i++) {
                if (streq(argv[i], "chart")) {
                        mode = MODE_CHART;
                        continue;
                } else if (streq(argv[i], "legacy")) {
                        type = TYPE_LEGACY;
                        continue;
                } else if (streq(argv[i], "direct")) {
                        type = TYPE_DIRECT;
                        continue;
                }

                assert_se(parse_sec(argv[i], &arg_loop_usec) >= 0);
        }

        assert_se(arg_loop_usec > 0);

        if (type == TYPE_LEGACY) {
                const char *e;

                e = secure_getenv("DBUS_SESSION_BUS_ADDRESS");
                assert_se(e);

                address = strdup(e);
                assert_se(address);
        }

        r = sd_bus_new(&b);
        assert_se(r >= 0);

        if (type == TYPE_DIRECT) {
                assert_se(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) >= 0);

                r = sd_bus_set_fd(b, pair[0], pair[0]);
                assert_se(r >= 0);

                r = sd_bus_set_server(b, true, SD_ID128_NULL);
                assert_se(r >= 0);
        } else {
                r = sd_bus_set_address(b, address);
                assert_se(r >= 0);

                r = sd_bus_set_bus_client(b, true);
                assert_se(r >= 0);
        }

        r = sd_bus_start(b);
        assert_se(r >= 0);

        if (type != TYPE_DIRECT) {
                r = sd_bus_get_unique_name(b, &unique);
                assert_se(r >= 0);

                server_name = strdup(unique);
                assert_se(server_name);
        }

        sync();
        setpriority(PRIO_PROCESS, 0, -19);

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                CPU_ZERO(&cpuset);
                CPU_SET(0, &cpuset);
                pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

                safe_close(bus_ref);
                sd_bus_unref(b);

                switch (mode) {
                case MODE_BISECT:
                        client_bisect(address, server_name);
                        break;

                case MODE_CHART:
                        client_chart(type, address, server_name, pair[1]);
                        break;
                }

                _exit(EXIT_SUCCESS);
        }

        CPU_ZERO(&cpuset);
        CPU_SET(1, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

        server(b, &result);

        if (mode == MODE_BISECT)
                printf("Copying/memfd are equally fast at %zu bytes\n", result);

        assert_se(waitpid(pid, NULL, 0) == pid);

        safe_close(pair[1]);
        sd_bus_unref(b);

        return 0;
}
