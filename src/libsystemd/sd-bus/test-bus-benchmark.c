/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "fd-util.h"
#include "tests.h"
#include "time-util.h"

#define MAX_SIZE (2*1024*1024)

static usec_t arg_loop_usec = 100 * USEC_PER_MSEC;

typedef enum Type {
        TYPE_LEGACY,
        TYPE_DIRECT,
} Type;

static void server(sd_bus *b, size_t *result) {
        int r;

        assert(result);

        for (;;) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = ASSERT_OK(sd_bus_process(b, &m));

                if (r == 0)
                        ASSERT_OK(sd_bus_wait(b, USEC_INFINITY));
                if (!m)
                        continue;

                if (sd_bus_message_is_method_call(m, "benchmark.server", "Ping"))
                        ASSERT_OK(sd_bus_reply_method_return(m, /* types= */ NULL));
                else if (sd_bus_message_is_method_call(m, "benchmark.server", "Work")) {
                        const void *p;
                        size_t sz;

                        /* Make sure the mmap is mapped */
                        ASSERT_OK_POSITIVE(sd_bus_message_read_array(m, 'y', &p, &sz));

                        ASSERT_OK(sd_bus_reply_method_return(m, /* types= */ NULL));
                } else if (sd_bus_message_is_method_call(m, "benchmark.server", "Exit")) {
                        uint64_t res;
                        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "t", &res));

                        *result = res;
                        return;

                } else if (!sd_bus_message_is_signal(m, /* interface= */ NULL, /* member= */ NULL))
                        assert_not_reached();
        }
}

static void transaction(sd_bus *b, size_t sz, const char *server_name) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        uint8_t *p;

        ASSERT_OK(sd_bus_message_new_method_call(b, &m, server_name, "/", "benchmark.server", "Work"));
        ASSERT_OK(sd_bus_message_append_array_space(m, 'y', sz, (void**) &p));

        memset(p, 0x80, sz);

        ASSERT_OK(sd_bus_call(b, m, /* usec= */ 0, /* reterr_error= */ NULL, &reply));
}

static void client_bisect(const char *address, const char *server_name) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *x = NULL;
        size_t lsize, rsize, csize;
        sd_bus *b;

        ASSERT_OK(sd_bus_new(&b));

        ASSERT_OK(sd_bus_set_address(b, address));

        ASSERT_OK(sd_bus_start(b));

        ASSERT_OK(sd_bus_call_method(b, server_name, "/", "benchmark.server", "Ping", /* reterr_error= */ NULL, /* ret_reply= */ NULL, /* types= */ NULL));

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
        ASSERT_OK(sd_bus_message_new_method_call(b, &x, server_name, "/", "benchmark.server", "Exit"));
        ASSERT_OK(sd_bus_message_append(x, "t", csize));
        ASSERT_OK(sd_bus_send(b, x, /* ret_cookie= */ NULL));

        sd_bus_unref(b);
}

static void client_chart(Type type, const char *address, const char *server_name, int fd) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *x = NULL;
        size_t csize;
        sd_bus *b;

        ASSERT_OK(sd_bus_new(&b));

        if (type == TYPE_DIRECT) {
                ASSERT_OK(sd_bus_set_fd(b, fd, fd));
        } else {
                ASSERT_OK(sd_bus_set_address(b, address));

                ASSERT_OK(sd_bus_set_bus_client(b, true));
        }

        ASSERT_OK(sd_bus_start(b));

        ASSERT_OK(sd_bus_call_method(b, server_name, "/", "benchmark.server", "Ping", /* reterr_error= */ NULL, /* ret_reply= */ NULL, /* types= */ NULL));

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
        ASSERT_OK(sd_bus_message_new_method_call(b, &x, server_name, "/", "benchmark.server", "Exit"));
        ASSERT_OK(sd_bus_message_append(x, "t", csize));
        ASSERT_OK(sd_bus_send(b, x, /* ret_cookie= */ NULL));

        sd_bus_unref(b);
}

int main(int argc, char *argv[]) {
        enum {
                MODE_BISECT,
                MODE_CHART,
        } mode = MODE_BISECT;
        Type type = TYPE_LEGACY;
        int i, pair[2] = EBADF_PAIR;
        _cleanup_free_ char *address = NULL, *server_name = NULL;
        _cleanup_close_ int bus_ref = -EBADF;
        const char *unique;
        cpu_set_t cpuset;
        size_t result;
        sd_bus *b;
        pid_t pid;

        test_setup_logging(LOG_DEBUG);

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

                ASSERT_OK(parse_sec(argv[i], &arg_loop_usec));
        }

        ASSERT_GT(arg_loop_usec, 0U);

        if (type == TYPE_LEGACY) {
                const char *e;

                e = ASSERT_NOT_NULL(secure_getenv("DBUS_SESSION_BUS_ADDRESS"));

                address = ASSERT_NOT_NULL(strdup(e));
        }

        ASSERT_OK(sd_bus_new(&b));

        if (type == TYPE_DIRECT) {
                ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM, 0, pair));

                ASSERT_OK(sd_bus_set_fd(b, pair[0], pair[0]));

                ASSERT_OK(sd_bus_set_server(b, true, SD_ID128_NULL));
        } else {
                ASSERT_OK(sd_bus_set_address(b, address));

                ASSERT_OK(sd_bus_set_bus_client(b, true));
        }

        ASSERT_OK(sd_bus_start(b));

        if (type != TYPE_DIRECT) {
                ASSERT_OK(sd_bus_get_unique_name(b, &unique));

                server_name = ASSERT_NOT_NULL(strdup(unique));
        }

        sync();
        setpriority(PRIO_PROCESS, 0, -19);

        pid = ASSERT_OK_ERRNO(fork());

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

        ASSERT_OK_EQ_ERRNO(waitpid(pid, NULL, 0), pid);

        safe_close(pair[1]);
        sd_bus_unref(b);

        return 0;
}
