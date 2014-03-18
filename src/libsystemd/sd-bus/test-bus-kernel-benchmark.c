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

#include <ctype.h>
#include <sys/wait.h>

#include "util.h"
#include "log.h"
#include "time-util.h"

#include "sd-bus.h"
#include "bus-message.h"
#include "bus-error.h"
#include "bus-kernel.h"
#include "bus-internal.h"
#include "bus-util.h"

#define MAX_SIZE (4*1024*1024)

static usec_t arg_loop_usec = 100 * USEC_PER_MSEC;

static void server(sd_bus *b, size_t *result) {
        int r;

        for (;;) {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;

                r = sd_bus_process(b, &m);
                assert_se(r >= 0);

                if (r == 0)
                        assert_se(sd_bus_wait(b, (usec_t) -1) >= 0);
                if (!m)
                        continue;

                if (sd_bus_message_is_method_call(m, "benchmark.server", "Ping"))
                        assert_se(sd_bus_reply_method_return(m, NULL) >= 0);
                else if (sd_bus_message_is_method_call(m, "benchmark.server", "Work")) {
                        const void *p;
                        size_t sz;

                        /* Make sure the mmap is mapped */
                        assert_se(sd_bus_message_read_array(m, 'y', &p, &sz) > 0);

                        assert_se(sd_bus_reply_method_return(m, NULL) >= 0);
                } else if (sd_bus_message_is_method_call(m, "benchmark.server", "Exit")) {
                        uint64_t res;
                        assert_se(sd_bus_message_read(m, "t", &res) > 0);

                        *result = res;
                        return;

                } else
                        assert_not_reached("Unknown method");
        }
}

static void transaction(sd_bus *b, size_t sz) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        uint8_t *p;

        assert_se(sd_bus_message_new_method_call(b, &m, ":1.1", "/", "benchmark.server", "Work") >= 0);
        assert_se(sd_bus_message_append_array_space(m, 'y', sz, (void**) &p) >= 0);

        memset(p, 0x80, sz);

        assert_se(sd_bus_call(b, m, 0, NULL, &reply) >= 0);
}

static void client_bisect(const char *address) {
        _cleanup_bus_message_unref_ sd_bus_message *x = NULL;
        size_t lsize, rsize, csize;
        sd_bus *b;
        int r;

        r = sd_bus_new(&b);
        assert_se(r >= 0);

        r = sd_bus_set_address(b, address);
        assert_se(r >= 0);

        r = sd_bus_start(b);
        assert_se(r >= 0);

        assert_se(sd_bus_call_method(b, ":1.1", "/", "benchmark.server", "Ping", NULL, NULL, NULL) >= 0);

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
                        transaction(b, csize);
                        if (now(CLOCK_MONOTONIC) >= t + arg_loop_usec)
                                break;
                }
                printf("%u\t", (unsigned) ((n_copying * USEC_PER_SEC) / arg_loop_usec));

                b->use_memfd = -1;

                t = now(CLOCK_MONOTONIC);
                for (n_memfd = 0;; n_memfd++) {
                        transaction(b, csize);
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
        assert_se(sd_bus_message_new_method_call(b, &x, ":1.1", "/", "benchmark.server", "Exit") >= 0);
        assert_se(sd_bus_message_append(x, "t", csize) >= 0);
        assert_se(sd_bus_send(b, x, NULL) >= 0);

        sd_bus_unref(b);
}

static void client_chart(const char *address) {
        _cleanup_bus_message_unref_ sd_bus_message *x = NULL;
        size_t csize;
        sd_bus *b;
        int r;

        r = sd_bus_new(&b);
        assert_se(r >= 0);

        r = sd_bus_set_address(b, address);
        assert_se(r >= 0);

        r = sd_bus_start(b);
        assert_se(r >= 0);

        assert_se(sd_bus_call_method(b, ":1.1", "/", "benchmark.server", "Ping", NULL, NULL, NULL) >= 0);

        printf("SIZE\tCOPY\tMEMFD\n");

        for (csize = 1; csize <= MAX_SIZE; csize *= 2) {
                usec_t t;
                unsigned n_copying, n_memfd;

                printf("%zu\t", csize);

                b->use_memfd = 0;

                t = now(CLOCK_MONOTONIC);
                for (n_copying = 0;; n_copying++) {
                        transaction(b, csize);
                        if (now(CLOCK_MONOTONIC) >= t + arg_loop_usec)
                                break;
                }

                printf("%u\t", (unsigned) ((n_copying * USEC_PER_SEC) / arg_loop_usec));

                b->use_memfd = -1;

                t = now(CLOCK_MONOTONIC);
                for (n_memfd = 0;; n_memfd++) {
                        transaction(b, csize);
                        if (now(CLOCK_MONOTONIC) >= t + arg_loop_usec)
                                break;
                }

                printf("%u\n", (unsigned) ((n_memfd * USEC_PER_SEC) / arg_loop_usec));
        }

        b->use_memfd = 1;
        assert_se(sd_bus_message_new_method_call(b, &x, ":1.1", "/", "benchmark.server", "Exit") >= 0);
        assert_se(sd_bus_message_append(x, "t", csize) >= 0);
        assert_se(sd_bus_send(b, x, NULL) >= 0);

        sd_bus_unref(b);
}

int main(int argc, char *argv[]) {
        enum {
                MODE_BISECT,
                MODE_CHART,
        } mode = MODE_BISECT;
        int i;
        _cleanup_free_ char *name = NULL, *bus_name = NULL, *address = NULL;
        _cleanup_close_ int bus_ref = -1;
        cpu_set_t cpuset;
        size_t result;
        sd_bus *b;
        pid_t pid;
        int r;

        for (i = 1; i < argc; i++) {
                if (streq(argv[i], "chart")) {
                        mode = MODE_CHART;
                        continue;
                }

                assert_se(parse_sec(argv[i], &arg_loop_usec) >= 0);
        }

        assert_se(arg_loop_usec > 0);

        assert_se(asprintf(&name, "deine-mutter-%u", (unsigned) getpid()) >= 0);

        bus_ref = bus_kernel_create_bus(name, false, &bus_name);
        if (bus_ref == -ENOENT)
                exit(EXIT_TEST_SKIP);

        assert_se(bus_ref >= 0);

        address = strappend("kernel:path=", bus_name);
        assert_se(address);

        r = sd_bus_new(&b);
        assert_se(r >= 0);

        r = sd_bus_set_address(b, address);
        assert_se(r >= 0);

        r = sd_bus_start(b);
        assert_se(r >= 0);

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
                        client_bisect(address);
                        break;

                case MODE_CHART:
                        client_chart(address);
                        break;
                }

                _exit(0);
        }

        CPU_ZERO(&cpuset);
        CPU_SET(1, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

        server(b, &result);

        if (mode == MODE_BISECT)
                printf("Copying/memfd are equally fast at %zu bytes\n", result);

        assert_se(waitpid(pid, NULL, 0) == pid);

        sd_bus_unref(b);

        return 0;
}
