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

#include "sd-bus.h"
#include "bus-message.h"
#include "bus-error.h"
#include "bus-kernel.h"
#include "bus-internal.h"

#define N_TRIES 10000
#define MAX_SIZE (1*1024*1024)

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
                        assert_se(sd_bus_reply_method_return(b, m, NULL) >= 0);
                else if (sd_bus_message_is_method_call(m, "benchmark.server", "Work")) {
                        const void *p;
                        size_t sz;

                        /* Make sure the mmap is mapped */
                        assert_se(sd_bus_message_read_array(m, 'y', &p, &sz) > 0);

                        assert_se(sd_bus_reply_method_return(b, m, NULL) >= 0);
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
        /* size_t psz, i; */
        uint8_t *p;

        assert_se(sd_bus_message_new_method_call(b, ":1.1", "/", "benchmark.server", "Work", &m) >= 0);
        assert_se(sd_bus_message_append_array_space(m, 'y', sz, (void**) &p) >= 0);

        /* Touch every page */
        /* psz = page_size(); */
        /* for (i = 0; i < sz; i += psz) */
        /*         p[i] = 'X'; */

        assert_se(sd_bus_send_with_reply_and_block(b, m, 0, NULL, &reply) >= 0);
}

static void client(const char *address) {
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

        for (;;) {
                usec_t copy, memfd, t;
                unsigned i;

                csize = (lsize + rsize) / 2;

                log_info("Trying size=%zu", csize);

                if (csize <= lsize)
                        break;

                if (csize <= 0)
                        break;

                log_info("copying...");
                b->use_memfd = 0;
                t = now(CLOCK_MONOTONIC);
                for (i = 0; i <  N_TRIES; i++)
                        transaction(b, csize);
                copy = (now(CLOCK_MONOTONIC) - t);
                log_info("%llu usec per copy transaction", (unsigned long long) (copy / N_TRIES));

                log_info("sending memfd...");
                b->use_memfd = -1;
                t = now(CLOCK_MONOTONIC);
                for (i = 0; i <  N_TRIES; i++)
                        transaction(b, csize);
                memfd = (now(CLOCK_MONOTONIC) - t);
                log_info("%llu usec per memfd transaction", (unsigned long long) (memfd / N_TRIES));

                if (copy == memfd)
                        break;

                if (copy < memfd)
                        lsize = csize;
                else
                        rsize = csize;
        }

        assert_se(sd_bus_message_new_method_call(b, ":1.1", "/", "benchmark.server", "Exit", &x) >= 0);
        assert_se(sd_bus_message_append(x, "t", csize) >= 0);
        assert_se(sd_bus_send(b, x, NULL) >= 0);

        sd_bus_unref(b);
}

int main(int argc, char *argv[]) {
        _cleanup_free_ char *bus_name = NULL, *address = NULL;
        _cleanup_close_ int bus_ref = -1;
        cpu_set_t cpuset;
        size_t result;
        sd_bus *b;
        pid_t pid;
        int r;

        log_set_max_level(LOG_DEBUG);

        bus_ref = bus_kernel_create("deine-mutter", &bus_name);
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

                close_nointr_nofail(bus_ref);
                sd_bus_unref(b);

                client(address);
                _exit(0);
        }

        CPU_ZERO(&cpuset);
        CPU_SET(1, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

        server(b, &result);

        log_info("Copying/memfd are equally fast at %zu", result);

        assert_se(waitpid(pid, NULL, 0) == pid);

        sd_bus_unref(b);

        return 0;
}
