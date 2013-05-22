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

#define N_TRIES 500
#define MAX_SIZE (5*1024*1024)

static void server(sd_bus *b, usec_t *result) {
        usec_t x = 0;
        int r;

        for (;;) {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;

                r = sd_bus_process(b, &m);
                assert_se(r >= 0);

                if (r == 0)
                        assert_se(sd_bus_wait(b, (usec_t) -1) >= 0);

                if (!m)
                        continue;

                /* log_error("huhu %s from %s", sd_bus_message_get_member(m), sd_bus_message_get_sender(m)); */

                if (sd_bus_message_is_method_call(m, "benchmark.server", "Work")) {
                        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
                        size_t i, sz;
                        char *q;
                        const char *p;

                        assert_se(sd_bus_message_read_array(m, 'y', (const void**) &p, &sz) > 0);
                        assert_se(sd_bus_message_new_method_return(b, m, &reply) >= 0);
                        assert_se(sd_bus_message_append_array_space(reply, 'y', sz, (void**) &q) >= 0);

                        x = now(CLOCK_MONOTONIC);

                        for (i = 0; i < sz; i++)
                                q[i] = toupper(p[i]);

                        x = now(CLOCK_MONOTONIC) - x;

                        assert_se(sd_bus_send(b, reply, NULL) >= 0);
                } else if (sd_bus_message_is_method_call(m, "benchmark.server", "Exit")) {
                        usec_t t;

                        assert_se(sd_bus_message_read(m, "t", &t) > 0);
                        assert_se(t >= x);
                        *result = t - x;
                        return;

                } else if (sd_bus_message_is_method_call(m, "benchmark.server", "Ping")) {
                        assert_se(sd_bus_reply_method_return(b, m, "y", 1) >= 0);
                } else
                        assert_not_reached("Unknown method");
        }
}

static void client(sd_bus *b, size_t sz) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        char *p;
        const char *q;
        usec_t t;
        size_t l, i;

        assert_se(sd_bus_call_method(b, ":1.1", "/", "benchmark.server", "Ping", NULL, NULL, NULL) >= 0);

        assert_se(sd_bus_message_new_method_call(b, ":1.1", "/", "benchmark.server", "Work", &m) >= 0);
        assert_se(sd_bus_message_append_array_space(m, 'y', sz, (void**) &p) >= 0);

        for (i = 0; i < sz; i++)
                p[i] = 'a' + (char) (i % 26);

        t = now(CLOCK_MONOTONIC);
        assert_se(sd_bus_send_with_reply_and_block(b, m, 0, NULL, &reply) >= 0);
        t = now(CLOCK_MONOTONIC) - t;

        assert_se(sd_bus_message_read_array(reply, 'y', (const void**) &q, &l) > 0);
        assert_se(l == sz);

        for (i = 0; i < sz; i++) {
                assert_se(q[i] == 'A' + (char) (i % 26));
        }

        sd_bus_message_unref(m);

        assert_se(sd_bus_message_new_method_call(b, ":1.1", "/", "benchmark.server", "Exit", &m) >= 0);
        assert_se(sd_bus_message_append(m, "t", t) >= 0);
        assert_se(sd_bus_send(b, m, NULL) >= 0);
}

static void run_benchmark(size_t sz, bool force_copy, usec_t *result) {

        _cleanup_close_ int bus_ref = -1;
        _cleanup_free_ char *bus_name = NULL, *address = NULL;
        sd_bus *b;
        int r;
        pid_t pid;

        bus_ref = bus_kernel_create("deine-mutter", &bus_name);
        if (bus_ref == -ENOENT)
                exit(EXIT_TEST_SKIP);

        assert_se(bus_ref >= 0);

        address = strappend("kernel:path=", bus_name);
        assert_se(address);

        r = sd_bus_new(&b);
        assert_se(r >= 0);

        b->use_memfd = force_copy ? 0 : -1;

        r = sd_bus_set_address(b, address);
        assert_se(r >= 0);

        r = sd_bus_start(b);
        assert_se(r >= 0);

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                close_nointr_nofail(bus_ref);
                sd_bus_unref(b);

                r = sd_bus_new(&b);
                assert_se(r >= 0);

                b->use_memfd = force_copy ? 0 : -1;

                r = sd_bus_set_address(b, address);
                assert_se(r >= 0);

                r = sd_bus_start(b);
                assert_se(r >= 0);

                client(b, sz);
                _exit(0);
        }

        server(b, result);
        sd_bus_unref(b);

        assert_se(waitpid(pid, NULL, 0) == pid);
}

int main(int argc, char *argv[]) {
        size_t lsize, rsize, csize;

        log_set_max_level(LOG_DEBUG);

        lsize = 1;
        rsize = MAX_SIZE;

        for (;;) {
                usec_t copy = 0, memfd = 0;
                unsigned i;

                csize = (lsize + rsize) / 2;

                log_info("Trying size=%zu", csize);

                if (csize <= lsize)
                        break;

                for (i = 0; i <  N_TRIES; i++) {
                        usec_t t;

                        run_benchmark(csize, true, &t);
                        copy += t;
                }

                for (i = 0; i < N_TRIES; i++) {
                        usec_t t;

                        run_benchmark(csize, false, &t);
                        memfd += t;
                }

                copy /= N_TRIES;
                memfd /= N_TRIES;

                if (copy == memfd)
                        break;

                if (copy < memfd)
                        lsize = csize;
                else
                        rsize = csize;
        }

        log_info("Copying/memfd are equally fast at %zu", csize);

        return 0;
}
