/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <signal.h>
#include <sys/mman.h>

#include "macro.h"
#include "sigbus.h"
#include "util.h"

#define SIGBUS_QUEUE_MAX 64

static struct sigaction old_sigaction;
static unsigned n_installed = 0;

/* We maintain a fixed size list of page addresses that triggered a
   SIGBUS. We access with list with atomic operations, so that we
   don't have to deal with locks between signal handler and main
   programs in possibly multiple threads. */

static void* volatile sigbus_queue[SIGBUS_QUEUE_MAX];
static volatile sig_atomic_t n_sigbus_queue = 0;

static void sigbus_push(void *addr) {
        unsigned u;

        assert(addr);

        /* Find a free place, increase the number of entries and leave, if we can */
        for (u = 0; u < SIGBUS_QUEUE_MAX; u++)
                if (__sync_bool_compare_and_swap(&sigbus_queue[u], NULL, addr)) {
                        __sync_fetch_and_add(&n_sigbus_queue, 1);
                        return;
                }

        /* If we can't, make sure the queue size is out of bounds, to
         * mark it as overflow */
        for (;;) {
                unsigned c;

                __sync_synchronize();
                c = n_sigbus_queue;

                if (c > SIGBUS_QUEUE_MAX) /* already overflow */
                        return;

                if (__sync_bool_compare_and_swap(&n_sigbus_queue, c, c + SIGBUS_QUEUE_MAX))
                        return;
        }
}

int sigbus_pop(void **ret) {
        assert(ret);

        for (;;) {
                unsigned u, c;

                __sync_synchronize();
                c = n_sigbus_queue;

                if (_likely_(c == 0))
                        return 0;

                if (_unlikely_(c >= SIGBUS_QUEUE_MAX))
                        return -EOVERFLOW;

                for (u = 0; u < SIGBUS_QUEUE_MAX; u++) {
                        void *addr;

                        addr = sigbus_queue[u];
                        if (!addr)
                                continue;

                        if (__sync_bool_compare_and_swap(&sigbus_queue[u], addr, NULL)) {
                                __sync_fetch_and_sub(&n_sigbus_queue, 1);
                                *ret = addr;
                                return 1;
                        }
                }
        }
}

static void sigbus_handler(int sn, siginfo_t *si, void *data) {
        unsigned long ul;
        void *aligned;

        assert(sn == SIGBUS);
        assert(si);

        if (si->si_code != BUS_ADRERR || !si->si_addr) {
                assert_se(sigaction(SIGBUS, &old_sigaction, NULL) == 0);
                raise(SIGBUS);
                return;
        }

        ul = (unsigned long) si->si_addr;
        ul = ul / page_size();
        ul = ul * page_size();
        aligned = (void*) ul;

        /* Let's remember which address failed */
        sigbus_push(aligned);

        /* Replace mapping with an anonymous page, so that the
         * execution can continue, however with a zeroed out page */
        assert_se(mmap(aligned, page_size(), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == aligned);
}

void sigbus_install(void) {
        struct sigaction sa = {
                .sa_sigaction = sigbus_handler,
                .sa_flags = SA_SIGINFO,
        };

        n_installed++;

        if (n_installed == 1)
                assert_se(sigaction(SIGBUS, &sa, &old_sigaction) == 0);

        return;
}

void sigbus_reset(void) {

        if (n_installed <= 0)
                return;

        n_installed--;

        if (n_installed == 0)
                assert_se(sigaction(SIGBUS, &old_sigaction, NULL) == 0);

        return;
}
