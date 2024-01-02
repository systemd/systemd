/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <sys/mman.h>

#include "macro.h"
#include "memory-util.h"
#include "missing_syscall.h"
#include "process-util.h"
#include "sigbus.h"
#include "signal-util.h"

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
        assert(addr);

        /* Find a free place, increase the number of entries and leave, if we can */
        for (size_t u = 0; u < SIGBUS_QUEUE_MAX; u++) {
                /* OK to initialize this here since we haven't started the atomic ops yet */
                void *tmp = NULL;
                if (__atomic_compare_exchange_n(&sigbus_queue[u], &tmp, addr, false,
                                                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                        __atomic_fetch_add(&n_sigbus_queue, 1, __ATOMIC_SEQ_CST);
                        return;
                }
        }

        /* If we can't, make sure the queue size is out of bounds, to
         * mark it as overflowed */
        for (;;) {
                sig_atomic_t c;

                __atomic_thread_fence(__ATOMIC_SEQ_CST);
                c = n_sigbus_queue;

                if (c > SIGBUS_QUEUE_MAX) /* already overflowed */
                        return;

                /* OK if we clobber c here, since we either immediately return
                 * or it will be immediately reinitialized on next loop */
                if (__atomic_compare_exchange_n(&n_sigbus_queue, &c, c + SIGBUS_QUEUE_MAX, false,
                                                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                        return;
        }
}

int sigbus_pop(void **ret) {
        assert(ret);

        for (;;) {
                unsigned u, c;

                __atomic_thread_fence(__ATOMIC_SEQ_CST);
                c = n_sigbus_queue;

                if (_likely_(c == 0))
                        return 0;

                if (_unlikely_(c > SIGBUS_QUEUE_MAX))
                        return -EOVERFLOW;

                for (u = 0; u < SIGBUS_QUEUE_MAX; u++) {
                        void *addr;

                        addr = sigbus_queue[u];
                        if (!addr)
                                continue;

                        /* OK if we clobber addr here, since we either immediately return
                         * or it will be immediately reinitialized on next loop */
                        if (__atomic_compare_exchange_n(&sigbus_queue[u], &addr, NULL, false,
                                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                                __atomic_fetch_sub(&n_sigbus_queue, 1, __ATOMIC_SEQ_CST);
                                /* If we successfully entered this if condition, addr won't
                                 * have been modified since its assignment, so safe to use it */
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
                propagate_signal(sn, si);
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

        /* make sure that sysconf() is not called from a signal handler because
        * it is not guaranteed to be async-signal-safe since POSIX.1-2008 */
        (void) page_size();

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
