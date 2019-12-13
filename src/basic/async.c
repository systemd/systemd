/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <unistd.h>

#include "async.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "macro.h"
#include "process-util.h"
#include "signal-util.h"
#include "util.h"

int asynchronous_job(void* (*func)(void *p), void *arg) {
        sigset_t ss, saved_ss;
        pthread_attr_t a;
        pthread_t t;
        int r, k;

        /* It kinda sucks that we have to resort to threads to implement an asynchronous close(), but well, such is
         * life. */

        r = pthread_attr_init(&a);
        if (r > 0)
                return -r;

        r = pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        if (r > 0) {
                r = -r;
                goto finish;
        }

        assert_se(sigfillset(&ss) >= 0);

        /* Block all signals before forking off the thread, so that the new thread is started with all signals
         * blocked. This way the existence of the new thread won't affect signal handling in other threads. */

        r = pthread_sigmask(SIG_BLOCK, &ss, &saved_ss);
        if (r > 0) {
                r = -r;
                goto finish;
        }

        r = pthread_create(&t, &a, func, arg);

        k = pthread_sigmask(SIG_SETMASK, &saved_ss, NULL);

        if (r > 0)
                r = -r;
        else if (k > 0)
                r = -k;
        else
                r = 0;

finish:
        pthread_attr_destroy(&a);
        return r;
}

int asynchronous_sync(pid_t *ret_pid) {
        int r;

        /* This forks off an invocation of fork() as a child process, in order to initiate synchronization to
         * disk. Note that we implement this as helper process rather than thread as we don't want the sync() to hang our
         * original process ever, and a thread would do that as the process can't exit with threads hanging in blocking
         * syscalls. */

        r = safe_fork("(sd-sync)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS, ret_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child process */
                (void) sync();
                _exit(EXIT_SUCCESS);
        }

        return 0;
}

static void *close_thread(void *p) {
        (void) pthread_setname_np(pthread_self(), "close");

        assert_se(close_nointr(PTR_TO_FD(p)) != -EBADF);
        return NULL;
}

int asynchronous_close(int fd) {
        int r;

        /* This is supposed to behave similar to safe_close(), but
         * actually invoke close() asynchronously, so that it will
         * never block. Ideally the kernel would have an API for this,
         * but it doesn't, so we work around it, and hide this as a
         * far away as we can. */

        if (fd >= 0) {
                PROTECT_ERRNO;

                r = asynchronous_job(close_thread, FD_TO_PTR(fd));
                if (r < 0)
                         assert_se(close_nointr(fd) != -EBADF);
        }

        return -1;
}
