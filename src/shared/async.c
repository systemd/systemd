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

#include <pthread.h>
#include <unistd.h>

#include "async.h"
#include "log.h"
#include "util.h"

int asynchronous_job(void* (*func)(void *p), void *arg) {
        pthread_attr_t a;
        pthread_t t;
        int r;

        /* It kinda sucks that we have to resort to threads to
         * implement an asynchronous sync(), but well, such is
         * life.
         *
         * Note that issuing this command right before exiting a
         * process will cause the process to wait for the sync() to
         * complete. This function hence is nicely asynchronous really
         * only in long running processes. */

        r = pthread_attr_init(&a);
        if (r != 0)
                return -r;

        r = pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        if (r != 0) {
                r = -r;
                goto finish;
        }

        r = pthread_create(&t, &a, func, arg);
        if (r != 0) {
                r = -r;
                goto finish;
        }

finish:
        pthread_attr_destroy(&a);
        return r;
}

static void *sync_thread(void *p) {
        sync();
        return NULL;
}

int asynchronous_sync(void) {
        log_debug("Spawning new thread for sync");

        return asynchronous_job(sync_thread, NULL);
}

static void *close_thread(void *p) {
        safe_close(PTR_TO_INT(p));
        return NULL;
}

int asynchronous_close(int fd) {
        int r;

        /* This is supposed to behave similar to safe_close(), but
         * actually invoke close() asynchronously, so that it will
         * never block. Ideally the kernel would have an API for this,
         * but it doesn't, so we work around it, and hide this as a
         * far away as we can. */

        r = asynchronous_job(close_thread, INT_TO_PTR(fd));
        if (r < 0)
                safe_close(fd);

        return -1;
}
