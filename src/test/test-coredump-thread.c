/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* This is a test program that aborts from a chosen thread of a multi-threaded process,
 * so we can check that the coredump is attributed to the thread that crashed.
 *
 * It always runs two threads, "test-tid-main" and "test-tid-thread". The argument picks
 * which of them aborts: "main" or "thread".
 */

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "string-util.h"

static void* second_thread(void *p) {
        if (!PTR_TO_INT(p)) {
                pause();
                return NULL;
        }

        (void) pthread_setname_np(pthread_self(), "test-tid-thread");
        abort();
}

int main(int argc, char *argv[]) {
        pthread_t t;
        bool crash_thread;

        if (argc != 2)
                return EXIT_FAILURE;

        if (streq(argv[1], "main"))
                crash_thread = false;
        else if (streq(argv[1], "thread"))
                crash_thread = true;
        else
                return EXIT_FAILURE;

        (void) pthread_setname_np(pthread_self(), "test-tid-main");

        if (pthread_create(&t, NULL, second_thread, INT_TO_PTR(crash_thread)) != 0)
                return EXIT_FAILURE;

        if (!crash_thread) {
                (void) pthread_setname_np(t, "test-tid-thread");
                abort();
        }

        (void) pthread_join(t, NULL);
        return EXIT_FAILURE;
}
