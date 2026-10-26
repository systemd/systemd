/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* This is a test program that aborts from a chosen thread of a multi-threaded process,
 * so we can check that the coredump is attributed to the thread that crashed.
 *
 * "main":   the main thread aborts, while an idle thread named "test-tid-idle" exists.
 * "thread": a thread named "test-tid-crash" aborts.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void* idle_thread(void *p) {
        pause();
        return NULL;
}

static void* crash_thread(void *p) {
        (void) pthread_setname_np(pthread_self(), "test-tid-crash");
        abort();
}

int main(int argc, char *argv[]) {
        pthread_t t;

        if (argc != 2)
                return EXIT_FAILURE;

        if (strcmp(argv[1], "main") == 0) {
                if (pthread_create(&t, NULL, idle_thread, NULL) != 0)
                        return EXIT_FAILURE;
                (void) pthread_setname_np(t, "test-tid-idle");
                abort();
        }

        if (strcmp(argv[1], "thread") == 0) {
                if (pthread_create(&t, NULL, crash_thread, NULL) != 0)
                        return EXIT_FAILURE;
                (void) pthread_join(t, NULL);
        }

        return EXIT_FAILURE;
}
