/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* In 'store' mode pushes a couple of memfds with known content into the supervisor's fd store via FDSTORE=1
 * sd_notify() messages. In 'check' mode reads back the fds passed via LISTEN_FDS and verifies the content
 * matches what was pushed.
 *
 * This binary is intentionally linked against libsystemd only so that it can go in the minimal image. */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "sd-daemon.h"

#define DATA_A "fdstore-data-a"
#define DATA_B "fdstore-data-b"

#define _cleanup_(f) __attribute__((cleanup(f)))

static void closep(int *fd) {
        if (!fd || *fd < 0)
                return;

        close(*fd);
        *fd = -EBADF;
}

static int push_one(const char *fdname, const char *content) {
        _cleanup_(closep) int fd = -EBADF;
        int r;

        assert(fdname);
        assert(content);

        fd = memfd_create(fdname, MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (fd < 0) {
                fprintf(stderr, "memfd_create(%s) failed: %m\n", fdname);
                return -errno;
        }

        size_t len = strlen(content);
        if (write(fd, content, len) != (ssize_t) len) {
                fprintf(stderr, "write(%s) failed: %m\n", fdname);
                return -errno;
        }

        char msg[256];
        r = snprintf(msg, sizeof(msg), "FDSTORE=1\nFDNAME=%s", fdname);
        if (r < 0 || (size_t) r >= sizeof(msg)) {
                if (r >= 0)
                        errno = ENOBUFS;
                fprintf(stderr, "FDSTORE message for fdname=%s did not fit in buffer\n", fdname);
                return -errno;
        }

        r = sd_pid_notify_with_fds(0, /* unset_environment= */ 0, msg, &fd, 1);
        if (r < 0) {
                errno = -r;
                fprintf(stderr, "sd_pid_notify_with_fds(%s) failed: %m\n", fdname);
                return r;
        }
        if (r == 0) {
                fprintf(stderr, "NOTIFY_SOCKET not set\n");
                return -ENOENT;
        }

        return 0;
}

static int do_store(void) {
        int r;

        if (push_one("test-fd-a", DATA_A) < 0)
                return EXIT_FAILURE;

        if (push_one("test-fd-b", DATA_B) < 0)
                return EXIT_FAILURE;

        /* Wait for our supervisor to actually process the FDSTORE messages before we exit, otherwise
         * the cgroup-based pidref to unit lookup may fail once we're gone. */
        r = sd_notify_barrier(0, 5 * 1000 * 1000);
        if (r < 0) {
                errno = -r;
                fprintf(stderr, "sd_notify_barrier failed: %m\n");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

static int do_check(void) {
        bool seen_a = false, seen_b = false;
        int n;

        n = sd_listen_fds(/* unset_environment= */ 0);
        if (n < 0) {
                errno = -n;
                fprintf(stderr, "sd_listen_fds failed: %m\n");
                return EXIT_FAILURE;
        }
        if (n < 2) {
                fprintf(stderr, "Expected at least 2 fds via LISTEN_FDS, got %d\n", n);
                return EXIT_FAILURE;
        }

        for (int i = 0; i < n; i++) {
                int fd = SD_LISTEN_FDS_START + i;
                char buf[256] = {};
                ssize_t k;

                if (lseek(fd, 0, SEEK_SET) < 0) {
                        fprintf(stderr, "lseek(fd=%d) failed: %m\n", fd);
                        return EXIT_FAILURE;
                }
                k = read(fd, buf, sizeof(buf) - 1);
                if (k < 0) {
                        fprintf(stderr, "read(fd=%d) failed: %m\n", fd);
                        return EXIT_FAILURE;
                }
                buf[k] = 0;

                if (strcmp(buf, DATA_A) == 0)
                        seen_a = true;
                else if (strcmp(buf, DATA_B) == 0)
                        seen_b = true;
                else
                        fprintf(stderr, "Unexpected fd content: '%s'\n", buf);
        }

        if (!seen_a || !seen_b) {
                fprintf(stderr, "Missing expected fds: seen_a=%d seen_b=%d\n", seen_a, seen_b);
                return EXIT_FAILURE;
        }

        printf("Payload received both preserved fds with matching content.\n");
        return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
        int r;

        if (argc < 2) {
                fprintf(stderr, "Usage: %s store|check\n", argv[0]);
                return EXIT_FAILURE;
        }

        if (strcmp(argv[1], "store") == 0)
                r = do_store();
        else if (strcmp(argv[1], "check") == 0)
                r = do_check();
        else {
                fprintf(stderr, "Unknown verb: %s\n", argv[1]);
                return EXIT_FAILURE;
        }

        if (r != EXIT_SUCCESS)
                return r;

        /* On success, become sleep so if we are a container payload it can stay alive. */
        execlp("sleep", "sleep", "infinity", (char *) NULL);
        fprintf(stderr, "execlp(sleep) failed: %m\n");
        return EXIT_FAILURE;
}
