/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* In 'store' mode pushes a couple of memfds with known content into the supervisor's fd store via FDSTORE=1
 * sd_notify() messages. In 'check' mode reads back the fds passed via LISTEN_FDS and verifies the content
 * matches what was pushed, and that they are passed back under the names they were pushed with. In
 * 'wipe[=GLOB]' mode removes all or glob-matched stored fds. In 'listen' mode verifies that sd_listen_fds()
 * accepts all fds passed via LISTEN_FDS, i.e. that LISTEN_PID and LISTEN_PIDFDID refer to us. In 'exit' mode
 * exits immediately instead of staying alive. Multiple modes may be run in sequence.
 *
 * This binary is intentionally linked against libsystemd only so that it can go in the minimal image. */

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "sd-daemon.h"

#define NAME_A "test-fd-a"
#define NAME_B "test-fd-b"
#define DATA_A "fdstore-data-a"
#define DATA_B "fdstore-data-b"

#define _cleanup_(f) __attribute__((cleanup(f)))

static void closep(int *fd) {
        if (!fd || *fd < 0)
                return;

        close(*fd);
        *fd = -EBADF;
}

static void strv_freep(char ***l) {
        if (!l || !*l)
                return;

        for (char **i = *l; *i; i++)
                free(*i);
        free(*l);
}

static _Noreturn void exit_handler(int sig) {
        _exit(EXIT_SUCCESS);
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

        r = sd_pid_notify_with_fds(/* pid= */ 0, /* unset_environment= */ 0, msg, &fd, 1);
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

        if (push_one(NAME_A, DATA_A) < 0)
                return EXIT_FAILURE;

        if (push_one(NAME_B, DATA_B) < 0)
                return EXIT_FAILURE;

        /* Wait for our supervisor to actually process the FDSTORE messages before we exit, otherwise
         * the cgroup-based pidref to unit lookup may fail once we're gone. */
        r = sd_notify_barrier(/* unset_environment= */ 0, 5 * 1000 * 1000);
        if (r < 0) {
                errno = -r;
                fprintf(stderr, "sd_notify_barrier failed: %m\n");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

static int do_check(void) {
        _cleanup_(strv_freep) char **names = NULL;
        bool seen_a = false, seen_b = false;
        int n;

        n = sd_listen_fds_with_names(/* unset_environment= */ 0, &names);
        if (n < 0) {
                errno = -n;
                fprintf(stderr, "sd_listen_fds_with_names failed: %m\n");
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

                const char *expected_name;
                if (strcmp(buf, DATA_A) == 0) {
                        seen_a = true;
                        expected_name = NAME_A;
                } else if (strcmp(buf, DATA_B) == 0) {
                        seen_b = true;
                        expected_name = NAME_B;
                } else {
                        fprintf(stderr, "Unexpected fd content: '%s'\n", buf);
                        continue;
                }

                if (strcmp(names[i], expected_name) != 0) {
                        fprintf(stderr, "Unexpected name '%s' for fd with content '%s', expected '%s'\n",
                                names[i], buf, expected_name);
                        return EXIT_FAILURE;
                }
        }

        if (!seen_a || !seen_b) {
                fprintf(stderr, "Missing expected fds: seen_a=%d seen_b=%d\n", seen_a, seen_b);
                return EXIT_FAILURE;
        }

        printf("Payload received both preserved fds with matching content and names.\n");
        return EXIT_SUCCESS;
}

static int do_listen(void) {
        const char *e;
        char *end;
        long m;
        int n;

        e = getenv("LISTEN_FDS");
        if (!e) {
                fprintf(stderr, "$LISTEN_FDS not set\n");
                return EXIT_FAILURE;
        }

        errno = 0;
        m = strtol(e, &end, 10);
        if (errno != 0 || end == e || *end != 0 || m <= 0) {
                fprintf(stderr, "Invalid $LISTEN_FDS: '%s'\n", e);
                return EXIT_FAILURE;
        }

        /* sd_listen_fds() ignores $LISTEN_FDS if $LISTEN_PID or $LISTEN_PIDFDID refer to another process */
        n = sd_listen_fds(/* unset_environment= */ 0);
        if (n < 0) {
                errno = -n;
                fprintf(stderr, "sd_listen_fds failed: %m\n");
                return EXIT_FAILURE;
        }
        if (n != m) {
                fprintf(stderr, "sd_listen_fds returned %d, but $LISTEN_FDS=%s\n", n, e);
                return EXIT_FAILURE;
        }

        printf("sd_listen_fds accepted all %d fds.\n", n);
        return EXIT_SUCCESS;
}

static int notify(const char *name, const char *value) {
        int r;

        r = sd_notifyf(/* unset_environment= */ 0, "%s=%s", name, value);
        if (r < 0) {
                errno = -r;
                fprintf(stderr, "sd_notify(%s=%s) failed: %m\n", name, value);
                return EXIT_FAILURE;
        }
        if (r == 0) {
                fprintf(stderr, "NOTIFY_SOCKET not set\n");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
        int r;

        if (argc < 2) {
                fprintf(stderr, "Usage: %s {store|check|listen|wipe[=GLOB]|exit}...\n", argv[0]);
                return EXIT_FAILURE;
        }

        for (int i = 1; i < argc; i++) {
                if (strcmp(argv[i], "store") == 0)
                        r = do_store();
                else if (strcmp(argv[i], "check") == 0)
                        r = do_check();
                else if (strcmp(argv[i], "listen") == 0)
                        r = do_listen();
                else if (strcmp(argv[i], "exit") == 0)
                        return EXIT_SUCCESS;
                else if (strcmp(argv[i], "wipe") == 0)
                        r = notify("FDSTOREWIPE", "*");
                else if (strncmp(argv[i], "wipe=", strlen("wipe=")) == 0)
                        r = notify("FDSTOREWIPE", argv[i] + strlen("wipe="));
                else {
                        fprintf(stderr, "Unknown verb: %s\n", argv[i]);
                        return EXIT_FAILURE;
                }

                if (r != EXIT_SUCCESS)
                        return r;
        }

        /* On success, stay alive so if we are a container payload we keep it running. Install handlers
         * for the signals an outer supervisor may use to terminate us, so we exit cleanly (with status 0)
         * and the container service ends up in 'inactive' rather than 'failed'. */
        struct sigaction sa = { .sa_handler = exit_handler };
        if (sigaction(SIGTERM, &sa, /* __oact= */ NULL) < 0 ||
            sigaction(SIGINT, &sa, /* __oact= */ NULL) < 0) {
                fprintf(stderr, "Failed to install signal handlers: %m\n");
                return EXIT_FAILURE;
        }

        r = notify("READY", "1");
        if (r != EXIT_SUCCESS)
                return r;

        for (;;)
                pause();
}
