/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Helper for TEST-91-LIVEUPDATE: creates memfds and stores them in the fd store,
 * or verifies that inherited fd store entries contain the expected content.
 *
 * Usage:
 *   test-luo store - create memfds with test data and push them to the fd store
 *   test-luo check - verify fd store content matches expectations
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "memfd-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

#define TEST_DATA_1 "liveupdate-test-data-1"
#define TEST_DATA_2 "liveupdate-test-data-2"

static int do_store(void) {
        _cleanup_close_ int fd1 = -EBADF, fd2 = -EBADF;
        int r;

        fd1 = memfd_new_and_seal("luo-test-1", TEST_DATA_1, strlen(TEST_DATA_1));
        if (fd1 < 0)
                return log_error_errno(fd1, "Failed to create memfd 1: %m");

        fd2 = memfd_new_and_seal("luo-test-2", TEST_DATA_2, strlen(TEST_DATA_2));
        if (fd2 < 0)
                return log_error_errno(fd2, "Failed to create memfd 2: %m");

        r = sd_pid_notify_with_fds(0, /* unset_environment= */ false, "FDSTORE=1\nFDNAME=testfd1", &fd1, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to store memfd 1 in fd store: %m");

        r = sd_pid_notify_with_fds(0, /* unset_environment= */ false, "FDSTORE=1\nFDNAME=testfd2", &fd2, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to store memfd 2 in fd store: %m");

        log_info("Stored 2 memfds in fd store.");

        /* Wait for PID 1 to actually process all our FDSTORE notifications before we exit, otherwise
         * the cgroup-based pidref to unit lookup may fail once we're gone, and the fds end up closed. */
        r = sd_notify_barrier(0, 5 * USEC_PER_SEC);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for notification barrier: %m");

        return 0;
}

static int do_check(void) {
        const char *e;
        _cleanup_strv_free_ char **names = NULL;
        size_t n_fds;
        int r;

        /* sd_listen_fds_with_names() checks LISTEN_PID which won't match since we're a child process.
         * Read LISTEN_FDS and LISTEN_FDNAMES directly from the environment instead. */
        e = getenv("LISTEN_FDS");
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No LISTEN_FDS environment variable set");

        r = safe_atozu(e, &n_fds);
        if (r < 0)
                return log_error_errno(r, "Failed to parse LISTEN_FDS='%s': %m", e);
        if (n_fds == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No file descriptors in fd store after kexec");

        log_info("Got %zu fd(s) in fd store after kexec.", n_fds);

        /* Parse LISTEN_FDNAMES to match fds by name, not position */
        e = getenv("LISTEN_FDNAMES");
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No LISTEN_FDNAMES environment variable set");

        names = strv_split(e, ":");
        if (!names)
                return log_oom();
        assert(n_fds == strv_length(names));

        static const struct {
                const char *name;
                const char *expected;
        } checks[] = {
                { "testfd1", TEST_DATA_1 },
                { "testfd2", TEST_DATA_2 },
        };

        if (n_fds < ELEMENTSOF(checks))
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Not enough fds in fd store after kexec: expected at least %zu, got %zu",
                                       ELEMENTSOF(checks), n_fds);

        for (size_t i = 0; i < ELEMENTSOF(checks); i++) {
                char buf[256];
                ssize_t n;
                size_t idx = 0;
                int fd = -EBADF;

                /* Find the fd by name */
                STRV_FOREACH(name, names) {
                        if (idx >= n_fds)
                                break;
                        if (streq(*name, checks[i].name)) {
                                fd = SD_LISTEN_FDS_START + idx;
                                break;
                        }
                        idx++;
                }

                if (fd < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "fd '%s' not found in LISTEN_FDNAMES", checks[i].name);

                /* memfds are sealed; pread() avoids needing a separate lseek() */
                n = pread(fd, buf, sizeof(buf) - 1, 0);
                if (n < 0)
                        return log_error_errno(errno, "Failed to read fd %d: %m", fd);

                buf[n] = '\0';

                if (!streq(buf, checks[i].expected))
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EBADMSG),
                                        "Content mismatch for '%s': expected '%s', got '%s'",
                                        checks[i].name, checks[i].expected, buf);

                /* Remove the fd from the fd store so we don't keep accumulating duplicates across
                 * repeated invocations (and across repeated kexec cycles). */
                r = sd_pid_notifyf(0, /* unset_environment= */ false,
                                   "FDSTOREREMOVE=1\nFDNAME=%s", checks[i].name);
                if (r < 0)
                        return log_error_errno(r, "Failed to remove fd '%s' from fd store: %m", checks[i].name);

                log_info("Verified fd '%s': content matches.", checks[i].name);
        }

        log_info("All fd store checks passed.");

        /* Wait for PID 1 to actually process all our FDSTORE notifications before we exit, otherwise
         * the cgroup-based pidref to unit lookup may fail once we're gone, and the fds end up closed. */
        r = sd_notify_barrier(0, 5 * USEC_PER_SEC);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for notification barrier: %m");

        return 0;
}

static int run(int argc, char *argv[]) {
        if (argc != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Usage: %s store|check", argv[0]);

        if (streq(argv[1], "store"))
                return do_store();
        if (streq(argv[1], "check"))
                return do_check();

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown command: %s", argv[1]);
}

DEFINE_MAIN_FUNCTION(run);
