/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Helper for TEST-91-LIVEUPDATE: creates memfds and stores them in the fd store,
 * creates a LUO session directly via /dev/liveupdate and stores a memfd in it,
 * or verifies everything after kexec.
 *
 * Usage:
 *   test-luo store - create memfds and a LUO session, push all to the fd store
 *   test-luo check - verify fd store content and LUO session memfd after kexec
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "fd-util.h"
#include "log.h"
#include "luo-util.h"
#include "main-func.h"
#include "memfd-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

#define TEST_DATA_1 "liveupdate-test-data-1"
#define TEST_DATA_2 "liveupdate-test-data-2"
#define SESSION_MEMFD_DATA "luo-session-memfd-test-data"
#define SESSION_MEMFD_TOKEN UINT64_C(42)

static int do_store(const char *prefix) {
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

        /* Create a LUO session directly via /dev/liveupdate, put a memfd in it, and store the session fd */
        _cleanup_close_ int device_fd = -EBADF, session_fd = -EBADF, session_memfd = -EBADF;
        const char *session_name = strjoina(prefix, "-direct");

        device_fd = luo_open_device();
        if (device_fd < 0)
                return log_error_errno(device_fd, "Failed to open /dev/liveupdate: %m");

        session_fd = luo_create_session(device_fd, session_name);
        if (session_fd < 0)
                return log_error_errno(session_fd, "Failed to create LUO session '%s': %m", session_name);

        session_memfd = memfd_new_and_seal("session-test", SESSION_MEMFD_DATA, strlen(SESSION_MEMFD_DATA));
        if (session_memfd < 0)
                return log_error_errno(session_memfd, "Failed to create session memfd: %m");

        r = luo_session_preserve_fd(session_fd, session_memfd, SESSION_MEMFD_TOKEN);
        if (r < 0)
                return log_error_errno(r, "Failed to preserve memfd in session: %m");

        r = sd_pid_notifyf_with_fds(0, false, &session_fd, 1, "FDSTORE=1\nFDNAME=%s-direct", prefix);
        if (r < 0)
                return log_error_errno(r, "Failed to store session fd in fd store: %m");
        TAKE_FD(session_fd);

        log_info("Stored LUO session '%s' with memfd in fd store.", session_name);

        /* Wait for PID 1 to actually process all our FDSTORE notifications before we exit, otherwise
         * the cgroup-based pidref to unit lookup may fail once we're gone, and the fds end up closed. */
        r = sd_notify_barrier(0, 5 * USEC_PER_SEC);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for notification barrier: %m");

        return 0;
}

static int do_check(const char *prefix) {
        const char *e;
        _cleanup_strv_free_ char **names = NULL;
        const char *session_fdname = strjoina(prefix, "-direct");
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

        /* Verify the LUO session fd survived and its memfd content is intact */
        int session_fd = -EBADF;
        size_t idx = 0;
        STRV_FOREACH(name, names) {
                if (idx >= n_fds)
                        break;
                if (streq(*name, session_fdname)) {
                        session_fd = SD_LISTEN_FDS_START + idx;
                        break;
                }
                idx++;
        }

        if (session_fd < 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "LUO session fd '%s' not found in fd store", session_fdname);

        r = fd_is_luo_session(session_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to check if fd is LUO session: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "fd '%s' is not a LUO session!", session_fdname);

        _cleanup_close_ int session_memfd = luo_session_retrieve_fd(session_fd, SESSION_MEMFD_TOKEN);
        if (session_memfd < 0)
                return log_error_errno(session_memfd, "Failed to retrieve memfd from session: %m");

        char sbuf[256];
        ssize_t sn = pread(session_memfd, sbuf, sizeof(sbuf) - 1, 0);
        if (sn < 0)
                return log_error_errno(errno, "Failed to read session memfd: %m");
        sbuf[sn] = '\0';

        if (!streq(sbuf, SESSION_MEMFD_DATA))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Session memfd content mismatch: expected '%s', got '%s'",
                                       SESSION_MEMFD_DATA, sbuf);

        /* Remove the LUO session fd from the fd store as well. */
        r = sd_pid_notifyf(0, /* unset_environment= */ false,
                           "FDSTOREREMOVE=1\nFDNAME=%s", session_fdname);
        if (r < 0)
                return log_error_errno(r, "Failed to remove fd '%s' from fd store: %m", session_fdname);

        log_info("Verified LUO session memfd content matches.");

        /* Wait for PID 1 to actually process all our FDSTORE notifications before we exit, otherwise
         * the cgroup-based pidref to unit lookup may fail once we're gone, and the fds end up closed. */
        r = sd_notify_barrier(0, 5 * USEC_PER_SEC);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for notification barrier: %m");

        return 0;
}

static int run(int argc, char *argv[]) {
        if (argc < 2 || argc > 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Usage: %s store|check [PREFIX]", argv[0]);

        const char *prefix = argc > 2 ? argv[2] : "luosession";

        if (streq(argv[1], "store"))
                return do_store(prefix);
        if (streq(argv[1], "check"))
                return do_check(prefix);

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown command: %s", argv[1]);
}

DEFINE_MAIN_FUNCTION(run);
