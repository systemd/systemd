/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Helper for TEST-91-LIVEUPDATE: creates memfds and stores them in the fd store,
 * creates a LUO session directly via /dev/liveupdate and stores a memfd in it,
 * or verifies everything after kexec.
 *
 * Usage:
 *   test-luo store        - create memfds and a LUO session, push all to the fd store
 *   test-luo check        - verify fd store content and LUO session memfd after kexec
 *   test-luo store-hijack - store a fd store entry holding a child LUO session named like
 *                           PID 1's own ("systemd"), to exercise the serialize-side anti-hijack guard
 *   test-luo check-hijack - verify the hijacking session fd was NOT serialized/restored after kexec
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

/* Name PID 1 reserves for its own LUO session (must match LUO_SESSION_NAME). A unit that tries to
 * preserve a child session under this name is an attempt to hijack PID 1's namespace, and the
 * serialize-side guard in manager_luo_serialize_fd_stores() must refuse to serialize it. */
#define HIJACK_SESSION_NAME LUO_SESSION_NAME
#define HIJACK_FDNAME "hijackfd"
#define HIJACK_MEMFD_DATA "luo-hijack-memfd-test-data"
#define HIJACK_MEMFD_TOKEN UINT64_C(99)

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

static int do_store_hijack(void) {
        int r;

        /* Create a child LUO session named exactly like PID 1's own session, put a memfd in it, and push the
         * session fd into our fd store. On kexec, PID 1's manager_luo_serialize_fd_stores() must detect the
         * reserved session name and refuse to serialize this entry (anti-hijack guard). */
        _cleanup_close_ int device_fd = -EBADF, session_fd = -EBADF, session_memfd = -EBADF;

        device_fd = luo_open_device();
        if (device_fd < 0)
                return log_error_errno(device_fd, "Failed to open /dev/liveupdate: %m");

        session_fd = luo_create_session(device_fd, HIJACK_SESSION_NAME);
        if (session_fd < 0)
                return log_error_errno(session_fd, "Failed to create hijacking LUO session '%s': %m", HIJACK_SESSION_NAME);

        session_memfd = memfd_new_and_seal("hijack-test", HIJACK_MEMFD_DATA, strlen(HIJACK_MEMFD_DATA));
        if (session_memfd < 0)
                return log_error_errno(session_memfd, "Failed to create hijack session memfd: %m");

        r = luo_session_preserve_fd(session_fd, session_memfd, HIJACK_MEMFD_TOKEN);
        if (r < 0)
                return log_error_errno(r, "Failed to preserve memfd in hijack session: %m");

        r = sd_pid_notify_with_fds(0, /* unset_environment= */ false, "FDSTORE=1\nFDNAME=" HIJACK_FDNAME, &session_fd, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to store hijack session fd in fd store: %m");
        TAKE_FD(session_fd);

        log_info("Stored hijacking LUO session '%s' with memfd in fd store.", HIJACK_SESSION_NAME);

        /* Wait for PID 1 to actually process the FDSTORE notification before we exit, otherwise
         * the cgroup-based pidref to unit lookup may fail once we're gone, and the fd ends up closed. */
        r = sd_notify_barrier(0, 5 * USEC_PER_SEC);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for notification barrier: %m");

        return 0;
}

static int do_check_hijack(void) {
        _cleanup_strv_free_ char **names = NULL;
        const char *e;
        size_t n_fds;
        int r;

        /* The hijacking session fd ("hijackfd") must NOT have survived kexec: PID 1 refused to serialize it
         * because its session name infringes PID 1's reserved namespace. So it must be absent from
         * LISTEN_FDNAMES here. */
        e = getenv("LISTEN_FDS");
        if (!e) {
                log_info("No LISTEN_FDS set after kexec, hijack fd correctly not restored.");
                return 0;
        }

        r = safe_atozu(e, &n_fds);
        if (r < 0)
                return log_error_errno(r, "Failed to parse LISTEN_FDS='%s': %m", e);

        e = getenv("LISTEN_FDNAMES");
        if (!e) {
                if (n_fds == 0) {
                        log_info("No fds restored after kexec, hijack fd correctly not restored.");
                        return 0;
                }
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "LISTEN_FDS=%zu but no LISTEN_FDNAMES set", n_fds);
        }

        names = strv_split(e, ":");
        if (!names)
                return log_oom();

        if (strv_contains(names, HIJACK_FDNAME))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Hijacking session fd '%s' was restored after kexec, anti-hijack guard failed!",
                                       HIJACK_FDNAME);

        log_info("Verified hijacking session fd '%s' was not restored after kexec.", HIJACK_FDNAME);
        return 0;
}

static int run(int argc, char *argv[]) {
        if (argc < 2 || argc > 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Usage: %s store|check|store-hijack|check-hijack [PREFIX]", argv[0]);

        const char *prefix = argc > 2 ? argv[2] : "luosession";

        if (streq(argv[1], "store"))
                return do_store(prefix);
        if (streq(argv[1], "check"))
                return do_check(prefix);
        if (streq(argv[1], "store-hijack"))
                return do_store_hijack();
        if (streq(argv[1], "check-hijack"))
                return do_check_hijack();

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown command: %s", argv[1]);
}

DEFINE_MAIN_FUNCTION(run);
