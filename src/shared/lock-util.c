/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "lock-util.h"
#include "log.h"
#include "pidref.h"
#include "process-util.h"
#include "socket-util.h"
#include "time-util.h"

static int lock_in_child(int fd, const char *path, LockType type, int operation, sd_event *event) {
        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
        int r;

        assert(fd >= 0);
        assert(event);

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, pair) < 0)
                return log_debug_errno(errno, "Failed to create lock worker socket: %m");

        r = sd_event_add_io(event, &source, pair[0], EPOLLIN, /* callback= */ NULL, /* userdata= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to watch lock worker socket: %m");

        r = sd_event_source_set_priority(source, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                return log_debug_errno(r, "Failed to set lock worker priority: %m");

        /* A child waits for the lock so the parent can handle cancellation. make_lock_file_at()
         * retries if the previous holder unlinked the file before closing it. */
        int except_fds[] = { fd, pair[1] };
        r = pidref_safe_fork_full(
                        "(sd-lock)",
                        /* stdio_fds= */ NULL,
                        except_fds,
                        ELEMENTSOF(except_fds),
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL,
                        &child);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork lock worker: %m");
        if (r == 0) {
                LockFile lock = LOCK_FILE_INIT;

                if (path)
                        r = make_lock_file_at(fd, path, operation, &lock);
                else
                        r = lock_generic(fd, type, operation);

                struct iovec iov = IOVEC_MAKE(&r, sizeof(r));
                (void) send_one_fd_iov(pair[1], r < 0 ? -EBADF : path ? lock.fd : fd, &iov, 1, MSG_NOSIGNAL);
                /* The socket message retains the lock until the parent receives or closes it. */
                _exit(EXIT_SUCCESS);
        }
        pair[1] = safe_close(pair[1]);

        r = sd_event_loop(event);
        if (r < 0)
                return r;
        if (r > 0)
                return -ECANCELED;

        _cleanup_close_ int lock_fd = -EBADF;
        struct iovec iov = IOVEC_MAKE(&r, sizeof(r));
        ssize_t n = receive_one_fd_iov(pair[0], &iov, 1, MSG_CMSG_CLOEXEC|MSG_DONTWAIT, &lock_fd);
        if (n < 0)
                return log_debug_errno(n, "Failed to receive lock from worker: %m");
        if (n != sizeof(r) || (r >= 0 && lock_fd < 0))
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Invalid lock worker reply.");
        if (r < 0)
                return log_debug_errno(r, "Failed to acquire lock in worker: %m");

        return TAKE_FD(lock_fd);
}

int lock_generic_with_timeout(int fd, LockType type, int operation, usec_t timeout) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        assert(fd >= 0);

        if (timeout == USEC_INFINITY)
                return lock_generic(fd, type, operation);

        if (type == LOCK_NONE)
                return 0;

        /* POSIX locks belong to the process and cannot be acquired on behalf of the parent. */
        if (!IN_SET(type, LOCK_BSD, LOCK_UNPOSIX))
                return -EOPNOTSUPP;

        r = lock_generic(fd, type, operation|LOCK_NB);
        if (r != -EAGAIN || timeout == 0 || FLAGS_SET(operation, LOCK_NB))
                return r;

        r = sd_event_new(&event);
        if (r < 0)
                return log_debug_errno(r, "Failed to create lock event loop: %m");

        r = sd_event_add_time_relative(event, /* ret= */ NULL, CLOCK_MONOTONIC, timeout,
                                       /* accuracy= */ 1, /* callback= */ NULL, INT_TO_PTR(-ETIMEDOUT));
        if (r < 0)
                return log_debug_errno(r, "Failed to add lock deadline: %m");

        _cleanup_close_ int lock_fd = lock_in_child(fd, /* path= */ NULL, type, operation, event);
        /* lock_in_child() returns a duplicate fd on success, but this function returns zero or a negative error.
         * Closing lock_fd leaves the lock held because fd still references the same open file description. */
        return MIN(lock_fd, 0);
}

int make_lock_file_at_with_event(int dir_fd, const char *path, int operation, sd_event *event, LockFile *ret) {
        _cleanup_free_ char *name = NULL;
        _cleanup_close_ int dfd = -EBADF;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(path);
        assert(event);
        assert(ret);

        r = make_lock_file_at(dir_fd, path, operation|LOCK_NB, ret);
        if (r != -EBUSY || FLAGS_SET(operation, LOCK_NB))
                return r;

        name = strdup(path);
        if (!name)
                return -ENOMEM;

        dfd = fd_reopen(dir_fd, O_PATH|O_DIRECTORY);
        if (dfd < 0)
                return log_debug_errno(dfd, "Failed to reopen lock directory: %m");

        int fd = lock_in_child(dfd, path, LOCK_UNPOSIX, operation, event);
        if (fd < 0)
                return fd;

        *ret = (LockFile) {
                .dir_fd = TAKE_FD(dfd),
                .path = TAKE_PTR(name),
                .fd = fd,
                .operation = operation,
        };
        return 0;
}
