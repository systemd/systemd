/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "async-close.h"
#include "constants.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "notify-recv.h"
#include "pidref.h"
#include "process-util.h"
#include "socket-util.h"

int notify_socket_prepare_fd(const char *socket_path, bool accept_fds, char **ret_path) {
        int r;

        /* Prepare a notification socket, using an abstract address unless a path is supplied. */

        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to create notification socket: %m");

        _cleanup_free_ char *path = NULL;
        if (socket_path) {
                union sockaddr_union sa;
                r = sockaddr_un_set_path(&sa.un, socket_path);
                if (r < 0)
                        return r;
                if (bind(fd, &sa.sa, r) < 0)
                        return -errno;
        } else
                r = socket_autobind(fd, &path);
        if (r < 0)
                return log_debug_errno(r, "Failed to bind notification socket: %m");

        r = setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to enable SO_PASSCRED on notification socket: %m");

        /* SO_PASSPIDFD is supported since kernel v6.5. */
        r = setsockopt_int(fd, SOL_SOCKET, SO_PASSPIDFD, true);
        if (r < 0)
                log_debug_errno(r, "Failed to enable SO_PASSPIDFD on notification socket, ignoring: %m");

        if (!accept_fds) {
                /* since kernel v6.16 */
                r = setsockopt_int(fd, SOL_SOCKET, SO_PASSRIGHTS, false);
                if (r < 0)
                        log_debug_errno(r, "Failed to disable SO_PASSRIGHTS on notification socket, ignoring: %m");
        }

        if (ret_path)
                *ret_path = TAKE_PTR(path);
        return TAKE_FD(fd);
}

int notify_socket_prepare_full(
                sd_event *event,
                int64_t priority,
                sd_event_io_handler_t handler,
                void *userdata,
                bool accept_fds,
                char **ret_path,
                sd_event_source **ret_event_source) {

        _cleanup_free_ char *path = NULL;
        int r;

        assert(event);

        _cleanup_close_ int fd = notify_socket_prepare_fd(/* socket_path= */ NULL, accept_fds, &path);
        if (fd < 0)
                return fd;

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(event, &s, fd, EPOLLIN, handler, userdata);
        if (r < 0)
                return log_debug_errno(r, "Failed to create notification event source: %m");

        r = sd_event_source_set_priority(s, priority);
        if (r < 0)
                return log_debug_errno(r, "Failed to set priority to notification event source: %m");

        r = sd_event_source_set_io_fd_own(s, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to make notification event source own file descriptor: %m");
        TAKE_FD(fd);

        (void) sd_event_source_set_description(s, "notify-socket");

        if (ret_event_source)
                *ret_event_source = TAKE_PTR(s);
        else {
                r = sd_event_source_set_floating(s, true);
                if (r < 0)
                        return log_debug_errno(r, "Failed to make notification event source floating: %m");
        }

        if (ret_path)
                *ret_path = TAKE_PTR(path);

        return 0;
}

static void notify_cmsg_close_all(struct msghdr *mh) {
        assert(mh);

        struct cmsghdr *cmsg;
        CMSG_FOREACH(cmsg, mh) {
                if (cmsg->cmsg_level != SOL_SOCKET)
                        continue;
                if (cmsg->cmsg_type == SCM_RIGHTS)
                        asynchronous_close_many(CMSG_TYPED_DATA(cmsg, int),
                                                (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
                else if (cmsg->cmsg_type == SCM_PIDFD) {
                        assert(cmsg->cmsg_len == CMSG_LEN(sizeof(int)));
                        safe_close(*CMSG_TYPED_DATA(cmsg, int));
                }
        }
}

int notify_recv_with_fd_array(
                int fd,
                char **ret_text,
                struct ucred *ret_ucred,
                PidRef *ret_pidref,
                int **ret_fds,
                size_t *ret_n_fds) {

        char buf[NOTIFY_BUFFER_MAX];
        struct iovec iovec = {
                .iov_base = buf,
                .iov_len = sizeof(buf),
        };
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred)) +
                         CMSG_SPACE(sizeof(int)) + /* SCM_PIDFD */
                         CMSG_SPACE(sizeof(int) * NOTIFY_FD_MAX)) control;
        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        ssize_t n;

        assert(fd >= 0);
        assert(!ret_fds || ret_n_fds);

        /* Receives a $NOTIFY_SOCKET message (aka sd_notify()). Does various validations.
         *
         * Returns -EAGAIN on recoverable errors (e.g. in case an invalid message is received, following
         * the logic that an invalid message shall be ignored, and treated like no message at all). */

        n = recvmsg(fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return -EAGAIN;
                return log_error_errno(errno, "Failed to receive notification message: %m");
        }

        /* Received descriptors can refer to FUSE files or devices with blocking close operations. Always
         * close SCM_RIGHTS asynchronously, including malformed messages and allocation failures. */
        _cleanup_(notify_cmsg_close_all) struct msghdr received = msghdr;
        if (FLAGS_SET(received.msg_flags, MSG_CTRUNC))
                return log_warning_errno(SYNTHETIC_ERRNO(EAGAIN), "Got message with truncated control data, ignoring.");
        if (FLAGS_SET(received.msg_flags, MSG_TRUNC))
                return log_warning_errno(SYNTHETIC_ERRNO(EAGAIN), "Got message with truncated payload data, ignoring.");

        const struct ucred *ucred = NULL;
        _cleanup_close_ int pidfd = -EBADF;
        int *fd_array = NULL;
        size_t n_fds = 0;

        struct cmsghdr *cmsg;
        CMSG_FOREACH(cmsg, &received) {
                if (cmsg->cmsg_level != SOL_SOCKET)
                        continue;

                switch (cmsg->cmsg_type) {

                case SCM_RIGHTS:
                        assert(!fd_array && n_fds == 0);

                        fd_array = CMSG_TYPED_DATA(cmsg, int);
                        n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                        break;

                case SCM_PIDFD:
                        assert(cmsg->cmsg_len == CMSG_LEN(sizeof(int)));
                        assert(pidfd < 0);

                        pidfd = TAKE_FD(*CMSG_TYPED_DATA(cmsg, int));
                        break;

                case SCM_CREDENTIALS:
                        assert(cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)));
                        assert(!ucred);

                        ucred = CMSG_TYPED_DATA(cmsg, struct ucred);
                        break;
                }
        }

        if ((ret_ucred || ret_pidref) && (!ucred || !pid_is_valid(ucred->pid)))
                return log_warning_errno(SYNTHETIC_ERRNO(EAGAIN),
                                         "Got notification datagram lacking valid credential information, ignoring.");

        /* As extra safety check, let's make sure the string we get doesn't contain embedded NUL bytes.
         * We permit one trailing NUL byte in the message, but don't expect it. */
        if (n > 1 && memchr(buf, 0, n - 1))
                return log_warning_errno(SYNTHETIC_ERRNO(EAGAIN), "Got notification message with embedded NUL, ignoring.");

        _cleanup_free_ char *text = NULL;
        if (ret_text) {
                text = memdup_suffix0(buf, n);
                if (!text) {
                        log_oom_warning();
                        return -EAGAIN;
                }
        }

        if (ret_fds) {
                int *fds = n_fds > 0 ? memdup(fd_array, n_fds * sizeof(int)) : NULL;
                if (n_fds > 0 && !fds) {
                        log_oom_warning();
                        return -EAGAIN;
                }
                for (size_t i = 0; i < n_fds; i++)
                        fd_array[i] = -EBADF;
                *ret_fds = fds;
                *ret_n_fds = n_fds;
        }

        if (ret_ucred)
                *ret_ucred = *ucred;

        if (ret_pidref) {
                if (pidfd >= 0)
                        *ret_pidref = (PidRef) {
                                .pid = ucred->pid,
                                .fd = TAKE_FD(pidfd),
                        };
                else
                        *ret_pidref = PIDREF_MAKE_FROM_PID(ucred->pid);
        }

        if (ret_text)
                *ret_text = TAKE_PTR(text);

        return 0;
}

int notify_recv(int fd, char **ret_text, struct ucred *ret_ucred, PidRef *ret_pidref) {
        return notify_recv_with_fd_array(fd, ret_text, ret_ucred, ret_pidref, NULL, NULL);
}
