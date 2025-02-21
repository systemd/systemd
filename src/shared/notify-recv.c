/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "notify-recv.h"
#include "socket-util.h"

int notify_recv(
                int fd,
                char **ret_text,
                struct ucred *ret_ucred,
                PidRef *ret_pidref) {

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
        int r;

        assert(fd >= 0);

        /* Receives a $NOTIFY_SOCKET message (aka sd_notify()). Does various validations.
         *
         * Returns -EAGAIN on recoverable errors (e.g. in case an invalid message is received, following
         * the logic that an invalid message shall be ignored, and treated like no message at all). */

        n = recvmsg_safe(fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if (ERRNO_IS_NEG_TRANSIENT(n))
                return -EAGAIN;
        if (n == -ECHRNG) {
                log_warning_errno(n, "Got message with truncated control data (unexpected fds sent?), ignoring.");
                return -EAGAIN;
        }
        if (n == -EXFULL) {
                log_warning_errno(n, "Got message with truncated payload data, ignoring.");
                return -EAGAIN;
        }
        if (n < 0)
                return log_error_errno(n, "Failed to receive notification message: %m");

        const struct ucred *ucred = NULL;
        _cleanup_close_ int pidfd = -EBADF;

        struct cmsghdr *cmsg;
        CMSG_FOREACH(cmsg, &msghdr) {
                if (cmsg->cmsg_level != SOL_SOCKET)
                        continue;

                switch (cmsg->cmsg_type) {

                case SCM_RIGHTS:
                        /* For now, just close every fd */
                        close_many(CMSG_TYPED_DATA(cmsg, int),
                                   (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
                        break;

                case SCM_PIDFD:
                        assert(cmsg->cmsg_len == CMSG_LEN(sizeof(int)));
                        assert(pidfd < 0);

                        pidfd = *CMSG_TYPED_DATA(cmsg, int);
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

        if (ret_text) {
                char *s = memdup_suffix0(buf, n);
                if (!s) {
                        log_oom_warning();
                        return -EAGAIN;
                }

                *ret_text = s;
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

        return 0;
}
