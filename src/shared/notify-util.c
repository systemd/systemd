/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "notify-util.h"
#include "socket-util.h"

int notify_recv(int fd,
                char **ret_text,
                struct ucred *ret_ucred,
                PidRef *ret_pidref) {

        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred)) +
                         CMSG_SPACE(sizeof(int)) + /* SCM_PIDFD */
                         CMSG_SPACE(sizeof(int) * NOTIFY_FD_MAX)) control;
        struct iovec iovec;
        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        ssize_t n;

        assert(fd >= 0);

        /* Receives a $NOTIFY_SOCKET message (aka sd_notify()). Does various validations. Returns -EAGAIN in
         * case an invalid message is received (following the logic that an invalid message shall be ignored,
         * and treated like no message at all). */

        _cleanup_free_ char *buf = new(char, NOTIFY_BUFFER_MAX+1);
        if (!buf)
                return log_oom_debug();

        iovec = (struct iovec) {
                .iov_base = buf,
                .iov_len = NOTIFY_BUFFER_MAX,
        };

        n = recvmsg_safe(fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if (ERRNO_IS_NEG_TRANSIENT(n))
                return -EAGAIN;
        if (n == -ECHRNG) {
                log_debug_errno(n, "Got message with truncated control data (unexpected fds sent?), ignoring.");
                return -EAGAIN;
        }
        if (n == -EXFULL) {
                log_debug_errno(n, "Got message with truncated payload data, ignoring.");
                return -EAGAIN;
        }
        if (n < 0)
                return (int) n;

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
                        pidfd = *CMSG_TYPED_DATA(cmsg, int);
                        break;

                case SCM_CREDENTIALS:
                        assert(cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)));
                        ucred = CMSG_TYPED_DATA(cmsg, struct ucred);
                        break;
                }
        }

        if (n == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN), "Got empty notification message, ignoring.");
        if (memchr(buf, 0, n - 1))
                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN), "Got notification message with embedded NUL, ignoring.");

        if ((ret_ucred || ret_pidref) && (!ucred || ucred->pid <= 0))
                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN), "Got notification datagram lacking valid credential information, ignoring.");

        if (ret_pidref) {
                assert(ucred);
                assert(ucred->pid > 0);

                if (pidfd >= 0)
                        *ret_pidref = (PidRef) {
                                .pid = ucred->pid,
                                .fd = TAKE_FD(pidfd),
                        };
                else
                        *ret_pidref = PIDREF_MAKE_FROM_PID(ucred->pid);
        }

        if (ret_text) {
                buf[n] = 0;
                *ret_text = TAKE_PTR(buf);
        }

        if (ret_ucred)
                *ret_ucred = *ucred;

        return 0;
}
