/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "async.h"
#include "constants.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "log.h"
#include "notify-recv.h"
#include "pidref.h"
#include "process-util.h"
#include "socket-util.h"
#include "strv.h"

int notify_socket_prepare_full(
                sd_event *event,
                int64_t priority,
                sd_event_io_handler_t handler,
                void *userdata,
                bool accept_fds,
                char **ret_path,
                sd_event_source **ret_event_source) {

        int r;

        assert(event);

        /* This creates an autobind AF_UNIX socket and adds an IO event source for the socket, which helps
         * prepare the notification socket used to communicate with worker processes. */

        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to create notification socket: %m");

        _cleanup_free_ char *path = NULL;
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

int notify_recv_with_fds(
                int fd,
                char **ret_text,
                struct ucred *ret_ucred,
                PidRef *ret_pidref,
                FDSet **ret_fds) {

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
                log_warning_errno(n, "Got message with truncated control data (%s fds sent?), ignoring.",
                                  ret_fds ? "too many" : "unexpected");
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
        int *fd_array = NULL;
        size_t n_fds = 0;

        struct cmsghdr *cmsg;
        CMSG_FOREACH(cmsg, &msghdr) {
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

                        pidfd = *CMSG_TYPED_DATA(cmsg, int);
                        break;

                case SCM_CREDENTIALS:
                        assert(cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)));
                        assert(!ucred);

                        ucred = CMSG_TYPED_DATA(cmsg, struct ucred);
                        break;
                }
        }

        _cleanup_(fdset_free_asyncp) FDSet *fds = NULL;
        if (n_fds > 0) {
                assert(fd_array);

                if (!ret_fds) {
                        log_debug("Received fds via notification while none is expected, closing all.");
                        asynchronous_close_many(fd_array, n_fds);
                } else {
                        r = fdset_new_array(&fds, fd_array, n_fds);
                        if (r < 0) {
                                asynchronous_close_many(fd_array, n_fds);
                                log_warning_errno(r, "Failed to collect fds from notification, ignoring message: %m");
                                return -EAGAIN;
                        }
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

        if (ret_fds)
                *ret_fds = TAKE_PTR(fds);

        return 0;
}

int notify_recv_with_fds_strv(
                int fd,
                char ***ret_list,
                struct ucred *ret_ucred,
                PidRef *ret_pidref,
                FDSet **ret_fds) {

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        _cleanup_(fdset_free_asyncp) FDSet *fds = NULL;
        struct ucred ucred = UCRED_INVALID;
        _cleanup_free_ char *text = NULL;
        int r;

        r = notify_recv_with_fds(
                        fd,
                        ret_list ? &text : NULL,
                        ret_ucred ? &ucred : NULL,
                        ret_pidref ? &pidref : NULL,
                        ret_fds ? &fds : NULL);
        if (r < 0)
                return r;

        if (ret_list) {
                char **l = strv_split_newlines(text);
                if (!l) {
                        log_oom_warning();
                        return -EAGAIN;
                }

                *ret_list = l;
        }

        if (ret_ucred)
                *ret_ucred = ucred;
        if (ret_pidref)
                *ret_pidref = TAKE_PIDREF(pidref);
        if (ret_fds)
                *ret_fds = TAKE_PTR(fds);

        return 0;
}
