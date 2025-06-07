/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/audit.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <sys/socket.h>

#include "errno-util.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "libaudit-util.h"
#include "log.h"
#include "socket-util.h"

static int try_audit_request(int fd) {
        struct iovec iov;
        struct msghdr mh;
        ssize_t n;

        assert(fd >= 0);

        struct {
                struct nlmsghdr hdr;
                struct nlmsgerr err;
        } _packed_ msg = {
                .hdr.nlmsg_len = NLMSG_LENGTH(0),
                .hdr.nlmsg_type = AUDIT_GET_FEATURE,
                .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
        };
        iov = IOVEC_MAKE(&msg, msg.hdr.nlmsg_len);
        mh = (struct msghdr) {
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };

        if (sendmsg(fd, &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        iov.iov_len = sizeof(msg);

        n = recvmsg_safe(fd, &mh, 0);
        if (n < 0)
                return n;
        if (n != NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                return -EIO;

        if (msg.hdr.nlmsg_type != NLMSG_ERROR)
                return -EINVAL;

        return msg.err.error;
}

bool use_audit(void) {
        static int cached_use = -1;
        int r;

        if (cached_use >= 0)
                return cached_use;

        _cleanup_close_ int fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_AUDIT);
        if (fd < 0) {
                cached_use = !ERRNO_IS_PRIVILEGE(errno) && !ERRNO_IS_NOT_SUPPORTED(errno);
                if (cached_use)
                        log_debug_errno(errno, "Unexpected error while creating audit socket, proceeding with its use: %m");
                else
                        log_debug_errno(errno, "Won't talk to audit, because feature or privilege absent: %m");
        } else {
                /* If we try and use the audit fd but get -ECONNREFUSED, it is because we are not in the
                 * initial user namespace, and the kernel does not have support for audit outside of the
                 * initial user namespace (see
                 * https://elixir.bootlin.com/linux/latest/C/ident/audit_netlink_ok).
                 *
                 * If we receive any other error, do not disable audit because we are not sure that the error
                 * indicates that audit will not work in general. */
                r = try_audit_request(fd);
                if (r < 0) {
                        cached_use = r != -ECONNREFUSED;
                        log_debug_errno(r, cached_use ?
                                        "Failed to make request on audit fd, ignoring: %m" :
                                        "Won't talk to audit: %m");
                } else
                        cached_use = true;
        }

        return cached_use;
}

int close_audit_fd(int fd) {
#if HAVE_AUDIT
        if (fd >= 0)
                audit_close(fd);
#else
        assert(fd < 0);
#endif
        return -EBADF;
}

int open_audit_fd_or_warn(void) {
#if HAVE_AUDIT
        /* If the kernel lacks netlink or audit support, don't worry about it. */
        int fd = audit_open();
        if (fd < 0)
                return log_full_errno(ERRNO_IS_NOT_SUPPORTED(errno) ? LOG_DEBUG : LOG_WARNING,
                                      errno, "Failed to connect to audit log, ignoring: %m");

        return fd;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "libaudit support not compiled in");
#endif
}
