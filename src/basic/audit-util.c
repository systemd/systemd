/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <linux/audit.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <sys/socket.h>

#include "alloc-util.h"
#include "audit-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "iovec-util.h"
#include "macro.h"
#include "parse-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "user-util.h"

int audit_session_from_pid(pid_t pid, uint32_t *id) {
        _cleanup_free_ char *s = NULL;
        const char *p;
        uint32_t u;
        int r;

        assert(id);

        /* We don't convert ENOENT to ESRCH here, since we can't
         * really distinguish between "audit is not available in the
         * kernel" and "the process does not exist", both which will
         * result in ENOENT. */

        p = procfs_file_alloca(pid, "sessionid");

        r = read_one_line_file(p, &s);
        if (r < 0)
                return r;

        r = safe_atou32(s, &u);
        if (r < 0)
                return r;

        if (!audit_session_is_valid(u))
                return -ENODATA;

        *id = u;
        return 0;
}

int audit_loginuid_from_pid(pid_t pid, uid_t *uid) {
        _cleanup_free_ char *s = NULL;
        const char *p;
        uid_t u;
        int r;

        assert(uid);

        p = procfs_file_alloca(pid, "loginuid");

        r = read_one_line_file(p, &s);
        if (r < 0)
                return r;

        r = parse_uid(s, &u);
        if (r == -ENXIO) /* the UID was -1 */
                return -ENODATA;
        if (r < 0)
                return r;

        *uid = u;
        return 0;
}

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

        if (cached_use < 0) {
                int fd;

                fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_AUDIT);
                if (fd < 0) {
                        cached_use = !IN_SET(errno, EAFNOSUPPORT, EPROTONOSUPPORT, EPERM);
                        if (!cached_use)
                                log_debug_errno(errno, "Won't talk to audit: %m");
                } else {
                        /* If we try and use the audit fd but get -ECONNREFUSED, it is because
                         * we are not in the initial user namespace, and the kernel does not
                         * have support for audit outside of the initial user namespace
                         * (see https://elixir.bootlin.com/linux/latest/C/ident/audit_netlink_ok).
                         *
                         * If we receive any other error, do not disable audit because we are not
                         * sure that the error indicates that audit will not work in general. */
                        r = try_audit_request(fd);
                        if (r < 0) {
                                cached_use = r != -ECONNREFUSED;
                                log_debug_errno(r, cached_use ?
                                                   "Failed to make request on audit fd, ignoring: %m" :
                                                   "Won't talk to audit: %m");
                        } else
                                cached_use = true;

                        safe_close(fd);
                }
        }

        return cached_use;
}
