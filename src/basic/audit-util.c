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
        iov = (struct iovec) {
                .iov_base = &msg,
                .iov_len = msg.hdr.nlmsg_len,
        };
        mh = (struct msghdr) {
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };

        if (sendmsg(fd, &mh, MSG_NOSIGNAL) < 0) {
                log_debug_errno(errno, "Failed to send AUDIT_GET_FEATURE request, ignoring: %m");
                return 0;
        }

        iov.iov_len = sizeof(msg);

        n = recvmsg_safe(fd, &mh, 0);
        if (n < 0) {
                log_debug_errno(errno, "Failed to recv AUDIT_GET_FEATURE request ack, ignoring: %m");
                return 0;
        }

        if (n != NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                log_debug("Unexpected size for netlink ack, ignoring.");
                return 0;
        }

        if (msg.hdr.nlmsg_type != NLMSG_ERROR) {
                log_debug("Expected NLMSG_ERROR message but got %d, ignoring.", msg.hdr.nlmsg_type);
                return 0;
        }

        if (msg.err.error == 0)
                return 1;

        /* If we try and use the audit fd but get ECONNREFUSED, it is because
         * we are not in the initial user namespace, and the kernel does not
         * have support for audit outside of the initial user namespace. */
        if (msg.err.error == -ECONNREFUSED)
                return log_debug_errno(msg.err.error, "Won't talk to audit: %m");
        else {
                log_debug_errno(msg.err.error, "AUDIT_GET_FEATURE request failed, ignoring: %m");
                return 0;
        }
}

bool use_audit(void) {
        static int cached_use = -1;

        if (cached_use < 0) {
                int fd;

                fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_AUDIT);
                if (fd < 0) {
                        cached_use = !IN_SET(errno, EAFNOSUPPORT, EPROTONOSUPPORT, EPERM);
                        if (!cached_use)
                                log_debug_errno(errno, "Won't talk to audit: %m");
                } else {
                        cached_use = try_audit_request(fd) >= 0;
                        safe_close(fd);
                }
        }

        return cached_use;
}
