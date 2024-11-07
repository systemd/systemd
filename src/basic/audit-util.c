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
#include "stat-util.h"
#include "user-util.h"
#include "virt.h"

int audit_session_from_pid(const PidRef *pid, uint32_t *ret_id) {
        int r;

        if (!pidref_is_set(pid))
                return -ESRCH;

        /* Auditing is currently not virtualized for containers. Let's hence not use the audit session ID
         * from now, it will be leaked in from the host */
        if (detect_container() > 0)
                return -ENODATA;

        const char *p = procfs_file_alloca(pid->pid, "sessionid");

        _cleanup_free_ char *s = NULL;
        bool enoent = false;
        r = read_virtual_file(p, SIZE_MAX, &s, /* ret_size= */ NULL);
        if (r == -ENOENT) {
                if (proc_mounted() == 0)
                        return -ENOSYS;
                enoent = true;
        } else if (r < 0)
                return r;

        r = pidref_verify(pid);
        if (r < 0)
                return r;

        if (enoent) /* We got ENOENT, but /proc/ was mounted and the PID still valid? In that case it appears
                     * auditing is not supported by the kernel. */
                return -ENODATA;

        uint32_t u;
        r = safe_atou32(s, &u);
        if (r < 0)
                return r;

        if (!audit_session_is_valid(u))
                return -ENODATA;

        if (ret_id)
                *ret_id = u;

        return 0;
}

int audit_loginuid_from_pid(const PidRef *pid, uid_t *ret_uid) {
        int r;

        if (!pidref_is_set(pid))
                return -ESRCH;

        /* Auditing is currently not virtualized for containers. Let's hence not use the audit session ID
         * from now, it will be leaked in from the host */
        if (detect_container() > 0)
                return -ENODATA;

        const char *p = procfs_file_alloca(pid->pid, "loginuid");

        _cleanup_free_ char *s = NULL;
        bool enoent = false;
        r = read_virtual_file(p, SIZE_MAX, &s, /* ret_size= */ NULL);
        if (r == -ENOENT) {
                if (proc_mounted() == 0)
                        return -ENOSYS;
                enoent = true;
        } else if (r < 0)
                return r;

        r = pidref_verify(pid);
        if (r < 0)
                return r;

        if (enoent) /* We got ENOENT, but /proc/ was mounted and the PID still valid? In that case it appears
                     * auditing is not supported by the kernel. */
                return -ENODATA;

        uid_t u;
        r = parse_uid(s, &u);
        if (r == -ENXIO) /* the UID was -1 */
                return -ENODATA;
        if (r < 0)
                return r;

        if (ret_uid)
                *ret_uid = u;

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
