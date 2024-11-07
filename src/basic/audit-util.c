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

static int audit_read_field(const PidRef *pid, const char *field, char **ret) {
        int r;

        assert(field);
        assert(ret);

        if (!pidref_is_set(pid))
                return -ESRCH;

        /* Auditing is currently not virtualized for containers. Let's hence not use the audit session ID or
         * login UID for now, it will be leaked in from the host */
        if (detect_container() > 0)
                return -ENODATA;

        const char *p = procfs_file_alloca(pid->pid, field);

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

        delete_trailing_chars(s, NEWLINE);

        *ret = TAKE_PTR(s);
        return 0;
}

int audit_session_from_pid(const PidRef *pid, uint32_t *ret_id) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = audit_read_field(pid, "sessionid", &s);
        if (r < 0)
                return r;

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
        _cleanup_free_ char *s = NULL;
        int r;

        r = audit_read_field(pid, "loginuid", &s);
        if (r < 0)
                return r;

        if (streq(s, "4294967295")) /* loginuid as 4294967295 means not part of any session. */
                return -ENODATA;

        return parse_uid(s, ret_uid);
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
