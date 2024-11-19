/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioctl.h>
#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "memory-util.h"
#include "missing_magic.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidfd-util.h"
#include "stat-util.h"
#include "string-util.h"

int pidfd_get_namespace(int fd, unsigned int ns_type_flag) {
        static bool cached_supported = true;

        assert(fd >= 0);

        if (!cached_supported)
                return -EOPNOTSUPP;

        int nsfd = ioctl(fd, ns_type_flag);
        if (nsfd < 0) {
                /* ERRNO_IS_(IOCTL_)NOT_SUPPORTED cannot be used here, because kernel returns -EOPNOTSUPP
                 * if the NS is disabled at build time. */
                if (IN_SET(errno, ENOTTY, EINVAL)) {
                        cached_supported = false;
                        return -EOPNOTSUPP;
                }
                if (errno == EOPNOTSUPP) /* Translate to something more distinguishable */
                        return -ENOPKG;

                return -errno;
        }

        return nsfd;
}

static int pidfd_get_info(int fd, struct pidfd_info *info) {
        static bool cached_supported = true;
        int r;

        assert(fd >= 0);
        assert(info);

        if (!cached_supported)
                return -EOPNOTSUPP;

        if (ioctl(fd, PIDFD_GET_INFO, info) < 0) {
                if (ERRNO_IS_IOCTL_NOT_SUPPORTED(errno)) {
                        cached_supported = false;
                        return -EOPNOTSUPP;
                }

                return -errno;
        }

        return 0;
}

static int pidfd_get_pid_fdinfo(int fd, pid_t *ret) {
        char path[STRLEN("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *fdinfo = NULL;
        int r;

        assert(fd >= 0);

        xsprintf(path, "/proc/self/fdinfo/%i", fd);

        r = read_full_virtual_file(path, &fdinfo, NULL);
        if (r == -ENOENT)
                return proc_fd_enoent_errno();
        if (r < 0)
                return r;

        char *p = find_line_startswith(fdinfo, "Pid:");
        if (!p)
                return -ENOTTY; /* not a pidfd? */

        p = skip_leading_chars(p, /* bad = */ NULL);
        p[strcspn(p, WHITESPACE)] = 0;

        if (streq(p, "0"))
                return -EREMOTE; /* PID is in foreign PID namespace? */
        if (streq(p, "-1"))
                return -ESRCH;   /* refers to reaped process? */

        return parse_pid(p, ret);
}

static int pidfd_get_pid_ioctl(int fd, pid_t *ret) {
        struct pidfd_info info = { .mask = PIDFD_INFO_PID };
        int r;

        assert(fd >= 0);

        r = pidfd_get_info(fd, &info);
        if (r < 0)
                return r;

        assert(FLAGS_SET(info.mask, PIDFD_INFO_PID));

        if (ret)
                *ret = info.pid;
        return 0;
}

int pidfd_get_pid(int fd, pid_t *ret) {
        int r;

        /* Converts a pidfd into a pid. We try ioctl(PIDFD_GET_INFO) (kernel 6.13+) first,
         * /proc/self/fdinfo/ as fallback. Well known errors:
         *
         *    -EBADF   → fd invalid
         *    -ESRCH   → fd valid, but process is already reaped
         *    -EREMOTE → fd valid, but pid is in another namespace we cannot translate to the local one
         *
         * pidfd_get_pid_fdinfo() might additionally fail for other reasons:
         *
         *    -ENOSYS  → /proc/ not mounted
         *    -ENOTTY  → fd valid, but not a pidfd
         */

        assert(fd >= 0);

        r = pidfd_get_pid_ioctl(fd, ret);
        if (r != -EOPNOTSUPP)
                return r;

        return pidfd_get_pid_fdinfo(fd, ret);
}

int pidfd_verify_pid(int pidfd, pid_t pid) {
        pid_t current_pid;
        int r;

        assert(pidfd >= 0);
        assert(pid > 0);

        r = pidfd_get_pid(pidfd, &current_pid);
        if (r < 0)
                return r;

        return current_pid != pid ? -ESRCH : 0;
}

int pidfd_get_ppid(int fd, pid_t *ret) {
        struct pidfd_info info = { .mask = PIDFD_INFO_PID };
        int r;

        assert(fd >= 0);

        r = pidfd_get_info(fd, &info);
        if (r < 0)
                return r;

        assert(FLAGS_SET(info.mask, PIDFD_INFO_PID));

        if (info.ppid == 0)
                return -EADDRNOTAVAIL;

        if (ret)
                *ret = info.ppid;
        return 0;
}

int pidfd_get_uid(int fd, uid_t *ret) {
        struct pidfd_info info = { .mask = PIDFD_INFO_CREDS };
        int r;

        assert(fd >= 0);

        r = pidfd_get_info(fd, &info);
        if (r < 0)
                return r;

        assert(FLAGS_SET(info.mask, PIDFD_INFO_CREDS));

        if (ret)
                *ret = info.ruid;
        return 0;
}

int pidfd_get_cgroupid(int fd, uint64_t *ret) {
        struct pidfd_info info = { .mask = PIDFD_INFO_CGROUPID };
        int r;

        assert(fd >= 0);

        r = pidfd_get_info(fd, &info);
        if (r < 0)
                return r;

        if (!FLAGS_SET(info.mask, PIDFD_INFO_CGROUPID))
                return -ENODATA;

        if (ret)
                *ret = info.cgroupid;
        return 0;
}

int pidfd_get_inode_id(int fd, uint64_t *ret) {
        static int cached_supported = -1;

        assert(fd >= 0);

        if (cached_supported < 0) {
                cached_supported = fd_is_fs_type(fd, PID_FS_MAGIC);
                if (cached_supported < 0)
                        return cached_supported;
        }
        if (cached_supported == 0)
                return -EOPNOTSUPP;

        struct stat st;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (ret)
                *ret = (uint64_t) st.st_ino;
        return 0;
}
