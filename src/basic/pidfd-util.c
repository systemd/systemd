/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioctl.h>
#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "memory-util.h"
#include "missing_pidfd.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidfd-util.h"
#include "string-util.h"

static bool pidfd_get_info_supported = true;

static bool ERRNO_IS_NEG_PIDFD_IOCTL_NOT_SUPPORTED(intmax_t r) {
        return IN_SET(r, -ENOTTY, -EINVAL);
}
_DEFINE_ABS_WRAPPER(PIDFD_IOCTL_NOT_SUPPORTED);

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

        assert(fd >= 0);

        if (ioctl(fd, PIDFD_GET_INFO, &info) < 0)
                return -errno;

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
         *
         * pidfd_get_pid_fdinfo() might additionally fail for other reasons:
         *
         *    -ENOSYS  → /proc/ not mounted
         *    -ENOTTY  → fd valid, but not a pidfd
         *    -EREMOTE → fd valid, but pid is in another namespace we cannot translate to the local one
         */

        assert(fd >= 0);

        if (pidfd_get_info_supported) {
                r = pidfd_get_pid_ioctl(fd, ret);
                if (!ERRNO_IS_NEG_PIDFD_IOCTL_NOT_SUPPORTED(r))
                        return r;

                pidfd_get_info_supported = false;
        }

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
