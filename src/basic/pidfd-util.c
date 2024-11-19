/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioctl.h>
#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "memory-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidfd-util.h"
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

int pidfd_get_pid(int fd, pid_t *ret) {
        char path[STRLEN("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *fdinfo = NULL;
        int r;

        /* Converts a pidfd into a pid. Well known errors:
         *
         *    -EBADF   → fd invalid
         *    -ENOSYS  → /proc/ not mounted
         *    -ENOTTY  → fd valid, but not a pidfd
         *    -EREMOTE → fd valid, but pid is in another namespace we cannot translate to the local one
         *    -ESRCH   → fd valid, but process is already reaped
         */

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
