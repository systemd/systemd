/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
#include "process-util.h"
#include "stat-util.h"
#include "string-util.h"

static int have_pidfs = -1;

static int pidfd_check_pidfs(void) {

        if (have_pidfs >= 0)
                return have_pidfs;

        _cleanup_close_ int fd = pidfd_open(getpid_cached(), 0);
        if (fd < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        return (have_pidfs = false);

                return -errno;
        }

        return (have_pidfs = fd_is_fs_type(fd, PID_FS_MAGIC));
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

int pidfd_get_inode_id(int fd, uint64_t *ret) {
        int r;

        assert(fd >= 0);

        r = pidfd_check_pidfs();
        if (r < 0)
                return r;
        if (r == 0)
                return -EOPNOTSUPP;

        struct stat st;
        if (fstat(fd, &st) < 0)
                return -errno;

        if (ret)
                *ret = (uint64_t) st.st_ino;
        return 0;
}
