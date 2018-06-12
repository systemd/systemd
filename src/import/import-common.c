/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sched.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "btrfs-util.h"
#include "capability-util.h"
#include "fd-util.h"
#include "import-common.h"
#include "process-util.h"
#include "signal-util.h"
#include "util.h"

int import_make_read_only_fd(int fd) {
        int r;

        assert(fd >= 0);

        /* First, let's make this a read-only subvolume if it refers
         * to a subvolume */
        r = btrfs_subvol_set_read_only_fd(fd, true);
        if (IN_SET(r, -ENOTTY, -ENOTDIR, -EINVAL)) {
                struct stat st;

                /* This doesn't refer to a subvolume, or the file
                 * system isn't even btrfs. In that, case fall back to
                 * chmod()ing */

                r = fstat(fd, &st);
                if (r < 0)
                        return log_error_errno(errno, "Failed to stat temporary image: %m");

                /* Drop "w" flag */
                if (fchmod(fd, st.st_mode & 07555) < 0)
                        return log_error_errno(errno, "Failed to chmod() final image: %m");

                return 0;

        } else if (r < 0)
                return log_error_errno(r, "Failed to make subvolume read-only: %m");

        return 0;
}

int import_make_read_only(const char *path) {
        _cleanup_close_ int fd = 1;

        fd = open(path, O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", path);

        return import_make_read_only_fd(fd);
}

int import_fork_tar_x(const char *path, pid_t *ret) {
        _cleanup_close_pair_ int pipefd[2] = { -1, -1 };
        pid_t pid;
        int r;

        assert(path);
        assert(ret);

        if (pipe2(pipefd, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to create pipe for tar: %m");

        r = safe_fork("(tar)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                uint64_t retain =
                        (1ULL << CAP_CHOWN) |
                        (1ULL << CAP_FOWNER) |
                        (1ULL << CAP_FSETID) |
                        (1ULL << CAP_MKNOD) |
                        (1ULL << CAP_SETFCAP) |
                        (1ULL << CAP_DAC_OVERRIDE);

                /* Child */

                pipefd[1] = safe_close(pipefd[1]);

                r = rearrange_stdio(pipefd[0], -1, STDERR_FILENO);
                if (r < 0) {
                        log_error_errno(r, "Failed to rearrange stdin/stdout: %m");
                        _exit(EXIT_FAILURE);
                }

                if (unshare(CLONE_NEWNET) < 0)
                        log_error_errno(errno, "Failed to lock tar into network namespace, ignoring: %m");

                r = capability_bounding_set_drop(retain, true);
                if (r < 0)
                        log_error_errno(r, "Failed to drop capabilities, ignoring: %m");

                execlp("tar", "tar", "--numeric-owner", "-C", path, "-px", "--xattrs", "--xattrs-include=*", NULL);
                log_error_errno(errno, "Failed to execute tar: %m");
                _exit(EXIT_FAILURE);
        }

        *ret = pid;

        return TAKE_FD(pipefd[1]);
}

int import_fork_tar_c(const char *path, pid_t *ret) {
        _cleanup_close_pair_ int pipefd[2] = { -1, -1 };
        pid_t pid;
        int r;

        assert(path);
        assert(ret);

        if (pipe2(pipefd, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to create pipe for tar: %m");

        r = safe_fork("(tar)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                uint64_t retain = (1ULL << CAP_DAC_OVERRIDE);

                /* Child */

                pipefd[0] = safe_close(pipefd[0]);

                r = rearrange_stdio(-1, pipefd[1], STDERR_FILENO);
                if (r < 0) {
                        log_error_errno(r, "Failed to rearrange stdin/stdout: %m");
                        _exit(EXIT_FAILURE);
                }

                if (unshare(CLONE_NEWNET) < 0)
                        log_error_errno(errno, "Failed to lock tar into network namespace, ignoring: %m");

                r = capability_bounding_set_drop(retain, true);
                if (r < 0)
                        log_error_errno(r, "Failed to drop capabilities, ignoring: %m");

                execlp("tar", "tar", "-C", path, "-c", "--xattrs", "--xattrs-include=*", ".", NULL);
                log_error_errno(errno, "Failed to execute tar: %m");
                _exit(EXIT_FAILURE);
        }

        *ret = pid;

        return TAKE_FD(pipefd[0]);
}
