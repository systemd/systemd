/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sched.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "capability-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "import-common.h"
#include "os-util.h"
#include "process-util.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "tmpfile-util.h"
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
        bool use_selinux;
        pid_t pid;
        int r;

        assert(path);
        assert(ret);

        if (pipe2(pipefd, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to create pipe for tar: %m");

        use_selinux = mac_selinux_use();

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

                execlp("tar", "tar", "--numeric-owner", "-C", path, "-px", "--xattrs", "--xattrs-include=*",
                       use_selinux ? "--selinux" : "--no-selinux", NULL);
                log_error_errno(errno, "Failed to execute tar: %m");
                _exit(EXIT_FAILURE);
        }

        *ret = pid;

        return TAKE_FD(pipefd[1]);
}

int import_fork_tar_c(const char *path, pid_t *ret) {
        _cleanup_close_pair_ int pipefd[2] = { -1, -1 };
        bool use_selinux;
        pid_t pid;
        int r;

        assert(path);
        assert(ret);

        if (pipe2(pipefd, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to create pipe for tar: %m");

        use_selinux = mac_selinux_use();

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

                execlp("tar", "tar", "-C", path, "-c", "--xattrs", "--xattrs-include=*",
                       use_selinux ? "--selinux" : "--no-selinux", ".", NULL);
                log_error_errno(errno, "Failed to execute tar: %m");
                _exit(EXIT_FAILURE);
        }

        *ret = pid;

        return TAKE_FD(pipefd[0]);
}

int import_mangle_os_tree(const char *path) {
        _cleanup_closedir_ DIR *d = NULL, *cd = NULL;
        _cleanup_free_ char *child = NULL, *t = NULL;
        const char *joined;
        struct dirent *de;
        int r;

        assert(path);

        /* Some tarballs contain a single top-level directory that contains the actual OS directory tree. Try to
         * recognize this, and move the tree one level up. */

        r = path_is_os_tree(path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether '%s' is an OS tree: %m", path);
        if (r > 0) {
                log_debug("Directory tree '%s' is a valid OS tree.", path);
                return 0;
        }

        log_debug("Directory tree '%s' is not recognizable as OS tree, checking whether to rearrange it.", path);

        d = opendir(path);
        if (!d)
                return log_error_errno(r, "Failed to open directory '%s': %m", path);

        errno = 0;
        de = readdir_no_dot(d);
        if (!de) {
                if (errno != 0)
                        return log_error_errno(errno, "Failed to iterate through directory '%s': %m", path);

                log_debug("Directory '%s' is empty, leaving it as it is.", path);
                return 0;
        }

        child = strdup(de->d_name);
        if (!child)
                return log_oom();

        errno = 0;
        de = readdir_no_dot(d);
        if (de) {
                if (errno != 0)
                        return log_error_errno(errno, "Failed to iterate through directory '%s': %m", path);

                log_debug("Directory '%s' does not look like a directory tree, and has multiple children, leaving as it is.", path);
                return 0;
        }

        joined = prefix_roota(path, child);
        r = path_is_os_tree(joined);
        if (r == -ENOTDIR) {
                log_debug("Directory '%s' does not look like a directory tree, and contains a single regular file only, leaving as it is.", path);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether '%s' is an OS tree: %m", joined);
        if (r == 0) {
                log_debug("Neither '%s' nor '%s' is a valid OS tree, leaving them as they are.", path, joined);
                return 0;
        }

        /* Nice, we have checked now:
         *
         * 1. The top-level directory does not qualify as OS tree
         * 1. The top-level directory only contains one item
         * 2. That item is a directory
         * 3. And that directory qualifies as OS tree
         *
         * Let's now rearrange things, moving everything in the inner directory one level up */

        cd = xopendirat(dirfd(d), child, O_NOFOLLOW);
        if (!cd)
                return log_error_errno(errno, "Can't open directory '%s': %m", joined);

        log_info("Rearranging '%s', moving OS tree one directory up.", joined);

        /* Let's rename the child to an unguessable name so that we can be sure all files contained in it can be
         * safely moved up and won't collide with the name. */
        r = tempfn_random(child, NULL, &t);
        if (r < 0)
                return log_oom();
        r = rename_noreplace(dirfd(d), child, dirfd(d), t);
        if (r < 0)
                return log_error_errno(r, "Unable to rename '%s' to '%s/%s': %m", joined, path, t);

        FOREACH_DIRENT_ALL(de, cd, return log_error_errno(errno, "Failed to iterate through directory '%s': %m", joined)) {
                if (dot_or_dot_dot(de->d_name))
                        continue;

                r = rename_noreplace(dirfd(cd), de->d_name, dirfd(d), de->d_name);
                if (r < 0)
                        return log_error_errno(r, "Unable to move '%s/%s/%s' to '%s/%s': %m", path, t, de->d_name, path, de->d_name);
        }

        if (unlinkat(dirfd(d), t, AT_REMOVEDIR) < 0)
                return log_error_errno(errno, "Failed to remove temporary directory '%s/%s': %m", path, t);

        log_info("Successfully rearranged OS tree.");

        return 0;
}
