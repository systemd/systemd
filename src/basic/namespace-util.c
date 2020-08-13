/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mount.h>

#include "fd-util.h"
#include "fs-util.h"
#include "mkdir.h"
#include "missing_fs.h"
#include "missing_magic.h"
#include "mkdir.h"
#include "namespace-util.h"
#include "process-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "user-util.h"

int namespace_open(pid_t pid, int *pidns_fd, int *mntns_fd, int *netns_fd, int *userns_fd, int *root_fd) {
        _cleanup_close_ int pidnsfd = -1, mntnsfd = -1, netnsfd = -1, usernsfd = -1;
        int rfd = -1;

        assert(pid >= 0);

        if (mntns_fd) {
                const char *mntns;

                mntns = procfs_file_alloca(pid, "ns/mnt");
                mntnsfd = open(mntns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (mntnsfd < 0)
                        return -errno;
        }

        if (pidns_fd) {
                const char *pidns;

                pidns = procfs_file_alloca(pid, "ns/pid");
                pidnsfd = open(pidns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (pidnsfd < 0)
                        return -errno;
        }

        if (netns_fd) {
                const char *netns;

                netns = procfs_file_alloca(pid, "ns/net");
                netnsfd = open(netns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (netnsfd < 0)
                        return -errno;
        }

        if (userns_fd) {
                const char *userns;

                userns = procfs_file_alloca(pid, "ns/user");
                usernsfd = open(userns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (usernsfd < 0 && errno != ENOENT)
                        return -errno;
        }

        if (root_fd) {
                const char *root;

                root = procfs_file_alloca(pid, "root");
                rfd = open(root, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
                if (rfd < 0)
                        return -errno;
        }

        if (pidns_fd)
                *pidns_fd = TAKE_FD(pidnsfd);

        if (mntns_fd)
                *mntns_fd = TAKE_FD(mntnsfd);

        if (netns_fd)
                *netns_fd = TAKE_FD(netnsfd);

        if (userns_fd)
                *userns_fd = TAKE_FD(usernsfd);

        if (root_fd)
                *root_fd = TAKE_FD(rfd);

        return 0;
}

int namespace_enter(int pidns_fd, int mntns_fd, int netns_fd, int userns_fd, int root_fd) {
        if (userns_fd >= 0) {
                /* Can't setns to your own userns, since then you could
                 * escalate from non-root to root in your own namespace, so
                 * check if namespaces equal before attempting to enter. */
                _cleanup_free_ char *userns_fd_path = NULL;
                int r;
                if (asprintf(&userns_fd_path, "/proc/self/fd/%d", userns_fd) < 0)
                        return -ENOMEM;

                r = files_same(userns_fd_path, "/proc/self/ns/user", 0);
                if (r < 0)
                        return r;
                if (r)
                        userns_fd = -1;
        }

        if (pidns_fd >= 0)
                if (setns(pidns_fd, CLONE_NEWPID) < 0)
                        return -errno;

        if (mntns_fd >= 0)
                if (setns(mntns_fd, CLONE_NEWNS) < 0)
                        return -errno;

        if (netns_fd >= 0)
                if (setns(netns_fd, CLONE_NEWNET) < 0)
                        return -errno;

        if (userns_fd >= 0)
                if (setns(userns_fd, CLONE_NEWUSER) < 0)
                        return -errno;

        if (root_fd >= 0) {
                if (fchdir(root_fd) < 0)
                        return -errno;

                if (chroot(".") < 0)
                        return -errno;
        }

        return reset_uid_gid();
}

int fd_is_network_ns(int fd) {
        struct statfs s;
        int r;

        /* Checks whether the specified file descriptor refers to a network namespace. On old kernels there's no nice
         * way to detect that, hence on those we'll return a recognizable error (EUCLEAN), so that callers can handle
         * this somewhat nicely.
         *
         * This function returns > 0 if the fd definitely refers to a network namespace, 0 if it definitely does not
         * refer to a network namespace, -EUCLEAN if we can't determine, and other negative error codes on error. */

        if (fstatfs(fd, &s) < 0)
                return -errno;

        if (!is_fs_type(&s, NSFS_MAGIC)) {
                /* On really old kernels, there was no "nsfs", and network namespace sockets belonged to procfs
                 * instead. Handle that in a somewhat smart way. */

                if (is_fs_type(&s, PROC_SUPER_MAGIC)) {
                        struct statfs t;

                        /* OK, so it is procfs. Let's see if our own network namespace is procfs, too. If so, then the
                         * passed fd might refer to a network namespace, but we can't know for sure. In that case,
                         * return a recognizable error. */

                        if (statfs("/proc/self/ns/net", &t) < 0)
                                return -errno;

                        if (s.f_type == t.f_type)
                                return -EUCLEAN; /* It's possible, we simply don't know */
                }

                return 0; /* No! */
        }

        r = ioctl(fd, NS_GET_NSTYPE);
        if (r < 0) {
                if (errno == ENOTTY) /* Old kernels didn't know this ioctl, let's also return a recognizable error in that case */
                        return -EUCLEAN;

                return -errno;
        }

        return r == CLONE_NEWNET;
}

int detach_mount_namespace(void) {

        /* Detaches the mount namespace, disabling propagation from our namespace to the host */

        if (unshare(CLONE_NEWNS) < 0)
                return -errno;

        if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0)
                return -errno;

        return 0;
}

int bind_mount_in_namespace(
                pid_t target,
                const char *propagate_path,
                const char *incoming_path,
                const char *src,
                const char *dest,
                int read_only,
                int make_file_or_directory,
                char **error_path) {

        _cleanup_close_pair_ int errno_pipe_fd[2] = { -1, -1 };
        char mount_slave[] = "/tmp/propagate.XXXXXX", *mount_tmp, *mount_outside, *p;
        bool mount_slave_created = false, mount_slave_mounted = false,
                mount_tmp_created = false, mount_tmp_mounted = false,
                mount_outside_created = false, mount_outside_mounted = false;
        _cleanup_free_ char *chased_src = NULL;
        struct stat st;
        pid_t child;
        int r;

        assert(target > 0);
        assert(propagate_path);
        assert(incoming_path);
        assert(src);
        assert(dest);

        /* One day, when bind mounting /proc/self/fd/n works across
         * namespace boundaries we should rework this logic to make
         * use of it... */

        p = strjoina(propagate_path, "/");
        if (laccess(p, F_OK) < 0) {
                if (error_path)
                        *error_path = strdup("Target does not allow propagation of mount points.");
                return -EOPNOTSUPP;
        }

        r = chase_symlinks(src, NULL, CHASE_TRAIL_SLASH, &chased_src, NULL);
        if (r < 0) {
                if (error_path)
                        *error_path = strdup("Failed to resolve source path");
                return r;
        }

        if (lstat(chased_src, &st) < 0) {
                if (error_path)
                        *error_path = strdup("Failed to stat() source path");
                return -errno;
        }
        if (S_ISLNK(st.st_mode)) /* This shouldn't really happen, given that we just chased the symlinks above, but let's better be safe… */ {
                if (error_path)
                        *error_path = strdup("Source directory can't be a symbolic link");
                return -EOPNOTSUPP;
        }

        /* Our goal is to install a new bind mount into the container,
           possibly read-only. This is irritatingly complex
           unfortunately, currently.

           First, we start by creating a private playground in /tmp,
           that we can mount MS_SLAVE. (Which is necessary, since
           MS_MOVE cannot be applied to mounts with MS_SHARED parent
           mounts.) */

        if (!mkdtemp(mount_slave)) {
                if (error_path)
                        *error_path = strjoin("Failed to create playground ", mount_slave);
                return -errno;
        }

        mount_slave_created = true;

        if (mount(mount_slave, mount_slave, NULL, MS_BIND, NULL) < 0) {
                if (error_path)
                        *error_path = strjoin("Failed to make bind mount ", mount_slave);
                r = -errno;
                goto finish;
        }

        mount_slave_mounted = true;

        if (mount(NULL, mount_slave, NULL, MS_SLAVE, NULL) < 0) {
                if (error_path)
                        *error_path = strjoin("Failed to remount slave ", mount_slave);
                r = -errno;
                goto finish;
        }

        /* Second, we mount the source file or directory to a directory inside of our MS_SLAVE playground. */
        mount_tmp = strjoina(mount_slave, "/mount");
        if (S_ISDIR(st.st_mode))
                r = mkdir_errno_wrapper(mount_tmp, 0700);
        else
                r = touch(mount_tmp);
        if (r < 0) {
                if (error_path)
                        *error_path = strjoin("Failed to create temporary mount point ", mount_tmp);
                r = -errno;
                goto finish;
        }

        mount_tmp_created = true;

        if (mount(chased_src, mount_tmp, NULL, MS_BIND, NULL) < 0) {
                if (error_path)
                        *error_path = strjoin("Failed to mount ", chased_src);
                r = -errno;
                goto finish;
        }

        mount_tmp_mounted = true;

        /* Third, we remount the new bind mount read-only if requested. */
        if (read_only)
                if (mount(NULL, mount_tmp, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY, NULL) < 0) {
                        if (error_path)
                                *error_path = strjoin("Failed to remount read-only ", mount_tmp);
                        r = -errno;
                        goto finish;
                }

        /* Fourth, we move the new bind mount into the propagation directory. This way it will appear there read-only
         * right-away. */

        mount_outside = strjoina(propagate_path, "/XXXXXX");
        if (S_ISDIR(st.st_mode))
                r = mkdtemp(mount_outside) ? 0 : -errno;
        else {
                r = mkostemp_safe(mount_outside);
                safe_close(r);
        }
        if (r < 0) {
                if (error_path)
                        *error_path = strjoin("Cannot create propagation file or directory ", mount_outside);
                r = -errno;
                goto finish;
        }

        mount_outside_created = true;

        if (mount(mount_tmp, mount_outside, NULL, MS_MOVE, NULL) < 0) {
                if (error_path)
                        *error_path = strjoin("Failed to move ", mount_tmp, " to ", mount_outside);
                r = -errno;
                goto finish;
        }

        mount_outside_mounted = true;
        mount_tmp_mounted = false;

        if (S_ISDIR(st.st_mode))
                (void) rmdir(mount_tmp);
        else
                (void) unlink(mount_tmp);
        mount_tmp_created = false;

        (void) umount(mount_slave);
        mount_slave_mounted = false;

        (void) rmdir(mount_slave);
        mount_slave_created = false;

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0) {
                if (error_path)
                        *error_path = strdup("Failed to create pipe");
                r = -errno;
                goto finish;
        }

        r = safe_fork("(sd-bindmnt)", FORK_RESET_SIGNALS, &child);
        if (r < 0) {
                if (error_path)
                        *error_path = strdup("Failed to fork()");
                r = -errno;
                goto finish;
        }
        if (r == 0) {
                const char *mount_inside, *q;
                int mntfd;

                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                q = procfs_file_alloca(target, "ns/mnt");
                mntfd = open(q, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (mntfd < 0) {
                        r = log_error_errno(errno, "Failed to open mount namespace of leader: %m");
                        goto child_fail;
                }

                if (setns(mntfd, CLONE_NEWNS) < 0) {
                        r = log_error_errno(errno, "Failed to join namespace of leader: %m");
                        goto child_fail;
                }

                if (make_file_or_directory) {
                        if (S_ISDIR(st.st_mode))
                                (void) mkdir_p(dest, 0755);
                        else {
                                (void) mkdir_parents(dest, 0755);
                                (void) mknod(dest, S_IFREG|0600, 0);
                        }
                }

                /* Fifth, move the mount to the right place inside */
                mount_inside = strjoina(incoming_path, basename(mount_outside));
                if (mount(mount_inside, dest, NULL, MS_MOVE, NULL) < 0) {
                        r = log_error_errno(errno, "Failed to mount %s on %s: %m", mount_inside, dest);
                        goto child_fail;
                }

                _exit(EXIT_SUCCESS);

        child_fail:
                (void) write(errno_pipe_fd[1], &r, sizeof(r));
                errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

                _exit(EXIT_FAILURE);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        r = wait_for_terminate_and_check("(sd-bindmnt)", child, 0);
        if (r < 0) {
                if (error_path)
                        *error_path = strdup("Failed to wait for child");
                r = -errno;
                goto finish;
        }
        if (r != EXIT_SUCCESS) {
                if (read(errno_pipe_fd[0], &r, sizeof(r)) == sizeof(r)) {
                        if (error_path)
                                *error_path = strdup("Failed to mount");
                } else if (error_path)
                        *error_path = strdup("Child failed.");
                goto finish;
        }

finish:
        if (mount_outside_mounted)
                (void) umount(mount_outside);
        if (mount_outside_created) {
                if (S_ISDIR(st.st_mode))
                        (void) rmdir(mount_outside);
                else
                        (void) unlink(mount_outside);
        }

        if (mount_tmp_mounted)
                (void) umount(mount_tmp);
        if (mount_tmp_created) {
                if (S_ISDIR(st.st_mode))
                        (void) rmdir(mount_tmp);
                else
                        (void) unlink(mount_tmp);
        }

        if (mount_slave_mounted)
                (void) umount(mount_slave);
        if (mount_slave_created)
                (void) rmdir(mount_slave);

        return r;
}
