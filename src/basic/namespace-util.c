/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mount.h>

#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "missing_fs.h"
#include "missing_magic.h"
#include "missing_sched.h"
#include "namespace-util.h"
#include "process-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "user-util.h"

const struct namespace_info namespace_info[] = {
        [NAMESPACE_CGROUP] =  { "cgroup", "ns/cgroup", CLONE_NEWCGROUP,                          },
        [NAMESPACE_IPC]    =  { "ipc",    "ns/ipc",    CLONE_NEWIPC,                             },
        [NAMESPACE_NET]    =  { "net",    "ns/net",    CLONE_NEWNET,                             },
        /* So, the mount namespace flag is called CLONE_NEWNS for historical
         * reasons. Let's expose it here under a more explanatory name: "mnt".
         * This is in-line with how the kernel exposes namespaces in /proc/$PID/ns. */
        [NAMESPACE_MOUNT]  =  { "mnt",    "ns/mnt",    CLONE_NEWNS,                              },
        [NAMESPACE_PID]    =  { "pid",    "ns/pid",    CLONE_NEWPID,                             },
        [NAMESPACE_USER]   =  { "user",   "ns/user",   CLONE_NEWUSER,                            },
        [NAMESPACE_UTS]    =  { "uts",    "ns/uts",    CLONE_NEWUTS,                             },
        [NAMESPACE_TIME]   =  { "time",   "ns/time",   CLONE_NEWTIME,                            },
        { /* Allow callers to iterate over the array without using _NAMESPACE_TYPE_MAX. */       },
};

#define pid_namespace_path(pid, type) procfs_file_alloca(pid, namespace_info[type].proc_path)

static NamespaceType clone_flag_to_namespace_type(unsigned long clone_flag) {
        for (NamespaceType t = 0; t < _NAMESPACE_TYPE_MAX; t++)
                if (((namespace_info[t].clone_flag ^ clone_flag) & (CLONE_NEWCGROUP|CLONE_NEWIPC|CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUSER|CLONE_NEWUTS|CLONE_NEWTIME)) == 0)
                        return t;

        return _NAMESPACE_TYPE_INVALID;
}

int namespace_open(pid_t pid, int *pidns_fd, int *mntns_fd, int *netns_fd, int *userns_fd, int *root_fd) {
        _cleanup_close_ int pidnsfd = -EBADF, mntnsfd = -EBADF, netnsfd = -EBADF, usernsfd = -EBADF;
        int rfd = -EBADF;

        assert(pid >= 0);

        if (mntns_fd) {
                const char *mntns;

                mntns = pid_namespace_path(pid, NAMESPACE_MOUNT);
                mntnsfd = open(mntns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (mntnsfd < 0)
                        return -errno;
        }

        if (pidns_fd) {
                const char *pidns;

                pidns = pid_namespace_path(pid, NAMESPACE_PID);
                pidnsfd = open(pidns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (pidnsfd < 0)
                        return -errno;
        }

        if (netns_fd) {
                const char *netns;

                netns = pid_namespace_path(pid, NAMESPACE_NET);
                netnsfd = open(netns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (netnsfd < 0)
                        return -errno;
        }

        if (userns_fd) {
                const char *userns;

                userns = pid_namespace_path(pid, NAMESPACE_USER);
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
        int r;

        if (userns_fd >= 0) {
                /* Can't setns to your own userns, since then you could escalate from non-root to root in
                 * your own namespace, so check if namespaces are equal before attempting to enter. */

                r = inode_same_at(userns_fd, "", AT_FDCWD, "/proc/self/ns/user", AT_EMPTY_PATH);
                if (r < 0)
                        return r;
                if (r)
                        userns_fd = -EBADF;
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

int fd_is_ns(int fd, unsigned long nsflag) {
        struct statfs s;
        int r;

        /* Checks whether the specified file descriptor refers to a namespace created by specifying nsflag in clone().
         * On old kernels there's no nice way to detect that, hence on those we'll return a recognizable error (EUCLEAN),
         * so that callers can handle this somewhat nicely.
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

        return (unsigned long) r == nsflag;
}

int detach_mount_namespace(void) {
        /* Detaches the mount namespace, disabling propagation from our namespace to the host. Sets
         * propagation first to MS_SLAVE for all mounts (disabling propagation), and then back to MS_SHARED
         * (so that we create a new peer group).  */

        if (unshare(CLONE_NEWNS) < 0)
                return log_debug_errno(errno, "Failed to acquire mount namespace: %m");

        if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0)
                return log_debug_errno(errno, "Failed to set mount propagation to MS_SLAVE for all mounts: %m");

        if (mount(NULL, "/", NULL, MS_SHARED | MS_REC, NULL) < 0)
                return log_debug_errno(errno, "Failed to set mount propagation back to MS_SHARED for all mounts: %m");

        return 0;
}

int detach_mount_namespace_harder(uid_t target_uid, gid_t target_gid) {
        int r;

        /* Tried detach_mount_namespace() first. If that doesn't work due to permissions, opens up an
         * unprivileged user namespace with a mapping of the originating UID/GID to the specified target
         * UID/GID. Then, tries detach_mount_namespace() again.
         *
         * Or in other words: tries much harder to get a mount namespace, making use of unprivileged user
         * namespaces if need be.
         *
         * Note that after this function completed:
         *
         *    → if we had privs, afterwards uids/gids on files and processes are as before
         *
         *    → if we had no privs, our own id and all our files will show up owned by target_uid/target_gid,
         *    and everything else owned by nobody.
         *
         * Yes, that's quite a difference. */

        if (!uid_is_valid(target_uid))
                return -EINVAL;
        if (!gid_is_valid(target_gid))
                return -EINVAL;

        r = detach_mount_namespace();
        if (r != -EPERM)
                return r;

        if (unshare(CLONE_NEWUSER) < 0)
                return log_debug_errno(errno, "Failed to acquire user namespace: %m");

        r = write_string_filef("/proc/self/uid_map", 0,
                               UID_FMT " " UID_FMT " 1\n", target_uid, getuid());
        if (r < 0)
                return log_debug_errno(r, "Failed to write uid map: %m");

        r = write_string_file("/proc/self/setgroups", "deny", 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to write setgroups file: %m");

        r = write_string_filef("/proc/self/gid_map", 0,
                              GID_FMT " " GID_FMT " 1\n", target_gid, getgid());
        if (r < 0)
                return log_debug_errno(r, "Failed to write gid map: %m");

        return detach_mount_namespace();
}

int detach_mount_namespace_userns(int userns_fd) {
        int r;

        assert(userns_fd >= 0);

        if (setns(userns_fd, CLONE_NEWUSER) < 0)
                return log_debug_errno(errno, "Failed to join user namespace: %m");

        r = reset_uid_gid();
        if (r < 0)
                return log_debug_errno(r, "Failed to become root in user namespace: %m");

        return detach_mount_namespace();
}

int userns_acquire_empty(void) {
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        _cleanup_close_ int userns_fd = -EBADF;

        int r;

        r = safe_fork("(sd-mkuserns)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL|FORK_NEW_USERNS, &pid);
        if (r < 0)
                return r;
        if (r == 0)
                /* Child. We do nothing here, just freeze until somebody kills us. */
                freeze();

        r = namespace_open(pid, NULL, NULL, NULL, &userns_fd, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to open userns fd: %m");

        return TAKE_FD(userns_fd);
}

int userns_acquire(const char *uid_map, const char *gid_map) {
        char path[STRLEN("/proc//uid_map") + DECIMAL_STR_MAX(pid_t) + 1];
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        _cleanup_close_ int userns_fd = -EBADF;
        int r;

        assert(uid_map);
        assert(gid_map);

        /* Forks off a process in a new userns, configures the specified uidmap/gidmap, acquires an fd to it,
         * and then kills the process again. This way we have a userns fd that is not bound to any
         * process. We can use that for file system mounts and similar. */

        r = safe_fork("(sd-mkuserns)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL|FORK_NEW_USERNS, &pid);
        if (r < 0)
                return r;
        if (r == 0)
                /* Child. We do nothing here, just freeze until somebody kills us. */
                freeze();

        xsprintf(path, "/proc/" PID_FMT "/uid_map", pid);
        r = write_string_file(path, uid_map, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_error_errno(r, "Failed to write UID map: %m");

        xsprintf(path, "/proc/" PID_FMT "/gid_map", pid);
        r = write_string_file(path, gid_map, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_error_errno(r, "Failed to write GID map: %m");

        r = namespace_open(pid, NULL, NULL, NULL, &userns_fd, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to open userns fd: %m");

        return TAKE_FD(userns_fd);
}

int in_same_namespace(pid_t pid1, pid_t pid2, NamespaceType type) {
        const char *ns_path;
        struct stat ns_st1, ns_st2;

        if (pid1 == 0)
                pid1 = getpid_cached();

        if (pid2 == 0)
                pid2 = getpid_cached();

        if (pid1 == pid2)
                return 1;

        ns_path = pid_namespace_path(pid1, type);
        if (stat(ns_path, &ns_st1) < 0)
                return -errno;

        ns_path = pid_namespace_path(pid2, type);
        if (stat(ns_path, &ns_st2) < 0)
                return -errno;

        return stat_inode_same(&ns_st1, &ns_st2);
}

int namespace_open_by_type(NamespaceType type) {
        const char *p;
        int fd;

        assert(type >= 0);
        assert(type < _NAMESPACE_TYPE_MAX);

        p = pid_namespace_path(0, type);

        fd = RET_NERRNO(open(p, O_RDONLY|O_NOCTTY|O_CLOEXEC));
        if (fd == -ENOENT && proc_mounted() == 0)
                return -ENOSYS;

        return fd;
}

int is_our_namespace(int fd, NamespaceType request_type) {
        int clone_flag;

        assert(fd >= 0);

        clone_flag = ioctl(fd, NS_GET_NSTYPE);
        if (clone_flag < 0)
                return -errno;

        NamespaceType found_type = clone_flag_to_namespace_type(clone_flag);
        if (found_type < 0)
                return -EBADF; /* Uh? Unknown namespace type? */

        log_notice("%i vs %i", request_type, found_type);

        if (request_type >= 0 && request_type != found_type) /* It's a namespace, but not of the right type? */
                return -EUCLEAN;

        struct stat st_fd, st_ours;
        if (fstat(fd, &st_fd) < 0)
                return -errno;

        const char *p = pid_namespace_path(0, found_type);
        log_error("ns: %s", strna(p));
        if (stat(p, &st_ours) < 0) {
                if (errno == ENOENT)
                        return proc_mounted() == 0 ? -ENOSYS : -ENOENT;

                return -errno;
        }

        return stat_inode_same(&st_ours, &st_fd);
}
