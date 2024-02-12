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
#include "parse-util.h"
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

int namespace_open(
                pid_t pid,
                int *ret_pidns_fd,
                int *ret_mntns_fd,
                int *ret_netns_fd,
                int *ret_userns_fd,
                int *ret_root_fd) {

        _cleanup_close_ int pidns_fd = -EBADF, mntns_fd = -EBADF, netns_fd = -EBADF,
                userns_fd = -EBADF, root_fd = -EBADF;

        assert(pid >= 0);

        if (ret_pidns_fd) {
                const char *pidns;

                pidns = pid_namespace_path(pid, NAMESPACE_PID);
                pidns_fd = open(pidns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (pidns_fd < 0)
                        return -errno;
        }

        if (ret_mntns_fd) {
                const char *mntns;

                mntns = pid_namespace_path(pid, NAMESPACE_MOUNT);
                mntns_fd = open(mntns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (mntns_fd < 0)
                        return -errno;
        }

        if (ret_netns_fd) {
                const char *netns;

                netns = pid_namespace_path(pid, NAMESPACE_NET);
                netns_fd = open(netns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (netns_fd < 0)
                        return -errno;
        }

        if (ret_userns_fd) {
                const char *userns;

                userns = pid_namespace_path(pid, NAMESPACE_USER);
                userns_fd = open(userns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (userns_fd < 0 && errno != ENOENT)
                        return -errno;
        }

        if (ret_root_fd) {
                const char *root;

                root = procfs_file_alloca(pid, "root");
                root_fd = open(root, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
                if (root_fd < 0)
                        return -errno;
        }

        if (ret_pidns_fd)
                *ret_pidns_fd = TAKE_FD(pidns_fd);

        if (ret_mntns_fd)
                *ret_mntns_fd = TAKE_FD(mntns_fd);

        if (ret_netns_fd)
                *ret_netns_fd = TAKE_FD(netns_fd);

        if (ret_userns_fd)
                *ret_userns_fd = TAKE_FD(userns_fd);

        if (ret_root_fd)
                *ret_root_fd = TAKE_FD(root_fd);

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
                return log_debug_errno(r, "Failed to fork process (sd-mkuserns): %m");
        if (r == 0)
                /* Child. We do nothing here, just freeze until somebody kills us. */
                freeze();

        xsprintf(path, "/proc/" PID_FMT "/uid_map", pid);
        r = write_string_file(path, uid_map, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_debug_errno(r, "Failed to write UID map: %m");

        xsprintf(path, "/proc/" PID_FMT "/gid_map", pid);
        r = write_string_file(path, gid_map, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_debug_errno(r, "Failed to write GID map: %m");

        r = namespace_open(pid,
                           /* ret_pidns_fd = */ NULL,
                           /* ret_mntns_fd = */ NULL,
                           /* ret_netns_fd = */ NULL,
                           &userns_fd,
                           /* ret_root_fd = */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to open userns fd: %m");

        return TAKE_FD(userns_fd);
}

int netns_acquire(void) {
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        _cleanup_close_ int netns_fd = -EBADF;
        int r;

        /* Forks off a process in a new network namespace, acquires a network namespace fd, and then kills
         * the process again. This way we have a netns fd that is not bound to any process. */

        r = safe_fork("(sd-mknetns)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL|FORK_NEW_NETNS, &pid);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork process (sd-mknetns): %m");
        if (r == 0)
                /* Child. We do nothing here, just freeze until somebody kills us. */
                freeze();

        r = namespace_open(pid,
                           /* ret_pidns_fd = */ NULL,
                           /* ret_mntns_fd = */ NULL,
                           &netns_fd,
                           /* ret_userns_fd = */ NULL,
                           /* ret_root_fd = */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to open netns fd: %m");

        return TAKE_FD(netns_fd);
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

int parse_userns_uid_range(const char *s, uid_t *ret_uid_shift, uid_t *ret_uid_range) {
        _cleanup_free_ char *buffer = NULL;
        const char *range, *shift;
        int r;
        uid_t uid_shift, uid_range = 65536;

        assert(s);

        range = strchr(s, ':');
        if (range) {
                buffer = strndup(s, range - s);
                if (!buffer)
                        return log_oom();
                shift = buffer;

                range++;
                r = safe_atou32(range, &uid_range);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse UID range \"%s\": %m", range);
        } else
                shift = s;

        r = parse_uid(shift, &uid_shift);
        if (r < 0)
                return log_error_errno(r, "Failed to parse UID \"%s\": %m", s);

        if (!userns_shift_range_valid(uid_shift, uid_range))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UID range cannot be empty or go beyond " UID_FMT ".", UID_INVALID);

        if (ret_uid_shift)
                *ret_uid_shift = uid_shift;

        if (ret_uid_range)
                *ret_uid_range = uid_range;

        return 0;
}
