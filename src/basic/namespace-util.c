/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/magic.h>
#include <linux/nsfs.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <unistd.h>

#include "capability-util.h"
#include "dlfcn-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "pidfd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "uid-range.h"
#include "user-util.h"

const struct namespace_info namespace_info[_NAMESPACE_TYPE_MAX + 1] = {
        [NAMESPACE_CGROUP] =  { "cgroup", "ns/cgroup", CLONE_NEWCGROUP, PIDFD_GET_CGROUP_NAMESPACE, PROC_CGROUP_INIT_INO },
        [NAMESPACE_IPC]    =  { "ipc",    "ns/ipc",    CLONE_NEWIPC,    PIDFD_GET_IPC_NAMESPACE,    PROC_IPC_INIT_INO    },
        [NAMESPACE_NET]    =  { "net",    "ns/net",    CLONE_NEWNET,    PIDFD_GET_NET_NAMESPACE,    0                    },
        /* So, the mount namespace flag is called CLONE_NEWNS for historical
         * reasons. Let's expose it here under a more explanatory name: "mnt".
         * This is in-line with how the kernel exposes namespaces in /proc/$PID/ns. */
        [NAMESPACE_MOUNT]  =  { "mnt",    "ns/mnt",    CLONE_NEWNS,     PIDFD_GET_MNT_NAMESPACE,    0                    },
        [NAMESPACE_PID]    =  { "pid",    "ns/pid",    CLONE_NEWPID,    PIDFD_GET_PID_NAMESPACE,    PROC_PID_INIT_INO    },
        [NAMESPACE_USER]   =  { "user",   "ns/user",   CLONE_NEWUSER,   PIDFD_GET_USER_NAMESPACE,   PROC_USER_INIT_INO   },
        [NAMESPACE_UTS]    =  { "uts",    "ns/uts",    CLONE_NEWUTS,    PIDFD_GET_UTS_NAMESPACE,    PROC_UTS_INIT_INO    },
        [NAMESPACE_TIME]   =  { "time",   "ns/time",   CLONE_NEWTIME,   PIDFD_GET_TIME_NAMESPACE,   PROC_TIME_INIT_INO   },
        {}, /* Allow callers to iterate over the array without using _NAMESPACE_TYPE_MAX. */
};

#define pid_namespace_path(pid, type) procfs_file_alloca(pid, namespace_info[type].proc_path)

NamespaceType clone_flag_to_namespace_type(unsigned long clone_flag) {
        for (NamespaceType t = 0; t < _NAMESPACE_TYPE_MAX; t++)
                if (((namespace_info[t].clone_flag ^ clone_flag) & (CLONE_NEWCGROUP|CLONE_NEWIPC|CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUSER|CLONE_NEWUTS|CLONE_NEWTIME)) == 0)
                        return t;

        return _NAMESPACE_TYPE_INVALID;
}

bool namespace_type_supported(NamespaceType type) {
        assert(type >= 0 && type < _NAMESPACE_TYPE_MAX);

        const char *p = pid_namespace_path(0, type);
        return access(p, F_OK) >= 0;
}

static int pidref_namespace_open_by_type_internal(const PidRef *pidref, NamespaceType type, bool *need_verify) {
        int r;

        assert(pidref_is_set(pidref));
        assert(type >= 0 && type < _NAMESPACE_TYPE_MAX);

        if (pidref_is_remote(pidref))
                return -EREMOTE;

        if (pidref->fd >= 0) {
                r = pidfd_get_namespace(pidref->fd, namespace_info[type].pidfd_get_ns_ioctl_cmd);
                if (r == -ENOPKG)
                        return log_debug_errno(
                                        r,
                                        "Cannot open %s namespace for PID "PID_FMT" as the namespace type is not supported by the kernel",
                                        namespace_info[type].proc_name, pidref->pid);
                if (!ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return r;
        }

        if (need_verify) /* The caller shall call pidref_verify() later */
                *need_verify = true;

        _cleanup_close_ int nsfd = -EBADF;
        const char *p;

        p = pid_namespace_path(pidref->pid, type);
        nsfd = RET_NERRNO(open(p, O_RDONLY|O_NOCTTY|O_CLOEXEC));
        if (nsfd == -ENOENT) {
                r = proc_mounted();
                if (r == 0)
                        /* /proc/ is not available or not set up properly, we're most likely in some chroot environment. */
                        return log_debug_errno(
                                        SYNTHETIC_ERRNO(ENOSYS),
                                        "Cannot open %s namespace for PID "PID_FMT" as /proc is not mounted",
                                        namespace_info[type].proc_name, pidref->pid);
                if (r > 0)
                        /* If /proc/ is definitely around then this means the namespace type is not supported */
                        return log_debug_errno(
                                        SYNTHETIC_ERRNO(ENOPKG),
                                        "Cannot open %s namespace for PID "PID_FMT" via /proc as the namespace type is not supported by the kernel",
                                        namespace_info[type].proc_name, pidref->pid);

                /* can't determine? then propagate original error */
        }
        if (nsfd < 0)
                return nsfd;

        if (!need_verify) { /* Otherwise we verify on our own */
                r = pidref_verify(pidref);
                if (r < 0)
                        return r;
        }

        return TAKE_FD(nsfd);
}

int pidref_namespace_open_by_type(const PidRef *pidref, NamespaceType type) {
        return pidref_namespace_open_by_type_internal(pidref, type, NULL);
}

int namespace_open_by_type(NamespaceType type) {
        _cleanup_(pidref_done) PidRef self = PIDREF_NULL;
        int r;

        assert(type >= 0 && type < _NAMESPACE_TYPE_MAX);

        r = pidref_set_self(&self);
        if (r < 0)
                return r;

        return pidref_namespace_open_by_type(&self, type);
}

int pidref_namespace_open(
                const PidRef *pidref,
                int *ret_pidns_fd,
                int *ret_mntns_fd,
                int *ret_netns_fd,
                int *ret_userns_fd,
                int *ret_root_fd) {

        _cleanup_close_ int pidns_fd = -EBADF, mntns_fd = -EBADF, netns_fd = -EBADF,
                userns_fd = -EBADF, root_fd = -EBADF;
        bool need_verify = false;
        int r;

        assert(pidref_is_set(pidref));

        if (pidref_is_remote(pidref))
                return -EREMOTE;

        if (ret_pidns_fd) {
                pidns_fd = pidref_namespace_open_by_type_internal(pidref, NAMESPACE_PID, &need_verify);
                if (pidns_fd < 0)
                        return pidns_fd;
        }

        if (ret_mntns_fd) {
                mntns_fd = pidref_namespace_open_by_type_internal(pidref, NAMESPACE_MOUNT, &need_verify);
                if (mntns_fd < 0)
                        return mntns_fd;
        }

        if (ret_netns_fd) {
                netns_fd = pidref_namespace_open_by_type_internal(pidref, NAMESPACE_NET, &need_verify);
                if (netns_fd < 0)
                        return netns_fd;
        }

        if (ret_userns_fd) {
                userns_fd = pidref_namespace_open_by_type_internal(pidref, NAMESPACE_USER, &need_verify);
                if (userns_fd < 0 && userns_fd != -ENOPKG)
                        return userns_fd;
        }

        if (ret_root_fd) {
                const char *root;

                root = procfs_file_alloca(pidref->pid, "root");
                root_fd = RET_NERRNO(open(root, O_CLOEXEC|O_DIRECTORY));
                if (root_fd == -ENOENT && proc_mounted() == 0)
                        return -ENOSYS;
                if (root_fd < 0)
                        return root_fd;

                need_verify = true;
        }

        if (need_verify) {
                r = pidref_verify(pidref);
                if (r < 0)
                        return r;
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

int namespace_open(
                pid_t pid,
                int *ret_pidns_fd,
                int *ret_mntns_fd,
                int *ret_netns_fd,
                int *ret_userns_fd,
                int *ret_root_fd) {

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        r = pidref_set_pid(&pidref, pid);
        if (r < 0)
                return r;

        return pidref_namespace_open(&pidref, ret_pidns_fd, ret_mntns_fd, ret_netns_fd, ret_userns_fd, ret_root_fd);
}

int namespace_enter(int pidns_fd, int mntns_fd, int netns_fd, int userns_fd, int root_fd) {
        int r;

        /* Block dlopen() now, to avoid us inadvertently loading shared library from another namespace */
        block_dlopen();

         /* Join namespaces, but only if we're not part of them already. This is important if we don't
          * necessarily own the namespace in question, as kernel would unconditionally return EPERM otherwise. */

        if (pidns_fd >= 0) {
                r = is_our_namespace(pidns_fd, NAMESPACE_PID);
                if (r < 0)
                        return r;
                if (r > 0)
                        pidns_fd = -EBADF;
        }

        if (mntns_fd >= 0) {
                r = is_our_namespace(mntns_fd, NAMESPACE_MOUNT);
                if (r < 0)
                        return r;
                if (r > 0)
                        mntns_fd = -EBADF;
        }

        if (netns_fd >= 0) {
                r = is_our_namespace(netns_fd, NAMESPACE_NET);
                if (r < 0)
                        return r;
                if (r > 0)
                        netns_fd = -EBADF;
        }

        if (userns_fd >= 0) {
                /* Can't setns to your own userns, since then you could escalate from non-root to root in
                 * your own namespace, so check if namespaces are equal before attempting to enter. */

                r = is_our_namespace(userns_fd, NAMESPACE_USER);
                if (r < 0)
                        return r;
                if (r > 0)
                        userns_fd = -EBADF;
        }

        r = have_effective_cap(CAP_SYS_ADMIN);
        if (r < 0)
                return r;

        bool have_cap_sys_admin = r > 0;

        if (!have_cap_sys_admin) {
                /* If we don't have CAP_SYS_ADMIN in our own user namespace, our best bet is to enter the
                 * user namespace first (if we got one) to get CAP_SYS_ADMIN within the child user namespace,
                 * and then hope the other namespaces are owned by the child user namespace. If they aren't,
                 * we'll just get an EPERM later on when trying to setns() to them. */

                if (userns_fd < 0)
                        return log_debug_errno(
                                        SYNTHETIC_ERRNO(EPERM),
                                        "Need CAP_SYS_ADMIN or a child user namespace to enter namespaces.");

                if (setns(userns_fd, CLONE_NEWUSER) < 0)
                        return -errno;
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

        if (userns_fd >= 0 && have_cap_sys_admin)
                if (setns(userns_fd, CLONE_NEWUSER) < 0)
                        return -errno;

        if (root_fd >= 0) {
                if (fchdir(root_fd) < 0)
                        return -errno;

                if (chroot(".") < 0)
                        return -errno;
        }

        if (userns_fd >= 0) {
                /* Try to become root in the user namespace but don't error out if we can't, since it's not
                 * uncommon to have user namespaces without a root user in them. */
                r = reset_uid_gid();
                if (r < 0)
                        log_debug_errno(r, "Unable to drop auxiliary groups or reset UID/GID, ignoring: %m");
        }

        return 0;
}

int fd_is_namespace(int fd, NamespaceType type) {
        int r;

        /* Checks whether the specified file descriptor refers to a namespace (of type if type != _NAMESPACE_INVALID). */

        assert(fd >= 0);
        assert(type < _NAMESPACE_TYPE_MAX);

        r = fd_is_fs_type(fd, NSFS_MAGIC);
        if (r <= 0)
                return r;

        if (type < 0)
                return true;

        int clone_flag = ioctl(fd, NS_GET_NSTYPE);
        if (clone_flag < 0)
                return -errno;

        NamespaceType found_type = clone_flag_to_namespace_type(clone_flag);
        if (found_type < 0)
                return -EBADF; /* Uh? Unknown namespace type? */

        return found_type == type;
}

int is_our_namespace(int fd, NamespaceType type) {
        int r;

        assert(fd >= 0);
        assert(type < _NAMESPACE_TYPE_MAX);

        r = fd_is_namespace(fd, type);
        if (r < 0)
                return r;
        if (r == 0) /* Not a namespace or not of the right type? */
                return -EUCLEAN;

        _cleanup_close_ int our_ns = namespace_open_by_type(type);
        if (our_ns < 0)
                return our_ns;

        return fd_inode_same(fd, our_ns);
}

int are_our_namespaces(int pidns_fd, int mntns_fd, int netns_fd, int userns_fd, int root_fd) {
        int r;

        if (pidns_fd >= 0) {
                r = is_our_namespace(pidns_fd, NAMESPACE_PID);
                if (r <= 0)
                        return r;
        }

        if (mntns_fd >= 0) {
                r = is_our_namespace(mntns_fd, NAMESPACE_MOUNT);
                if (r <= 0)
                        return r;
        }

        if (netns_fd >= 0) {
                r = is_our_namespace(netns_fd, NAMESPACE_NET);
                if (r <= 0)
                        return r;
        }

        if (userns_fd >= 0) {
                r = is_our_namespace(userns_fd, NAMESPACE_USER);
                if (r <= 0)
                        return r;
        }

        if (root_fd >= 0) {
                r = dir_fd_is_root(root_fd);
                if (r <= 0)
                        return r;
        }

        return true;
}

int namespace_is_init(NamespaceType type) {
        int r;

        assert(type >= 0);
        assert(type < _NAMESPACE_TYPE_MAX);

        if (namespace_info[type].root_inode == 0)
                return -EBADR; /* Cannot answer this question */

        const char *p = pid_namespace_path(0, type);

        struct stat st;
        r = RET_NERRNO(stat(p, &st));
        if (r == -ENOENT) {
                /* If the /proc/ns/<type> API is not around in /proc/ then ns is off in the kernel and we are in the init ns */
                r = proc_mounted();
                if (r < 0)
                        return -ENOENT; /* If we can't determine if /proc/ is mounted propagate original error */

                return r ? true : -ENOSYS;
        }
        if (r < 0)
                return r;

        return st.st_ino == namespace_info[type].root_inode;
}

int pidref_in_same_namespace(PidRef *pid1, PidRef *pid2, NamespaceType type) {
        _cleanup_close_ int ns1 = -EBADF, ns2 = -EBADF;

        /* Accepts NULL to indicate our own process */

        assert(!pid1 || pidref_is_set(pid1));
        assert(!pid2 || pidref_is_set(pid2));
        assert(type >= 0 && type < _NAMESPACE_TYPE_MAX);

        if (pidref_equal(pid1, pid2))
                return true;

        if (!pid1)
                ns1 = namespace_open_by_type(type);
        else
                ns1 = pidref_namespace_open_by_type(pid1, type);
        if (ns1 < 0)
                return ns1;

        if (!pid2)
                ns2 = namespace_open_by_type(type);
        else
                ns2 = pidref_namespace_open_by_type(pid2, type);
        if (ns2 < 0)
                return ns2;

        return fd_inode_same(ns1, ns2);
}

int in_same_namespace(pid_t pid1, pid_t pid2, NamespaceType type) {
        assert(pid1 >= 0);
        assert(pid2 >= 0);
        return pidref_in_same_namespace(pid1 == 0 ? NULL : &PIDREF_MAKE_FROM_PID(pid1),
                                        pid2 == 0 ? NULL : &PIDREF_MAKE_FROM_PID(pid2),
                                        type);
}

int namespace_get_leader(PidRef *pidref, NamespaceType type, PidRef *ret) {
        int r;

        /* Note: we don't bother with pidref_is_set()/pidref_is_remote() here, as the first call we do,
         * pidref_get_ppid_as_pidref() calls those anyway */

        assert(type >= 0 && type < _NAMESPACE_TYPE_MAX);
        assert(ret);

        _cleanup_(pidref_done) PidRef current = PIDREF_NULL;
        PidRef *c = pidref;

        for (;;) {
                _cleanup_(pidref_done) PidRef parent = PIDREF_NULL;

                r = pidref_get_ppid_as_pidref(c, &parent);
                if (r < 0)
                        return r;

                r = pidref_in_same_namespace(c, &parent, type);
                if (r < 0)
                        return r;
                if (r == 0) {
                        /* If the parent and the child are not in the same namespace, then the child is
                         * the leader we are looking for. */

                        if (pidref_is_set(&current))
                                *ret = TAKE_PIDREF(current);
                        else {
                                r = pidref_copy(c, ret);
                                if (r < 0)
                                        return r;
                        }

                        return 0;
                }

                pidref_done(&current);
                current = TAKE_PIDREF(parent);
                c = &current;
        }
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
        uid_t from_uid;
        gid_t from_gid;
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

        from_uid = getuid();
        from_gid = getgid();

        if (unshare(CLONE_NEWUSER) < 0)
                return log_debug_errno(errno, "Failed to acquire user namespace: %m");

        r = write_string_filef("/proc/self/uid_map", 0,
                               UID_FMT " " UID_FMT " 1\n", target_uid, from_uid);
        if (r < 0)
                return log_debug_errno(r, "Failed to write uid map: %m");

        r = write_string_file("/proc/self/setgroups", "deny", 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to write setgroups file: %m");

        r = write_string_filef("/proc/self/gid_map", 0,
                               GID_FMT " " GID_FMT " 1\n", target_gid, from_gid);
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

int userns_acquire_empty(void) {
        _cleanup_(pidref_done_sigkill_wait) PidRef pid = PIDREF_NULL;
        int r;

        r = pidref_safe_fork("(sd-mkuserns)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL|FORK_NEW_USERNS|FORK_FREEZE, &pid);
        if (r < 0)
                return r;
        assert(r > 0);

        return pidref_namespace_open_by_type(&pid, NAMESPACE_USER);
}

int userns_acquire(const char *uid_map, const char *gid_map, bool setgroups_deny) {
        char path[STRLEN("/proc//setgroups") + DECIMAL_STR_MAX(pid_t) + 1];
        _cleanup_(pidref_done_sigkill_wait) PidRef pid = PIDREF_NULL;
        int r;

        assert(uid_map);
        assert(gid_map);

        /* Forks off a process in a new userns, configures the specified uidmap/gidmap, acquires an fd to it,
         * and then kills the process again. This way we have a userns fd that is not bound to any
         * process. We can use that for file system mounts and similar. */

        r = pidref_safe_fork("(sd-mkuserns)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL|FORK_NEW_USERNS|FORK_FREEZE, &pid);
        if (r < 0)
                return r;
        assert(r > 0);

        xsprintf(path, "/proc/" PID_FMT "/uid_map", pid.pid);
        r = write_string_file(path, uid_map, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_debug_errno(r, "Failed to write UID map: %m");

        if (setgroups_deny) {
                xsprintf(path, "/proc/" PID_FMT "/setgroups", pid.pid);
                r = write_string_file(path, "deny", WRITE_STRING_FILE_DISABLE_BUFFER);
                if (r < 0)
                        return log_debug_errno(r, "Failed to write setgroups file: %m");
        }

        xsprintf(path, "/proc/" PID_FMT "/gid_map", pid.pid);
        r = write_string_file(path, gid_map, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_debug_errno(r, "Failed to write GID map: %m");

        return pidref_namespace_open_by_type(&pid, NAMESPACE_USER);
}

int userns_acquire_self_root(void) {

        /* Returns a user namespace with only our own uid/gid mapped to root, and everything else unmapped.
         *
         * Note: this can be acquired unprivileged! */

        _cleanup_free_ char *uid_map = NULL, *gid_map = NULL;
        if (asprintf(&uid_map, "0 " UID_FMT " 1", getuid()) < 0)
                return -ENOMEM;
        if (asprintf(&gid_map, "0 " GID_FMT " 1", getgid()) < 0)
                return -ENOMEM;

        return userns_acquire(uid_map, gid_map, /* setgroups_deny= */ true);
}

int userns_enter_and_pin(int userns_fd, PidRef *ret) {
        _cleanup_close_pair_ int pfd[2] = EBADF_PAIR;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        ssize_t n;
        char x;
        int r;

        assert(userns_fd >= 0);
        assert(ret);

        if (pipe2(pfd, O_CLOEXEC) < 0)
                return -errno;

        r = pidref_safe_fork_full(
                        "(sd-pinuserns)",
                        /* stdio_fds= */ NULL,
                        (int[]) { pfd[1], userns_fd }, 2,
                        FORK_CLOSE_ALL_FDS|FORK_REOPEN_LOG|FORK_DEATHSIG_SIGKILL,
                        &pidref);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child. */

                if (setns(userns_fd, CLONE_NEWUSER) < 0) {
                        log_debug_errno(errno, "Failed to join userns: %m");
                        _exit(EXIT_FAILURE);
                }

                userns_fd = safe_close(userns_fd);

                n = write(pfd[1], &(const char) { 'x' }, 1);
                if (n < 0) {
                        log_debug_errno(errno, "Failed to write to pipe: %m");
                        _exit(EXIT_FAILURE);
                }
                assert(n == 1);

                freeze();
        }

        pfd[1] = safe_close(pfd[1]);

        n = read(pfd[0], &x, 1);
        if (n < 0)
                return -errno;
        if (n == 0)
                return -EPROTO;
        assert(n == 1);
        assert(x == 'x');

        *ret = TAKE_PIDREF(pidref);
        return 0;
}

bool userns_supported(void) {
        return access("/proc/self/uid_map", F_OK) >= 0;
}

int userns_get_base_uid(int userns_fd, uid_t *ret_uid, gid_t *ret_gid) {
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        int r;

        assert(userns_fd >= 0);

        r = userns_enter_and_pin(userns_fd, &pidref);
        if (r < 0)
                return r;

        uid_t uid;
        r = uid_map_search_root(pidref.pid, UID_RANGE_USERNS_OUTSIDE, &uid);
        if (r < 0)
                return r;

        gid_t gid;
        r = uid_map_search_root(pidref.pid, GID_RANGE_USERNS_OUTSIDE, &gid);
        if (r < 0)
                return r;

        if (!ret_gid && uid != gid)
                return -EUCLEAN;

        if (ret_uid)
                *ret_uid = uid;
        if (ret_gid)
                *ret_gid = gid;

        return 0;
}

int process_is_owned_by_uid(const PidRef *pidref, uid_t uid) {
        int r;

        /* Checks if the specified process either is owned directly by the specified user, or if it is inside
         * a user namespace owned by it. */

        assert(uid_is_valid(uid));

        uid_t process_uid;
        r = pidref_get_uid(pidref, &process_uid);
        if (r < 0)
                return r;
        if (process_uid == uid)
                return true;

        _cleanup_close_ int userns_fd = -EBADF;
        userns_fd = pidref_namespace_open_by_type(pidref, NAMESPACE_USER);
        if (userns_fd == -ENOPKG) /* If userns is not supported, then they don't matter for ownership */
                return false;
        if (userns_fd < 0)
                return userns_fd;

        for (unsigned iteration = 0;; iteration++) {
                uid_t ns_uid;

                /* This process is in our own userns? Then we are done, in our own userns only the UIDs
                 * themselves matter. */
                r = is_our_namespace(userns_fd, NAMESPACE_USER);
                if (r < 0)
                        return r;
                if (r > 0)
                        return false;

                if (ioctl(userns_fd, NS_GET_OWNER_UID, &ns_uid) < 0)
                        return -errno;
                if (ns_uid == uid)
                        return true;

                /* Paranoia check */
                if (iteration > 16)
                        return log_debug_errno(SYNTHETIC_ERRNO(ELOOP), "Giving up while tracing parents of user namespaces after %u steps.", iteration);

                /* Go up the tree */
                _cleanup_close_ int parent_fd = ioctl(userns_fd, NS_GET_USERNS);
                if (parent_fd < 0) {
                        if (errno == EPERM) /* EPERM means we left our own userns */
                                return false;

                        return -errno;
                }

                close_and_replace(userns_fd, parent_fd);
        }
}

int is_idmapping_supported(const char *path) {
        _cleanup_close_ int mount_fd = -EBADF, userns_fd = -EBADF, dir_fd = -EBADF;
        int r;

        assert(path);

        if (!mount_new_api_supported())
                return false;

        userns_fd = r = userns_acquire_self_root();
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r) || ERRNO_IS_NEG_PRIVILEGE(r) || r == -EINVAL)
                return false;
        if (r == -ENOSPC) {
                log_debug_errno(r, "Failed to acquire new user namespace, user.max_user_namespaces seems to be exhausted or maybe even zero, assuming ID-mapping is not supported: %m");
                return false;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to acquire new user namespace for checking if '%s' supports ID-mapping: %m", path);

        dir_fd = r = RET_NERRNO(open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return false;
        if (r < 0)
                return log_debug_errno(r, "Failed to open '%s', cannot determine if ID-mapping is supported: %m", path);

        mount_fd = r = RET_NERRNO(open_tree(dir_fd, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC));
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r) || ERRNO_IS_NEG_PRIVILEGE(r) || r == -EINVAL)
                return false;
        if (r < 0)
                return log_debug_errno(r, "Failed to open mount tree '%s', cannot determine if ID-mapping is supported: %m", path);

        r = RET_NERRNO(mount_setattr(mount_fd, "", AT_EMPTY_PATH,
                       &(struct mount_attr) {
                                .attr_set = MOUNT_ATTR_IDMAP | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_RDONLY | MOUNT_ATTR_NODEV,
                                .userns_fd = userns_fd,
                        }, sizeof(struct mount_attr)));
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r) || ERRNO_IS_NEG_PRIVILEGE(r) || r == -EINVAL)
                return false;
        if (r < 0)
                return log_debug_errno(r, "Failed to set mount attribute to '%s', cannot determine if ID-mapping is supported: %m", path);

        return true;
}

int netns_acquire(void) {
        _cleanup_(pidref_done_sigkill_wait) PidRef pid = PIDREF_NULL;
        int r;

        /* Forks off a process in a new network namespace, acquires a network namespace fd, and then kills
         * the process again. This way we have a netns fd that is not bound to any process. */

        r = pidref_safe_fork("(sd-mknetns)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL|FORK_NEW_NETNS|FORK_FREEZE, &pid);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork process into new netns: %m");
        assert(r > 0);

        return pidref_namespace_open_by_type(&pid, NAMESPACE_NET);
}
