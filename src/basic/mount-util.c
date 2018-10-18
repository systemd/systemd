/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

/* Include later */
#include <libmount.h>

#include "alloc-util.h"
#include "def.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "mount-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "set.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"

/* This is the original MAX_HANDLE_SZ definition from the kernel, when the API was introduced. We use that in place of
 * any more currently defined value to future-proof things: if the size is increased in the API headers, and our code
 * is recompiled then it would cease working on old kernels, as those refuse any sizes larger than this value with
 * EINVAL right-away. Hence, let's disconnect ourselves from any such API changes, and stick to the original definition
 * from when it was introduced. We use it as a start value only anyway (see below), and hence should be able to deal
 * with large file handles anyway. */
#define ORIGINAL_MAX_HANDLE_SZ 128

int name_to_handle_at_loop(
                int fd,
                const char *path,
                struct file_handle **ret_handle,
                int *ret_mnt_id,
                int flags) {

        _cleanup_free_ struct file_handle *h = NULL;
        size_t n = ORIGINAL_MAX_HANDLE_SZ;

        /* We need to invoke name_to_handle_at() in a loop, given that it might return EOVERFLOW when the specified
         * buffer is too small. Note that in contrast to what the docs might suggest, MAX_HANDLE_SZ is only good as a
         * start value, it is not an upper bound on the buffer size required.
         *
         * This improves on raw name_to_handle_at() also in one other regard: ret_handle and ret_mnt_id can be passed
         * as NULL if there's no interest in either. */

        for (;;) {
                int mnt_id = -1;

                h = malloc0(offsetof(struct file_handle, f_handle) + n);
                if (!h)
                        return -ENOMEM;

                h->handle_bytes = n;

                if (name_to_handle_at(fd, path, h, &mnt_id, flags) >= 0) {

                        if (ret_handle)
                                *ret_handle = TAKE_PTR(h);

                        if (ret_mnt_id)
                                *ret_mnt_id = mnt_id;

                        return 0;
                }
                if (errno != EOVERFLOW)
                        return -errno;

                if (!ret_handle && ret_mnt_id && mnt_id >= 0) {

                        /* As it appears, name_to_handle_at() fills in mnt_id even when it returns EOVERFLOW when the
                         * buffer is too small, but that's undocumented. Hence, let's make use of this if it appears to
                         * be filled in, and the caller was interested in only the mount ID an nothing else. */

                        *ret_mnt_id = mnt_id;
                        return 0;
                }

                /* If name_to_handle_at() didn't increase the byte size, then this EOVERFLOW is caused by something
                 * else (apparently EOVERFLOW is returned for untriggered nfs4 mounts sometimes), not by the too small
                 * buffer. In that case propagate EOVERFLOW */
                if (h->handle_bytes <= n)
                        return -EOVERFLOW;

                /* The buffer was too small. Size the new buffer by what name_to_handle_at() returned. */
                n = h->handle_bytes;
                if (offsetof(struct file_handle, f_handle) + n < n) /* check for addition overflow */
                        return -EOVERFLOW;

                h = mfree(h);
        }
}

static int fd_fdinfo_mnt_id(int fd, const char *filename, int flags, int *mnt_id) {
        char path[STRLEN("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *fdinfo = NULL;
        _cleanup_close_ int subfd = -1;
        char *p;
        int r;

        if ((flags & AT_EMPTY_PATH) && isempty(filename))
                xsprintf(path, "/proc/self/fdinfo/%i", fd);
        else {
                subfd = openat(fd, filename, O_CLOEXEC|O_PATH);
                if (subfd < 0)
                        return -errno;

                xsprintf(path, "/proc/self/fdinfo/%i", subfd);
        }

        r = read_full_file(path, &fdinfo, NULL);
        if (r == -ENOENT) /* The fdinfo directory is a relatively new addition */
                return -EOPNOTSUPP;
        if (r < 0)
                return r;

        p = startswith(fdinfo, "mnt_id:");
        if (!p) {
                p = strstr(fdinfo, "\nmnt_id:");
                if (!p) /* The mnt_id field is a relatively new addition */
                        return -EOPNOTSUPP;

                p += 8;
        }

        p += strspn(p, WHITESPACE);
        p[strcspn(p, WHITESPACE)] = 0;

        return safe_atoi(p, mnt_id);
}

int fd_is_mount_point(int fd, const char *filename, int flags) {
        _cleanup_free_ struct file_handle *h = NULL, *h_parent = NULL;
        int mount_id = -1, mount_id_parent = -1;
        bool nosupp = false, check_st_dev = true;
        struct stat a, b;
        int r;

        assert(fd >= 0);
        assert(filename);

        /* First we will try the name_to_handle_at() syscall, which
         * tells us the mount id and an opaque file "handle". It is
         * not supported everywhere though (kernel compile-time
         * option, not all file systems are hooked up). If it works
         * the mount id is usually good enough to tell us whether
         * something is a mount point.
         *
         * If that didn't work we will try to read the mount id from
         * /proc/self/fdinfo/<fd>. This is almost as good as
         * name_to_handle_at(), however, does not return the
         * opaque file handle. The opaque file handle is pretty useful
         * to detect the root directory, which we should always
         * consider a mount point. Hence we use this only as
         * fallback. Exporting the mnt_id in fdinfo is a pretty recent
         * kernel addition.
         *
         * As last fallback we do traditional fstat() based st_dev
         * comparisons. This is how things were traditionally done,
         * but unionfs breaks this since it exposes file
         * systems with a variety of st_dev reported. Also, btrfs
         * subvolumes have different st_dev, even though they aren't
         * real mounts of their own. */

        r = name_to_handle_at_loop(fd, filename, &h, &mount_id, flags);
        if (IN_SET(r, -ENOSYS, -EACCES, -EPERM, -EOVERFLOW, -EINVAL))
                /* This kernel does not support name_to_handle_at() at all (ENOSYS), or the syscall was blocked
                 * (EACCES/EPERM; maybe through seccomp, because we are running inside of a container?), or the mount
                 * point is not triggered yet (EOVERFLOW, think nfs4), or some general name_to_handle_at() flakiness
                 * (EINVAL): fall back to simpler logic. */
                goto fallback_fdinfo;
        else if (r == -EOPNOTSUPP)
                /* This kernel or file system does not support name_to_handle_at(), hence let's see if the upper fs
                 * supports it (in which case it is a mount point), otherwise fallback to the traditional stat()
                 * logic */
                nosupp = true;
        else if (r < 0)
                return r;

        r = name_to_handle_at_loop(fd, "", &h_parent, &mount_id_parent, AT_EMPTY_PATH);
        if (r == -EOPNOTSUPP) {
                if (nosupp)
                        /* Neither parent nor child do name_to_handle_at()?  We have no choice but to fall back. */
                        goto fallback_fdinfo;
                else
                        /* The parent can't do name_to_handle_at() but the directory we are interested in can?  If so,
                         * it must be a mount point. */
                        return 1;
        } else if (r < 0)
                return r;

        /* The parent can do name_to_handle_at() but the
         * directory we are interested in can't? If so, it
         * must be a mount point. */
        if (nosupp)
                return 1;

        /* If the file handle for the directory we are
         * interested in and its parent are identical, we
         * assume this is the root directory, which is a mount
         * point. */

        if (h->handle_bytes == h_parent->handle_bytes &&
            h->handle_type == h_parent->handle_type &&
            memcmp(h->f_handle, h_parent->f_handle, h->handle_bytes) == 0)
                return 1;

        return mount_id != mount_id_parent;

fallback_fdinfo:
        r = fd_fdinfo_mnt_id(fd, filename, flags, &mount_id);
        if (IN_SET(r, -EOPNOTSUPP, -EACCES, -EPERM))
                goto fallback_fstat;
        if (r < 0)
                return r;

        r = fd_fdinfo_mnt_id(fd, "", AT_EMPTY_PATH, &mount_id_parent);
        if (r < 0)
                return r;

        if (mount_id != mount_id_parent)
                return 1;

        /* Hmm, so, the mount ids are the same. This leaves one
         * special case though for the root file system. For that,
         * let's see if the parent directory has the same inode as we
         * are interested in. Hence, let's also do fstat() checks now,
         * too, but avoid the st_dev comparisons, since they aren't
         * that useful on unionfs mounts. */
        check_st_dev = false;

fallback_fstat:
        /* yay for fstatat() taking a different set of flags than the other
         * _at() above */
        if (flags & AT_SYMLINK_FOLLOW)
                flags &= ~AT_SYMLINK_FOLLOW;
        else
                flags |= AT_SYMLINK_NOFOLLOW;
        if (fstatat(fd, filename, &a, flags) < 0)
                return -errno;

        if (fstatat(fd, "", &b, AT_EMPTY_PATH) < 0)
                return -errno;

        /* A directory with same device and inode as its parent? Must
         * be the root directory */
        if (a.st_dev == b.st_dev &&
            a.st_ino == b.st_ino)
                return 1;

        return check_st_dev && (a.st_dev != b.st_dev);
}

/* flags can be AT_SYMLINK_FOLLOW or 0 */
int path_is_mount_point(const char *t, const char *root, int flags) {
        _cleanup_free_ char *canonical = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        assert(t);
        assert((flags & ~AT_SYMLINK_FOLLOW) == 0);

        if (path_equal(t, "/"))
                return 1;

        /* we need to resolve symlinks manually, we can't just rely on
         * fd_is_mount_point() to do that for us; if we have a structure like
         * /bin -> /usr/bin/ and /usr is a mount point, then the parent that we
         * look at needs to be /usr, not /. */
        if (flags & AT_SYMLINK_FOLLOW) {
                r = chase_symlinks(t, root, CHASE_TRAIL_SLASH, &canonical);
                if (r < 0)
                        return r;

                t = canonical;
        }

        fd = open_parent(t, O_PATH|O_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        return fd_is_mount_point(fd, last_path_component(t), flags);
}

int path_get_mnt_id(const char *path, int *ret) {
        int r;

        r = name_to_handle_at_loop(AT_FDCWD, path, NULL, ret, 0);
        if (IN_SET(r, -EOPNOTSUPP, -ENOSYS, -EACCES, -EPERM, -EOVERFLOW, -EINVAL)) /* kernel/fs don't support this, or seccomp blocks access, or untriggered mount, or name_to_handle_at() is flaky */
                return fd_fdinfo_mnt_id(AT_FDCWD, path, 0, ret);

        return r;
}

int umount_recursive(const char *prefix, int flags) {
        bool again;
        int n = 0, r;

        /* Try to umount everything recursively below a
         * directory. Also, take care of stacked mounts, and keep
         * unmounting them until they are gone. */

        do {
                _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;

                again = false;
                r = 0;

                proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
                if (!proc_self_mountinfo)
                        return -errno;

                (void) __fsetlocking(proc_self_mountinfo, FSETLOCKING_BYCALLER);

                for (;;) {
                        _cleanup_free_ char *path = NULL, *p = NULL;
                        int k;

                        k = fscanf(proc_self_mountinfo,
                                   "%*s "       /* (1) mount id */
                                   "%*s "       /* (2) parent id */
                                   "%*s "       /* (3) major:minor */
                                   "%*s "       /* (4) root */
                                   "%ms "       /* (5) mount point */
                                   "%*s"        /* (6) mount options */
                                   "%*[^-]"     /* (7) optional fields */
                                   "- "         /* (8) separator */
                                   "%*s "       /* (9) file system type */
                                   "%*s"        /* (10) mount source */
                                   "%*s"        /* (11) mount options 2 */
                                   "%*[^\n]",   /* some rubbish at the end */
                                   &path);
                        if (k != 1) {
                                if (k == EOF)
                                        break;

                                continue;
                        }

                        r = cunescape(path, UNESCAPE_RELAX, &p);
                        if (r < 0)
                                return r;

                        if (!path_startswith(p, prefix))
                                continue;

                        if (umount2(p, flags) < 0) {
                                r = log_debug_errno(errno, "Failed to umount %s: %m", p);
                                continue;
                        }

                        log_debug("Successfully unmounted %s", p);

                        again = true;
                        n++;

                        break;
                }

        } while (again);

        return r ? r : n;
}

static int get_mount_flags(const char *path, unsigned long *flags) {
        struct statvfs buf;

        if (statvfs(path, &buf) < 0)
                return -errno;
        *flags = buf.f_flag;
        return 0;
}

/* Use this function only if do you have direct access to /proc/self/mountinfo
 * and need the caller to open it for you. This is the case when /proc is
 * masked or not mounted. Otherwise, use bind_remount_recursive. */
int bind_remount_recursive_with_mountinfo(const char *prefix, bool ro, char **blacklist, FILE *proc_self_mountinfo) {
        _cleanup_set_free_free_ Set *done = NULL;
        _cleanup_free_ char *cleaned = NULL;
        int r;

        assert(proc_self_mountinfo);

        /* Recursively remount a directory (and all its submounts) read-only or read-write. If the directory is already
         * mounted, we reuse the mount and simply mark it MS_BIND|MS_RDONLY (or remove the MS_RDONLY for read-write
         * operation). If it isn't we first make it one. Afterwards we apply MS_BIND|MS_RDONLY (or remove MS_RDONLY) to
         * all submounts we can access, too. When mounts are stacked on the same mount point we only care for each
         * individual "top-level" mount on each point, as we cannot influence/access the underlying mounts anyway. We
         * do not have any effect on future submounts that might get propagated, they migt be writable. This includes
         * future submounts that have been triggered via autofs.
         *
         * If the "blacklist" parameter is specified it may contain a list of subtrees to exclude from the
         * remount operation. Note that we'll ignore the blacklist for the top-level path. */

        cleaned = strdup(prefix);
        if (!cleaned)
                return -ENOMEM;

        path_simplify(cleaned, false);

        done = set_new(&path_hash_ops);
        if (!done)
                return -ENOMEM;

        for (;;) {
                _cleanup_set_free_free_ Set *todo = NULL;
                bool top_autofs = false;
                char *x;
                unsigned long orig_flags;

                todo = set_new(&path_hash_ops);
                if (!todo)
                        return -ENOMEM;

                rewind(proc_self_mountinfo);

                for (;;) {
                        _cleanup_free_ char *path = NULL, *p = NULL, *type = NULL;
                        int k;

                        k = fscanf(proc_self_mountinfo,
                                   "%*s "       /* (1) mount id */
                                   "%*s "       /* (2) parent id */
                                   "%*s "       /* (3) major:minor */
                                   "%*s "       /* (4) root */
                                   "%ms "       /* (5) mount point */
                                   "%*s"        /* (6) mount options (superblock) */
                                   "%*[^-]"     /* (7) optional fields */
                                   "- "         /* (8) separator */
                                   "%ms "       /* (9) file system type */
                                   "%*s"        /* (10) mount source */
                                   "%*s"        /* (11) mount options (bind mount) */
                                   "%*[^\n]",   /* some rubbish at the end */
                                   &path,
                                   &type);
                        if (k != 2) {
                                if (k == EOF)
                                        break;

                                continue;
                        }

                        r = cunescape(path, UNESCAPE_RELAX, &p);
                        if (r < 0)
                                return r;

                        if (!path_startswith(p, cleaned))
                                continue;

                        /* Ignore this mount if it is blacklisted, but only if it isn't the top-level mount we shall
                         * operate on. */
                        if (!path_equal(cleaned, p)) {
                                bool blacklisted = false;
                                char **i;

                                STRV_FOREACH(i, blacklist) {

                                        if (path_equal(*i, cleaned))
                                                continue;

                                        if (!path_startswith(*i, cleaned))
                                                continue;

                                        if (path_startswith(p, *i)) {
                                                blacklisted = true;
                                                log_debug("Not remounting %s blacklisted by %s, called for %s", p, *i, cleaned);
                                                break;
                                        }
                                }
                                if (blacklisted)
                                        continue;
                        }

                        /* Let's ignore autofs mounts.  If they aren't
                         * triggered yet, we want to avoid triggering
                         * them, as we don't make any guarantees for
                         * future submounts anyway.  If they are
                         * already triggered, then we will find
                         * another entry for this. */
                        if (streq(type, "autofs")) {
                                top_autofs = top_autofs || path_equal(cleaned, p);
                                continue;
                        }

                        if (!set_contains(done, p)) {
                                r = set_consume(todo, p);
                                p = NULL;
                                if (r == -EEXIST)
                                        continue;
                                if (r < 0)
                                        return r;
                        }
                }

                /* If we have no submounts to process anymore and if
                 * the root is either already done, or an autofs, we
                 * are done */
                if (set_isempty(todo) &&
                    (top_autofs || set_contains(done, cleaned)))
                        return 0;

                if (!set_contains(done, cleaned) &&
                    !set_contains(todo, cleaned)) {
                        /* The prefix directory itself is not yet a mount, make it one. */
                        if (mount(cleaned, cleaned, NULL, MS_BIND|MS_REC, NULL) < 0)
                                return -errno;

                        orig_flags = 0;
                        (void) get_mount_flags(cleaned, &orig_flags);
                        orig_flags &= ~MS_RDONLY;

                        if (mount(NULL, cleaned, NULL, orig_flags|MS_BIND|MS_REMOUNT|(ro ? MS_RDONLY : 0), NULL) < 0)
                                return -errno;

                        log_debug("Made top-level directory %s a mount point.", prefix);

                        x = strdup(cleaned);
                        if (!x)
                                return -ENOMEM;

                        r = set_consume(done, x);
                        if (r < 0)
                                return r;
                }

                while ((x = set_steal_first(todo))) {

                        r = set_consume(done, x);
                        if (IN_SET(r, 0, -EEXIST))
                                continue;
                        if (r < 0)
                                return r;

                        /* Deal with mount points that are obstructed by a later mount */
                        r = path_is_mount_point(x, NULL, 0);
                        if (IN_SET(r, 0, -ENOENT))
                                continue;
                        if (IN_SET(r, -EACCES, -EPERM)) {
                                /* Even if root user invoke this, submounts under private FUSE or NFS mount points
                                 * may not be acceessed. E.g.,
                                 *
                                 * $ bindfs --no-allow-other ~/mnt/mnt ~/mnt/mnt
                                 * $ bindfs --no-allow-other ~/mnt ~/mnt
                                 *
                                 * Then, root user cannot access the mount point ~/mnt/mnt.
                                 * In such cases, the submounts are ignored, as we have no way to manage them. */
                                log_debug_errno(r, "Failed to determine '%s' is mount point or not, ignoring: %m", x);
                                continue;
                        }
                        if (r < 0)
                                return r;

                        /* Try to reuse the original flag set */
                        orig_flags = 0;
                        (void) get_mount_flags(x, &orig_flags);
                        orig_flags &= ~MS_RDONLY;

                        if (mount(NULL, x, NULL, orig_flags|MS_BIND|MS_REMOUNT|(ro ? MS_RDONLY : 0), NULL) < 0)
                                return -errno;

                        log_debug("Remounted %s read-only.", x);
                }
        }
}

int bind_remount_recursive(const char *prefix, bool ro, char **blacklist) {
        _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;

        proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
        if (!proc_self_mountinfo)
                return -errno;

        (void) __fsetlocking(proc_self_mountinfo, FSETLOCKING_BYCALLER);

        return bind_remount_recursive_with_mountinfo(prefix, ro, blacklist, proc_self_mountinfo);
}

int mount_move_root(const char *path) {
        assert(path);

        if (chdir(path) < 0)
                return -errno;

        if (mount(path, "/", NULL, MS_MOVE, NULL) < 0)
                return -errno;

        if (chroot(".") < 0)
                return -errno;

        if (chdir("/") < 0)
                return -errno;

        return 0;
}

bool fstype_is_network(const char *fstype) {
        const char *x;

        x = startswith(fstype, "fuse.");
        if (x)
                fstype = x;

        return STR_IN_SET(fstype,
                          "afs",
                          "cifs",
                          "smbfs",
                          "sshfs",
                          "ncpfs",
                          "ncp",
                          "nfs",
                          "nfs4",
                          "gfs",
                          "gfs2",
                          "glusterfs",
                          "pvfs2", /* OrangeFS */
                          "ocfs2",
                          "lustre");
}

bool fstype_is_api_vfs(const char *fstype) {
        return STR_IN_SET(fstype,
                          "autofs",
                          "bpf",
                          "cgroup",
                          "cgroup2",
                          "configfs",
                          "cpuset",
                          "debugfs",
                          "devpts",
                          "devtmpfs",
                          "efivarfs",
                          "fusectl",
                          "hugetlbfs",
                          "mqueue",
                          "proc",
                          "pstore",
                          "ramfs",
                          "securityfs",
                          "sysfs",
                          "tmpfs",
                          "tracefs");
}

bool fstype_is_ro(const char *fstype) {
        /* All Linux file systems that are necessarily read-only */
        return STR_IN_SET(fstype,
                          "DM_verity_hash",
                          "iso9660",
                          "squashfs");
}

bool fstype_can_discard(const char *fstype) {
        return STR_IN_SET(fstype,
                          "btrfs",
                          "ext4",
                          "vfat",
                          "xfs");
}

bool fstype_can_uid_gid(const char *fstype) {

        /* All file systems that have a uid=/gid= mount option that fixates the owners of all files and directories,
         * current and future. */

        return STR_IN_SET(fstype,
                          "adfs",
                          "fat",
                          "hfs",
                          "hpfs",
                          "iso9660",
                          "msdos",
                          "ntfs",
                          "vfat");
}

int repeat_unmount(const char *path, int flags) {
        bool done = false;

        assert(path);

        /* If there are multiple mounts on a mount point, this
         * removes them all */

        for (;;) {
                if (umount2(path, flags) < 0) {

                        if (errno == EINVAL)
                                return done;

                        return -errno;
                }

                done = true;
        }
}

const char* mode_to_inaccessible_node(mode_t mode) {
        /* This function maps a node type to a corresponding inaccessible file node. These nodes are created during
         * early boot by PID 1. In some cases we lacked the privs to create the character and block devices (maybe
         * because we run in an userns environment, or miss CAP_SYS_MKNOD, or run with a devices policy that excludes
         * device nodes with major and minor of 0), but that's fine, in that case we use an AF_UNIX file node instead,
         * which is not the same, but close enough for most uses. And most importantly, the kernel allows bind mounts
         * from socket nodes to any non-directory file nodes, and that's the most important thing that matters. */

        switch(mode & S_IFMT) {
                case S_IFREG:
                        return "/run/systemd/inaccessible/reg";

                case S_IFDIR:
                        return "/run/systemd/inaccessible/dir";

                case S_IFCHR:
                        if (access("/run/systemd/inaccessible/chr", F_OK) == 0)
                                return "/run/systemd/inaccessible/chr";
                        return "/run/systemd/inaccessible/sock";

                case S_IFBLK:
                        if (access("/run/systemd/inaccessible/blk", F_OK) == 0)
                                return "/run/systemd/inaccessible/blk";
                        return "/run/systemd/inaccessible/sock";

                case S_IFIFO:
                        return "/run/systemd/inaccessible/fifo";

                case S_IFSOCK:
                        return "/run/systemd/inaccessible/sock";
        }
        return NULL;
}

#define FLAG(name) (flags & name ? STRINGIFY(name) "|" : "")
static char* mount_flags_to_string(long unsigned flags) {
        char *x;
        _cleanup_free_ char *y = NULL;
        long unsigned overflow;

        overflow = flags & ~(MS_RDONLY |
                             MS_NOSUID |
                             MS_NODEV |
                             MS_NOEXEC |
                             MS_SYNCHRONOUS |
                             MS_REMOUNT |
                             MS_MANDLOCK |
                             MS_DIRSYNC |
                             MS_NOATIME |
                             MS_NODIRATIME |
                             MS_BIND |
                             MS_MOVE |
                             MS_REC |
                             MS_SILENT |
                             MS_POSIXACL |
                             MS_UNBINDABLE |
                             MS_PRIVATE |
                             MS_SLAVE |
                             MS_SHARED |
                             MS_RELATIME |
                             MS_KERNMOUNT |
                             MS_I_VERSION |
                             MS_STRICTATIME |
                             MS_LAZYTIME);

        if (flags == 0 || overflow != 0)
                if (asprintf(&y, "%lx", overflow) < 0)
                        return NULL;

        x = strjoin(FLAG(MS_RDONLY),
                    FLAG(MS_NOSUID),
                    FLAG(MS_NODEV),
                    FLAG(MS_NOEXEC),
                    FLAG(MS_SYNCHRONOUS),
                    FLAG(MS_REMOUNT),
                    FLAG(MS_MANDLOCK),
                    FLAG(MS_DIRSYNC),
                    FLAG(MS_NOATIME),
                    FLAG(MS_NODIRATIME),
                    FLAG(MS_BIND),
                    FLAG(MS_MOVE),
                    FLAG(MS_REC),
                    FLAG(MS_SILENT),
                    FLAG(MS_POSIXACL),
                    FLAG(MS_UNBINDABLE),
                    FLAG(MS_PRIVATE),
                    FLAG(MS_SLAVE),
                    FLAG(MS_SHARED),
                    FLAG(MS_RELATIME),
                    FLAG(MS_KERNMOUNT),
                    FLAG(MS_I_VERSION),
                    FLAG(MS_STRICTATIME),
                    FLAG(MS_LAZYTIME),
                    y);
        if (!x)
                return NULL;
        if (!y)
                x[strlen(x) - 1] = '\0'; /* truncate the last | */
        return x;
}

int mount_verbose(
                int error_log_level,
                const char *what,
                const char *where,
                const char *type,
                unsigned long flags,
                const char *options) {

        _cleanup_free_ char *fl = NULL, *o = NULL;
        unsigned long f;
        int r;

        r = mount_option_mangle(options, flags, &f, &o);
        if (r < 0)
                return log_full_errno(error_log_level, r,
                                      "Failed to mangle mount options %s: %m",
                                      strempty(options));

        fl = mount_flags_to_string(f);

        if ((f & MS_REMOUNT) && !what && !type)
                log_debug("Remounting %s (%s \"%s\")...",
                          where, strnull(fl), strempty(o));
        else if (!what && !type)
                log_debug("Mounting %s (%s \"%s\")...",
                          where, strnull(fl), strempty(o));
        else if ((f & MS_BIND) && !type)
                log_debug("Bind-mounting %s on %s (%s \"%s\")...",
                          what, where, strnull(fl), strempty(o));
        else if (f & MS_MOVE)
                log_debug("Moving mount %s → %s (%s \"%s\")...",
                          what, where, strnull(fl), strempty(o));
        else
                log_debug("Mounting %s on %s (%s \"%s\")...",
                          strna(type), where, strnull(fl), strempty(o));
        if (mount(what, where, type, f, o) < 0)
                return log_full_errno(error_log_level, errno,
                                      "Failed to mount %s (type %s) on %s (%s \"%s\"): %m",
                                      strna(what), strna(type), where, strnull(fl), strempty(o));
        return 0;
}

int umount_verbose(const char *what) {
        log_debug("Umounting %s...", what);
        if (umount(what) < 0)
                return log_error_errno(errno, "Failed to unmount %s: %m", what);
        return 0;
}

const char *mount_propagation_flags_to_string(unsigned long flags) {

        switch (flags & (MS_SHARED|MS_SLAVE|MS_PRIVATE)) {
        case 0:
                return "";
        case MS_SHARED:
                return "shared";
        case MS_SLAVE:
                return "slave";
        case MS_PRIVATE:
                return "private";
        }

        return NULL;
}

int mount_propagation_flags_from_string(const char *name, unsigned long *ret) {

        if (isempty(name))
                *ret = 0;
        else if (streq(name, "shared"))
                *ret = MS_SHARED;
        else if (streq(name, "slave"))
                *ret = MS_SLAVE;
        else if (streq(name, "private"))
                *ret = MS_PRIVATE;
        else
                return -EINVAL;
        return 0;
}

int mount_option_mangle(
                const char *options,
                unsigned long mount_flags,
                unsigned long *ret_mount_flags,
                char **ret_remaining_options) {

        const struct libmnt_optmap *map;
        _cleanup_free_ char *ret = NULL;
        const char *p;
        int r;

        /* This extracts mount flags from the mount options, and store
         * non-mount-flag options to '*ret_remaining_options'.
         * E.g.,
         * "rw,nosuid,nodev,relatime,size=1630748k,mode=700,uid=1000,gid=1000"
         * is split to MS_NOSUID|MS_NODEV|MS_RELATIME and
         * "size=1630748k,mode=700,uid=1000,gid=1000".
         * See more examples in test-mount-utils.c.
         *
         * Note that if 'options' does not contain any non-mount-flag options,
         * then '*ret_remaining_options' is set to NULL instread of empty string.
         * Note that this does not check validity of options stored in
         * '*ret_remaining_options'.
         * Note that if 'options' is NULL, then this just copies 'mount_flags'
         * to '*ret_mount_flags'. */

        assert(ret_mount_flags);
        assert(ret_remaining_options);

        map = mnt_get_builtin_optmap(MNT_LINUX_MAP);
        if (!map)
                return -EINVAL;

        p = options;
        for (;;) {
                _cleanup_free_ char *word = NULL;
                const struct libmnt_optmap *ent;

                r = extract_first_word(&p, &word, ",", EXTRACT_QUOTES);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                for (ent = map; ent->name; ent++) {
                        /* All entries in MNT_LINUX_MAP do not take any argument.
                         * Thus, ent->name does not contain "=" or "[=]". */
                        if (!streq(word, ent->name))
                                continue;

                        if (!(ent->mask & MNT_INVERT))
                                mount_flags |= ent->id;
                        else if (mount_flags & ent->id)
                                mount_flags ^= ent->id;

                        break;
                }

                /* If 'word' is not a mount flag, then store it in '*ret_remaining_options'. */
                if (!ent->name && !strextend_with_separator(&ret, ",", word, NULL))
                        return -ENOMEM;
        }

        *ret_mount_flags = mount_flags;
        *ret_remaining_options = TAKE_PTR(ret);

        return 0;
}

int dev_is_devtmpfs(void) {
        _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;
        int mount_id, r;
        char *e;

        r = path_get_mnt_id("/dev", &mount_id);
        if (r < 0)
                return r;

        proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
        if (!proc_self_mountinfo)
                return -errno;

        (void) __fsetlocking(proc_self_mountinfo, FSETLOCKING_BYCALLER);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                int mid;

                r = read_line(proc_self_mountinfo, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (sscanf(line, "%i", &mid) != 1)
                        continue;

                if (mid != mount_id)
                        continue;

                e = strstr(line, " - ");
                if (!e)
                        continue;

                /* accept any name that starts with the currently expected type */
                if (startswith(e + 3, "devtmpfs"))
                        return true;
        }

        return false;
}
