/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "missing_stat.h"
#include "missing_syscall.h"
#include "mkdir.h"
#include "mountpoint-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "user-util.h"

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

        assert((flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);

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

static int fd_fdinfo_mnt_id(int fd, const char *filename, int flags, int *ret_mnt_id) {
        char path[STRLEN("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *fdinfo = NULL;
        _cleanup_close_ int subfd = -1;
        char *p;
        int r;

        assert(ret_mnt_id);
        assert((flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);

        if ((flags & AT_EMPTY_PATH) && isempty(filename))
                xsprintf(path, "/proc/self/fdinfo/%i", fd);
        else {
                subfd = openat(fd, filename, O_CLOEXEC|O_PATH|(flags & AT_SYMLINK_FOLLOW ? 0 : O_NOFOLLOW));
                if (subfd < 0)
                        return -errno;

                xsprintf(path, "/proc/self/fdinfo/%i", subfd);
        }

        r = read_full_virtual_file(path, &fdinfo, NULL);
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

        return safe_atoi(p, ret_mnt_id);
}

static bool filename_possibly_with_slash_suffix(const char *s) {
        const char *slash, *copied;

        /* Checks whether the specified string is either file name, or a filename with a suffix of
         * slashes. But nothing else.
         *
         * this is OK: foo, bar, foo/, bar/, foo//, bar///
         * this is not OK: "", "/", "/foo", "foo/bar", ".", ".." … */

        slash = strchr(s, '/');
        if (!slash)
                return filename_is_valid(s);

        if (slash - s > PATH_MAX) /* We want to allocate on the stack below, hence do a size check first */
                return false;

        if (slash[strspn(slash, "/")] != 0) /* Check that the suffix consist only of one or more slashes */
                return false;

        copied = strndupa(s, slash - s);
        return filename_is_valid(copied);
}

static bool is_name_to_handle_at_fatal_error(int err) {
        /* name_to_handle_at() can return "acceptable" errors that are due to the context. For
         * example the kernel does not support name_to_handle_at() at all (ENOSYS), or the syscall
         * was blocked (EACCES/EPERM; maybe through seccomp, because we are running inside of a
         * container), or the mount point is not triggered yet (EOVERFLOW, think nfs4), or some
         * general name_to_handle_at() flakiness (EINVAL). However other errors are not supposed to
         * happen and therefore are considered fatal ones. */

        assert(err < 0);

        return !IN_SET(err, -EOPNOTSUPP, -ENOSYS, -EACCES, -EPERM, -EOVERFLOW, -EINVAL);
}

int fd_is_mount_point(int fd, const char *filename, int flags) {
        _cleanup_free_ struct file_handle *h = NULL, *h_parent = NULL;
        int mount_id = -1, mount_id_parent = -1;
        bool nosupp = false, check_st_dev = true;
        STRUCT_STATX_DEFINE(sx);
        struct stat a, b;
        int r;

        assert(fd >= 0);
        assert(filename);
        assert((flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);

        /* Insist that the specified filename is actually a filename, and not a path, i.e. some inode further
         * up or down the tree then immediately below the specified directory fd. */
        if (!filename_possibly_with_slash_suffix(filename))
                return -EINVAL;

        /* First we will try statx()' STATX_ATTR_MOUNT_ROOT attribute, which is our ideal API, available
         * since kernel 5.8.
         *
         * If that fails, our second try is the name_to_handle_at() syscall, which tells us the mount id and
         * an opaque file "handle". It is not supported everywhere though (kernel compile-time option, not
         * all file systems are hooked up). If it works the mount id is usually good enough to tell us
         * whether something is a mount point.
         *
         * If that didn't work we will try to read the mount id from /proc/self/fdinfo/<fd>. This is almost
         * as good as name_to_handle_at(), however, does not return the opaque file handle. The opaque file
         * handle is pretty useful to detect the root directory, which we should always consider a mount
         * point. Hence we use this only as fallback. Exporting the mnt_id in fdinfo is a pretty recent
         * kernel addition.
         *
         * As last fallback we do traditional fstat() based st_dev comparisons. This is how things were
         * traditionally done, but unionfs breaks this since it exposes file systems with a variety of st_dev
         * reported. Also, btrfs subvolumes have different st_dev, even though they aren't real mounts of
         * their own. */

        if (statx(fd, filename, (FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? 0 : AT_SYMLINK_NOFOLLOW) |
                                (flags & AT_EMPTY_PATH) |
                                AT_NO_AUTOMOUNT, STATX_TYPE, &sx) < 0) {
                if (!ERRNO_IS_NOT_SUPPORTED(errno) && !ERRNO_IS_PRIVILEGE(errno))
                        return -errno;

                /* If statx() is not available or forbidden, fall back to name_to_handle_at() below */
        } else if (FLAGS_SET(sx.stx_attributes_mask, STATX_ATTR_MOUNT_ROOT)) /* yay! */
                return FLAGS_SET(sx.stx_attributes, STATX_ATTR_MOUNT_ROOT);
        else if (FLAGS_SET(sx.stx_mask, STATX_TYPE) && S_ISLNK(sx.stx_mode))
                return false; /* symlinks are never mount points */

        r = name_to_handle_at_loop(fd, filename, &h, &mount_id, flags);
        if (r < 0) {
                if (is_name_to_handle_at_fatal_error(r))
                        return r;
                if (r != -EOPNOTSUPP)
                        goto fallback_fdinfo;

                /* This kernel or file system does not support name_to_handle_at(), hence let's see
                 * if the upper fs supports it (in which case it is a mount point), otherwise fall
                 * back to the traditional stat() logic */
                nosupp = true;
        }

        r = name_to_handle_at_loop(fd, "", &h_parent, &mount_id_parent, AT_EMPTY_PATH);
        if (r < 0) {
                if (is_name_to_handle_at_fatal_error(r))
                        return r;
                if (r != -EOPNOTSUPP)
                        goto fallback_fdinfo;
                if (nosupp)
                        /* Both the parent and the directory can't do name_to_handle_at() */
                        goto fallback_fdinfo;

                /* The parent can't do name_to_handle_at() but the directory we are
                 * interested in can?  If so, it must be a mount point. */
                return 1;
        }

        /* The parent can do name_to_handle_at() but the directory we are interested in can't? If
         * so, it must be a mount point. */
        if (nosupp)
                return 1;

        /* If the file handle for the directory we are interested in and its parent are identical,
         * we assume this is the root directory, which is a mount point. */

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

        /* Hmm, so, the mount ids are the same. This leaves one special case though for the root file
         * system. For that, let's see if the parent directory has the same inode as we are interested
         * in. Hence, let's also do fstat() checks now, too, but avoid the st_dev comparisons, since they
         * aren't that useful on unionfs mounts. */
        check_st_dev = false;

fallback_fstat:
        /* yay for fstatat() taking a different set of flags than the other _at() above */
        if (flags & AT_SYMLINK_FOLLOW)
                flags &= ~AT_SYMLINK_FOLLOW;
        else
                flags |= AT_SYMLINK_NOFOLLOW;
        if (fstatat(fd, filename, &a, flags) < 0)
                return -errno;
        if (S_ISLNK(a.st_mode)) /* Symlinks are never mount points */
                return false;

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
                r = chase_symlinks(t, root, CHASE_TRAIL_SLASH, &canonical, NULL);
                if (r < 0)
                        return r;

                t = canonical;
        }

        fd = open_parent(t, O_PATH|O_CLOEXEC, 0);
        if (fd < 0)
                return fd;

        return fd_is_mount_point(fd, last_path_component(t), flags);
}

int path_get_mnt_id(const char *path, int *ret) {
        STRUCT_NEW_STATX_DEFINE(buf);
        int r;

        if (statx(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT, STATX_MNT_ID, &buf.sx) < 0) {
                if (!ERRNO_IS_NOT_SUPPORTED(errno) && !ERRNO_IS_PRIVILEGE(errno))
                        return -errno;

                /* Fall back to name_to_handle_at() and then fdinfo if statx is not supported or we lack
                 * privileges */

        } else if (FLAGS_SET(buf.nsx.stx_mask, STATX_MNT_ID)) {
                *ret = buf.nsx.stx_mnt_id;
                return 0;
        }

        r = name_to_handle_at_loop(AT_FDCWD, path, NULL, ret, 0);
        if (r == 0 || is_name_to_handle_at_fatal_error(r))
                return r;

        return fd_fdinfo_mnt_id(AT_FDCWD, path, 0, ret);
}

bool fstype_is_network(const char *fstype) {
        const char *x;

        x = startswith(fstype, "fuse.");
        if (x)
                fstype = x;

        return STR_IN_SET(fstype,
                          "afs",
                          "ceph",
                          "cifs",
                          "smb3",
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
                          "lustre",
                          "davfs");
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

bool fstype_is_blockdev_backed(const char *fstype) {
        const char *x;

        x = startswith(fstype, "fuse.");
        if (x)
                fstype = x;

        return !streq(fstype, "9p") && !fstype_is_network(fstype) && !fstype_is_api_vfs(fstype);
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
                          "exfat",
                          "fat",
                          "hfs",
                          "hpfs",
                          "iso9660",
                          "msdos",
                          "ntfs",
                          "vfat");
}

int dev_is_devtmpfs(void) {
        _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;
        int mount_id, r;
        char *e;

        r = path_get_mnt_id("/dev", &mount_id);
        if (r < 0)
                return r;

        r = fopen_unlocked("/proc/self/mountinfo", "re", &proc_self_mountinfo);
        if (r < 0)
                return r;

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
