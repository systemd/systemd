/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#if WANT_LINUX_FS_H
#include <linux/fs.h>
#endif

#include "alloc-util.h"
#include "chase.h"
#include "fd-util.h"
#include "fileio.h"
#include "filesystems.h"
#include "fs-util.h"
#include "missing_fs.h"
#include "missing_mount.h"
#include "missing_stat.h"
#include "missing_syscall.h"
#include "mkdir.h"
#include "mountpoint-util.h"
#include "nulstr-util.h"
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

        size_t n = ORIGINAL_MAX_HANDLE_SZ;

        assert((flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);

        /* We need to invoke name_to_handle_at() in a loop, given that it might return EOVERFLOW when the specified
         * buffer is too small. Note that in contrast to what the docs might suggest, MAX_HANDLE_SZ is only good as a
         * start value, it is not an upper bound on the buffer size required.
         *
         * This improves on raw name_to_handle_at() also in one other regard: ret_handle and ret_mnt_id can be passed
         * as NULL if there's no interest in either. */

        for (;;) {
                _cleanup_free_ struct file_handle *h = NULL;
                int mnt_id = -1;

                h = malloc0(offsetof(struct file_handle, f_handle) + n);
                if (!h)
                        return -ENOMEM;

                h->handle_bytes = n;

                if (name_to_handle_at(fd, strempty(path), h, &mnt_id, flags) >= 0) {

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

                /* paranoia: check for overflow (note that .handle_bytes is unsigned only) */
                if (n > UINT_MAX - offsetof(struct file_handle, f_handle))
                        return -EOVERFLOW;
        }
}

static int fd_fdinfo_mnt_id(int fd, const char *filename, int flags, int *ret_mnt_id) {
        char path[STRLEN("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ void *fdinfo = NULL;
        _cleanup_close_ int subfd = -EBADF;
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
                return proc_mounted() > 0 ? -EOPNOTSUPP : -ENOSYS;
        if (r < 0)
                return r;

        p = find_line_startswith(fdinfo, "mnt_id:");
        if (!p) /* The mnt_id field is a relatively new addition */
                return -EOPNOTSUPP;

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

        copied = strndupa_safe(s, slash - s);
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
        assert((flags & ~AT_SYMLINK_FOLLOW) == 0);

        if (!filename) {
                /* If the file name is specified as NULL we'll see if the specified 'fd' is a mount
                 * point. That's only supported if the kernel supports statx(), or if the inode specified via
                 * 'fd' refers to a directory. Otherwise, we'll have to fail (ENOTDIR), because we have no
                 * kernel API to query the information we need. */
                flags |= AT_EMPTY_PATH;
                filename = "";
        } else if (!filename_possibly_with_slash_suffix(filename))
                /* Insist that the specified filename is actually a filename, and not a path, i.e. some inode further
                 * up or down the tree then immediately below the specified directory fd. */
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

        if (statx(fd,
                  filename,
                  (FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? 0 : AT_SYMLINK_NOFOLLOW) |
                  (flags & AT_EMPTY_PATH) |
                  AT_NO_AUTOMOUNT |            /* don't trigger automounts – mounts are a local concept, hence no need to trigger automounts to determine STATX_ATTR_MOUNT_ROOT */
                  AT_STATX_DONT_SYNC,          /* don't go to the network for this – for similar reasons */
                  STATX_TYPE,
                  &sx) < 0) {
                if (!ERRNO_IS_NOT_SUPPORTED(errno) && /* statx() is not supported by the kernel. */
                    !ERRNO_IS_PRIVILEGE(errno) &&     /* maybe filtered by seccomp. */
                    errno != EINVAL)                  /* glibc's fallback method returns EINVAL when AT_STATX_DONT_SYNC is set. */
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

        if (isempty(filename))
                r = name_to_handle_at_loop(fd, "..", &h_parent, &mount_id_parent, 0); /* can't work for non-directories 😢 */
        else
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

        if (h->handle_type == h_parent->handle_type &&
            memcmp_nn(h->f_handle, h->handle_bytes,
                      h_parent->f_handle, h_parent->handle_bytes) == 0)
                return 1;

        return mount_id != mount_id_parent;

fallback_fdinfo:
        r = fd_fdinfo_mnt_id(fd, filename, flags, &mount_id);
        if (IN_SET(r, -EOPNOTSUPP, -EACCES, -EPERM, -ENOSYS))
                goto fallback_fstat;
        if (r < 0)
                return r;

        if (isempty(filename))
                r = fd_fdinfo_mnt_id(fd, "..", 0, &mount_id_parent); /* can't work for non-directories 😢 */
        else
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

        if (isempty(filename))
                r = fstatat(fd, "..", &b, 0);
        else
                r = fstatat(fd, "", &b, AT_EMPTY_PATH);
        if (r < 0)
                return -errno;

        /* A directory with same device and inode as its parent? Must be the root directory */
        if (stat_inode_same(&a, &b))
                return 1;

        return check_st_dev && (a.st_dev != b.st_dev);
}

/* flags can be AT_SYMLINK_FOLLOW or 0 */
int path_is_mount_point(const char *t, const char *root, int flags) {
        _cleanup_free_ char *canonical = NULL;
        _cleanup_close_ int fd = -EBADF;
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
                r = chase(t, root, CHASE_TRAIL_SLASH, &canonical, NULL);
                if (r < 0)
                        return r;

                t = canonical;
        }

        fd = open_parent(t, O_PATH|O_CLOEXEC, 0);
        if (fd < 0)
                return fd;

        return fd_is_mount_point(fd, last_path_component(t), flags);
}

int path_get_mnt_id_at_fallback(int dir_fd, const char *path, int *ret) {
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(ret);

        r = name_to_handle_at_loop(dir_fd, path, NULL, ret, isempty(path) ? AT_EMPTY_PATH : 0);
        if (r == 0 || is_name_to_handle_at_fatal_error(r))
                return r;

        return fd_fdinfo_mnt_id(dir_fd, path, isempty(path) ? AT_EMPTY_PATH : 0, ret);
}

int path_get_mnt_id_at(int dir_fd, const char *path, int *ret) {
        STRUCT_NEW_STATX_DEFINE(buf);

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(ret);

        if (statx(dir_fd,
                  strempty(path),
                  (isempty(path) ? AT_EMPTY_PATH : AT_SYMLINK_NOFOLLOW) |
                  AT_NO_AUTOMOUNT |    /* don't trigger automounts, mnt_id is a local concept */
                  AT_STATX_DONT_SYNC,  /* don't go to the network, mnt_id is a local concept */
                  STATX_MNT_ID,
                  &buf.sx) < 0) {
                if (!ERRNO_IS_NOT_SUPPORTED(errno) && /* statx() is not supported by the kernel. */
                    !ERRNO_IS_PRIVILEGE(errno) &&     /* maybe filtered by seccomp. */
                    errno != EINVAL)                  /* glibc's fallback method returns EINVAL when AT_STATX_DONT_SYNC is set. */
                        return -errno;

                /* Fall back to name_to_handle_at() and then fdinfo if statx is not supported or we lack
                 * privileges */

        } else if (FLAGS_SET(buf.nsx.stx_mask, STATX_MNT_ID)) {
                *ret = buf.nsx.stx_mnt_id;
                return 0;
        }

        return path_get_mnt_id_at_fallback(dir_fd, path, ret);
}

bool fstype_is_network(const char *fstype) {
        const char *x;

        x = startswith(fstype, "fuse.");
        if (x)
                fstype = x;

        if (nulstr_contains(filesystem_sets[FILESYSTEM_SET_NETWORK].value, fstype))
                return true;

        /* Filesystems not present in the internal database */
        return STR_IN_SET(fstype,
                          "davfs",
                          "glusterfs",
                          "lustre",
                          "sshfs");
}

bool fstype_needs_quota(const char *fstype) {
       /* 1. quotacheck needs to be run for some filesystems after they are mounted
        *    if the filesystem was not unmounted cleanly.
        * 2. You may need to run quotaon to enable quota usage tracking and/or
        *    enforcement.
        * ext2     - needs 1) and 2)
        * ext3     - needs 2) if configured using usrjquota/grpjquota mount options
        * ext4     - needs 1) if created without journal, needs 2) if created without QUOTA
        *            filesystem feature
        * reiserfs - needs 2).
        * jfs      - needs 2)
        * f2fs     - needs 2) if configured using usrjquota/grpjquota/prjjquota mount options
        * xfs      - nothing needed
        * gfs2     - nothing needed
        * ocfs2    - nothing needed
        * btrfs    - nothing needed
        * for reference see filesystem and quota manpages */
        return STR_IN_SET(fstype,
                          "ext2",
                          "ext3",
                          "ext4",
                          "reiserfs",
                          "jfs",
                          "f2fs");
}

bool fstype_is_api_vfs(const char *fstype) {
        const FilesystemSet *fs;

        FOREACH_POINTER(fs,
                filesystem_sets + FILESYSTEM_SET_BASIC_API,
                filesystem_sets + FILESYSTEM_SET_AUXILIARY_API,
                filesystem_sets + FILESYSTEM_SET_PRIVILEGED_API,
                filesystem_sets + FILESYSTEM_SET_TEMPORARY)
            if (nulstr_contains(fs->value, fstype))
                    return true;

        /* Filesystems not present in the internal database */
        return STR_IN_SET(fstype,
                          "autofs",
                          "cpuset",
                          "devtmpfs");
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
                          "cramfs",
                          "erofs",
                          "iso9660",
                          "squashfs");
}

bool fstype_can_discard(const char *fstype) {
        assert(fstype);

        /* Use a curated list as first check, to avoid calling fsopen() which might load kmods, which might
         * not be allowed in our MAC context. */
        if (STR_IN_SET(fstype, "btrfs", "f2fs", "ext4", "vfat", "xfs"))
                return true;

        /* On new kernels we can just ask the kernel */
        return mount_option_supported(fstype, "discard", NULL) > 0;
}

bool fstype_can_norecovery(const char *fstype) {
        assert(fstype);

        /* Use a curated list as first check, to avoid calling fsopen() which might load kmods, which might
         * not be allowed in our MAC context. */
        if (STR_IN_SET(fstype, "ext3", "ext4", "xfs", "btrfs"))
                return true;

        /* On new kernels we can just ask the kernel */
        return mount_option_supported(fstype, "norecovery", NULL) > 0;
}

bool fstype_can_umask(const char *fstype) {
        assert(fstype);

        /* Use a curated list as first check, to avoid calling fsopen() which might load kmods, which might
         * not be allowed in our MAC context. If we don't know ourselves, on new kernels we can just ask the
         * kernel. */
        return streq(fstype, "vfat") || mount_option_supported(fstype, "umask", "0077") > 0;
}

bool fstype_can_uid_gid(const char *fstype) {
        /* All file systems that have a uid=/gid= mount option that fixates the owners of all files and
         * directories, current and future. Note that this does *not* ask the kernel via
         * mount_option_supported() here because the uid=/gid= setting of various file systems mean different
         * things: some apply it only to the root dir inode, others to all inodes in the file system. Thus we
         * maintain the curated list below. 😢 */

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
        if (r == -ENOENT)
                return proc_mounted() > 0 ? -ENOENT : -ENOSYS;
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

                e = strstrafter(line, " - ");
                if (!e)
                        continue;

                /* accept any name that starts with the currently expected type */
                if (startswith(e, "devtmpfs"))
                        return true;
        }

        return false;
}

int mount_fd(const char *source,
             int target_fd,
             const char *filesystemtype,
             unsigned long mountflags,
             const void *data) {

        if (mount(source, FORMAT_PROC_FD_PATH(target_fd), filesystemtype, mountflags, data) < 0) {
                if (errno != ENOENT)
                        return -errno;

                /* ENOENT can mean two things: either that the source is missing, or that /proc/ isn't
                 * mounted. Check for the latter to generate better error messages. */
                if (proc_mounted() == 0)
                        return -ENOSYS;

                return -ENOENT;
        }

        return 0;
}

int mount_nofollow(
                const char *source,
                const char *target,
                const char *filesystemtype,
                unsigned long mountflags,
                const void *data) {

        _cleanup_close_ int fd = -EBADF;

        /* In almost all cases we want to manipulate the mount table without following symlinks, hence
         * mount_nofollow() is usually the way to go. The only exceptions are environments where /proc/ is
         * not available yet, since we need /proc/self/fd/ for this logic to work. i.e. during the early
         * initialization of namespacing/container stuff where /proc is not yet mounted (and maybe even the
         * fs to mount) we can only use traditional mount() directly.
         *
         * Note that this disables following only for the final component of the target, i.e symlinks within
         * the path of the target are honoured, as are symlinks in the source path everywhere. */

        fd = open(target, O_PATH|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return mount_fd(source, fd, filesystemtype, mountflags, data);
}

const char *mount_propagation_flag_to_string(unsigned long flags) {

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

int mount_propagation_flag_from_string(const char *name, unsigned long *ret) {

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

bool mount_propagation_flag_is_valid(unsigned long flag) {
        return IN_SET(flag, 0, MS_SHARED, MS_PRIVATE, MS_SLAVE);
}

bool mount_new_api_supported(void) {
        static int cache = -1;
        int r;

        if (cache >= 0)
                return cache;

        /* This is the newer API among the ones we use, so use it as boundary */
        r = RET_NERRNO(mount_setattr(-EBADF, NULL, 0, NULL, 0));
        if (r == 0 || ERRNO_IS_NOT_SUPPORTED(r)) /* This should return an error if it is working properly */
                return (cache = false);

        return (cache = true);
}

unsigned long ms_nosymfollow_supported(void) {
        _cleanup_close_ int fsfd = -EBADF, mntfd = -EBADF;
        static int cache = -1;

        /* Returns MS_NOSYMFOLLOW if it is supported, zero otherwise. */

        if (cache >= 0)
                return cache ? MS_NOSYMFOLLOW : 0;

        if (!mount_new_api_supported())
                goto not_supported;

        /* Checks if MS_NOSYMFOLLOW is supported (which was added in 5.10). We use the new mount API's
         * mount_setattr() call for that, which was added in 5.12, which is close enough. */

        fsfd = fsopen("tmpfs", FSOPEN_CLOEXEC);
        if (fsfd < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        goto not_supported;

                log_debug_errno(errno, "Failed to open superblock context for tmpfs: %m");
                return 0;
        }

        if (fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        goto not_supported;

                log_debug_errno(errno, "Failed to create tmpfs superblock: %m");
                return 0;
        }

        mntfd = fsmount(fsfd, FSMOUNT_CLOEXEC, 0);
        if (mntfd < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        goto not_supported;

                log_debug_errno(errno, "Failed to turn superblock fd into mount fd: %m");
                return 0;
        }

        if (mount_setattr(mntfd, "", AT_EMPTY_PATH|AT_RECURSIVE,
                          &(struct mount_attr) {
                                  .attr_set = MOUNT_ATTR_NOSYMFOLLOW,
                          }, sizeof(struct mount_attr)) < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        goto not_supported;

                log_debug_errno(errno, "Failed to set MOUNT_ATTR_NOSYMFOLLOW mount attribute: %m");
                return 0;
        }

        cache = true;
        return MS_NOSYMFOLLOW;

not_supported:
        cache = false;
        return 0;
}

int mount_option_supported(const char *fstype, const char *key, const char *value) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        /* Checks if the specified file system supports a mount option. Returns > 0 if it supports it, == 0 if
         * it does not. Return -EAGAIN if we can't determine it. And any other error otherwise. */

        assert(fstype);
        assert(key);

        fd = fsopen(fstype, FSOPEN_CLOEXEC);
        if (fd < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        return -EAGAIN;  /* new mount API not available → don't know */

                return log_debug_errno(errno, "Failed to open superblock context for '%s': %m", fstype);
        }

        /* Various file systems have not been converted to the new mount API yet. For such file systems
         * fsconfig() with FSCONFIG_SET_STRING/FSCONFIG_SET_FLAG never fail. Which sucks, because we want to
         * use it for testing support, after all. Let's hence do a check if the file system got converted yet
         * first. */
        if (fsconfig(fd, FSCONFIG_SET_FD, "adefinitelynotexistingmountoption", NULL, fd) < 0) {
                /* If FSCONFIG_SET_FD is not supported for the fs, then the file system was not converted to
                 * the new mount API yet. If it returns EINVAL the mount option doesn't exist, but the fstype
                 * is converted. */
                if (errno == EOPNOTSUPP)
                        return -EAGAIN; /* FSCONFIG_SET_FD not supported on the fs, hence not converted to new mount API → don't know */
                if (errno != EINVAL)
                        return log_debug_errno(errno, "Failed to check if file system has been converted to new mount API: %m");

                /* So FSCONFIG_SET_FD worked, but the option didn't exist (we got EINVAL), this means the fs
                 * is converted. Let's now ask the actual question we wonder about. */
        } else
                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN), "FSCONFIG_SET_FD worked unexpectedly for '%s', whoa!", fstype);

        if (value)
                r = fsconfig(fd, FSCONFIG_SET_STRING, key, value, 0);
        else
                r = fsconfig(fd, FSCONFIG_SET_FLAG, key, NULL, 0);
        if (r < 0) {
                if (errno == EINVAL)
                        return false; /* EINVAL means option not supported. */

                return log_debug_errno(errno, "Failed to set '%s%s%s' on '%s' superblock context: %m",
                                       key, value ? "=" : "", strempty(value), fstype);
        }

        return true; /* works! */
}
