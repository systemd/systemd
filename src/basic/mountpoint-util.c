/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/mount.h>

#include "alloc-util.h"
#include "chase.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "filesystems.h"
#include "fs-util.h"
#include "log.h"
#include "mountpoint-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "stat-util.h"
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

bool is_name_to_handle_at_fatal_error(int err) {
        /* name_to_handle_at() can return "acceptable" errors that are due to the context. For example
         * the file system does not support name_to_handle_at() (EOPNOTSUPP), or the syscall was blocked
         * (EACCES/EPERM; maybe through seccomp, because we are running inside of a container), or
         * the mount point is not triggered yet (EOVERFLOW, think autofs+nfs4), or some general name_to_handle_at()
         * flakiness (EINVAL). However other errors are not supposed to happen and therefore are considered
         * fatal ones. */

        assert(err < 0);

        if (ERRNO_IS_NEG_NOT_SUPPORTED(err))
                return false;
        if (ERRNO_IS_NEG_PRIVILEGE(err))
                return false;

        return !IN_SET(err, -EOVERFLOW, -EINVAL);
}

int name_to_handle_at_loop(
                int fd,
                const char *path,
                struct file_handle **ret_handle,
                int *ret_mnt_id,
                int flags) {

        size_t n = ORIGINAL_MAX_HANDLE_SZ;

        assert(fd >= 0 || fd == AT_FDCWD);
        assert((flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH|AT_HANDLE_FID)) == 0);

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

                /* If name_to_handle_at() didn't increase the byte size, then this EOVERFLOW is caused by
                 * something else (apparently EOVERFLOW is returned for untriggered nfs4 autofs mounts
                 * sometimes), not by the too small buffer. In that case propagate EOVERFLOW */
                if (h->handle_bytes <= n)
                        return -EOVERFLOW;

                /* The buffer was too small. Size the new buffer by what name_to_handle_at() returned. */
                n = h->handle_bytes;

                /* paranoia: check for overflow (note that .handle_bytes is unsigned only) */
                if (n > UINT_MAX - offsetof(struct file_handle, f_handle))
                        return -EOVERFLOW;
        }
}

int name_to_handle_at_try_fid(
                int fd,
                const char *path,
                struct file_handle **ret_handle,
                int *ret_mnt_id,
                int flags) {

        int r;

        assert(fd >= 0 || fd == AT_FDCWD);

        /* First issues name_to_handle_at() with AT_HANDLE_FID. If this fails and this is not a fatal error
         * we'll try without the flag, in order to support older kernels that didn't have AT_HANDLE_FID
         * (i.e. older than Linux 6.5). */

        r = name_to_handle_at_loop(fd, path, ret_handle, ret_mnt_id, flags | AT_HANDLE_FID);
        if (r >= 0 || is_name_to_handle_at_fatal_error(r))
                return r;

        return name_to_handle_at_loop(fd, path, ret_handle, ret_mnt_id, flags & ~AT_HANDLE_FID);
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

bool file_handle_equal(const struct file_handle *a, const struct file_handle *b) {
        if (a == b)
                return true;
        if (!a != !b)
                return false;
        if (a->handle_type != b->handle_type)
                return false;

        return memcmp_nn(a->f_handle, a->handle_bytes, b->f_handle, b->handle_bytes) == 0;
}

int is_mount_point_at(int fd, const char *filename, int flags) {
        assert(fd >= 0 || fd == AT_FDCWD);
        assert((flags & ~AT_SYMLINK_FOLLOW) == 0);

        if (isempty(filename)) {
                if (fd == AT_FDCWD)
                        filename = ".";
                else {
                        /* If the file name is empty we'll see if the specified 'fd' is a mount point.
                         * That's only supported by statx(), or if the inode specified via 'fd' refers to a
                         * directory. Otherwise, we'll have to fail (ENOTDIR), because we have no kernel API
                         * to query the information we need. */
                        flags |= AT_EMPTY_PATH;
                        filename = "";
                }

        } else if (!STR_IN_SET(filename, ".", "./")) {
                /* Insist that the specified filename is actually a filename, and not a path, i.e. some inode
                 * further up or down the tree then immediately below the specified directory fd. */
                if (!filename_possibly_with_slash_suffix(filename))
                        return -EINVAL;
        }

        struct statx sx = {}; /* explicitly initialize the struct to make msan silent. */
        if (statx(fd, filename,
                  at_flags_normalize_nofollow(flags) |
                  AT_NO_AUTOMOUNT |            /* don't trigger automounts – mounts are a local concept, hence no need to trigger automounts to determine STATX_ATTR_MOUNT_ROOT */
                  AT_STATX_DONT_SYNC,          /* don't go to the network for this – for similar reasons */
                  STATX_TYPE,
                  &sx) < 0)
                return -errno;

        if (!FLAGS_SET(sx.stx_attributes_mask, STATX_ATTR_MOUNT_ROOT))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOSYS), "statx() does not provides STATX_ATTR_MOUNT_ROOT, running on an old kernel?");

        return FLAGS_SET(sx.stx_attributes, STATX_ATTR_MOUNT_ROOT);
}

/* flags can be AT_SYMLINK_FOLLOW or 0 */
int path_is_mount_point_full(const char *path, const char *root, int flags) {
        _cleanup_close_ int dfd = -EBADF;
        _cleanup_free_ char *fn = NULL;

        assert(path);
        assert((flags & ~AT_SYMLINK_FOLLOW) == 0);

        if (path_equal(path, "/"))
                return 1;

        /* we need to resolve symlinks manually, we can't just rely on is_mount_point_at() to do that for us;
         * if we have a structure like /bin -> /usr/bin/ and /usr is a mount point, then the parent that we
         * look at needs to be /usr, not /. */
        dfd = chase_and_open_parent(path, root,
                                    CHASE_TRAIL_SLASH|(FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? 0 : CHASE_NOFOLLOW),
                                    &fn);
        if (dfd < 0)
                return dfd;

        return is_mount_point_at(dfd, fn, flags);
}

int path_get_mnt_id_at(int dir_fd, const char *path, int *ret) {
        struct statx sx;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(ret);

        if (statx(dir_fd,
                  strempty(path),
                  (isempty(path) ? AT_EMPTY_PATH : AT_SYMLINK_NOFOLLOW) |
                  AT_NO_AUTOMOUNT |    /* don't trigger automounts, mnt_id is a local concept */
                  AT_STATX_DONT_SYNC,  /* don't go to the network, mnt_id is a local concept */
                  STATX_MNT_ID,
                  &sx) < 0)
                return -errno;

        if (!FLAGS_SET(sx.stx_mask, STATX_MNT_ID))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOSYS), "statx() does not support STATX_MNT_ID, running on an old kernel?");

        *ret = sx.stx_mnt_id;
        return 0;
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
        assert(fstype);

        const FilesystemSet *fs;
        FOREACH_ARGUMENT(fs,
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

const char* fstype_norecovery_option(const char *fstype) {
        int r;

        assert(fstype);

        /* Use a curated list as first check, to avoid calling fsopen() which might load kmods, which might
         * not be allowed in our MAC context. */
        if (STR_IN_SET(fstype, "ext3", "ext4", "xfs"))
                return "norecovery";

        /* btrfs dropped support for the "norecovery" option in 6.8
         * (https://github.com/torvalds/linux/commit/a1912f712188291f9d7d434fba155461f1ebef66) and replaced
         * it with rescue=nologreplay, so we check for the new name first and fall back to checking for the
         * old name if the new name doesn't work. */
        if (streq(fstype, "btrfs")) {
                r = mount_option_supported(fstype, "rescue=nologreplay", NULL);
                if (r == -EAGAIN) {
                        log_debug_errno(r, "Failed to check for btrfs 'rescue=nologreplay' option, assuming old kernel with 'norecovery': %m");
                        return "norecovery";
                }
                if (r < 0)
                        log_debug_errno(r, "Failed to check for btrfs 'rescue=nologreplay' option, assuming it is not supported: %m");
                if (r > 0)
                        return "rescue=nologreplay";
        }

        /* On new kernels we can just ask the kernel */
        return mount_option_supported(fstype, "norecovery", NULL) > 0 ? "norecovery" : NULL;
}

bool fstype_can_fmask_dmask(const char *fstype) {
        assert(fstype);

        /* Use a curated list as first check, to avoid calling fsopen() which might load kmods, which might
         * not be allowed in our MAC context. If we don't know ourselves, on new kernels we can just ask the
         * kernel. */
        return streq(fstype, "vfat") || (mount_option_supported(fstype, "fmask", "0177") > 0 && mount_option_supported(fstype, "dmask", "0077") > 0);
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

static int mount_fd(
                const char *source,
                int target_fd,
                const char *filesystemtype,
                unsigned long mountflags,
                const void *data) {

        assert(target_fd >= 0);

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

        assert(target);

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

const char* mount_propagation_flag_to_string(unsigned long flags) {

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
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open superblock context for '%s': %m", fstype);

        /* Various file systems support fs context only in recent kernels (e.g. btrfs). For older kernels
         * fsconfig() with FSCONFIG_SET_STRING/FSCONFIG_SET_FLAG never fail. Which sucks, because we want to
         * use it for testing support, after all. Let's hence do a check if the file system got converted yet
         * first. */
        if (fsconfig(fd, FSCONFIG_SET_FD, "adefinitelynotexistingmountoption", NULL, fd) < 0) {
                /* If FSCONFIG_SET_FD is not supported for the fs, then the file system was not converted to
                 * the new mount API yet. If it returns EINVAL the mount option doesn't exist, but the fstype
                 * is converted. */
                if (errno == EOPNOTSUPP)
                        return -EAGAIN; /* fs not converted to new mount API → don't know */
                if (errno != EINVAL)
                        return log_debug_errno(errno, "Failed to check if file system '%s' has been converted to new mount API: %m", fstype);

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

bool path_below_api_vfs(const char *p) {
        assert(p);

        /* API VFS are either directly mounted on any of these three paths, or below it. */
        return PATH_STARTSWITH_SET(p, "/dev", "/sys", "/proc");
}
