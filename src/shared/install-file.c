/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioctl.h>

#include "btrfs-util.h"
#include "chattr-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "install-file.h"
#include "missing_syscall.h"
#include "rm-rf.h"
#include "sync-util.h"

static int fs_make_very_read_only(int fd) {
        struct stat st;
        int r;

        assert(fd >= 0);

        /* Tries to make the specified fd "comprehensively" read-only. Primary use case for this is OS images,
         * i.e. either loopback files or larger directory hierarchies. Depending on the inode type and
         * backing file system this means something different:
         *
         * 1. If the fd refers to a btrfs subvolume we'll mark it read-only as a whole
         * 2. If the fd refers to any other directory we'll set the FS_IMMUTABLE_FL flag on it
         * 3. If the fd refers to a regular file we'll drop the w bits.
         * 4. If the fd refers to a block device, use BLKROSET to set read-only state
         *
         * You might wonder why not drop the x bits for directories. That's because we want to guarantee that
         * everything "inside" the image remains largely the way it is, in case you mount it. And since the
         * mode of the root dir of the image is pretty visible we don't want to modify it. btrfs subvol flags
         * and the FS_IMMUTABLE_FL otoh are much less visible. Changing the mode of regular files should be
         * OK though, since after all this is supposed to be used for disk images, i.e. the fs in the disk
         * image doesn't make the mode of the loopback file it is stored in visible. */

        if (fstat(fd, &st) < 0)
                return -errno;

        switch (st.st_mode & S_IFMT) {

        case S_IFDIR:
                if (btrfs_might_be_subvol(&st)) {
                        r = btrfs_subvol_set_read_only_fd(fd, true);
                        if (r >= 0)
                                return 0;
                        if (!ERRNO_IS_NEG_IOCTL_NOT_SUPPORTED(r))
                                return r;
                }

                r = chattr_fd(fd, FS_IMMUTABLE_FL, FS_IMMUTABLE_FL, NULL);
                if (r < 0)
                        return r;

                break;

        case S_IFREG:
                if ((st.st_mode & 0222) != 0)
                        if (fchmod(fd, st.st_mode & 07555) < 0)
                                return -errno;

                break;

        case S_IFBLK: {
                int ro = 1;

                if (ioctl(fd, BLKROSET, &ro) < 0)
                        return -errno;

                break;
        }

        default:
                return -EBADFD;
        }

        return 0;
}

static int unlinkat_maybe_dir(int dirfd, const char *pathname) {

        /* Invokes unlinkat() for regular files first, and if this fails with EISDIR tries again with
         * AT_REMOVEDIR */

        if (unlinkat(dirfd, pathname, 0) < 0) {
                if (errno != EISDIR)
                        return -errno;

                if (unlinkat(dirfd, pathname, AT_REMOVEDIR) < 0)
                        return -errno;
        }

        return 0;
}

int install_file(int source_atfd, const char *source_name,
                 int target_atfd, const char *target_name,
                 InstallFileFlags flags) {

        _cleanup_close_ int rofd = -EBADF;
        int r;

        /* Moves a file or directory tree into place, with some bells and whistles:
         *
         * 1. Optionally syncs before/after to ensure file installation can be used as barrier
         * 2. Optionally marks the file/directory read-only using fs_make_very_read_only()
         * 3. Optionally operates in replacing or in non-replacing mode.
         * 4. If it replaces will remove the old tree if needed.
         */

        assert(source_atfd >= 0 || source_atfd == AT_FDCWD);
        assert(source_name);
        assert(target_atfd >= 0 || target_atfd == AT_FDCWD);

        /* If target_name is specified as NULL no renaming takes place. Instead it is assumed the file is
         * already in place, and only the syncing/read-only marking shall be applied. Note that with
         * target_name=NULL and flags=0 this call is a NOP */

        if ((flags & (INSTALL_FSYNC|INSTALL_FSYNC_FULL|INSTALL_SYNCFS|INSTALL_READ_ONLY)) != 0) {
                _cleanup_close_ int pfd = -EBADF;
                struct stat st;

                /* Open an O_PATH fd for the source if we need to sync things or mark things read only. */

                pfd = openat(source_atfd, source_name, O_PATH|O_CLOEXEC|O_NOFOLLOW);
                if (pfd < 0)
                        return -errno;

                if (fstat(pfd, &st) < 0)
                        return -errno;

                switch (st.st_mode & S_IFMT) {

                case S_IFREG: {
                        _cleanup_close_ int regfd = -EBADF;

                        regfd = fd_reopen(pfd, O_RDONLY|O_CLOEXEC);
                        if (regfd < 0)
                                return regfd;

                        if ((flags & (INSTALL_FSYNC_FULL|INSTALL_SYNCFS)) != 0) {
                                /* If this is just a regular file (as oppose to a fully populated directory)
                                 * let's downgrade INSTALL_SYNCFS to INSTALL_FSYNC_FULL, after all this is
                                 * going to be a single inode we install */
                                r = fsync_full(regfd);
                                if (r < 0)
                                        return r;
                        } else if (flags & INSTALL_FSYNC) {
                                if (fsync(regfd) < 0)
                                        return -errno;
                        }

                        if (flags & INSTALL_READ_ONLY)
                                rofd = TAKE_FD(regfd);

                        break;
                }

                case S_IFDIR: {
                        _cleanup_close_ int dfd = -EBADF;

                        dfd = fd_reopen(pfd, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                        if (dfd < 0)
                                return dfd;

                        if (flags & INSTALL_SYNCFS) {
                                if (syncfs(dfd) < 0)
                                        return -errno;
                        } else if (flags & INSTALL_FSYNC_FULL) {
                                r = fsync_full(dfd);
                                if (r < 0)
                                        return r;
                        } else if (flags & INSTALL_FSYNC) {
                                if (fsync(dfd) < 0)
                                        return -errno;
                        }

                        if (flags & INSTALL_READ_ONLY)
                                rofd = TAKE_FD(dfd);

                        break;
                }

                default:
                        /* Other inodes: char/block device inodes, fifos, symlinks, sockets don't need
                         * syncing themselves, as they only exist in the directory, and have no contents on
                         * disk */

                        if (target_name && (flags & (INSTALL_FSYNC_FULL|INSTALL_SYNCFS)) != 0) {
                                r = fsync_directory_of_file(pfd);
                                if (r < 0)
                                        return r;
                        }

                        break;
                }
        }

        if (target_name) {
                /* Rename the file */

                if (flags & INSTALL_REPLACE) {
                        /* First, try a simple renamat(), maybe that's enough */
                        if (renameat(source_atfd, source_name, target_atfd, target_name) < 0) {
                                _cleanup_close_ int dfd = -EBADF;

                                if (!IN_SET(errno, EEXIST, ENOTDIR, ENOTEMPTY, EISDIR, EBUSY))
                                        return -errno;

                                /* Hmm, the target apparently existed already. Let's try to use
                                 * RENAME_EXCHANGE. But let's first open the inode if it's a directory, so
                                 * that we can later remove its contents if it's a directory. Why do this
                                 * before the rename()? Mostly because if we have trouble opening the thing
                                 * we want to know before we start actually modifying the file system. */

                                dfd = openat(target_atfd, target_name, O_RDONLY|O_DIRECTORY|O_CLOEXEC, 0);
                                if (dfd < 0 && errno != ENOTDIR)
                                        return -errno;

                                if (renameat2(source_atfd, source_name, target_atfd, target_name, RENAME_EXCHANGE) < 0) {

                                        if (!ERRNO_IS_NOT_SUPPORTED(errno) && errno != EINVAL)
                                                return -errno;

                                        /* The exchange didn't work, let's remove the target first, and try again */

                                        if (dfd >= 0)
                                                (void) rm_rf_children(TAKE_FD(dfd), REMOVE_PHYSICAL|REMOVE_SUBVOLUME|REMOVE_CHMOD, NULL);

                                        r = unlinkat_maybe_dir(target_atfd, target_name);
                                        if (r < 0)
                                                return log_debug_errno(r, "Failed to remove target directory: %m");

                                        if (renameat(source_atfd, source_name, target_atfd, target_name) < 0)
                                                return -errno;
                                } else {
                                        /* The exchange worked, hence let's remove the source (i.e. the old target) */
                                        if (dfd >= 0)
                                                (void) rm_rf_children(TAKE_FD(dfd), REMOVE_PHYSICAL|REMOVE_SUBVOLUME|REMOVE_CHMOD, NULL);

                                        r = unlinkat_maybe_dir(source_atfd, source_name);
                                        if (r < 0)
                                                return log_debug_errno(r, "Failed to remove replaced target directory: %m");
                                }
                        }
                } else {
                        r = rename_noreplace(source_atfd, source_name, target_atfd, target_name);
                        if (r < 0)
                                return r;
                }
        }

        if (rofd >= 0) {
                r = fs_make_very_read_only(rofd);
                if (r < 0)
                        return r;
        }

        if ((flags & (INSTALL_FSYNC_FULL|INSTALL_SYNCFS)) != 0) {
                if (target_name)
                        r = fsync_parent_at(target_atfd, target_name);
                else
                        r = fsync_parent_at(source_atfd, source_name);
                if (r < 0)
                        return r;
        }

        return 0;
}
