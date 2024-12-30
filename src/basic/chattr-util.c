/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>

#include "bitfield.h"
#include "chattr-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "string-util.h"

int chattr_full(
              int dir_fd,
              const char *path,
              unsigned value,
              unsigned mask,
              unsigned *ret_previous,
              unsigned *ret_final,
              ChattrApplyFlags flags) {

        _cleanup_close_ int fd = -EBADF;
        unsigned old_attr, new_attr;
        int set_flags_errno = 0;
        struct stat st;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        fd = xopenat(dir_fd, path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return fd;

        if (fstat(fd, &st) < 0)
                return -errno;

        /* Explicitly check whether this is a regular file or directory. If it is anything else (such
         * as a device node or fifo), then the ioctl will not hit the file systems but possibly
         * drivers, where the ioctl might have different effects. Notably, DRM is using the same
         * ioctl() number. */

        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
                return -ENOTTY;

        if (mask == 0 && !ret_previous && !ret_final)
                return 0;

        if (ioctl(fd, FS_IOC_GETFLAGS, &old_attr) < 0)
                return -errno;

        new_attr = (old_attr & ~mask) | (value & mask);
        if (new_attr == old_attr) {
                if (ret_previous)
                        *ret_previous = old_attr;
                if (ret_final)
                        *ret_final = old_attr;
                return 0;
        }

        if (ioctl(fd, FS_IOC_SETFLAGS, &new_attr) >= 0) {
                unsigned attr;

                /* Some filesystems (BTRFS) silently fail when a flag cannot be set. Let's make sure our
                 * changes actually went through by querying the flags again and verifying they're equal to
                 * the flags we tried to configure. */

                if (ioctl(fd, FS_IOC_GETFLAGS, &attr) < 0)
                        return -errno;

                if (new_attr == attr) {
                        if (ret_previous)
                                *ret_previous = old_attr;
                        if (ret_final)
                                *ret_final = new_attr;
                        return 1;
                }

                /* Trigger the fallback logic. */
                errno = EINVAL;
        }

        if ((errno != EINVAL && !ERRNO_IS_NOT_SUPPORTED(errno)) ||
            !FLAGS_SET(flags, CHATTR_FALLBACK_BITWISE))
                return -errno;

        /* When -EINVAL is returned, we assume that incompatible attributes are simultaneously
         * specified. E.g., compress(c) and nocow(C) attributes cannot be set to files on btrfs.
         * As a fallback, let's try to set attributes one by one.
         *
         * Also, when we get EOPNOTSUPP (or a similar error code) we assume a flag might just not be
         * supported, and we can ignore it too */

        unsigned current_attr = old_attr;

        BIT_FOREACH(i, mask) {
                unsigned new_one, mask_one = 1u << i;

                new_one = UPDATE_FLAG(current_attr, mask_one, FLAGS_SET(value, mask_one));
                if (new_one == current_attr)
                        continue;

                if (ioctl(fd, FS_IOC_SETFLAGS, &new_one) < 0) {
                        if (!ERRNO_IS_IOCTL_NOT_SUPPORTED(errno))
                                return -errno;

                        log_full_errno(FLAGS_SET(flags, CHATTR_WARN_UNSUPPORTED_FLAGS) ? LOG_WARNING : LOG_DEBUG,
                                       errno,
                                       "Unable to set file attribute 0x%x on %s, ignoring: %m", mask_one, strna(path));

                        /* Ensures that we record whether only EOPNOTSUPP&friends are encountered, or if a more serious
                         * error (thus worth logging at a different level, etc) was seen too. */
                        if (set_flags_errno == 0 || !ERRNO_IS_NOT_SUPPORTED(errno))
                                set_flags_errno = -errno;

                        continue;
                }

                if (ioctl(fd, FS_IOC_GETFLAGS, &current_attr) < 0)
                        return -errno;
        }

        if (ret_previous)
                *ret_previous = old_attr;
        if (ret_final)
                *ret_final = current_attr;

        /* -ENOANO indicates that some attributes cannot be set. ERRNO_IS_NOT_SUPPORTED indicates that all
         * encountered failures were due to flags not supported by the FS, so return a specific error in
         * that case, so callers can handle it properly (e.g.: tmpfiles.d can use debug level logging). */
        return current_attr == new_attr ? 1 : ERRNO_IS_NOT_SUPPORTED(set_flags_errno) ? set_flags_errno : -ENOANO;
}

int read_attr_fd(int fd, unsigned *ret) {
        struct stat st;

        assert(fd >= 0);
        assert(ret);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
                return -ENOTTY;

        _cleanup_close_ int fd_close = -EBADF;
        fd = fd_reopen_condition(fd, O_RDONLY|O_CLOEXEC|O_NOCTTY, O_PATH, &fd_close); /* drop O_PATH if it is set */
        if (fd < 0)
                return fd;

        return RET_NERRNO(ioctl(fd, FS_IOC_GETFLAGS, ret));
}

int read_attr_at(int dir_fd, const char *path, unsigned *ret) {
        _cleanup_close_ int fd_close = -EBADF;
        int fd;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(ret);

        if (isempty(path) && dir_fd != AT_FDCWD)
                fd = dir_fd;
        else {
                fd_close = xopenat(dir_fd, path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
                if (fd_close < 0)
                        return fd_close;

                fd = fd_close;
        }

        return read_attr_fd(fd, ret);
}
