/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>

#include "btrfs-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "homework-quota.h"
#include "log.h"
#include "memory-util.h"
#include "quota-util.h"
#include "stat-util.h"
#include "user-record.h"
#include "user-util.h"

int home_update_quota_btrfs(UserRecord *h, int fd, const char *path) {
        int r;

        assert(h);
        assert(path);

        _cleanup_close_ int _fd = -EBADF;
        if (fd < 0) {
                _fd = open(path, O_CLOEXEC|O_RDONLY);
                if (_fd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", path);

                fd = _fd;
        }

        if (h->disk_size == UINT64_MAX)
                return 0;

        /* If the user wants quota, enable it */
        r = btrfs_quota_enable_fd(fd, true);
        if (r == -ENOTTY)
                return log_error_errno(r, "No btrfs quota support on subvolume %s.", path);
        if (r < 0)
                return log_error_errno(r, "Failed to enable btrfs quota support on %s.", path);

        r = btrfs_qgroup_set_limit_fd(fd, 0, h->disk_size);
        if (r < 0)
                return log_error_errno(r, "Failed to set disk quota on subvolume %s: %m", path);

        log_info("Set btrfs quota.");

        return 0;
}

int home_update_quota_classic(UserRecord *h, int fd, const char *path) {
        struct dqblk req;
        int r;

        assert(h);
        assert(uid_is_valid(h->uid));
        assert(path);

        _cleanup_close_ int _fd = -EBADF;
        if (fd < 0) {
                _fd = open(path, O_CLOEXEC|O_RDONLY);
                if (_fd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", path);

                fd = _fd;
        }

        if (h->disk_size == UINT64_MAX)
                return 0;

        r = quotactl_fd_with_fallback(fd, QCMD_FIXED(Q_GETQUOTA, USRQUOTA), h->uid, &req);
        if (r == -ESRCH)
                zero(req);
        else if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return log_error_errno(r, "No UID quota support on %s.", path);
        else if (r < 0)
                return log_error_errno(r, "Failed to query disk quota for UID " UID_FMT ": %m", h->uid);
        else if (FLAGS_SET(req.dqb_valid, QIF_BLIMITS) && h->disk_size / QIF_DQBLKSIZE == req.dqb_bhardlimit) {
                /* Shortcut things if everything is set up properly already */
                log_info("Configured quota already matches the intended setting, not updating quota.");
                return 0;
        }

        req.dqb_valid = QIF_BLIMITS;
        req.dqb_bsoftlimit = req.dqb_bhardlimit = h->disk_size / QIF_DQBLKSIZE;

        r = quotactl_fd_with_fallback(fd, QCMD_FIXED(Q_SETQUOTA, USRQUOTA), h->uid, &req);
        if (r == -ESRCH)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY), "UID quota not available on %s.", path);
        if (r < 0)
                return log_error_errno(r, "Failed to set disk quota for UID " UID_FMT ": %m", h->uid);

        log_info("Updated per-UID quota.");

        return 0;
}

int home_update_quota_auto(UserRecord *h, int fd, const char *path) {
        struct statfs sfs;
        int r;

        assert(h);

        if (h->disk_size == UINT64_MAX)
                return 0;

        if (!path) {
                path = user_record_image_path(h);
                if (!path)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Home record lacks image path.");
        }

        _cleanup_close_ int _fd = -EBADF;
        if (fd < 0) {
                _fd = open(path, O_CLOEXEC|O_RDONLY);
                if (_fd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", path);

                fd = _fd;
        }

        if (fstatfs(fd, &sfs) < 0)
                return log_error_errno(errno, "Failed to statfs() file system: %m");

        if (is_fs_type(&sfs, XFS_SUPER_MAGIC) ||
            is_fs_type(&sfs, EXT4_SUPER_MAGIC))
                return home_update_quota_classic(h, fd, path);

        if (is_fs_type(&sfs, BTRFS_SUPER_MAGIC)) {

                r = btrfs_is_subvol_fd(fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to test if %s is a subvolume: %m", path);
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTTY), "Directory %s is not a subvolume, cannot apply quota.", path);

                return home_update_quota_btrfs(h, fd, path);
        }

        return log_error_errno(SYNTHETIC_ERRNO(ENOTTY), "Type of directory %s not known, cannot apply quota.", path);
}
