/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "btrfs-util.h"
#include "fs-util.h"
#include "label.h"
#include "macro.h"
#include "selinux-util.h"
#include "smack-util.h"

int label_fix_full(
                int atfd,
                const char *inode_path, /* path of inode to apply label to */
                const char *label_path, /* path to use as database lookup key in label database (typically same as inode_path, but not always) */
                LabelFixFlags flags) {

        int r, q;

        if (atfd < 0 && atfd != AT_FDCWD)
                return -EBADF;

        if (!inode_path && atfd < 0) /* We need at least one of atfd and an inode path */
                return -EINVAL;

        /* If both atfd and inode_path are specified, we take the specified path relative to atfd which must be an fd to a dir.
         *
         * If only atfd is specified (and inode_path is NULL), we'll operated on the inode the atfd refers to.
         *
         * If atfd is AT_FDCWD then we'll operate on the inode the path refers to.
         */

        r = mac_selinux_fix_full(atfd, inode_path, label_path, flags);
        q = mac_smack_fix_full(atfd, inode_path, label_path, flags);
        if (r < 0)
                return r;
        if (q < 0)
                return q;

        return 0;
}

int symlink_label(const char *old_path, const char *new_path) {
        int r;

        assert(old_path);
        assert(new_path);

        r = mac_selinux_create_file_prepare(new_path, S_IFLNK);
        if (r < 0)
                return r;

        r = RET_NERRNO(symlink(old_path, new_path));
        mac_selinux_create_file_clear();

        if (r < 0)
                return r;

        return mac_smack_fix(new_path, 0);
}

int symlink_atomic_full_label(const char *from, const char *to, bool make_relative) {
        int r;

        assert(from);
        assert(to);

        r = mac_selinux_create_file_prepare(to, S_IFLNK);
        if (r < 0)
                return r;

        r = symlinkat_atomic_full(from, AT_FDCWD, to, make_relative);
        mac_selinux_create_file_clear();

        if (r < 0)
                return r;

        return mac_smack_fix(to, 0);
}

int mknod_label(const char *pathname, mode_t mode, dev_t dev) {
        int r;

        assert(pathname);

        r = mac_selinux_create_file_prepare(pathname, mode);
        if (r < 0)
                return r;

        r = RET_NERRNO(mknod(pathname, mode, dev));
        mac_selinux_create_file_clear();

        if (r < 0)
                return r;

        return mac_smack_fix(pathname, 0);
}

int btrfs_subvol_make_label(const char *path) {
        int r;

        assert(path);

        r = mac_selinux_create_file_prepare(path, S_IFDIR);
        if (r < 0)
                return r;

        r = btrfs_subvol_make(path);
        mac_selinux_create_file_clear();

        if (r < 0)
                return r;

        return mac_smack_fix(path, 0);
}
