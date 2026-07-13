/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "btrfs-util.h"
#include "errno-util.h"
#include "label-util.h"
#include "path-util.h"
#include "selinux-util.h"
#include "smack-util.h"

int label_fix_full(
                int atfd,
                const char *inode_path, /* path of inode to apply label to */
                const char *label_path, /* path to use as database lookup key in label database (typically same as inode_path, but not always) */
                LabelFixFlags flags,
                LabelContext *label_userdata) {

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

        r = mac_selinux_fix_full(atfd, inode_path, label_path, flags, label_userdata);
        q = mac_smack_fix_full(atfd, inode_path, label_path, flags);
        if (r < 0)
                return r;
        if (q < 0)
                return q;

        return 0;
}

int symlink_label(const char *old_path, const char *new_path, LabelContext *label_userdata) {
        int r;

        assert(old_path);
        assert(new_path);

        r = mac_selinux_create_file_prepare(new_path, S_IFLNK, label_userdata);
        if (r < 0)
                return r;

        r = RET_NERRNO(symlink(old_path, new_path));
        mac_selinux_create_file_clear();

        if (r < 0)
                return r;

        return mac_smack_fix(new_path, 0);
}

int mknodat_label(int dirfd, const char *pathname, mode_t mode, dev_t dev, LabelContext *label_userdata) {
        int r;

        assert(dirfd >= 0 || dirfd == AT_FDCWD);
        assert(pathname);

        r = mac_selinux_create_file_prepare_at(dirfd, pathname, mode, label_userdata);
        if (r < 0)
                return r;

        r = RET_NERRNO(mknodat(dirfd, pathname, mode, dev));
        mac_selinux_create_file_clear();

        if (r < 0)
                return r;

        return mac_smack_fix_full(dirfd, pathname, NULL, 0);
}

int btrfs_subvol_make_label(const char *path, LabelContext *label_userdata) {
        int r;

        assert(path);

        r = mac_selinux_create_file_prepare(path, S_IFDIR, label_userdata);
        if (r < 0)
                return r;

        r = btrfs_subvol_make(AT_FDCWD, path);
        mac_selinux_create_file_clear();

        if (r < 0)
                return r;

        return mac_smack_fix(path, 0);
}

int mac_label_context_new(const char *root, LabelContext **ret) {
        assert(ret);

        if (empty_or_root(root)) {
                *ret = NULL;
                return 0;
        }

        if (mac_smack_use()) {
                *ret = NULL;
                return 0;
        }

        return mac_selinux_label_context_new(root, ret);
}

LabelContext* mac_label_context_free(LabelContext *c) {
        return mac_selinux_label_context_free(c);
}

static int init_internal(bool lazy) {
        int r;

        assert(!(mac_selinux_use() && mac_smack_use()));

        if (lazy)
                r = mac_selinux_init_lazy();
        else
                r = mac_selinux_init();
        if (r < 0)
                return r;

        return mac_smack_init();
}

int mac_init_lazy(void) {
        return init_internal(/* lazy= */ true);
}

int mac_init(void) {
        return init_internal(/* lazy= */ false);
}
