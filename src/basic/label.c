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

int label_fix_container(const char *path, const char *inside_path, LabelFixFlags flags) {
        int r, q;

        r = mac_selinux_fix_container(path, inside_path, flags);
        q = mac_smack_fix_container(path, inside_path, flags);

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

        if (symlink(old_path, new_path) < 0)
                r = -errno;

        mac_selinux_create_file_clear();

        if (r < 0)
                return r;

        return mac_smack_fix(new_path, 0);
}

int symlink_atomic_label(const char *from, const char *to) {
        int r;

        assert(from);
        assert(to);

        r = mac_selinux_create_file_prepare(to, S_IFLNK);
        if (r < 0)
                return r;

        if (symlink_atomic(from, to) < 0)
                r = -errno;

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

        if (mknod(pathname, mode, dev) < 0)
                r = -errno;

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
