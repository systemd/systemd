/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "mkdir-label.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "user-util.h"

int mkdirat_label(int dirfd, const char *path, mode_t mode) {
        int r;

        assert(path);

        r = mac_selinux_create_file_prepare_at(dirfd, path, S_IFDIR);
        if (r < 0)
                return r;

        r = mkdirat_errno_wrapper(dirfd, path, mode);
        mac_selinux_create_file_clear();
        if (r < 0)
                return r;

        return mac_smack_fix_at(dirfd, path, 0);
}

int mkdir_safe_label(const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdir_safe_internal(path, mode, uid, gid, flags, mkdirat_label);
}

int mkdir_parents_label(const char *path, mode_t mode) {
        return mkdir_parents_internal(NULL, path, mode, UID_INVALID, UID_INVALID, 0, mkdirat_label);
}

int mkdir_p_label(const char *path, mode_t mode) {
        return mkdir_p_internal(NULL, path, mode, UID_INVALID, UID_INVALID, 0, mkdirat_label);
}
