/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "errno-util.h"
#include "label-util.h"
#include "mkdir-label.h"
#include "selinux-util.h"
#include "smack-util.h"

int mkdirat_label(int dirfd, const char *path, mode_t mode) {
        int r;

        assert(path);

        r = mac_selinux_create_file_prepare_at(dirfd, path, S_IFDIR);
        if (r < 0)
                return r;

        r = RET_NERRNO(mkdirat(dirfd, path, mode));
        mac_selinux_create_file_clear();
        if (r < 0)
                return r;

        return mac_smack_fix_full(dirfd, path, NULL, 0);
}

int mkdirat_safe_label(int dir_fd, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdirat_safe_internal(dir_fd, path, mode, uid, gid, flags, mkdirat_label);
}

int mkdirat_parents_label(int dir_fd, const char *path, mode_t mode) {
        return mkdirat_parents_internal(dir_fd, path, mode, UID_INVALID, UID_INVALID, 0, mkdirat_label);
}

int mkdir_parents_safe_label(const char *prefix, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags) {
        return mkdir_parents_internal(prefix, path, mode, uid, gid, flags, mkdirat_label);
}

int mkdir_p_label(const char *path, mode_t mode) {
        return mkdir_p_internal(NULL, path, mode, UID_INVALID, UID_INVALID, 0, mkdirat_label);
}
