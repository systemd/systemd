/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "errno-util.h"
#include "label-util.h"         /* IWYU pragma: keep */
#include "mkdir.h"
#include "selinux-util.h"
#include "smack-util.h"

int mkdirat_label(int dirfd, const char *path, mode_t mode, LabelContext *label_context) {
        int r;

        assert(path);

        r = mac_selinux_create_file_prepare_at(dirfd, path, S_IFDIR, label_context);
        if (r < 0)
                return r;

        r = RET_NERRNO(mkdirat(dirfd, path, mode));
        mac_selinux_create_file_clear();
        if (r < 0)
                return r;

        return mac_smack_fix_full(dirfd, path, NULL, 0);
}

int mkdirat_safe_label(int dir_fd, const char *path, mode_t mode, uid_t uid, gid_t gid, MkdirFlags flags, LabelContext *label_context) {
        return mkdirat_safe_internal(dir_fd, path, mode, uid, gid, flags, mkdirat_label, label_context);
}

int mkdirat_parents_label(int dir_fd, const char *path, mode_t mode, LabelContext *label_context) {
        return mkdirat_parents_internal(dir_fd, path, mode, UID_INVALID, UID_INVALID, 0, mkdirat_label, label_context);
}
