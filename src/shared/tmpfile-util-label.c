/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "selinux-util.h"
#include "tmpfile-util.h"
#include "tmpfile-util-label.h"

int fopen_temporary_at_label(
                int dir_fd,
                const char *target,
                const char *path,
                FILE **f,
                char **temp_path) {

        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(path);

        r = mac_selinux_create_file_prepare_at(dir_fd, target, S_IFREG);
        if (r < 0)
                return r;

        r = fopen_temporary_at(dir_fd, path, f, temp_path);

        mac_selinux_create_file_clear();

        return r;
}
