/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "selinux-util.h"
#include "tmpfile-util-label.h"
#include "tmpfile-util.h"

int fopen_temporary_label(
                const char *target,
                const char *path,
                FILE **f,
                char **temp_path) {

        int r;

        r = mac_selinux_create_file_prepare(target, S_IFREG);
        if (r < 0)
                return r;

        r = fopen_temporary(path, f, temp_path);

        mac_selinux_create_file_clear();

        return r;
}
