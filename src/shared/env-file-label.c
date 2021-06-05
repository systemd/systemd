/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "env-file-label.h"
#include "env-file.h"
#include "selinux-util.h"

int write_env_file_label(const char *fname, char **l) {
        int r;

        r = mac_selinux_create_file_prepare(fname, S_IFREG);
        if (r < 0)
                return r;

        r = write_env_file(fname, l);

        mac_selinux_create_file_clear();

        return r;
}
