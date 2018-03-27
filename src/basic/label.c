/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "btrfs-util.h"
#include "label.h"
#include "macro.h"
#include "selinux-util.h"
#include "smack-util.h"

int label_fix(const char *path, LabelFixFlags flags) {
        int r, q;

        r = mac_selinux_fix(path, flags);
        q = mac_smack_fix(path, flags);

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
