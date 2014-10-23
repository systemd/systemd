/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "label.h"
#include "util.h"

int label_fix(const char *path, bool ignore_enoent, bool ignore_erofs) {
        int r = 0;

        if (mac_selinux_use()) {
                r = mac_selinux_fix(path, ignore_enoent, ignore_erofs);
                if (r < 0)
                        return r;
        }

        if (mac_smack_use()) {
                r = mac_smack_relabel_in_dev(path);
                if (r < 0)
                        return r;
        }

        return r;
}
