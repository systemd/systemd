/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010-2012 Lennart Poettering

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
#include <stdlib.h>
#include <unistd.h>

#include "util.h"
#include "label.h"
#include "path-util.h"
#include "dev-setup.h"

int dev_setup(const char *prefix, uid_t uid, gid_t gid) {
        static const char symlinks[] =
                "-/proc/kcore\0"     "/dev/core\0"
                "/proc/self/fd\0"    "/dev/fd\0"
                "/proc/self/fd/0\0"  "/dev/stdin\0"
                "/proc/self/fd/1\0"  "/dev/stdout\0"
                "/proc/self/fd/2\0"  "/dev/stderr\0";

        const char *j, *k;
        int r;

        NULSTR_FOREACH_PAIR(j, k, symlinks) {
                _cleanup_free_ char *link_name = NULL;
                const char *n;

                if (j[0] == '-') {
                        j++;

                        if (access(j, F_OK) < 0)
                                continue;
                }

                if (prefix) {
                        link_name = prefix_root(prefix, k);
                        if (!link_name)
                                return -ENOMEM;

                        n = link_name;
                } else
                        n = k;

                r = symlink_label(j, n);
                if (r < 0)
                        log_debug_errno(r, "Failed to symlink %s to %s: %m", j, n);

                if (uid != UID_INVALID || gid != GID_INVALID)
                        if (lchown(n, uid, gid) < 0)
                                log_debug_errno(errno, "Failed to chown %s: %m", n);
        }

        return 0;
}
