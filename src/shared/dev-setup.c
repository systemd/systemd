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
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "dev-setup.h"
#include "log.h"
#include "macro.h"
#include "util.h"
#include "label.h"

static int symlink_and_label(const char *old_path, const char *new_path) {
        int r;

        assert(old_path);
        assert(new_path);

        r = label_context_set(new_path, S_IFLNK);
        if (r < 0)
                return r;

        if (symlink(old_path, new_path) < 0)
                r = -errno;

        label_context_clear();

        return r;
}

int dev_setup(const char *prefix) {
        const char *j, *k;

        static const char symlinks[] =
                "-/proc/kcore\0"     "/dev/core\0"
                "/proc/self/fd\0"    "/dev/fd\0"
                "/proc/self/fd/0\0"  "/dev/stdin\0"
                "/proc/self/fd/1\0"  "/dev/stdout\0"
                "/proc/self/fd/2\0"  "/dev/stderr\0";

        NULSTR_FOREACH_PAIR(j, k, symlinks) {
                if (j[0] == '-') {
                        j++;

                        if (access(j, F_OK) < 0)
                                continue;
                }

                if (prefix) {
                        _cleanup_free_ char *link_name = NULL;

                        link_name = strjoin(prefix, "/", k, NULL);
                        if (!link_name)
                                return -ENOMEM;

                        symlink_and_label(j, link_name);
                } else
                        symlink_and_label(j, k);
        }

        return 0;
}
