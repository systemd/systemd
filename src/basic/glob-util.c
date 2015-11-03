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

#include <glob.h>

#include "glob-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

int glob_exists(const char *path) {
        _cleanup_globfree_ glob_t g = {};
        int k;

        assert(path);

        errno = 0;
        k = glob(path, GLOB_NOSORT|GLOB_BRACE, NULL, &g);

        if (k == GLOB_NOMATCH)
                return 0;
        if (k == GLOB_NOSPACE)
                return -ENOMEM;
        if (k != 0)
                return errno ? -errno : -EIO;

        return !strv_isempty(g.gl_pathv);
}

int glob_extend(char ***strv, const char *path) {
        _cleanup_globfree_ glob_t g = {};
        int k;
        char **p;

        errno = 0;
        k = glob(path, GLOB_NOSORT|GLOB_BRACE, NULL, &g);

        if (k == GLOB_NOMATCH)
                return -ENOENT;
        if (k == GLOB_NOSPACE)
                return -ENOMEM;
        if (k != 0)
                return errno ? -errno : -EIO;
        if (strv_isempty(g.gl_pathv))
                return -ENOENT;

        STRV_FOREACH(p, g.gl_pathv) {
                k = strv_extend(strv, *p);
                if (k < 0)
                        return k;
        }

        return 0;
}
