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

#include <dirent.h>
#include <errno.h>
#include <glob.h>
#include <sys/types.h>

#include "dirent-util.h"
#include "glob-util.h"
#include "macro.h"
#include "path-util.h"
#include "strv.h"

int safe_glob(const char *path, int flags, glob_t *pglob) {
        int k;

        /* We want to set GLOB_ALTDIRFUNC ourselves, don't allow it to be set. */
        assert(!(flags & GLOB_ALTDIRFUNC));

        if (!pglob->gl_closedir)
                pglob->gl_closedir = (void (*)(void *)) closedir;
        if (!pglob->gl_readdir)
                pglob->gl_readdir = (struct dirent *(*)(void *)) readdir_no_dot;
        if (!pglob->gl_opendir)
                pglob->gl_opendir = (void *(*)(const char *)) opendir;
        if (!pglob->gl_lstat)
                pglob->gl_lstat = lstat;
        if (!pglob->gl_stat)
                pglob->gl_stat = stat;

        errno = 0;
        k = glob(path, flags | GLOB_ALTDIRFUNC, NULL, pglob);

        if (k == GLOB_NOMATCH)
                return -ENOENT;
        if (k == GLOB_NOSPACE)
                return -ENOMEM;
        if (k != 0)
                return errno > 0 ? -errno : -EIO;
        if (strv_isempty(pglob->gl_pathv))
                return -ENOENT;

        return 0;
}

int glob_exists(const char *path) {
        _cleanup_globfree_ glob_t g = {};
        int k;

        assert(path);

        k = safe_glob(path, GLOB_NOSORT|GLOB_BRACE, &g);
        if (k == -ENOENT)
                return false;
        if (k < 0)
                return k;
        return true;
}

int glob_extend(char ***strv, const char *path) {
        _cleanup_globfree_ glob_t g = {};
        int k;

        k = safe_glob(path, GLOB_NOSORT|GLOB_BRACE, &g);
        if (k < 0)
                return k;

        return strv_extend_strv(strv, g.gl_pathv, false);
}
