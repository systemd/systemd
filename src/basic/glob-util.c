/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dirent.h>
#include <errno.h>
#include <glob.h>
#include <sys/types.h>

#include "dirent-util.h"
#include "glob-util.h"
#include "macro.h"
#include "path-util.h"
#include "strv.h"

static void closedir_wrapper(void* v) {
        (void) closedir(v);
}

int safe_glob(const char *path, int flags, glob_t *pglob) {
        int k;

        /* We want to set GLOB_ALTDIRFUNC ourselves, don't allow it to be set. */
        assert(!(flags & GLOB_ALTDIRFUNC));

        if (!pglob->gl_closedir)
                pglob->gl_closedir = closedir_wrapper;
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
