/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dirent-util.h"
#include "errno-util.h"
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
                return errno_or_else(EIO);
        if (strv_isempty(pglob->gl_pathv))
                return -ENOENT;

        return 0;
}

int glob_first(const char *path, char **ret_first) {
        _cleanup_globfree_ glob_t g = {};
        int k;

        assert(path);

        k = safe_glob(path, GLOB_NOSORT|GLOB_BRACE, &g);
        if (k == -ENOENT) {
                if (ret_first)
                        *ret_first = NULL;
                return false;
        }
        if (k < 0)
                return k;

        if (ret_first) {
                char *first = strdup(g.gl_pathv[0]);
                if (!first)
                        return log_oom_debug();
                *ret_first = first;
        }

        return true;
}

int glob_extend(char ***strv, const char *path, int flags) {
        _cleanup_globfree_ glob_t g = {};
        int k;

        k = safe_glob(path, GLOB_NOSORT|GLOB_BRACE|flags, &g);
        if (k < 0)
                return k;

        return strv_extend_strv(strv, g.gl_pathv, false);
}

int glob_non_glob_prefix(const char *path, char **ret) {
        /* Return the path of the path that has no glob characters. */

        size_t n = strcspn(path, GLOB_CHARS);

        if (path[n] != '\0')
                while (n > 0 && path[n-1] != '/')
                        n--;

        if (n == 0)
                return -ENOENT;

        char *ans = strndup(path, n);
        if (!ans)
                return -ENOMEM;
        *ret = ans;
        return 0;
}
