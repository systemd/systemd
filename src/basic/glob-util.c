/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>
#include <sys/stat.h>

#include "dirent-util.h"
#include "errno-util.h"
#include "glob-util.h"
#include "string-util.h"
#include "strv.h"

static bool safe_glob_verify(const char *p, const char *prefix) {
        if (isempty(p))
                return false; /* should not happen, but for safey. */

        if (prefix) {
                /* Skip the prefix, as we allow dots in prefix.
                 * Note, glob() does not normalize paths, hence do not use path_startswith(). */
                p = startswith(p, prefix);
                if (!p)
                        return false; /* should not happen, but for safety. */
        }

        for (;;) {
                p += strspn(p, "/");
                if (*p == '\0')
                        return true;
                if (*p == '.') {
                        p++;
                        if (IN_SET(*p, '/', '\0'))
                                return false; /* refuse dot */
                        if (*p == '.') {
                                p++;
                                if (IN_SET(*p, '/', '\0'))
                                        return false; /* refuse dot dot */
                        }
                }

                p += strcspn(p, "/");
                if (*p == '\0')
                        return true;
        }
}

DEFINE_TRIVIAL_DESTRUCTOR(closedir_wrapper, void, closedir);

int safe_glob_internal(const char *path, int flags, bool use_gnu_extension, opendir_t opendir_func, char ***ret) {
        _cleanup_(globfree) glob_t g = {
                .gl_closedir = closedir_wrapper,
                .gl_readdir = (struct dirent* (*)(void *)) readdir_no_dot,
                .gl_opendir = (void* (*)(const char *)) (opendir_func ?: opendir),
                .gl_lstat = lstat,
                .gl_stat = stat,
        };
        int r;

        assert(path);

        // TODO: expand braces if GLOB_BRACE is specified but not supported.

#if GLOB_ALTDIRFUNC == 0
        use_gnu_extension = false;
#else
        SET_FLAG(flags, GLOB_ALTDIRFUNC, use_gnu_extension);
#endif

        errno = 0;
        r = glob(path, flags, NULL, &g);
        if (r == GLOB_NOMATCH)
                return -ENOENT;
        if (r == GLOB_NOSPACE)
                return -ENOMEM;
        if (r != 0)
                return errno_or_else(EIO);

        if (!use_gnu_extension) {
                _cleanup_free_ char *prefix = NULL;
                r = glob_non_glob_prefix(path, &prefix);
                if (r < 0 && r != -ENOENT)
                        return r;

                _cleanup_strv_free_ char **filtered = NULL;
                size_t n_filtered = 0;
                STRV_FOREACH(p, g.gl_pathv) {
                        if (!safe_glob_verify(*p, prefix))
                                continue;

                        if (!ret)
                                return 0; /* Found at least one entry, let's return earlier. */

                        /* When musl is used, each entry is not a head of allocated memory. Hence, it is
                         * necessary to copy the string. */
                        r = strv_extend_with_size(&filtered, &n_filtered, *p);
                        if (r < 0)
                                return r;
                }

                if (n_filtered == 0)
                        return -ENOENT;

                assert(ret);
                *ret = TAKE_PTR(filtered);
                return 0;
        }

        if (strv_isempty(g.gl_pathv))
                return -ENOENT;

        if (ret) {
                *ret = g.gl_pathv;
                TAKE_STRUCT(g); /* To avoid the result being freed. */
        }

        return 0;
}

int glob_first(const char *path, char **ret) {
        _cleanup_strv_free_ char **v = NULL;
        int r;

        assert(path);

        r = safe_glob(path, GLOB_NOSORT|GLOB_BRACE, &v);
        if (r == -ENOENT) {
                if (ret)
                        *ret = NULL;
                return false;
        }
        if (r < 0)
                return r;

        assert(!strv_isempty(v));

        if (ret) {
                /* Free all results except for the first one. */
                STRV_FOREACH(p, strv_skip(v, 1))
                        *p = mfree(*p);

                /* Then, take the first result. */
                *ret = TAKE_PTR(*v);
        }

        return true;
}

int glob_extend(char ***strv, const char *path, int flags) {
        char **v;
        int r;

        assert(path);

        r = safe_glob(path, GLOB_NOSORT|GLOB_BRACE|flags, &v);
        if (r < 0)
                return r;

        return strv_extend_strv_consume(strv, v, /* filter_duplicates = */ false);
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

bool string_is_glob(const char *p) {
        /* Check if a string contains any glob patterns. */
        return !!strpbrk(p, GLOB_CHARS);
}
