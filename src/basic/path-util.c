/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fs-util.h"
#include "glob-util.h"
#include "log.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

bool is_path(const char *p) {
        if (!p) /* A NULL pointer is definitely not a path */
                return false;

        return strchr(p, '/');
}

int path_split_and_make_absolute(const char *p, char ***ret) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(p);
        assert(ret);

        l = strv_split(p, ":");
        if (!l)
                return -ENOMEM;

        r = path_strv_make_absolute_cwd(l);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(l);
        return r;
}

char* path_make_absolute(const char *p, const char *prefix) {
        assert(p);

        /* Makes every item in the list an absolute path by prepending
         * the prefix, if specified and necessary */

        if (path_is_absolute(p) || isempty(prefix))
                return strdup(p);

        return path_join(prefix, p);
}

int safe_getcwd(char **ret) {
        _cleanup_free_ char *cwd = NULL;

        cwd = get_current_dir_name();
        if (!cwd)
                return negative_errno();

        /* Let's make sure the directory is really absolute, to protect us from the logic behind
         * CVE-2018-1000001 */
        if (cwd[0] != '/')
                return -ENOMEDIUM;

        if (ret)
                *ret = TAKE_PTR(cwd);

        return 0;
}

int path_make_absolute_cwd(const char *p, char **ret) {
        char *c;
        int r;

        assert(p);
        assert(ret);

        /* Similar to path_make_absolute(), but prefixes with the
         * current working directory. */

        if (path_is_absolute(p))
                c = strdup(p);
        else {
                _cleanup_free_ char *cwd = NULL;

                r = safe_getcwd(&cwd);
                if (r < 0)
                        return r;

                c = path_join(cwd, p);
        }
        if (!c)
                return -ENOMEM;

        *ret = c;
        return 0;
}

int path_make_relative(const char *from, const char *to, char **ret) {
        _cleanup_free_ char *result = NULL;
        unsigned n_parents;
        const char *f, *t;
        int r, k;
        char *p;

        assert(from);
        assert(to);
        assert(ret);

        /* Strips the common part, and adds ".." elements as necessary. */

        if (!path_is_absolute(from) || !path_is_absolute(to))
                return -EINVAL;

        for (;;) {
                r = path_find_first_component(&from, true, &f);
                if (r < 0)
                        return r;

                k = path_find_first_component(&to, true, &t);
                if (k < 0)
                        return k;

                if (r == 0) {
                        /* end of 'from' */
                        if (k == 0) {
                                /* from and to are equivalent. */
                                result = strdup(".");
                                if (!result)
                                        return -ENOMEM;
                        } else {
                                /* 'to' is inside of 'from'. */
                                r = path_simplify_alloc(t, &result);
                                if (r < 0)
                                        return r;

                                if (!path_is_valid(result))
                                        return -EINVAL;
                        }

                        *ret = TAKE_PTR(result);
                        return 0;
                }

                if (r != k || !strneq(f, t, r))
                        break;
        }

        /* If we're here, then "from_dir" has one or more elements that need to
         * be replaced with "..". */

        for (n_parents = 1;; n_parents++) {
                /* If this includes ".." we can't do a simple series of "..". */
                r = path_find_first_component(&from, false, &f);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
        }

        if (isempty(t) && n_parents * 3 > PATH_MAX)
                /* PATH_MAX is counted *with* the trailing NUL byte */
                return -EINVAL;

        result = new(char, n_parents * 3 + !isempty(t) + strlen_ptr(t));
        if (!result)
                return -ENOMEM;

        for (p = result; n_parents > 0; n_parents--)
                p = mempcpy(p, "../", 3);

        if (isempty(t)) {
                /* Remove trailing slash and terminate string. */
                *(--p) = '\0';
                *ret = TAKE_PTR(result);
                return 0;
        }

        strcpy(p, t);

        path_simplify(result);

        if (!path_is_valid(result))
                return -EINVAL;

        *ret = TAKE_PTR(result);
        return 0;
}

int path_make_relative_parent(const char *from_child, const char *to, char **ret) {
        _cleanup_free_ char *from = NULL;
        int r;

        assert(from_child);
        assert(to);
        assert(ret);

        /* Similar to path_make_relative(), but provides the relative path from the parent directory of
         * 'from_child'. This may be useful when creating relative symlink.
         *
         * E.g.
         * - from = "/path/to/aaa", to = "/path/to/bbb"
         *      path_make_relative(from, to) = "../bbb"
         *      path_make_relative_parent(from, to) = "bbb"
         *
         * - from = "/path/to/aaa/bbb", to = "/path/to/ccc/ddd"
         *      path_make_relative(from, to) = "../../ccc/ddd"
         *      path_make_relative_parent(from, to) = "../ccc/ddd"
         */

        r = path_extract_directory(from_child, &from);
        if (r < 0)
                return r;

        return path_make_relative(from, to, ret);
}

char* path_startswith_strv(const char *p, char * const *strv) {
        assert(p);

        STRV_FOREACH(s, strv) {
                char *t;

                t = path_startswith(p, *s);
                if (t)
                        return t;
        }

        return NULL;
}

int path_strv_make_absolute_cwd(char **l) {
        int r;

        /* Goes through every item in the string list and makes it
         * absolute. This works in place and won't rollback any
         * changes on failure. */

        STRV_FOREACH(s, l) {
                char *t;

                r = path_make_absolute_cwd(*s, &t);
                if (r < 0)
                        return r;

                path_simplify(t);
                free_and_replace(*s, t);
        }

        return 0;
}

char** path_strv_resolve(char **l, const char *root) {
        unsigned k = 0;
        bool enomem = false;
        int r;

        if (strv_isempty(l))
                return l;

        /* Goes through every item in the string list and canonicalize
         * the path. This works in place and won't rollback any
         * changes on failure. */

        STRV_FOREACH(s, l) {
                _cleanup_free_ char *orig = NULL;
                char *t, *u;

                if (!path_is_absolute(*s)) {
                        free(*s);
                        continue;
                }

                if (root) {
                        orig = *s;
                        t = path_join(root, orig);
                        if (!t) {
                                enomem = true;
                                continue;
                        }
                } else
                        t = *s;

                r = chase(t, root, 0, &u, NULL);
                if (r == -ENOENT) {
                        if (root) {
                                u = TAKE_PTR(orig);
                                free(t);
                        } else
                                u = t;
                } else if (r < 0) {
                        free(t);

                        if (r == -ENOMEM)
                                enomem = true;

                        continue;
                } else if (root) {
                        char *x;

                        free(t);
                        x = path_startswith(u, root);
                        if (x) {
                                /* restore the slash if it was lost */
                                if (!startswith(x, "/"))
                                        *(--x) = '/';

                                t = strdup(x);
                                free(u);
                                if (!t) {
                                        enomem = true;
                                        continue;
                                }
                                u = t;
                        } else {
                                /* canonicalized path goes outside of
                                 * prefix, keep the original path instead */
                                free_and_replace(u, orig);
                        }
                } else
                        free(t);

                l[k++] = u;
        }

        l[k] = NULL;

        if (enomem)
                return NULL;

        return l;
}

char** path_strv_resolve_uniq(char **l, const char *root) {

        if (strv_isempty(l))
                return l;

        if (!path_strv_resolve(l, root))
                return NULL;

        return strv_uniq(l);
}

char* skip_leading_slash(const char *p) {
        return skip_leading_chars(p, "/");
}

char* path_simplify_full(char *path, PathSimplifyFlags flags) {
        bool add_slash = false, keep_trailing_slash, absolute, beginning = true;
        char *f = path;
        int r;

        /* Removes redundant inner and trailing slashes. Also removes unnecessary dots.
         * Modifies the passed string in-place.
         *
         * ///foo//./bar/.   becomes /foo/bar
         * .//./foo//./bar/. becomes foo/bar
         * /../foo/bar       becomes /foo/bar
         * /../foo/bar/..    becomes /foo/bar/..
         */

        if (isempty(path))
                return path;

        keep_trailing_slash = FLAGS_SET(flags, PATH_SIMPLIFY_KEEP_TRAILING_SLASH) && endswith(path, "/");

        absolute = path_is_absolute(path);
        f += absolute;  /* Keep leading /, if present. */

        for (const char *p = f;;) {
                const char *e;

                r = path_find_first_component(&p, true, &e);
                if (r == 0)
                        break;

                if (r > 0 && absolute && beginning && path_startswith(e, ".."))
                        /* If we're at the beginning of an absolute path, we can safely skip ".." */
                        continue;

                beginning = false;

                if (add_slash)
                        *f++ = '/';

                if (r < 0) {
                        /* if path is invalid, then refuse to simplify the remaining part. */
                        memmove(f, p, strlen(p) + 1);
                        return path;
                }

                memmove(f, e, r);
                f += r;

                add_slash = true;
        }

        /* Special rule, if we stripped everything, we need a "." for the current directory. */
        if (f == path)
                *f++ = '.';

        if (*(f-1) != '/' && keep_trailing_slash)
                *f++ = '/';

        *f = '\0';
        return path;
}

int path_simplify_alloc(const char *path, char **ret) {
        assert(ret);

        if (!path) {
                *ret = NULL;
                return 0;
        }

        char *t = strdup(path);
        if (!t)
                return -ENOMEM;

        *ret = path_simplify(t);
        return 0;
}

char* path_startswith_full(const char *original_path, const char *prefix, PathStartWithFlags flags) {
        assert(original_path);
        assert(prefix);

        /* Returns a pointer to the start of the first component after the parts matched by
         * the prefix, iff
         * - both paths are absolute or both paths are relative,
         * and
         * - each component in prefix in turn matches a component in path at the same position.
         * An empty string will be returned when the prefix and path are equivalent.
         *
         * Returns NULL otherwise.
         */

        const char *path = original_path;

        if ((path[0] == '/') != (prefix[0] == '/'))
                return NULL;

        for (;;) {
                const char *p, *q;
                int m, n;

                m = path_find_first_component(&path, !FLAGS_SET(flags, PATH_STARTSWITH_REFUSE_DOT_DOT), &p);
                if (m < 0)
                        return NULL;

                n = path_find_first_component(&prefix, !FLAGS_SET(flags, PATH_STARTSWITH_REFUSE_DOT_DOT), &q);
                if (n < 0)
                        return NULL;

                if (n == 0) {
                        if (!p)
                                p = path;

                        if (FLAGS_SET(flags, PATH_STARTSWITH_RETURN_LEADING_SLASH)) {

                                if (p <= original_path)
                                        return NULL;

                                p--;

                                if (*p != '/')
                                        return NULL;
                        }

                        return (char*) p;
                }

                if (m != n)
                        return NULL;

                if (!strneq(p, q, m))
                        return NULL;
        }
}

int path_compare(const char *a, const char *b) {
        int r;

        /* Order NULL before non-NULL */
        r = CMP(!!a, !!b);
        if (r != 0)
                return r;

        /* A relative path and an absolute path must not compare as equal.
         * Which one is sorted before the other does not really matter.
         * Here a relative path is ordered before an absolute path. */
        r = CMP(path_is_absolute(a), path_is_absolute(b));
        if (r != 0)
                return r;

        for (;;) {
                const char *aa, *bb;
                int j, k;

                j = path_find_first_component(&a, true, &aa);
                k = path_find_first_component(&b, true, &bb);

                if (j < 0 || k < 0) {
                        /* When one of paths is invalid, order invalid path after valid one. */
                        r = CMP(j < 0, k < 0);
                        if (r != 0)
                                return r;

                        /* fallback to use strcmp() if both paths are invalid. */
                        return strcmp(a, b);
                }

                /* Order prefixes first: "/foo" before "/foo/bar" */
                if (j == 0) {
                        if (k == 0)
                                return 0;
                        return -1;
                }
                if (k == 0)
                        return 1;

                /* Alphabetical sort: "/foo/aaa" before "/foo/b" */
                r = memcmp(aa, bb, MIN(j, k));
                if (r != 0)
                        return r;

                /* Sort "/foo/a" before "/foo/aaa" */
                r = CMP(j, k);
                if (r != 0)
                        return r;
        }
}

int path_compare_filename(const char *a, const char *b) {
        _cleanup_free_ char *fa = NULL, *fb = NULL;
        int r, j, k;

        /* Order NULL before non-NULL */
        r = CMP(!!a, !!b);
        if (r != 0)
                return r;

        j = path_extract_filename(a, &fa);
        k = path_extract_filename(b, &fb);

        /* When one of paths is "." or root, then order it earlier. */
        r = CMP(j != -EADDRNOTAVAIL, k != -EADDRNOTAVAIL);
        if (r != 0)
                return r;

        /* When one of paths is invalid (or we get OOM), order invalid path after valid one. */
        r = CMP(j < 0, k < 0);
        if (r != 0)
                return r;

        /* fallback to use strcmp() if both paths are invalid. */
        if (j < 0)
                return strcmp(a, b);

        return strcmp(fa, fb);
}

int path_equal_or_inode_same_full(const char *a, const char *b, int flags) {
        /* Returns true if paths are of the same entry, false if not, <0 on error. */

        if (path_equal(a, b))
                return 1;

        if (!a || !b)
                return 0;

        return inode_same(a, b, flags);
}

char* path_extend_internal(char **x, ...) {
        size_t sz, old_sz;
        char *q, *nx;
        const char *p;
        va_list ap;
        bool slash;

        /* Joins all listed strings until the sentinel and places a "/" between them unless the strings
         * end/begin already with one so that it is unnecessary. Note that slashes which are already
         * duplicate won't be removed. The string returned is hence always equal to or longer than the sum of
         * the lengths of the individual strings.
         *
         * The first argument may be an already allocated string that is extended via realloc() if
         * non-NULL. path_extend() and path_join() are macro wrappers around this function, making use of the
         * first parameter to distinguish the two operations.
         *
         * Note: any listed empty string is simply skipped. This can be useful for concatenating strings of
         * which some are optional.
         *
         * Examples:
         *
         * path_join("foo", "bar") → "foo/bar"
         * path_join("foo/", "bar") → "foo/bar"
         * path_join("", "foo", "", "bar", "") → "foo/bar" */

        sz = old_sz = x ? strlen_ptr(*x) : 0;
        va_start(ap, x);
        while ((p = va_arg(ap, char*)) != POINTER_MAX) {
                size_t add;

                if (isempty(p))
                        continue;

                add = 1 + strlen(p);
                if (sz > SIZE_MAX - add) { /* overflow check */
                        va_end(ap);
                        return NULL;
                }

                sz += add;
        }
        va_end(ap);

        nx = realloc(x ? *x : NULL, GREEDY_ALLOC_ROUND_UP(sz+1));
        if (!nx)
                return NULL;
        if (x)
                *x = nx;

        if (old_sz > 0)
                slash = nx[old_sz-1] == '/';
        else {
                nx[old_sz] = 0;
                slash = true; /* no need to generate a slash anymore */
        }

        q = nx + old_sz;

        va_start(ap, x);
        while ((p = va_arg(ap, char*)) != POINTER_MAX) {
                if (isempty(p))
                        continue;

                if (!slash && p[0] != '/')
                        *(q++) = '/';

                q = stpcpy(q, p);
                slash = endswith(p, "/");
        }
        va_end(ap);

        return nx;
}

int open_and_check_executable(const char *name, const char *root, char **ret_path, int *ret_fd) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *resolved = NULL;
        int r;

        assert(name);

        /* Function chase() is invoked only when root is not NULL, as using it regardless of
         * root value would alter the behavior of existing callers for example: /bin/sleep would become
         * /usr/bin/sleep when find_executables is called. Hence, this function should be invoked when
         * needed to avoid unforeseen regression or other complicated changes. */
        if (root) {
                /* prefix root to name in case full paths are not specified */
                r = chase(name, root, CHASE_PREFIX_ROOT, &resolved, &fd);
                if (r < 0)
                        return r;

                name = resolved;
        } else {
                /* We need to use O_PATH because there may be executables for which we have only exec permissions,
                 * but not read (usually suid executables). */
                fd = open(name, O_PATH|O_CLOEXEC);
                if (fd < 0)
                        return -errno;
        }

        r = fd_verify_regular(fd);
        if (r < 0)
                return r;

        r = access_fd(fd, X_OK);
        if (r == -ENOSYS)
                /* /proc/ is not mounted. Fall back to access(). */
                r = RET_NERRNO(access(name, X_OK));
        if (r < 0)
                return r;

        if (ret_path) {
                if (resolved)
                        *ret_path = TAKE_PTR(resolved);
                else {
                        r = path_make_absolute_cwd(name, ret_path);
                        if (r < 0)
                                return r;

                        path_simplify(*ret_path);
                }
        }

        if (ret_fd)
                *ret_fd = TAKE_FD(fd);

        return 0;
}

int find_executable_full(
                const char *name,
                const char *root,
                char * const *exec_search_path,
                bool use_path_envvar,
                char **ret_filename,
                int *ret_fd) {

        int last_error = -ENOENT, r = 0;

        assert(name);

        if (is_path(name))
                return open_and_check_executable(name, root, ret_filename, ret_fd);

        if (exec_search_path) {
                STRV_FOREACH(element, exec_search_path) {
                        _cleanup_free_ char *full_path = NULL;

                        if (!path_is_absolute(*element)) {
                                log_debug("Exec search path '%s' isn't absolute, ignoring.", *element);
                                continue;
                        }

                        full_path = path_join(*element, name);
                        if (!full_path)
                                return -ENOMEM;

                        r = open_and_check_executable(full_path, root, ret_filename, ret_fd);
                        if (r >= 0)
                                return 0;
                        if (r != -EACCES)
                                last_error = r;
                }
                return last_error;
        }

        const char *p = NULL;

        if (use_path_envvar)
                /* Plain getenv, not secure_getenv, because we want to actually allow the user to pick the
                 * binary. */
                p = getenv("PATH");
        if (!p)
                p = default_PATH();

        /* Resolve a single-component name to a full path */
        for (;;) {
                _cleanup_free_ char *element = NULL;

                r = extract_first_word(&p, &element, ":", EXTRACT_RELAX|EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (!path_is_absolute(element)) {
                        log_debug("Exec search path '%s' isn't absolute, ignoring.", element);
                        continue;
                }

                if (!path_extend(&element, name))
                        return -ENOMEM;

                r = open_and_check_executable(element, root, ret_filename, ret_fd);
                if (r >= 0) /* Found it! */
                        return 0;
                /* PATH entries which we don't have access to are ignored, as per tradition. */
                if (r != -EACCES)
                        last_error = r;
        }

        return last_error;
}

bool paths_check_timestamp(const char* const* paths, usec_t *timestamp, bool update) {
        bool changed = false, originally_unset;

        assert(timestamp);

        if (!paths)
                return false;

        originally_unset = *timestamp == 0;

        STRV_FOREACH(i, paths) {
                struct stat stats;
                usec_t u;

                if (stat(*i, &stats) < 0)
                        continue;

                u = timespec_load(&stats.st_mtim);

                /* check first */
                if (*timestamp >= u)
                        continue;

                log_debug(originally_unset ? "Loaded timestamp for '%s'." : "Timestamp of '%s' changed.", *i);

                /* update timestamp */
                if (update) {
                        *timestamp = u;
                        changed = true;
                } else
                        return true;
        }

        return changed;
}

static int executable_is_good(const char *executable) {
        _cleanup_free_ char *p = NULL, *d = NULL;
        int r;

        r = find_executable(executable, &p);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        /* An fsck that is linked to /bin/true is a non-existent fsck */

        r = readlink_malloc(p, &d);
        if (r == -EINVAL) /* not a symlink */
                return 1;
        if (r < 0)
                return r;

        return !PATH_IN_SET(d, "true"
                               "/bin/true",
                               "/usr/bin/true",
                               "/dev/null");
}

int fsck_exists(void) {
        return executable_is_good("fsck");
}

int fsck_exists_for_fstype(const char *fstype) {
        const char *checker;
        int r;

        assert(fstype);

        if (streq(fstype, "auto"))
                return -EINVAL;

        r = fsck_exists();
        if (r <= 0)
                return r;

        checker = strjoina("fsck.", fstype);
        return executable_is_good(checker);
}

static const char* skip_slash_or_dot(const char *p) {
        for (; !isempty(p); p++) {
                if (*p == '/')
                        continue;
                if (startswith(p, "./")) {
                        p++;
                        continue;
                }
                break;
        }
        return p;
}

int path_find_first_component(const char **p, bool accept_dot_dot, const char **ret) {
        const char *q, *first, *end_first, *next;
        size_t len;

        assert(p);

        /* When a path is input, then returns the pointer to the first component and its length, and
         * move the input pointer to the next component or nul. This skips both over any '/'
         * immediately *before* and *after* the first component before returning.
         *
         * Examples
         *   Input:  p: "//.//aaa///bbbbb/cc"
         *   Output: p: "bbbbb///cc"
         *           ret: "aaa///bbbbb/cc"
         *           return value: 3 (== strlen("aaa"))
         *
         *   Input:  p: "aaa//"
         *   Output: p: (pointer to NUL)
         *           ret: "aaa//"
         *           return value: 3 (== strlen("aaa"))
         *
         *   Input:  p: "/", ".", ""
         *   Output: p: (pointer to NUL)
         *           ret: NULL
         *           return value: 0
         *
         *   Input:  p: NULL
         *   Output: p: NULL
         *           ret: NULL
         *           return value: 0
         *
         *   Input:  p: "(too long component)"
         *   Output: return value: -EINVAL
         *
         *   (when accept_dot_dot is false)
         *   Input:  p: "//..//aaa///bbbbb/cc"
         *   Output: return value: -EINVAL
         */

        q = *p;

        first = skip_slash_or_dot(q);
        if (isempty(first)) {
                *p = first;
                if (ret)
                        *ret = NULL;
                return 0;
        }
        if (streq(first, ".")) {
                *p = first + 1;
                if (ret)
                        *ret = NULL;
                return 0;
        }

        end_first = strchrnul(first, '/');
        len = end_first - first;

        if (len > NAME_MAX)
                return -EINVAL;
        if (!accept_dot_dot && len == 2 && first[0] == '.' && first[1] == '.')
                return -EINVAL;

        next = skip_slash_or_dot(end_first);

        *p = next + streq(next, ".");
        if (ret)
                *ret = first;
        return len;
}

static const char* skip_slash_or_dot_backward(const char *path, const char *q) {
        assert(path);
        assert(!q || q >= path);

        for (; q; q = PTR_SUB1(q, path)) {
                if (*q == '/')
                        continue;
                if (q > path && strneq(q - 1, "/.", 2))
                        continue;
                if (q == path && *q == '.')
                        continue;
                break;
        }
        return q;
}

int path_find_last_component(const char *path, bool accept_dot_dot, const char **next, const char **ret) {
        const char *q, *last_end, *last_begin;
        size_t len;

        /* Similar to path_find_first_component(), but search components from the end.
        *
        * Examples
        *   Input:  path: "//.//aaa///bbbbb/cc//././"
        *           next: NULL
        *   Output: next: "/cc//././"
        *           ret: "cc//././"
        *           return value: 2 (== strlen("cc"))
        *
        *   Input:  path: "//.//aaa///bbbbb/cc//././"
        *           next: "/cc//././"
        *   Output: next: "///bbbbb/cc//././"
        *           ret: "bbbbb/cc//././"
        *           return value: 5 (== strlen("bbbbb"))
        *
        *   Input:  path: "//.//aaa///bbbbb/cc//././"
        *           next: "///bbbbb/cc//././"
        *   Output: next: "//.//aaa///bbbbb/cc//././" (next == path)
        *           ret: "aaa///bbbbb/cc//././"
        *           return value: 3 (== strlen("aaa"))
        *
        *   Input:  path: "/", ".", "", or NULL
        *   Output: next: equivalent to path
        *           ret: NULL
        *           return value: 0
        *
        *   Input:  path: "(too long component)"
        *   Output: return value: -EINVAL
        *
        *   (when accept_dot_dot is false)
        *   Input:  path: "//..//aaa///bbbbb/cc/..//"
        *   Output: return value: -EINVAL
        */

        if (isempty(path)) {
                if (next)
                        *next = path;
                if (ret)
                        *ret = NULL;
                return 0;
        }

        if (next && *next) {
                if (*next < path || *next > path + strlen(path))
                        return -EINVAL;
                if (*next == path) {
                        if (ret)
                                *ret = NULL;
                        return 0;
                }
                if (!IN_SET(**next, '\0', '/'))
                        return -EINVAL;
                q = *next - 1;
        } else
                q = path + strlen(path) - 1;

        q = skip_slash_or_dot_backward(path, q);
        if (!q) { /* the root directory, "." or "./" */
                if (next)
                        *next = path;
                if (ret)
                        *ret = NULL;
                return 0;
        }

        last_end = q + 1;

        while (q && *q != '/')
                q = PTR_SUB1(q, path);

        last_begin = q ? q + 1 : path;
        len = last_end - last_begin;

        if (len > NAME_MAX)
                return -EINVAL;
        if (!accept_dot_dot && len == 2 && strneq(last_begin, "..", 2))
                return -EINVAL;

        if (next) {
                q = skip_slash_or_dot_backward(path, q);
                *next = q ? q + 1 : path;
        }

        if (ret)
                *ret = last_begin;
        return len;
}

const char* last_path_component(const char *path) {

        /* Finds the last component of the path, preserving the optional trailing slash that signifies a directory.
         *
         *    a/b/c → c
         *    a/b/c/ → c/
         *    x → x
         *    x/ → x/
         *    /y → y
         *    /y/ → y/
         *    / → /
         *    // → /
         *    /foo/a → a
         *    /foo/a/ → a/
         *
         *    Also, the empty string is mapped to itself.
         *
         * This is different than basename(), which returns "" when a trailing slash is present.
         *
         * This always succeeds (except if you pass NULL in which case it returns NULL, too).
         */

        unsigned l, k;

        if (!path)
                return NULL;

        l = k = strlen(path);
        if (l == 0) /* special case — an empty string */
                return path;

        while (k > 0 && path[k-1] == '/')
                k--;

        if (k == 0) /* the root directory */
                return path + l - 1;

        while (k > 0 && path[k-1] != '/')
                k--;

        return path + k;
}

int path_split_prefix_filename(const char *path, char **ret_dir, char **ret_filename) {
        _cleanup_free_ char *d = NULL;
        const char *c, *next = NULL;
        int r;

        /* Split the path into dir prefix/filename pair. Returns:
         *
         * -EINVAL        → if the path is not valid
         * -EADDRNOTAVAIL → if the path refers to the uppermost directory in hierarchy (i.e. has neither
         *                  dir prefix nor filename - the root dir itself or ".")
         * -EDESTADDRREQ  → if only a filename was passed, and caller only specifies ret_dir
         * -ENOMEM        → no memory
         *
         * Returns >= 0 on success. If the input path has a trailing slash, returns O_DIRECTORY, to
         * indicate the referenced file must be a directory.
         *
         * This function guarantees to return a fully valid filename, i.e. one that passes
         * filename_is_valid() – this means "." and ".." are not accepted. */

        if (isempty(path))
                return -EINVAL;

        r = path_find_last_component(path, /* accept_dot_dot = */ false, &next, &c);
        if (r < 0)
                return r;
        if (r == 0) /* root directory or "." */
                return -EADDRNOTAVAIL;

        if (ret_dir) {
                if (next == path) {
                        if (*path != '/') { /* filename only */
                                if (!ret_filename)
                                        return -EDESTADDRREQ;
                        } else {
                                d = strdup("/");
                                if (!d)
                                        return -ENOMEM;
                        }
                } else {
                        d = strndup(path, next - path);
                        if (!d)
                                return -ENOMEM;

                        path_simplify(d);

                        if (!path_is_valid(d))
                                return -EINVAL;
                }

        } else if (!path_is_valid(path))
                /* We didn't validate the dir prefix, hence check if the whole path is valid now */
                return -EINVAL;

        if (ret_filename) {
                char *fn = strndup(c, r);
                if (!fn)
                        return -ENOMEM;

                *ret_filename = fn;
        }

        if (ret_dir)
                *ret_dir = TAKE_PTR(d);

        return strlen(c) > (size_t) r ? O_DIRECTORY : 0;
}

bool filename_part_is_valid(const char *p) {
        const char *e;

        /* Checks f the specified string is OK to be *part* of a filename. This is different from
         * filename_is_valid() as "." and ".." and "" are OK by this call, but not by filename_is_valid(). */

        if (!p)
                return false;

        e = strchrnul(p, '/');
        if (*e != 0)
                return false;

        if (e - p > NAME_MAX) /* NAME_MAX is counted *without* the trailing NUL byte */
                return false;

        return true;
}

bool filename_is_valid(const char *p) {

        if (isempty(p))
                return false;

        if (dot_or_dot_dot(p)) /* Yes, in this context we consider "." and ".." invalid */
                return false;

        return filename_part_is_valid(p);
}

bool path_is_valid_full(const char *p, bool accept_dot_dot) {
        if (isempty(p))
                return false;

        for (const char *e = p;;) {
                int r;

                r = path_find_first_component(&e, accept_dot_dot, NULL);
                if (r < 0)
                        return false;

                if (e - p >= PATH_MAX) /* Already reached the maximum length for a path? (PATH_MAX is counted
                                        * *with* the trailing NUL byte) */
                        return false;
                if (*e == 0)           /* End of string? Yay! */
                        return true;
        }
}

bool path_is_normalized(const char *p) {
        if (!path_is_safe(p))
                return false;

        if (streq(p, ".") || startswith(p, "./") || endswith(p, "/.") || strstr(p, "/./"))
                return false;

        if (strstr(p, "//"))
                return false;

        return true;
}

int file_in_same_dir(const char *path, const char *filename, char **ret) {
        _cleanup_free_ char *b = NULL;
        int r;

        assert(path);
        assert(filename);
        assert(ret);

        /* This removes the last component of path and appends filename, unless the latter is absolute anyway
         * or the former isn't */

        if (path_is_absolute(filename))
                b = strdup(filename);
        else {
                _cleanup_free_ char *dn = NULL;

                r = path_extract_directory(path, &dn);
                if (r == -EDESTADDRREQ) /* no path prefix */
                        b = strdup(filename);
                else if (r < 0)
                        return r;
                else
                        b = path_join(dn, filename);
        }
        if (!b)
                return -ENOMEM;

        *ret = TAKE_PTR(b);
        return 0;
}

bool hidden_or_backup_file(const char *filename) {
        assert(filename);

        if (filename[0] == '.' ||
            STR_IN_SET(filename,
                       "lost+found",
                       "aquota.user",
                       "aquota.group") ||
            endswith(filename, "~"))
                return true;

        const char *dot = strrchr(filename, '.');
        if (!dot)
                return false;

        /* Please, let's not add more entries to the list below. If external projects think it's a good idea
         * to come up with always new suffixes and that everybody else should just adjust to that, then it
         * really should be on them. Hence, in future, let's not add any more entries. Instead, let's ask
         * those packages to instead adopt one of the generic suffixes/prefixes for hidden files or backups,
         * possibly augmented with an additional string. Specifically: there's now:
         *
         *    The generic suffixes "~" and ".bak" for backup files
         *    The generic prefix "." for hidden files
         *
         * Thus, if a new package manager "foopkg" wants its own set of ".foopkg-new", ".foopkg-old",
         * ".foopkg-dist" or so registered, let's refuse that and ask them to use ".foopkg.new",
         * ".foopkg.old" or ".foopkg~" instead.
         */

        return STR_IN_SET(dot + 1,
                          "ignore",
                          "rpmnew",
                          "rpmsave",
                          "rpmorig",
                          "dpkg-old",
                          "dpkg-new",
                          "dpkg-tmp",
                          "dpkg-dist",
                          "dpkg-bak",
                          "dpkg-backup",
                          "dpkg-remove",
                          "ucf-new",
                          "ucf-old",
                          "ucf-dist",
                          "swp",
                          "bak",
                          "old",
                          "new");
}

bool is_device_path(const char *path) {

        /* Returns true for paths that likely refer to a device, either by path in sysfs or to something in
         * /dev. This accepts any path that starts with /dev/ or /sys/ and has something after that prefix.
         * It does not actually resolve the path.
         *
         * Examples:
         * /dev/sda, /dev/sda/foo, /sys/class, /dev/.., /sys/.., /./dev/foo → yes.
         * /../dev/sda, /dev, /sys, /usr/path, /usr/../dev/sda → no.
         */

        const char *p = PATH_STARTSWITH_SET(ASSERT_PTR(path), "/dev/", "/sys/");
        return !isempty(p);
}

bool valid_device_node_path(const char *path) {

        /* Some superficial checks whether the specified path is a valid device node path, all without
         * looking at the actual device node. */

        if (!PATH_STARTSWITH_SET(path, "/dev/", "/run/systemd/inaccessible/"))
                return false;

        if (endswith(path, "/")) /* can't be a device node if it ends in a slash */
                return false;

        return path_is_normalized(path);
}

bool valid_device_allow_pattern(const char *path) {
        assert(path);

        /* Like valid_device_node_path(), but also allows full-subsystem expressions like those accepted by
         * DeviceAllow= and DeviceDeny=. */

        if (STARTSWITH_SET(path, "block-", "char-"))
                return true;

        return valid_device_node_path(path);
}

bool dot_or_dot_dot(const char *path) {
        if (!path)
                return false;
        if (path[0] != '.')
                return false;
        if (path[1] == 0)
                return true;
        if (path[1] != '.')
                return false;

        return path[2] == 0;
}

bool path_implies_directory(const char *path) {

        /* Sometimes, if we look at a path we already know it must refer to a directory, because it is
         * suffixed with a slash, or its last component is "." or ".." */

        if (!path)
                return false;

        if (dot_or_dot_dot(path))
                return true;

        return ENDSWITH_SET(path, "/", "/.", "/..");
}

bool empty_or_root(const char *path) {

        /* For operations relative to some root directory, returns true if the specified root directory is
         * redundant, i.e. either / or NULL or the empty string or any equivalent. */

        if (isempty(path))
                return true;

        return path_equal(path, "/");
}

const char* empty_to_root(const char *path) {
        return isempty(path) ? "/" : path;
}

int empty_or_root_harder_to_null(const char **path) {
        int r;

        assert(path);

        /* This nullifies the input path when the path is empty or points to "/". */

        if (empty_or_root(*path)) {
                *path = NULL;
                return 0;
        }

        r = path_is_root(*path);
        if (r < 0)
                return r;
        if (r > 0)
                *path = NULL;

        return 0;
}

bool path_strv_contains(char * const *l, const char *path) {
        assert(path);

        STRV_FOREACH(i, l)
                if (path_equal(*i, path))
                        return true;

        return false;
}

bool prefixed_path_strv_contains(char * const *l, const char *path) {
        assert(path);

        STRV_FOREACH(i, l) {
                const char *j = *i;

                if (*j == '-')
                        j++;
                if (*j == '+')
                        j++;

                if (path_equal(j, path))
                        return true;
        }

        return false;
}

int path_glob_can_match(const char *pattern, const char *prefix, char **ret) {
        assert(pattern);
        assert(prefix);

        for (const char *a = pattern, *b = prefix;;) {
                _cleanup_free_ char *g = NULL, *h = NULL;
                const char *p, *q;
                int r, s;

                r = path_find_first_component(&a, /* accept_dot_dot= */ false, &p);
                if (r < 0)
                        return r;

                s = path_find_first_component(&b, /* accept_dot_dot= */ false, &q);
                if (s < 0)
                        return s;

                if (s == 0) {
                        /* The pattern matches the prefix. */
                        if (ret) {
                                char *t;

                                t = path_join(prefix, p);
                                if (!t)
                                        return -ENOMEM;

                                *ret = t;
                        }
                        return true;
                }

                if (r == 0)
                        break;

                if (r == s && strneq(p, q, r))
                        continue; /* common component. Check next. */

                g = strndup(p, r);
                if (!g)
                        return -ENOMEM;

                if (!string_is_glob(g))
                        break;

                /* We found a glob component. Check if the glob pattern matches the prefix component. */

                h = strndup(q, s);
                if (!h)
                        return -ENOMEM;

                r = fnmatch(g, h, 0);
                if (r == FNM_NOMATCH)
                        break;
                if (r != 0) /* Failure to process pattern? */
                        return -EINVAL;
        }

        /* The pattern does not match the prefix. */
        if (ret)
                *ret = NULL;
        return false;
}

#if HAVE_SPLIT_BIN
static bool dir_is_split(const char *a, const char *b) {
        int r;

        r = inode_same(a, b, AT_NO_AUTOMOUNT);
        if (r < 0 && r != -ENOENT) {
                log_debug_errno(r, "Failed to compare \"%s\" and \"%s\", assuming split directories: %m", a, b);
                return true;
        }
        return r == 0;
}
#endif

const char* default_PATH(void) {
#if HAVE_SPLIT_BIN
        static const char *default_path = NULL;

        /* Return one of the three sets of paths:
         * a) split /usr/s?bin, /usr/local/sbin doesn't matter.
         * b) merged /usr/s?bin, /usr/sbin is a symlink, but /usr/local/sbin is not,
         * c) fully merged, neither /usr/sbin nor /usr/local/sbin are symlinks,
         *
         * On error the fallback to the safe value with both directories as configured is returned.
         */

        if (default_path)
                return default_path;

        if (dir_is_split("/usr/sbin", "/usr/bin"))
                return (default_path = DEFAULT_PATH_WITH_FULL_SBIN);  /* a */
        if (dir_is_split("/usr/local/sbin", "/usr/local/bin"))
                return (default_path = DEFAULT_PATH_WITH_LOCAL_SBIN); /* b */
        return (default_path = DEFAULT_PATH_WITHOUT_SBIN);            /* c */
#else
        return DEFAULT_PATH_WITHOUT_SBIN;
#endif
}
