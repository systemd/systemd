/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* When we include libgen.h because we need dirname() we immediately
 * undefine basename() since libgen.h defines it as a macro to the
 * POSIX version which is really broken. We prefer GNU basename(). */
#include <libgen.h>
#undef basename

#include "alloc-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fs-util.h"
#include "glob-util.h"
#include "log.h"
#include "macro.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "utf8.h"

int path_split_and_make_absolute(const char *p, char ***ret) {
        char **l;
        int r;

        assert(p);
        assert(ret);

        l = strv_split(p, ":");
        if (!l)
                return -ENOMEM;

        r = path_strv_make_absolute_cwd(l);
        if (r < 0) {
                strv_free(l);
                return r;
        }

        *ret = l;
        return r;
}

char *path_make_absolute(const char *p, const char *prefix) {
        assert(p);

        /* Makes every item in the list an absolute path by prepending
         * the prefix, if specified and necessary */

        if (path_is_absolute(p) || isempty(prefix))
                return strdup(p);

        return path_join(prefix, p);
}

int safe_getcwd(char **ret) {
        char *cwd;

        cwd = get_current_dir_name();
        if (!cwd)
                return negative_errno();

        /* Let's make sure the directory is really absolute, to protect us from the logic behind
         * CVE-2018-1000001 */
        if (cwd[0] != '/') {
                free(cwd);
                return -ENOMEDIUM;
        }

        *ret = cwd;
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
                                result = strdup(t);
                                if (!result)
                                        return -ENOMEM;

                                path_simplify(result);

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

char* path_startswith_strv(const char *p, char **set) {
        char **s, *t;

        STRV_FOREACH(s, set) {
                t = path_startswith(p, *s);
                if (t)
                        return t;
        }

        return NULL;
}

int path_strv_make_absolute_cwd(char **l) {
        char **s;
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

char **path_strv_resolve(char **l, const char *root) {
        char **s;
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

                r = chase_symlinks(t, root, 0, &u, NULL);
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

char **path_strv_resolve_uniq(char **l, const char *root) {

        if (strv_isempty(l))
                return l;

        if (!path_strv_resolve(l, root))
                return NULL;

        return strv_uniq(l);
}

char *path_simplify(char *path) {
        bool add_slash = false;
        char *f = path;
        int r;

        assert(path);

        /* Removes redundant inner and trailing slashes. Also removes unnecessary dots.
         * Modifies the passed string in-place.
         *
         * ///foo//./bar/.   becomes /foo/bar
         * .//./foo//./bar/. becomes foo/bar
         */

        if (isempty(path))
                return path;

        if (path_is_absolute(path))
                f++;

        for (const char *p = f;;) {
                const char *e;

                r = path_find_first_component(&p, true, &e);
                if (r == 0)
                        break;

                if (add_slash)
                        *f++ = '/';

                if (r < 0) {
                        /* if path is invalid, then refuse to simplify remaining part. */
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

        *f = '\0';
        return path;
}

int path_simplify_and_warn(
                char *path,
                unsigned flag,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue) {

        bool fatal = flag & PATH_CHECK_FATAL;

        assert(!FLAGS_SET(flag, PATH_CHECK_ABSOLUTE | PATH_CHECK_RELATIVE));

        if (!utf8_is_valid(path))
                return log_syntax_invalid_utf8(unit, LOG_ERR, filename, line, path);

        if (flag & (PATH_CHECK_ABSOLUTE | PATH_CHECK_RELATIVE)) {
                bool absolute;

                absolute = path_is_absolute(path);

                if (!absolute && (flag & PATH_CHECK_ABSOLUTE))
                        return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                          "%s= path is not absolute%s: %s",
                                          lvalue, fatal ? "" : ", ignoring", path);

                if (absolute && (flag & PATH_CHECK_RELATIVE))
                        return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                          "%s= path is absolute%s: %s",
                                          lvalue, fatal ? "" : ", ignoring", path);
        }

        path_simplify(path);

        if (!path_is_valid(path))
                return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                  "%s= path has invalid length (%zu bytes)%s.",
                                  lvalue, strlen(path), fatal ? "" : ", ignoring");

        if (!path_is_normalized(path))
                return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                  "%s= path is not normalized%s: %s",
                                  lvalue, fatal ? "" : ", ignoring", path);

        return 0;
}

char *path_startswith_full(const char *path, const char *prefix, bool accept_dot_dot) {
        assert(path);
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

        if ((path[0] == '/') != (prefix[0] == '/'))
                return NULL;

        for (;;) {
                const char *p, *q;
                int r, k;

                r = path_find_first_component(&path, accept_dot_dot, &p);
                if (r < 0)
                        return NULL;

                k = path_find_first_component(&prefix, accept_dot_dot, &q);
                if (k < 0)
                        return NULL;

                if (k == 0)
                        return (char*) (p ?: path);

                if (r != k)
                        return NULL;

                if (!strneq(p, q, r))
                        return NULL;
        }
}

int path_compare(const char *a, const char *b) {
        int r;

        assert(a);
        assert(b);

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

bool path_equal_or_files_same(const char *a, const char *b, int flags) {
        return path_equal(a, b) || files_same(a, b, flags) > 0;
}

bool path_equal_filename(const char *a, const char *b) {
        _cleanup_free_ char *a_basename = NULL, *b_basename = NULL;
        int r;

        assert(a);
        assert(b);

        r = path_extract_filename(a, &a_basename);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse basename of %s: %m", a);
                return false;
        }
        r = path_extract_filename(b, &b_basename);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse basename of %s: %m", b);
                return false;
        }

        return path_equal(a_basename, b_basename);
}

char* path_extend_internal(char **x, ...) {
        size_t sz, old_sz;
        char *q, *nx;
        const char *p;
        va_list ap;
        bool slash;

        /* Joins all listed strings until the sentinel and places a "/" between them unless the strings end/begin
         * already with one so that it is unnecessary. Note that slashes which are already duplicate won't be
         * removed. The string returned is hence always equal to or longer than the sum of the lengths of each
         * individual string.
         *
         * The first argument may be an already allocated string that is extended via realloc() if
         * non-NULL. path_extend() and path_join() are macro wrappers around this function, making use of the
         * first parameter to distinguish the two operations.
         *
         * Note: any listed empty string is simply skipped. This can be useful for concatenating strings of which some
         * are optional.
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

static int check_x_access(const char *path, int *ret_fd) {
        _cleanup_close_ int fd = -1;
        int r;

        /* We need to use O_PATH because there may be executables for which we have only exec
         * permissions, but not read (usually suid executables). */
        fd = open(path, O_PATH|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        r = fd_verify_regular(fd);
        if (r < 0)
                return r;

        r = access_fd(fd, X_OK);
        if (r == -ENOSYS) {
                /* /proc is not mounted. Fallback to access(). */
                if (access(path, X_OK) < 0)
                        return -errno;
        } else if (r < 0)
                return r;

        if (ret_fd)
                *ret_fd = TAKE_FD(fd);

        return 0;
}

int find_executable_full(const char *name, bool use_path_envvar, char **ret_filename, int *ret_fd) {
        int last_error, r;
        const char *p = NULL;

        assert(name);

        if (is_path(name)) {
                _cleanup_close_ int fd = -1;

                r = check_x_access(name, ret_fd ? &fd : NULL);
                if (r < 0)
                        return r;

                if (ret_filename) {
                        r = path_make_absolute_cwd(name, ret_filename);
                        if (r < 0)
                                return r;
                }

                if (ret_fd)
                        *ret_fd = TAKE_FD(fd);

                return 0;
        }

        if (use_path_envvar)
                /* Plain getenv, not secure_getenv, because we want to actually allow the user to pick the
                 * binary. */
                p = getenv("PATH");
        if (!p)
                p = DEFAULT_PATH;

        last_error = -ENOENT;

        /* Resolve a single-component name to a full path */
        for (;;) {
                _cleanup_free_ char *element = NULL;
                _cleanup_close_ int fd = -1;

                r = extract_first_word(&p, &element, ":", EXTRACT_RELAX|EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (!path_is_absolute(element))
                        continue;

                if (!path_extend(&element, name))
                        return -ENOMEM;

                r = check_x_access(element, ret_fd ? &fd : NULL);
                if (r < 0) {
                        /* PATH entries which we don't have access to are ignored, as per tradition. */
                        if (r != -EACCES)
                                last_error = r;
                        continue;
                }

                /* Found it! */
                if (ret_filename)
                        *ret_filename = path_simplify(TAKE_PTR(element));
                if (ret_fd)
                        *ret_fd = TAKE_FD(fd);

                return 0;
        }

        return last_error;
}

bool paths_check_timestamp(const char* const* paths, usec_t *timestamp, bool update) {
        bool changed = false, originally_unset;
        const char* const* i;

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

int fsck_exists(const char *fstype) {
        const char *checker;

        assert(fstype);

        if (streq(fstype, "auto"))
                return -EINVAL;

        checker = strjoina("fsck.", fstype);
        return executable_is_good(checker);
}

char* dirname_malloc(const char *path) {
        char *d, *dir, *dir2;

        assert(path);

        d = strdup(path);
        if (!d)
                return NULL;

        dir = dirname(d);
        assert(dir);

        if (dir == d)
                return d;

        dir2 = strdup(dir);
        free(d);

        return dir2;
}

static const char *skip_slash_or_dot(const char *p) {
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

static const char *skip_slash_or_dot_backward(const char *path, const char *q) {
        assert(path);

        for (; q >= path; q--) {
                if (*q == '/')
                        continue;
                if (q > path && strneq(q - 1, "/.", 2))
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
        if ((q < path) || /* the root directory */
            (q == path && *q == '.')) { /* path is "." or "./" */
                if (next)
                        *next = path;
                if (ret)
                        *ret = NULL;
                return 0;
        }

        last_end = q + 1;

        while (q >= path && *q != '/')
                q--;

        last_begin = q + 1;
        len = last_end - last_begin;

        if (len > NAME_MAX)
                return -EINVAL;
        if (!accept_dot_dot && len == 2 && strneq(last_begin, "..", 2))
                return -EINVAL;

        if (next) {
                q = skip_slash_or_dot_backward(path, q);
                if (q < path)
                        *next = path;
                else
                        *next = q + 1;
        }

        if (ret)
                *ret = last_begin;
        return len;
}

const char *last_path_component(const char *path) {

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

int path_extract_filename(const char *path, char **ret) {
        _cleanup_free_ char *a = NULL;
        const char *c, *next = NULL;
        int r;

        /* Extracts the filename part (i.e. right-most component) from a path, i.e. string that passes
         * filename_is_valid(). A wrapper around last_path_component(), but eats up trailing
         * slashes. Returns:
         *
         * -EINVAL        → if the path is not valid
         * -EADDRNOTAVAIL → if only a directory was specified, but no filename, i.e. the root dir
         *                  itself or "." is specified
         * -ENOMEM        → no memory
         *
         * Returns >= 0 on success. If the input path has a trailing slash, returns O_DIRECTORY, to
         * indicate the referenced file must be a directory.
         *
         * This function guarantees to return a fully valid filename, i.e. one that passes
         * filename_is_valid() – this means "." and ".." are not accepted. */

        if (!path_is_valid(path))
                return -EINVAL;

        r = path_find_last_component(path, false, &next, &c);
        if (r < 0)
                return r;
        if (r == 0) /* root directory */
                return -EADDRNOTAVAIL;

        a = strndup(c, r);
        if (!a)
                return -ENOMEM;

        *ret = TAKE_PTR(a);
        return strlen(c) > (size_t)r ? O_DIRECTORY : 0;
}

int path_extract_directory(const char *path, char **ret) {
        _cleanup_free_ char *a = NULL;
        const char *c, *next = NULL;
        int r;

        /* The inverse of path_extract_filename(), i.e. returns the directory path prefix. Returns:
         *
         * -EINVAL        → if the path is not valid
         * -EDESTADDRREQ  → if no directory was specified in the passed in path, i.e. only a filename was passed
         * -EADDRNOTAVAIL → if the passed in parameter had no filename but did have a directory, i.e.
         *                   the root dir itself or "." was specified
         * -ENOMEM        → no memory (surprise!)
         *
         * This function guarantees to return a fully valid path, i.e. one that passes path_is_valid().
         */

        r = path_find_last_component(path, false, &next, &c);
        if (r < 0)
                return r;
        if (r == 0) /* empty or root */
                return isempty(path) ? -EINVAL : -EADDRNOTAVAIL;
        if (next == path) {
                if (*path != '/') /* filename only */
                        return -EDESTADDRREQ;

                a = strdup("/");
                if (!a)
                        return -ENOMEM;
                *ret = TAKE_PTR(a);
                return 0;
        }

        a = strndup(path, next - path);
        if (!a)
                return -ENOMEM;

        path_simplify(a);

        if (!path_is_valid(a))
                return -EINVAL;

        *ret = TAKE_PTR(a);
        return 0;
}

bool filename_is_valid(const char *p) {
        const char *e;

        if (isempty(p))
                return false;

        if (dot_or_dot_dot(p))
                return false;

        e = strchrnul(p, '/');
        if (*e != 0)
                return false;

        if (e - p > NAME_MAX) /* NAME_MAX is counted *without* the trailing NUL byte */
                return false;

        return true;
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

char *file_in_same_dir(const char *path, const char *filename) {
        char *e, *ret;
        size_t k;

        assert(path);
        assert(filename);

        /* This removes the last component of path and appends
         * filename, unless the latter is absolute anyway or the
         * former isn't */

        if (path_is_absolute(filename))
                return strdup(filename);

        e = strrchr(path, '/');
        if (!e)
                return strdup(filename);

        k = strlen(filename);
        ret = new(char, (e + 1 - path) + k + 1);
        if (!ret)
                return NULL;

        memcpy(mempcpy(ret, path, e + 1 - path), filename, k + 1);
        return ret;
}

bool hidden_or_backup_file(const char *filename) {
        const char *p;

        assert(filename);

        if (filename[0] == '.' ||
            streq(filename, "lost+found") ||
            streq(filename, "aquota.user") ||
            streq(filename, "aquota.group") ||
            endswith(filename, "~"))
                return true;

        p = strrchr(filename, '.');
        if (!p)
                return false;

        /* Please, let's not add more entries to the list below. If external projects think it's a good idea to come up
         * with always new suffixes and that everybody else should just adjust to that, then it really should be on
         * them. Hence, in future, let's not add any more entries. Instead, let's ask those packages to instead adopt
         * one of the generic suffixes/prefixes for hidden files or backups, possibly augmented with an additional
         * string. Specifically: there's now:
         *
         *    The generic suffixes "~" and ".bak" for backup files
         *    The generic prefix "." for hidden files
         *
         * Thus, if a new package manager "foopkg" wants its own set of ".foopkg-new", ".foopkg-old", ".foopkg-dist"
         * or so registered, let's refuse that and ask them to use ".foopkg.new", ".foopkg.old" or ".foopkg~" instead.
         */

        return STR_IN_SET(p + 1,
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

        /* Returns true on paths that likely refer to a device, either by path in sysfs or to something in /dev */

        return PATH_STARTSWITH_SET(path, "/dev/", "/sys/");
}

bool valid_device_node_path(const char *path) {

        /* Some superficial checks whether the specified path is a valid device node path, all without looking at the
         * actual device node. */

        if (!PATH_STARTSWITH_SET(path, "/dev/", "/run/systemd/inaccessible/"))
                return false;

        if (endswith(path, "/")) /* can't be a device node if it ends in a slash */
                return false;

        return path_is_normalized(path);
}

bool valid_device_allow_pattern(const char *path) {
        assert(path);

        /* Like valid_device_node_path(), but also allows full-subsystem expressions, like DeviceAllow= and DeviceDeny=
         * accept it */

        if (STARTSWITH_SET(path, "block-", "char-"))
                return true;

        return valid_device_node_path(path);
}

int systemd_installation_has_version(const char *root, unsigned minimal_version) {
        const char *pattern;
        int r;

        /* Try to guess if systemd installation is later than the specified version. This
         * is hacky and likely to yield false negatives, particularly if the installation
         * is non-standard. False positives should be relatively rare.
         */

        NULSTR_FOREACH(pattern,
                       /* /lib works for systems without usr-merge, and for systems with a sane
                        * usr-merge, where /lib is a symlink to /usr/lib. /usr/lib is necessary
                        * for Gentoo which does a merge without making /lib a symlink.
                        */
                       "lib/systemd/libsystemd-shared-*.so\0"
                       "lib64/systemd/libsystemd-shared-*.so\0"
                       "usr/lib/systemd/libsystemd-shared-*.so\0"
                       "usr/lib64/systemd/libsystemd-shared-*.so\0") {

                _cleanup_strv_free_ char **names = NULL;
                _cleanup_free_ char *path = NULL;
                char *c, **name;

                path = path_join(root, pattern);
                if (!path)
                        return -ENOMEM;

                r = glob_extend(&names, path, 0);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                assert_se(c = endswith(path, "*.so"));
                *c = '\0'; /* truncate the glob part */

                STRV_FOREACH(name, names) {
                        /* This is most likely to run only once, hence let's not optimize anything. */
                        char *t, *t2;
                        unsigned version;

                        t = startswith(*name, path);
                        if (!t)
                                continue;

                        t2 = endswith(t, ".so");
                        if (!t2)
                                continue;

                        t2[0] = '\0'; /* truncate the suffix */

                        r = safe_atou(t, &version);
                        if (r < 0) {
                                log_debug_errno(r, "Found libsystemd shared at \"%s.so\", but failed to parse version: %m", *name);
                                continue;
                        }

                        log_debug("Found libsystemd shared at \"%s.so\", version %u (%s).",
                                  *name, version,
                                  version >= minimal_version ? "OK" : "too old");
                        if (version >= minimal_version)
                                return true;
                }
        }

        return false;
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

bool empty_or_root(const char *path) {

        /* For operations relative to some root directory, returns true if the specified root directory is redundant,
         * i.e. either / or NULL or the empty string or any equivalent. */

        if (isempty(path))
                return true;

        return path_equal(path, "/");
}

bool path_strv_contains(char **l, const char *path) {
        char **i;

        STRV_FOREACH(i, l)
                if (path_equal(*i, path))
                        return true;

        return false;
}

bool prefixed_path_strv_contains(char **l, const char *path) {
        char **i, *j;

        STRV_FOREACH(i, l) {
                j = *i;
                if (*j == '-')
                        j++;
                if (*j == '+')
                        j++;
                if (path_equal(j, path))
                        return true;
        }

        return false;
}
