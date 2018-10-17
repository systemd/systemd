/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* When we include libgen.h because we need dirname() we immediately
 * undefine basename() since libgen.h defines it as a macro to the
 * POSIX version which is really broken. We prefer GNU basename(). */
#include <libgen.h>
#undef basename

#include "alloc-util.h"
#include "extract-word.h"
#include "fs-util.h"
#include "glob-util.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "parse-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "utf8.h"

bool path_is_absolute(const char *p) {
        return p[0] == '/';
}

bool is_path(const char *p) {
        return !!strchr(p, '/');
}

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

        if (endswith(prefix, "/"))
                return strjoin(prefix, p);
        else
                return strjoin(prefix, "/", p);
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

                c = path_join(NULL, cwd, p);
        }
        if (!c)
                return -ENOMEM;

        *ret = c;
        return 0;
}

int path_make_relative(const char *from_dir, const char *to_path, char **_r) {
        char *f, *t, *r, *p;
        unsigned n_parents = 0;

        assert(from_dir);
        assert(to_path);
        assert(_r);

        /* Strips the common part, and adds ".." elements as necessary. */

        if (!path_is_absolute(from_dir) || !path_is_absolute(to_path))
                return -EINVAL;

        f = strdupa(from_dir);
        t = strdupa(to_path);

        path_simplify(f, true);
        path_simplify(t, true);

        /* Skip the common part. */
        for (;;) {
                size_t a, b;

                f += *f == '/';
                t += *t == '/';

                if (!*f) {
                        if (!*t)
                                /* from_dir equals to_path. */
                                r = strdup(".");
                        else
                                /* from_dir is a parent directory of to_path. */
                                r = strdup(t);
                        if (!r)
                                return -ENOMEM;

                        *_r = r;
                        return 0;
                }

                if (!*t)
                        break;

                a = strcspn(f, "/");
                b = strcspn(t, "/");

                if (a != b || memcmp(f, t, a) != 0)
                        break;

                f += a;
                t += b;
        }

        /* If we're here, then "from_dir" has one or more elements that need to
         * be replaced with "..". */

        /* Count the number of necessary ".." elements. */
        for (; *f;) {
                size_t w;

                w = strcspn(f, "/");

                /* If this includes ".." we can't do a simple series of "..", refuse */
                if (w == 2 && f[0] == '.' && f[1] == '.')
                        return -EINVAL;

                /* Count number of elements */
                n_parents++;

                f += w;
                f += *f == '/';
        }

        r = new(char, n_parents * 3 + strlen(t) + 1);
        if (!r)
                return -ENOMEM;

        for (p = r; n_parents > 0; n_parents--)
                p = mempcpy(p, "../", 3);

        if (*t)
                strcpy(p, t);
        else
                /* Remove trailing slash */
                *(--p) = 0;

        *_r = r;
        return 0;
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

                path_simplify(t, false);
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
                        t = prefix_root(root, orig);
                        if (!t) {
                                enomem = true;
                                continue;
                        }
                } else
                        t = *s;

                r = chase_symlinks(t, root, 0, &u);
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

char *path_simplify(char *path, bool kill_dots) {
        char *f, *t;
        bool slash = false, ignore_slash = false, absolute;

        assert(path);

        /* Removes redundant inner and trailing slashes. Also removes unnecessary dots
         * if kill_dots is true. Modifies the passed string in-place.
         *
         * ///foo//./bar/.   becomes /foo/./bar/.      (if kill_dots is false)
         * ///foo//./bar/.   becomes /foo/bar          (if kill_dots is true)
         * .//./foo//./bar/. becomes ././foo/./bar/.   (if kill_dots is false)
         * .//./foo//./bar/. becomes foo/bar           (if kill_dots is true)
         */

        if (isempty(path))
                return path;

        absolute = path_is_absolute(path);

        f = path;
        if (kill_dots && *f == '.' && IN_SET(f[1], 0, '/')) {
                ignore_slash = true;
                f++;
        }

        for (t = path; *f; f++) {

                if (*f == '/') {
                        slash = true;
                        continue;
                }

                if (slash) {
                        if (kill_dots && *f == '.' && IN_SET(f[1], 0, '/'))
                                continue;

                        slash = false;
                        if (ignore_slash)
                                ignore_slash = false;
                        else
                                *(t++) = '/';
                }

                *(t++) = *f;
        }

        /* Special rule, if we stripped everything, we either need a "/" (for the root directory)
         * or "." for the current directory */
        if (t == path) {
                if (absolute)
                        *(t++) = '/';
                else
                        *(t++) = '.';
        }

        *t = 0;
        return path;
}

char* path_startswith(const char *path, const char *prefix) {
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
                size_t a, b;

                path += strspn(path, "/");
                prefix += strspn(prefix, "/");

                if (*prefix == 0)
                        return (char*) path;

                if (*path == 0)
                        return NULL;

                a = strcspn(path, "/");
                b = strcspn(prefix, "/");

                if (a != b)
                        return NULL;

                if (memcmp(path, prefix, a) != 0)
                        return NULL;

                path += a;
                prefix += b;
        }
}

int path_compare(const char *a, const char *b) {
        int d;

        assert(a);
        assert(b);

        /* A relative path and an absolute path must not compare as equal.
         * Which one is sorted before the other does not really matter.
         * Here a relative path is ordered before an absolute path. */
        d = (a[0] == '/') - (b[0] == '/');
        if (d != 0)
                return d;

        for (;;) {
                size_t j, k;

                a += strspn(a, "/");
                b += strspn(b, "/");

                if (*a == 0 && *b == 0)
                        return 0;

                /* Order prefixes first: "/foo" before "/foo/bar" */
                if (*a == 0)
                        return -1;
                if (*b == 0)
                        return 1;

                j = strcspn(a, "/");
                k = strcspn(b, "/");

                /* Alphabetical sort: "/foo/aaa" before "/foo/b" */
                d = memcmp(a, b, MIN(j, k));
                if (d != 0)
                        return (d > 0) - (d < 0); /* sign of d */

                /* Sort "/foo/a" before "/foo/aaa" */
                d = (j > k) - (j < k);  /* sign of (j - k) */
                if (d != 0)
                        return d;

                a += j;
                b += k;
        }
}

bool path_equal(const char *a, const char *b) {
        return path_compare(a, b) == 0;
}

bool path_equal_or_files_same(const char *a, const char *b, int flags) {
        return path_equal(a, b) || files_same(a, b, flags) > 0;
}

char* path_join(const char *root, const char *path, const char *rest) {
        assert(path);

        if (!isempty(root))
                return strjoin(root, endswith(root, "/") ? "" : "/",
                               path[0] == '/' ? path+1 : path,
                               rest ? (endswith(path, "/") ? "" : "/") : NULL,
                               rest && rest[0] == '/' ? rest+1 : rest);
        else
                return strjoin(path,
                               rest ? (endswith(path, "/") ? "" : "/") : NULL,
                               rest && rest[0] == '/' ? rest+1 : rest);
}

int find_binary(const char *name, char **ret) {
        int last_error, r;
        const char *p;

        assert(name);

        if (is_path(name)) {
                if (access(name, X_OK) < 0)
                        return -errno;

                if (ret) {
                        r = path_make_absolute_cwd(name, ret);
                        if (r < 0)
                                return r;
                }

                return 0;
        }

        /**
         * Plain getenv, not secure_getenv, because we want
         * to actually allow the user to pick the binary.
         */
        p = getenv("PATH");
        if (!p)
                p = DEFAULT_PATH;

        last_error = -ENOENT;

        for (;;) {
                _cleanup_free_ char *j = NULL, *element = NULL;

                r = extract_first_word(&p, &element, ":", EXTRACT_RELAX|EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (!path_is_absolute(element))
                        continue;

                j = strjoin(element, "/", name);
                if (!j)
                        return -ENOMEM;

                if (access(j, X_OK) >= 0) {
                        /* Found it! */

                        if (ret) {
                                *ret = path_simplify(j, false);
                                j = NULL;
                        }

                        return 0;
                }

                last_error = -errno;
        }

        return last_error;
}

bool paths_check_timestamp(const char* const* paths, usec_t *timestamp, bool update) {
        bool changed = false;
        const char* const* i;

        assert(timestamp);

        if (!paths)
                return false;

        STRV_FOREACH(i, paths) {
                struct stat stats;
                usec_t u;

                if (stat(*i, &stats) < 0)
                        continue;

                u = timespec_load(&stats.st_mtim);

                /* first check */
                if (*timestamp >= u)
                        continue;

                log_debug("timestamp of '%s' changed", *i);

                /* update timestamp */
                if (update) {
                        *timestamp = u;
                        changed = true;
                } else
                        return true;
        }

        return changed;
}

static int binary_is_good(const char *binary) {
        _cleanup_free_ char *p = NULL, *d = NULL;
        int r;

        r = find_binary(binary, &p);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        /* An fsck that is linked to /bin/true is a non-existent
         * fsck */

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
        return binary_is_good(checker);
}

int mkfs_exists(const char *fstype) {
        const char *mkfs;

        assert(fstype);

        if (streq(fstype, "auto"))
                return -EINVAL;

        mkfs = strjoina("mkfs.", fstype);
        return binary_is_good(mkfs);
}

char *prefix_root(const char *root, const char *path) {
        char *n, *p;
        size_t l;

        /* If root is passed, prefixes path with it. Otherwise returns
         * it as is. */

        assert(path);

        /* First, drop duplicate prefixing slashes from the path */
        while (path[0] == '/' && path[1] == '/')
                path++;

        if (empty_or_root(root))
                return strdup(path);

        l = strlen(root) + 1 + strlen(path) + 1;

        n = new(char, l);
        if (!n)
                return NULL;

        p = stpcpy(n, root);

        while (p > n && p[-1] == '/')
                p--;

        if (path[0] != '/')
                *(p++) = '/';

        strcpy(p, path);
        return n;
}

int parse_path_argument_and_warn(const char *path, bool suppress_root, char **arg) {
        char *p;
        int r;

        /*
         * This function is intended to be used in command line
         * parsers, to handle paths that are passed in. It makes the
         * path absolute, and reduces it to NULL if omitted or
         * root (the latter optionally).
         *
         * NOTE THAT THIS WILL FREE THE PREVIOUS ARGUMENT POINTER ON
         * SUCCESS! Hence, do not pass in uninitialized pointers.
         */

        if (isempty(path)) {
                *arg = mfree(*arg);
                return 0;
        }

        r = path_make_absolute_cwd(path, &p);
        if (r < 0)
                return log_error_errno(r, "Failed to parse path \"%s\" and make it absolute: %m", path);

        path_simplify(p, false);
        if (suppress_root && empty_or_root(p))
                p = mfree(p);

        free_and_replace(*arg, p);

        return 0;
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
         */

        unsigned l, k;

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

bool filename_is_valid(const char *p) {
        const char *e;

        if (isempty(p))
                return false;

        if (dot_or_dot_dot(p))
                return false;

        e = strchrnul(p, '/');
        if (*e != 0)
                return false;

        if (e - p > FILENAME_MAX) /* FILENAME_MAX is counted *without* the trailing NUL byte */
                return false;

        return true;
}

bool path_is_valid(const char *p) {

        if (isempty(p))
                return false;

        if (strlen(p) >= PATH_MAX) /* PATH_MAX is counted *with* the trailing NUL byte */
                return false;

        return true;
}

bool path_is_normalized(const char *p) {

        if (!path_is_valid(p))
                return false;

        if (dot_or_dot_dot(p))
                return false;

        if (startswith(p, "../") || endswith(p, "/..") || strstr(p, "/../"))
                return false;

        if (startswith(p, "./") || endswith(p, "/.") || strstr(p, "/./"))
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

        if (startswith(path, "block-") ||
            startswith(path, "char-"))
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

                path = prefix_root(root, pattern);
                if (!path)
                        return -ENOMEM;

                r = glob_extend(&names, path);
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

bool empty_or_root(const char *root) {

        /* For operations relative to some root directory, returns true if the specified root directory is redundant,
         * i.e. either / or NULL or the empty string or any equivalent. */

        if (!root)
                return true;

        return root[strspn(root, "/")] == 0;
}

int path_simplify_and_warn(
                char *path,
                unsigned flag,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue) {

        bool absolute, fatal = flag & PATH_CHECK_FATAL;

        assert(!FLAGS_SET(flag, PATH_CHECK_ABSOLUTE | PATH_CHECK_RELATIVE));

        if (!utf8_is_valid(path)) {
                log_syntax_invalid_utf8(unit, LOG_ERR, filename, line, path);
                return -EINVAL;
        }

        if (flag & (PATH_CHECK_ABSOLUTE | PATH_CHECK_RELATIVE)) {
                absolute = path_is_absolute(path);

                if (!absolute && (flag & PATH_CHECK_ABSOLUTE)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "%s= path is not absolute%s: %s",
                                   lvalue, fatal ? "" : ", ignoring", path);
                        return -EINVAL;
                }

                if (absolute && (flag & PATH_CHECK_RELATIVE)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "%s= path is absolute%s: %s",
                                   lvalue, fatal ? "" : ", ignoring", path);
                        return -EINVAL;
                }
        }

        path_simplify(path, true);

        if (!path_is_normalized(path)) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "%s= path is not normalized%s: %s",
                           lvalue, fatal ? "" : ", ignoring", path);
                return -EINVAL;
        }

        return 0;
}
