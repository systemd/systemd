/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "chase.h"
#include "conf-files.h"
#include "constants.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "log.h"
#include "macro.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "set.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"

static int files_add(
                DIR *dir,
                const char *dirpath,
                Hashmap **files,
                Set **masked,
                const char *suffix,
                unsigned flags) {

        int r;

        assert(dir);
        assert(dirpath);
        assert(files);
        assert(masked);

        FOREACH_DIRENT(de, dir, return -errno) {
                _cleanup_free_ char *n = NULL, *p = NULL;
                struct stat st;

                /* Does this match the suffix? */
                if (suffix && !endswith(de->d_name, suffix))
                        continue;

                /* Has this file already been found in an earlier directory? */
                if (hashmap_contains(*files, de->d_name)) {
                        log_debug("Skipping overridden file '%s/%s'.", dirpath, de->d_name);
                        continue;
                }

                /* Has this been masked in an earlier directory? */
                if ((flags & CONF_FILES_FILTER_MASKED) && set_contains(*masked, de->d_name)) {
                        log_debug("File '%s/%s' is masked by previous entry.", dirpath, de->d_name);
                        continue;
                }

                /* Read file metadata if we shall validate the check for file masks, for node types or whether the node is marked executable. */
                if (flags & (CONF_FILES_FILTER_MASKED|CONF_FILES_REGULAR|CONF_FILES_DIRECTORY|CONF_FILES_EXECUTABLE))
                        if (fstatat(dirfd(dir), de->d_name, &st, 0) < 0) {
                                log_debug_errno(errno, "Failed to stat '%s/%s', ignoring: %m", dirpath, de->d_name);
                                continue;
                        }

                /* Is this a masking entry? */
                if ((flags & CONF_FILES_FILTER_MASKED))
                        if (null_or_empty(&st)) {
                                /* Mark this one as masked */
                                r = set_put_strdup(masked, de->d_name);
                                if (r < 0)
                                        return r;

                                log_debug("File '%s/%s' is a mask.", dirpath, de->d_name);
                                continue;
                        }

                /* Does this node have the right type? */
                if (flags & (CONF_FILES_REGULAR|CONF_FILES_DIRECTORY))
                        if (!((flags & CONF_FILES_DIRECTORY) && S_ISDIR(st.st_mode)) &&
                            !((flags & CONF_FILES_REGULAR) && S_ISREG(st.st_mode))) {
                                log_debug("Ignoring '%s/%s', as it does not have the right type.", dirpath, de->d_name);
                                continue;
                        }

                /* Does this node have the executable bit set? */
                if (flags & CONF_FILES_EXECUTABLE)
                        /* As requested: check if the file is marked executable. Note that we don't check access(X_OK)
                         * here, as we care about whether the file is marked executable at all, and not whether it is
                         * executable for us, because if so, such errors are stuff we should log about. */

                        if ((st.st_mode & 0111) == 0) { /* not executable */
                                log_debug("Ignoring '%s/%s', as it is not marked executable.", dirpath, de->d_name);
                                continue;
                        }

                n = strdup(de->d_name);
                if (!n)
                        return -ENOMEM;

                if ((flags & CONF_FILES_BASENAME))
                        r = hashmap_ensure_put(files, &string_hash_ops_free, n, n);
                else {
                        p = path_join(dirpath, de->d_name);
                        if (!p)
                                return -ENOMEM;

                        r = hashmap_ensure_put(files, &string_hash_ops_free_free, n, p);
                }
                if (r < 0)
                        return r;
                assert(r > 0);

                TAKE_PTR(n);
                TAKE_PTR(p);
        }

        return 0;
}

static int base_cmp(char * const *a, char * const *b) {
        assert(a);
        assert(b);
        return path_compare_filename(*a, *b);
}

static int copy_and_sort_files_from_hashmap(Hashmap *fh, char ***ret) {
        _cleanup_free_ char **sv = NULL;
        char **files;

        assert(ret);

        sv = hashmap_get_strv(fh);
        if (!sv)
                return -ENOMEM;

        /* The entries in the array given by hashmap_get_strv() are still owned by the hashmap. */
        files = strv_copy(sv);
        if (!files)
                return -ENOMEM;

        typesafe_qsort(files, strv_length(files), base_cmp);

        *ret = files;
        return 0;
}

int conf_files_list_strv(
                char ***ret,
                const char *suffix,
                const char *root,
                unsigned flags,
                const char * const *dirs) {

        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_set_free_ Set *masked = NULL;
        int r;

        assert(ret);

        STRV_FOREACH(p, dirs) {
                _cleanup_closedir_ DIR *dir = NULL;
                _cleanup_free_ char *path = NULL;

                r = chase_and_opendir(*p, root, CHASE_PREFIX_ROOT, &path, &dir);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_debug_errno(r, "Failed to chase and open directory '%s', ignoring: %m", *p);
                        continue;
                }

                r = files_add(dir, path, &fh, &masked, suffix, flags);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to search for files in '%s', ignoring: %m", path);
        }

        return copy_and_sort_files_from_hashmap(fh, ret);
}

int conf_files_list_strv_at(
                char ***ret,
                const char *suffix,
                int rfd,
                unsigned flags,
                const char * const *dirs) {

        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_set_free_ Set *masked = NULL;
        int r;

        assert(rfd >= 0 || rfd == AT_FDCWD);
        assert(ret);

        STRV_FOREACH(p, dirs) {
                _cleanup_closedir_ DIR *dir = NULL;
                _cleanup_free_ char *path = NULL;

                r = chase_and_opendirat(rfd, *p, CHASE_AT_RESOLVE_IN_ROOT, &path, &dir);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_debug_errno(r, "Failed to chase and open directory '%s', ignoring: %m", *p);
                        continue;
                }

                r = files_add(dir, path, &fh, &masked, suffix, flags);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to search for files in '%s', ignoring: %m", path);
        }

        return copy_and_sort_files_from_hashmap(fh, ret);
}

int conf_files_insert(char ***strv, const char *root, char **dirs, const char *path) {
        /* Insert a path into strv, at the place honouring the usual sorting rules:
         * - we first compare by the basename
         * - and then we compare by dirname, allowing just one file with the given
         *   basename.
         * This means that we will
         * - add a new entry if basename(path) was not on the list,
         * - do nothing if an entry with higher priority was already present,
         * - do nothing if our new entry matches the existing entry,
         * - replace the existing entry if our new entry has higher priority.
         */
        size_t i, n;
        char *t;
        int r;

        n = strv_length(*strv);
        for (i = 0; i < n; i++) {
                int c;

                c = base_cmp((char* const*) *strv + i, (char* const*) &path);
                if (c == 0)
                        /* Oh, there already is an entry with a matching name (the last component). */
                        STRV_FOREACH(dir, dirs) {
                                _cleanup_free_ char *rdir = NULL;
                                char *p1, *p2;

                                rdir = path_join(root, *dir);
                                if (!rdir)
                                        return -ENOMEM;

                                p1 = path_startswith((*strv)[i], rdir);
                                if (p1)
                                        /* Existing entry with higher priority
                                         * or same priority, no need to do anything. */
                                        return 0;

                                p2 = path_startswith(path, *dir);
                                if (p2) {
                                        /* Our new entry has higher priority */

                                        t = path_join(root, path);
                                        if (!t)
                                                return log_oom();

                                        return free_and_replace((*strv)[i], t);
                                }
                        }

                else if (c > 0)
                        /* Following files have lower priority, let's go insert our
                         * new entry. */
                        break;

                /* … we are not there yet, let's continue */
        }

        /* The new file has lower priority than all the existing entries */
        t = path_join(root, path);
        if (!t)
                return -ENOMEM;

        r = strv_insert(strv, i, t);
        if (r < 0)
                free(t);

        return r;
}

int conf_files_list(char ***ret, const char *suffix, const char *root, unsigned flags, const char *dir) {
        return conf_files_list_strv(ret, suffix, root, flags, STRV_MAKE_CONST(dir));
}

int conf_files_list_at(char ***ret, const char *suffix, int rfd, unsigned flags, const char *dir) {
        return conf_files_list_strv_at(ret, suffix, rfd, flags, STRV_MAKE_CONST(dir));
}

int conf_files_list_nulstr(char ***ret, const char *suffix, const char *root, unsigned flags, const char *dirs) {
        _cleanup_strv_free_ char **d = NULL;

        assert(ret);

        d = strv_split_nulstr(dirs);
        if (!d)
                return -ENOMEM;

        return conf_files_list_strv(ret, suffix, root, flags, (const char**) d);
}

int conf_files_list_nulstr_at(char ***ret, const char *suffix, int rfd, unsigned flags, const char *dirs) {
        _cleanup_strv_free_ char **d = NULL;

        assert(ret);

        d = strv_split_nulstr(dirs);
        if (!d)
                return -ENOMEM;

        return conf_files_list_strv_at(ret, suffix, rfd, flags, (const char**) d);
}

int conf_files_list_with_replacement(
                const char *root,
                char **config_dirs,
                const char *replacement,
                char ***ret_files,
                char **ret_replace_file) {

        _cleanup_strv_free_ char **f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(config_dirs);
        assert(ret_files);
        assert(ret_replace_file || !replacement);

        r = conf_files_list_strv(&f, ".conf", root, 0, (const char* const*) config_dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate config files: %m");

        if (replacement) {
                r = conf_files_insert(&f, root, config_dirs, replacement);
                if (r < 0)
                        return log_error_errno(r, "Failed to extend config file list: %m");

                p = path_join(root, replacement);
                if (!p)
                        return log_oom();
        }

        *ret_files = TAKE_PTR(f);
        if (ret_replace_file)
                *ret_replace_file = TAKE_PTR(p);

        return 0;
}

int conf_files_list_dropins(
                char ***ret,
                const char *dropin_dirname,
                const char *root,
                const char * const *dirs) {

        _cleanup_strv_free_ char **dropin_dirs = NULL;
        const char *suffix;
        int r;

        assert(ret);
        assert(dropin_dirname);
        assert(dirs);

        suffix = strjoina("/", dropin_dirname);
        r = strv_extend_strv_concat(&dropin_dirs, (char**) dirs, suffix);
        if (r < 0)
                return r;

        return conf_files_list_strv(ret, ".conf", root, 0, (const char* const*) dropin_dirs);
}

/**
 * Open and read a config file.
 *
 * The <fn> argument may be:
 * - '-', meaning stdin.
 * - a file name without a path. In this case <config_dirs> are searched.
 * - a path, either relative or absolute. In this case <fn> is opened directly.
 *
 * This method is only suitable for configuration files which have a flat layout without dropins.
 */
int conf_file_read(
                const char *root,
                const char **config_dirs,
                const char *fn,
                parse_line_t parse_line,
                void *userdata,
                bool ignore_enoent,
                bool *invalid_config) {

        _cleanup_fclose_ FILE *_f = NULL;
        _cleanup_free_ char *_fn = NULL;
        unsigned v = 0;
        FILE *f;
        int r = 0;

        assert(fn);

        if (streq(fn, "-")) {
                f = stdin;
                fn = "<stdin>";

                log_debug("Reading config from stdin%s", special_glyph(SPECIAL_GLYPH_ELLIPSIS));

        } else if (is_path(fn)) {
                r = path_make_absolute_cwd(fn, &_fn);
                if (r < 0)
                        return log_error_errno(r, "Failed to make path absolute: %m");
                fn = _fn;

                f = _f = fopen(fn, "re");
                if (!_f)
                        r = -errno;
                else
                        log_debug("Reading config file \"%s\"%s", fn, special_glyph(SPECIAL_GLYPH_ELLIPSIS));

        } else {
                r = search_and_fopen(fn, "re", root, config_dirs, &_f, &_fn);
                if (r >= 0) {
                        f = _f;
                        fn = _fn;
                        log_debug("Reading config file \"%s\"%s", fn, special_glyph(SPECIAL_GLYPH_ELLIPSIS));
                }
        }

        if (r == -ENOENT && ignore_enoent) {
                log_debug_errno(r, "Failed to open \"%s\", ignoring: %m", fn);
                return 0; /* No error, but nothing happened. */
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read '%s': %m", fn);

        r = 1;  /* We entered the part where we may modify state. */

        for (;;) {
                _cleanup_free_ char *line = NULL;
                bool invalid_line = false;
                int k;

                k = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (k < 0)
                        return log_error_errno(k, "Failed to read '%s': %m", fn);
                if (k == 0)
                        break;

                v++;

                if (IN_SET(line[0], 0, '#'))
                        continue;

                k = parse_line(userdata, fn, v, line, invalid_config ? &invalid_line : NULL);
                if (k < 0 && invalid_line)
                        /* Allow reporting with a special code if the caller requested this. */
                        *invalid_config = true;
                else
                        /* The first error, if any, becomes our return value. */
                        RET_GATHER(r, k);
        }

        if (ferror(f))
                RET_GATHER(r, log_error_errno(errno_or_else(EIO),
                                              "Failed to read from file %s: %m", fn));

        return r;
}
