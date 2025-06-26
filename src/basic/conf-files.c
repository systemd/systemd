/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "chase.h"
#include "conf-files.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "log.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "set.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"

static int files_add(
                const char *dirpath,
                const char *root,
                int rfd,
                Hashmap **files,
                Set **masked,
                const char *suffix,
                ConfFilesFlags flags) {

        int r;

        assert(dirpath);
        assert(files);
        assert(masked);

        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_free_ char *resolved_dirpath = NULL;
        if (rfd >= 0 || rfd == AT_FDCWD) {
                assert(!root);
                r = chase_and_opendirat(rfd, dirpath, CHASE_AT_RESOLVE_IN_ROOT, &resolved_dirpath, &dir);
        } else
                r = chase_and_opendir(dirpath, root, CHASE_PREFIX_ROOT, &resolved_dirpath, &dir);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to chase and open directory '%s%s', ignoring: %m", strempty(root), dirpath);

        FOREACH_DIRENT(de, dir, return -errno) {

                /* Does this match the suffix? */
                if (suffix && !endswith(de->d_name, suffix))
                        continue;

                /* Has this file already been found in an earlier directory? */
                if (hashmap_contains(*files, de->d_name)) {
                        log_debug("Skipping overridden file '%s/%s'.", resolved_dirpath, de->d_name);
                        continue;
                }

                /* Has this been masked in an earlier directory? */
                if ((flags & CONF_FILES_FILTER_MASKED) != 0 && set_contains(*masked, de->d_name)) {
                        log_debug("File '%s/%s' is masked by previous entry.", resolved_dirpath, de->d_name);
                        continue;
                }

                struct stat st;
                if (FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_SYMLINK)) {

                        _cleanup_free_ char *p = path_join(resolved_dirpath, de->d_name);
                        if (!p)
                                return log_oom_debug();

                        _cleanup_free_ char *resolved_path = NULL;
                        if (rfd >= 0 || rfd == AT_FDCWD)
                                r = chaseat(rfd, p, CHASE_AT_RESOLVE_IN_ROOT | CHASE_NONEXISTENT, &resolved_path, /* ret_fd = */ NULL);
                        else
                                r = chase(p, root, CHASE_NONEXISTENT, &resolved_path, /* ret_fd = */ NULL);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to chase '%s/%s', ignoring: %m", resolved_dirpath, de->d_name);
                                continue;
                        }

                        if (r == 0) {
                                /* If the path points to /dev/null in a image or so, then the device node may not exist. */
                                if (path_equal(path_startswith(resolved_path, strempty(root)), "dev/null")) {
                                        /* Mark this one as masked */
                                        r = set_put_strdup(masked, de->d_name);
                                        if (r < 0)
                                                return log_oom_debug();

                                        log_debug("File '%s/%s' is a mask (symlink to /dev/null).", resolved_dirpath, de->d_name);
                                        continue;
                                }

                                log_debug_errno(SYNTHETIC_ERRNO(ENOENT), "Failed to chase '%s/%s', ignoring: %m", resolved_dirpath, de->d_name);
                                continue;
                        }

                        if (rfd >= 0 || rfd == AT_FDCWD)
                                r = fstatat(rfd, resolved_path, &st, AT_SYMLINK_NOFOLLOW);
                        else
                                r = stat(resolved_path, &st);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to stat '%s/%s', ignoring: %m", resolved_dirpath, de->d_name);
                                continue;
                        }

                } else {

                        /* Even if no verification is requested, let's unconditionally call chase(), to drop
                         * unresolvable symlinks. */

                        _cleanup_free_ char *p = path_join(resolved_dirpath, de->d_name);
                        if (!p)
                                return log_oom_debug();

                        if (rfd >= 0 || rfd == AT_FDCWD)
                                r = chase_and_statat(rfd, p, CHASE_AT_RESOLVE_IN_ROOT, /* ret_path = */ NULL, &st);
                        else
                                r = chase_and_stat(p, root, /* chase_flags = */ 0, /* ret_path = */ NULL, &st);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to chase and stat '%s/%s', ignoring: %m", resolved_dirpath, de->d_name);
                                continue;
                        }
                }

                /* Is this a masking entry? */
                if ((FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_SYMLINK) && stat_is_null(&st)) ||
                    (FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_EMPTY) && stat_is_empty(&st))) {
                        /* Mark this one as masked */
                        r = set_put_strdup(masked, de->d_name);
                        if (r < 0)
                                return log_oom_debug();

                        log_debug("File '%s/%s' is a mask.", resolved_dirpath, de->d_name);
                        continue;
                }

                /* Is this node a regular file? */
                if (FLAGS_SET(flags, CONF_FILES_REGULAR) && !S_ISREG(st.st_mode)) {
                        log_debug("Ignoring '%s/%s', as it is not a regular file.", resolved_dirpath, de->d_name);
                        continue;
                }

                /* Is this node a directory? */
                if (FLAGS_SET(flags, CONF_FILES_DIRECTORY) && !S_ISDIR(st.st_mode)) {
                        log_debug("Ignoring '%s/%s', as it is not a directory.", resolved_dirpath, de->d_name);
                        continue;
                }

                /* Does this node have the executable bit set?
                 * As requested: check if the file is marked executable. Note that we don't check access(X_OK)
                 * here, as we care about whether the file is marked executable at all, and not whether it is
                 * executable for us, because if so, such errors are stuff we should log about. */
                if (FLAGS_SET(flags, CONF_FILES_EXECUTABLE) && (st.st_mode & 0111) == 0) {
                        log_debug("Ignoring '%s/%s', as it is not marked executable.", resolved_dirpath, de->d_name);
                        continue;
                }

                _cleanup_free_ char *n = strdup(de->d_name);
                if (!n)
                        return log_oom_debug();

                if (FLAGS_SET(flags, CONF_FILES_BASENAME)) {
                        r = hashmap_ensure_put(files, &string_hash_ops_free, n, n);
                        if (r < 0)
                                return log_oom_debug();
                } else {
                        _cleanup_free_ char *p = path_join(resolved_dirpath, de->d_name);
                        if (!p)
                                return log_oom_debug();

                        r = hashmap_ensure_put(files, &string_hash_ops_free_free, n, p);
                        if (r < 0)
                                return log_oom_debug();

                        TAKE_PTR(p);
                }
                assert(r > 0);

                TAKE_PTR(n);
        }

        return 0;
}

static int copy_and_sort_files_from_hashmap(Hashmap *fh, char ***ret) {
        _cleanup_free_ char **sv = NULL;
        char **files;
        int r;

        assert(ret);

        r = hashmap_dump_sorted(fh, (void***) &sv, /* ret_n = */ NULL);
        if (r < 0)
                return r;

        /* The entries in the array given by hashmap_dump_sorted() are still owned by the hashmap. */
        files = strv_copy(sv);
        if (!files)
                return -ENOMEM;

        *ret = files;
        return 0;
}

int conf_files_list_strv(
                char ***ret,
                const char *suffix,
                const char *root,
                ConfFilesFlags flags,
                const char * const *dirs) {

        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_set_free_ Set *masked = NULL;
        int r;

        assert(ret);

        STRV_FOREACH(p, dirs) {
                r = files_add(*p, root, /* rfd = */ -EBADF, &fh, &masked, suffix, flags);
                if (r == -ENOMEM)
                        return r;
        }

        return copy_and_sort_files_from_hashmap(fh, ret);
}

int conf_files_list_strv_at(
                char ***ret,
                const char *suffix,
                int rfd,
                ConfFilesFlags flags,
                const char * const *dirs) {

        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_set_free_ Set *masked = NULL;
        int r;

        assert(rfd >= 0 || rfd == AT_FDCWD);
        assert(ret);

        STRV_FOREACH(p, dirs) {
                r = files_add(*p, /* root = */ NULL, rfd, &fh, &masked, suffix, flags);
                if (r == -ENOMEM)
                        return r;
        }

        return copy_and_sort_files_from_hashmap(fh, ret);
}

int conf_files_list(char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char *dir) {
        return conf_files_list_strv(ret, suffix, root, flags, STRV_MAKE_CONST(dir));
}

int conf_files_list_at(char ***ret, const char *suffix, int rfd, ConfFilesFlags flags, const char *dir) {
        return conf_files_list_strv_at(ret, suffix, rfd, flags, STRV_MAKE_CONST(dir));
}

int conf_files_list_nulstr(char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char *dirs) {
        _cleanup_strv_free_ char **d = NULL;

        assert(ret);

        d = strv_split_nulstr(dirs);
        if (!d)
                return -ENOMEM;

        return conf_files_list_strv(ret, suffix, root, flags, (const char**) d);
}

int conf_files_list_nulstr_at(char ***ret, const char *suffix, int rfd, ConfFilesFlags flags, const char *dirs) {
        _cleanup_strv_free_ char **d = NULL;

        assert(ret);

        d = strv_split_nulstr(dirs);
        if (!d)
                return -ENOMEM;

        return conf_files_list_strv_at(ret, suffix, rfd, flags, (const char**) d);
}

int conf_files_insert(char ***strv, const char *root, char **dirs, const char *path, char **ret_inserted) {
        /* Insert a path into strv, at the place honouring the usual sorting rules:
         * - we first compare by the basename
         * - and then we compare by dirname, allowing just one file with the given basename.
         * This means that we will
         * - add a new entry if basename(path) was not on the list,
         * - do nothing if an entry with higher priority was already present,
         * - do nothing if our new entry matches the existing entry,
         * - replace the existing entry if our new entry has higher priority.
         *
         * Do not call this directly, but through conf_files_list_with_replacement(), except when testing. */

        int r;

        _cleanup_free_ char *dirpath = NULL;
        r = path_extract_directory(path, &dirpath);
        if (r < 0)
                return r;

        _cleanup_free_ char *filename = NULL;
        r = path_extract_filename(path, &filename);
        if (r < 0)
                return r;

        _cleanup_free_ char *resolved_dirpath = NULL;
        r = chase(dirpath, root, CHASE_PREFIX_ROOT | CHASE_NONEXISTENT, &resolved_dirpath, /* ret_fd = */ NULL);
        if (r < 0)
                return r;

        _cleanup_free_ char *resolved_path = path_join(resolved_dirpath, filename);
        if (!resolved_path)
                return -ENOMEM;

        char **pos = NULL;
        STRV_FOREACH(s, *strv) {
                r = path_compare_filename(*s, filename);
                if (r < 0)
                        /* we are not there yet, let's continue */
                        continue;

                if (r > 0) {
                        /* Following files have lower priority, let's go insert our new entry. */
                        pos = s;
                        break;
                }

                /* Oh, there already is an entry with a matching name (the last component). */
                STRV_FOREACH(dir, dirs) {
                        _cleanup_free_ char *rdir = NULL;

                        if (chase(*dir, root, CHASE_PREFIX_ROOT | CHASE_MUST_BE_DIRECTORY, &rdir, /* ret_fd = */ NULL) < 0)
                                continue;

                        if (path_startswith(*s, rdir)) {
                                /* Existing entry with higher priority or same priority, no need to
                                 * do anything. */
                                if (ret_inserted)
                                        *ret_inserted = NULL;
                                return 0;
                        }

                        if (path_equal(resolved_dirpath, rdir)) {
                                /* Our new entry has higher priority */
                                if (ret_inserted) {
                                        char *t = strdup(resolved_path);
                                        if (!t)
                                                return -ENOMEM;

                                        *ret_inserted = t;
                                }

                                return free_and_replace(*s, resolved_path);
                        }
                }

                return -EINVAL; /* The file in the strv is not under the conf directories. */
        }

        /* The new file has lower priority than all the existing entries */

        _cleanup_free_ char *copy = NULL;
        if (ret_inserted) {
                copy = strdup(resolved_path);
                if (!copy)
                        return -ENOMEM;
        }

        r = strv_insert(strv, pos ? (size_t) (pos - *strv) : SIZE_MAX, resolved_path);
        if (r < 0)
                return r;

        TAKE_PTR(resolved_path);
        if (ret_inserted)
                *ret_inserted = TAKE_PTR(copy);

        return 0;
}

int conf_files_list_with_replacement(
                const char *root,
                char **config_dirs,
                const char *replacement,
                char ***ret_files,
                char **ret_replace_file) {

        _cleanup_strv_free_ char **f = NULL;
        int r;

        assert(config_dirs);
        assert(ret_files);
        assert(ret_replace_file || !replacement);

        r = conf_files_list_strv(&f, ".conf", root, 0, (const char* const*) config_dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate config files: %m");

        if (replacement) {
                r = conf_files_insert(&f, root, config_dirs, replacement, ret_replace_file);
                if (r < 0)
                        return log_error_errno(r, "Failed to extend config file list: %m");
        }

        *ret_files = TAKE_PTR(f);
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
        r = strv_extend_strv_concat(&dropin_dirs, dirs, suffix);
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

                log_debug("Reading config from stdin%s", glyph(GLYPH_ELLIPSIS));

        } else if (is_path(fn)) {
                r = path_make_absolute_cwd(fn, &_fn);
                if (r < 0)
                        return log_error_errno(r, "Failed to make path absolute: %m");
                fn = _fn;

                f = _f = fopen(fn, "re");
                if (!_f)
                        r = -errno;
                else
                        log_debug("Reading config file \"%s\"%s", fn, glyph(GLYPH_ELLIPSIS));

        } else {
                r = search_and_fopen(fn, "re", root, config_dirs, &_f, &_fn);
                if (r >= 0) {
                        f = _f;
                        fn = _fn;
                        log_debug("Reading config file \"%s\"%s", fn, glyph(GLYPH_ELLIPSIS));
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

                k = parse_line(fn, v, line, invalid_config ? &invalid_line : NULL, userdata);
                if (k < 0 && invalid_line)
                        /* Allow reporting with a special code if the caller requested this. */
                        *invalid_config = true;
                else
                        /* The first error, if any, becomes our return value. */
                        RET_GATHER(r, k);
        }

        if (ferror(f))
                RET_GATHER(r, log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read from file %s.", fn));

        return r;
}
