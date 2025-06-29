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
                DIR *dir,
                const char *dirpath,
                int rfd,
                const char *root, /* for logging, can be NULL */
                Hashmap **files,
                Set **masked,
                const char *suffix,
                ConfFilesFlags flags) {

        int r;

        assert(dir);
        assert(dirpath);
        assert(rfd >= 0 || rfd == AT_FDCWD);
        assert(files);
        assert(masked);

        root = strempty(root);

        FOREACH_DIRENT(de, dir, return log_debug_errno(errno, "Failed to read directory '%s/%s': %m",
                                                       root, skip_leading_slash(dirpath))) {

                /* Does this match the suffix? */
                if (suffix && !endswith(de->d_name, suffix))
                        continue;

                /* Has this file already been found in an earlier directory? */
                if (hashmap_contains(*files, de->d_name)) {
                        log_debug("Skipping overridden file '%s/%s/%s'.",
                                  root, skip_leading_slash(dirpath), de->d_name);
                        continue;
                }

                /* Has this been masked in an earlier directory? */
                if ((flags & CONF_FILES_FILTER_MASKED) != 0 && set_contains(*masked, de->d_name)) {
                        log_debug("File '%s/%s/%s' is masked by previous entry.",
                                  root, skip_leading_slash(dirpath), de->d_name);
                        continue;
                }

                _cleanup_free_ char *p = path_join(dirpath, de->d_name);
                if (!p)
                        return log_oom_debug();

                _cleanup_free_ char *resolved_path = NULL;
                bool need_stat = (flags & (CONF_FILES_FILTER_MASKED | CONF_FILES_REGULAR | CONF_FILES_DIRECTORY | CONF_FILES_EXECUTABLE)) != 0;
                struct stat st;

                if (!need_stat || FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_SYMLINK)) {

                        /* Even if no verification is requested, let's unconditionally call chaseat(),
                         * to drop unsafe symlinks. */

                        r = chaseat(rfd, p, CHASE_AT_RESOLVE_IN_ROOT | CHASE_NONEXISTENT, &resolved_path, /* ret_fd = */ NULL);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to chase '%s/%s', ignoring: %m",
                                                root, skip_leading_slash(p));
                                continue;
                        }
                        if (r == 0 && FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_SYMLINK)) {

                                /* If the path points to /dev/null in a image or so, then the device node may not exist. */
                                if (path_equal(skip_leading_slash(resolved_path), "dev/null")) {
                                        /* Mark this one as masked */
                                        r = set_put_strdup(masked, de->d_name);
                                        if (r < 0)
                                                return log_oom_debug();

                                        log_debug("File '%s/%s' is a mask (symlink to /dev/null).",
                                                  root, skip_leading_slash(p));
                                        continue;
                                }

                                /* If the flag is set, we need to have stat, hence, skip the entry. */
                                log_debug_errno(SYNTHETIC_ERRNO(ENOENT), "Failed to chase '%s/%s', ignoring: %m",
                                                root, skip_leading_slash(p));
                                continue;
                        }

                        if (need_stat && fstatat(rfd, resolved_path, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                                log_debug_errno(errno, "Failed to stat '%s/%s', ignoring: %m",
                                                root, skip_leading_slash(p));
                                continue;
                        }

                } else {
                        r = chase_and_statat(rfd, p, CHASE_AT_RESOLVE_IN_ROOT, &resolved_path, &st);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to chase and stat '%s/%s', ignoring: %m",
                                                root, skip_leading_slash(p));
                                continue;
                        }
                }

                /* Is this a masking entry? */
                if (FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_SYMLINK) && stat_may_be_dev_null(&st)) {
                        /* Mark this one as masked */
                        r = set_put_strdup(masked, de->d_name);
                        if (r < 0)
                                return log_oom_debug();

                        log_debug("File '%s/%s' is a mask (symlink to /dev/null).", root, skip_leading_slash(p));
                        continue;
                }

                if (FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_EMPTY) && stat_is_empty(&st)) {
                        /* Mark this one as masked */
                        r = set_put_strdup(masked, de->d_name);
                        if (r < 0)
                                return log_oom_debug();

                        log_debug("File '%s/%s' is a mask (an empty file).", root, skip_leading_slash(p));
                        continue;
                }

                /* Is this node a regular file? */
                if (FLAGS_SET(flags, CONF_FILES_REGULAR) && !S_ISREG(st.st_mode)) {
                        log_debug("Ignoring '%s/%s', as it is not a regular file.", root, skip_leading_slash(p));
                        continue;
                }

                /* Is this node a directory? */
                if (FLAGS_SET(flags, CONF_FILES_DIRECTORY) && !S_ISDIR(st.st_mode)) {
                        log_debug("Ignoring '%s/%s', as it is not a directory.", root, skip_leading_slash(p));
                        continue;
                }

                /* Does this node have the executable bit set?
                 * As requested: check if the file is marked executable. Note that we don't check access(X_OK)
                 * here, as we care about whether the file is marked executable at all, and not whether it is
                 * executable for us, because if so, such errors are stuff we should log about. */
                if (FLAGS_SET(flags, CONF_FILES_EXECUTABLE) && (st.st_mode & 0111) == 0) {
                        log_debug("Ignoring '%s/%s', as it is not marked executable.", root, skip_leading_slash(p));
                        continue;
                }

                _cleanup_free_ char *n = strdup(de->d_name);
                if (!n)
                        return log_oom_debug();

                r = hashmap_ensure_put(files, &string_hash_ops_free_free, n, p);
                if (r < 0) {
                        assert(r == -ENOMEM);
                        return log_oom_debug();
                }
                assert(r > 0);

                TAKE_PTR(n);
                TAKE_PTR(p);
        }

        return 0;
}

static int copy_and_sort_files_from_hashmap(Hashmap *fh, const char *root, ConfFilesFlags flags, char ***ret) {
        _cleanup_free_ char **sv = NULL;
        _cleanup_strv_free_ char **files = NULL;
        size_t n = 0;
        int r;

        assert(ret);

        r = hashmap_dump_sorted(fh, (void***) &sv, /* ret_n = */ NULL);
        if (r < 0)
                return log_oom_debug();

        /* The entries in the array given by hashmap_dump_sorted() are still owned by the hashmap. */
        STRV_FOREACH(s, sv) {
                _cleanup_free_ char *p = NULL;

                if (FLAGS_SET(flags, CONF_FILES_BASENAME)) {
                        r = path_extract_filename(*s, &p);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to extract filename from '%s': %m", *s);
                } else if (root) {
                        r = chaseat_prefix_root(*s, root, &p);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to prefix '%s' with root '%s': %m", *s, root);
                }

                if (p)
                        r = strv_consume_with_size(&files, &n, TAKE_PTR(p));
                else
                        r = strv_extend_with_size(&files, &n, *s);
                if (r < 0)
                        return log_oom_debug();
        }

        *ret = TAKE_PTR(files);
        return 0;
}

static int insert_replacement(Hashmap **fh, char *filename_replacement, char *resolved_replacement, char **ret) {
        _cleanup_free_ char *fname = ASSERT_PTR(filename_replacement), *path = ASSERT_PTR(resolved_replacement);
        int r;

        assert(fh);

        /* This consumes the input filename and path. */

        const char *existing = hashmap_get(*fh, fname);
        if (existing) {
                log_debug("An entry with higher priority already exists ('%s' -> '%s'), ignoring the replacement: %s",
                          fname, existing, path);
                if (ret)
                        *ret = NULL;
                return 0;
        }

        _cleanup_free_ char *copy = NULL;
        if (ret) {
                copy = strdup(path);
                if (!copy)
                        return log_oom_debug();
        }

        r = hashmap_ensure_put(fh, &string_hash_ops_free_free, fname, path);
        if (r < 0) {
                assert(r == -ENOMEM);
                return log_oom_debug();
        }
        assert(r > 0);

        log_debug("Inserted replacement: '%s' -> '%s'", fname, path);

        TAKE_PTR(fname);
        TAKE_PTR(path);

        if (ret)
                *ret = TAKE_PTR(copy);
        return 0;
}

static int conf_files_list_impl(
                const char *suffix,
                int rfd,
                const char *root, /* for logging, can be NULL */
                ConfFilesFlags flags,
                const char * const *dirs,
                const char *replacement,
                Hashmap **ret,
                char **ret_inserted) {

        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_set_free_ Set *masked = NULL;
        int r;

        assert(rfd >= 0 || rfd == AT_FDCWD);
        assert(ret);

        _cleanup_free_ char *filename_replacement = NULL, *resolved_dirpath_replacement = NULL, *resolved_replacement = NULL, *inserted = NULL;
        if (replacement) {
                r = path_extract_filename(replacement, &filename_replacement);
                if (r < 0)
                        return r;

                _cleanup_free_ char *d = NULL;
                r = path_extract_directory(replacement, &d);
                if (r < 0)
                        return r;

                r = chaseat(rfd, d, CHASE_AT_RESOLVE_IN_ROOT | CHASE_NONEXISTENT, &resolved_dirpath_replacement, /* ret_fd = */ NULL);
                if (r < 0)
                        return r;

                resolved_replacement = path_join(resolved_dirpath_replacement, filename_replacement);
                if (!resolved_replacement)
                        return log_oom_debug();
        }

        STRV_FOREACH(p, dirs) {
                _cleanup_closedir_ DIR *dir = NULL;
                _cleanup_free_ char *path = NULL;

                r = chase_and_opendirat(rfd, *p, CHASE_AT_RESOLVE_IN_ROOT, &path, &dir);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_debug_errno(r, "Failed to chase and open directory '%s%s', ignoring: %m", strempty(root), *p);
                        continue;
                }

                if (resolved_replacement && path_equal(resolved_dirpath_replacement, path)) {
                        r = insert_replacement(&fh, TAKE_PTR(filename_replacement), TAKE_PTR(resolved_replacement), ret_inserted ? &inserted : NULL);
                        if (r < 0)
                                return r;
                }

                r = files_add(dir, path, rfd, root, &fh, &masked, suffix, flags);
                if (r == -ENOMEM)
                        return r;
        }

        if (resolved_replacement) {
                r = insert_replacement(&fh, TAKE_PTR(filename_replacement), TAKE_PTR(resolved_replacement), ret_inserted ? &inserted : NULL);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(fh);
        if (ret_inserted)
                *ret_inserted = TAKE_PTR(inserted);
        return 0;
}

static int prepare_dirs(const char *root, char * const *dirs, int *ret_rfd, char **ret_root, char ***ret_dirs) {
        _cleanup_free_ char *root_abs = NULL;
        _cleanup_strv_free_ char **dirs_abs = NULL;
        int r;

        assert(ret_rfd);
        assert(ret_root);
        assert(ret_dirs);

        r = empty_or_root_harder_to_null(&root);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine if '%s' points to the root directory: %m", strempty(root));

        dirs_abs = strv_copy(dirs);
        if (!dirs_abs)
                return log_oom();

        if (root) {
                /* WHen a non-trivial root is specified, we will prefix the result later. Hence, it is not
                 * necessary to modify each config directories here. but needs to normalize the root directory. */
                r = path_make_absolute_cwd(root, &root_abs);
                if (r < 0)
                        return log_debug_errno(r, "Failed to make '%s' absolute: %m", root);

                path_simplify(root_abs);
        } else {
                /* When an empty root or "/" is specified, we will open "/" below, hence we need to make
                 * each config directory absolute if relative. */
                r = path_strv_make_absolute_cwd(dirs_abs);
                if (r < 0)
                        return log_debug_errno(r, "Failed to make directories absolute: %m");
        }

        _cleanup_close_ int rfd = open(empty_to_root(root_abs), O_CLOEXEC|O_DIRECTORY|O_PATH);
        if (rfd < 0)
                return log_debug_errno(errno, "Failed to open '%s': %m", empty_to_root(root_abs));

        *ret_rfd = TAKE_FD(rfd);
        *ret_root = TAKE_PTR(root_abs);
        *ret_dirs = TAKE_PTR(dirs_abs);
        return 0;
}

int conf_files_list_strv(
                char ***ret,
                const char *suffix,
                const char *root,
                ConfFilesFlags flags,
                const char * const *dirs) {

        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_close_ int rfd = -EBADF;
        _cleanup_free_ char *root_abs = NULL;
        _cleanup_strv_free_ char **dirs_abs = NULL;
        int r;

        assert(ret);

        r = prepare_dirs(root, (char**) dirs, &rfd, &root_abs, &dirs_abs);
        if (r < 0)
                return r;

        r = conf_files_list_impl(suffix, rfd, root_abs, flags, (const char * const *) dirs_abs,
                                 /* replacement = */ NULL, &fh, /* ret_inserted = */ NULL);
        if (r < 0)
                return r;

        return copy_and_sort_files_from_hashmap(fh, empty_to_root(root_abs), flags, ret);
}

int conf_files_list_strv_at(
                char ***ret,
                const char *suffix,
                int rfd,
                ConfFilesFlags flags,
                const char * const *dirs) {

        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_free_ char *root = NULL;
        int r;

        assert(rfd >= 0 || rfd == AT_FDCWD);
        assert(ret);

        if (rfd >= 0 && DEBUG_LOGGING)
                (void) fd_get_path(rfd, &root); /* for logging */

        r = conf_files_list_impl(suffix, rfd, root, flags, dirs, /* replacement = */ NULL, &fh, /* ret_inserted = */ NULL);
        if (r < 0)
                return r;

        return copy_and_sort_files_from_hashmap(fh, /* root = */ NULL, flags, ret);
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

int conf_files_list_with_replacement(
                const char *root,
                char **config_dirs,
                const char *replacement,
                char ***ret_files,
                char **ret_inserted) {

        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_free_ char *inserted = NULL;
        ConfFilesFlags flags = CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED_BY_SYMLINK;
        _cleanup_close_ int rfd = -EBADF;
        _cleanup_free_ char *root_abs = NULL;
        _cleanup_strv_free_ char **dirs_abs = NULL;
        int r;

        assert(ret_files);

        r = prepare_dirs(root, config_dirs, &rfd, &root_abs, &dirs_abs);
        if (r < 0)
                return r;

        r = conf_files_list_impl(".conf", rfd, root_abs, flags, (const char * const *) dirs_abs,
                                 replacement, &fh, ret_inserted ? &inserted : NULL);
        if (r < 0)
                return r;

        if (inserted) {
                char *p;

                r = chaseat_prefix_root(inserted, root_abs, &p);
                if (r < 0)
                        return log_debug_errno(r, "Failed to prefix '%s' with root '%s': %m", inserted, empty_to_root(root_abs));

                free_and_replace(inserted, p);
        }

        r = copy_and_sort_files_from_hashmap(fh, empty_to_root(root_abs), flags, ret_files);
        if (r < 0)
                return r;

        if (ret_inserted)
                *ret_inserted = TAKE_PTR(inserted);
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
