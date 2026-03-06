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

ConfFile* conf_file_free(ConfFile *c) {
        if (!c)
                return NULL;

        free(c->filename);
        free(c->result);
        free(c->original_path);
        free(c->resolved_path);
        safe_close(c->fd);

        return mfree(c);
}

void conf_file_free_many(ConfFile **array, size_t n) {
        FOREACH_ARRAY(i, array, n)
                conf_file_free(*i);

        free(array);
}

static int conf_files_log_level(ConfFilesFlags flags) {
        return FLAGS_SET(flags, CONF_FILES_WARN) ? LOG_WARNING : LOG_DEBUG;
}

static int prepare_dirs(
                const char *root,
                ConfFilesFlags flags,
                char * const *dirs,
                char **ret_root,
                int *ret_rfd,
                char ***ret_dirs) {

        _cleanup_free_ char *root_abs = NULL;
        _cleanup_strv_free_ char **dirs_abs = NULL;
        int r;

        assert(ret_root);
        assert(ret_rfd);
        assert(ret_dirs || strv_isempty(dirs));

        int log_level = conf_files_log_level(flags);

        r = empty_or_root_harder_to_null(&root);
        if (r < 0)
                return log_full_errno(log_level, r, "Failed to determine if '%s' points to the root directory: %m", strempty(root));

        if (ret_dirs) {
                dirs_abs = strv_copy(dirs);
                if (!dirs_abs)
                        return log_oom_full(log_level);
        }

        _cleanup_close_ int rfd = XAT_FDROOT;
        if (root) {
                /* When a non-trivial root is specified, we will prefix the result later. Hence, it is not
                 * necessary to modify each config directories here. but needs to normalize the root directory. */
                r = path_make_absolute_cwd(root, &root_abs);
                if (r < 0)
                        return log_full_errno(log_level, r, "Failed to make '%s' absolute: %m", root);

                path_simplify(root_abs);

                rfd = open(root, O_CLOEXEC|O_DIRECTORY|O_PATH);
                if (rfd < 0)
                        return log_full_errno(log_level, errno, "Failed to open '%s': %m", root_abs);

        } else if (ret_dirs) {
                /* When an empty root or "/" is specified, we will open "/" below, hence we need to make
                 * each config directory absolute if relative. */
                r = path_strv_make_absolute_cwd(dirs_abs);
                if (r < 0)
                        return log_full_errno(log_level, r, "Failed to make directories absolute: %m");
        }

        *ret_root = TAKE_PTR(root_abs);
        *ret_rfd = TAKE_FD(rfd);
        if (ret_dirs)
                *ret_dirs = TAKE_PTR(dirs_abs);
        return 0;
}

static int conf_file_prefix_root(ConfFile *c, const char *root, ConfFilesFlags flags) {
        char *p;
        int r;

        assert(c);

        int log_level = conf_files_log_level(flags);

        r = chaseat_prefix_root(c->result, root, &p);
        if (r < 0)
                return log_full_errno(log_level, r, "Failed to prefix '%s' with root '%s': %m", c->result, root);
        free_and_replace(c->result, p);

        r = chaseat_prefix_root(c->resolved_path, root, &p);
        if (r < 0)
                return log_full_errno(log_level, r, "Failed to prefix '%s' with root '%s': %m", c->resolved_path, root);
        free_and_replace(c->resolved_path, p);

        /* Do not use chaseat_prefix_root(), as it is for the result of chaseat(), but the path is not chased. */
        p = path_join(empty_to_root(root), skip_leading_slash(c->original_path));
        if (!p)
                return log_oom_full(log_level);

        path_simplify(p);
        return free_and_replace(c->original_path, p);
}

static bool conf_files_need_stat(ConfFilesFlags flags) {
        return (flags & (CONF_FILES_FILTER_MASKED | CONF_FILES_REGULAR | CONF_FILES_DIRECTORY | CONF_FILES_EXECUTABLE)) != 0;
}

static ChaseFlags conf_files_chase_flags(ConfFilesFlags flags) {
        ChaseFlags chase_flags = CHASE_AT_RESOLVE_IN_ROOT;

        if (!conf_files_need_stat(flags) || FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_SYMLINK))
                /* Even if no verification is requested, let's unconditionally call chaseat(),
                 * to drop unsafe symlinks. */
                chase_flags |= CHASE_NONEXISTENT;

        return chase_flags;
}

static int conf_file_chase_and_verify(
                const char *root,          /* for logging, can be NULL */
                int rfd,
                const char *original_path, /* for logging */
                const char *path,
                const char *name,
                Set **masked,              /* optional */
                ConfFilesFlags flags,
                char **ret_path,
                int *ret_fd,
                struct stat *ret_stat) {

        _cleanup_free_ char *resolved_path = NULL;
        _cleanup_close_ int fd = -EBADF;
        struct stat st = {};
        int r;

        assert(rfd >= 0 || IN_SET(rfd, AT_FDCWD, XAT_FDROOT));
        assert(original_path);
        assert(path);
        assert(name);

        int log_level = conf_files_log_level(flags);

        root = empty_to_root(root);

        r = chaseat(rfd, path, conf_files_chase_flags(flags), &resolved_path, &fd);
        if (r < 0)
                return log_full_errno(log_level, r, "Failed to chase '%s%s': %m",
                                      root, skip_leading_slash(original_path));
        if (r == 0) {
                if (FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_SYMLINK)) {
                        /* If the path points to /dev/null in a image or so, then the device node may not exist. */
                        if (path_equal(skip_leading_slash(resolved_path), "dev/null")) {
                                if (masked) {
                                        /* Mark this one as masked */
                                        r = set_put_strdup(masked, name);
                                        if (r < 0)
                                                return log_oom_full(log_level);
                                }

                                return log_debug_errno(SYNTHETIC_ERRNO(ERFKILL),
                                                       "File '%s%s' is a mask (symlink to /dev/null).",
                                                       root, skip_leading_slash(original_path));
                        }
                }

                if (conf_files_need_stat(flags))
                        /* If we need to have stat, skip the entry. */
                        return log_full_errno(log_level, SYNTHETIC_ERRNO(ENOENT), "Failed to chase '%s%s': %m",
                                              root, skip_leading_slash(original_path));
        }

        /* Even if we do not need stat, let's take stat now. The caller may use the info later. */
        if (fd >= 0 && fstat(fd, &st) < 0)
                return log_full_errno(log_level, errno, "Failed to stat '%s%s': %m",
                                      root, skip_leading_slash(original_path));

        /* Is this a masking entry? */
        if (FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_SYMLINK) && stat_may_be_dev_null(&st)) {
                if (masked) {
                        /* Mark this one as masked */
                        r = set_put_strdup(masked, name);
                        if (r < 0)
                                return log_oom_full(log_level);
                }

                return log_debug_errno(SYNTHETIC_ERRNO(ERFKILL),
                                       "File '%s%s' is a mask (symlink to /dev/null).",
                                       root, skip_leading_slash(original_path));
        }

        if (FLAGS_SET(flags, CONF_FILES_FILTER_MASKED_BY_EMPTY) && stat_is_empty(&st)) {
                if (masked) {
                        /* Mark this one as masked */
                        r = set_put_strdup(masked, name);
                        if (r < 0)
                                return log_oom_full(log_level);
                }

                return log_debug_errno(SYNTHETIC_ERRNO(ERFKILL),
                                       "File '%s%s' is a mask (an empty file).",
                                       root, skip_leading_slash(original_path));
        }

        if (FLAGS_SET(flags, CONF_FILES_REGULAR|CONF_FILES_DIRECTORY)) {
                if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADFD),
                                               "File '%s%s' is neither a regular file or directory.",
                                               root, skip_leading_slash(original_path));
        } else {
                /* Is this node a regular file? */
                if (FLAGS_SET(flags, CONF_FILES_REGULAR)) {
                        r = stat_verify_regular(&st);
                        if (r < 0)
                                return log_debug_errno(r, "File '%s%s' is not a regular file: %m",
                                                       root, skip_leading_slash(original_path));
                }

                /* Is this node a directory? */
                if (FLAGS_SET(flags, CONF_FILES_DIRECTORY)) {
                        r = stat_verify_directory(&st);
                        if (r < 0)
                                return log_debug_errno(r, "File '%s%s' is not a directory: %m",
                                                       root, skip_leading_slash(original_path));
                }
        }

        /* Does this node have the executable bit set?
         * As requested: check if the file is marked executable. Note that we don't check access(X_OK) here,
         * as we care about whether the file is marked executable at all, and not whether it is executable
         * for us, because if so, such errors are stuff we should log about. */
        if (FLAGS_SET(flags, CONF_FILES_EXECUTABLE) && (st.st_mode & 0111) == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOEXEC),
                                       "File '%s%s' is not marked executable.",
                                       root, skip_leading_slash(original_path));

        if (ret_path)
                *ret_path = TAKE_PTR(resolved_path);
        if (ret_fd)
                *ret_fd = TAKE_FD(fd);
        if (ret_stat)
                *ret_stat = st;

        return 0;
}

int conf_file_new_at(
                const char *path,
                const char *root,
                int rfd,
                ConfFilesFlags flags,
                ConfFile **ret) {
        int r;

        assert(path);
        assert(rfd >= 0 || IN_SET(rfd, AT_FDCWD, XAT_FDROOT));
        assert(ret);

        int log_level = conf_files_log_level(flags);

        _cleanup_free_ char *_root = NULL;
        if (DEBUG_LOGGING && !root) {
                (void) fd_get_path(rfd, &_root);
                root = _root;
        }

        _cleanup_(conf_file_freep) ConfFile *c = new(ConfFile, 1);
        if (!c)
                return log_oom_full(log_level);

        *c = (ConfFile) {
                .original_path = strdup(path),
                .fd = -EBADF,
        };

        if (!c->original_path)
                return log_oom_full(log_level);

        r = path_extract_filename(path, &c->filename);
        if (r < 0)
                return log_full_errno(log_level, r, "Failed to extract filename from '%s': %m", path);

        _cleanup_free_ char *dirpath = NULL, *resolved_dirpath = NULL;
        r = path_extract_directory(path, &dirpath);
        if (r < 0 && r != -EDESTADDRREQ)
                return log_full_errno(log_level, r, "Failed to extract directory from '%s': %m", path);
        if (r >= 0) {
                r = chaseat(rfd, dirpath,
                            CHASE_MUST_BE_DIRECTORY | conf_files_chase_flags(flags),
                            &resolved_dirpath, /* ret_fd= */ NULL);
                if (r < 0)
                        return log_full_errno(log_level, r, "Failed to chase '%s%s': %m", empty_to_root(root), skip_leading_slash(dirpath));
        }

        c->result = path_join(resolved_dirpath, c->filename);
        if (!c->result)
                return log_oom_full(log_level);

        r = conf_file_chase_and_verify(
                        root,
                        rfd,
                        c->original_path,
                        c->result,
                        c->filename,
                        /* masked= */ NULL,
                        flags,
                        &c->resolved_path,
                        &c->fd,
                        &c->st);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}

int conf_file_new(const char *path, const char *root, ConfFilesFlags flags, ConfFile **ret) {
        int r;

        assert(path);
        assert(ret);

        _cleanup_free_ char *root_abs = NULL;
        _cleanup_close_ int rfd = -EBADF;
        r = prepare_dirs(root, flags, /* dirs= */ NULL, &root_abs, &rfd, /* ret_dirs= */ NULL);
        if (r < 0)
                return r;

        _cleanup_free_ char *path_abs = NULL;
        if (!root_abs) {
                r = path_make_absolute_cwd(path, &path_abs);
                if (r < 0)
                        return log_full_errno(conf_files_log_level(flags), r, "Failed to make '%s' absolute: %m", path);

                path = path_abs;
        }

        _cleanup_(conf_file_freep) ConfFile *c = NULL;
        r = conf_file_new_at(path, root_abs, rfd, flags, &c);
        if (r < 0)
                return r;

        r = conf_file_prefix_root(c, root_abs, flags);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                conf_file_hash_ops,
                char, string_hash_func, string_compare_func,
                ConfFile, conf_file_free);

static int files_add(
                DIR *dir,
                const char *original_dirpath,
                const char *resolved_dirpath,
                const char *root, /* for logging, can be NULL */
                int rfd,
                Hashmap **files,
                Set **masked,
                const char *suffix,
                ConfFilesFlags flags) {

        int r;

        assert(dir);
        assert(original_dirpath);
        assert(resolved_dirpath);
        assert(rfd >= 0 || IN_SET(rfd, AT_FDCWD, XAT_FDROOT));
        assert(files);
        assert(masked);

        int log_level = conf_files_log_level(flags);

        root = empty_to_root(root);

        FOREACH_DIRENT(de, dir, return log_full_errno(log_level, errno, "Failed to read directory '%s%s': %m",
                                                      root, skip_leading_slash(original_dirpath))) {

                _cleanup_free_ char *original_path = path_join(original_dirpath, de->d_name);
                if (!original_path)
                        return log_oom_full(log_level);

                /* Does this match the suffix? */
                if (suffix && !endswith(de->d_name, suffix)) {
                        log_debug("Skipping file '%s%s', suffix is not '%s'.", root, skip_leading_slash(original_path), suffix);
                        continue;
                }

                /* Has this file already been found in an earlier directory? */
                if (hashmap_contains(*files, de->d_name)) {
                        log_debug("Skipping overridden file '%s%s'.", root, skip_leading_slash(original_path));
                        continue;
                }

                /* Has this been masked in an earlier directory? */
                if ((flags & CONF_FILES_FILTER_MASKED) != 0 && set_contains(*masked, de->d_name)) {
                        log_debug("File '%s%s' is masked by previous entry.", root, skip_leading_slash(original_path));
                        continue;
                }

                _cleanup_free_ char *p = path_join(resolved_dirpath, de->d_name);
                if (!p)
                        return log_oom_full(log_level);

                _cleanup_free_ char *resolved_path = NULL;
                _cleanup_close_ int fd = -EBADF;
                struct stat st;
                r = conf_file_chase_and_verify(
                                root,
                                rfd,
                                original_path,
                                p,
                                de->d_name,
                                masked,
                                flags,
                                &resolved_path,
                                &fd,
                                &st);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        continue;

                _cleanup_(conf_file_freep) ConfFile *c = new(ConfFile, 1);
                if (!c)
                        return log_oom_full(log_level);

                *c = (ConfFile) {
                        .filename = strdup(de->d_name),
                        .result = TAKE_PTR(p),
                        .original_path = TAKE_PTR(original_path),
                        .resolved_path = TAKE_PTR(resolved_path),
                        .fd = TAKE_FD(fd),
                        .st = st,
                };

                if (!c->filename)
                        return log_oom_full(log_level);

                r = hashmap_ensure_put(files, &conf_file_hash_ops, c->filename, c);
                if (r < 0) {
                        assert(r == -ENOMEM);
                        return log_oom_full(log_level);
                }
                assert(r > 0);

                TAKE_PTR(c);
        }

        return 0;
}

static int dump_files(Hashmap *fh, const char *root, ConfFilesFlags flags, ConfFile ***ret_files, size_t *ret_n_files) {
        ConfFile **files = NULL;
        size_t n_files = 0;
        int r;

        CLEANUP_ARRAY(files, n_files, conf_file_free_many);

        assert(ret_files);
        assert(ret_n_files);

        /* The entries in the array given by hashmap_dump_sorted() are still owned by the hashmap. */
        r = hashmap_dump_sorted(fh, (void***) &files, &n_files);
        if (r < 0)
                return log_oom_full(conf_files_log_level(flags));

        /* Hence, we need to remove them from the hashmap. */
        FOREACH_ARRAY(i, files, n_files)
                assert_se(hashmap_remove(fh, (*i)->filename) == *i);

        if (root)
                FOREACH_ARRAY(i, files, n_files) {
                        r = conf_file_prefix_root(*i, root, flags);
                        if (r < 0)
                                return r;
                }

        *ret_files = TAKE_PTR(files);
        *ret_n_files = n_files;
        return 0;
}

static int copy_and_sort_files_from_hashmap(
                Hashmap *fh,
                const char *suffix,
                const char *root,
                ConfFilesFlags flags,
                char ***ret) {

        _cleanup_strv_free_ char **results = NULL;
        _cleanup_free_ ConfFile **files = NULL;
        size_t n_files = 0, n_results = 0;
        int r;

        assert(ret);

        int log_level = conf_files_log_level(flags);

        /* The entries in the array given by hashmap_dump_sorted() are still owned by the hashmap.
         * Hence, do not use conf_file_free_many() for 'entries' */
        r = hashmap_dump_sorted(fh, (void***) &files, &n_files);
        if (r < 0)
                return log_oom_full(log_level);

        FOREACH_ARRAY(i, files, n_files) {
                ConfFile *c = *i;
                const char *add = NULL;

                if (FLAGS_SET(flags, CONF_FILES_BASENAME))
                        add = c->filename;
                else if (root && !FLAGS_SET(flags, CONF_FILES_DONT_PREFIX_ROOT)) {
                        _cleanup_free_ char *p = NULL;

                        r = chaseat_prefix_root(c->result, root, &p);
                        if (r < 0)
                                return log_full_errno(log_level, r, "Failed to prefix '%s' with root '%s': %m", c->result, root);

                        if (FLAGS_SET(flags, CONF_FILES_TRUNCATE_SUFFIX) && suffix) {
                                char *e = endswith(p, suffix);
                                if (!e)
                                        continue;

                                *e = 0;
                        }

                        if (strv_consume_with_size(&results, &n_results, TAKE_PTR(p)) < 0)
                                return log_oom_full(log_level);

                        continue;
                } else
                        add = c->result;

                if (FLAGS_SET(flags, CONF_FILES_TRUNCATE_SUFFIX)) {
                        const char *e = endswith(add, suffix);
                        if (!e)
                                continue;

                        _cleanup_free_ char *n = strndup(add, e - add);
                        if (!n)
                                return log_oom_full(log_level);

                        r = strv_consume_with_size(&results, &n_results, TAKE_PTR(n));
                } else
                        r = strv_extend_with_size(&results, &n_results, add);
                if (r < 0)
                        return log_oom_full(log_level);
        }

        *ret = TAKE_PTR(results);
        return 0;
}

static int insert_replacement(Hashmap **fh, ConfFile *replacement, ConfFilesFlags flags, const ConfFile **ret) {
        _cleanup_(conf_file_freep) ConfFile *c = ASSERT_PTR(replacement);
        int r;

        assert(fh);
        assert(ret);

        /* This consumes the input ConfFile. */

        ConfFile *existing = hashmap_get(*fh, c->filename);
        if (existing) {
                log_debug("An entry with higher priority '%s' -> '%s' already exists, ignoring the replacement: %s",
                          existing->filename, existing->result, c->original_path);
                *ret = NULL;
                return 0;
        }

        r = hashmap_ensure_put(fh, &conf_file_hash_ops, c->filename, c);
        if (r < 0) {
                assert(r == -ENOMEM);
                return log_oom_full(conf_files_log_level(flags));
        }
        assert(r > 0);

        log_debug("Inserted replacement: '%s' -> '%s'", c->filename, c->result);

        *ret = TAKE_PTR(c);
        return 0;
}

static int conf_files_list_impl(
                const char *suffix,
                const char *root, /* for logging, can be NULL */
                int rfd,
                ConfFilesFlags flags,
                const char * const *dirs,
                const char *replacement,
                Hashmap **ret,
                const ConfFile **ret_inserted) {

        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_set_free_ Set *masked = NULL;
        _cleanup_(conf_file_freep) ConfFile *c = NULL;
        const ConfFile *inserted = NULL;
        int r;

        assert(rfd >= 0 || IN_SET(rfd, AT_FDCWD, XAT_FDROOT));
        assert(ret);

        root = empty_to_root(root);

        if (replacement) {
                r = conf_file_new_at(replacement, root, rfd, flags & CONF_FILES_WARN, &c);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(p, dirs) {
                _cleanup_closedir_ DIR *dir = NULL;
                _cleanup_free_ char *path = NULL;

                r = chase_and_opendirat(rfd, *p, CHASE_AT_RESOLVE_IN_ROOT, &path, &dir);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_full_errno(conf_files_log_level(flags), r,
                                               "Failed to chase and open directory '%s%s', ignoring: %m",
                                               root, skip_leading_slash(*p));
                        continue;
                }

                if (c && streq_ptr(path_startswith(c->result, path), c->filename)) {
                        r = insert_replacement(&fh, TAKE_PTR(c), flags, &inserted);
                        if (r < 0)
                                return r;
                }

                r = files_add(dir, *p, path, root, rfd, &fh, &masked, suffix, flags);
                if (r == -ENOMEM)
                        return r;
        }

        if (c) {
                r = insert_replacement(&fh, TAKE_PTR(c), flags, &inserted);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(fh);
        if (ret_inserted)
                *ret_inserted = inserted;
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

        r = prepare_dirs(root, flags, (char**) dirs, &root_abs, &rfd, &dirs_abs);
        if (r < 0)
                return r;

        r = conf_files_list_impl(suffix, root_abs, rfd, flags, (const char * const *) dirs_abs,
                                 /* replacement= */ NULL, &fh, /* ret_inserted= */ NULL);
        if (r < 0)
                return r;

        return copy_and_sort_files_from_hashmap(fh, suffix, empty_to_root(root_abs), flags, ret);
}

int conf_files_list_strv_full(
                const char *suffix,
                const char *root,
                ConfFilesFlags flags,
                const char * const *dirs,
                ConfFile ***ret_files,
                size_t *ret_n_files) {

        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_close_ int rfd = -EBADF;
        _cleanup_free_ char *root_abs = NULL;
        _cleanup_strv_free_ char **dirs_abs = NULL;
        int r;

        assert(ret_files);
        assert(ret_n_files);

        r = prepare_dirs(root, flags, (char**) dirs, &root_abs, &rfd, &dirs_abs);
        if (r < 0)
                return r;

        r = conf_files_list_impl(suffix, root_abs, rfd, flags, (const char * const *) dirs_abs,
                                 /* replacement= */ NULL, &fh, /* ret_inserted= */ NULL);
        if (r < 0)
                return r;

        return dump_files(fh, empty_to_root(root_abs), flags, ret_files, ret_n_files);
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

        assert(rfd >= 0 || IN_SET(rfd, AT_FDCWD, XAT_FDROOT));
        assert(ret);

        if (DEBUG_LOGGING)
                (void) fd_get_path(rfd, &root); /* for logging */

        r = conf_files_list_impl(suffix, root, rfd, flags, dirs, /* replacement= */ NULL, &fh, /* ret_inserted= */ NULL);
        if (r < 0)
                return r;

        return copy_and_sort_files_from_hashmap(fh, suffix, /* root= */ NULL, flags, ret);
}

int conf_files_list_strv_at_full(
                const char *suffix,
                int rfd,
                ConfFilesFlags flags,
                const char * const *dirs,
                ConfFile ***ret_files,
                size_t *ret_n_files) {

        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_free_ char *root = NULL;
        int r;

        assert(rfd >= 0 || IN_SET(rfd, AT_FDCWD, XAT_FDROOT));
        assert(ret_files);
        assert(ret_n_files);

        if (DEBUG_LOGGING)
                (void) fd_get_path(rfd, &root); /* for logging */

        r = conf_files_list_impl(suffix, root, rfd, flags, dirs, /* replacement= */ NULL, &fh, /* ret_inserted= */ NULL);
        if (r < 0)
                return r;

        return dump_files(fh, /* root= */ NULL, flags, ret_files, ret_n_files);
}

int conf_files_list(char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char *dir) {
        return conf_files_list_strv(ret, suffix, root, flags, STRV_MAKE_CONST(dir));
}

int conf_files_list_full(const char *suffix, const char *root, ConfFilesFlags flags, const char *dir, ConfFile ***ret_files, size_t *ret_n_files) {
        return conf_files_list_strv_full(suffix, root, flags, STRV_MAKE_CONST(dir), ret_files, ret_n_files);
}

int conf_files_list_at(char ***ret, const char *suffix, int rfd, ConfFilesFlags flags, const char *dir) {
        return conf_files_list_strv_at(ret, suffix, rfd, flags, STRV_MAKE_CONST(dir));
}

int conf_files_list_at_full(const char *suffix, int rfd, ConfFilesFlags flags, const char *dir, ConfFile ***ret_files, size_t *ret_n_files) {
        return conf_files_list_strv_at_full(suffix, rfd, flags, STRV_MAKE_CONST(dir), ret_files, ret_n_files);
}

int conf_files_list_nulstr(char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char *dirs) {
        _cleanup_strv_free_ char **d = NULL;

        assert(ret);

        d = strv_split_nulstr(dirs);
        if (!d)
                return log_oom_full(conf_files_log_level(flags));

        return conf_files_list_strv(ret, suffix, root, flags, (const char**) d);
}

int conf_files_list_nulstr_full(const char *suffix, const char *root, ConfFilesFlags flags, const char *dirs, ConfFile ***ret_files, size_t *ret_n_files) {
        _cleanup_strv_free_ char **d = NULL;

        assert(ret_files);
        assert(ret_n_files);

        d = strv_split_nulstr(dirs);
        if (!d)
                return log_oom_full(conf_files_log_level(flags));

        return conf_files_list_strv_full(suffix, root, flags, (const char**) d, ret_files, ret_n_files);
}

int conf_files_list_nulstr_at(char ***ret, const char *suffix, int rfd, ConfFilesFlags flags, const char *dirs) {
        _cleanup_strv_free_ char **d = NULL;

        assert(ret);

        d = strv_split_nulstr(dirs);
        if (!d)
                return log_oom_full(conf_files_log_level(flags));

        return conf_files_list_strv_at(ret, suffix, rfd, flags, (const char**) d);
}

int conf_files_list_nulstr_at_full(const char *suffix, int rfd, ConfFilesFlags flags, const char *dirs, ConfFile ***ret_files, size_t *ret_n_files) {
        _cleanup_strv_free_ char **d = NULL;

        assert(ret_files);
        assert(ret_n_files);

        d = strv_split_nulstr(dirs);
        if (!d)
                return log_oom_full(conf_files_log_level(flags));

        return conf_files_list_strv_at_full(suffix, rfd, flags, (const char**) d, ret_files, ret_n_files);
}

int conf_files_list_with_replacement(
                const char *root,
                char **config_dirs,
                const char *replacement,
                char ***ret_files,
                char **ret_inserted) {

        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_free_ char *inserted = NULL;
        ConfFilesFlags flags = CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED_BY_SYMLINK | CONF_FILES_WARN;
        _cleanup_close_ int rfd = -EBADF;
        _cleanup_free_ char *root_abs = NULL;
        _cleanup_strv_free_ char **dirs_abs = NULL;
        const ConfFile *c = NULL;
        int r;

        assert(ret_files);

        r = prepare_dirs(root, flags, config_dirs, &root_abs, &rfd, &dirs_abs);
        if (r < 0)
                return r;

        r = conf_files_list_impl(".conf", root_abs, rfd, flags, (const char * const *) dirs_abs,
                                 replacement, &fh, ret_inserted ? &c : NULL);
        if (r < 0)
                return r;

        if (c) {
                r = chaseat_prefix_root(c->result, root_abs, &inserted);
                if (r < 0)
                        return log_full_errno(conf_files_log_level(flags), r,
                                              "Failed to prefix '%s' with root '%s': %m",
                                              c->result, empty_to_root(root_abs));
        }

        r = copy_and_sort_files_from_hashmap(fh, ".conf", empty_to_root(root_abs), flags, ret_files);
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
                int root_fd,
                ConfFilesFlags flags,
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
                return log_oom_full(conf_files_log_level(flags));

        return conf_files_list_strv_at(ret, ".conf", root_fd, flags, (const char* const*) dropin_dirs);
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
