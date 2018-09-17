/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf-files.h"
#include "def.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "path-util.h"
#include "set.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "util.h"

static int files_add(
                Hashmap *h,
                Set *masked,
                const char *suffix,
                const char *root,
                unsigned flags,
                const char *path) {

        _cleanup_closedir_ DIR *dir = NULL;
        const char *dirpath;
        struct dirent *de;
        int r;

        assert(h);
        assert((flags & CONF_FILES_FILTER_MASKED) == 0 || masked);
        assert(path);

        dirpath = prefix_roota(root, path);

        dir = opendir(dirpath);
        if (!dir) {
                if (errno == ENOENT)
                        return 0;

                return log_debug_errno(errno, "Failed to open directory '%s': %m", dirpath);
        }

        FOREACH_DIRENT(de, dir, return -errno) {
                struct stat st;
                char *p, *key;

                /* Does this match the suffix? */
                if (suffix && !endswith(de->d_name, suffix))
                        continue;

                /* Has this file already been found in an earlier directory? */
                if (hashmap_contains(h, de->d_name)) {
                        log_debug("Skipping overridden file '%s/%s'.", dirpath, de->d_name);
                        continue;
                }

                /* Has this been masked in an earlier directory? */
                if ((flags & CONF_FILES_FILTER_MASKED) && set_contains(masked, de->d_name)) {
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
                                log_debug("Ignoring '%s/%s', as it is not a of the right type.", dirpath, de->d_name);
                                continue;
                        }

                /* Does this node have the executable bit set? */
                if (flags & CONF_FILES_EXECUTABLE)
                        /* As requested: check if the file is marked exectuable. Note that we don't check access(X_OK)
                         * here, as we care about whether the file is marked executable at all, and not whether it is
                         * executable for us, because if so, such errors are stuff we should log about. */

                        if ((st.st_mode & 0111) == 0) { /* not executable */
                                log_debug("Ignoring '%s/%s', as it is not marked executable.", dirpath, de->d_name);
                                continue;
                        }

                if (flags & CONF_FILES_BASENAME) {
                        p = strdup(de->d_name);
                        if (!p)
                                return -ENOMEM;

                        key = p;
                } else {
                        p = strjoin(dirpath, "/", de->d_name);
                        if (!p)
                                return -ENOMEM;

                        key = basename(p);
                }

                r = hashmap_put(h, key, p);
                if (r < 0) {
                        free(p);
                        return log_debug_errno(r, "Failed to add item to hashmap: %m");
                }

                assert(r > 0);
        }

        return 0;
}

static int base_cmp(char * const *a, char * const *b) {
        return strcmp(basename(*a), basename(*b));
}

static int conf_files_list_strv_internal(char ***strv, const char *suffix, const char *root, unsigned flags, char **dirs) {
        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_set_free_free_ Set *masked = NULL;
        char **files, **p;
        int r;

        assert(strv);

        /* This alters the dirs string array */
        if (!path_strv_resolve_uniq(dirs, root))
                return -ENOMEM;

        fh = hashmap_new(&path_hash_ops);
        if (!fh)
                return -ENOMEM;

        if (flags & CONF_FILES_FILTER_MASKED) {
                masked = set_new(&path_hash_ops);
                if (!masked)
                        return -ENOMEM;
        }

        STRV_FOREACH(p, dirs) {
                r = files_add(fh, masked, suffix, root, flags, *p);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to search for files in %s, ignoring: %m", *p);
        }

        files = hashmap_get_strv(fh);
        if (!files)
                return -ENOMEM;

        typesafe_qsort(files, hashmap_size(fh), base_cmp);
        *strv = files;

        return 0;
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
        size_t i;
        char *t;
        int r;

        for (i = 0; i < strv_length(*strv); i++) {
                int c;

                c = base_cmp((char* const*) *strv + i, (char* const*) &path);
                if (c == 0) {
                        char **dir;

                        /* Oh, we found our spot and it already contains something. */
                        STRV_FOREACH(dir, dirs) {
                                char *p1, *p2;

                                p1 = path_startswith((*strv)[i], root);
                                if (p1)
                                        /* Skip "/" in *dir, because p1 is without "/" too */
                                        p1 = path_startswith(p1, *dir + 1);
                                if (p1)
                                        /* Existing entry with higher priority
                                         * or same priority, no need to do anything. */
                                        return 0;

                                p2 = path_startswith(path, *dir);
                                if (p2) {
                                        /* Our new entry has higher priority */
                                        t = path_join(root, path, NULL);
                                        if (!t)
                                                return log_oom();

                                        return free_and_replace((*strv)[i], t);
                                }
                        }

                } else if (c > 0)
                        /* Following files have lower priority, let's go insert our
                         * new entry. */
                        break;

                /* … we are not there yet, let's continue */
        }

        t = path_join(root, path, NULL);
        if (!t)
                return log_oom();

        r = strv_insert(strv, i, t);
        if (r < 0)
                free(t);
        return r;
}

int conf_files_insert_nulstr(char ***strv, const char *root, const char *dirs, const char *path) {
        _cleanup_strv_free_ char **d = NULL;

        assert(strv);

        d = strv_split_nulstr(dirs);
        if (!d)
                return -ENOMEM;

        return conf_files_insert(strv, root, d, path);
}

int conf_files_list_strv(char ***strv, const char *suffix, const char *root, unsigned flags, const char* const* dirs) {
        _cleanup_strv_free_ char **copy = NULL;

        assert(strv);

        copy = strv_copy((char**) dirs);
        if (!copy)
                return -ENOMEM;

        return conf_files_list_strv_internal(strv, suffix, root, flags, copy);
}

int conf_files_list(char ***strv, const char *suffix, const char *root, unsigned flags, const char *dir, ...) {
        _cleanup_strv_free_ char **dirs = NULL;
        va_list ap;

        assert(strv);

        va_start(ap, dir);
        dirs = strv_new_ap(dir, ap);
        va_end(ap);

        if (!dirs)
                return -ENOMEM;

        return conf_files_list_strv_internal(strv, suffix, root, flags, dirs);
}

int conf_files_list_nulstr(char ***strv, const char *suffix, const char *root, unsigned flags, const char *dirs) {
        _cleanup_strv_free_ char **d = NULL;

        assert(strv);

        d = strv_split_nulstr(dirs);
        if (!d)
                return -ENOMEM;

        return conf_files_list_strv_internal(strv, suffix, root, flags, d);
}

int conf_files_list_with_replacement(
                const char *root,
                char **config_dirs,
                const char *replacement,
                char ***files,
                char **replace_file) {

        _cleanup_strv_free_ char **f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(config_dirs);
        assert(files);
        assert(replace_file || !replacement);

        r = conf_files_list_strv(&f, ".conf", root, 0, (const char* const*) config_dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate config files: %m");

        if (replacement) {
                r = conf_files_insert(&f, root, config_dirs, replacement);
                if (r < 0)
                        return log_error_errno(r, "Failed to extend config file list: %m");

                p = path_join(root, replacement, NULL);
                if (!p)
                        return log_oom();
        }

        *files = TAKE_PTR(f);
        if (replace_file)
                *replace_file = TAKE_PTR(p);
        return 0;
}

int conf_files_cat(const char *root, const char *name) {
        _cleanup_strv_free_ char **dirs = NULL, **files = NULL;
        _cleanup_free_ char *path = NULL;
        const char *dir;
        char **t;
        int r;

        NULSTR_FOREACH(dir, CONF_PATHS_NULSTR("")) {
                assert(endswith(dir, "/"));
                r = strv_extendf(&dirs, "%s%s.d", dir, name);
                if (r < 0)
                        return log_error_errno(r, "Failed to build directory list: %m");
        }

        r = conf_files_list_strv(&files, ".conf", root, 0, (const char* const*) dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to query file list: %m");

        path = path_join(root, "/etc", name);
        if (!path)
                return log_oom();

        if (DEBUG_LOGGING) {
                log_debug("Looking for configuration in:");
                log_debug("   %s", path);
                STRV_FOREACH(t, dirs)
                        log_debug("   %s/*.conf", *t);
        }

        /* show */
        return cat_files(path, files, CAT_FLAGS_MAIN_FILE_OPTIONAL);
}
