/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "install.h"
#include "log.h"
#include "macro.h"
#include "mkdir.h"
#include "path-lookup.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static int user_runtime_dir(char **ret, const char *suffix) {
        const char *e;
        char *j;

        assert(ret);
        assert(suffix);

        e = getenv("XDG_RUNTIME_DIR");
        if (!e)
                return -ENXIO;

        j = strappend(e, suffix);
        if (!j)
                return -ENOMEM;

        *ret = j;
        return 0;
}

static int user_config_dir(char **ret, const char *suffix) {
        const char *e;
        char *j;

        assert(ret);

        e = getenv("XDG_CONFIG_HOME");
        if (e)
                j = strappend(e, suffix);
        else {
                const char *home;

                home = getenv("HOME");
                if (!home)
                        return -ENXIO;

                j = strjoin(home, "/.config", suffix, NULL);
        }

        if (!j)
                return -ENOMEM;

        *ret = j;
        return 0;
}

static int user_data_dir(char **ret, const char *suffix) {
        const char *e;
        char *j;

        assert(ret);
        assert(suffix);

        /* We don't treat /etc/xdg/systemd here as the spec
         * suggests because we assume that is a link to
         * /etc/systemd/ anyway. */

        e = getenv("XDG_DATA_HOME");
        if (e)
                j = strappend(e, suffix);
        else {
                const char *home;

                home = getenv("HOME");
                if (!home)
                        return -ENXIO;


                j = strjoin(home, "/.local/share", suffix, NULL);
        }
        if (!j)
                return -ENOMEM;

        *ret = j;
        return 1;
}

static char** user_dirs(
                const char *persistent_config,
                const char *runtime_config,
                const char *generator,
                const char *generator_early,
                const char *generator_late,
                const char *transient,
                const char *persistent_control,
                const char *runtime_control) {

        const char * const config_unit_paths[] = {
                USER_CONFIG_UNIT_PATH,
                "/etc/systemd/user",
                NULL
        };

        const char * const data_unit_paths[] = {
                "/usr/local/lib/systemd/user",
                "/usr/local/share/systemd/user",
                USER_DATA_UNIT_PATH,
                "/usr/lib/systemd/user",
                "/usr/share/systemd/user",
                NULL
        };

        const char *e;
        _cleanup_strv_free_ char **config_dirs = NULL, **data_dirs = NULL;
        _cleanup_free_ char *data_home = NULL;
        _cleanup_free_ char **res = NULL;
        char **tmp;
        int r;

        /* Implement the mechanisms defined in
         *
         * http://standards.freedesktop.org/basedir-spec/basedir-spec-0.6.html
         *
         * We look in both the config and the data dirs because we
         * want to encourage that distributors ship their unit files
         * as data, and allow overriding as configuration.
         */

        e = getenv("XDG_CONFIG_DIRS");
        if (e) {
                config_dirs = strv_split(e, ":");
                if (!config_dirs)
                        return NULL;
        }

        r = user_data_dir(&data_home, "/systemd/user");
        if (r < 0 && r != -ENXIO)
                return NULL;

        e = getenv("XDG_DATA_DIRS");
        if (e)
                data_dirs = strv_split(e, ":");
        else
                data_dirs = strv_new("/usr/local/share",
                                     "/usr/share",
                                     NULL);
        if (!data_dirs)
                return NULL;

        /* Now merge everything we found. */
        if (strv_extend(&res, persistent_control) < 0)
                return NULL;

        if (strv_extend(&res, runtime_control) < 0)
                return NULL;

        if (strv_extend(&res, transient) < 0)
                return NULL;

        if (strv_extend(&res, generator_early) < 0)
                return NULL;

        if (!strv_isempty(config_dirs))
                if (strv_extend_strv_concat(&res, config_dirs, "/systemd/user") < 0)
                        return NULL;

        if (strv_extend(&res, persistent_config) < 0)
                return NULL;

        if (strv_extend_strv(&res, (char**) config_unit_paths, false) < 0)
                return NULL;

        if (strv_extend(&res, runtime_config) < 0)
                return NULL;

        if (strv_extend(&res, generator) < 0)
                return NULL;

        if (strv_extend(&res, data_home) < 0)
                return NULL;

        if (!strv_isempty(data_dirs))
                if (strv_extend_strv_concat(&res, data_dirs, "/systemd/user") < 0)
                        return NULL;

        if (strv_extend_strv(&res, (char**) data_unit_paths, false) < 0)
                return NULL;

        if (strv_extend(&res, generator_late) < 0)
                return NULL;

        if (path_strv_make_absolute_cwd(res) < 0)
                return NULL;

        tmp = res;
        res = NULL;
        return tmp;
}

static int acquire_generator_dirs(
                UnitFileScope scope,
                char **generator,
                char **generator_early,
                char **generator_late) {

        _cleanup_free_ char *x = NULL, *y = NULL, *z = NULL;
        const char *prefix;

        assert(generator);
        assert(generator_early);
        assert(generator_late);

        switch (scope) {

        case UNIT_FILE_SYSTEM:
                prefix = "/run/systemd/";
                break;

        case UNIT_FILE_USER: {
                const char *e;

                e = getenv("XDG_RUNTIME_DIR");
                if (!e)
                        return -ENXIO;

                prefix = strjoina(e, "/systemd/");
                break;
        }

        case UNIT_FILE_GLOBAL:
                return -EOPNOTSUPP;

        default:
                assert_not_reached("Hmm, unexpected scope value.");
        }

        x = strappend(prefix, "generator");
        if (!x)
                return -ENOMEM;

        y = strappend(prefix, "generator.early");
        if (!y)
                return -ENOMEM;

        z = strappend(prefix, "generator.late");
        if (!z)
                return -ENOMEM;

        *generator = x;
        *generator_early = y;
        *generator_late = z;

        x = y = z = NULL;
        return 0;
}

static int acquire_transient_dir(UnitFileScope scope, char **ret) {
        assert(ret);

        switch (scope) {

        case UNIT_FILE_SYSTEM: {
                char *transient;

                transient = strdup("/run/systemd/transient");
                if (!transient)
                        return -ENOMEM;

                *ret = transient;
                return 0;
        }

        case UNIT_FILE_USER:
                return user_runtime_dir(ret, "/systemd/transient");

        case UNIT_FILE_GLOBAL:
                return -EOPNOTSUPP;

        default:
                assert_not_reached("Hmm, unexpected scope value.");
        }
}

static int acquire_config_dirs(UnitFileScope scope, char **persistent, char **runtime) {
        _cleanup_free_ char *a = NULL, *b = NULL;
        int r;

        assert(persistent);
        assert(runtime);

        switch (scope) {

        case UNIT_FILE_SYSTEM:
                a = strdup(SYSTEM_CONFIG_UNIT_PATH);
                b = strdup("/run/systemd/system");
                break;

        case UNIT_FILE_GLOBAL:
                a = strdup(USER_CONFIG_UNIT_PATH);
                b = strdup("/run/systemd/user");
                break;

        case UNIT_FILE_USER:
                r = user_config_dir(&a, "/systemd/user");
                if (r < 0)
                        return r;

                r = user_runtime_dir(runtime, "/systemd/user");
                if (r < 0)
                        return r;

                *persistent = a;
                a = NULL;

                return 0;

        default:
                assert_not_reached("Hmm, unexpected scope value.");
        }

        if (!a || !b)
                return -ENOMEM;

        *persistent = a;
        *runtime = b;
        a = b = NULL;

        return 0;
}

static int acquire_control_dirs(UnitFileScope scope, char **persistent, char **runtime) {
        _cleanup_free_ char *a = NULL;
        int r;

        assert(persistent);
        assert(runtime);

        switch (scope) {

        case UNIT_FILE_SYSTEM:  {
                _cleanup_free_ char *b = NULL;

                a = strdup("/etc/systemd/system.control");
                if (!a)
                        return -ENOMEM;

                b = strdup("/run/systemd/system.control");
                if (!b)
                        return -ENOMEM;

                *runtime = b;
                b = NULL;

                break;
        }

        case UNIT_FILE_USER:
                r = user_config_dir(&a, "/systemd/system.control");
                if (r < 0)
                        return r;

                r = user_runtime_dir(runtime, "/systemd/system.control");
                if (r < 0)
                        return r;

                break;

        case UNIT_FILE_GLOBAL:
                return -EOPNOTSUPP;

        default:
                assert_not_reached("Hmm, unexpected scope value.");
        }

        *persistent = a;
        a = NULL;

        return 0;
}

static int patch_root_prefix(char **p, const char *root_dir) {
        char *c;

        assert(p);

        if (!*p)
                return 0;

        c = prefix_root(root_dir, *p);
        if (!c)
                return -ENOMEM;

        free(*p);
        *p = c;

        return 0;
}

static int patch_root_prefix_strv(char **l, const char *root_dir) {
        char **i;
        int r;

        if (!root_dir)
                return 0;

        STRV_FOREACH(i, l) {
                r = patch_root_prefix(i, root_dir);
                if (r < 0)
                        return r;
        }

        return 0;
}

int lookup_paths_init(
                LookupPaths *p,
                UnitFileScope scope,
                LookupPathsFlags flags,
                const char *root_dir) {

        _cleanup_free_ char
                *root = NULL,
                *persistent_config = NULL, *runtime_config = NULL,
                *generator = NULL, *generator_early = NULL, *generator_late = NULL,
                *transient = NULL,
                *persistent_control = NULL, *runtime_control = NULL;
        bool append = false; /* Add items from SYSTEMD_UNIT_PATH before normal directories */
        _cleanup_strv_free_ char **paths = NULL;
        const char *e;
        int r;

        assert(p);
        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        if (!isempty(root_dir) && !path_equal(root_dir, "/")) {
                if (scope == UNIT_FILE_USER)
                        return -EINVAL;

                r = is_dir(root_dir, true);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOTDIR;

                root = strdup(root_dir);
                if (!root)
                        return -ENOMEM;
        }

        r = acquire_config_dirs(scope, &persistent_config, &runtime_config);
        if (r < 0 && r != -ENXIO)
                return r;

        if ((flags & LOOKUP_PATHS_EXCLUDE_GENERATED) == 0) {
                r = acquire_generator_dirs(scope, &generator, &generator_early, &generator_late);
                if (r < 0 && r != -EOPNOTSUPP && r != -ENXIO)
                        return r;
        }

        r = acquire_transient_dir(scope, &transient);
        if (r < 0 && r != -EOPNOTSUPP && r != -ENXIO)
                return r;

        r = acquire_control_dirs(scope, &persistent_control, &runtime_control);
        if (r < 0 && r != -EOPNOTSUPP && r != -ENXIO)
                return r;

        /* First priority is whatever has been passed to us via env vars */
        e = getenv("SYSTEMD_UNIT_PATH");
        if (e) {
                const char *k;

                k = endswith(e, ":");
                if (k) {
                        e = strndupa(e, k - e);
                        append = true;
                }

                /* FIXME: empty components in other places should be
                 * rejected. */

                r = path_split_and_make_absolute(e, &paths);
                if (r < 0)
                        return r;
        }

        if (!paths || append) {
                /* Let's figure something out. */

                _cleanup_strv_free_ char **add = NULL;

                /* For the user units we include share/ in the search
                 * path in order to comply with the XDG basedir spec.
                 * For the system stuff we avoid such nonsense. OTOH
                 * we include /lib in the search path for the system
                 * stuff but avoid it for user stuff. */

                switch (scope) {

                case UNIT_FILE_SYSTEM:
                        add = strv_new(
                                        /* If you modify this you also want to modify
                                         * systemdsystemunitpath= in systemd.pc.in! */
                                        STRV_IFNOTNULL(persistent_control),
                                        STRV_IFNOTNULL(runtime_control),
                                        STRV_IFNOTNULL(transient),
                                        STRV_IFNOTNULL(generator_early),
                                        persistent_config,
                                        SYSTEM_CONFIG_UNIT_PATH,
                                        "/etc/systemd/system",
                                        runtime_config,
                                        "/run/systemd/system",
                                        STRV_IFNOTNULL(generator),
                                        "/usr/local/lib/systemd/system",
                                        SYSTEM_DATA_UNIT_PATH,
                                        "/usr/lib/systemd/system",
#ifdef HAVE_SPLIT_USR
                                        "/lib/systemd/system",
#endif
                                        STRV_IFNOTNULL(generator_late),
                                        NULL);
                        break;

                case UNIT_FILE_GLOBAL:
                        add = strv_new(
                                        /* If you modify this you also want to modify
                                         * systemduserunitpath= in systemd.pc.in, and
                                         * the arrays in user_dirs() above! */
                                        STRV_IFNOTNULL(persistent_control),
                                        STRV_IFNOTNULL(runtime_control),
                                        STRV_IFNOTNULL(transient),
                                        STRV_IFNOTNULL(generator_early),
                                        persistent_config,
                                        USER_CONFIG_UNIT_PATH,
                                        "/etc/systemd/user",
                                        runtime_config,
                                        "/run/systemd/user",
                                        STRV_IFNOTNULL(generator),
                                        "/usr/local/lib/systemd/user",
                                        "/usr/local/share/systemd/user",
                                        USER_DATA_UNIT_PATH,
                                        "/usr/lib/systemd/user",
                                        "/usr/share/systemd/user",
                                        STRV_IFNOTNULL(generator_late),
                                        NULL);
                        break;

                case UNIT_FILE_USER:
                        add = user_dirs(persistent_config, runtime_config,
                                        generator, generator_early, generator_late,
                                        transient,
                                        persistent_config, runtime_control);
                        break;

                default:
                        assert_not_reached("Hmm, unexpected scope?");
                }

                if (!add)
                        return -ENOMEM;

                if (paths) {
                        r = strv_extend_strv(&paths, add, true);
                        if (r < 0)
                                return r;
                } else {
                        /* Small optimization: if paths is NULL (and it usually is), we can simply assign 'add' to it,
                         * and don't have to copy anything */
                        paths = add;
                        add = NULL;
                }
        }

        r = patch_root_prefix(&persistent_config, root);
        if (r < 0)
                return r;
        r = patch_root_prefix(&runtime_config, root);
        if (r < 0)
                return r;

        r = patch_root_prefix(&generator, root);
        if (r < 0)
                return r;
        r = patch_root_prefix(&generator_early, root);
        if (r < 0)
                return r;
        r = patch_root_prefix(&generator_late, root);
        if (r < 0)
                return r;

        r = patch_root_prefix(&transient, root);
        if (r < 0)
                return r;

        r = patch_root_prefix(&persistent_control, root);
        if (r < 0)
                return r;

        r = patch_root_prefix(&runtime_control, root);
        if (r < 0)
                return r;

        r = patch_root_prefix_strv(paths, root);
        if (r < 0)
                return -ENOMEM;

        p->search_path = strv_uniq(paths);
        paths = NULL;

        p->persistent_config = persistent_config;
        p->runtime_config = runtime_config;
        persistent_config = runtime_config = NULL;

        p->generator = generator;
        p->generator_early = generator_early;
        p->generator_late = generator_late;
        generator = generator_early = generator_late = NULL;

        p->transient = transient;
        transient = NULL;

        p->persistent_control = persistent_control;
        p->runtime_control = runtime_control;
        persistent_control = runtime_control = NULL;

        p->root_dir = root;
        root = NULL;

        return 0;
}

void lookup_paths_free(LookupPaths *p) {
        if (!p)
                return;

        p->search_path = strv_free(p->search_path);

        p->persistent_config = mfree(p->persistent_config);
        p->runtime_config = mfree(p->runtime_config);

        p->generator = mfree(p->generator);
        p->generator_early = mfree(p->generator_early);
        p->generator_late = mfree(p->generator_late);

        p->transient = mfree(p->transient);

        p->persistent_control = mfree(p->persistent_control);
        p->runtime_control = mfree(p->runtime_control);

        p->root_dir = mfree(p->root_dir);
}

int lookup_paths_reduce(LookupPaths *p) {
        _cleanup_free_ struct stat *stats = NULL;
        size_t n_stats = 0, allocated = 0;
        unsigned c = 0;
        int r;

        assert(p);

        /* Drop duplicates and non-existing directories from the search path. We figure out whether two directories are
         * the same by comparing their device and inode numbers. Note one special tweak: when we have a root path set,
         * we do not follow symlinks when retrieving them, because the kernel wouldn't take the root prefix into
         * account when following symlinks. When we have no root path set this restriction does not apply however. */

        if (!p->search_path)
                return 0;

        while (p->search_path[c]) {
                struct stat st;
                unsigned k;

                if (p->root_dir)
                        r = lstat(p->search_path[c], &st);
                else
                        r = stat(p->search_path[c], &st);
                if (r < 0) {
                        if (errno == ENOENT)
                                goto remove_item;

                        /* If something we don't grok happened, let's better leave it in. */
                        log_debug_errno(errno, "Failed to stat %s: %m", p->search_path[c]);
                        c++;
                        continue;
                }

                for (k = 0; k < n_stats; k++) {
                        if (stats[k].st_dev == st.st_dev &&
                            stats[k].st_ino == st.st_ino)
                                break;
                }

                if (k < n_stats) /* Is there already an entry with the same device/inode? */
                        goto remove_item;

                if (!GREEDY_REALLOC(stats, allocated, n_stats+1))
                        return -ENOMEM;

                stats[n_stats++] = st;
                c++;
                continue;

        remove_item:
                free(p->search_path[c]);
                memmove(p->search_path + c,
                        p->search_path + c + 1,
                        (strv_length(p->search_path + c + 1) + 1) * sizeof(char*));
        }

        if (strv_isempty(p->search_path)) {
                log_debug("Ignoring unit files.");
                p->search_path = strv_free(p->search_path);
        } else {
                _cleanup_free_ char *t;

                t = strv_join(p->search_path, "\n\t");
                if (!t)
                        return -ENOMEM;

                log_debug("Looking for unit files in (higher priority first):\n\t%s", t);
        }

        return 0;
}

int lookup_paths_mkdir_generator(LookupPaths *p) {
        int r, q;

        assert(p);

        if (!p->generator || !p->generator_early || !p->generator_late)
                return -EINVAL;

        r = mkdir_p_label(p->generator, 0755);

        q = mkdir_p_label(p->generator_early, 0755);
        if (q < 0 && r >= 0)
                r = q;

        q = mkdir_p_label(p->generator_late, 0755);
        if (q < 0 && r >= 0)
                r = q;

        return r;
}

void lookup_paths_trim_generator(LookupPaths *p) {
        assert(p);

        /* Trim empty dirs */

        if (p->generator)
                (void) rmdir(p->generator);
        if (p->generator_early)
                (void) rmdir(p->generator_early);
        if (p->generator_late)
                (void) rmdir(p->generator_late);
}

void lookup_paths_flush_generator(LookupPaths *p) {
        assert(p);

        /* Flush the generated unit files in full */

        if (p->generator)
                (void) rm_rf(p->generator, REMOVE_ROOT);
        if (p->generator_early)
                (void) rm_rf(p->generator_early, REMOVE_ROOT);
        if (p->generator_late)
                (void) rm_rf(p->generator_late, REMOVE_ROOT);
}

char **generator_binary_paths(UnitFileScope scope) {

        switch (scope) {

        case UNIT_FILE_SYSTEM:
                return strv_new("/run/systemd/system-generators",
                                "/etc/systemd/system-generators",
                                "/usr/local/lib/systemd/system-generators",
                                SYSTEM_GENERATOR_PATH,
                                NULL);

        case UNIT_FILE_GLOBAL:
        case UNIT_FILE_USER:
                return strv_new("/run/systemd/user-generators",
                                "/etc/systemd/user-generators",
                                "/usr/local/lib/systemd/user-generators",
                                USER_GENERATOR_PATH,
                                NULL);

        default:
                assert_not_reached("Hmm, unexpected scope.");
        }
}
