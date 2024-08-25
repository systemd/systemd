/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "nulstr-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"

int runtime_directory(RuntimeScope scope, const char *suffix, char **ret) {
        int r;

        assert(IN_SET(scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER));
        assert(suffix);
        assert(ret);

        /* Accept $RUNTIME_DIRECTORY as authoritative
         * If its missing apply the suffix to /run/, or $XDG_RUNTIME_DIR if we are in a user runtime scope.
         *
         * Return value indicates whether the suffix was applied or not */

        const char *e = secure_getenv("RUNTIME_DIRECTORY");
        if (e)
                return strdup_to(ret, e);

        if (scope == RUNTIME_SCOPE_USER) {
                r = xdg_user_runtime_dir(suffix, ret);
                if (r < 0)
                        return r;
        } else {
                char *d = path_join("/run", suffix);
                if (!d)
                        return -ENOMEM;
                *ret = d;
        }

        return 1;
}

static const char* const user_data_unit_paths[] = {
        "/usr/local/lib/systemd/user",
        "/usr/local/share/systemd/user",
        USER_DATA_UNIT_DIR,
        "/usr/lib/systemd/user",
        "/usr/share/systemd/user",
        NULL
};

static const char* const user_config_unit_paths[] = {
        USER_CONFIG_UNIT_DIR,
        "/etc/systemd/user",
        NULL
};

int xdg_user_dirs(char ***ret_config_dirs, char ***ret_data_dirs) {
        /* Implement the mechanisms defined in
         *
         * https://standards.freedesktop.org/basedir-spec/basedir-spec-0.6.html
         *
         * We look in both the config and the data dirs because we
         * want to encourage that distributors ship their unit files
         * as data, and allow overriding as configuration.
         */
        const char *e;
        _cleanup_strv_free_ char **config_dirs = NULL, **data_dirs = NULL;

        e = getenv("XDG_CONFIG_DIRS");
        if (e)
                config_dirs = strv_split(e, ":");
        else
                config_dirs = strv_new("/etc/xdg");
        if (!config_dirs)
                return -ENOMEM;

        e = getenv("XDG_DATA_DIRS");
        if (e)
                data_dirs = strv_split(e, ":");
        else
                data_dirs = strv_new("/usr/local/share",
                                     "/usr/share");
        if (!data_dirs)
                return -ENOMEM;

        *ret_config_dirs = TAKE_PTR(config_dirs);
        *ret_data_dirs = TAKE_PTR(data_dirs);

        return 0;
}

static char** user_dirs(
                const char *persistent_config,
                const char *runtime_config,
                const char *global_persistent_config,
                const char *global_runtime_config,
                const char *generator,
                const char *generator_early,
                const char *generator_late,
                const char *transient,
                const char *persistent_control,
                const char *runtime_control) {

        _cleanup_strv_free_ char **config_dirs = NULL, **data_dirs = NULL;
        _cleanup_free_ char *data_home = NULL;
        _cleanup_strv_free_ char **res = NULL;
        int r;

        r = xdg_user_dirs(&config_dirs, &data_dirs);
        if (r < 0)
                return NULL;

        r = xdg_user_data_dir("/systemd/user", &data_home);
        if (r < 0 && r != -ENXIO)
                return NULL;

        /* Now merge everything we found. */
        if (strv_extend_many(
                            &res,
                            persistent_control,
                            runtime_control,
                            transient,
                            generator_early,
                            persistent_config) < 0)
                return NULL;

        if (strv_extend_strv_concat(&res, (const char* const*) config_dirs, "/systemd/user") < 0)
                return NULL;

        /* global config has lower priority than the user config of the same type */
        if (strv_extend(&res, global_persistent_config) < 0)
                return NULL;

        if (strv_extend_strv(&res, (char**) user_config_unit_paths, false) < 0)
                return NULL;

        if (strv_extend_many(
                            &res,
                            runtime_config,
                            global_runtime_config,
                            generator,
                            data_home) < 0)
                return NULL;

        if (strv_extend_strv_concat(&res, (const char* const*) data_dirs, "/systemd/user") < 0)
                return NULL;

        if (strv_extend_strv(&res, (char**) user_data_unit_paths, false) < 0)
                return NULL;

        if (strv_extend(&res, generator_late) < 0)
                return NULL;

        if (path_strv_make_absolute_cwd(res) < 0)
                return NULL;

        return TAKE_PTR(res);
}

bool path_is_user_data_dir(const char *path) {
        assert(path);

        return path_strv_contains((char* const*) user_data_unit_paths, path);
}

bool path_is_user_config_dir(const char *path) {
        assert(path);

        return path_strv_contains((char* const*) user_config_unit_paths, path);
}

static int acquire_generator_dirs(
                RuntimeScope scope,
                const char *tempdir,
                char **ret,
                char **ret_early,
                char **ret_late) {

        _cleanup_free_ char *prefix_alloc = NULL, *g = NULL, *early = NULL, *late = NULL;
        const char *prefix;
        int r;

        assert(IN_SET(scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER, RUNTIME_SCOPE_GLOBAL));
        assert(ret);
        assert(ret_early);
        assert(ret_late);

        if (scope == RUNTIME_SCOPE_GLOBAL)
                return -EOPNOTSUPP;

        if (tempdir)
                prefix = tempdir;
        else if (scope == RUNTIME_SCOPE_SYSTEM)
                prefix = "/run/systemd";
        else { /* RUNTIME_SCOPE_USER */
                r = xdg_user_runtime_dir("/systemd", &prefix_alloc);
                if (r < 0)
                        return r;

                prefix = prefix_alloc;
        }

        g = path_join(prefix, "generator");
        if (!g)
                return -ENOMEM;

        early = path_join(prefix, "generator.early");
        if (!early)
                return -ENOMEM;

        late = path_join(prefix, "generator.late");
        if (!late)
                return -ENOMEM;

        *ret = TAKE_PTR(g);
        *ret_early = TAKE_PTR(early);
        *ret_late = TAKE_PTR(late);

        return 0;
}

static int acquire_transient_dir(RuntimeScope scope, const char *tempdir, char **ret) {
        char *transient;

        assert(IN_SET(scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER, RUNTIME_SCOPE_GLOBAL));
        assert(ret);

        if (scope == RUNTIME_SCOPE_GLOBAL)
                return -EOPNOTSUPP;

        if (tempdir)
                transient = path_join(tempdir, "transient");
        else if (scope == RUNTIME_SCOPE_SYSTEM)
                transient = strdup("/run/systemd/transient");
        else /* RUNTIME_SCOPE_USER */
                return xdg_user_runtime_dir("/systemd/transient", ret);

        if (!transient)
                return -ENOMEM;

        *ret = transient;
        return 0;
}

typedef enum LookupDirType {
        LOOKUP_DIR_CONFIG,
        LOOKUP_DIR_CONTROL,
        LOOKUP_DIR_ATTACHED,
        _LOOKUP_DIR_MAX,
        _LOOKUP_DIR_INVALID = -EINVAL,
} LookupDirType;

static int acquire_lookup_dirs(
                LookupDirType type,
                RuntimeScope scope,
                char **ret_persistent,
                char **ret_runtime) {

        /* RUNTIME_SCOPE_USER dirs are relative to XDG_CONFIG_DIR and XDG_RUNTIME_DIR, respectively */
        static const struct {
                const char *persistent;
                const char *runtime;
        } dirs[_LOOKUP_DIR_MAX][_RUNTIME_SCOPE_MAX] = {
                [LOOKUP_DIR_CONFIG] = {
                        [RUNTIME_SCOPE_SYSTEM] = { SYSTEM_CONFIG_UNIT_DIR, "/run/systemd/system" },
                        [RUNTIME_SCOPE_GLOBAL] = { USER_CONFIG_UNIT_DIR,   "/run/systemd/user"   },
                        [RUNTIME_SCOPE_USER]   = { "systemd/user",         "systemd/user"        },
                },
                [LOOKUP_DIR_CONTROL] = {
                        [RUNTIME_SCOPE_SYSTEM] = { "/etc/systemd/system.control", "/run/systemd/system.control" },
                        [RUNTIME_SCOPE_USER]   = { "systemd/user.control",        "systemd/user.control"        },
                },
                [LOOKUP_DIR_ATTACHED] = {
                        [RUNTIME_SCOPE_SYSTEM] = { "/etc/systemd/system.attached", "/run/systemd/system.attached" },
                        /* Portable services are not available to regular users for now. */
                },
        };

        _cleanup_free_ char *a = NULL, *b = NULL;
        int r;

        assert(type >= 0 && type < _LOOKUP_DIR_MAX);
        assert(IN_SET(scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER, RUNTIME_SCOPE_GLOBAL));
        assert(ret_persistent);
        assert(ret_runtime);

        const char *persistent = dirs[type][scope].persistent;
        const char *runtime = dirs[type][scope].runtime;
        assert(!persistent == !runtime);

        if (!persistent)
                return -EOPNOTSUPP;

        switch (scope) {

        case RUNTIME_SCOPE_SYSTEM:
        case RUNTIME_SCOPE_GLOBAL:
                a = strdup(persistent);
                b = strdup(runtime);
                if (!a || !b)
                        return -ENOMEM;

                *ret_persistent = TAKE_PTR(a);
                *ret_runtime = TAKE_PTR(b);

                return 0;

        case RUNTIME_SCOPE_USER:
                r = xdg_user_config_dir(persistent, &a);
                if (r < 0)
                        return r;

                r = xdg_user_runtime_dir(runtime, ret_runtime);
                if (r < 0) {
                        if (r != -ENXIO)
                                return r;

                        /* If XDG_RUNTIME_DIR is not set, don't consider that fatal, simply initialize the runtime
                         * directory to NULL */
                        *ret_runtime = NULL;
                }

                *ret_persistent = TAKE_PTR(a);

                return 0;

        default:
                assert_not_reached();
        }
}

static int patch_root_prefix(char **p, const char *root_dir) {
        char *c;

        assert(p);

        if (!root_dir)
                return 0;

        if (!*p)
                return 0;

        c = path_join(root_dir, *p);
        if (!c)
                return -ENOMEM;

        free_and_replace(*p, c);
        return 0;
}

static int patch_root_prefix_strv(char **l, const char *root_dir) {
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

static int get_paths_from_environ(const char *var, char ***ret) {
        const char *e;
        int r;

        assert(var);
        assert(ret);

        e = getenv(var);
        if (!e) {
                *ret = NULL;
                return 0;
        }

        bool append = endswith(e, ":"); /* Whether to append the normal search paths after what's obtained
                                           from envvar */

        /* FIXME: empty components in other places should be rejected. */

        r = path_split_and_make_absolute(e, ret);
        if (r < 0)
                return r;

        return append;
}

int lookup_paths_init(
                LookupPaths *lp,
                RuntimeScope scope,
                LookupPathsFlags flags,
                const char *root_dir) {

        _cleanup_(rmdir_and_freep) char *tempdir = NULL;
        _cleanup_free_ char
                *root = NULL,
                *persistent_config = NULL, *runtime_config = NULL,
                *global_persistent_config = NULL, *global_runtime_config = NULL,
                *generator = NULL, *generator_early = NULL, *generator_late = NULL,
                *transient = NULL,
                *persistent_control = NULL, *runtime_control = NULL,
                *persistent_attached = NULL, *runtime_attached = NULL;
        _cleanup_strv_free_ char **paths = NULL;
        int r;

        assert(lp);
        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);

        if (!empty_or_root(root_dir)) {
                if (scope == RUNTIME_SCOPE_USER)
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

        if (flags & LOOKUP_PATHS_TEMPORARY_GENERATED) {
                r = mkdtemp_malloc("/tmp/systemd-temporary-XXXXXX", &tempdir);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create temporary directory: %m");
        }

        /* Note: when XDG_RUNTIME_DIR is not set this will not return -ENXIO, but simply set runtime_config to NULL */
        r = acquire_lookup_dirs(LOOKUP_DIR_CONFIG, scope, &persistent_config, &runtime_config);
        if (r < 0)
                return r;

        if (scope == RUNTIME_SCOPE_USER) {
                r = acquire_lookup_dirs(LOOKUP_DIR_CONFIG, RUNTIME_SCOPE_GLOBAL, &global_persistent_config, &global_runtime_config);
                if (r < 0)
                        return r;
        }

        r = acquire_lookup_dirs(LOOKUP_DIR_CONTROL, scope, &persistent_control, &runtime_control);
        if (r < 0 && r != -EOPNOTSUPP)
                return r;

        r = acquire_lookup_dirs(LOOKUP_DIR_ATTACHED, scope, &persistent_attached, &runtime_attached);
        if (r < 0 && r != -EOPNOTSUPP)
                return r;

        if ((flags & LOOKUP_PATHS_EXCLUDE_GENERATED) == 0) {
                /* Note: if XDG_RUNTIME_DIR is not set, this will fail completely with ENXIO */
                r = acquire_generator_dirs(scope, tempdir,
                                           &generator, &generator_early, &generator_late);
                if (r < 0 && !IN_SET(r, -EOPNOTSUPP, -ENXIO))
                        return r;
        }

        /* Note: if XDG_RUNTIME_DIR is not set, this will fail completely with ENXIO */
        r = acquire_transient_dir(scope, tempdir, &transient);
        if (r < 0 && !IN_SET(r, -EOPNOTSUPP, -ENXIO))
                return r;

        /* First priority is whatever has been passed to us via env vars */
        r = get_paths_from_environ("SYSTEMD_UNIT_PATH", &paths);
        if (r < 0)
                return r;

        if (!paths || r > 0) {
                /* Let's figure something out. */

                _cleanup_strv_free_ char **add = NULL;

                /* For the user units we include share/ in the search
                 * path in order to comply with the XDG basedir spec.
                 * For the system stuff we avoid such nonsense. OTOH
                 * we include /lib in the search path for the system
                 * stuff but avoid it for user stuff. */

                switch (scope) {

                case RUNTIME_SCOPE_SYSTEM:
                        add = strv_new(
                                        /* If you modify this you also want to modify
                                         * systemdsystemunitpath= in systemd.pc.in! */
                                        STRV_IFNOTNULL(persistent_control),
                                        STRV_IFNOTNULL(runtime_control),
                                        STRV_IFNOTNULL(transient),
                                        STRV_IFNOTNULL(generator_early),
                                        persistent_config,
                                        SYSTEM_CONFIG_UNIT_DIR,
                                        "/etc/systemd/system",
                                        STRV_IFNOTNULL(persistent_attached),
                                        runtime_config,
                                        "/run/systemd/system",
                                        STRV_IFNOTNULL(runtime_attached),
                                        STRV_IFNOTNULL(generator),
                                        "/usr/local/lib/systemd/system",
                                        SYSTEM_DATA_UNIT_DIR,
                                        "/usr/lib/systemd/system",
                                        /* To be used ONLY for images which might be legacy split-usr */
                                        STRV_IFNOTNULL(flags & LOOKUP_PATHS_SPLIT_USR ? "/lib/systemd/system" : NULL),
                                        STRV_IFNOTNULL(generator_late));
                        break;

                case RUNTIME_SCOPE_GLOBAL:
                        add = strv_new(
                                        /* If you modify this you also want to modify
                                         * systemduserunitpath= in systemd.pc.in, and
                                         * the arrays in user_dirs() above! */
                                        STRV_IFNOTNULL(persistent_control),
                                        STRV_IFNOTNULL(runtime_control),
                                        STRV_IFNOTNULL(transient),
                                        STRV_IFNOTNULL(generator_early),
                                        persistent_config,
                                        USER_CONFIG_UNIT_DIR,
                                        "/etc/systemd/user",
                                        runtime_config,
                                        "/run/systemd/user",
                                        STRV_IFNOTNULL(generator),
                                        "/usr/local/share/systemd/user",
                                        "/usr/share/systemd/user",
                                        "/usr/local/lib/systemd/user",
                                        USER_DATA_UNIT_DIR,
                                        "/usr/lib/systemd/user",
                                        STRV_IFNOTNULL(generator_late));
                        break;

                case RUNTIME_SCOPE_USER:
                        add = user_dirs(persistent_config, runtime_config,
                                        global_persistent_config, global_runtime_config,
                                        generator, generator_early, generator_late,
                                        transient,
                                        persistent_control, runtime_control);
                        break;

                default:
                        assert_not_reached();
                }

                if (!add)
                        return -ENOMEM;

                if (paths) {
                        r = strv_extend_strv(&paths, add, true);
                        if (r < 0)
                                return r;
                } else
                        /* Small optimization: if paths is NULL (and it usually is), we can simply assign 'add' to it,
                         * and don't have to copy anything */
                        paths = TAKE_PTR(add);
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

        r = patch_root_prefix(&persistent_attached, root);
        if (r < 0)
                return r;
        r = patch_root_prefix(&runtime_attached, root);
        if (r < 0)
                return r;

        r = patch_root_prefix_strv(paths, root);
        if (r < 0)
                return -ENOMEM;

        *lp = (LookupPaths) {
                .search_path = strv_uniq(TAKE_PTR(paths)),

                .persistent_config = TAKE_PTR(persistent_config),
                .runtime_config = TAKE_PTR(runtime_config),

                .generator = TAKE_PTR(generator),
                .generator_early = TAKE_PTR(generator_early),
                .generator_late = TAKE_PTR(generator_late),

                .transient = TAKE_PTR(transient),

                .persistent_control = TAKE_PTR(persistent_control),
                .runtime_control = TAKE_PTR(runtime_control),

                .persistent_attached = TAKE_PTR(persistent_attached),
                .runtime_attached = TAKE_PTR(runtime_attached),

                .root_dir = TAKE_PTR(root),
                .temporary_dir = TAKE_PTR(tempdir),
        };

        return 0;
}

int lookup_paths_init_or_warn(LookupPaths *lp, RuntimeScope scope, LookupPathsFlags flags, const char *root_dir) {
        int r;

        r = lookup_paths_init(lp, scope, flags, root_dir);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize unit search paths%s%s: %m",
                                       isempty(root_dir) ? "" : " for root directory ", strempty(root_dir));
        return r;
}

void lookup_paths_done(LookupPaths *lp) {
        assert(lp);

        lp->search_path = strv_free(lp->search_path);

        lp->persistent_config = mfree(lp->persistent_config);
        lp->runtime_config = mfree(lp->runtime_config);

        lp->persistent_attached = mfree(lp->persistent_attached);
        lp->runtime_attached = mfree(lp->runtime_attached);

        lp->generator = mfree(lp->generator);
        lp->generator_early = mfree(lp->generator_early);
        lp->generator_late = mfree(lp->generator_late);

        lp->transient = mfree(lp->transient);

        lp->persistent_control = mfree(lp->persistent_control);
        lp->runtime_control = mfree(lp->runtime_control);

        lp->root_dir = mfree(lp->root_dir);
        lp->temporary_dir = mfree(lp->temporary_dir);
}

void lookup_paths_log(LookupPaths *lp) {
        assert(lp);

        if (strv_isempty(lp->search_path)) {
                log_debug("Ignoring unit files.");
                lp->search_path = strv_free(lp->search_path);
        } else {
                _cleanup_free_ char *t = NULL;

                t = strv_join(lp->search_path, "\n\t");
                log_debug("Looking for unit files in (higher priority first):\n\t%s", strna(t));
        }
}

char **generator_binary_paths(RuntimeScope scope) {
        _cleanup_strv_free_ char **paths = NULL;
        int r;

        /* First priority is whatever has been passed to us via env vars */
        r = get_paths_from_environ("SYSTEMD_GENERATOR_PATH", &paths);
        if (r < 0)
                return NULL;

        if (!paths || r > 0) {
                _cleanup_strv_free_ char **add = NULL;

                switch (scope) {

                case RUNTIME_SCOPE_SYSTEM:
                        add = strv_new("/run/systemd/system-generators",
                                       "/etc/systemd/system-generators",
                                       "/usr/local/lib/systemd/system-generators",
                                       SYSTEM_GENERATOR_DIR);
                        break;

                case RUNTIME_SCOPE_GLOBAL:
                case RUNTIME_SCOPE_USER:
                        add = strv_new("/run/systemd/user-generators",
                                       "/etc/systemd/user-generators",
                                       "/usr/local/lib/systemd/user-generators",
                                       USER_GENERATOR_DIR);
                        break;

                default:
                        assert_not_reached();
                }
                if (!add)
                        return NULL;

                if (paths) {
                        r = strv_extend_strv(&paths, add, true);
                        if (r < 0)
                                return NULL;
                } else
                        /* Small optimization: if paths is NULL (and it usually is), we can simply assign 'add' to it,
                         * and don't have to copy anything */
                        paths = TAKE_PTR(add);
        }

        return TAKE_PTR(paths);
}

char **env_generator_binary_paths(RuntimeScope runtime_scope) {
        _cleanup_strv_free_ char **paths = NULL, **add = NULL;
        int r;

        /* First priority is whatever has been passed to us via env vars */
        r = get_paths_from_environ("SYSTEMD_ENVIRONMENT_GENERATOR_PATH", &paths);
        if (r < 0)
                return NULL;

        if (!paths || r > 0) {
                switch (runtime_scope) {

                case RUNTIME_SCOPE_SYSTEM:
                        add = strv_new("/run/systemd/system-environment-generators",
                                        "/etc/systemd/system-environment-generators",
                                        "/usr/local/lib/systemd/system-environment-generators",
                                        SYSTEM_ENV_GENERATOR_DIR);
                        break;

                case RUNTIME_SCOPE_USER:
                        add = strv_new("/run/systemd/user-environment-generators",
                                       "/etc/systemd/user-environment-generators",
                                       "/usr/local/lib/systemd/user-environment-generators",
                                       USER_ENV_GENERATOR_DIR);
                        break;

                default:
                        assert_not_reached();
                }
                if (!add)
                        return NULL;
        }

        if (paths) {
                r = strv_extend_strv(&paths, add, true);
                if (r < 0)
                        return NULL;
        } else
                /* Small optimization: if paths is NULL (and it usually is), we can simply assign 'add' to it,
                 * and don't have to copy anything */
                paths = TAKE_PTR(add);

        return TAKE_PTR(paths);
}
