/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "fs-util.h"
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
#include "tmpfile-util.h"
#include "user-util.h"
#include "util.h"

int xdg_user_runtime_dir(char **ret, const char *suffix) {
        const char *e;
        char *j;

        assert(ret);
        assert(suffix);

        e = getenv("XDG_RUNTIME_DIR");
        if (!e)
                return -ENXIO;

        j = strjoin(e, suffix);
        if (!j)
                return -ENOMEM;

        *ret = j;
        return 0;
}

int xdg_user_config_dir(char **ret, const char *suffix) {
        const char *e;
        char *j;
        int r;

        assert(ret);

        e = getenv("XDG_CONFIG_HOME");
        if (e)
                j = strjoin(e, suffix);
        else {
                _cleanup_free_ char *home = NULL;

                r = get_home_dir(&home);
                if (r < 0)
                        return r;

                j = strjoin(home, "/.config", suffix);
        }

        if (!j)
                return -ENOMEM;

        *ret = j;
        return 0;
}

int xdg_user_data_dir(char **ret, const char *suffix) {
        const char *e;
        char *j;
        int r;

        assert(ret);
        assert(suffix);

        /* We don't treat /etc/xdg/systemd here as the spec
         * suggests because we assume that is a link to
         * /etc/systemd/ anyway. */

        e = getenv("XDG_DATA_HOME");
        if (e)
                j = strjoin(e, suffix);
        else {
                _cleanup_free_ char *home = NULL;

                r = get_home_dir(&home);
                if (r < 0)
                        return r;

                j = strjoin(home, "/.local/share", suffix);
        }
        if (!j)
                return -ENOMEM;

        *ret = j;
        return 1;
}

static const char* const user_data_unit_paths[] = {
        "/usr/local/lib/systemd/user",
        "/usr/local/share/systemd/user",
        USER_DATA_UNIT_PATH,
        "/usr/lib/systemd/user",
        "/usr/share/systemd/user",
        NULL
};

static const char* const user_config_unit_paths[] = {
        USER_CONFIG_UNIT_PATH,
        "/etc/systemd/user",
        NULL
};

int xdg_user_dirs(char ***ret_config_dirs, char ***ret_data_dirs) {
        /* Implement the mechanisms defined in
         *
         * http://standards.freedesktop.org/basedir-spec/basedir-spec-0.6.html
         *
         * We look in both the config and the data dirs because we
         * want to encourage that distributors ship their unit files
         * as data, and allow overriding as configuration.
         */
        const char *e;
        _cleanup_strv_free_ char **config_dirs = NULL, **data_dirs = NULL;

        e = getenv("XDG_CONFIG_DIRS");
        if (e) {
                config_dirs = strv_split(e, ":");
                if (!config_dirs)
                        return -ENOMEM;
        }

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

        r = xdg_user_data_dir(&data_home, "/systemd/user");
        if (r < 0 && r != -ENXIO)
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

        if (strv_extend_strv_concat(&res, config_dirs, "/systemd/user") < 0)
                return NULL;

        if (strv_extend(&res, persistent_config) < 0)
                return NULL;

        /* global config has lower priority than the user config of the same type */
        if (strv_extend(&res, global_persistent_config) < 0)
                return NULL;

        if (strv_extend_strv(&res, (char**) user_config_unit_paths, false) < 0)
                return NULL;

        if (strv_extend(&res, runtime_config) < 0)
                return NULL;

        if (strv_extend(&res, global_runtime_config) < 0)
                return NULL;

        if (strv_extend(&res, generator) < 0)
                return NULL;

        if (strv_extend(&res, data_home) < 0)
                return NULL;

        if (strv_extend_strv_concat(&res, data_dirs, "/systemd/user") < 0)
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

        return strv_contains((char**) user_data_unit_paths, path);
}

bool path_is_user_config_dir(const char *path) {
        assert(path);

        return strv_contains((char**) user_config_unit_paths, path);
}

static int acquire_generator_dirs(
                UnitFileScope scope,
                const char *tempdir,
                char **generator,
                char **generator_early,
                char **generator_late) {

        _cleanup_free_ char *x = NULL, *y = NULL, *z = NULL;
        const char *prefix;

        assert(generator);
        assert(generator_early);
        assert(generator_late);
        assert(IN_SET(scope, UNIT_FILE_SYSTEM, UNIT_FILE_USER, UNIT_FILE_GLOBAL));

        if (scope == UNIT_FILE_GLOBAL)
                return -EOPNOTSUPP;

        if (tempdir)
                prefix = tempdir;
        else if (scope == UNIT_FILE_SYSTEM)
                prefix = "/run/systemd";
        else {
                /* UNIT_FILE_USER */
                const char *e;

                e = getenv("XDG_RUNTIME_DIR");
                if (!e)
                        return -ENXIO;

                prefix = strjoina(e, "/systemd");
        }

        x = path_join(prefix, "generator");
        if (!x)
                return -ENOMEM;

        y = path_join(prefix, "generator.early");
        if (!y)
                return -ENOMEM;

        z = path_join(prefix, "generator.late");
        if (!z)
                return -ENOMEM;

        *generator = TAKE_PTR(x);
        *generator_early = TAKE_PTR(y);
        *generator_late = TAKE_PTR(z);

        return 0;
}

static int acquire_transient_dir(
                UnitFileScope scope,
                const char *tempdir,
                char **ret) {

        char *transient;

        assert(ret);
        assert(IN_SET(scope, UNIT_FILE_SYSTEM, UNIT_FILE_USER, UNIT_FILE_GLOBAL));

        if (scope == UNIT_FILE_GLOBAL)
                return -EOPNOTSUPP;

        if (tempdir)
                transient = path_join(tempdir, "transient");
        else if (scope == UNIT_FILE_SYSTEM)
                transient = strdup("/run/systemd/transient");
        else
                return xdg_user_runtime_dir(ret, "/systemd/transient");

        if (!transient)
                return -ENOMEM;
        *ret = transient;
        return 0;
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
                r = xdg_user_config_dir(&a, "/systemd/user");
                if (r < 0 && r != -ENXIO)
                        return r;

                r = xdg_user_runtime_dir(runtime, "/systemd/user");
                if (r < 0) {
                        if (r != -ENXIO)
                                return r;

                        /* If XDG_RUNTIME_DIR is not set, don't consider that fatal, simply initialize the runtime
                         * directory to NULL */
                        *runtime = NULL;
                }

                *persistent = TAKE_PTR(a);

                return 0;

        default:
                assert_not_reached("Hmm, unexpected scope value.");
        }

        if (!a || !b)
                return -ENOMEM;

        *persistent = TAKE_PTR(a);
        *runtime = TAKE_PTR(b);

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

                *runtime = TAKE_PTR(b);

                break;
        }

        case UNIT_FILE_USER:
                r = xdg_user_config_dir(&a, "/systemd/user.control");
                if (r < 0 && r != -ENXIO)
                        return r;

                r = xdg_user_runtime_dir(runtime, "/systemd/user.control");
                if (r < 0) {
                        if (r != -ENXIO)
                                return r;

                        /* If XDG_RUNTIME_DIR is not set, don't consider this fatal, simply initialize the directory to
                         * NULL */
                        *runtime = NULL;
                }

                break;

        case UNIT_FILE_GLOBAL:
                return -EOPNOTSUPP;

        default:
                assert_not_reached("Hmm, unexpected scope value.");
        }

        *persistent = TAKE_PTR(a);

        return 0;
}

static int acquire_attached_dirs(
                UnitFileScope scope,
                char **ret_persistent,
                char **ret_runtime) {

        _cleanup_free_ char *a = NULL, *b = NULL;

        assert(ret_persistent);
        assert(ret_runtime);

        /* Portable services are not available to regular users for now. */
        if (scope != UNIT_FILE_SYSTEM)
                return -EOPNOTSUPP;

        a = strdup("/etc/systemd/system.attached");
        if (!a)
                return -ENOMEM;

        b = strdup("/run/systemd/system.attached");
        if (!b)
                return -ENOMEM;

        *ret_persistent = TAKE_PTR(a);
        *ret_runtime = TAKE_PTR(b);

        return 0;
}

static int patch_root_prefix(char **p, const char *root_dir) {
        char *c;

        assert(p);

        if (!*p)
                return 0;

        c = path_join(root_dir, *p);
        if (!c)
                return -ENOMEM;

        free_and_replace(*p, c);
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

        _cleanup_(rmdir_and_freep) char *tempdir = NULL;
        _cleanup_free_ char
                *root = NULL,
                *persistent_config = NULL, *runtime_config = NULL,
                *global_persistent_config = NULL, *global_runtime_config = NULL,
                *generator = NULL, *generator_early = NULL, *generator_late = NULL,
                *transient = NULL,
                *persistent_control = NULL, *runtime_control = NULL,
                *persistent_attached = NULL, *runtime_attached = NULL;
        bool append = false; /* Add items from SYSTEMD_UNIT_PATH before normal directories */
        _cleanup_strv_free_ char **paths = NULL;
        const char *e;
        int r;

        assert(p);
        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

#if HAVE_SPLIT_USR
        flags |= LOOKUP_PATHS_SPLIT_USR;
#endif

        if (!empty_or_root(root_dir)) {
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

        if (flags & LOOKUP_PATHS_TEMPORARY_GENERATED) {
                r = mkdtemp_malloc("/tmp/systemd-temporary-XXXXXX", &tempdir);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create temporary directory: %m");
        }

        /* Note: when XDG_RUNTIME_DIR is not set this will not return -ENXIO, but simply set runtime_config to NULL */
        r = acquire_config_dirs(scope, &persistent_config, &runtime_config);
        if (r < 0)
                return r;

        if (scope == UNIT_FILE_USER) {
                r = acquire_config_dirs(UNIT_FILE_GLOBAL, &global_persistent_config, &global_runtime_config);
                if (r < 0)
                        return r;
        }

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

        /* Note: when XDG_RUNTIME_DIR is not set this will not return -ENXIO, but simply set runtime_control to NULL */
        r = acquire_control_dirs(scope, &persistent_control, &runtime_control);
        if (r < 0 && r != -EOPNOTSUPP)
                return r;

        r = acquire_attached_dirs(scope, &persistent_attached, &runtime_attached);
        if (r < 0 && r != -EOPNOTSUPP)
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

                /* FIXME: empty components in other places should be rejected. */

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
                                        STRV_IFNOTNULL(persistent_attached),
                                        runtime_config,
                                        "/run/systemd/system",
                                        STRV_IFNOTNULL(runtime_attached),
                                        STRV_IFNOTNULL(generator),
                                        "/usr/local/lib/systemd/system",
                                        SYSTEM_DATA_UNIT_PATH,
                                        "/usr/lib/systemd/system",
                                        STRV_IFNOTNULL(flags & LOOKUP_PATHS_SPLIT_USR ? "/lib/systemd/system" : NULL),
                                        STRV_IFNOTNULL(generator_late));
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
                                        "/usr/local/share/systemd/user",
                                        "/usr/share/systemd/user",
                                        "/usr/local/lib/systemd/user",
                                        USER_DATA_UNIT_PATH,
                                        "/usr/lib/systemd/user",
                                        STRV_IFNOTNULL(generator_late));
                        break;

                case UNIT_FILE_USER:
                        add = user_dirs(persistent_config, runtime_config,
                                        global_persistent_config, global_runtime_config,
                                        generator, generator_early, generator_late,
                                        transient,
                                        persistent_control, runtime_control);
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

        *p = (LookupPaths) {
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

void lookup_paths_free(LookupPaths *p) {
        if (!p)
                return;

        p->search_path = strv_free(p->search_path);

        p->persistent_config = mfree(p->persistent_config);
        p->runtime_config = mfree(p->runtime_config);

        p->persistent_attached = mfree(p->persistent_attached);
        p->runtime_attached = mfree(p->runtime_attached);

        p->generator = mfree(p->generator);
        p->generator_early = mfree(p->generator_early);
        p->generator_late = mfree(p->generator_late);

        p->transient = mfree(p->transient);

        p->persistent_control = mfree(p->persistent_control);
        p->runtime_control = mfree(p->runtime_control);

        p->root_dir = mfree(p->root_dir);
        p->temporary_dir = mfree(p->temporary_dir);
}

void lookup_paths_log(LookupPaths *p) {
        assert(p);

        if (strv_isempty(p->search_path)) {
                log_debug("Ignoring unit files.");
                p->search_path = strv_free(p->search_path);
        } else {
                _cleanup_free_ char *t;

                t = strv_join(p->search_path, "\n\t");
                log_debug("Looking for unit files in (higher priority first):\n\t%s", strna(t));
        }
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
                (void) rm_rf(p->generator, REMOVE_ROOT|REMOVE_PHYSICAL);
        if (p->generator_early)
                (void) rm_rf(p->generator_early, REMOVE_ROOT|REMOVE_PHYSICAL);
        if (p->generator_late)
                (void) rm_rf(p->generator_late, REMOVE_ROOT|REMOVE_PHYSICAL);

        if (p->temporary_dir)
                (void) rm_rf(p->temporary_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
}

char **generator_binary_paths(UnitFileScope scope) {

        switch (scope) {

        case UNIT_FILE_SYSTEM:
                return strv_new("/run/systemd/system-generators",
                                "/etc/systemd/system-generators",
                                "/usr/local/lib/systemd/system-generators",
                                SYSTEM_GENERATOR_PATH);

        case UNIT_FILE_GLOBAL:
        case UNIT_FILE_USER:
                return strv_new("/run/systemd/user-generators",
                                "/etc/systemd/user-generators",
                                "/usr/local/lib/systemd/user-generators",
                                USER_GENERATOR_PATH);

        default:
                assert_not_reached("Hmm, unexpected scope.");
        }
}
