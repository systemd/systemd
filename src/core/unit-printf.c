/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "cgroup-util.h"
#include "format-util.h"
#include "macro.h"
#include "sd-path.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "unit.h"
#include "user-util.h"

static int specifier_prefix_and_instance(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const Unit *u = ASSERT_PTR(userdata);

        return unit_name_to_prefix_and_instance(u->id, ret);
}

static int specifier_prefix(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const Unit *u = ASSERT_PTR(userdata);

        return unit_name_to_prefix(u->id, ret);
}

static int specifier_prefix_unescaped(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        _cleanup_free_ char *p = NULL;
        const Unit *u = ASSERT_PTR(userdata);
        int r;

        r = unit_name_to_prefix(u->id, &p);
        if (r < 0)
                return r;

        return unit_name_unescape(p, ret);
}

static int specifier_instance_unescaped(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const Unit *u = ASSERT_PTR(userdata);

        return unit_name_unescape(strempty(u->instance), ret);
}

static int specifier_last_component(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const Unit *u = ASSERT_PTR(userdata);
        _cleanup_free_ char *prefix = NULL;
        char *dash;
        int r;

        r = unit_name_to_prefix(u->id, &prefix);
        if (r < 0)
                return r;

        dash = strrchr(prefix, '-');
        if (dash)
                return specifier_string(specifier, dash + 1, root, userdata, ret);

        *ret = TAKE_PTR(prefix);
        return 0;
}

static int specifier_last_component_unescaped(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        _cleanup_free_ char *p = NULL;
        int r;

        r = specifier_last_component(specifier, data, root, userdata, &p);
        if (r < 0)
                return r;

        return unit_name_unescape(p, ret);
}

static int specifier_filename(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const Unit *u = ASSERT_PTR(userdata);

        if (u->instance)
                return unit_name_path_unescape(u->instance, ret);
        else
                return unit_name_to_path(u->id, ret);
}

static void bad_specifier(const Unit *u, char specifier) {
        log_unit_warning(u, "Specifier '%%%c' used in unit configuration, which is deprecated. Please update your unit file, as it does not work as intended.", specifier);
}

static int specifier_cgroup(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const Unit *u = ASSERT_PTR(userdata);

        bad_specifier(u, specifier);

        if (u->cgroup_path) {
                char *n;

                n = strdup(u->cgroup_path);
                if (!n)
                        return -ENOMEM;

                *ret = n;
                return 0;
        }

        return unit_default_cgroup_path(u, ret);
}

static int specifier_cgroup_root(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const Unit *u = ASSERT_PTR(userdata);
        char *n;

        bad_specifier(u, specifier);

        n = strdup(u->manager->cgroup_root);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_cgroup_slice(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const Unit *u = ASSERT_PTR(userdata), *slice;
        char *n;

        bad_specifier(u, specifier);

        slice = UNIT_GET_SLICE(u);
        if (slice) {
                if (slice->cgroup_path)
                        n = strdup(slice->cgroup_path);
                else
                        return unit_default_cgroup_path(slice, ret);
        } else
                n = strdup(u->manager->cgroup_root);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_special_directory(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const Unit *u = ASSERT_PTR(userdata);
        char *n;

        n = strdup(u->manager->prefix[PTR_TO_UINT(data)]);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_credentials_dir(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const Unit *u = ASSERT_PTR(userdata);
        char *d;

        assert(ret);

        d = strjoin(u->manager->prefix[EXEC_DIRECTORY_RUNTIME], "/credentials/", u->id);
        if (!d)
                return -ENOMEM;

        *ret = d;
        return 0;
}

static int specifier_shared_data_dir(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const Unit *u = ASSERT_PTR(userdata);

        assert(ret);

        return sd_path_lookup(MANAGER_IS_SYSTEM(u->manager) ? SD_PATH_SYSTEM_SHARED : SD_PATH_USER_SHARED, NULL, ret);
}

int unit_name_printf(const Unit *u, const char* format, char **ret) {
        /*
         * This will use the passed string as format string and replace the following specifiers (which should all be
         * safe for inclusion in unit names):
         *
         * %n: the full id of the unit                 (foo-aaa@bar.waldo)
         * %N: the id of the unit without the suffix   (foo-aaa@bar)
         * %p: the prefix                              (foo-aaa)
         * %i: the instance                            (bar)
         * %j: the last component of the prefix        (aaa)
         */

        const Specifier table[] = {
                { 'i', specifier_string,              u->instance },
                { 'j', specifier_last_component,      NULL },
                { 'n', specifier_string,              u->id },
                { 'N', specifier_prefix_and_instance, NULL },
                { 'p', specifier_prefix,              NULL },

                COMMON_SYSTEM_SPECIFIERS,

                COMMON_CREDS_SPECIFIERS(u->manager->runtime_scope),
                {}
        };

        assert(u);
        assert(format);
        assert(ret);

        return specifier_printf(format, UNIT_NAME_MAX, table, NULL, u, ret);
}

int unit_full_printf_full(const Unit *u, const char *format, size_t max_length, char **ret) {
        /* This is similar to unit_name_printf() but also supports unescaping. Also, adds a couple of
         * additional codes (which are likely not suitable for unescaped inclusion in unit names):
         *
         * %f: the unescaped instance if set, otherwise the id unescaped as path
         *
         * %c: cgroup path of unit (deprecated)
         * %r: where units in this slice are placed in the cgroup tree (deprecated)
         * %R: the root of this systemd's instance tree (deprecated)
         *
         * %C: the cache directory root (e.g. /var/cache or $XDG_CACHE_HOME)
         * %d: the credentials directory ($CREDENTIALS_DIRECTORY)
         * %D: the shared data root (e.g. /usr/share or $XDG_DATA_HOME)
         * %E: the configuration directory root (e.g. /etc or $XDG_CONFIG_HOME)
         * %L: the log directory root (e.g. /var/log or $XDG_STATE_HOME/log)
         * %S: the state directory root (e.g. /var/lib or $XDG_STATE_HOME)
         * %t: the runtime directory root (e.g. /run or $XDG_RUNTIME_DIR)
         *
         * %h: the homedir of the running user
         * %s: the shell of the running user
         *
         * NOTICE: When you add new entries here, please be careful: specifiers which depend on settings of
         * the unit file itself are broken by design, as they would resolve differently depending on whether
         * they are used before or after the relevant configuration setting. Hence: don't add them.
         */

        assert(u);
        assert(format);
        assert(ret);

        const Specifier table[] = {
                { 'i', specifier_string,                   u->instance },
                { 'I', specifier_instance_unescaped,       NULL },
                { 'j', specifier_last_component,           NULL },
                { 'J', specifier_last_component_unescaped, NULL },
                { 'n', specifier_string,                   u->id },
                { 'N', specifier_prefix_and_instance,      NULL },
                { 'p', specifier_prefix,                   NULL },
                { 'P', specifier_prefix_unescaped,         NULL },

                { 'f', specifier_filename,                 NULL },
                { 'y', specifier_real_path,                u->fragment_path },
                { 'Y', specifier_real_directory,           u->fragment_path },

                { 'c', specifier_cgroup,                   NULL },  /* deprecated, see 1b89b0c499cd4bf0ff389caab4ecaae6e75f9d4e */
                { 'r', specifier_cgroup_slice,             NULL },  /* deprecated, see 1b89b0c499cd4bf0ff389caab4ecaae6e75f9d4e */
                { 'R', specifier_cgroup_root,              NULL },  /* deprecated, see 1b89b0c499cd4bf0ff389caab4ecaae6e75f9d4e */

                { 'C', specifier_special_directory,        UINT_TO_PTR(EXEC_DIRECTORY_CACHE) },
                { 'd', specifier_credentials_dir,          NULL },
                { 'D', specifier_shared_data_dir,          NULL },
                { 'E', specifier_special_directory,        UINT_TO_PTR(EXEC_DIRECTORY_CONFIGURATION) },
                { 'L', specifier_special_directory,        UINT_TO_PTR(EXEC_DIRECTORY_LOGS) },
                { 'S', specifier_special_directory,        UINT_TO_PTR(EXEC_DIRECTORY_STATE) },
                { 't', specifier_special_directory,        UINT_TO_PTR(EXEC_DIRECTORY_RUNTIME) },

                { 'h', specifier_user_home,                NULL },
                { 's', specifier_user_shell,               NULL },

                COMMON_SYSTEM_SPECIFIERS,

                COMMON_CREDS_SPECIFIERS(u->manager->runtime_scope),

                COMMON_TMP_SPECIFIERS,
                {}
        };

        return specifier_printf(format, max_length, table, NULL, u, ret);
}
