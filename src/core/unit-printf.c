/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "cgroup-util.h"
#include "format-util.h"
#include "macro.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "unit.h"
#include "user-util.h"

static int specifier_prefix_and_instance(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        const Unit *u = userdata;
        char *a;
        int r;

        assert(u);

        r = unit_name_to_prefix_and_instance(u->id, &a);
        if (r < 0)
                return r;

        *ret_type = SPECIFIER_RESULT_STRING;
        *ret = a;
        return 0;
}

static int specifier_prefix(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        const Unit *u = userdata;
        char *a;
        int r;

        assert(u);

        r = unit_name_to_prefix(u->id, &a);
        if (r < 0)
                return r;

        *ret_type = SPECIFIER_RESULT_STRING;
        *ret = a;
        return 0;
}

static int specifier_prefix_unescaped(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        _cleanup_free_ char *p = NULL, *q = NULL;
        const Unit *u = userdata;
        int r;

        assert(u);

        r = unit_name_to_prefix(u->id, &p);
        if (r < 0)
                return r;

        r = unit_name_unescape(p, &q);
        if (r < 0)
                return r;

        *ret_type = SPECIFIER_RESULT_STRING;
        *ret = TAKE_PTR(q);
        return 0;
}

static int specifier_instance_unescaped(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        const Unit *u = userdata;
        char *a = NULL;
        int r;

        assert(u);

        if (!isempty(u->instance)) {
                r = unit_name_unescape(strempty(u->instance), &a);
                if (r < 0)
                        return r;
        }

        *ret_type = SPECIFIER_RESULT_STRING;
        *ret = a;
        return 0;
}

static int unit_get_last_component(const Unit *u, char **ret) {
        char *prefix, *dash;
        int r;

        assert(u);
        assert(ret);

        r = unit_name_to_prefix(u->id, &prefix);
        if (r < 0)
                return r;

        dash = strrchr(prefix, '-');
        if (dash)
                memmove(prefix, dash + 1, strlen(dash + 1) + 1);

        *ret = prefix;
        return 0;
}

static int specifier_last_component(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        char *a;
        int r;

        r = unit_get_last_component(userdata, &a);
        if (r < 0)
                return r;

        *ret_type = SPECIFIER_RESULT_STRING;
        *ret = a;
        return 0;
}

static int specifier_last_component_unescaped(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        _cleanup_free_ char *p = NULL;
        char *a;
        int r;

        r = unit_get_last_component(userdata, &p);
        if (r < 0)
                return r;

        r = unit_name_unescape(p, &a);
        if (r < 0)
                return r;

        *ret_type = SPECIFIER_RESULT_STRING;
        *ret = a;
        return 0;
}

static int specifier_filename(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        const Unit *u = userdata;
        char *a;
        int r;

        assert(u);

        if (u->instance)
                r = unit_name_path_unescape(u->instance, &a);
        else
                r = unit_name_to_path(u->id, &a);
        if (r < 0)
                return r;

        *ret_type = SPECIFIER_RESULT_STRING;
        *ret = a;
        return 0;
}

static void bad_specifier(const Unit *u, char specifier) {
        log_unit_warning(u, "Specifier '%%%c' used in unit configuration, which is deprecated. Please update your unit file, as it does not work as intended.", specifier);
}

static int specifier_cgroup(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        const Unit *u = userdata;
        char *n;

        assert(u);

        bad_specifier(u, specifier);

        if (u->cgroup_path) {
                *ret_type = SPECIFIER_RESULT_STRING_CONST;
                *ret = (void*) u->cgroup_path;
                return 0;
        }

        n = unit_default_cgroup_path(u);
        if (!n)
                return -ENOMEM;

        *ret_type = SPECIFIER_RESULT_STRING;
        *ret = n;
        return 0;
}

static int specifier_cgroup_root(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        const Unit *u = userdata;

        assert(u);

        bad_specifier(u, specifier);

        *ret_type = SPECIFIER_RESULT_STRING_CONST;
        *ret = (void*) u->manager->cgroup_root;
        return 0;
}

static int specifier_cgroup_slice(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        const Unit *u = userdata;

        assert(u);

        bad_specifier(u, specifier);

        if (UNIT_ISSET(u->slice)) {
                const Unit *slice;
                char *n;

                slice = UNIT_DEREF(u->slice);

                if (slice->cgroup_path) {
                        *ret_type = SPECIFIER_RESULT_STRING_CONST;
                        *ret = (void*) slice->cgroup_path;
                        return 0;
                }

                n = unit_default_cgroup_path(slice);
                if (!n)
                        return -ENOMEM;

                *ret_type = SPECIFIER_RESULT_STRING;
                *ret = n;
                return 0;
        }

        *ret_type = SPECIFIER_RESULT_STRING_CONST;
        *ret = (void*) u->manager->cgroup_root;
        return 0;
}

static int specifier_special_directory(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        const Unit *u = userdata;

        assert(u);

        *ret_type = SPECIFIER_RESULT_STRING_CONST;
        *ret = (void*) u->manager->prefix[PTR_TO_UINT(data)];
        return 0;
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

                COMMON_CREDS_SPECIFIERS,
                {}
        };

        assert(u);
        assert(format);
        assert(ret);

        return specifier_printf(format, table, u, ret);
}

int unit_full_printf(const Unit *u, const char *format, char **ret) {
        /* This is similar to unit_name_printf() but also supports unescaping. Also, adds a couple of additional codes
         * (which are likely not suitable for unescaped inclusion in unit names):
         *
         * %f: the unescaped instance if set, otherwise the id unescaped as path
         *
         * %c: cgroup path of unit (deprecated)
         * %r: where units in this slice are placed in the cgroup tree (deprecated)
         * %R: the root of this systemd's instance tree (deprecated)
         *
         * %C: the cache directory root (e.g. /var/cache or $XDG_CACHE_HOME)
         * %E: the configuration directory root (e.g. /etc or $XDG_CONFIG_HOME)
         * %L: the log directory root (e.g. /var/log or $XDG_CONFIG_HOME/log)
         * %S: the state directory root (e.g. /var/lib or $XDG_CONFIG_HOME)
         * %t: the runtime directory root (e.g. /run or $XDG_RUNTIME_DIR)
         *
         * %h: the homedir of the running user
         * %s: the shell of the running user
         *
         * NOTICE: When you add new entries here, please be careful: specifiers which depend on settings of the unit
         * file itself are broken by design, as they would resolve differently depending on whether they are used
         * before or after the relevant configuration setting. Hence: don't add them.
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

                { 'c', specifier_cgroup,                   NULL },
                { 'r', specifier_cgroup_slice,             NULL },
                { 'R', specifier_cgroup_root,              NULL },

                { 'C', specifier_special_directory,        UINT_TO_PTR(EXEC_DIRECTORY_CACHE) },
                { 'E', specifier_special_directory,        UINT_TO_PTR(EXEC_DIRECTORY_CONFIGURATION) },
                { 'L', specifier_special_directory,        UINT_TO_PTR(EXEC_DIRECTORY_LOGS) },
                { 'S', specifier_special_directory,        UINT_TO_PTR(EXEC_DIRECTORY_STATE) },
                { 't', specifier_special_directory,        UINT_TO_PTR(EXEC_DIRECTORY_RUNTIME) },

                { 'h', specifier_user_home,                NULL },
                { 's', specifier_user_shell,               NULL },

                COMMON_SYSTEM_SPECIFIERS,

                COMMON_CREDS_SPECIFIERS,

                COMMON_TMP_SPECIFIERS,
                {}
        };

        return specifier_printf(format, table, u, ret);
}
