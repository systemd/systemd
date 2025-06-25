/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "install.h"
#include "install-printf.h"
#include "specifier.h"
#include "string-util.h"
#include "unit-name.h"

static int specifier_prefix_and_instance(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const InstallInfo *i = ASSERT_PTR(userdata);
        _cleanup_free_ char *prefix = NULL;
        int r;

        r = unit_name_to_prefix_and_instance(i->name, &prefix);
        if (r < 0)
                return r;

        if (endswith(prefix, "@") && i->default_instance) {
                char *ans;

                ans = strjoin(prefix, i->default_instance);
                if (!ans)
                        return -ENOMEM;
                *ret = ans;
        } else
                *ret = TAKE_PTR(prefix);

        return 0;
}

static int specifier_name(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const InstallInfo *i = ASSERT_PTR(userdata);

        if (unit_name_is_valid(i->name, UNIT_NAME_TEMPLATE) && i->default_instance)
                return unit_name_replace_instance(i->name, i->default_instance, ret);

        return strdup_to(ret, i->name);
}

static int specifier_prefix(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const InstallInfo *i = ASSERT_PTR(userdata);

        return unit_name_to_prefix(i->name, ret);
}

static int specifier_instance(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const InstallInfo *i = ASSERT_PTR(userdata);
        char *instance;
        int r;

        r = unit_name_to_instance(i->name, &instance);
        if (r < 0)
                return r;

        if (isempty(instance)) {
                r = free_and_strdup(&instance, strempty(i->default_instance));
                if (r < 0)
                        return r;
        }

        *ret = instance;
        return 0;
}

static int specifier_last_component(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        _cleanup_free_ char *prefix = NULL;
        char *dash;
        int r;

        assert(ret);

        r = specifier_prefix(specifier, data, root, userdata, &prefix);
        if (r < 0)
                return r;

        dash = strrchr(prefix, '-');
        if (dash)
                return strdup_to(ret, dash + 1);

        *ret = TAKE_PTR(prefix);
        return 0;
}

int install_name_printf(
                RuntimeScope scope,
                const InstallInfo *info,
                const char *format,
                char **ret) {
        /* This is similar to unit_name_printf() */

        const Specifier table[] = {
                { 'i', specifier_instance,            NULL },
                { 'j', specifier_last_component,      NULL },
                { 'n', specifier_name,                NULL },
                { 'N', specifier_prefix_and_instance, NULL },
                { 'p', specifier_prefix,              NULL },

                COMMON_SYSTEM_SPECIFIERS,

                COMMON_CREDS_SPECIFIERS(scope),
                {}
        };

        assert(info);
        assert(format);
        assert(ret);

        return specifier_printf(format, UNIT_NAME_MAX, table, info->root, info, ret);
}
