/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "format-util.h"
#include "install-printf.h"
#include "install.h"
#include "macro.h"
#include "specifier.h"
#include "string-util.h"
#include "unit-name.h"
#include "user-util.h"

static int specifier_prefix_and_instance(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        const UnitFileInstallInfo *i = userdata;
        _cleanup_free_ char *prefix = NULL;
        int r;

        assert(i);

        r = unit_name_to_prefix_and_instance(i->name, &prefix);
        if (r < 0)
                return r;

        if (endswith(prefix, "@") && i->default_instance) {
                if (!strextend(&prefix, i->default_instance))
                        return -ENOMEM;
        }

        *ret_type = SPECIFIER_RESULT_STRING;
        *ret = TAKE_PTR(prefix);
        return 0;
}

static int specifier_name(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        const UnitFileInstallInfo *i = userdata;
        char *ans;
        int r;

        assert(i);

        if (unit_name_is_valid(i->name, UNIT_NAME_TEMPLATE) && i->default_instance) {
                r = unit_name_replace_instance(i->name, i->default_instance, &ans);
                if (r < 0)
                        return r;

                *ret_type = SPECIFIER_RESULT_STRING;
                *ret = ans;
                return 0;
        }

        *ret_type = SPECIFIER_RESULT_STRING_CONST;
        *ret = (void*) i->name;
        return 0;
}

static int specifier_prefix(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        const UnitFileInstallInfo *i = userdata;
        char *ans;
        int r;

        assert(i);

        r = unit_name_to_prefix(i->name, &ans);
        if (r < 0)
                return r;

        *ret_type = SPECIFIER_RESULT_STRING;
        *ret = ans;
        return 0;
}

static int specifier_instance(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        const UnitFileInstallInfo *i = userdata;
        char *instance;
        int r;

        assert(i);

        r = unit_name_to_instance(i->name, &instance);
        if (r < 0)
                return r;

        if (isempty(instance)) {
                *ret_type = SPECIFIER_RESULT_STRING_CONST;
                *ret = (void*) i->default_instance;
        } else {
                *ret_type = SPECIFIER_RESULT_STRING;
                *ret = instance;
        }

        return 0;
}

static int specifier_last_component(char specifier, const void *data, const void *userdata, SpecifierResultType *ret_type, void **ret) {
        char *dash;
        int r;

        r = specifier_prefix(specifier, data, userdata, ret_type, ret);
        if (r < 0)
                return r;

        dash = strrchr(*ret, '-');
        if (dash)
                memmove(*ret, dash + 1, strlen(dash + 1) + 1);

        return 0;
}

int install_full_printf_internal(const UnitFileInstallInfo *i, const char *format, size_t max_length, char **ret) {
        /* This is similar to unit_name_printf() */

        const Specifier table[] = {
                { 'i', specifier_instance,            NULL },
                { 'j', specifier_last_component,      NULL },
                { 'n', specifier_name,                NULL },
                { 'N', specifier_prefix_and_instance, NULL },
                { 'p', specifier_prefix,              NULL },

                COMMON_SYSTEM_SPECIFIERS,

                COMMON_CREDS_SPECIFIERS,
                {}
        };

        assert(i);
        assert(format);
        assert(ret);

        return specifier_printf(format, max_length, table, i, ret);
}
