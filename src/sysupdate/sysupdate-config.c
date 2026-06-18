/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "log.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "sysupdate-config.h"
#include "sysupdate.h"
#include "web-util.h"

const Specifier specifier_table[] = {
        COMMON_SYSTEM_SPECIFIERS,
        COMMON_TMP_SPECIFIERS,
        {}
};

int config_parse_url_specifiers(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = ASSERT_PTR(data);
        _cleanup_free_ char *resolved = NULL;
        int r;

        assert(rvalue);

        if (isempty(rvalue)) {
                *s = mfree(*s);
                return 0;
        }

        r = specifier_printf(rvalue, NAME_MAX, specifier_table, arg_root, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (!http_url_is_valid(resolved)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s= URL is not valid, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        return free_and_replace(*s, resolved);
}

int config_parse_url_specifiers_many(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char ***s = ASSERT_PTR(data);
        _cleanup_free_ char *resolved = NULL;
        int r;

        assert(rvalue);

        if (isempty(rvalue)) {
                *s = strv_free(*s);
                return 0;
        }

        r = specifier_printf(rvalue, NAME_MAX, specifier_table, arg_root, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (!http_url_is_valid(resolved)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s= URL is not valid, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (strv_push(s, TAKE_PTR(resolved)) < 0)
                return log_oom();

        return 0;
}
