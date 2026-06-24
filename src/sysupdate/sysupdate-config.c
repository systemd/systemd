/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "condition.h"
#include "log.h"
#include "specifier.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "sysupdate-config.h"
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

        const char *root = userdata;
        char **s = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        if (isempty(rvalue)) {
                *s = mfree(*s);
                return 0;
        }

        _cleanup_free_ char *resolved = NULL;
        r = specifier_printf(rvalue, NAME_MAX, specifier_table, root, NULL, &resolved);
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

static const char* const suggest_on_type_table[_CONDITION_TYPE_MAX] = {
        [CONDITION_ARCHITECTURE]             = "SuggestOnArchitecture",
        [CONDITION_FIRMWARE]                 = "SuggestOnFirmware",
        [CONDITION_VIRTUALIZATION]           = "SuggestOnVirtualization",
        [CONDITION_HOST]                     = "SuggestOnHost",
        [CONDITION_FRACTION]                 = "SuggestOnFraction",
        [CONDITION_KERNEL_COMMAND_LINE]      = "SuggestOnKernelCommandLine",
        [CONDITION_VERSION]                  = "SuggestOnVersion",
        [CONDITION_CREDENTIAL]               = "SuggestOnCredential",
        [CONDITION_SECURITY]                 = "SuggestOnSecurity",
        [CONDITION_OS_RELEASE]               = "SuggestOnOSRelease",
        [CONDITION_MACHINE_TAG]              = "SuggestOnMachineTag",
};

DEFINE_STRING_TABLE_LOOKUP(suggest_on_type, ConditionType);

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

        const char *root = userdata;
        char ***s = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        if (isempty(rvalue)) {
                *s = strv_free(*s);
                return 0;
        }

        _cleanup_free_ char *resolved = NULL;
        r = specifier_printf(rvalue, NAME_MAX, specifier_table, root, NULL, &resolved);
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

        if (strv_consume(s, TAKE_PTR(resolved)) < 0)
                return log_oom();

        return 0;
}

int config_parse_condition(
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

        ConditionType cond = ltype;
        Condition **list = data, *c;
        bool negate;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *list = condition_free_list_type(*list, cond);
                return 0;
        }

        negate = rvalue[0] == '!';
        if (negate)
                rvalue++;

        c = condition_new(cond, rvalue, /* triggering= */ false, negate);
        if (!c)
                return log_oom();

        /* Drop previous assignment. */
        *list = condition_free_list_type(*list, cond);

        LIST_PREPEND(conditions, *list, c);
        return 0;
}
