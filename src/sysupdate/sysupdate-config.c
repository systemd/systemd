/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "condition.h"
#include "log.h"
#include "path-util.h"
#include "runtime-scope.h"
#include "specifier.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "sysupdate-config.h"
#include "web-util.h"

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
        r = specifier_printf(rvalue, SIZE_MAX, system_and_tmp_specifier_table, root, /* userdata= */ NULL, &resolved);
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

int config_parse_protect_version(
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

        _cleanup_free_ char *resolved = NULL;
        char ***protected_versions = ASSERT_PTR(data);
        const char *root = userdata;
        int r;

        assert(rvalue);

        if (isempty(rvalue)) {
                *protected_versions = strv_free(*protected_versions);
                return 0;
        }

        r = specifier_printf(rvalue, NAME_MAX, system_and_tmp_specifier_table, root, /* userdata= */ NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in ProtectVersion=, ignoring: %s", rvalue);
                return 0;
        }

        if (!version_is_valid(resolved, VERSION_ALLOW_UNDERSCORE|VERSION_ALLOW_PLUS))  {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "ProtectVersion= string is not valid, ignoring: %s", resolved);
                return 0;
        }

        r = strv_extend(protected_versions, resolved);
        if (r < 0)
                return log_oom();

        return 0;
}

int config_parse_version_bound(
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

        _cleanup_free_ char *resolved = NULL;
        char **version = ASSERT_PTR(data);
        const char *root = userdata;
        int r;

        assert(rvalue);

        if (isempty(rvalue)) {
                *version = mfree(*version);
                return 0;
        }

        r = specifier_printf(rvalue, NAME_MAX, system_and_tmp_specifier_table, root, /* userdata= */ NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (!version_is_valid(resolved, VERSION_ALLOW_UNDERSCORE|VERSION_ALLOW_PLUS)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s= string is not valid, ignoring: %s", lvalue, resolved);
                return 0;
        }

        return free_and_replace(*version, resolved);
}

static const char* const suggest_on_type_table[_CONDITION_TYPE_MAX] = {
        [CONDITION_ARCHITECTURE]        = "SuggestOnArchitecture",
        [CONDITION_FIRMWARE]            = "SuggestOnFirmware",
        [CONDITION_VIRTUALIZATION]      = "SuggestOnVirtualization",
        [CONDITION_HOST]                = "SuggestOnHost",
        [CONDITION_FRACTION]            = "SuggestOnFraction",
        [CONDITION_KERNEL_COMMAND_LINE] = "SuggestOnKernelCommandLine",
        [CONDITION_VERSION]             = "SuggestOnVersion",
        [CONDITION_CREDENTIAL]          = "SuggestOnCredential",
        [CONDITION_SECURITY]            = "SuggestOnSecurity",
        [CONDITION_OS_RELEASE]          = "SuggestOnOSRelease",
        [CONDITION_MACHINE_TAG]         = "SuggestOnMachineTag",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(suggest_on_type, ConditionType);

static const char* const enabled_on_type_table[_CONDITION_TYPE_MAX] = {
        [CONDITION_ARCHITECTURE]        = "EnabledOnArchitecture",
        [CONDITION_FIRMWARE]            = "EnabledOnFirmware",
        [CONDITION_VIRTUALIZATION]      = "EnabledOnVirtualization",
        [CONDITION_HOST]                = "EnabledOnHost",
        [CONDITION_FRACTION]            = "EnabledOnFraction",
        [CONDITION_KERNEL_COMMAND_LINE] = "EnabledOnKernelCommandLine",
        [CONDITION_VERSION]             = "EnabledOnVersion",
        [CONDITION_CREDENTIAL]          = "EnabledOnCredential",
        [CONDITION_SECURITY]            = "EnabledOnSecurity",
        [CONDITION_OS_RELEASE]          = "EnabledOnOSRelease",
        [CONDITION_MACHINE_TAG]         = "EnabledOnMachineTag",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(enabled_on_type, ConditionType);

int config_resolve_enabled(int enabled, Condition *enabled_on, bool default_enabled, const char *root, const char *name) {
        int r;

        /* An explicit Enabled= setting takes precedence over the EnabledOn…= conditions. */
        if (enabled >= 0)
                return enabled;

        if (!enabled_on)
                return default_enabled;

        /* The conditions describe the running host, hence don't evaluate them for --root= or --image=. */
        if (!empty_or_root(root)) {
                log_warning("Not evaluating EnabledOn…= conditions of '%s' for root directory '%s', considering it not enabled.", name, root);
                return false;
        }

        /* Fail instead of assuming disabled, since vacuuming would then remove all instances. Don't pass on
         * the error as is, because callers give some errors a special meaning (e.g. -ENOENT means that no
         * transfers are defined, after which the cleanup logic removes all recorded resources). */
        r = condition_test_list(enabled_on, environ, RUNTIME_SCOPE_SYSTEM, enabled_on_type_to_string, /* logger= */ NULL, /* userdata= */ NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to evaluate EnabledOn…= conditions of '%s': %m", name);
                return -EINVAL;
        }

        return r;
}

int config_resolve_suggest(int suggest, Condition *suggest_on, const char *root, const char *name) {
        /* Like the EnabledOn…= conditions, the SuggestOn…= conditions describe the running host, hence don't
         * evaluate them for --root= or --image=. Otherwise they are evaluated later when needed. */
        if (suggest >= 0 || !suggest_on || empty_or_root(root))
                return suggest;

        log_warning("Not evaluating SuggestOn…= conditions of '%s' for root directory '%s', considering it not suggested.", name, root);
        return false;
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

        const char *root = userdata;
        char ***s = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        if (isempty(rvalue)) {
                *s = strv_free(*s);
                return 0;
        }

        _cleanup_free_ char *resolved = NULL;
        r = specifier_printf(rvalue, SIZE_MAX, system_and_tmp_specifier_table, root, /* userdata= */ NULL, &resolved);
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

        const char *root = userdata;
        ConditionType cond = ltype;
        Condition **list = data, *c;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *list = condition_free_list_type(*list, cond);
                return 0;
        }

        bool trigger = rvalue[0] == '|';
        if (trigger) {
                rvalue++;
                rvalue += strspn(rvalue, WHITESPACE);
        }

        bool negate = rvalue[0] == '!';
        if (negate) {
                rvalue++;
                rvalue += strspn(rvalue, WHITESPACE);
        }

        _cleanup_free_ char *resolved = NULL;
        r = specifier_printf(rvalue, SIZE_MAX, system_and_tmp_specifier_table, root, /* userdata= */ NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        c = condition_new(cond, resolved, trigger, negate);
        if (!c)
                return log_oom();

        LIST_PREPEND(conditions, *list, c);
        return 0;
}
