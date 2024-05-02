/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-util.h"
#include "errno-util.h"
#include "journald-client.h"
#include "nulstr-util.h"
#include "pcre2-util.h"
#include "strv.h"

/* This consumes both `allow_list` and `deny_list` arguments. Hence, those arguments are not owned by the
 * caller anymore and should not be freed. */
static void client_set_filtering_patterns(ClientContext *c, Set *allow_list, Set *deny_list) {
        assert(c);

        set_free_and_replace(c->log_filter_allowed_patterns, allow_list);
        set_free_and_replace(c->log_filter_denied_patterns, deny_list);
}

static int client_parse_log_filter_nulstr(const char *nulstr, size_t len, Set **ret) {
        _cleanup_set_free_ Set *s = NULL;
        _cleanup_strv_free_ char **patterns_strv = NULL;
        int r;

        assert(nulstr);
        assert(ret);

        patterns_strv = strv_parse_nulstr(nulstr, len);
        if (!patterns_strv)
                return log_oom_debug();

        STRV_FOREACH(pattern, patterns_strv) {
                _cleanup_(pattern_freep) pcre2_code *compiled_pattern = NULL;

                r = pattern_compile_and_log(*pattern, 0, &compiled_pattern);
                if (r < 0)
                        return r;

                r = set_ensure_consume(&s, &pcre2_code_hash_ops_free, TAKE_PTR(compiled_pattern));
                if (r < 0)
                        return log_debug_errno(r, "Failed to insert regex into set: %m");
        }

        *ret = TAKE_PTR(s);

        return 0;
}

int client_context_read_log_filter_patterns(ClientContext *c, const char *cgroup) {
        char *deny_list_xattr, *xattr_end;
        _cleanup_free_ char *xattr = NULL, *unit_cgroup = NULL;
        _cleanup_set_free_ Set *allow_list = NULL, *deny_list = NULL;
        int r;

        assert(c);

        r = cg_path_get_unit_path(cgroup, &unit_cgroup);
        if (r < 0)
                return log_debug_errno(r, "Failed to get the unit's cgroup path for %s: %m", cgroup);

        r = cg_get_xattr_malloc(unit_cgroup, "user.journald_log_filter_patterns", &xattr);
        if (ERRNO_IS_NEG_XATTR_ABSENT(r)) {
                client_set_filtering_patterns(c, NULL, NULL);
                return 0;
        } else if (r < 0)
                return log_debug_errno(r, "Failed to get user.journald_log_filter_patterns xattr for %s: %m", unit_cgroup);

        xattr_end = xattr + r;

        /* We expect '0xff' to be present in the attribute, even if the lists are empty. We expect the
         * following:
         * - Allow list, but no deny list: 0xXX, ...., 0xff
         * - No allow list, but deny list: 0xff, 0xXX, ....
         * - Allow list, and deny list:    0xXX, ...., 0xff, 0xXX, ....
         * This is due to the fact allowed and denied patterns list are two nulstr joined together with '0xff'.
         * None of the allowed or denied nulstr have a nul-termination character.
         *
         * We do not expect both the allow list and deny list to be empty, as this condition is tested
         * before writing to xattr. */
        deny_list_xattr = memchr(xattr, (char)0xff, r);
        if (!deny_list_xattr)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Missing delimiter in cgroup user.journald_log_filter_patterns attribute: %m");

        r = client_parse_log_filter_nulstr(xattr, deny_list_xattr - xattr, &allow_list);
        if (r < 0)
                return r;

        /* Use 'deny_list_xattr + 1' to skip '0xff'. */
        ++deny_list_xattr;
        r = client_parse_log_filter_nulstr(deny_list_xattr, xattr_end - deny_list_xattr, &deny_list);
        if (r < 0)
                return r;

        client_set_filtering_patterns(c, TAKE_PTR(allow_list), TAKE_PTR(deny_list));

        return 0;
}

int client_context_check_keep_log(ClientContext *c, const char *message, size_t len) {
        pcre2_code *regex;

        if (!c || !message)
                return true;

        SET_FOREACH(regex, c->log_filter_denied_patterns)
                if (pattern_matches_and_log(regex, message, len, NULL) > 0)
                        return false;

        SET_FOREACH(regex, c->log_filter_allowed_patterns)
                if (pattern_matches_and_log(regex, message, len, NULL) > 0)
                        return true;

        return set_isempty(c->log_filter_allowed_patterns);
}
