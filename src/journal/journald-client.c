/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-util.h"
#include "errno-util.h"
#include "journald-client.h"
#include "nulstr-util.h"
#include "pcre2-util.h"

static void client_set_filtering_patterns(ClientContext *c, Set *allow_list, Set *deny_list) {
        set_free_and_replace(c->log_filter_allowed_patterns, allow_list);
        set_free_and_replace(c->log_filter_denied_patterns, deny_list);
}

static int client_parse_log_filter_nulstr(const char *nulstr, Set **ret) {
        _cleanup_set_free_ Set *_ret = NULL;
        int r;

        NULSTR_FOREACH(pattern, nulstr) {
                 _cleanup_(pattern_freep) pcre2_code *compiled_pattern = NULL;

                r = pattern_compile_and_log(pattern, 0, &compiled_pattern);
                if (r < 0)
                        return log_debug_errno(r, "Failed to compile log filtering pattern '%s': %m", pattern);

                r = set_ensure_consume(&_ret, &pcre2_code_hash_ops_free, TAKE_PTR(compiled_pattern));
                if (r < 0)
                        return log_debug_errno(r, "Failed to insert regex into set: %m");
        }

        set_free_and_replace(*ret, _ret);

        return 0;
}

int client_context_read_log_filter_patterns(ClientContext *c, const char *cgroup) {
        char *deny_list_xattr = NULL;
        _cleanup_free_ char *xattr = NULL;
        _cleanup_set_free_ Set *allow_list = NULL, *deny_list = NULL;
        int r;

        r = cg_get_xattr_malloc(SYSTEMD_CGROUP_CONTROLLER, cgroup, "user.journald_log_filter_patterns", &xattr);
        if (r < 0 && !ERRNO_IS_XATTR_ABSENT(r))
                return log_debug_errno(r, "Failed to get user.journald_log_filter_patterns xattr for %s: %m", cgroup);
        else if (r < 0 && ERRNO_IS_XATTR_ABSENT(r)) {
                client_set_filtering_patterns(c, NULL, NULL);
                return 0;
        }

        /* We expect '0xff' to be present in the attribute, even if the lists are empty. We expect the
         * following:
         * - No allow list, nor deny list: 0x00, 0x00, 0xff, 0x00, 0x00
         * - Allow list, but no deny list: 0xXX, ...., 0x00, 0x00, 0xff, 0x00, 0x00
         * - No allow list, but deny list: 0x00, 0x00, 0xff, 0xXX, ...., 0x00, 0x00
         * - Allow list, and deny list:    0xXX, ...., 0x00, 0x00, 0xff, 0xXX, ...., 0x00, 0x00
         * This is due to the fast allowed and denied patterns list are two nulstr joined together with
         * '0xff'.
         */
        deny_list_xattr = memchr(xattr, (char)0xff, r);
        if (!deny_list_xattr)
                return log_debug_errno(-EBADMSG, "Missing separation character in cgroup user.journald_log_filter_patterns attribute: %m");

        r = client_parse_log_filter_nulstr(xattr, &allow_list);
        if (r < 0)
                return r;

        /* Use 'deny_list_xattr + 1' to skip '0xff'. */
        r = client_parse_log_filter_nulstr(deny_list_xattr + 1, &deny_list);
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
