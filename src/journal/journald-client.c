/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-util.h"
#include "journald-client.h"
#include "nulstr-util.h"
#include "pcre2-util.h"

int client_context_read_log_filter_patterns(ClientContext *c, const char *cgroup) {
        const char *pattern;
        _cleanup_free_ char *xattr = NULL;
        _cleanup_set_free_ Set *allow_list = NULL, *deny_list = NULL;
        Set **current_list = &allow_list;
        int r;

        r = cg_get_xattr_malloc(SYSTEMD_CGROUP_CONTROLLER, cgroup, "user.journald_log_filter_patterns", &xattr);
        if (r < 0 && r != -ENODATA)
                return log_debug_errno(r, "Failed to get user.journald_log_filter_patterns xattr for %s: %m", cgroup);

        NULSTR_FOREACH(pattern, xattr) {
                 _cleanup_(pattern_freep) pcre2_code *compiled_pattern = NULL;

                if (streq(pattern, "\xff")) {
                        current_list = &deny_list;
                        continue;
                }

                r = pattern_compile_and_log(pattern, 0, &compiled_pattern);
                if (r < 0)
                        return log_debug_errno(r, "Failed to compile log filtering pattern '%s' for %s: %m",
                                               pattern, cgroup);

                r = set_ensure_consume(current_list, &pcre2_code_hash_ops_free, TAKE_PTR(compiled_pattern));
                if (r < 0)
                        return log_debug_errno(r, "Failed to insert regex into set for %s: %m", cgroup);
        }

        set_free_and_replace(c->log_filter_allowed_patterns, allow_list);
        set_free_and_replace(c->log_filter_denied_patterns, deny_list);

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
