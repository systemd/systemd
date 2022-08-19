/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journald-client.h"
#include "pcre2-util.h"

int client_context_check_keep_log(ClientContext *c, const char *message, size_t len) {
        pcre2_code *regex;
        bool matched_allow, matched_deny;
        int r;

        if (!c || !message)
                return true;

        matched_allow = set_isempty(c->log_filter_allowed_patterns);
        SET_FOREACH(regex, c->log_filter_allowed_patterns) {
                r = pattern_matches_and_log(regex, message, len, NULL);
                if (r < 0)
                        return r;
                if (r == true)
                        matched_allow = true;
        }

        matched_deny = !set_isempty(c->log_filter_denied_patterns);
        SET_FOREACH(regex, c->log_filter_denied_patterns) {
                r = pattern_matches_and_log(regex, message, len, NULL);
                if (r < 0)
                        return r;
                if (r == true)
                        matched_deny = true;
        }

        return matched_allow && !matched_deny;
}
