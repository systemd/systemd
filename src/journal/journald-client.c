/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journald-client.h"
#include "pcre2-util.h"

int client_context_check_keep_log(ClientContext *c, const char *message, size_t len) {
        bool matched_allowlist = false;
        pcre2_code *regex;

        if (!c || !message)
                return true;

        SET_FOREACH(regex, c->log_filter_denied_patterns)
                if (pattern_matches_and_log(regex, message, len, NULL) > 0)
                        return false;

        SET_FOREACH(regex, c->log_filter_allowed_patterns)
                if (pattern_matches_and_log(regex, message, len, NULL) > 0)
                        matched_allowlist = true;

        return set_isempty(c->log_filter_allowed_patterns) || matched_allowlist;
}
