/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journald-client.h"
#include "pcre2-util.h"

int client_context_check_keep_log(ClientContext *c, const char *message, size_t len)
{
        int r;

        if (!c || !message || !c->log_filter_regex)
                return 1;

        r = pattern_matches_and_log(c->log_filter_regex, message, len, NULL);
        if (r < 0)
                return r;

        return r == c->log_filter_allow_list;
}
