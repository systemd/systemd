/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journald-client.h"
#include "pcre2-util.h"

int client_context_check_keep_log(ClientContext *c, const char *message)
{
        int r;

        assert(c);
        assert(message);

        if (c->log_include_regex) {
                r = pattern_matches_and_log(c->log_include_regex, message, strlen(message), NULL);
                if (r < 0)
                        return r;
                if (r == 0)
                        /* If the include pattern does not matches the message,
                         * it should be discarded. */
                        return 0;
        }

        if (c->log_exclude_regex) {
                r = pattern_matches_and_log(c->log_exclude_regex, message, strlen(message), NULL);
                if (r < 0)
                        return r;
                if (r == 1)
                        /* If the exclude pattern matches the message, it
                         * should be discarded. */
                        return 0;
        }

        return 1;
}
