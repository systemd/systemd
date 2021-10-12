/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "integrity-util.h"

#include "extract-word.h"
#include "percent-util.h"

int parse_integrity_options(
                const char *options,
                uint32_t *activate_flags,
                int *percent,
                usec_t *commit_time,
                char **data_device,
                char **integrity_alg) {
        int r;

        for (;;) {
                _cleanup_free_ char *word = NULL;
                char *val;

                r = extract_first_word(&options, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS | EXTRACT_UNESCAPE_SEPARATORS);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse options: %m");
                if (r == 0)
                        break;
                else if (streq(word, "allow-discards")) {
                        if (activate_flags)
                                *activate_flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;
                } else if ((val = startswith(word, "journal-watermark="))) {
                        int tmp_percent = parse_percent(val);
                        if (tmp_percent < 0)
                                return log_error_errno(tmp_percent, "Failed to parse journal-watermark value or value out of range (%s)", val);
                        if (percent)
                                *percent = tmp_percent;
                } else if ((val = startswith(word, "journal-commit-time="))) {
                        usec_t tmp_commit_time;
                        r = parse_sec(val, &tmp_commit_time);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse journal-commit-time value (%s)", val);
                        if (commit_time)
                                *commit_time = tmp_commit_time;
                } else if ((val = startswith(word, "data-device="))) {
                        r = free_and_strdup(data_device, val);
                        if (r < 0)
                                return log_oom();
                } else if ((val = startswith(word, "integrity-algorithm="))) {
                        r = free_and_strdup(integrity_alg, val);
                        if (r < 0)
                                return log_oom();
                } else
                        log_warning("Encountered unknown option '%s', ignoring.", word);
        }

        return r;
}
