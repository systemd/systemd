/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "integrity_common.h"

#include "extract-word.h"
#include "parse-util.h"

int parse_integrity_options(const char *options, uint32_t *activate_flags, struct crypt_params_integrity *p, char **data_device, char **integrity_algr) {
        int r;

        for (;;) {
                _cleanup_free_ char *word = NULL;
                char *val;

                r = extract_first_word(&options, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS | EXTRACT_UNESCAPE_SEPARATORS);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse options: %m");
                if (r == 0)
                        break;
                if (isempty(word))
                        continue;
                else if (streq(word, "allow-discards")) {
                        if (activate_flags)
                                *activate_flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;
                } else if ((val = startswith(word, "journal-watermark="))) {
                        uint32_t percent;
                        r = safe_atou32(val, &percent);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse journal-watermark value (%s)", val);

                        if (percent > 100) {
                                log_warning("journal-watermark domain is 0..100, using default for invalid value %u\n", percent);
                        } else {
                                if (p)
                                        p->journal_watermark = percent;
                        }
                } else if ((val = startswith(word, "journal-commit-time="))) {
                        uint32_t commit_time;
                        r = safe_atou32(val, &commit_time);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse journal-commit-time value (%s)", val);
                        if (p)
                                p->journal_commit_time = commit_time;
                } else if ((val = startswith(word, "data-device="))) {
                        r = free_and_strdup(data_device, val);
                        if (r < 0)
                                return log_oom();
                } else if ((val = startswith(word, "integrity="))) {
                        r = free_and_strdup(integrity_algr, val);
                        if (r < 0)
                                return log_oom();
                        if (p)
                                p->integrity = *integrity_algr;
                } else
                        log_warning("Encountered unknown option '%s', ignoring.", word);
        }

        return r;
}
