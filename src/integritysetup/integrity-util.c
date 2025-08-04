/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "extract-word.h"
#include "integrity-util.h"
#include "log.h"
#include "percent-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

static int supported_integrity_algorithm(char *user_supplied) {
        if (!STR_IN_SET(user_supplied, "crc32", "crc32c", "xxhash64", "sha1", "sha256", "hmac-sha256"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unsupported integrity algorithm (%s)", user_supplied);
        return 0;
}

int parse_integrity_options(
                const char *options,
                uint32_t *ret_activate_flags,
                int *ret_percent,
                usec_t *ret_commit_time,
                char **ret_data_device,
                char **ret_integrity_alg) {
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
                        if (ret_activate_flags)
                                *ret_activate_flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;
                } else if ((val = startswith(word, "mode="))) {
                        if (streq(val, "journal")) {
                                if (ret_activate_flags)
                                        *ret_activate_flags &= ~(CRYPT_ACTIVATE_NO_JOURNAL | CRYPT_ACTIVATE_NO_JOURNAL_BITMAP);
                        } else if (streq(val, "bitmap")) {
                                if (ret_activate_flags) {
                                        *ret_activate_flags &= ~CRYPT_ACTIVATE_NO_JOURNAL;
                                        *ret_activate_flags |= CRYPT_ACTIVATE_NO_JOURNAL_BITMAP;
                                }
                        } else if (streq(val, "direct")) {
                                if (ret_activate_flags) {
                                        *ret_activate_flags |= CRYPT_ACTIVATE_NO_JOURNAL;
                                        *ret_activate_flags &= ~CRYPT_ACTIVATE_NO_JOURNAL_BITMAP;
                                }
                        } else
                                log_warning("Encountered unknown mode option '%s', ignoring.", val);
                } else if ((val = startswith(word, "journal-watermark="))) {
                        r = parse_percent(val);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse journal-watermark value or value out of range (%s)", val);
                        if (ret_percent)
                                *ret_percent = r;
                } else if ((val = startswith(word, "journal-commit-time="))) {
                        usec_t tmp_commit_time;
                        r = parse_sec(val, &tmp_commit_time);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse journal-commit-time value (%s)", val);
                        if (ret_commit_time)
                                *ret_commit_time = tmp_commit_time;
                } else if ((val = startswith(word, "data-device="))) {
                        if (ret_data_device) {
                                r = free_and_strdup(ret_data_device, val);
                                if (r < 0)
                                        return log_oom();
                        }
                } else if ((val = startswith(word, "integrity-algorithm="))) {
                        r = supported_integrity_algorithm(val);
                        if (r < 0)
                                return r;
                        if (ret_integrity_alg) {
                                r = free_and_strdup(ret_integrity_alg, val);
                                if (r < 0)
                                        return log_oom();
                        }
                } else
                        log_warning("Encountered unknown option '%s', ignoring.", word);
        }

        return r;
}
