/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "extract-word.h"
#include "integrity-util.h"
#include "log.h"
#include "percent-util.h"
#include "string-table.h"
#include "string-util.h"
#include "time-util.h"

/* Integrity algorithm names used by integritysetup/integritytab */
static const char* const integrity_algorithm_table[_INTEGRITY_ALGORITHM_MAX] = {
        [INTEGRITY_ALGORITHM_CRC32]        = "crc32",
        [INTEGRITY_ALGORITHM_CRC32C]       = "crc32c",
        [INTEGRITY_ALGORITHM_XXHASH64]     = "xxhash64",
        [INTEGRITY_ALGORITHM_SHA1]         = "sha1",
        [INTEGRITY_ALGORITHM_SHA256]       = "sha256",
        [INTEGRITY_ALGORITHM_HMAC_SHA256]  = "hmac-sha256",
        [INTEGRITY_ALGORITHM_HMAC_SHA512]  = "hmac-sha512",
        [INTEGRITY_ALGORITHM_PHMAC_SHA256] = "phmac-sha256",
        [INTEGRITY_ALGORITHM_PHMAC_SHA512] = "phmac-sha512",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(integrity_algorithm, IntegrityAlgorithm);

int parse_integrity_options(
                const char *options,
                uint32_t *ret_activate_flags,
                int *ret_percent,
                usec_t *ret_commit_time,
                char **ret_data_device,
                IntegrityAlgorithm *ret_integrity_alg) {
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
                        IntegrityAlgorithm a = integrity_algorithm_from_string(val);
                        if (a < 0)
                                return log_error_errno(a, "Unsupported integrity algorithm (%s)", val);

                        if (ret_integrity_alg)
                                *ret_integrity_alg = a;
                } else
                        log_warning("Encountered unknown option '%s', ignoring.", word);
        }

        return r;
}
