/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "integrity-util.h"

#include "extract-word.h"
#include "path-util.h"
#include "percent-util.h"
#include "fileio.h"

static int supported_integrity_algorithm(char *user_supplied) {
        if (!STRCASE_IN_SET(user_supplied, "crc32", "crc32c", "sha1", "sha256", "hmac-sha256"))
                return log_error_errno(EINVAL, "Unsupported integrity algorithm (%s)", user_supplied);
        return 0;
}

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
                        r = parse_percent(val);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse journal-watermark value or value out of range (%s)", val);
                        if (percent)
                                *percent = r;
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
                        r = supported_integrity_algorithm(*integrity_alg);
                        if (r < 0)
                                return r;
                } else
                        log_warning("Encountered unknown option '%s', ignoring.", word);
        }

        return r;
}

int verify_hmac_key_file(
                const char *key_file,
                char **key_file_contents,
                size_t *key_file_size) {
        int r;
        char *tmp_key_file_contents;
        size_t tmp_key_file_size;

        if (key_file[0] == '-')
                return 0;
        if (!path_is_absolute(key_file))
                return log_error_errno(EINVAL, "hmac key file not absolute %s", key_file);

        r = read_full_file_full(
                        AT_FDCWD, key_file, UINT64_MAX, 4096,
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET|READ_FULL_FILE_FAIL_WHEN_LARGER,
                        NULL,
                        &tmp_key_file_contents, &tmp_key_file_size);
        if (r < 0)
                return log_error_errno(r, "Failed to process hmac key file: %m");

        if (key_file_contents && key_file_size) {
                *key_file_contents = tmp_key_file_contents;
                *key_file_size = tmp_key_file_size;
        } else
                free(tmp_key_file_contents);

        return 0;
}
