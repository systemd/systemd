/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "extract-word.h"
#include "journal-compression-util.h"
#include "parse-util.h"

int config_parse_compression(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        OrderedHashmap **configs = ASSERT_PTR(data);
        bool parse_level = ltype;
        int r;

        if (isempty(rvalue)) {
                *configs = ordered_hashmap_free(*configs);
                return 1;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                int level = -1;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);
                if (r == 0)
                        return 1;

                if (parse_level) {
                        char *q = strchr(word, ':');
                        if (q) {
                                *q++ = '\0';

                                r = safe_atoi(q, &level);
                                if (r < 0) {
                                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                                   "Compression level must be positive, ignoring: %s", q);
                                        continue;
                                }
                        }
                }

                Compression c = compression_lowercase_from_string(word);
                if (c <= 0 || !compression_supported(c)) {
                        log_syntax(unit, LOG_WARNING, filename, line, c,
                                   "Compression algorithm '%s' is not supported on the system, ignoring.", word);
                        continue;
                }

                /* If the compression algorithm is already specified, update the compression level. */
                CompressionConfig *existing = ordered_hashmap_get(*configs, INT_TO_PTR(c));
                if (existing) {
                        existing->level = level;
                        continue;
                }

                _cleanup_free_ CompressionConfig *cc = new(CompressionConfig, 1);
                if (!cc)
                        return log_oom();

                *cc = (CompressionConfig) {
                        .algorithm = c,
                        .level = level,
                };

                r = ordered_hashmap_ensure_put(configs, &trivial_hash_ops_value_free, INT_TO_PTR(c), cc);
                if (r < 0)
                        return log_oom();

                TAKE_PTR(cc);
        }
}
