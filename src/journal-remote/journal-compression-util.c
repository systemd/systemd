/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "extract-word.h"
#include "hashmap.h"
#include "journal-compression-util.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"

static int compression_config_put(OrderedHashmap **configs, Compression c, int level) {
        assert(configs);

        if (!compression_supported(c))
                return 0;

        /* If the compression algorithm is already specified, update the compression level. */
        CompressionConfig *cc = ordered_hashmap_get(*configs, INT_TO_PTR(c));
        if (cc)
                cc->level = level;
        else {
                _cleanup_free_ CompressionConfig *new_config = new(CompressionConfig, 1);
                if (!new_config)
                        return log_oom();

                *new_config = (CompressionConfig) {
                        .algorithm = c,
                        .level = level,
                };

                if (ordered_hashmap_ensure_put(configs, &trivial_hash_ops_value_free, INT_TO_PTR(c), new_config) < 0)
                        return log_oom();

                TAKE_PTR(new_config);
        }

        if (c == COMPRESSION_NONE) {
                /* disables all configs except for 'none' */
                ORDERED_HASHMAP_FOREACH(cc, *configs)
                        if (cc->algorithm != COMPRESSION_NONE)
                                free(ordered_hashmap_remove(*configs, INT_TO_PTR(cc->algorithm)));
        } else
                /* otherwise, drop 'none' if stored. */
                free(ordered_hashmap_get(*configs, INT_TO_PTR(COMPRESSION_NONE)));

        return 1;
}

int compression_configs_mangle(OrderedHashmap **configs) {
        int r;

        /* When compression is explicitly disabled, then free the list. */
        if (ordered_hashmap_contains(*configs, INT_TO_PTR(COMPRESSION_NONE))) {
                *configs = ordered_hashmap_free(*configs);
                return 0;
        }

        /* When compression algorithms are explicitly specified, then honor the list. */
        if (!ordered_hashmap_isempty(*configs))
                return 0;

        /* If nothing specified, then list all supported algorithms with the default compression level. */

        _cleanup_(ordered_hashmap_freep) OrderedHashmap *h = NULL;

        /* First, put the default algorithm. */
        if (DEFAULT_COMPRESSION != COMPRESSION_NONE) {
                r = compression_config_put(&h, DEFAULT_COMPRESSION, -1);
                if (r < 0)
                        return r;
        }

        /* Then, list all other algorithms. */
        for (Compression c = 1; c < _COMPRESSION_MAX; c++) {
                r = compression_config_put(&h, c, -1);
                if (r < 0)
                        return r;
        }

        return free_and_replace_full(*configs, h, ordered_hashmap_free);
}

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
                /* an empty string clears the previous assignments. */
                *configs = ordered_hashmap_free(*configs);
                return 1;
        }

        if (parse_boolean(rvalue) == 0)
                /* 'no' disables compression. To indicate that, store 'none'. */
                return compression_config_put(configs, COMPRESSION_NONE, -1);

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

                r = compression_config_put(configs, c, level);
                if (r < 0)
                        return r;
        }
}
