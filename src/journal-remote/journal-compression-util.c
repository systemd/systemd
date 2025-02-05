/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "extract-word.h"
#include "journal-compression-util.h"
#include "parse-util.h"

void compression_args_clear(CompressionArgs *args) {
        assert(args);
        args->size = 0;
        args->opts = mfree(args->opts);
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

        CompressionArgs *args = ASSERT_PTR(data);
        bool parse_level = ltype;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                compression_args_clear(args);
                return 1;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *algorithm = NULL, *word = NULL;
                int level = -1;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);
                if (r == 0)
                        return 1;

                if (parse_level) {
                        const char *q = word;
                        r = extract_first_word(&q, &algorithm, ":", 0);
                        if (r < 0)
                                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);
                        if (!isempty(q)) {
                                r = safe_atoi(q, &level);
                                if (r < 0) {
                                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                                   "Compression level %s should be positive, ignoring.", q);
                                        continue;
                                }
                        }
                } else
                        algorithm = TAKE_PTR(word);

                Compression c = compression_lowercase_from_string(algorithm);
                if (c < 0 || !compression_supported(c)) {
                        log_syntax(unit, LOG_WARNING, filename, line, c,
                                   "Compression=%s is not supported on a system, ignoring.", algorithm);
                        continue;
                }

                bool found = false;
                FOREACH_ARRAY(opt, args->opts, args->size)
                        if (opt->algorithm == c) {
                                found = true;
                                if (parse_level)
                                        opt->level = level;
                                break;
                        }

                if (found)
                        continue;

                if (!GREEDY_REALLOC(args->opts, args->size + 1))
                        return log_oom();

                args->opts[args->size++] = (CompressionOpts) {
                        .algorithm = c,
                        .level = level,
                };
        }
}
