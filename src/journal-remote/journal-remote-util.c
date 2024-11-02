#include "extract-word.h"
#include "journal-remote-util.h"
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

        CompressionArgs *args = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                args = NULL;
                return 1;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *algorithm = NULL, *word = NULL;
                int level = -1;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);
                if (r == 0)
                        break;

                const char *q = word;
                r = extract_first_word(&q, &algorithm, ":", 0);
                if (r < 0)
                        return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

                Compression c = compression_lowercase_from_string(algorithm);
                if (c < 0 || !compression_supported(c)) {
                        log_syntax(unit, LOG_WARNING, filename, line, c,
                                   "Compression=%s is not supported on a system, ignoring", algorithm);
                        continue;
                }

                if (!isempty(q)) {
                        r = safe_atoi(q, &level);
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "Compression level %s should be positive, ignoring", word);
                                continue;
                        }
                }

                bool found = false;
                for (size_t i = 0; i < args->size; i++) {
                        if (args->opts[i].algorithm == c) {
                                args->opts[i].level = level;
                                found = true;
                                break;
                        }
                }

                if (found) {
                        continue;
                }

                if (!GREEDY_REALLOC(args->opts, (args->size + 1) * sizeof(CompressionOpts))) {
                        return log_oom();
                }

                args->opts[args->size].algorithm = c;
                args->opts[args->size].level = level;
                args->size++;
        }
        return 1;
}
