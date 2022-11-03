/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "env-file.h"
#include "env-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "utf8.h"

static int parse_env_file_internal(
                FILE *f,
                const char *fname,
                int (*push) (const char *filename, unsigned line,
                             const char *key, char *value, void *userdata),
                void *userdata) {

        size_t n_key = 0, n_value = 0, last_value_whitespace = SIZE_MAX, last_key_whitespace = SIZE_MAX;
        _cleanup_free_ char *contents = NULL, *key = NULL, *value = NULL;
        unsigned line = 1;
        int r;

        enum {
                PRE_KEY,
                KEY,
                PRE_VALUE,
                VALUE,
                VALUE_ESCAPE,
                SINGLE_QUOTE_VALUE,
                DOUBLE_QUOTE_VALUE,
                DOUBLE_QUOTE_VALUE_ESCAPE,
                COMMENT,
                COMMENT_ESCAPE
        } state = PRE_KEY;

        if (f)
                r = read_full_stream(f, &contents, NULL);
        else
                r = read_full_file(fname, &contents, NULL);
        if (r < 0)
                return r;

        for (char *p = contents; *p; p++) {
                char c = *p;

                switch (state) {

                case PRE_KEY:
                        if (strchr(COMMENTS, c))
                                state = COMMENT;
                        else if (!strchr(WHITESPACE, c)) {
                                state = KEY;
                                last_key_whitespace = SIZE_MAX;

                                if (!GREEDY_REALLOC(key, n_key+2))
                                        return -ENOMEM;

                                key[n_key++] = c;
                        }
                        break;

                case KEY:
                        if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                                line++;
                                n_key = 0;
                        } else if (c == '=') {
                                state = PRE_VALUE;
                                last_value_whitespace = SIZE_MAX;
                        } else {
                                if (!strchr(WHITESPACE, c))
                                        last_key_whitespace = SIZE_MAX;
                                else if (last_key_whitespace == SIZE_MAX)
                                         last_key_whitespace = n_key;

                                if (!GREEDY_REALLOC(key, n_key+2))
                                        return -ENOMEM;

                                key[n_key++] = c;
                        }

                        break;

                case PRE_VALUE:
                        if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                                line++;
                                key[n_key] = 0;

                                if (value)
                                        value[n_value] = 0;

                                /* strip trailing whitespace from key */
                                if (last_key_whitespace != SIZE_MAX)
                                        key[last_key_whitespace] = 0;

                                r = push(fname, line, key, value, userdata);
                                if (r < 0)
                                        return r;

                                n_key = 0;
                                value = NULL;
                                n_value = 0;

                        } else if (c == '\'')
                                state = SINGLE_QUOTE_VALUE;
                        else if (c == '"')
                                state = DOUBLE_QUOTE_VALUE;
                        else if (c == '\\')
                                state = VALUE_ESCAPE;
                        else if (!strchr(WHITESPACE, c)) {
                                state = VALUE;

                                if (!GREEDY_REALLOC(value, n_value+2))
                                        return  -ENOMEM;

                                value[n_value++] = c;
                        }

                        break;

                case VALUE:
                        if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                                line++;

                                key[n_key] = 0;

                                if (value)
                                        value[n_value] = 0;

                                /* Chomp off trailing whitespace from value */
                                if (last_value_whitespace != SIZE_MAX)
                                        value[last_value_whitespace] = 0;

                                /* strip trailing whitespace from key */
                                if (last_key_whitespace != SIZE_MAX)
                                        key[last_key_whitespace] = 0;

                                r = push(fname, line, key, value, userdata);
                                if (r < 0)
                                        return r;

                                n_key = 0;
                                value = NULL;
                                n_value = 0;

                        } else if (c == '\\') {
                                state = VALUE_ESCAPE;
                                last_value_whitespace = SIZE_MAX;
                        } else {
                                if (!strchr(WHITESPACE, c))
                                        last_value_whitespace = SIZE_MAX;
                                else if (last_value_whitespace == SIZE_MAX)
                                        last_value_whitespace = n_value;

                                if (!GREEDY_REALLOC(value, n_value+2))
                                        return -ENOMEM;

                                value[n_value++] = c;
                        }

                        break;

                case VALUE_ESCAPE:
                        state = VALUE;

                        if (!strchr(NEWLINE, c)) {
                                /* Escaped newlines we eat up entirely */
                                if (!GREEDY_REALLOC(value, n_value+2))
                                        return -ENOMEM;

                                value[n_value++] = c;
                        }
                        break;

                case SINGLE_QUOTE_VALUE:
                        if (c == '\'')
                                state = PRE_VALUE;
                        else {
                                if (!GREEDY_REALLOC(value, n_value+2))
                                        return -ENOMEM;

                                value[n_value++] = c;
                        }

                        break;

                case DOUBLE_QUOTE_VALUE:
                        if (c == '"')
                                state = PRE_VALUE;
                        else if (c == '\\')
                                state = DOUBLE_QUOTE_VALUE_ESCAPE;
                        else {
                                if (!GREEDY_REALLOC(value, n_value+2))
                                        return -ENOMEM;

                                value[n_value++] = c;
                        }

                        break;

                case DOUBLE_QUOTE_VALUE_ESCAPE:
                        state = DOUBLE_QUOTE_VALUE;

                        if (strchr(SHELL_NEED_ESCAPE, c)) {
                                /* If this is a char that needs escaping, just unescape it. */
                                if (!GREEDY_REALLOC(value, n_value+2))
                                        return -ENOMEM;
                                value[n_value++] = c;
                        } else if (c != '\n') {
                                /* If other char than what needs escaping, keep the "\" in place, like the
                                 * real shell does. */
                                if (!GREEDY_REALLOC(value, n_value+3))
                                        return -ENOMEM;
                                value[n_value++] = '\\';
                                value[n_value++] = c;
                        }

                        /* Escaped newlines (aka "continuation lines") are eaten up entirely */
                        break;

                case COMMENT:
                        if (c == '\\')
                                state = COMMENT_ESCAPE;
                        else if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                                line++;
                        }
                        break;

                case COMMENT_ESCAPE:
                        state = COMMENT;
                        break;
                }
        }

        if (IN_SET(state,
                   PRE_VALUE,
                   VALUE,
                   VALUE_ESCAPE,
                   SINGLE_QUOTE_VALUE,
                   DOUBLE_QUOTE_VALUE,
                   DOUBLE_QUOTE_VALUE_ESCAPE)) {

                key[n_key] = 0;

                if (value)
                        value[n_value] = 0;

                if (state == VALUE)
                        if (last_value_whitespace != SIZE_MAX)
                                value[last_value_whitespace] = 0;

                /* strip trailing whitespace from key */
                if (last_key_whitespace != SIZE_MAX)
                        key[last_key_whitespace] = 0;

                r = push(fname, line, key, value, userdata);
                if (r < 0)
                        return r;

                value = NULL;
        }

        return 0;
}

static int check_utf8ness_and_warn(
                const char *filename, unsigned line,
                const char *key, char *value) {

        if (!utf8_is_valid(key)) {
                _cleanup_free_ char *p = NULL;

                p = utf8_escape_invalid(key);
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s:%u: invalid UTF-8 in key '%s', ignoring.",
                                       strna(filename), line, p);
        }

        if (value && !utf8_is_valid(value)) {
                _cleanup_free_ char *p = NULL;

                p = utf8_escape_invalid(value);
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s:%u: invalid UTF-8 value for key %s: '%s', ignoring.",
                                       strna(filename), line, key, p);
        }

        return 0;
}

static int parse_env_file_push(
                const char *filename, unsigned line,
                const char *key, char *value,
                void *userdata) {

        const char *k;
        va_list aq, *ap = userdata;
        int r;

        r = check_utf8ness_and_warn(filename, line, key, value);
        if (r < 0)
                return r;

        va_copy(aq, *ap);

        while ((k = va_arg(aq, const char *))) {
                char **v;

                v = va_arg(aq, char **);

                if (streq(key, k)) {
                        va_end(aq);
                        free(*v);
                        *v = value;

                        return 1;
                }
        }

        va_end(aq);
        free(value);

        return 0;
}

int parse_env_filev(
                FILE *f,
                const char *fname,
                va_list ap) {

        int r;
        va_list aq;

        va_copy(aq, ap);
        r = parse_env_file_internal(f, fname, parse_env_file_push, &aq);
        va_end(aq);
        return r;
}

int parse_env_file_sentinel(
                FILE *f,
                const char *fname,
                ...) {

        va_list ap;
        int r;

        va_start(ap, fname);
        r = parse_env_filev(f, fname, ap);
        va_end(ap);

        return r;
}

static int load_env_file_push(
                const char *filename, unsigned line,
                const char *key, char *value,
                void *userdata) {
        char ***m = userdata;
        char *p;
        int r;

        r = check_utf8ness_and_warn(filename, line, key, value);
        if (r < 0)
                return r;

        p = strjoin(key, "=", value);
        if (!p)
                return -ENOMEM;

        r = strv_env_replace_consume(m, p);
        if (r < 0)
                return r;

        free(value);
        return 0;
}

int load_env_file(FILE *f, const char *fname, char ***rl) {
        _cleanup_strv_free_ char **m = NULL;
        int r;

        r = parse_env_file_internal(f, fname, load_env_file_push, &m);
        if (r < 0)
                return r;

        *rl = TAKE_PTR(m);
        return 0;
}

static int load_env_file_push_pairs(
                const char *filename, unsigned line,
                const char *key, char *value,
                void *userdata) {

        char ***m = ASSERT_PTR(userdata);
        int r;

        r = check_utf8ness_and_warn(filename, line, key, value);
        if (r < 0)
                return r;

        /* Check if the key is present */
        for (char **t = *m; t && *t; t += 2)
                if (streq(t[0], key)) {
                        if (value)
                                return free_and_replace(t[1], value);
                        else
                                return free_and_strdup(t+1, "");
                }

        r = strv_extend(m, key);
        if (r < 0)
                return r;

        if (value)
                return strv_push(m, value);
        else
                return strv_extend(m, "");
}

int load_env_file_pairs(FILE *f, const char *fname, char ***rl) {
        _cleanup_strv_free_ char **m = NULL;
        int r;

        r = parse_env_file_internal(f, fname, load_env_file_push_pairs, &m);
        if (r < 0)
                return r;

        *rl = TAKE_PTR(m);
        return 0;
}

static int merge_env_file_push(
                const char *filename, unsigned line,
                const char *key, char *value,
                void *userdata) {

        char ***env = ASSERT_PTR(userdata);
        char *expanded_value;

        if (!value) {
                log_error("%s:%u: invalid syntax (around \"%s\"), ignoring.", strna(filename), line, key);
                return 0;
        }

        if (!env_name_is_valid(key)) {
                log_error("%s:%u: invalid variable name \"%s\", ignoring.", strna(filename), line, key);
                free(value);
                return 0;
        }

        expanded_value = replace_env(value, *env,
                                     REPLACE_ENV_USE_ENVIRONMENT|
                                     REPLACE_ENV_ALLOW_BRACELESS|
                                     REPLACE_ENV_ALLOW_EXTENDED);
        if (!expanded_value)
                return -ENOMEM;

        free_and_replace(value, expanded_value);

        log_debug("%s:%u: setting %s=%s", filename, line, key, value);

        return load_env_file_push(filename, line, key, value, env);
}

int merge_env_file(
                char ***env,
                FILE *f,
                const char *fname) {

        /* NOTE: this function supports braceful and braceless variable expansions,
         * plus "extended" substitutions, unlike other exported parsing functions.
         */

        return parse_env_file_internal(f, fname, merge_env_file_push, env);
}

static void write_env_var(FILE *f, const char *v) {
        const char *p;

        p = strchr(v, '=');
        if (!p) {
                /* Fallback */
                fputs_unlocked(v, f);
                fputc_unlocked('\n', f);
                return;
        }

        p++;
        fwrite_unlocked(v, 1, p-v, f);

        if (string_has_cc(p, NULL) || chars_intersect(p, WHITESPACE SHELL_NEED_QUOTES)) {
                fputc_unlocked('"', f);

                for (; *p; p++) {
                        if (strchr(SHELL_NEED_ESCAPE, *p))
                                fputc_unlocked('\\', f);

                        fputc_unlocked(*p, f);
                }

                fputc_unlocked('"', f);
        } else
                fputs_unlocked(p, f);

        fputc_unlocked('\n', f);
}

int write_env_file(const char *fname, char **l) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(fname);

        r = fopen_temporary(fname, &f, &p);
        if (r < 0)
                return r;

        (void) fchmod_umask(fileno(f), 0644);

        STRV_FOREACH(i, l)
                write_env_var(f, *i);

        r = fflush_and_check(f);
        if (r >= 0) {
                if (rename(p, fname) >= 0)
                        return 0;

                r = -errno;
        }

        (void) unlink(p);
        return r;
}
