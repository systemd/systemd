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

typedef int (*push_env_func_t)(
                const char *filename,
                unsigned line,
                const char *key,
                char *value,
                void *userdata);

static int parse_env_file_internal(
                FILE *f,
                const char *fname,
                push_env_func_t push,
                void *userdata) {

        size_t n_key = 0, n_value = 0, last_value_whitespace = SIZE_MAX, last_key_whitespace = SIZE_MAX;
        _cleanup_free_ void *contents = NULL;
        _cleanup_free_ char *key = NULL, *value = NULL;
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

        assert(f || fname);
        assert(push);

        if (f)
                r = read_full_stream(f, &contents, NULL);
        else
                r = read_full_file(fname, &contentsp, NULL);
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
                                        return -ENOMEM;

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
                        log_debug("The line which doesn't begin with \";\" or \"#\", but follows a comment" \
                                  " line trailing with escape is now treated as a non comment line since v254.");
                        if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                                line++;
                        } else
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

        assert(key);

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

        assert(key);

        r = check_utf8ness_and_warn(filename, line, key, value);
        if (r < 0)
                return r;

        va_copy(aq, *ap);

        while ((k = va_arg(aq, const char *))) {
                char **v;

                v = va_arg(aq, char **);

                if (streq(key, k)) {
                        va_end(aq);
                        free_and_replace(*v, value);

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

        assert(f || fname);

        va_copy(aq, ap);
        r = parse_env_file_internal(f, fname, parse_env_file_push, &aq);
        va_end(aq);
        return r;
}

int parse_env_file_fdv(int fd, const char *fname, va_list ap) {
        _cleanup_fclose_ FILE *f = NULL;
        va_list aq;
        int r;

        assert(fd >= 0);

        r = fdopen_independent(fd, "re", &f);
        if (r < 0)
                return r;

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

        assert(f || fname);

        va_start(ap, fname);
        r = parse_env_filev(f, fname, ap);
        va_end(ap);

        return r;
}

int parse_env_file_fd_sentinel(
                int fd,
                const char *fname, /* only used for logging */
                ...) {

        va_list ap;
        int r;

        assert(fd >= 0);

        va_start(ap, fname);
        r = parse_env_file_fdv(fd, fname, ap);
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

        assert(key);

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

int load_env_file(FILE *f, const char *fname, char ***ret) {
        _cleanup_strv_free_ char **m = NULL;
        int r;

        assert(f || fname);
        assert(ret);

        r = parse_env_file_internal(f, fname, load_env_file_push, &m);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

static int load_env_file_push_pairs(
                const char *filename, unsigned line,
                const char *key, char *value,
                void *userdata) {

        char ***m = ASSERT_PTR(userdata);
        int r;

        assert(key);

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

int load_env_file_pairs(FILE *f, const char *fname, char ***ret) {
        _cleanup_strv_free_ char **m = NULL;
        int r;

        assert(f || fname);
        assert(ret);

        r = parse_env_file_internal(f, fname, load_env_file_push_pairs, &m);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

int load_env_file_pairs_fd(int fd, const char *fname, char ***ret) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(fd >= 0);

        r = fdopen_independent(fd, "re", &f);
        if (r < 0)
                return r;

        return load_env_file_pairs(f, fname, ret);
}

static int merge_env_file_push(
                const char *filename, unsigned line,
                const char *key, char *value,
                void *userdata) {

        char ***env = ASSERT_PTR(userdata);
        char *expanded_value;
        int r;

        assert(key);

        if (!value) {
                log_error("%s:%u: invalid syntax (around \"%s\"), ignoring.", strna(filename), line, key);
                return 0;
        }

        if (!env_name_is_valid(key)) {
                log_error("%s:%u: invalid variable name \"%s\", ignoring.", strna(filename), line, key);
                free(value);
                return 0;
        }

        r = replace_env(value,
                        *env,
                        REPLACE_ENV_USE_ENVIRONMENT|REPLACE_ENV_ALLOW_BRACELESS|REPLACE_ENV_ALLOW_EXTENDED,
                        &expanded_value);
        if (r < 0)
                return log_error_errno(r, "%s:%u: Failed to expand variable '%s': %m", strna(filename), line, value);

        free_and_replace(value, expanded_value);

        log_debug("%s:%u: setting %s=%s", filename, line, key, value);

        return load_env_file_push(filename, line, key, value, env);
}

int merge_env_file(
                char ***env,
                FILE *f,
                const char *fname) {

        assert(env);
        assert(f || fname);

        /* NOTE: this function supports braceful and braceless variable expansions,
         * plus "extended" substitutions, unlike other exported parsing functions.
         */

        return parse_env_file_internal(f, fname, merge_env_file_push, env);
}

static void write_env_var(FILE *f, const char *v) {
        const char *p;

        assert(f);
        assert(v);

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

int write_env_file(int dir_fd, const char *fname, char **headers, char **l) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(fname);

        r = fopen_temporary_at(dir_fd, fname, &f, &p);
        if (r < 0)
                return r;

        (void) fchmod_umask(fileno(f), 0644);

        STRV_FOREACH(i, headers) {
                assert(isempty(*i) || startswith(*i, "#"));
                fputs_unlocked(*i, f);
                fputc_unlocked('\n', f);
        }

        STRV_FOREACH(i, l)
                write_env_var(f, *i);

        r = fflush_and_check(f);
        if (r >= 0) {
                if (renameat(dir_fd, p, dir_fd, fname) >= 0)
                        return 0;

                r = -errno;
        }

        (void) unlinkat(dir_fd, p, 0);
        return r;
}

int write_vconsole_conf(int dir_fd, const char *fname, char **l) {
        char **headers = STRV_MAKE(
                "# Written by systemd-localed(8) or systemd-firstboot(1), read by systemd-localed",
                "# and systemd-vconsole-setup(8). Use localectl(1) to update this file.");

        return write_env_file(dir_fd, fname, headers, l);
}
