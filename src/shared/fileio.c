/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <unistd.h>
#include <sys/sendfile.h>
#include "fileio.h"
#include "util.h"
#include "strv.h"
#include "utf8.h"
#include "ctype.h"

int write_string_to_file(FILE *f, const char *line) {
        errno = 0;
        fputs(line, f);
        if (!endswith(line, "\n"))
                fputc('\n', f);

        fflush(f);

        if (ferror(f))
                return errno ? -errno : -EIO;

        return 0;
}

int write_string_file(const char *fn, const char *line) {
        _cleanup_fclose_ FILE *f = NULL;

        assert(fn);
        assert(line);

        f = fopen(fn, "we");
        if (!f)
                return -errno;

        return write_string_to_file(f, line);
}

int write_string_file_atomic(const char *fn, const char *line) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(fn);
        assert(line);

        r = fopen_temporary(fn, &f, &p);
        if (r < 0)
                return r;

        fchmod_umask(fileno(f), 0644);

        errno = 0;
        fputs(line, f);
        if (!endswith(line, "\n"))
                fputc('\n', f);

        fflush(f);

        if (ferror(f))
                r = errno ? -errno : -EIO;
        else {
                if (rename(p, fn) < 0)
                        r = -errno;
                else
                        r = 0;
        }

        if (r < 0)
                unlink(p);

        return r;
}

int read_one_line_file(const char *fn, char **line) {
        _cleanup_fclose_ FILE *f = NULL;
        char t[LINE_MAX], *c;

        assert(fn);
        assert(line);

        f = fopen(fn, "re");
        if (!f)
                return -errno;

        if (!fgets(t, sizeof(t), f)) {

                if (ferror(f))
                        return errno ? -errno : -EIO;

                t[0] = 0;
        }

        c = strdup(t);
        if (!c)
                return -ENOMEM;
        truncate_nl(c);

        *line = c;
        return 0;
}

ssize_t sendfile_full(int out_fd, const char *fn) {
        _cleanup_fclose_ FILE *f;
        struct stat st;
        int r;
        ssize_t s;

        size_t n, l;
        _cleanup_free_ char *buf = NULL;

        assert(out_fd > 0);
        assert(fn);

        f = fopen(fn, "re");
        if (!f)
                return -errno;

        r = fstat(fileno(f), &st);
        if (r < 0)
                return -errno;

        s = sendfile(out_fd, fileno(f), NULL, st.st_size);
        if (s < 0)
                if (errno == EINVAL || errno == ENOSYS) {
                        /* continue below */
                } else
                        return -errno;
        else
                return s;

        /* sendfile() failed, fall back to read/write */

        /* Safety check */
        if (st.st_size > 4*1024*1024)
                return -E2BIG;

        n = st.st_size > 0 ? st.st_size : LINE_MAX;
        l = 0;

        while (true) {
                char *t;
                size_t k;

                t = realloc(buf, n);
                if (!t)
                        return -ENOMEM;

                buf = t;
                k = fread(buf + l, 1, n - l, f);

                if (k <= 0) {
                        if (ferror(f))
                                return -errno;

                        break;
                }

                l += k;
                n *= 2;

                /* Safety check */
                if (n > 4*1024*1024)
                        return -E2BIG;
        }

        r = write(out_fd, buf, l);
        if (r < 0)
                return -errno;

        return (ssize_t) l;
}

int read_full_file(const char *fn, char **contents, size_t *size) {
        _cleanup_fclose_ FILE *f = NULL;
        size_t n, l;
        _cleanup_free_ char *buf = NULL;
        struct stat st;

        assert(fn);
        assert(contents);

        f = fopen(fn, "re");
        if (!f)
                return -errno;

        if (fstat(fileno(f), &st) < 0)
                return -errno;

        /* Safety check */
        if (st.st_size > 4*1024*1024)
                return -E2BIG;

        n = st.st_size > 0 ? st.st_size : LINE_MAX;
        l = 0;

        for (;;) {
                char *t;
                size_t k;

                t = realloc(buf, n+1);
                if (!t)
                        return -ENOMEM;

                buf = t;
                k = fread(buf + l, 1, n - l, f);

                if (k <= 0) {
                        if (ferror(f))
                                return -errno;

                        break;
                }

                l += k;
                n *= 2;

                /* Safety check */
                if (n > 4*1024*1024)
                        return -E2BIG;
        }

        buf[l] = 0;
        *contents = buf;
        buf = NULL; /* do not free */

        if (size)
                *size = l;

        return 0;
}

static int parse_env_file_internal(
                const char *fname,
                const char *newline,
                int (*push) (const char *filename, unsigned line,
                             const char *key, char *value, void *userdata),
                void *userdata) {

        _cleanup_free_ char *contents = NULL, *key = NULL;
        size_t key_alloc = 0, n_key = 0, value_alloc = 0, n_value = 0, last_value_whitespace = (size_t) -1, last_key_whitespace = (size_t) -1;
        char *p, *value = NULL;
        int r;
        unsigned line = 1;

        enum {
                PRE_KEY,
                KEY,
                PRE_VALUE,
                VALUE,
                VALUE_ESCAPE,
                SINGLE_QUOTE_VALUE,
                SINGLE_QUOTE_VALUE_ESCAPE,
                DOUBLE_QUOTE_VALUE,
                DOUBLE_QUOTE_VALUE_ESCAPE,
                COMMENT,
                COMMENT_ESCAPE
        } state = PRE_KEY;

        assert(fname);
        assert(newline);

        r = read_full_file(fname, &contents, NULL);
        if (r < 0)
                return r;

        for (p = contents; *p; p++) {
                char c = *p;

                switch (state) {

                case PRE_KEY:
                        if (strchr(COMMENTS, c))
                                state = COMMENT;
                        else if (!strchr(WHITESPACE, c)) {
                                state = KEY;
                                last_key_whitespace = (size_t) -1;

                                if (!greedy_realloc((void**) &key, &key_alloc, n_key+2)) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                key[n_key++] = c;
                        }
                        break;

                case KEY:
                        if (strchr(newline, c)) {
                                state = PRE_KEY;
                                line ++;
                                n_key = 0;
                        } else if (c == '=') {
                                state = PRE_VALUE;
                                last_value_whitespace = (size_t) -1;
                        } else {
                                if (!strchr(WHITESPACE, c))
                                        last_key_whitespace = (size_t) -1;
                                else if (last_key_whitespace == (size_t) -1)
                                         last_key_whitespace = n_key;

                                if (!greedy_realloc((void**) &key, &key_alloc, n_key+2)) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                key[n_key++] = c;
                        }

                        break;

                case PRE_VALUE:
                        if (strchr(newline, c)) {
                                state = PRE_KEY;
                                line ++;
                                key[n_key] = 0;

                                if (value)
                                        value[n_value] = 0;

                                /* strip trailing whitespace from key */
                                if (last_key_whitespace != (size_t) -1)
                                        key[last_key_whitespace] = 0;

                                r = push(fname, line, key, value, userdata);
                                if (r < 0)
                                        goto fail;

                                n_key = 0;
                                value = NULL;
                                value_alloc = n_value = 0;

                        } else if (c == '\'')
                                state = SINGLE_QUOTE_VALUE;
                        else if (c == '\"')
                                state = DOUBLE_QUOTE_VALUE;
                        else if (c == '\\')
                                state = VALUE_ESCAPE;
                        else if (!strchr(WHITESPACE, c)) {
                                state = VALUE;

                                if (!greedy_realloc((void**) &value, &value_alloc, n_value+2)) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                value[n_value++] = c;
                        }

                        break;

                case VALUE:
                        if (strchr(newline, c)) {
                                state = PRE_KEY;
                                line ++;

                                key[n_key] = 0;

                                if (value)
                                        value[n_value] = 0;

                                /* Chomp off trailing whitespace from value */
                                if (last_value_whitespace != (size_t) -1)
                                        value[last_value_whitespace] = 0;

                                /* strip trailing whitespace from key */
                                if (last_key_whitespace != (size_t) -1)
                                        key[last_key_whitespace] = 0;

                                r = push(fname, line, key, value, userdata);
                                if (r < 0)
                                        goto fail;

                                n_key = 0;
                                value = NULL;
                                value_alloc = n_value = 0;

                        } else if (c == '\\') {
                                state = VALUE_ESCAPE;
                                last_value_whitespace = (size_t) -1;
                        } else {
                                if (!strchr(WHITESPACE, c))
                                        last_value_whitespace = (size_t) -1;
                                else if (last_value_whitespace == (size_t) -1)
                                        last_value_whitespace = n_value;

                                if (!greedy_realloc((void**) &value, &value_alloc, n_value+2)) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                value[n_value++] = c;
                        }

                        break;

                case VALUE_ESCAPE:
                        state = VALUE;

                        if (!strchr(newline, c)) {
                                /* Escaped newlines we eat up entirely */
                                if (!greedy_realloc((void**) &value, &value_alloc, n_value+2)) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                value[n_value++] = c;
                        }
                        break;

                case SINGLE_QUOTE_VALUE:
                        if (c == '\'')
                                state = PRE_VALUE;
                        else if (c == '\\')
                                state = SINGLE_QUOTE_VALUE_ESCAPE;
                        else {
                                if (!greedy_realloc((void**) &value, &value_alloc, n_value+2)) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                value[n_value++] = c;
                        }

                        break;

                case SINGLE_QUOTE_VALUE_ESCAPE:
                        state = SINGLE_QUOTE_VALUE;

                        if (!strchr(newline, c)) {
                                if (!greedy_realloc((void**) &value, &value_alloc, n_value+2)) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                value[n_value++] = c;
                        }
                        break;

                case DOUBLE_QUOTE_VALUE:
                        if (c == '\"')
                                state = PRE_VALUE;
                        else if (c == '\\')
                                state = DOUBLE_QUOTE_VALUE_ESCAPE;
                        else {
                                if (!greedy_realloc((void**) &value, &value_alloc, n_value+2)) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                value[n_value++] = c;
                        }

                        break;

                case DOUBLE_QUOTE_VALUE_ESCAPE:
                        state = DOUBLE_QUOTE_VALUE;

                        if (!strchr(newline, c)) {
                                if (!greedy_realloc((void**) &value, &value_alloc, n_value+2)) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                value[n_value++] = c;
                        }
                        break;

                case COMMENT:
                        if (c == '\\')
                                state = COMMENT_ESCAPE;
                        else if (strchr(newline, c)) {
                                state = PRE_KEY;
                                line ++;
                        }
                        break;

                case COMMENT_ESCAPE:
                        state = COMMENT;
                        break;
                }
        }

        if (state == PRE_VALUE ||
            state == VALUE ||
            state == VALUE_ESCAPE ||
            state == SINGLE_QUOTE_VALUE ||
            state == SINGLE_QUOTE_VALUE_ESCAPE ||
            state == DOUBLE_QUOTE_VALUE ||
            state == DOUBLE_QUOTE_VALUE_ESCAPE) {

                key[n_key] = 0;

                if (value)
                        value[n_value] = 0;

                if (state == VALUE)
                        if (last_value_whitespace != (size_t) -1)
                                value[last_value_whitespace] = 0;

                /* strip trailing whitespace from key */
                if (last_key_whitespace != (size_t) -1)
                        key[last_key_whitespace] = 0;

                r = push(fname, line, key, value, userdata);
                if (r < 0)
                        goto fail;
        }

        return 0;

fail:
        free(value);
        return r;
}

static int parse_env_file_push(const char *filename, unsigned line,
                               const char *key, char *value, void *userdata) {

        const char *k;
        va_list aq, *ap = userdata;

        if (!utf8_is_valid(key)) {
                _cleanup_free_ char *p = utf8_escape_invalid(key);

                log_error("%s:%u: invalid UTF-8 in key '%s', ignoring.",
                          filename, line, p);
                return -EINVAL;
        }

        if (value && !utf8_is_valid(value)) {
                _cleanup_free_ char *p = utf8_escape_invalid(value);

                log_error("%s:%u: invalid UTF-8 value for key %s: '%s', ignoring.",
                          filename, line, key, p);
                return -EINVAL;
        }

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

int parse_env_file(
                const char *fname,
                const char *newline, ...) {

        va_list ap;
        int r;

        if (!newline)
                newline = NEWLINE;

        va_start(ap, newline);
        r = parse_env_file_internal(fname, newline, parse_env_file_push, &ap);
        va_end(ap);

        return r;
}

static int load_env_file_push(const char *filename, unsigned line,
                              const char *key, char *value, void *userdata) {
        char ***m = userdata;
        char *p;
        int r;

        if (!utf8_is_valid(key)) {
                _cleanup_free_ char *t = utf8_escape_invalid(key);

                log_error("%s:%u: invalid UTF-8 for key '%s', ignoring.",
                          filename, line, t);
                return -EINVAL;
        }

        if (value && !utf8_is_valid(value)) {
                _cleanup_free_ char *t = utf8_escape_invalid(value);

                log_error("%s:%u: invalid UTF-8 value for key %s: '%s', ignoring.",
                          filename, line, key, t);
                return -EINVAL;
        }

        p = strjoin(key, "=", strempty(value), NULL);
        if (!p)
                return -ENOMEM;

        r = strv_consume(m, p);
        if (r < 0)
                return r;

        free(value);
        return 0;
}

int load_env_file(const char *fname, const char *newline, char ***rl) {
        char **m = NULL;
        int r;

        if (!newline)
                newline = NEWLINE;

        r = parse_env_file_internal(fname, newline, load_env_file_push, &m);
        if (r < 0) {
                strv_free(m);
                return r;
        }

        *rl = m;
        return 0;
}

static void write_env_var(FILE *f, const char *v) {
        const char *p;

        p = strchr(v, '=');
        if (!p) {
                /* Fallback */
                fputs(v, f);
                fputc('\n', f);
                return;
        }

        p++;
        fwrite(v, 1, p-v, f);

        if (string_has_cc(p) || chars_intersect(p, WHITESPACE "\'\"\\`$")) {
                fputc('\"', f);

                for (; *p; p++) {
                        if (strchr("\'\"\\`$", *p))
                                fputc('\\', f);

                        fputc(*p, f);
                }

                fputc('\"', f);
        } else
                fputs(p, f);

        fputc('\n', f);
}

int write_env_file(const char *fname, char **l) {
        char **i;
        _cleanup_free_ char *p = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        r = fopen_temporary(fname, &f, &p);
        if (r < 0)
                return r;

        fchmod_umask(fileno(f), 0644);

        errno = 0;
        STRV_FOREACH(i, l)
                write_env_var(f, *i);

        fflush(f);

        if (ferror(f))
                r = errno ? -errno : -EIO;
        else {
                if (rename(p, fname) < 0)
                        r = -errno;
                else
                        r = 0;
        }

        if (r < 0)
                unlink(p);

        return r;
}

int executable_is_script(const char *path, char **interpreter) {
        int r;
        char _cleanup_free_ *line = NULL;
        int len;
        char *ans;

        assert(path);

        r = read_one_line_file(path, &line);
        if (r < 0)
                return r;

        if (!startswith(line, "#!"))
                return 0;

        ans = strstrip(line + 2);
        len = strcspn(ans, " \t");

        if (len == 0)
                return 0;

        ans = strndup(ans, len);
        if (!ans)
                return -ENOMEM;

        *interpreter = ans;
        return 1;
}

/**
 * Retrieve one field from a file like /proc/self/status.  pattern
 * should start with '\n' and end with a ':'. Whitespace and zeros
 * after the ':' will be skipped. field must be freed afterwards.
 */
int get_status_field(const char *filename, const char *pattern, char **field) {
        _cleanup_free_ char *status = NULL;
        char *t;
        size_t len;
        int r;

        assert(filename);
        assert(pattern);
        assert(field);

        r = read_full_file(filename, &status, NULL);
        if (r < 0)
                return r;

        t = strstr(status, pattern);
        if (!t)
                return -ENOENT;

        t += strlen(pattern);
        if (*t) {
                t += strspn(t, " \t");

                /* Also skip zeros, because when this is used for
                 * capabilities, we don't want the zeros. This way the
                 * same capability set always maps to the same string,
                 * irrespective of the total capability set size. For
                 * other numbers it shouldn't matter. */
                t += strspn(t, "0");
                /* Back off one char if there's nothing but whitespace
                   and zeros */
                if (!*t || isspace(*t))
                        t --;
        }

        len = strcspn(t, WHITESPACE);

        *field = strndup(t, len);
        if (!*field)
                return -ENOMEM;

        return 0;
}
