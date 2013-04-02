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
#include "fileio.h"
#include "util.h"
#include "strv.h"

int write_string_file(const char *fn, const char *line) {
        _cleanup_fclose_ FILE *f = NULL;

        assert(fn);
        assert(line);

        f = fopen(fn, "we");
        if (!f)
                return -errno;

        errno = 0;
        if (fputs(line, f) < 0)
                return errno ? -errno : -EIO;

        if (!endswith(line, "\n"))
                fputc('\n', f);

        fflush(f);

        if (ferror(f))
                return errno ? -errno : -EIO;

        return 0;
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
        if (fputs(line, f) < 0) {
                r = -errno;
                goto finish;
        }

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

finish:
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
        buf = NULL;

        if (size)
                *size = l;

        return 0;
}

int parse_env_file(
                const char *fname,
                const char *separator, ...) {

        int r = 0;
        char *contents = NULL, *p;

        assert(fname);
        assert(separator);

        r = read_full_file(fname, &contents, NULL);
        if (r < 0)
                return r;

        p = contents;
        for (;;) {
                const char *key = NULL;

                p += strspn(p, separator);
                p += strspn(p, WHITESPACE);

                if (!*p)
                        break;

                if (!strchr(COMMENTS, *p)) {
                        va_list ap;
                        char **value;

                        va_start(ap, separator);
                        while ((key = va_arg(ap, char *))) {
                                size_t n;
                                char *v;

                                value = va_arg(ap, char **);

                                n = strlen(key);
                                if (!strneq(p, key, n) ||
                                    p[n] != '=')
                                        continue;

                                p += n + 1;
                                n = strcspn(p, separator);

                                if (n >= 2 &&
                                    strchr(QUOTES, p[0]) &&
                                    p[n-1] == p[0])
                                        v = strndup(p+1, n-2);
                                else
                                        v = strndup(p, n);

                                if (!v) {
                                        r = -ENOMEM;
                                        va_end(ap);
                                        goto fail;
                                }

                                if (v[0] == '\0') {
                                        /* return empty value strings as NULL */
                                        free(v);
                                        v = NULL;
                                }

                                free(*value);
                                *value = v;

                                p += n;

                                r ++;
                                break;
                        }
                        va_end(ap);
                }

                if (!key)
                        p += strcspn(p, separator);
        }

fail:
        free(contents);
        return r;
}

int load_env_file(const char *fname, char ***rl) {

        _cleanup_fclose_ FILE *f;
        _cleanup_strv_free_ char **m = NULL;
        _cleanup_free_ char *c = NULL;

        assert(fname);
        assert(rl);

        /* This reads an environment file, but will not complain about
         * any invalid assignments, that needs to be done by the
         * caller */

        f = fopen(fname, "re");
        if (!f)
                return -errno;

        while (!feof(f)) {
                char l[LINE_MAX], *p, *cs, *b;

                if (!fgets(l, sizeof(l), f)) {
                        if (ferror(f))
                                return -errno;

                        /* The previous line was a continuation line?
                         * Let's process it now, before we leave the
                         * loop */
                        if (c)
                                goto process;

                        break;
                }

                /* Is this a continuation line? If so, just append
                 * this to c, and go to next line right-away */
                cs = endswith(l, "\\\n");
                if (cs) {
                        *cs = '\0';
                        b = strappend(c, l);
                        if (!b)
                                return -ENOMEM;

                        free(c);
                        c = b;
                        continue;
                }

                /* If the previous line was a continuation line,
                 * append the current line to it */
                if (c) {
                        b = strappend(c, l);
                        if (!b)
                                return -ENOMEM;

                        free(c);
                        c = b;
                }

        process:
                p = strstrip(c ? c : l);

                if (*p && !strchr(COMMENTS, *p)) {
                        _cleanup_free_ char *u;
                        int k;

                        u = normalize_env_assignment(p);
                        if (!u)
                                return -ENOMEM;

                        k = strv_extend(&m, u);
                        if (k < 0)
                                return -ENOMEM;
                }

                free(c);
                c = NULL;
        }

        *rl = m;
        m = NULL;

        return 0;
}

int write_env_file(const char *fname, char **l) {
        char **i;
        char _cleanup_free_ *p = NULL;
        FILE _cleanup_fclose_ *f = NULL;
        int r;

        r = fopen_temporary(fname, &f, &p);
        if (r < 0)
                return r;

        fchmod_umask(fileno(f), 0644);

        errno = 0;
        STRV_FOREACH(i, l) {
                fputs(*i, f);
                fputc('\n', f);
        }

        fflush(f);

        if (ferror(f)) {
                if (errno > 0)
                        r = -errno;
                else
                        r = -EIO;
        } else {
                if (rename(p, fname) < 0)
                        r = -errno;
                else
                        r = 0;
        }

        if (r < 0)
                unlink(p);

        return r;
}
