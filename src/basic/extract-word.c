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

#include "alloc-util.h"
#include "escape.h"
#include "extract-word.h"
#include "string-util.h"
#include "utf8.h"
#include "util.h"

int extract_first_word(const char **p, char **ret, const char *separators, ExtractFlags flags) {
        _cleanup_free_ char *s = NULL;
        size_t allocated = 0, sz = 0;
        char c;
        int r;

        char quote = 0;                 /* 0 or ' or " */
        bool backslash = false;         /* whether we've just seen a backslash */

        assert(p);
        assert(ret);

        /* Bail early if called after last value or with no input */
        if (!*p)
                goto finish_force_terminate;
        c = **p;

        if (!separators)
                separators = WHITESPACE;

        /* Parses the first word of a string, and returns it in
         * *ret. Removes all quotes in the process. When parsing fails
         * (because of an uneven number of quotes or similar), leaves
         * the pointer *p at the first invalid character. */

        if (flags & EXTRACT_DONT_COALESCE_SEPARATORS)
                if (!GREEDY_REALLOC(s, allocated, sz+1))
                        return -ENOMEM;

        for (;; (*p) ++, c = **p) {
                if (c == 0)
                        goto finish_force_terminate;
                else if (strchr(separators, c)) {
                        if (flags & EXTRACT_DONT_COALESCE_SEPARATORS) {
                                (*p) ++;
                                goto finish_force_next;
                        }
                } else {
                        /* We found a non-blank character, so we will always
                         * want to return a string (even if it is empty),
                         * allocate it here. */
                        if (!GREEDY_REALLOC(s, allocated, sz+1))
                                return -ENOMEM;
                        break;
                }
        }

        for (;; (*p) ++, c = **p) {
                if (backslash) {
                        if (!GREEDY_REALLOC(s, allocated, sz+7))
                                return -ENOMEM;

                        if (c == 0) {
                                if ((flags & EXTRACT_CUNESCAPE_RELAX) &&
                                    (!quote || flags & EXTRACT_RELAX)) {
                                        /* If we find an unquoted trailing backslash and we're in
                                         * EXTRACT_CUNESCAPE_RELAX mode, keep it verbatim in the
                                         * output.
                                         *
                                         * Unbalanced quotes will only be allowed in EXTRACT_RELAX
                                         * mode, EXTRACT_CUNESCAPE_RELAX mode does not allow them.
                                         */
                                        s[sz++] = '\\';
                                        goto finish_force_terminate;
                                }
                                if (flags & EXTRACT_RELAX)
                                        goto finish_force_terminate;
                                return -EINVAL;
                        }

                        if (flags & EXTRACT_CUNESCAPE) {
                                uint32_t u;

                                r = cunescape_one(*p, (size_t) -1, &c, &u);
                                if (r < 0) {
                                        if (flags & EXTRACT_CUNESCAPE_RELAX) {
                                                s[sz++] = '\\';
                                                s[sz++] = c;
                                        } else
                                                return -EINVAL;
                                } else {
                                        (*p) += r - 1;

                                        if (c != 0)
                                                s[sz++] = c; /* normal explicit char */
                                        else
                                                sz += utf8_encode_unichar(s + sz, u); /* unicode chars we'll encode as utf8 */
                                }
                        } else
                                s[sz++] = c;

                        backslash = false;

                } else if (quote) {     /* inside either single or double quotes */
                        for (;; (*p) ++, c = **p) {
                                if (c == 0) {
                                        if (flags & EXTRACT_RELAX)
                                                goto finish_force_terminate;
                                        return -EINVAL;
                                } else if (c == quote) {        /* found the end quote */
                                        quote = 0;
                                        break;
                                } else if (c == '\\' && !(flags & EXTRACT_RETAIN_ESCAPE)) {
                                        backslash = true;
                                        break;
                                } else {
                                        if (!GREEDY_REALLOC(s, allocated, sz+2))
                                                return -ENOMEM;

                                        s[sz++] = c;
                                }
                        }

                } else {
                        for (;; (*p) ++, c = **p) {
                                if (c == 0)
                                        goto finish_force_terminate;
                                else if ((c == '\'' || c == '"') && (flags & EXTRACT_QUOTES)) {
                                        quote = c;
                                        break;
                                } else if (c == '\\' && !(flags & EXTRACT_RETAIN_ESCAPE)) {
                                        backslash = true;
                                        break;
                                } else if (strchr(separators, c)) {
                                        if (flags & EXTRACT_DONT_COALESCE_SEPARATORS) {
                                                (*p) ++;
                                                goto finish_force_next;
                                        }
                                        /* Skip additional coalesced separators. */
                                        for (;; (*p) ++, c = **p) {
                                                if (c == 0)
                                                        goto finish_force_terminate;
                                                if (!strchr(separators, c))
                                                        break;
                                        }
                                        goto finish;

                                } else {
                                        if (!GREEDY_REALLOC(s, allocated, sz+2))
                                                return -ENOMEM;

                                        s[sz++] = c;
                                }
                        }
                }
        }

finish_force_terminate:
        *p = NULL;
finish:
        if (!s) {
                *p = NULL;
                *ret = NULL;
                return 0;
        }

finish_force_next:
        s[sz] = 0;
        *ret = s;
        s = NULL;

        return 1;
}

int extract_first_word_and_warn(
                const char **p,
                char **ret,
                const char *separators,
                ExtractFlags flags,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *rvalue) {

        /* Try to unquote it, if it fails, warn about it and try again
         * but this time using EXTRACT_CUNESCAPE_RELAX to keep the
         * backslashes verbatim in invalid escape sequences. */

        const char *save;
        int r;

        save = *p;
        r = extract_first_word(p, ret, separators, flags);
        if (r >= 0)
                return r;

        if (r == -EINVAL && !(flags & EXTRACT_CUNESCAPE_RELAX)) {

                /* Retry it with EXTRACT_CUNESCAPE_RELAX. */
                *p = save;
                r = extract_first_word(p, ret, separators, flags|EXTRACT_CUNESCAPE_RELAX);
                if (r >= 0) {
                        /* It worked this time, hence it must have been an invalid escape sequence we could correct. */
                        log_syntax(unit, LOG_WARNING, filename, line, EINVAL, "Invalid escape sequences in line, correcting: \"%s\"", rvalue);
                        return r;
                }

                /* If it's still EINVAL; then it must be unbalanced quoting, report this. */
                if (r == -EINVAL)
                        return log_syntax(unit, LOG_ERR, filename, line, r, "Unbalanced quoting, ignoring: \"%s\"", rvalue);
        }

        /* Can be any error, report it */
        return log_syntax(unit, LOG_ERR, filename, line, r, "Unable to decode word \"%s\", ignoring: %m", rvalue);
}

int extract_many_words(const char **p, const char *separators, ExtractFlags flags, ...) {
        va_list ap;
        char **l;
        int n = 0, i, c, r;

        /* Parses a number of words from a string, stripping any
         * quotes if necessary. */

        assert(p);

        /* Count how many words are expected */
        va_start(ap, flags);
        for (;;) {
                if (!va_arg(ap, char **))
                        break;
                n++;
        }
        va_end(ap);

        if (n <= 0)
                return 0;

        /* Read all words into a temporary array */
        l = newa0(char*, n);
        for (c = 0; c < n; c++) {

                r = extract_first_word(p, &l[c], separators, flags);
                if (r < 0) {
                        int j;

                        for (j = 0; j < c; j++)
                                free(l[j]);

                        return r;
                }

                if (r == 0)
                        break;
        }

        /* If we managed to parse all words, return them in the passed
         * in parameters */
        va_start(ap, flags);
        for (i = 0; i < n; i++) {
                char **v;

                v = va_arg(ap, char **);
                assert(v);

                *v = l[i];
        }
        va_end(ap);

        return c;
}
