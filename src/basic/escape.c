/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "escape.h"
#include "hexdecoct.h"
#include "macro.h"
#include "utf8.h"

int cescape_char(char c, char *buf) {
        char *buf_old = buf;

        /* Needs space for 4 characters in the buffer */

        switch (c) {

                case '\a':
                        *(buf++) = '\\';
                        *(buf++) = 'a';
                        break;
                case '\b':
                        *(buf++) = '\\';
                        *(buf++) = 'b';
                        break;
                case '\f':
                        *(buf++) = '\\';
                        *(buf++) = 'f';
                        break;
                case '\n':
                        *(buf++) = '\\';
                        *(buf++) = 'n';
                        break;
                case '\r':
                        *(buf++) = '\\';
                        *(buf++) = 'r';
                        break;
                case '\t':
                        *(buf++) = '\\';
                        *(buf++) = 't';
                        break;
                case '\v':
                        *(buf++) = '\\';
                        *(buf++) = 'v';
                        break;
                case '\\':
                        *(buf++) = '\\';
                        *(buf++) = '\\';
                        break;
                case '"':
                        *(buf++) = '\\';
                        *(buf++) = '"';
                        break;
                case '\'':
                        *(buf++) = '\\';
                        *(buf++) = '\'';
                        break;

                default:
                        /* For special chars we prefer octal over
                         * hexadecimal encoding, simply because glib's
                         * g_strescape() does the same */
                        if ((c < ' ') || (c >= 127)) {
                                *(buf++) = '\\';
                                *(buf++) = octchar((unsigned char) c >> 6);
                                *(buf++) = octchar((unsigned char) c >> 3);
                                *(buf++) = octchar((unsigned char) c);
                        } else
                                *(buf++) = c;
                        break;
        }

        return buf - buf_old;
}

char *cescape_length(const char *s, size_t n) {
        const char *f;
        char *r, *t;

        assert(s || n == 0);

        /* Does C style string escaping. May be reversed with
         * cunescape(). */

        r = new(char, n*4 + 1);
        if (!r)
                return NULL;

        for (f = s, t = r; f < s + n; f++)
                t += cescape_char(*f, t);

        *t = 0;

        return r;
}

char *cescape(const char *s) {
        assert(s);

        return cescape_length(s, strlen(s));
}

int cunescape_one(const char *p, size_t length, char32_t *ret, bool *eight_bit) {
        int r = 1;

        assert(p);
        assert(ret);

        /* Unescapes C style. Returns the unescaped character in ret.
         * Sets *eight_bit to true if the escaped sequence either fits in
         * one byte in UTF-8 or is a non-unicode literal byte and should
         * instead be copied directly.
         */

        if (length != (size_t) -1 && length < 1)
                return -EINVAL;

        switch (p[0]) {

        case 'a':
                *ret = '\a';
                break;
        case 'b':
                *ret = '\b';
                break;
        case 'f':
                *ret = '\f';
                break;
        case 'n':
                *ret = '\n';
                break;
        case 'r':
                *ret = '\r';
                break;
        case 't':
                *ret = '\t';
                break;
        case 'v':
                *ret = '\v';
                break;
        case '\\':
                *ret = '\\';
                break;
        case '"':
                *ret = '"';
                break;
        case '\'':
                *ret = '\'';
                break;

        case 's':
                /* This is an extension of the XDG syntax files */
                *ret = ' ';
                break;

        case 'x': {
                /* hexadecimal encoding */
                int a, b;

                if (length != (size_t) -1 && length < 3)
                        return -EINVAL;

                a = unhexchar(p[1]);
                if (a < 0)
                        return -EINVAL;

                b = unhexchar(p[2]);
                if (b < 0)
                        return -EINVAL;

                /* Don't allow NUL bytes */
                if (a == 0 && b == 0)
                        return -EINVAL;

                *ret = (a << 4U) | b;
                *eight_bit = true;
                r = 3;
                break;
        }

        case 'u': {
                /* C++11 style 16bit unicode */

                int a[4];
                size_t i;
                uint32_t c;

                if (length != (size_t) -1 && length < 5)
                        return -EINVAL;

                for (i = 0; i < 4; i++) {
                        a[i] = unhexchar(p[1 + i]);
                        if (a[i] < 0)
                                return a[i];
                }

                c = ((uint32_t) a[0] << 12U) | ((uint32_t) a[1] << 8U) | ((uint32_t) a[2] << 4U) | (uint32_t) a[3];

                /* Don't allow 0 chars */
                if (c == 0)
                        return -EINVAL;

                *ret = c;
                r = 5;
                break;
        }

        case 'U': {
                /* C++11 style 32bit unicode */

                int a[8];
                size_t i;
                char32_t c;

                if (length != (size_t) -1 && length < 9)
                        return -EINVAL;

                for (i = 0; i < 8; i++) {
                        a[i] = unhexchar(p[1 + i]);
                        if (a[i] < 0)
                                return a[i];
                }

                c = ((uint32_t) a[0] << 28U) | ((uint32_t) a[1] << 24U) | ((uint32_t) a[2] << 20U) | ((uint32_t) a[3] << 16U) |
                    ((uint32_t) a[4] << 12U) | ((uint32_t) a[5] <<  8U) | ((uint32_t) a[6] <<  4U) |  (uint32_t) a[7];

                /* Don't allow 0 chars */
                if (c == 0)
                        return -EINVAL;

                /* Don't allow invalid code points */
                if (!unichar_is_valid(c))
                        return -EINVAL;

                *ret = c;
                r = 9;
                break;
        }

        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7': {
                /* octal encoding */
                int a, b, c;
                char32_t m;

                if (length != (size_t) -1 && length < 3)
                        return -EINVAL;

                a = unoctchar(p[0]);
                if (a < 0)
                        return -EINVAL;

                b = unoctchar(p[1]);
                if (b < 0)
                        return -EINVAL;

                c = unoctchar(p[2]);
                if (c < 0)
                        return -EINVAL;

                /* don't allow NUL bytes */
                if (a == 0 && b == 0 && c == 0)
                        return -EINVAL;

                /* Don't allow bytes above 255 */
                m = ((uint32_t) a << 6U) | ((uint32_t) b << 3U) | (uint32_t) c;
                if (m > 255)
                        return -EINVAL;

                *ret = m;
                *eight_bit = true;
                r = 3;
                break;
        }

        default:
                return -EINVAL;
        }

        return r;
}

int cunescape_length_with_prefix(const char *s, size_t length, const char *prefix, UnescapeFlags flags, char **ret) {
        char *r, *t;
        const char *f;
        size_t pl;

        assert(s);
        assert(ret);

        /* Undoes C style string escaping, and optionally prefixes it. */

        pl = strlen_ptr(prefix);

        r = new(char, pl+length+1);
        if (!r)
                return -ENOMEM;

        if (prefix)
                memcpy(r, prefix, pl);

        for (f = s, t = r + pl; f < s + length; f++) {
                size_t remaining;
                bool eight_bit = false;
                char32_t u;
                int k;

                remaining = s + length - f;
                assert(remaining > 0);

                if (*f != '\\') {
                        /* A literal, copy verbatim */
                        *(t++) = *f;
                        continue;
                }

                if (remaining == 1) {
                        if (flags & UNESCAPE_RELAX) {
                                /* A trailing backslash, copy verbatim */
                                *(t++) = *f;
                                continue;
                        }

                        free(r);
                        return -EINVAL;
                }

                k = cunescape_one(f + 1, remaining - 1, &u, &eight_bit);
                if (k < 0) {
                        if (flags & UNESCAPE_RELAX) {
                                /* Invalid escape code, let's take it literal then */
                                *(t++) = '\\';
                                continue;
                        }

                        free(r);
                        return k;
                }

                f += k;
                if (eight_bit)
                        /* One byte? Set directly as specified */
                        *(t++) = u;
                else
                        /* Otherwise encode as multi-byte UTF-8 */
                        t += utf8_encode_unichar(t, u);
        }

        *t = 0;

        *ret = r;
        return t - r;
}

int cunescape_length(const char *s, size_t length, UnescapeFlags flags, char **ret) {
        return cunescape_length_with_prefix(s, length, NULL, flags, ret);
}

int cunescape(const char *s, UnescapeFlags flags, char **ret) {
        return cunescape_length(s, strlen(s), flags, ret);
}

char *xescape_full(const char *s, const char *bad, size_t console_width, bool eight_bits) {
        char *ans, *t, *prev, *prev2;
        const char *f;

        /* Escapes all chars in bad, in addition to \ and all special chars, in \xFF style escaping. May be
         * reversed with cunescape(). If eight_bits is true, characters >= 127 are let through unchanged.
         * This corresponds to non-ASCII printable characters in pre-unicode encodings.
         *
         * If console_width is reached, output is truncated and "..." is appended. */

        if (console_width == 0)
                return strdup("");

        ans = new(char, MIN(strlen(s), console_width) * 4 + 1);
        if (!ans)
                return NULL;

        memset(ans, '_', MIN(strlen(s), console_width) * 4);
        ans[MIN(strlen(s), console_width) * 4] = 0;

        for (f = s, t = prev = prev2 = ans; ; f++) {
                char *tmp_t = t;

                if (!*f) {
                        *t = 0;
                        return ans;
                }

                if ((unsigned char) *f < ' ' || (!eight_bits && (unsigned char) *f >= 127) ||
                    *f == '\\' || strchr(bad, *f)) {
                        if ((size_t) (t - ans) + 4 > console_width)
                                break;

                        *(t++) = '\\';
                        *(t++) = 'x';
                        *(t++) = hexchar(*f >> 4);
                        *(t++) = hexchar(*f);
                } else {
                        if ((size_t) (t - ans) + 1 > console_width)
                                break;

                        *(t++) = *f;
                }

                /* We might need to go back two cycles to fit three dots, so remember two positions */
                prev2 = prev;
                prev = tmp_t;
        }

        /* We can just write where we want, since chars are one-byte */
        size_t c = MIN(console_width, 3u); /* If the console is too narrow, write fewer dots */
        size_t off;
        if (console_width - c >= (size_t) (t - ans))
                off = (size_t) (t - ans);
        else if (console_width - c >= (size_t) (prev - ans))
                off = (size_t) (prev - ans);
        else if (console_width - c >= (size_t) (prev2 - ans))
                off = (size_t) (prev2 - ans);
        else
                off = console_width - c;
        assert(off <= (size_t) (t - ans));

        memcpy(ans + off, "...", c);
        ans[off + c] = '\0';
        return ans;
}

char *escape_non_printable_full(const char *str, size_t console_width, bool eight_bit) {
        if (eight_bit)
                return xescape_full(str, "", console_width, true);
        else
                return utf8_escape_non_printable_full(str, console_width);
}

char *octescape(const char *s, size_t len) {
        char *r, *t;
        const char *f;

        /* Escapes all chars in bad, in addition to \ and " chars,
         * in \nnn style escaping. */

        r = new(char, len * 4 + 1);
        if (!r)
                return NULL;

        for (f = s, t = r; f < s + len; f++) {

                if (*f < ' ' || *f >= 127 || IN_SET(*f, '\\', '"')) {
                        *(t++) = '\\';
                        *(t++) = '0' + (*f >> 6);
                        *(t++) = '0' + ((*f >> 3) & 8);
                        *(t++) = '0' + (*f & 8);
                } else
                        *(t++) = *f;
        }

        *t = 0;

        return r;

}

static char *strcpy_backslash_escaped(char *t, const char *s, const char *bad, bool escape_tab_nl) {
        assert(bad);

        for (; *s; s++) {
                if (escape_tab_nl && IN_SET(*s, '\n', '\t')) {
                        *(t++) = '\\';
                        *(t++) = *s == '\n' ? 'n' : 't';
                        continue;
                }

                if (*s == '\\' || strchr(bad, *s))
                        *(t++) = '\\';

                *(t++) = *s;
        }

        return t;
}

char *shell_escape(const char *s, const char *bad) {
        char *r, *t;

        r = new(char, strlen(s)*2+1);
        if (!r)
                return NULL;

        t = strcpy_backslash_escaped(r, s, bad, false);
        *t = 0;

        return r;
}

char* shell_maybe_quote(const char *s, EscapeStyle style) {
        const char *p;
        char *r, *t;

        assert(s);

        /* Encloses a string in quotes if necessary to make it OK as a shell
         * string. Note that we treat benign UTF-8 characters as needing
         * escaping too, but that should be OK. */

        for (p = s; *p; p++)
                if (*p <= ' ' ||
                    *p >= 127 ||
                    strchr(SHELL_NEED_QUOTES, *p))
                        break;

        if (!*p)
                return strdup(s);

        r = new(char, (style == ESCAPE_POSIX) + 1 + strlen(s)*2 + 1 + 1);
        if (!r)
                return NULL;

        t = r;
        if (style == ESCAPE_BACKSLASH)
                *(t++) = '"';
        else if (style == ESCAPE_POSIX) {
                *(t++) = '$';
                *(t++) = '\'';
        } else
                assert_not_reached("Bad EscapeStyle");

        t = mempcpy(t, s, p - s);

        if (style == ESCAPE_BACKSLASH)
                t = strcpy_backslash_escaped(t, p, SHELL_NEED_ESCAPE, false);
        else
                t = strcpy_backslash_escaped(t, p, SHELL_NEED_ESCAPE_POSIX, true);

        if (style == ESCAPE_BACKSLASH)
                *(t++) = '"';
        else
                *(t++) = '\'';
        *t = 0;

        return r;
}
