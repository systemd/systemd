/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "escape.h"
#include "extract-word.h"
#include "glyph-util.h"
#include "gunicode.h"
#include "locale-util.h"
#include "log.h"
#include "memory-util.h"
#include "memstream-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "utf8.h"

char* first_word(const char *s, const char *word) {
        assert(s);
        assert(word);

        /* Checks if the string starts with the specified word, either followed by NUL or by whitespace.
         * Returns a pointer to the NUL or the first character after the whitespace. */

        if (isempty(word))
                return (char*) s;

        const char *p = startswith(s, word);
        if (!p)
                return NULL;
        if (*p == '\0')
                return (char*) p;

        const char *nw = skip_leading_chars(p, WHITESPACE);
        if (p == nw)
                return NULL;

        return (char*) nw;
}

char* strextendn(char **x, const char *s, size_t l) {
        assert(x);
        assert(s || l == 0);

        if (l > 0)
                l = strnlen(s, l); /* ignore trailing noise */

        if (l > 0 || !*x) {
                size_t q;
                char *m;

                q = strlen_ptr(*x);
                m = realloc(*x, q + l + 1);
                if (!m)
                        return NULL;

                *mempcpy_typesafe(m + q, s, l) = 0;

                *x = m;
        }

        return *x;
}

char* strstrip(char *s) {
        if (!s)
                return NULL;

        /* Drops trailing whitespace. Modifies the string in place. Returns pointer to first non-space character */

        return delete_trailing_chars(skip_leading_chars(s, WHITESPACE), WHITESPACE);
}

char* delete_chars(char *s, const char *bad) {
        char *f, *t;

        /* Drops all specified bad characters, regardless where in the string */

        if (!s)
                return NULL;

        if (!bad)
                bad = WHITESPACE;

        for (f = s, t = s; *f; f++) {
                if (strchr(bad, *f))
                        continue;

                *(t++) = *f;
        }

        *t = 0;

        return s;
}

char* delete_trailing_chars(char *s, const char *bad) {
        char *c = s;

        /* Drops all specified bad characters, at the end of the string */

        if (!s)
                return NULL;

        if (!bad)
                bad = WHITESPACE;

        for (char *p = s; *p; p++)
                if (!strchr(bad, *p))
                        c = p + 1;

        *c = 0;

        return s;
}

char* truncate_nl_full(char *s, size_t *ret_len) {
        size_t n;

        assert(s);

        n = strcspn(s, NEWLINE);
        s[n] = '\0';
        if (ret_len)
                *ret_len = n;
        return s;
}

char ascii_tolower(char x) {

        if (x >= 'A' && x <= 'Z')
                return x - 'A' + 'a';

        return x;
}

char ascii_toupper(char x) {

        if (x >= 'a' && x <= 'z')
                return x - 'a' + 'A';

        return x;
}

char* ascii_strlower(char *s) {
        assert(s);

        for (char *p = s; *p; p++)
                *p = ascii_tolower(*p);

        return s;
}

char* ascii_strupper(char *s) {
        assert(s);

        for (char *p = s; *p; p++)
                *p = ascii_toupper(*p);

        return s;
}

char* ascii_strlower_n(char *s, size_t n) {
        if (n <= 0)
                return s;

        for (size_t i = 0; i < n; i++)
                s[i] = ascii_tolower(s[i]);

        return s;
}

int ascii_strcasecmp_n(const char *a, const char *b, size_t n) {

        for (; n > 0; a++, b++, n--) {
                int x, y;

                x = (int) (uint8_t) ascii_tolower(*a);
                y = (int) (uint8_t) ascii_tolower(*b);

                if (x != y)
                        return x - y;
        }

        return 0;
}

int ascii_strcasecmp_nn(const char *a, size_t n, const char *b, size_t m) {
        int r;

        r = ascii_strcasecmp_n(a, b, MIN(n, m));
        if (r != 0)
                return r;

        return CMP(n, m);
}

bool chars_intersect(const char *a, const char *b) {
        /* Returns true if any of the chars in a are in b. */
        for (const char *p = a; *p; p++)
                if (strchr(b, *p))
                        return true;

        return false;
}

bool string_has_cc(const char *p, const char *ok) {
        assert(p);

        /*
         * Check if a string contains control characters. If 'ok' is
         * non-NULL it may be a string containing additional CCs to be
         * considered OK.
         */

        for (const char *t = p; *t; t++) {
                if (ok && strchr(ok, *t))
                        continue;

                if (char_is_cc(*t))
                        return true;
        }

        return false;
}

static int write_ellipsis(char *buf, bool unicode) {
        const char *s = glyph_full(GLYPH_ELLIPSIS, unicode);
        assert(strlen(s) == 3);
        memcpy(buf, s, 3);
        return 3;
}

static size_t ansi_sequence_length(const char *s, size_t len) {
        assert(s);

        if (len < 2)
                return 0;

        if (s[0] != 0x1B)  /* ASCII 27, aka ESC, aka Ctrl-[ */
                return 0;  /* Not the start of a sequence */

        if (s[1] == 0x5B) { /* [, start of CSI sequence */
                size_t i = 2;

                if (i == len)
                        return 0;

                while (s[i] >= 0x30 && s[i] <= 0x3F) /* Parameter bytes */
                        if (++i == len)
                                return 0;
                while (s[i] >= 0x20 && s[i] <= 0x2F) /* Intermediate bytes */
                        if (++i == len)
                                return 0;
                if (s[i] >= 0x40 && s[i] <= 0x7E) /* Final byte */
                        return i + 1;
                return 0;  /* Bad sequence */

        } else if (s[1] >= 0x40 && s[1] <= 0x5F) /* other non-CSI Fe sequence */
                return 2;

        return 0;  /* Bad escape? */
}

static bool string_has_ansi_sequence(const char *s, size_t len) {
        const char *t = s;

        while ((t = memchr(t, 0x1B, len - (t - s)))) {
                if (ansi_sequence_length(t, len - (t - s)) > 0)
                        return true;
                t++;
        }
        return false;
}

static size_t previous_ansi_sequence(const char *s, size_t length, const char **ret_where) {
        /* Locate the previous ANSI sequence and save its start in *ret_where and return length. */

        for (size_t i = length - 2; i > 0; i--) {  /* -2 because at least two bytes are needed */
                size_t slen = ansi_sequence_length(s + (i - 1), length - (i - 1));
                if (slen == 0)
                        continue;

                *ret_where = s + (i - 1);
                return slen;
        }

        *ret_where = NULL;
        return 0;
}

static char *ascii_ellipsize_mem(const char *s, size_t old_length, size_t new_length, unsigned percent) {
        size_t x, need_space, suffix_len;
        char *t;

        assert(s);
        assert(percent <= 100);
        assert(new_length != SIZE_MAX);

        if (old_length <= new_length)
                return strndup(s, old_length);

        /* Special case short ellipsations */
        switch (new_length) {

        case 0:
                return strdup("");

        case 1:
                if (is_locale_utf8())
                        return strdup("…");
                else
                        return strdup(".");

        case 2:
                if (!is_locale_utf8())
                        return strdup("..");
                break;
        }

        /* Calculate how much space the ellipsis will take up. If we are in UTF-8 mode we only need space for one
         * character ("…"), otherwise for three characters ("..."). Note that in both cases we need 3 bytes of storage,
         * either for the UTF-8 encoded character or for three ASCII characters. */
        need_space = is_locale_utf8() ? 1 : 3;

        t = new(char, new_length+3);
        if (!t)
                return NULL;

        assert(new_length >= need_space);

        x = ((new_length - need_space) * percent + 50) / 100;
        assert(x <= new_length - need_space);

        write_ellipsis(mempcpy(t, s, x), /* unicode= */ false);
        suffix_len = new_length - x - need_space;
        memcpy(t + x + 3, s + old_length - suffix_len, suffix_len);
        *(t + x + 3 + suffix_len) = '\0';

        return t;
}

char* ellipsize_mem(const char *s, size_t old_length, size_t new_length, unsigned percent) {
        size_t x, k, len, len2;
        const char *i, *j;
        int r;

        /* Note that 'old_length' refers to bytes in the string, while 'new_length' refers to character cells taken up
         * on screen. This distinction doesn't matter for ASCII strings, but it does matter for non-ASCII UTF-8
         * strings.
         *
         * Ellipsation is done in a locale-dependent way:
         * 1. If the string passed in is fully ASCII and the current locale is not UTF-8, three dots are used ("...")
         * 2. Otherwise, a unicode ellipsis is used ("…")
         *
         * In other words: you'll get a unicode ellipsis as soon as either the string contains non-ASCII characters or
         * the current locale is UTF-8.
         */

        assert(s);
        assert(percent <= 100);

        if (new_length == SIZE_MAX)
                return strndup(s, old_length);

        if (new_length == 0)
                return strdup("");

        bool has_ansi_seq = string_has_ansi_sequence(s, old_length);

        /* If no multibyte characters or ANSI sequences, use ascii_ellipsize_mem for speed */
        if (!has_ansi_seq && ascii_is_valid_n(s, old_length))
                return ascii_ellipsize_mem(s, old_length, new_length, percent);

        x = (new_length - 1) * percent / 100;
        assert(x <= new_length - 1);

        k = 0;
        for (i = s; i < s + old_length; ) {
                size_t slen = has_ansi_seq ? ansi_sequence_length(i, old_length - (i - s)) : 0;
                if (slen > 0) {
                        i += slen;
                        continue;  /* ANSI sequences don't take up any space in output */
                }

                char32_t c;
                r = utf8_encoded_to_unichar(i, &c);
                if (r < 0)
                        return NULL;

                int w = unichar_iswide(c) ? 2 : 1;
                if (k + w > x)
                        break;

                k += w;
                i += r;
        }

        const char *ansi_start = s + old_length;
        size_t ansi_len = 0;

        for (const char *t = j = s + old_length; t > i && k < new_length; ) {
                char32_t c;
                int w;
                const char *tt;

                if (has_ansi_seq && ansi_start >= t)
                        /* Figure out the previous ANSI sequence, if any */
                        ansi_len = previous_ansi_sequence(s, t - s, &ansi_start);

                /* If the sequence extends all the way to the current position, skip it. */
                if (has_ansi_seq && ansi_len > 0 && ansi_start + ansi_len == t) {
                        t = ansi_start;
                        continue;
                }

                tt = utf8_prev_char(t);
                r = utf8_encoded_to_unichar(tt, &c);
                if (r < 0)
                        return NULL;

                w = unichar_iswide(c) ? 2 : 1;
                if (k + w > new_length)
                        break;

                k += w;
                j = t = tt;  /* j should always point to the first "real" character */
        }

        /* We don't actually need to ellipsize */
        if (i >= j)
                return memdup_suffix0(s, old_length);

        if (k >= new_length) {
                /* Make space for ellipsis, if required and possible. We know that the edge character is not
                 * part of an ANSI sequence (because then we'd skip it). If the last character we looked at
                 * was wide, we don't need to make space. */
                if (j < s + old_length)
                        j = utf8_next_char(j);
                else if (i > s)
                        i = utf8_prev_char(i);
        }

        len = i - s;
        len2 = s + old_length - j;

        /* If we have ANSI, allow the same length as the source string + ellipsis. It'd be too involved to
         * figure out what exact space is needed. Strings with ANSI sequences are most likely to be fairly
         * short anyway. */
        size_t alloc_len = has_ansi_seq ? old_length + 3 + 1 : len + 3 + len2 + 1;

        char *e = new(char, alloc_len);
        if (!e)
                return NULL;

        memcpy_safe(e, s, len);
        write_ellipsis(e + len, /* unicode= */ true);

        char *dst = e + len + 3;

        if (has_ansi_seq)
                /* Copy over any ANSI sequences in full */
                for (const char *p = s + len; p < j; ) {
                        size_t slen = ansi_sequence_length(p, j - p);
                        if (slen > 0) {
                                dst = mempcpy(dst, p, slen);
                                p += slen;
                        } else
                                p = utf8_next_char(p);
                }

        memcpy_safe(dst, j, len2);
        dst[len2] = '\0';

        return e;
}

char* cellescape(char *buf, size_t len, const char *s) {
        /* Escape and ellipsize s into buffer buf of size len. Only non-control ASCII
         * characters are copied as they are, everything else is escaped. The result
         * is different then if escaping and ellipsization was performed in two
         * separate steps, because each sequence is either stored in full or skipped.
         *
         * This function should be used for logging about strings which expected to
         * be plain ASCII in a safe way.
         *
         * An ellipsis will be used if s is too long. It was always placed at the
         * very end.
         */

        size_t i = 0, last_char_width[4] = {}, k = 0;

        assert(buf);
        assert(len > 0); /* at least a terminating NUL */
        assert(s);

        for (;;) {
                char four[4];
                int w;

                if (*s == 0) /* terminating NUL detected? then we are done! */
                        goto done;

                w = cescape_char(*s, four);
                if (i + w + 1 > len) /* This character doesn't fit into the buffer anymore? In that case let's
                                      * ellipsize at the previous location */
                        break;

                /* OK, there was space, let's add this escaped character to the buffer */
                memcpy(buf + i, four, w);
                i += w;

                /* And remember its width in the ring buffer */
                last_char_width[k] = w;
                k = (k + 1) % 4;

                s++;
        }

        /* Ellipsation is necessary. This means we might need to truncate the string again to make space for 4
         * characters ideally, but the buffer is shorter than that in the first place take what we can get */
        for (size_t j = 0; j < ELEMENTSOF(last_char_width); j++) {

                if (i + 4 <= len) /* nice, we reached our space goal */
                        break;

                k = k == 0 ? 3 : k - 1;
                if (last_char_width[k] == 0) /* bummer, we reached the beginning of the strings */
                        break;

                assert(i >= last_char_width[k]);
                i -= last_char_width[k];
        }

        if (i + 4 <= len) /* yay, enough space */
                i += write_ellipsis(buf + i, /* unicode= */ false);
        else if (i + 3 <= len) { /* only space for ".." */
                buf[i++] = '.';
                buf[i++] = '.';
        } else if (i + 2 <= len) /* only space for a single "." */
                buf[i++] = '.';
        else
                assert(i + 1 <= len);

done:
        buf[i] = '\0';
        return buf;
}

char* strshorten(char *s, size_t l) {
        assert(s);

        if (l >= SIZE_MAX-1) /* Would not change anything */
                return s;

        if (strnlen(s, l+1) > l)
                s[l] = 0;

        return s;
}

int strgrowpad0(char **s, size_t l) {
        size_t sz;

        assert(s);

        if (*s) {
                sz = strlen(*s) + 1;
                if (sz >= l) /* never shrink */
                        return 0;
        } else
                sz = 0;

        char *q = realloc(*s, l);
        if (!q)
                return -ENOMEM;

        *s = q;

        memzero(*s + sz, l - sz);
        return 0;
}

char* strreplace(const char *text, const char *old_string, const char *new_string) {
        size_t l, old_len, new_len;
        char *t, *ret = NULL;
        const char *f;

        assert(old_string);
        assert(new_string);

        if (!text)
                return NULL;

        old_len = strlen(old_string);
        new_len = strlen(new_string);

        l = strlen(text);
        if (!GREEDY_REALLOC(ret, l+1))
                return NULL;

        f = text;
        t = ret;
        while (*f) {
                size_t d, nl;

                if (!startswith(f, old_string)) {
                        *(t++) = *(f++);
                        continue;
                }

                d = t - ret;
                nl = l - old_len + new_len;

                if (!GREEDY_REALLOC(ret, nl + 1))
                        return mfree(ret);

                l = nl;
                t = ret + d;

                t = stpcpy(t, new_string);
                f += old_len;
        }

        *t = 0;
        return ret;
}

static void advance_offsets(
                ssize_t diff,
                size_t offsets[2], /* note: we can't use [static 2] here, since this may be NULL */
                size_t shift[static 2],
                size_t size) {

        if (!offsets)
                return;

        assert(shift);

        if ((size_t) diff < offsets[0])
                shift[0] += size;
        if ((size_t) diff < offsets[1])
                shift[1] += size;
}

char* strip_tab_ansi(char **ibuf, size_t *_isz, size_t highlight[2]) {
        const char *begin = NULL;
        enum {
                STATE_OTHER,
                STATE_ESCAPE,
                STATE_CSI,
                STATE_OSC,
                STATE_OSC_CLOSING,
        } state = STATE_OTHER;
        _cleanup_(memstream_done) MemStream m = {};
        size_t isz, shift[2] = {}, n_carriage_returns = 0;
        FILE *f;

        assert(ibuf);
        assert(*ibuf);

        /* This does three things:
         *
         * 1. Replaces TABs by 8 spaces
         * 2. Strips ANSI color sequences (a subset of CSI), i.e. ESC '[' … 'm' sequences
         * 3. Strips ANSI operating system sequences (OSC), i.e. ESC ']' … ST sequences
         * 4. Strip trailing \r characters (since they would "move the cursor", but have no
         *    other effect).
         *
         * Everything else will be left as it is. In particular other ANSI sequences are left as they are, as
         * are any other special characters. Truncated ANSI sequences are left-as is too. This call is
         * supposed to suppress the most basic formatting noise, but nothing else.
         *
         * Why care for OSC sequences? Well, to undo what terminal_urlify() and friends generate. */

        isz = _isz ? *_isz : strlen(*ibuf);

        /* Note we turn off internal locking on f for performance reasons. It's safe to do so since we
         * created f here and it doesn't leave our scope. */
        f = memstream_init(&m);
        if (!f)
                return NULL;

        for (const char *i = *ibuf; i < *ibuf + isz + 1; i++) {

                bool eot = i >= *ibuf + isz;

                switch (state) {

                case STATE_OTHER:
                        if (eot)
                                break;

                        if (*i == '\r') {
                                n_carriage_returns++;
                                break;
                        } else if (*i == '\n')
                                /* Ignore carriage returns before new line */
                                n_carriage_returns = 0;
                        for (; n_carriage_returns > 0; n_carriage_returns--)
                                fputc('\r', f);

                        if (*i == '\x1B')
                                state = STATE_ESCAPE;
                        else if (*i == '\t') {
                                fputs("        ", f);
                                advance_offsets(i - *ibuf, highlight, shift, 7);
                        } else
                                fputc(*i, f);

                        break;

                case STATE_ESCAPE:
                        assert(n_carriage_returns == 0);

                        if (eot) {
                                fputc('\x1B', f);
                                advance_offsets(i - *ibuf, highlight, shift, 1);
                                break;
                        } else if (*i == '[') { /* ANSI CSI */
                                state = STATE_CSI;
                                begin = i + 1;
                        } else if (*i == ']') { /* ANSI OSC */
                                state = STATE_OSC;
                                begin = i + 1;
                        } else {
                                fputc('\x1B', f);
                                fputc(*i, f);
                                advance_offsets(i - *ibuf, highlight, shift, 1);
                                state = STATE_OTHER;
                        }

                        break;

                case STATE_CSI:
                        assert(n_carriage_returns == 0);

                        if (eot || !strchr(DIGITS ";:m", *i)) { /* EOT or invalid chars in sequence */
                                fputc('\x1B', f);
                                fputc('[', f);
                                advance_offsets(i - *ibuf, highlight, shift, 2);
                                state = STATE_OTHER;
                                i = begin-1;
                        } else if (*i == 'm')
                                state = STATE_OTHER;

                        break;

                case STATE_OSC:
                        assert(n_carriage_returns == 0);

                        /* There are three kinds of OSC terminators: \x07, \x1b\x5c or \x9c. We only support
                         * the first two, because the last one is a valid UTF-8 codepoint and hence creates
                         * an ambiguity (many Terminal emulators refuse to support it as well). */
                        if (eot || (!IN_SET(*i, '\x07', '\x1b') && !osc_char_is_valid(*i))) { /* EOT or invalid chars in sequence */
                                fputc('\x1B', f);
                                fputc(']', f);
                                advance_offsets(i - *ibuf, highlight, shift, 2);
                                state = STATE_OTHER;
                                i = begin-1;
                        } else if (*i == '\x07') /* Single character ST */
                                state = STATE_OTHER;
                        else if (*i == '\x1B')
                                state = STATE_OSC_CLOSING;

                        break;

                case STATE_OSC_CLOSING:
                        if (eot || *i != '\x5c') { /* EOT or incomplete two-byte ST in sequence */
                                fputc('\x1B', f);
                                fputc(']', f);
                                advance_offsets(i - *ibuf, highlight, shift, 2);
                                state = STATE_OTHER;
                                i = begin-1;
                        } else if (*i == '\x5c')
                                state = STATE_OTHER;

                        break;
                }
        }

        char *obuf;
        if (memstream_finalize(&m, &obuf, _isz) < 0)
                return NULL;

        free_and_replace(*ibuf, obuf);

        if (highlight) {
                highlight[0] += shift[0];
                highlight[1] += shift[1];
        }

        return *ibuf;
}

char* strextendv_with_separator(char **x, const char *separator, va_list ap) {
        _cleanup_free_ char *buffer = NULL;
        size_t f, l, l_separator;
        bool need_separator;
        char *nr, *p;

        if (!x)
                x = &buffer;

        l = f = strlen_ptr(*x);

        need_separator = !isempty(*x);
        l_separator = strlen_ptr(separator);

        va_list aq;
        va_copy(aq, ap);
        for (const char *t;;) {
                size_t n;

                t = va_arg(aq, const char *);
                if (!t)
                        break;
                if (t == POINTER_MAX)
                        continue;

                n = strlen(t);

                if (need_separator)
                        n += l_separator;

                if (n >= SIZE_MAX - l) {
                        va_end(aq);
                        return NULL;
                }

                l += n;
                need_separator = true;
        }
        va_end(aq);

        need_separator = !isempty(*x);

        nr = realloc(*x, GREEDY_ALLOC_ROUND_UP(l+1));
        if (!nr)
                return NULL;

        *x = nr;
        p = nr + f;

        for (;;) {
                const char *t;

                t = va_arg(ap, const char *);
                if (!t)
                        break;
                if (t == POINTER_MAX)
                        continue;

                if (need_separator && separator)
                        p = stpcpy(p, separator);

                p = stpcpy(p, t);

                need_separator = true;
        }

        assert(p == nr + l);
        *p = 0;

        /* If no buffer to extend was passed in return the start of the buffer */
        if (buffer)
                return TAKE_PTR(buffer);

        /* Otherwise we extended the buffer: return the end */
        return p;
}

char* strextend_with_separator_internal(char **x, const char *separator, ...) {
        va_list ap;
        char *ret;

        va_start(ap, separator);
        ret = strextendv_with_separator(x, separator, ap);
        va_end(ap);

        return ret;
}

int strextendf_with_separator(char **x, const char *separator, const char *format, ...) {
        size_t m, a, l_separator;
        va_list ap;
        int l;

        /* Appends a formatted string to the specified string. Don't use this in inner loops, since then
         * we'll spend a tonload of time in determining the length of the string passed in, over and over
         * again. */

        assert(x);
        assert(format);

        l_separator = isempty(*x) ? 0 : strlen_ptr(separator);

        /* Let's try to use the allocated buffer, if there's room at the end still. Otherwise let's extend by 64 chars. */
        if (*x) {
                m = strlen(*x);
                a = MALLOC_SIZEOF_SAFE(*x);
                assert(a >= m + 1);
        } else
                m = a = 0;

        if (a - m < 17 + l_separator) { /* if there's less than 16 chars space, then enlarge the buffer first */
                char *n;

                if (_unlikely_(l_separator > SIZE_MAX - 64)) /* overflow check #1 */
                        return -ENOMEM;
                if (_unlikely_(m > SIZE_MAX - 64 - l_separator)) /* overflow check #2 */
                        return -ENOMEM;

                n = realloc(*x, m + 64 + l_separator);
                if (!n)
                        return -ENOMEM;

                *x = n;
                a = MALLOC_SIZEOF_SAFE(*x);
        }

        /* Now, let's try to format the string into it */
        memcpy_safe(*x + m, separator, l_separator);
        va_start(ap, format);
        l = vsnprintf(*x + m + l_separator, a - m - l_separator, format, ap);
        va_end(ap);

        assert(l >= 0);

        if ((size_t) l < a - m - l_separator) {
                char *n;

                /* Nice! This worked. We are done. But first, let's return the extra space we don't
                 * need. This should be a cheap operation, since we only lower the allocation size here,
                 * never increase. */
                n = realloc(*x, m + (size_t) l + l_separator + 1);
                if (n)
                        *x = n;
        } else {
                char *n;

                /* Wasn't enough. Then let's allocate exactly what we need. */

                if (_unlikely_((size_t) l > SIZE_MAX - (l_separator + 1))) /* overflow check #1 */
                        goto oom;
                if (_unlikely_(m > SIZE_MAX - ((size_t) l + l_separator + 1))) /* overflow check #2 */
                        goto oom;

                a = m + (size_t) l + l_separator + 1;
                n = realloc(*x, a);
                if (!n)
                        goto oom;
                *x = n;

                va_start(ap, format);
                l = vsnprintf(*x + m + l_separator, a - m - l_separator, format, ap);
                va_end(ap);

                assert((size_t) l < a - m - l_separator);
        }

        return 0;

oom:
        /* truncate the bytes added after memcpy_safe() again */
        (*x)[m] = 0;
        return -ENOMEM;
}

char* strrep(const char *s, unsigned n) {
        char *r, *p;
        size_t l;

        assert(s);

        l = strlen(s);
        p = r = malloc(l * n + 1);
        if (!r)
                return NULL;

        for (unsigned i = 0; i < n; i++)
                p = stpcpy(p, s);

        *p = 0;
        return r;
}

int split_pair(const char *s, const char *sep, char **ret_first, char **ret_second) {
        assert(s);
        assert(!isempty(sep));
        assert(ret_first);
        assert(ret_second);

        const char *x = strstr(s, sep);
        if (!x)
                return -EINVAL;

        _cleanup_free_ char *a = strndup(s, x - s);
        if (!a)
                return -ENOMEM;

        _cleanup_free_ char *b = strdup(x + strlen(sep));
        if (!b)
                return -ENOMEM;

        *ret_first = TAKE_PTR(a);
        *ret_second = TAKE_PTR(b);
        return 0;
}

int free_and_strdup(char **p, const char *s) {
        char *t;

        assert(p);

        /* Replaces a string pointer with a strdup()ed new string,
         * possibly freeing the old one. */

        if (streq_ptr(*p, s))
                return 0;

        if (s) {
                t = strdup(s);
                if (!t)
                        return -ENOMEM;
        } else
                t = NULL;

        free_and_replace(*p, t);

        return 1;
}

int free_and_strdup_warn(char **p, const char *s) {
        int r;

        r = free_and_strdup(p, s);
        if (r < 0)
                return log_oom();
        return r;
}

int free_and_strndup(char **p, const char *s, size_t l) {
        char *t;

        assert(p);
        assert(s || l == 0);

        /* Replaces a string pointer with a strndup()ed new string,
         * freeing the old one. */

        if (!*p && !s)
                return 0;

        if (*p && s && strneq(*p, s, l) && (l > strlen(*p) || (*p)[l] == '\0'))
                return 0;

        if (s) {
                t = strndup(s, l);
                if (!t)
                        return -ENOMEM;
        } else
                t = NULL;

        free_and_replace(*p, t);
        return 1;
}

int strdup_to_full(char **ret, const char *src) {
        if (!src) {
                if (ret)
                        *ret = NULL;

                return 0;
        } else {
                if (ret) {
                        char *t = strdup(src);
                        if (!t)
                                return -ENOMEM;
                        *ret = t;
                }

                return 1;
        }
};

bool string_is_safe(const char *p) {
        if (!p)
                return false;

        /* Checks if the specified string contains no quotes or control characters */

        for (const char *t = p; *t; t++) {
                if (*t > 0 && *t < ' ') /* no control characters */
                        return false;

                if (strchr(QUOTES "\\\x7f", *t))
                        return false;
        }

        return true;
}

bool string_is_safe_ascii(const char *p) {
        return ascii_is_valid(p) && string_is_safe(p);
}

char* str_realloc(char *p) {
        /* Reallocate *p to actual size. Ignore failure, and return the original string on error. */

        if (!p)
                return NULL;

        return realloc(p, strlen(p) + 1) ?: p;
}

char* string_erase(char *x) {
        if (!x)
                return NULL;

        /* A delicious drop of snake-oil! To be called on memory where we stored passphrases or so, after we
         * used them. */
        explicit_bzero_safe(x, strlen(x));
        return x;
}

int string_truncate_lines(const char *s, size_t n_lines, char **ret) {
        const char *p = s, *e = s;
        bool truncation_applied = false;
        char *copy;
        size_t n = 0;

        assert(s);

        /* Truncate after the specified number of lines. Returns > 0 if a truncation was applied or == 0 if
         * there were fewer lines in the string anyway. Trailing newlines on input are ignored, and not
         * generated either. */

        for (;;) {
                size_t k;

                k = strcspn(p, "\n");

                if (p[k] == 0) {
                        if (k == 0) /* final empty line */
                                break;

                        if (n >= n_lines) /* above threshold */
                                break;

                        e = p + k; /* last line to include */
                        break;
                }

                assert(p[k] == '\n');

                if (n >= n_lines)
                        break;

                if (k > 0)
                        e = p + k;

                p += k + 1;
                n++;
        }

        /* e points after the last character we want to keep */
        if (isempty(e))
                copy = strdup(s);
        else {
                if (!in_charset(e, "\n")) /* We only consider things truncated if we remove something that
                                           * isn't a new-line or a series of them */
                        truncation_applied = true;

                copy = strndup(s, e - s);
        }
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return truncation_applied;
}

int string_extract_line(const char *s, size_t i, char **ret) {
        const char *p = s;
        size_t c = 0;

        /* Extract the i'nth line from the specified string. Returns > 0 if there are more lines after that,
         * and == 0 if we are looking at the last line or already beyond the last line. As special
         * optimization, if the first line is requested and the string only consists of one line we return
         * NULL, indicating the input string should be used as is, and avoid a memory allocation for a very
         * common case. */

        for (;;) {
                const char *q;

                q = strchr(p, '\n');
                if (i == c) {
                        /* The line we are looking for! */

                        if (q) {
                                char *m;

                                m = strndup(p, q - p);
                                if (!m)
                                        return -ENOMEM;

                                *ret = m;
                                return !isempty(q + 1); /* More coming? */
                        } else
                                /* Tell the caller to use the input string if equal */
                                return strdup_to(ret, p != s ? p : NULL);
                }

                if (!q)
                        /* No more lines, return empty line */
                        return strdup_to(ret, "");

                p = q + 1;
                c++;
        }
}

int string_contains_word_strv(const char *string, const char *separators, char * const *words, const char **ret_word) {
        /* In the default mode with no separators specified, we split on whitespace and coalesce separators. */
        const ExtractFlags flags = separators ? EXTRACT_DONT_COALESCE_SEPARATORS : 0;
        const char *found = NULL;
        int r;

        for (;;) {
                _cleanup_free_ char *w = NULL;

                r = extract_first_word(&string, &w, separators, flags);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                found = strv_find(words, w);
                if (found)
                        break;
        }

        if (ret_word)
                *ret_word = found;
        return !!found;
}

bool streq_skip_trailing_chars(const char *s1, const char *s2, const char *ok) {
        if (!s1 && !s2)
                return true;
        if (!s1 || !s2)
                return false;

        if (!ok)
                ok = WHITESPACE;

        for (; *s1 && *s2; s1++, s2++)
                if (*s1 != *s2)
                        break;

        return in_charset(s1, ok) && in_charset(s2, ok);
}

char* string_replace_char(char *str, char old_char, char new_char) {
        assert(str);
        assert(old_char != '\0');
        assert(new_char != '\0');
        assert(old_char != new_char);

        for (char *p = strchr(str, old_char); p; p = strchr(p + 1, old_char))
                *p = new_char;

        return str;
}

int make_cstring(const char *s, size_t n, MakeCStringMode mode, char **ret) {
        char *b;

        assert(s || n == 0);
        assert(mode >= 0);
        assert(mode < _MAKE_CSTRING_MODE_MAX);

        /* Converts a sized character buffer into a NUL-terminated NUL string, refusing if there are embedded
         * NUL bytes. Whether to expect a trailing NUL byte can be specified via 'mode' */

        if (n == 0) {
                if (mode == MAKE_CSTRING_REQUIRE_TRAILING_NUL)
                        return -EINVAL;

                if (!ret)
                        return 0;

                b = new0(char, 1);
        } else {
                const char *nul;

                nul = memchr(s, 0, n);
                if (nul) {
                        if (nul < s + n - 1 || /* embedded NUL? */
                            mode == MAKE_CSTRING_REFUSE_TRAILING_NUL)
                                return -EINVAL;

                        n--;
                } else if (mode == MAKE_CSTRING_REQUIRE_TRAILING_NUL)
                        return -EINVAL;

                if (!ret)
                        return 0;

                b = memdup_suffix0(s, n);
        }
        if (!b)
                return -ENOMEM;

        *ret = b;
        return 0;
}

size_t strspn_from_end(const char *str, const char *accept) {
        size_t n = 0;

        if (isempty(str))
                return 0;

        if (isempty(accept))
                return 0;

        for (const char *p = str + strlen(str); p > str && strchr(accept, p[-1]); p--)
                n++;

        return n;
}

char* strdupspn(const char *a, const char *accept) {
        if (isempty(a) || isempty(accept))
                return strdup("");

        return strndup(a, strspn(a, accept));
}

char* strdupcspn(const char *a, const char *reject) {
        if (isempty(a))
                return strdup("");
        if (isempty(reject))
                return strdup(a);

        return strndup(a, strcspn(a, reject));
}

char* find_line_startswith_internal(const char *haystack, const char *needle) {
        assert(haystack);
        assert(needle);

        /* Finds the first line in 'haystack' that starts with the specified string. Returns a pointer to the
         * first character after it */

        char *p = (char*) strstr(haystack, needle);
        if (!p)
                return NULL;

        if (p > haystack)
                while (p[-1] != '\n') {
                        p = strstr(p + 1, needle);
                        if (!p)
                                return NULL;
                }

        return p + strlen(needle);
}

char* find_line_internal(const char *haystack, const char *needle) {
        assert(haystack);
        assert(needle);

        /* Finds the first line in 'haystack' that match the specified string. Returns a pointer to the
         * beginning of the line */

        char *p = (char*) find_line_startswith(haystack, needle);
        if (!p)
                return NULL;

        if (*p == 0 || strchr(NEWLINE, *p))
                return p - strlen(needle);

        return NULL;
}

char* find_line_after_internal(const char *haystack, const char *needle) {
        assert(haystack);
        assert(needle);

        /* Finds the first line in 'haystack' that match the specified string. Returns a pointer to the
         * next line after it */

        char *p = (char*) find_line_startswith(haystack, needle);
        if (!p)
                return NULL;

        if (*p == 0)
                return p;
        if (strchr(NEWLINE, *p))
                return p + 1;

        return NULL;
}

bool version_is_valid(const char *s) {
        if (isempty(s))
                return false;

        if (!filename_part_is_valid(s))
                return false;

        /* This is a superset of the characters used by semver. We additionally allow "," and "_". */
        if (!in_charset(s, ALPHANUMERICAL ".,_-+"))
                return false;

        return true;
}

bool version_is_valid_versionspec(const char *s) {
        if (!filename_part_is_valid(s))
                return false;

        if (!in_charset(s, ALPHANUMERICAL "-.~^"))
                return false;

        return true;
}

ssize_t strlevenshtein(const char *x, const char *y) {
        _cleanup_free_ size_t *t0 = NULL, *t1 = NULL, *t2 = NULL;
        size_t xl, yl;

        /* This is inspired from the Linux kernel's Levenshtein implementation */

        if (streq_ptr(x, y))
                return 0;

        xl = strlen_ptr(x);
        if (xl > SSIZE_MAX)
                return -E2BIG;

        yl = strlen_ptr(y);
        if (yl > SSIZE_MAX)
                return -E2BIG;

        if (isempty(x))
                return yl;
        if (isempty(y))
                return xl;

        t0 = new0(size_t, yl + 1);
        if (!t0)
                return -ENOMEM;
        t1 = new0(size_t, yl + 1);
        if (!t1)
                return -ENOMEM;
        t2 = new0(size_t, yl + 1);
        if (!t2)
                return -ENOMEM;

        for (size_t i = 0; i <= yl; i++)
                t1[i] = i;

        for (size_t i = 0; i < xl; i++) {
                t2[0] = i + 1;

                for (size_t j = 0; j < yl; j++) {
                        /* Substitution */
                        t2[j+1] = t1[j] + (x[i] != y[j]);

                        /* Swap */
                        if (i > 0 && j > 0 && x[i-1] == y[j] && x[i] == y[j-1] && t2[j+1] > t0[j-1] + 1)
                                t2[j+1] = t0[j-1] + 1;

                        /* Deletion */
                        if (t2[j+1] > t1[j+1] + 1)
                                t2[j+1] = t1[j+1] + 1;

                        /* Insertion */
                        if (t2[j+1] > t2[j] + 1)
                                t2[j+1] = t2[j] + 1;
                }

                size_t *dummy = t0;
                t0 = t1;
                t1 = t2;
                t2 = dummy;
        }

        return t1[yl];
}

char* strrstr_internal(const char *haystack, const char *needle) {
        /* Like strstr() but returns the last rather than the first occurrence of "needle" in "haystack". */

        if (!haystack || !needle)
                return NULL;

        /* Special case: for the empty string we return the very last possible occurrence, i.e. *after* the
         * last char, not before. */
        if (*needle == 0)
                return (char*) strchr(haystack, 0);

        for (const char *p = strstr(haystack, needle), *q; p; p = q) {
                q = strstr(p + 1, needle);
                if (!q)
                        return (char *) p;
        }
        return NULL;
}

size_t str_common_prefix(const char *a, const char *b) {
        assert(a);
        assert(b);

        /* Returns the length of the common prefix of the two specified strings, or SIZE_MAX in case the
         * strings are fully identical. */

        for (size_t n = 0;; n++) {
                char c = a[n];
                if (c != b[n])
                        return n;
                if (c == 0)
                        return SIZE_MAX;
        }
}
