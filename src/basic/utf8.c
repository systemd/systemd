/* SPDX-License-Identifier: LGPL-2.0-or-later */

/* Parts of this file are based on the GLIB utf8 validation functions. The original copyright follows.
 *
 * gutf8.c - Operations on UTF-8 strings.
 * Copyright (C) 1999 Tom Tromey
 * Copyright (C) 2000 Red Hat, Inc.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "gunicode.h"
#include "hexdecoct.h"
#include "macro.h"
#include "string-util.h"
#include "utf8.h"

bool unichar_is_valid(char32_t ch) {

        if (ch >= 0x110000) /* End of unicode space */
                return false;
        if ((ch & 0xFFFFF800) == 0xD800) /* Reserved area for UTF-16 */
                return false;
        if ((ch >= 0xFDD0) && (ch <= 0xFDEF)) /* Reserved */
                return false;
        if ((ch & 0xFFFE) == 0xFFFE) /* BOM (Byte Order Mark) */
                return false;

        return true;
}

static bool unichar_is_control(char32_t ch) {

        /*
          0 to ' '-1 is the C0 range.
          DEL=0x7F, and DEL+1 to 0x9F is C1 range.
          '\t' is in C0 range, but more or less harmless and commonly used.
        */

        return (ch < ' ' && !IN_SET(ch, '\t', '\n')) ||
                (0x7F <= ch && ch <= 0x9F);
}

/* count of characters used to encode one unicode char */
static size_t utf8_encoded_expected_len(uint8_t c) {
        if (c < 0x80)
                return 1;
        if ((c & 0xe0) == 0xc0)
                return 2;
        if ((c & 0xf0) == 0xe0)
                return 3;
        if ((c & 0xf8) == 0xf0)
                return 4;
        if ((c & 0xfc) == 0xf8)
                return 5;
        if ((c & 0xfe) == 0xfc)
                return 6;

        return 0;
}

/* decode one unicode char */
int utf8_encoded_to_unichar(const char *str, char32_t *ret_unichar) {
        char32_t unichar;
        size_t len;

        assert(str);

        len = utf8_encoded_expected_len(str[0]);

        switch (len) {
        case 1:
                *ret_unichar = (char32_t)str[0];
                return 1;
        case 2:
                unichar = str[0] & 0x1f;
                break;
        case 3:
                unichar = (char32_t)str[0] & 0x0f;
                break;
        case 4:
                unichar = (char32_t)str[0] & 0x07;
                break;
        case 5:
                unichar = (char32_t)str[0] & 0x03;
                break;
        case 6:
                unichar = (char32_t)str[0] & 0x01;
                break;
        default:
                return -EINVAL;
        }

        for (size_t i = 1; i < len; i++) {
                if (((char32_t)str[i] & 0xc0) != 0x80)
                        return -EINVAL;

                unichar <<= 6;
                unichar |= (char32_t)str[i] & 0x3f;
        }

        *ret_unichar = unichar;
        return len;
}

bool utf8_is_printable_newline(const char* str, size_t length, bool allow_newline) {
        assert(str);

        for (const char *p = str; length > 0;) {
                int encoded_len;
                char32_t val;

                encoded_len = utf8_encoded_valid_unichar(p, length);
                if (encoded_len < 0)
                        return false;
                assert(encoded_len > 0 && (size_t) encoded_len <= length);

                if (utf8_encoded_to_unichar(p, &val) < 0 ||
                    unichar_is_control(val) ||
                    (!allow_newline && val == '\n'))
                        return false;

                length -= encoded_len;
                p += encoded_len;
        }

        return true;
}

char* utf8_is_valid_n(const char *str, size_t len_bytes) {
        /* Check if the string is composed of valid utf8 characters. If length len_bytes is given, stop after
         * len_bytes. Otherwise, stop at NUL. */

        assert(str);

        for (size_t i = 0; len_bytes != SIZE_MAX ? i < len_bytes : str[i] != '\0'; ) {
                int len;

                if (_unlikely_(str[i] == '\0'))
                        return NULL; /* embedded NUL */

                len = utf8_encoded_valid_unichar(str + i,
                                                 len_bytes != SIZE_MAX ? len_bytes - i : SIZE_MAX);
                if (_unlikely_(len < 0))
                        return NULL; /* invalid character */

                i += len;
        }

        return (char*) str;
}

char* utf8_escape_invalid(const char *str) {
        char *p, *s;

        assert(str);

        p = s = malloc(strlen(str) * 4 + 1);
        if (!p)
                return NULL;

        while (*str) {
                int len;

                len = utf8_encoded_valid_unichar(str, SIZE_MAX);
                if (len > 0) {
                        s = mempcpy(s, str, len);
                        str += len;
                } else {
                        s = stpcpy(s, UTF8_REPLACEMENT_CHARACTER);
                        str += 1;
                }
        }

        *s = '\0';
        return str_realloc(p);
}

int utf8_char_console_width(const char *str) {
        char32_t c;
        int r;

        r = utf8_encoded_to_unichar(str, &c);
        if (r < 0)
                return r;

        if (c == '\t')
                return 8; /* Assume a tab width of 8 */

        /* TODO: we should detect combining characters */

        return unichar_iswide(c) ? 2 : 1;
}

char* utf8_escape_non_printable_full(const char *str, size_t console_width, bool force_ellipsis) {
        char *p, *s, *prev_s;
        size_t n = 0; /* estimated print width */

        assert(str);

        if (console_width == 0)
                return strdup("");

        p = s = prev_s = malloc(strlen(str) * 4 + 1);
        if (!p)
                return NULL;

        for (;;) {
                int len;
                char *saved_s = s;

                if (!*str) { /* done! */
                        if (force_ellipsis)
                                goto truncation;
                        else
                                goto finish;
                }

                len = utf8_encoded_valid_unichar(str, SIZE_MAX);
                if (len > 0) {
                        if (utf8_is_printable(str, len)) {
                                int w;

                                w = utf8_char_console_width(str);
                                assert(w >= 0);
                                if (n + w > console_width)
                                        goto truncation;

                                s = mempcpy(s, str, len);
                                str += len;
                                n += w;

                        } else {
                                for (; len > 0; len--) {
                                        if (n + 4 > console_width)
                                                goto truncation;

                                        *(s++) = '\\';
                                        *(s++) = 'x';
                                        *(s++) = hexchar((int) *str >> 4);
                                        *(s++) = hexchar((int) *str);

                                        str += 1;
                                        n += 4;
                                }
                        }
                } else {
                        if (n + 1 > console_width)
                                goto truncation;

                        s = mempcpy(s, UTF8_REPLACEMENT_CHARACTER, strlen(UTF8_REPLACEMENT_CHARACTER));
                        str += 1;
                        n += 1;
                }

                prev_s = saved_s;
        }

 truncation:
        /* Try to go back one if we don't have enough space for the ellipsis */
        if (n + 1 > console_width)
                s = prev_s;

        s = mempcpy(s, "…", strlen("…"));

 finish:
        *s = '\0';
        return str_realloc(p);
}

char* ascii_is_valid_n(const char *str, size_t len) {
        /* Check whether the string consists of valid ASCII bytes, i.e values between 1 and 127, inclusive.
         * Stops at len, or NUL byte if len is SIZE_MAX. */

        assert(str);

        for (size_t i = 0; len != SIZE_MAX ? i < len : str[i] != '\0'; i++)
                if ((unsigned char) str[i] >= 128 || str[i] == '\0')
                        return NULL;

        return (char*) str;
}

int utf8_to_ascii(const char *str, char replacement_char, char **ret) {
        /* Convert to a string that has only ASCII chars, replacing anything that is not ASCII
         * by replacement_char. */

        _cleanup_free_ char *ans = new(char, strlen(str) + 1);
        if (!ans)
                return -ENOMEM;

        char *q = ans;

        for (const char *p = str; *p; q++) {
                int l;

                l = utf8_encoded_valid_unichar(p, SIZE_MAX);
                if (l < 0)  /* Non-UTF-8, let's not even try to propagate the garbage */
                        return l;

                if (l == 1)
                        *q = *p;
                else
                        /* non-ASCII, we need to replace it */
                        *q = replacement_char;

                p += l;
        }
        *q = '\0';

        *ret = TAKE_PTR(ans);
        return 0;
}

/**
 * utf8_encode_unichar() - Encode single UCS-4 character as UTF-8
 * @out_utf8: output buffer of at least 4 bytes or NULL
 * @g: UCS-4 character to encode
 *
 * This encodes a single UCS-4 character as UTF-8 and writes it into @out_utf8.
 * The length of the character is returned. It is not zero-terminated! If the
 * output buffer is NULL, only the length is returned.
 *
 * Returns: The length in bytes that the UTF-8 representation does or would
 *          occupy.
 */
size_t utf8_encode_unichar(char *out_utf8, char32_t g) {

        if (g < (1 << 7)) {
                if (out_utf8)
                        out_utf8[0] = g & 0x7f;
                return 1;
        } else if (g < (1 << 11)) {
                if (out_utf8) {
                        out_utf8[0] = 0xc0 | ((g >> 6) & 0x1f);
                        out_utf8[1] = 0x80 | (g & 0x3f);
                }
                return 2;
        } else if (g < (1 << 16)) {
                if (out_utf8) {
                        out_utf8[0] = 0xe0 | ((g >> 12) & 0x0f);
                        out_utf8[1] = 0x80 | ((g >> 6) & 0x3f);
                        out_utf8[2] = 0x80 | (g & 0x3f);
                }
                return 3;
        } else if (g < (1 << 21)) {
                if (out_utf8) {
                        out_utf8[0] = 0xf0 | ((g >> 18) & 0x07);
                        out_utf8[1] = 0x80 | ((g >> 12) & 0x3f);
                        out_utf8[2] = 0x80 | ((g >> 6) & 0x3f);
                        out_utf8[3] = 0x80 | (g & 0x3f);
                }
                return 4;
        }

        return 0;
}

char* utf16_to_utf8(const char16_t *s, size_t length /* bytes! */) {
        const uint8_t *f;
        char *r, *t;

        if (length == 0)
                return new0(char, 1);

        assert(s);

        if (length == SIZE_MAX) {
                length = char16_strlen(s);

                if (length > SIZE_MAX/2)
                        return NULL; /* overflow */

                length *= 2;
        }

        /* Input length is in bytes, i.e. the shortest possible character takes 2 bytes. Each unicode character may
         * take up to 4 bytes in UTF-8. Let's also account for a trailing NUL byte. */
        if (length > (SIZE_MAX - 1) / 2)
                return NULL; /* overflow */

        r = new(char, length * 2 + 1);
        if (!r)
                return NULL;

        f = (const uint8_t*) s;
        t = r;

        while (f + 1 < (const uint8_t*) s + length) {
                char16_t w1, w2;

                /* see RFC 2781 section 2.2 */

                w1 = f[1] << 8 | f[0];
                f += 2;

                if (!utf16_is_surrogate(w1)) {
                        t += utf8_encode_unichar(t, w1);
                        continue;
                }

                if (utf16_is_trailing_surrogate(w1))
                        continue; /* spurious trailing surrogate, ignore */

                if (f + 1 >= (const uint8_t*) s + length)
                        break;

                w2 = f[1] << 8 | f[0];
                f += 2;

                if (!utf16_is_trailing_surrogate(w2)) {
                        f -= 2;
                        continue; /* surrogate missing its trailing surrogate, ignore */
                }

                t += utf8_encode_unichar(t, utf16_surrogate_pair_to_unichar(w1, w2));
        }

        *t = 0;
        return r;
}

size_t utf16_encode_unichar(char16_t *out, char32_t c) {

        /* Note that this encodes as little-endian. */

        switch (c) {

        case 0 ... 0xd7ffU:
        case 0xe000U ... 0xffffU:
                out[0] = htole16(c);
                return 1;

        case 0x10000U ... 0x10ffffU:
                c -= 0x10000U;
                out[0] = htole16((c >> 10) + 0xd800U);
                out[1] = htole16((c & 0x3ffU) + 0xdc00U);
                return 2;

        default: /* A surrogate (invalid) */
                return 0;
        }
}

char16_t *utf8_to_utf16(const char *s, size_t length) {
        char16_t *n, *p;
        int r;

        if (length == 0)
                return new0(char16_t, 1);

        assert(s);

        if (length == SIZE_MAX)
                length = strlen(s);

        if (length > SIZE_MAX - 1)
                return NULL; /* overflow */

        n = new(char16_t, length + 1);
        if (!n)
                return NULL;

        p = n;

        for (size_t i = 0; i < length;) {
                char32_t unichar;
                size_t e;

                e = utf8_encoded_expected_len(s[i]);
                if (e <= 1) /* Invalid and single byte characters are copied as they are */
                        goto copy;

                if (i + e > length) /* sequence longer than input buffer, then copy as-is */
                        goto copy;

                r = utf8_encoded_to_unichar(s + i, &unichar);
                if (r < 0) /* sequence invalid, then copy as-is */
                        goto copy;

                p += utf16_encode_unichar(p, unichar);
                i += e;
                continue;

        copy:
                *(p++) = htole16(s[i++]);
        }

        *p = 0;
        return n;
}

size_t char16_strlen(const char16_t *s) {
        size_t n = 0;

        assert(s);

        while (*s != 0)
                n++, s++;

        return n;
}

size_t char16_strsize(const char16_t *s) {
        return s ? (char16_strlen(s) + 1) * sizeof(*s) : 0;
}

/* expected size used to encode one unicode char */
static int utf8_unichar_to_encoded_len(char32_t unichar) {

        if (unichar < 0x80)
                return 1;
        if (unichar < 0x800)
                return 2;
        if (unichar < 0x10000)
                return 3;
        if (unichar < 0x200000)
                return 4;
        if (unichar < 0x4000000)
                return 5;

        return 6;
}

/* validate one encoded unicode char and return its length */
int utf8_encoded_valid_unichar(const char *str, size_t length /* bytes */) {
        char32_t unichar;
        size_t len;
        int r;

        assert(str);
        assert(length > 0);

        /* We read until NUL, at most length bytes. SIZE_MAX may be used to disable the length check. */

        len = utf8_encoded_expected_len(str[0]);
        if (len == 0)
                return -EINVAL;

        /* Do we have a truncated multi-byte character? */
        if (len > length)
                return -EINVAL;

        /* ascii is valid */
        if (len == 1)
                return 1;

        /* check if expected encoded chars are available */
        for (size_t i = 0; i < len; i++)
                if ((str[i] & 0x80) != 0x80)
                        return -EINVAL;

        r = utf8_encoded_to_unichar(str, &unichar);
        if (r < 0)
                return r;

        /* check if encoded length matches encoded value */
        if (utf8_unichar_to_encoded_len(unichar) != (int) len)
                return -EINVAL;

        /* check if value has valid range */
        if (!unichar_is_valid(unichar))
                return -EINVAL;

        return (int) len;
}

size_t utf8_n_codepoints(const char *str) {
        size_t n = 0;

        /* Returns the number of UTF-8 codepoints in this string, or SIZE_MAX if the string is not valid UTF-8. */

        while (*str != 0) {
                int k;

                k = utf8_encoded_valid_unichar(str, SIZE_MAX);
                if (k < 0)
                        return SIZE_MAX;

                str += k;
                n++;
        }

        return n;
}

size_t utf8_console_width(const char *str) {

        if (isempty(str))
                return 0;

        /* Returns the approximate width a string will take on screen when printed on a character cell
         * terminal/console. */

        size_t n = 0;
        while (*str) {
                int w;

                w = utf8_char_console_width(str);
                if (w < 0)
                        return SIZE_MAX;

                n += w;
                str = utf8_next_char(str);
        }

        return n;
}
