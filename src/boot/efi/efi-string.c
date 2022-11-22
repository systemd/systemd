/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <stdint.h>

#include "efi-string.h"

#ifdef SD_BOOT
#  include "util.h"
#else
#  include <stdlib.h>
#  include "alloc-util.h"
#  define xnew(t, n) ASSERT_SE_PTR(new(t, n))
#  define xmalloc(n) ASSERT_SE_PTR(malloc(n))
#endif

/* String functions for both char and char16_t that should behave the same way as their respective
 * counterpart in userspace. Where it makes sense, these accept NULL and do something sensible whereas
 * userspace does not allow for this (strlen8(NULL) returns 0 like strlen_ptr(NULL) for example). To make it
 * easier to tell in code which kind of string they work on, we use 8/16 suffixes. This also makes is easier
 * to unit test them. */

#define DEFINE_STRNLEN(type, name)             \
        size_t name(const type *s, size_t n) { \
                if (!s)                        \
                        return 0;              \
                                               \
                size_t len = 0;                \
                while (len < n && *s) {        \
                        s++;                   \
                        len++;                 \
                }                              \
                                               \
                return len;                    \
        }

DEFINE_STRNLEN(char, strnlen8);
DEFINE_STRNLEN(char16_t, strnlen16);

#define TOLOWER(c)                                                \
        ({                                                        \
                typeof(c) _c = (c);                               \
                (_c >= 'A' && _c <= 'Z') ? _c + ('a' - 'A') : _c; \
        })

#define DEFINE_STRTOLOWER(type, name)     \
        void name(type *s) {              \
                if (!s)                   \
                        return;           \
                for (; *s; s++)           \
                        *s = TOLOWER(*s); \
        }

DEFINE_STRTOLOWER(char, strtolower8);
DEFINE_STRTOLOWER(char16_t, strtolower16);

#define DEFINE_STRNCASECMP(type, name, tolower)              \
        int name(const type *s1, const type *s2, size_t n) { \
                if (!s1 || !s2)                              \
                        return CMP(s1, s2);                  \
                                                             \
                while (n > 0) {                              \
                        type c1 = *s1, c2 = *s2;             \
                        if (tolower) {                       \
                                c1 = TOLOWER(c1);            \
                                c2 = TOLOWER(c2);            \
                        }                                    \
                        if (!c1 || c1 != c2)                 \
                                return CMP(c1, c2);          \
                                                             \
                        s1++;                                \
                        s2++;                                \
                        n--;                                 \
                }                                            \
                                                             \
                return 0;                                    \
        }

DEFINE_STRNCASECMP(char, strncmp8, false);
DEFINE_STRNCASECMP(char16_t, strncmp16, false);
DEFINE_STRNCASECMP(char, strncasecmp8, true);
DEFINE_STRNCASECMP(char16_t, strncasecmp16, true);

#define DEFINE_STRCPY(type, name)                                     \
        type *name(type * restrict dest, const type * restrict src) { \
                type *ret = ASSERT_PTR(dest);                         \
                                                                      \
                if (!src) {                                           \
                        *dest = '\0';                                 \
                        return ret;                                   \
                }                                                     \
                                                                      \
                while (*src) {                                        \
                        *dest = *src;                                 \
                        dest++;                                       \
                        src++;                                        \
                }                                                     \
                                                                      \
                *dest = '\0';                                         \
                return ret;                                           \
        }

DEFINE_STRCPY(char, strcpy8);
DEFINE_STRCPY(char16_t, strcpy16);

#define DEFINE_STRCHR(type, name)                  \
        type *name(const type *s, type c) {        \
                if (!s)                            \
                        return NULL;               \
                                                   \
                while (*s) {                       \
                        if (*s == c)               \
                                return (type *) s; \
                        s++;                       \
                }                                  \
                                                   \
                return NULL;                       \
        }

DEFINE_STRCHR(char, strchr8);
DEFINE_STRCHR(char16_t, strchr16);

#define DEFINE_STRNDUP(type, name, len_func)              \
        type *name(const type *s, size_t n) {             \
                if (!s)                                   \
                        return NULL;                      \
                                                          \
                size_t len = len_func(s, n);              \
                size_t size = len * sizeof(type);         \
                                                          \
                type *dup = xmalloc(size + sizeof(type)); \
                if (size > 0)                             \
                        memcpy(dup, s, size);             \
                dup[len] = '\0';                          \
                                                          \
                return dup;                               \
        }

DEFINE_STRNDUP(char, xstrndup8, strnlen8);
DEFINE_STRNDUP(char16_t, xstrndup16, strnlen16);

static unsigned utf8_to_unichar(const char *utf8, size_t n, char32_t *c) {
        char32_t unichar;
        unsigned len;

        assert(utf8);
        assert(c);

        if (!(utf8[0] & 0x80)) {
                *c = utf8[0];
                return 1;
        } else if ((utf8[0] & 0xe0) == 0xc0) {
                len = 2;
                unichar = utf8[0] & 0x1f;
        } else if ((utf8[0] & 0xf0) == 0xe0) {
                len = 3;
                unichar = utf8[0] & 0x0f;
        } else if ((utf8[0] & 0xf8) == 0xf0) {
                len = 4;
                unichar = utf8[0] & 0x07;
        } else if ((utf8[0] & 0xfc) == 0xf8) {
                len = 5;
                unichar = utf8[0] & 0x03;
        } else if ((utf8[0] & 0xfe) == 0xfc) {
                len = 6;
                unichar = utf8[0] & 0x01;
        } else {
                *c = UINT32_MAX;
                return 1;
        }

        if (len > n) {
                *c = UINT32_MAX;
                return len;
        }

        for (unsigned i = 1; i < len; i++) {
                if ((utf8[i] & 0xc0) != 0x80) {
                        *c = UINT32_MAX;
                        return len;
                }
                unichar <<= 6;
                unichar |= utf8[i] & 0x3f;
        }

        *c = unichar;
        return len;
}

/* Convert UTF-8 to UCS-2, skipping any invalid or short byte sequences. */
char16_t *xstrn8_to_16(const char *str8, size_t n) {
        if (!str8 || n == 0)
                return NULL;

        size_t i = 0;
        char16_t *str16 = xnew(char16_t, n + 1);

        while (n > 0 && *str8 != '\0') {
                char32_t unichar;

                size_t utf8len = utf8_to_unichar(str8, n, &unichar);
                str8 += utf8len;
                n = LESS_BY(n, utf8len);

                switch (unichar) {
                case 0 ... 0xd7ffU:
                case 0xe000U ... 0xffffU:
                        str16[i++] = unichar;
                        break;
                }
        }

        str16[i] = '\0';
        return str16;
}

static bool efi_fnmatch_prefix(const char16_t *p, const char16_t *h, const char16_t **ret_p, const char16_t **ret_h) {
        assert(p);
        assert(h);
        assert(ret_p);
        assert(ret_h);

        for (;; p++, h++)
                switch (*p) {
                case '\0':
                        /* End of pattern. Check that haystack is now empty. */
                        return *h == '\0';

                case '\\':
                        p++;
                        if (*p == '\0' || *p != *h)
                                /* Trailing escape or no match. */
                                return false;
                        break;

                case '?':
                        if (*h == '\0')
                                /* Early end of haystack. */
                                return false;
                        break;

                case '*':
                        /* Point ret_p at the remainder of the pattern. */
                        while (*p == '*')
                                p++;
                        *ret_p = p;
                        *ret_h = h;
                        return true;

                case '[':
                        if (*h == '\0')
                                /* Early end of haystack. */
                                return false;

                        bool first = true, can_range = true, match = false;
                        for (;; first = false) {
                                p++;
                                if (*p == '\0')
                                        return false;

                                if (*p == '\\') {
                                        p++;
                                        if (*p == '\0')
                                                return false;
                                        if (*p == *h)
                                                match = true;
                                        can_range = true;
                                        continue;
                                }

                                /* End of set unless it's the first char. */
                                if (*p == ']' && !first)
                                        break;

                                /* Range pattern if '-' is not first or last in set. */
                                if (*p == '-' && can_range && !first && *(p + 1) != ']') {
                                        char16_t low = *(p - 1);
                                        p++;
                                        if (*p == '\\')
                                                p++;
                                        if (*p == '\0')
                                                return false;

                                        if (low <= *h && *h <= *p)
                                                match = true;

                                        /* Ranges cannot be chained: [a-c-f] == [-abcf] */
                                        can_range = false;
                                        continue;
                                }

                                if (*p == *h)
                                        match = true;
                                can_range = true;
                        }

                        if (!match)
                                return false;
                        break;

                default:
                        if (*p != *h)
                                /* Single char mismatch. */
                                return false;
                }
}

/* Patterns are fnmatch-compatible (with reduced feature support). */
bool efi_fnmatch(const char16_t *pattern, const char16_t *haystack) {
        /* Patterns can be considered as simple patterns (without '*') concatenated by '*'. By doing so we
         * simply have to make sure the very first simple pattern matches the start of haystack. Then we just
         * look for the remaining simple patterns *somewhere* within the haystack (in order) as any extra
         * characters in between would be matches by the '*'. We then only have to ensure that the very last
         * simple pattern matches at the actual end of the haystack.
         *
         * This means we do not need to use backtracking which could have catastrophic runtimes with the
         * right input data. */

        for (bool first = true;;) {
                const char16_t *pattern_tail = NULL, *haystack_tail = NULL;
                bool match = efi_fnmatch_prefix(pattern, haystack, &pattern_tail, &haystack_tail);
                if (first) {
                        if (!match)
                                /* Initial simple pattern must match. */
                                return false;
                        if (!pattern_tail)
                                /* No '*' was in pattern, we can return early. */
                                return true;
                        first = false;
                }

                if (pattern_tail) {
                        assert(match);
                        pattern = pattern_tail;
                        haystack = haystack_tail;
                } else {
                        /* If we have a match this must be at the end of the haystack. Note that
                         * efi_fnmatch_prefix compares the NUL-bytes at the end, so we cannot match the end
                         * of pattern in the middle of haystack). */
                        if (match || *haystack == '\0')
                                return match;

                        /* Match one character using '*'. */
                        haystack++;
                }
        }
}

#define DEFINE_PARSE_NUMBER(type, name)                                    \
        bool name(const type *s, uint64_t *ret_u, const type **ret_tail) { \
                assert(ret_u);                                             \
                                                                           \
                if (!s)                                                    \
                        return false;                                      \
                                                                           \
                /* Need at least one digit. */                             \
                if (*s < '0' || *s > '9')                                  \
                        return false;                                      \
                                                                           \
                uint64_t u = 0;                                            \
                while (*s >= '0' && *s <= '9') {                           \
                        if (__builtin_mul_overflow(u, 10, &u))             \
                                return false;                              \
                        if (__builtin_add_overflow(u, *s - '0', &u))       \
                                return false;                              \
                        s++;                                               \
                }                                                          \
                                                                           \
                if (!ret_tail && *s != '\0')                               \
                        return false;                                      \
                                                                           \
                *ret_u = u;                                                \
                if (ret_tail)                                              \
                        *ret_tail = s;                                     \
                return true;                                               \
        }

DEFINE_PARSE_NUMBER(char, parse_number8);
DEFINE_PARSE_NUMBER(char16_t, parse_number16);

#ifdef SD_BOOT
/* To provide the actual implementation for these we need to remove the redirection to the builtins. */
#  undef memcmp
#  undef memcpy
#  undef memset
#else
/* And for userspace unit testing we need to give them an efi_ prefix. */
#  define memcmp efi_memcmp
#  define memcpy efi_memcpy
#  define memset efi_memset
#endif

_used_ int memcmp(const void *p1, const void *p2, size_t n) {
        const uint8_t *up1 = p1, *up2 = p2;
        int r;

        if (!p1 || !p2)
                return CMP(p1, p2);

        while (n > 0) {
                r = CMP(*up1, *up2);
                if (r != 0)
                        return r;

                up1++;
                up2++;
                n--;
        }

        return 0;
}

_used_ _weak_ void *memcpy(void * restrict dest, const void * restrict src, size_t n) {
        if (!dest || !src || n == 0)
                return dest;

#ifdef SD_BOOT
        /* The firmware-provided memcpy is likely optimized, so use that. The function is guaranteed to be
         * available by the UEFI spec. We still make it depend on the boot services pointer being set just in
         * case the compiler emits a call before it is available. */
        if (_likely_(BS)) {
                BS->CopyMem(dest, (void *) src, n);
                return dest;
        }
#endif

        uint8_t *d = dest;
        const uint8_t *s = src;

        while (n > 0) {
                *d = *s;
                d++;
                s++;
                n--;
        }

        return dest;
}

_used_ _weak_ void *memset(void *p, int c, size_t n) {
        if (!p || n == 0)
                return p;

#ifdef SD_BOOT
        /* See comment in efi_memcpy. Note that the signature has c and n swapped! */
        if (_likely_(BS)) {
                BS->SetMem(p, n, c);
                return p;
        }
#endif

        uint8_t *q = p;
        while (n > 0) {
                *q = c;
                q++;
                n--;
        }

        return p;
}
