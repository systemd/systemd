/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-string.h"
#include "macro-fundamental.h"

/* String functions for both char and char16_t that should behave the same way as their respective
 * counterpart in userspace. Where it makes sense, these accept NULL and do something sensible whereas
 * userspace does not allow for this (strlen8(NULL) returns 0 like strlen_ptr(NULL) for example). To make it
 * easier to tell in code which kind of string they work on, we use 8/16 suffixes. This also makes is easier
 * to unit test them.
 *
 * To avoid repetition and because char/char16_t string functions are fundamentally the same, we implement
 * them with macros. Note that these macros are to be only used within their respective function they
 * implement and therefore do not care about parameter hygiene and will also use the function parameters
 * without declaring them in the macro params. */

#define STRNLEN_U(until_nul, n)                         \
        ({                                              \
                if (!s)                                 \
                        return 0;                       \
                                                        \
                size_t len = 0, _n = n;                 \
                while ((until_nul || len < _n) && *s) { \
                        s++;                            \
                        len++;                          \
                }                                       \
                                                        \
                return len;                             \
        })

size_t strnlen8(const char *s, size_t n) {
        STRNLEN_U(false, n);
}

size_t strnlen16(const char16_t *s, size_t n) {
        STRNLEN_U(false, n);
}

size_t strlen8(const char *s) {
        STRNLEN_U(true, 0);
}

size_t strlen16(const char16_t *s) {
        STRNLEN_U(true, 0);
}

#define TOLOWER(c) ((c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c)

char tolower8(char c) {
        return TOLOWER(c);
}

char16_t tolower16(char16_t c) {
        return TOLOWER(c);
}

#define STRNCASECMP_U(tolower, until_nul, n)      \
        ({                                        \
                if (!s1 || !s2)                   \
                        return CMP(s1, s2);       \
                                                  \
                size_t _n = n;                    \
                while (until_nul || _n > 0) {     \
                        int c1 = *s1;             \
                        int c2 = *s2;             \
                        if (tolower) {            \
                                c1 = TOLOWER(c1); \
                                c2 = TOLOWER(c2); \
                        }                         \
                        if (!c1 || c1 != c2)      \
                                return c1 - c2;   \
                                                  \
                        s1++;                     \
                        s2++;                     \
                        _n--;                     \
                }                                 \
                                                  \
                return 0;                         \
        })

int strncmp8(const char *s1, const char *s2, size_t n) {
        STRNCASECMP_U(false, false, n);
}

int strncmp16(const char16_t *s1, const char16_t *s2, size_t n) {
        STRNCASECMP_U(false, false, n);
}

int strcmp8(const char *s1, const char *s2) {
        STRNCASECMP_U(false, true, 0);
}

int strcmp16(const char16_t *s1, const char16_t *s2) {
        STRNCASECMP_U(false, true, 0);
}

int strncasecmp8(const char *s1, const char *s2, size_t n) {
        STRNCASECMP_U(true, false, n);
}

int strncasecmp16(const char16_t *s1, const char16_t *s2, size_t n) {
        STRNCASECMP_U(true, false, n);
}

int strcasecmp8(const char *s1, const char *s2) {
        STRNCASECMP_U(true, true, 0);
}

int strcasecmp16(const char16_t *s1, const char16_t *s2) {
        STRNCASECMP_U(true, true, 0);
}
