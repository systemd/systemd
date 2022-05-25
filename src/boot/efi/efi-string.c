/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-string.h"

#ifdef SD_BOOT
#  include "util.h"
#  define xmalloc(n) xallocate_pool(n)
#else
#  include <stdlib.h>
#  include "macro.h"
#  define xmalloc(n) ASSERT_SE_PTR(malloc(n))
#endif

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

#define STRNLEN_U                       \
        ({                              \
                if (!s)                 \
                        return 0;       \
                                        \
                size_t len = 0;         \
                while (len < n && *s) { \
                        s++;            \
                        len++;          \
                }                       \
                                        \
                return len;             \
        })

size_t strnlen8(const char *s, size_t n) {
        STRNLEN_U;
}

size_t strnlen16(const char16_t *s, size_t n) {
        STRNLEN_U;
}

size_t strlen8(const char *s) {
        return strnlen8(s, SIZE_MAX);
}

size_t strlen16(const char16_t *s) {
        return strnlen16(s, SIZE_MAX);
}

#define TOLOWER(c) ((c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c)

char tolower8(char c) {
        return TOLOWER(c);
}

char16_t tolower16(char16_t c) {
        return TOLOWER(c);
}

#define STRNCASECMP_U(cmp_type, case)                \
        ({                                           \
                if (!s1 || !s2)                      \
                        return CMP(s1, s2);          \
                                                     \
                while (n > 0) {                      \
                        cmp_type c1 = *s1, c2 = *s2; \
                        if (case) {                  \
                                c1 = TOLOWER(c1);    \
                                c2 = TOLOWER(c2);    \
                        }                            \
                        if (!c1 || c1 != c2)         \
                                return c1 - c2;      \
                                                     \
                        s1++;                        \
                        s2++;                        \
                        n--;                         \
                }                                    \
                                                     \
                return 0;                            \
        })

int strncmp8(const char *s1, const char *s2, size_t n) {
        STRNCASECMP_U(unsigned char, false);
}

int strncmp16(const char16_t *s1, const char16_t *s2, size_t n) {
        STRNCASECMP_U(char16_t, false);
}

int strcmp8(const char *s1, const char *s2) {
        return strncmp8(s1, s2, SIZE_MAX);
}

int strcmp16(const char16_t *s1, const char16_t *s2) {
        return strncmp16(s1, s2, SIZE_MAX);
}

int strncasecmp8(const char *s1, const char *s2, size_t n) {
        STRNCASECMP_U(unsigned char, true);
}

int strncasecmp16(const char16_t *s1, const char16_t *s2, size_t n) {
        STRNCASECMP_U(char16_t, true);
}

int strcasecmp8(const char *s1, const char *s2) {
        return strncasecmp8(s1, s2, SIZE_MAX);
}

int strcasecmp16(const char16_t *s1, const char16_t *s2) {
        return strncasecmp16(s1, s2, SIZE_MAX);
}

#define STRCPY_U                           \
        ({                                 \
                assert(dest);              \
                typeof(*dest) *ret = dest; \
                                           \
                if (!src) {                \
                        *dest = '\0';      \
                        return ret;        \
                }                          \
                                           \
                while (*src) {             \
                        *dest = *src;      \
                        dest++;            \
                        src++;             \
                }                          \
                                           \
                *dest = '\0';              \
                return ret;                \
        })

char *strcpy8(char *restrict dest, const char *restrict src) {
        STRCPY_U;
}

char16_t *strcpy16(char16_t *restrict dest, const char16_t *restrict src) {
        STRCPY_U;
}

#define STRCHR_U(ret_type)                           \
        ({                                           \
                if (!s)                              \
                        return NULL;                 \
                                                     \
                while (*s) {                         \
                        if (*s == c)                 \
                                return (ret_type) s; \
                        s++;                         \
                }                                    \
                                                     \
                return NULL;                         \
        })

char *strchr8(const char *s, char c) {
        STRCHR_U(char *);
}

char16_t *strchr16(const char16_t *s, char16_t c) {
        STRCHR_U(char16_t *);
}

static void *xstrdup(const void *s, size_t size) {
        if (size == 0)
                return NULL;

        void *dup = xmalloc(size);
        return memcpy(dup, s, size);
}

char *xstrdup8(const char *s) {
        return xstrdup(s, strsize8(s));
}

char16_t *xstrdup16(const char16_t *s) {
        return xstrdup(s, strsize16(s));
}

int efi_memcmp(const void *p1, const void *p2, size_t n) {
        if (!p1 || !p2)
                return CMP(p1, p2);

        const uint8_t *up1 = p1, *up2 = p2;
        while (n > 0) {
                if (*up1 != *up2)
                        return *up1 - *up2;

                up1++;
                up2++;
                n--;
        }

        return 0;
}

void *efi_memcpy(void *restrict dest, const void *restrict src, size_t n) {
        if (!dest || !src || n == 0)
                return dest;

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

void *efi_memset(void *p, int c, size_t n) {
        if (!p || n == 0)
                return p;

        uint8_t *q = p;
        while (n > 0) {
                *q = c;
                q++;
                n--;
        }

        return p;
}

#ifdef SD_BOOT
#  undef memcmp
#  undef memcpy
#  undef memset
/* Provide the actual implementation for the builtins. To prevent a linker error, we mark memcpy/memset as
 * weak, because gnu-efi is currently providing them. */
__attribute__((alias("efi_memcmp"))) int memcmp(const void *p1, const void *p2, size_t n);
__attribute__((weak, alias("efi_memcpy"))) void *memcpy(void *restrict dest, const void *restrict src, size_t n);
__attribute__((weak, alias("efi_memset"))) void *memset(void *p, int c, size_t n);
#endif
