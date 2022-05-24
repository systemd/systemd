/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <stdint.h>

#include "efi-string.h"

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

size_t strlen8(const char *s) {
        return strnlen8(s, SIZE_MAX);
}

size_t strlen16(const char16_t *s) {
        return strnlen16(s, SIZE_MAX);
}

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
                        int c1 = *s1;                        \
                        int c2 = *s2;                        \
                        if (tolower) {                       \
                                c1 = TOLOWER(c1);            \
                                c2 = TOLOWER(c2);            \
                        }                                    \
                        if (!c1 || c1 != c2)                 \
                                return c1 - c2;              \
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

int strcmp8(const char *s1, const char *s2) {
        return strncmp8(s1, s2, SIZE_MAX);
}

int strcmp16(const char16_t *s1, const char16_t *s2) {
        return strncmp16(s1, s2, SIZE_MAX);
}

DEFINE_STRNCASECMP(char, strncasecmp8, true);
DEFINE_STRNCASECMP(char16_t, strncasecmp16, true);

int strcasecmp8(const char *s1, const char *s2) {
        return strncasecmp8(s1, s2, SIZE_MAX);
}

int strcasecmp16(const char16_t *s1, const char16_t *s2) {
        return strncasecmp16(s1, s2, SIZE_MAX);
}

#define DEFINE_STRCPY(type, name)                                     \
        type *name(type * restrict dest, const type * restrict src) { \
                assert(dest);                                         \
                type *ret = dest;                                     \
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

void *efi_memcpy(void * restrict dest, const void * restrict src, size_t n) {
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
__attribute__((weak, alias("efi_memcpy"))) void *memcpy(void * restrict dest, const void * restrict src, size_t n);
__attribute__((weak, alias("efi_memset"))) void *memset(void *p, int c, size_t n);
#endif
