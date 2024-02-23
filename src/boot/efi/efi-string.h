/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "macro-fundamental.h"

size_t strnlen8(const char *s, size_t n);
size_t strnlen16(const char16_t *s, size_t n);

static inline size_t strlen8(const char *s) {
        return strnlen8(s, SIZE_MAX);
}

static inline size_t strlen16(const char16_t *s) {
        return strnlen16(s, SIZE_MAX);
}

static inline size_t strsize8(const char *s) {
        return s ? (strlen8(s) + 1) * sizeof(*s) : 0;
}

static inline size_t strsize16(const char16_t *s) {
        return s ? (strlen16(s) + 1) * sizeof(*s) : 0;
}

void strtolower8(char *s);
void strtolower16(char16_t *s);

int strncmp8(const char *s1, const char *s2, size_t n);
int strncmp16(const char16_t *s1, const char16_t *s2, size_t n);
int strncasecmp8(const char *s1, const char *s2, size_t n);
int strncasecmp16(const char16_t *s1, const char16_t *s2, size_t n);

static inline int strcmp8(const char *s1, const char *s2) {
        return strncmp8(s1, s2, SIZE_MAX);
}

static inline int strcmp16(const char16_t *s1, const char16_t *s2) {
        return strncmp16(s1, s2, SIZE_MAX);
}

static inline int strcmp16_indirect(const char16_t **s1, const char16_t **s2) {
        return strcmp16(*ASSERT_PTR(s1), *ASSERT_PTR(s2));
}

static inline int strcasecmp8(const char *s1, const char *s2) {
        return strncasecmp8(s1, s2, SIZE_MAX);
}

static inline int strcasecmp16(const char16_t *s1, const char16_t *s2) {
        return strncasecmp16(s1, s2, SIZE_MAX);
}

static inline bool strneq8(const char *s1, const char *s2, size_t n) {
        return strncmp8(s1, s2, n) == 0;
}

static inline bool strneq16(const char16_t *s1, const char16_t *s2, size_t n) {
        return strncmp16(s1, s2, n) == 0;
}

static inline bool streq8(const char *s1, const char *s2) {
        return strcmp8(s1, s2) == 0;
}

static inline bool streq16(const char16_t *s1, const char16_t *s2) {
        return strcmp16(s1, s2) == 0;
}

static inline int strncaseeq8(const char *s1, const char *s2, size_t n) {
        return strncasecmp8(s1, s2, n) == 0;
}

static inline int strncaseeq16(const char16_t *s1, const char16_t *s2, size_t n) {
        return strncasecmp16(s1, s2, n) == 0;
}

static inline bool strcaseeq8(const char *s1, const char *s2) {
        return strcasecmp8(s1, s2) == 0;
}

static inline bool strcaseeq16(const char16_t *s1, const char16_t *s2) {
        return strcasecmp16(s1, s2) == 0;
}

char *strcpy8(char * restrict dest, const char * restrict src);
char16_t *strcpy16(char16_t * restrict dest, const char16_t * restrict src);

char *strchr8(const char *s, char c);
char16_t *strchr16(const char16_t *s, char16_t c);

char *xstrndup8(const char *s, size_t n);
char16_t *xstrndup16(const char16_t *s, size_t n);

static inline char *xstrdup8(const char *s) {
        return xstrndup8(s, SIZE_MAX);
}

static inline char16_t *xstrdup16(const char16_t *s) {
        return xstrndup16(s, SIZE_MAX);
}

char16_t *xstrn8_to_16(const char *str8, size_t n);
static inline char16_t *xstr8_to_16(const char *str8) {
        return xstrn8_to_16(str8, strlen8(str8));
}

char *startswith8(const char *s, const char *prefix);

bool efi_fnmatch(const char16_t *pattern, const char16_t *haystack);

bool parse_number8(const char *s, uint64_t *ret_u, const char **ret_tail);
bool parse_number16(const char16_t *s, uint64_t *ret_u, const char16_t **ret_tail);

bool parse_boolean(const char *v, bool *ret);

char *line_get_key_value(char *s, const char *sep, size_t *pos, char **ret_key, char **ret_value);

char16_t *hexdump(const void *data, size_t size);

#ifdef __clang__
#  define _gnu_printf_(a, b) _printf_(a, b)
#else
#  define _gnu_printf_(a, b) __attribute__((format(gnu_printf, a, b)))
#endif

_gnu_printf_(2, 3) void printf_status(EFI_STATUS status, const char *format, ...);
_gnu_printf_(2, 0) void vprintf_status(EFI_STATUS status, const char *format, va_list ap);
_gnu_printf_(2, 3) _warn_unused_result_ char16_t *xasprintf_status(EFI_STATUS status, const char *format, ...);
_gnu_printf_(2, 0) _warn_unused_result_ char16_t *xvasprintf_status(EFI_STATUS status, const char *format, va_list ap);

#if SD_BOOT
#  define printf(...) printf_status(EFI_SUCCESS, __VA_ARGS__)
#  define xasprintf(...) xasprintf_status(EFI_SUCCESS, __VA_ARGS__)

/* inttypes.h is provided by libc instead of the compiler and is not supposed to be used in freestanding
 * environments. We could use clang __*_FMT*__ constants for this, bug gcc does not have them. :( */

#  if defined(__ILP32__) || defined(__arm__) || defined(__i386__)
#    define PRI64_PREFIX "ll"
#  elif defined(__LP64__)
#    define PRI64_PREFIX "l"
#  elif defined(__LLP64__) || (__SIZEOF_LONG__ == 4 && __SIZEOF_POINTER__ == 8)
#    define PRI64_PREFIX "ll"
#  else
#    error Unknown 64-bit data model
#  endif

#  define PRIi32 "i"
#  define PRIu32 "u"
#  define PRIx32 "x"
#  define PRIX32 "X"
#  define PRIiPTR "zi"
#  define PRIuPTR "zu"
#  define PRIxPTR "zx"
#  define PRIXPTR "zX"
#  define PRIi64 PRI64_PREFIX "i"
#  define PRIu64 PRI64_PREFIX "u"
#  define PRIx64 PRI64_PREFIX "x"
#  define PRIX64 PRI64_PREFIX "X"

/* The compiler normally has knowledge about standard functions such as memcmp, but this is not the case when
 * compiling with -ffreestanding. By referring to builtins, the compiler can check arguments and do
 * optimizations again. Note that we still need to provide implementations as the compiler is free to not
 * inline its own implementation and instead issue a library call. */
#  define memchr __builtin_memchr
#  define memcmp __builtin_memcmp
#  define memcpy __builtin_memcpy
#  define memset __builtin_memset

static inline void *mempcpy(void * restrict dest, const void * restrict src, size_t n) {
        if (!dest || !src || n == 0)
                return dest;
        memcpy(dest, src, n);
        return (uint8_t *) dest + n;
}

#else
/* For unit testing. */
void *efi_memchr(const void *p, int c, size_t n);
int efi_memcmp(const void *p1, const void *p2, size_t n);
void *efi_memcpy(void * restrict dest, const void * restrict src, size_t n);
void *efi_memset(void *p, int c, size_t n);
#endif
