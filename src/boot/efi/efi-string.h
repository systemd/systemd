/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <uchar.h>

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

bool efi_fnmatch(const char16_t *pattern, const char16_t *haystack);

bool parse_number8(const char *s, uint64_t *ret_u, const char **ret_tail);
bool parse_number16(const char16_t *s, uint64_t *ret_u, const char16_t **ret_tail);

#ifdef SD_BOOT
/* The compiler normally has knowledge about standard functions such as memcmp, but this is not the case when
 * compiling with -ffreestanding. By referring to builtins, the compiler can check arguments and do
 * optimizations again. Note that we still need to provide implementations as the compiler is free to not
 * inline its own implementation and instead issue a library call. */
#  define memcmp __builtin_memcmp
#  define memcpy __builtin_memcpy
#  define memset __builtin_memset
#endif

/* The actual implementations of builtins with efi_ prefix so we can unit test them. */
int efi_memcmp(const void *p1, const void *p2, size_t n);
void *efi_memcpy(void * restrict dest, const void * restrict src, size_t n);
void *efi_memset(void *p, int c, size_t n);
