/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <uchar.h>

size_t strnlen8(const char *s, size_t n);
size_t strnlen16(const char16_t *s, size_t n);

size_t strlen8(const char *s);
size_t strlen16(const char16_t *s);

void strtolower8(char *s);
void strtolower16(char16_t *s);

int strncmp8(const char *s1, const char *s2, size_t n);
int strncmp16(const char16_t *s1, const char16_t *s2, size_t n);

int strcmp8(const char *s1, const char *s2);
int strcmp16(const char16_t *s1, const char16_t *s2);

int strncasecmp8(const char *s1, const char *s2, size_t n);
int strncasecmp16(const char16_t *s1, const char16_t *s2, size_t n);

int strcasecmp8(const char *s1, const char *s2);
int strcasecmp16(const char16_t *s1, const char16_t *s2);

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
