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
