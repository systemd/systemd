/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-string.h"

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
