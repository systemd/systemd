/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "macro.h"

size_t strnpcpy_full(char **dest, size_t size, const char *src, size_t len, bool *ret_truncated);
static inline size_t strnpcpy(char **dest, size_t size, const char *src, size_t len) {
        return strnpcpy_full(dest, size, src, len, NULL);
}
size_t strpcpy_full(char **dest, size_t size, const char *src, bool *ret_truncated);
static inline size_t strpcpy(char **dest, size_t size, const char *src) {
        return strpcpy_full(dest, size, src, NULL);
}
size_t strpcpyf_full(char **dest, size_t size, bool *ret_truncated, const char *src, ...) _printf_(4, 5);
#define strpcpyf(dest, size, src, ...) \
        strpcpyf_full((dest), (size), NULL, (src), ##__VA_ARGS__)
size_t strpcpyl_full(char **dest, size_t size, bool *ret_truncated, const char *src, ...) _sentinel_;
#define strpcpyl(dest, size, src, ...) \
        strpcpyl_full((dest), (size), NULL, (src), ##__VA_ARGS__)
size_t strnscpy_full(char *dest, size_t size, const char *src, size_t len, bool *ret_truncated);
static inline size_t strnscpy(char *dest, size_t size, const char *src, size_t len) {
        return strnscpy_full(dest, size, src, len, NULL);
}
size_t strscpy_full(char *dest, size_t size, const char *src, bool *ret_truncated);
static inline size_t strscpy(char *dest, size_t size, const char *src) {
        return strscpy_full(dest, size, src, NULL);
}
size_t strscpyl_full(char *dest, size_t size, bool *ret_truncated, const char *src, ...) _sentinel_;
#define strscpyl(dest, size, src, ...) \
        strscpyl_full(dest, size, NULL, src, ##__VA_ARGS__)
