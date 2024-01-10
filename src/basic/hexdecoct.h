/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#include "macro.h"

char octchar(int x) _const_;
int unoctchar(char c) _const_;

char decchar(int x) _const_;
int undecchar(char c) _const_;

char hexchar(int x) _const_;
int unhexchar(char c) _const_;

char *hexmem(const void *p, size_t l);
int unhexmem_full(const char *p, size_t l, bool secure, void **ret_data, size_t *ret_size);
static inline int unhexmem(const char *p, void **ret_data, size_t *ret_size) {
        return unhexmem_full(p, SIZE_MAX, false, ret_data, ret_size);
}

char base32hexchar(int x) _const_;
int unbase32hexchar(char c) _const_;

char base64char(int x) _const_;
char urlsafe_base64char(int x) _const_;
int unbase64char(char c) _const_;

char *base32hexmem(const void *p, size_t l, bool padding);
int unbase32hexmem(const char *p, size_t l, bool padding, void **mem, size_t *len);

ssize_t base64mem_full(const void *p, size_t l, size_t line_break, char **ret);
static inline ssize_t base64mem(const void *p, size_t l, char **ret) {
        return base64mem_full(p, l, SIZE_MAX, ret);
}

ssize_t base64_append(
                char **prefix,
                size_t plen,
                const void *p,
                size_t l,
                size_t margin,
                size_t width);
int unbase64mem_full(const char *p, size_t l, bool secure, void **ret_data, size_t *ret_size);
static inline int unbase64mem(const char *p, void **ret_data, size_t *ret_size) {
        return unbase64mem_full(p, SIZE_MAX, false, ret_data, ret_size);
}

void hexdump(FILE *f, const void *p, size_t s);
