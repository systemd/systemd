/* SPDX-License-Identifier: LGPL-2.1+ */
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
int unhexmem_full(const char *p, size_t l, bool secure, void **mem, size_t *len);
static inline int unhexmem(const char *p, size_t l, void **mem, size_t *len) {
        return unhexmem_full(p, l, false, mem, len);
}

char base32hexchar(int x) _const_;
int unbase32hexchar(char c) _const_;

char base64char(int x) _const_;
int unbase64char(char c) _const_;

char *base32hexmem(const void *p, size_t l, bool padding);
int unbase32hexmem(const char *p, size_t l, bool padding, void **mem, size_t *len);

ssize_t base64mem(const void *p, size_t l, char **out);
int base64_append(char **prefix, int plen,
                  const void *p, size_t l,
                  int margin, int width);
int unbase64mem_full(const char *p, size_t l, bool secure, void **mem, size_t *len);
static inline int unbase64mem(const char *p, size_t l, void **mem, size_t *len) {
        return unbase64mem_full(p, l, false, mem, len);
}

void hexdump(FILE *f, const void *p, size_t s);
