/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>                /* IWYU pragma: export */

#include "forward.h"
#include "iovec-util-fundamental.h" /* IWYU pragma: export */

extern const struct iovec iovec_nul_byte; /* Points to a single NUL byte */
extern const struct iovec iovec_empty;    /* Points to an empty, but valid (i.e. non-NULL) pointer */

size_t iovec_total_size(const struct iovec *iovec, size_t n) _nonnull_if_nonzero_(1, 2);

bool iovec_increment(struct iovec *iovec, size_t n, size_t k) _nonnull_if_nonzero_(1, 2);

struct iovec* iovec_make_string(struct iovec *iovec, const char *s);

#define IOVEC_MAKE_STRING(s) \
        *iovec_make_string(&(struct iovec) {}, s)

#define CONST_IOVEC_MAKE_STRING(s)              \
        (const struct iovec) {                  \
                .iov_base = (char*) s,          \
                .iov_len = STRLEN(s),           \
        }

void iovec_done_erase(struct iovec *iovec);

char* set_iovec_string_field(struct iovec *iovec, size_t *n_iovec, const char *field, const char *value);
char* set_iovec_string_field_free(struct iovec *iovec, size_t *n_iovec, const char *field, char *value);

void iovec_array_free(struct iovec *iovec, size_t n_iovec) _nonnull_if_nonzero_(1, 2);

int iovec_memcmp(const struct iovec *a, const struct iovec *b) _pure_;

struct iovec* iovec_memdup(const struct iovec *source, struct iovec *ret);

struct iovec* iovec_append(struct iovec *iovec, const struct iovec *append);
