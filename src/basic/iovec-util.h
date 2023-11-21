/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "alloc-util.h"
#include "macro.h"

size_t iovec_total_size(const struct iovec *iovec, size_t n);

bool iovec_increment(struct iovec *iovec, size_t n, size_t k);

/* This accepts both const and non-const pointers */
#define IOVEC_MAKE(base, len)                                           \
        (struct iovec) {                                                \
                .iov_base = (void*) (base),                             \
                .iov_len = (len),                                       \
        }

static inline struct iovec* iovec_make_string(struct iovec *iovec, const char *s) {
        assert(iovec);
        /* We don't use strlen_ptr() here, because we don't want to include string-util.h for now */
        *iovec = IOVEC_MAKE(s, s ? strlen(s) : 0);
        return iovec;
}

#define IOVEC_MAKE_STRING(s) \
        *iovec_make_string(&(struct iovec) {}, s)

static inline void iovec_done(struct iovec *iovec) {
        /* A _cleanup_() helper that frees the iov_base in the iovec */
        assert(iovec);

        iovec->iov_base = mfree(iovec->iov_base);
        iovec->iov_len = 0;
}

static inline void iovec_done_erase(struct iovec *iovec) {
        assert(iovec);

        iovec->iov_base = erase_and_free(iovec->iov_base);
        iovec->iov_len = 0;
}

static inline bool iovec_is_set(const struct iovec *iovec) {
        /* Checks if the iovec points to a non-empty chunk of memory */
        return iovec && iovec->iov_len > 0 && iovec->iov_base;
}

static inline bool iovec_is_valid(const struct iovec *iovec) {
        /* Checks if the iovec is either NULL, empty or points to a valid bit of memory */
        return !iovec || (iovec->iov_base || iovec->iov_len == 0);
}

char* set_iovec_string_field(struct iovec *iovec, size_t *n_iovec, const char *field, const char *value);
char* set_iovec_string_field_free(struct iovec *iovec, size_t *n_iovec, const char *field, char *value);

void iovec_array_free(struct iovec *iovec, size_t n_iovec);

static inline int iovec_memcmp(const struct iovec *a, const struct iovec *b) {

        if (a == b)
                return 0;

        return memcmp_nn(a ? a->iov_base : NULL,
                         a ? a->iov_len : 0,
                         b ? b->iov_base : NULL,
                         b ? b->iov_len : 0);
}
