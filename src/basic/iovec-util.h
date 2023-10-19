/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "macro.h"

static inline size_t IOVEC_TOTAL_SIZE(const struct iovec *i, size_t n) {
        size_t r = 0;

        for (size_t j = 0; j < n; j++)
                r += i[j].iov_len;

        return r;
}

static inline bool IOVEC_INCREMENT(struct iovec *i, size_t n, size_t k) {
        /* Returns true if there is nothing else to send (bytes written cover all of the iovec),
         * false if there's still work to do. */

        for (size_t j = 0; j < n; j++) {
                size_t sub;

                if (i[j].iov_len == 0)
                        continue;
                if (k == 0)
                        return false;

                sub = MIN(i[j].iov_len, k);
                i[j].iov_len -= sub;
                i[j].iov_base = (uint8_t*) i[j].iov_base + sub;
                k -= sub;
        }

        assert(k == 0); /* Anything else would mean that we wrote more bytes than available,
                         * or the kernel reported writing more bytes than sent. */
        return true;
}

#define IOVEC_NULL (struct iovec) {}
#define IOVEC_MAKE(base, len) (struct iovec) { .iov_base = (base), .iov_len = (len) }
#define IOVEC_MAKE_STRING(string)               \
        ({                                      \
                char *_s = (char*) (string);    \
                IOVEC_MAKE(_s, strlen(_s));     \
        })

char* set_iovec_string_field(struct iovec *iovec, size_t *n_iovec, const char *field, const char *value);
char* set_iovec_string_field_free(struct iovec *iovec, size_t *n_iovec, const char *field, char *value);

void iovec_array_free(struct iovec *iov, size_t n);
