/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "iovec-util.h"
#include "string-util.h"

static const uint8_t nul_byte = 0;

const struct iovec iovec_nul_byte = {
        .iov_base = (void*) &nul_byte,
        .iov_len = 1,
};

const struct iovec iovec_empty = {
        .iov_base = (void*) &nul_byte,
        .iov_len = 0,
};

size_t iovec_total_size(const struct iovec *iovec, size_t n) {
        size_t sum = 0;

        assert(iovec || n == 0);

        FOREACH_ARRAY(j, iovec, n)
                sum += j->iov_len;

        return sum;
}

bool iovec_increment(struct iovec *iovec, size_t n, size_t k) {
        assert(iovec || n == 0);

        /* Returns true if there is nothing else to send (bytes written cover all of the iovec),
         * false if there's still work to do. */

        FOREACH_ARRAY(j, iovec, n) {
                size_t sub;

                if (j->iov_len == 0)
                        continue;
                if (k == 0)
                        return false;

                sub = MIN(j->iov_len, k);
                j->iov_len -= sub;
                j->iov_base = (uint8_t*) j->iov_base + sub;
                k -= sub;
        }

        assert(k == 0); /* Anything else would mean that we wrote more bytes than available,
                         * or the kernel reported writing more bytes than sent. */
        return true;
}

char* set_iovec_string_field(struct iovec *iovec, size_t *n_iovec, const char *field, const char *value) {
        char *x;

        assert(iovec);
        assert(n_iovec);

        x = strjoin(field, value);
        if (x)
                iovec[(*n_iovec)++] = IOVEC_MAKE_STRING(x);
        return x;
}

char* set_iovec_string_field_free(struct iovec *iovec, size_t *n_iovec, const char *field, char *value) {
        char *x;

        assert(iovec);
        assert(n_iovec);

        x = set_iovec_string_field(iovec, n_iovec, field, value);
        free(value);
        return x;
}

void iovec_array_free(struct iovec *iovec, size_t n_iovec) {
        assert(iovec || n_iovec == 0);

        FOREACH_ARRAY(i, iovec, n_iovec)
                free(i->iov_base);

        free(iovec);
}

struct iovec* iovec_append(struct iovec *iovec, const struct iovec *append) {
        assert(iovec_is_valid(iovec));

        if (!iovec_is_set(append))
                return iovec;

        if (!greedy_realloc_append(&iovec->iov_base, &iovec->iov_len, append->iov_base, append->iov_len, 1))
                return NULL;

        return iovec;
}
