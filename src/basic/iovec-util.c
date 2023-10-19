/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "iovec-util.h"
#include "string-util.h"

size_t iovec_total_size(const struct iovec *i, size_t n) {
        size_t sum = 0;

        assert(i || n == 0);

        FOREACH_ARRAY(j, i, n)
                sum += j->iov_len;

        return sum;
}

bool iovec_increment(struct iovec *i, size_t n, size_t k) {
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

char* set_iovec_string_field(struct iovec *iovec, size_t *n_iovec, const char *field, const char *value) {
        char *x;

        x = strjoin(field, value);
        if (x)
                iovec[(*n_iovec)++] = IOVEC_MAKE_STRING(x);
        return x;
}

char* set_iovec_string_field_free(struct iovec *iovec, size_t *n_iovec, const char *field, char *value) {
        char *x;

        x = set_iovec_string_field(iovec, n_iovec, field, value);
        free(value);
        return x;
}

void iovec_array_free(struct iovec *iov, size_t n) {
        if (!iov)
                return;

        for (size_t i = 0; i < n; i++)
                free(iov[i].iov_base);

        free(iov);
}
