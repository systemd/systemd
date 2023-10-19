/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "iovec-util.h"
#include "string-util.h"


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

void iovec_array_free(struct iovec *iov, size_t n) {
        if (!iov)
                return;

        for (size_t i = 0; i < n; i++)
                free(iov[i].iov_base);

        free(iov);
}
