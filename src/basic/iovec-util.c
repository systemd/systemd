/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
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

int iovec_alloc(size_t n, struct iovec *ret) {
        assert(ret);

        void *buf = malloc(n ?: 1);
        if (!buf)
                return -ENOMEM;

        *ret = IOVEC_MAKE(buf, n);
        return 0;
}

size_t iovec_total_size(const struct iovec *iovec, size_t n) {
        size_t sum = 0;

        assert(iovec || n == 0);

        FOREACH_ARRAY(j, iovec, n) {
                if (j->iov_len > SIZE_MAX - sum)
                        return SIZE_MAX; /* Indicate overflow. */
                sum += j->iov_len;
        }

        return sum;
}

bool iovec_inc_many(struct iovec *iovec, size_t n, size_t k) {
        assert(iovec || n == 0);

        /* Returns true if there is nothing else to send (bytes written cover all of the iovec),
         * false if there's still work to do. */

        bool have = false;
        FOREACH_ARRAY(j, iovec, n) {
                if (j->iov_len == 0)
                        continue;
                if (k == 0)
                        return false;

                size_t sub = MIN(j->iov_len, k);
                iovec_inc(j, sub);
                k -= sub;

                have = have || iovec_is_set(j);
        }

        assert(k == 0); /* Anything else would mean that we wrote more bytes than available,
                         * or the kernel reported writing more bytes than sent. */

        return !have;
}

struct iovec* iovec_make_string(struct iovec *iovec, const char *s) {
        assert(iovec);

        *iovec = IOVEC_MAKE(s, strlen_ptr(s));
        return iovec;
}

void iovec_erase(struct iovec *iovec) {
        assert(iovec);

        /* Unlike iovec_done_erase(), which derives the buffer size with MALLOC_SIZEOF_SAFE(), this uses
         * iov_len as the buffer size. Hence, it can be used with iovec referring to a static array or a
         * buffer allocated on the stack. */
        explicit_bzero_safe(iovec->iov_base, iovec->iov_len);
}

void iovec_done_erase(struct iovec *iovec) {
        assert(iovec);

        iovec->iov_base = erase_and_free(iovec->iov_base);
        iovec->iov_len = 0;
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

int iovec_memcmp(const struct iovec *a, const struct iovec *b) {

        if (a == b)
                return 0;

        return memcmp_nn(a ? a->iov_base : NULL,
                         a ? a->iov_len : 0,
                         b ? b->iov_base : NULL,
                         b ? b->iov_len : 0);
}

struct iovec* iovec_memdup(const struct iovec *source, struct iovec *ret) {
        assert(ret);

        if (!iovec_is_set(source))
                *ret = (struct iovec) {};
        else {
                void *p = memdup(source->iov_base, source->iov_len);
                if (!p)
                        return NULL;

                *ret = IOVEC_MAKE(p, source->iov_len);
        }

        return ret;
}

int iovec_done_and_memdup(struct iovec *iovec, const struct iovec *source) {
        assert(iovec);

        if (iovec_equal(iovec, source))
                return 0;

        struct iovec copy;
        if (!iovec_memdup(source, &copy))
                return -ENOMEM;

        iovec_done(iovec);
        *iovec = copy;
        return 1;
}

struct iovec* iovec_append(struct iovec *iovec, const struct iovec *append) {
        assert(iovec_is_valid(iovec));

        if (!iovec_is_set(append))
                return iovec;

        if (!greedy_realloc_append(&iovec->iov_base, &iovec->iov_len, append->iov_base, append->iov_len, 1))
                return NULL;

        return iovec;
}

struct iovec* iovec_reduce(struct iovec *iovec, size_t n) {
        if (!iovec_is_set(iovec))
                return NULL;

        if (n > iovec->iov_len)
                return NULL;

        if (n == 0)
                return iovec;

        iovec->iov_len -= n;

        memmove(iovec->iov_base, (uint8_t*) iovec->iov_base + n, iovec->iov_len);
        return iovec;
}
