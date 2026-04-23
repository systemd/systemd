/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "string-util.h"
#include "unaligned.h"

void iovw_done(struct iovec_wrapper *iovw) {
        assert(iovw);

        iovw->iovec = mfree(iovw->iovec);
        iovw->count = 0;
}

void iovw_done_free(struct iovec_wrapper *iovw) {
        assert(iovw);

        FOREACH_ARRAY(i, iovw->iovec, iovw->count)
                iovec_done(i);

        iovw_done(iovw);
}

int iovw_compare(const struct iovec_wrapper *a, const struct iovec_wrapper *b) {
        int r;

        if (a == b)
                return 0;

        if (!a || !b)
                return CMP(!!a, !!b);

        /* Note, this performs structural (element-by-element) comparison, not content-based comparison.
         * Two wrappers with identical concatenated content but different element boundaries
         * (e.g., ["fo","o"] vs ["f","oo"]) will not compare as equal. */

        for (size_t i = 0, n = MIN(a->count, b->count); i < n; i++) {
                r = iovec_memcmp(a->iovec + i, b->iovec + i);
                if (r != 0)
                        return r;
        }

        return CMP(a->count, b->count);
}

int iovw_put_full(struct iovec_wrapper *iovw, bool accept_zero, void *data, size_t len) {
        assert(iovw);
        assert(data || len == 0);

        if (len == 0 && !accept_zero)
                return 0;

        if (iovw->count >= IOV_MAX)
                return -E2BIG;

        if (!GREEDY_REALLOC(iovw->iovec, iovw->count + 1))
                return -ENOMEM;

        iovw->iovec[iovw->count++] = IOVEC_MAKE(data, len);
        return 1;
}

int iovw_put_iov_full(struct iovec_wrapper *iovw, bool accept_zero, const struct iovec *iov) {
        assert(iovw);

        if (!iov)
                return 0;

        return iovw_put_full(iovw, accept_zero, iov->iov_base, iov->iov_len);
}

int iovw_put_iovw_full(struct iovec_wrapper *iovw, bool accept_zero, const struct iovec_wrapper *source) {
        int r;

        assert(iovw);

        if (iovw_isempty(source))
                return 0;

        /* We will reallocate iovw->iovec, hence the source cannot point to the same object. */
        if (iovw == source)
                return -EINVAL;

        if (iovw->count > SIZE_MAX - source->count)
                return -E2BIG;
        if (iovw->count + source->count > IOV_MAX)
                return -E2BIG;

        if (accept_zero) {
                if (!GREEDY_REALLOC_APPEND(iovw->iovec, iovw->count, source->iovec, source->count))
                        return -ENOMEM;

                return 0;
        }

        /* When accept_zero is false, we need to filter zero length iovec in source. */
        size_t original_count = iovw->count;

        FOREACH_ARRAY(iovec, source->iovec, source->count) {
                r = iovw_put_iov_full(iovw, accept_zero, iovec);
                if (r < 0)
                        goto rollback;
        }

        return 0;

rollback:
        iovw->count = original_count;
        return r;
}

int iovw_consume_full(struct iovec_wrapper *iovw, bool accept_zero, void *data, size_t len) {
        /* Move data into iovw or free on error */
        int r;

        r = iovw_put_full(iovw, accept_zero, data, len);
        if (r <= 0)
                free(data);

        return r;
}

int iovw_consume_iov_full(struct iovec_wrapper *iovw, bool accept_zero, struct iovec *iov) {
        int r;

        assert(iovw);

        if (!iov)
                return 0;

        r = iovw_put_iov_full(iovw, accept_zero, iov);
        if (r <= 0)
                iovec_done(iov);
        else
                /* On success, iov->iov_base is now owned by iovw. Let's emptify iov, but do not call
                 * iovec_done(), of course. */
                *iov = (struct iovec) {};

        return r;
}

int iovw_extend_full(struct iovec_wrapper *iovw, bool accept_zero, const void *data, size_t len) {
        assert(iovw);
        assert(data || len == 0);

        if (len == 0)
                return iovw_put_full(iovw, accept_zero, /* data= */ NULL, /* len= */ 0);

        void *c = memdup(data, len);
        if (!c)
                return -ENOMEM;

        return iovw_consume_full(iovw, accept_zero, c, len);
}

int iovw_extend_iov_full(struct iovec_wrapper *iovw, bool accept_zero, const struct iovec *iov) {
        assert(iovw);

        if (!iov)
                return 0;

        return iovw_extend_full(iovw, accept_zero, iov->iov_base, iov->iov_len);
}

int iovw_extend_iovw_full(struct iovec_wrapper *iovw, bool accept_zero, const struct iovec_wrapper *source) {
        int r;

        assert(iovw);

        /* This duplicates the source and merges it into the iovw. */

        if (iovw_isempty(source))
                return 0;

        /* iovw->iovec will be reallocated in the loop below, hence source cannot point to the same object. */
        if (iovw == source)
                return -EINVAL;

        if (iovw->count > SIZE_MAX - source->count)
                return -E2BIG;
        if (iovw->count + source->count > IOV_MAX)
                return -E2BIG;

        size_t original_count = iovw->count;

        FOREACH_ARRAY(iovec, source->iovec, source->count) {
                r = iovw_extend_iov_full(iovw, accept_zero, iovec);
                if (r < 0)
                        goto rollback;
        }

        return 0;

rollback:
        for (size_t i = original_count; i < iovw->count; i++)
                iovec_done(iovw->iovec + i);

        iovw->count = original_count;
        return r;
}

int iovw_put_string_field_full(struct iovec_wrapper *iovw, bool replace, const char *field, const char *value) {
        _cleanup_free_ char *x = NULL;
        int r;

        assert(iovw);

        x = strjoin(field, value);
        if (!x)
                return -ENOMEM;

        if (replace)
                FOREACH_ARRAY(iovec, iovw->iovec, iovw->count)
                        if (memory_startswith(iovec->iov_base, iovec->iov_len, field)) {
                                iovec->iov_len = strlen(x);
                                free_and_replace(iovec->iov_base, x);
                                return 0;
                        }

        r = iovw_put(iovw, x, strlen(x));
        if (r >= 0)
                TAKE_PTR(x);

        return r;
}

int iovw_put_string_fieldf_full(struct iovec_wrapper *iovw, bool replace, const char *field, const char *format, ...) {
        _cleanup_free_ char *value = NULL;
        va_list ap;
        int r;

        assert(format);

        va_start(ap, format);
        r = vasprintf(&value, format, ap);
        va_end(ap);
        if (r < 0)
                return -ENOMEM;

        return iovw_put_string_field_full(iovw, replace, field, value);
}

int iovw_put_string_field_free(struct iovec_wrapper *iovw, const char *field, char *value) {
        _cleanup_free_ _unused_ char *free_ptr = value;

        return iovw_put_string_field(iovw, field, value);
}

void iovw_rebase(struct iovec_wrapper *iovw, void *old, void *new) {
        assert(iovw);

        FOREACH_ARRAY(i, iovw->iovec, iovw->count) {
                assert(i->iov_base >= old);
                i->iov_base = (uint8_t*) i->iov_base - (uint8_t*) old + (uint8_t*) new;
        }
}

size_t iovw_size(const struct iovec_wrapper *iovw) {
        if (iovw_isempty(iovw))
                return 0;

        return iovec_total_size(iovw->iovec, iovw->count);
}

int iovw_concat(const struct iovec_wrapper *iovw, struct iovec *ret) {
        assert(iovw);
        assert(ret);

        /* Squish a series of iovecs into a single iovec. */

        size_t len = iovw_size(iovw);
        if (len == SIZE_MAX)
                return -E2BIG;  /* Prevent theoretical overflow */

        /* Always allocate one more byte to make the result usable as a NUL-terminated string. */
        _cleanup_free_ uint8_t *buf = malloc(len + 1);
        if (!buf)
                return -ENOMEM;

        uint8_t *p = buf;
        FOREACH_ARRAY(i, iovw->iovec, iovw->count)
                p = mempcpy_safe(p, i->iov_base, i->iov_len);

        *p = 0;

        *ret = IOVEC_MAKE(TAKE_PTR(buf), len);
        return 0;
}

char* iovw_to_cstring(const struct iovec_wrapper *iovw) {
        assert(iovw);

        /* Squish a series of iovecs into a C string. Embedded NULs are not allowed.
         * The caller is expected to filter them out when populating the data. */

        _cleanup_(iovec_done) struct iovec iov = {};
        if (iovw_concat(iovw, &iov) < 0)
                return NULL;

        assert(!memchr(iov.iov_base, 0, iov.iov_len));
        return TAKE_PTR(iov.iov_base);
}

int iovec_split(const struct iovec *iov, size_t length_size, struct iovec_wrapper *ret) {
        int r;

        assert(IN_SET(length_size, 1, 2, 4));
        assert(ret);

        /* This parses the input iovec as length-prefixed data, and stores the result as iovec_wrapper.
         * Note, zero-length entries are silently dropped. */

        if (!iovec_is_set(iov)) {
                *ret = (struct iovec_wrapper) {};
                return 0;
        }

        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        for (struct iovec i = *iov; iovec_is_set(&i); ) {
                if (i.iov_len < length_size)
                        return -EBADMSG;

                size_t len;
                switch (length_size) {
                case 1:
                        len = *(uint8_t*) i.iov_base;
                        break;
                case 2:
                        len = unaligned_read_be16(i.iov_base);
                        break;
                case 4:
                        len = unaligned_read_be32(i.iov_base);
                        break;
                default:
                        assert_not_reached();
                }

                iovec_inc(&i, length_size);

                if (len == 0)
                        continue;

                if (i.iov_len < len)
                        return -EBADMSG;

                r = iovw_extend(&iovw, i.iov_base, len);
                if (r < 0)
                        return r;

                iovec_inc(&i, len);
        }

        *ret = TAKE_STRUCT(iovw);
        return 0;
}

int iovw_merge(const struct iovec_wrapper *iovw, size_t length_size, struct iovec *ret) {
        assert(IN_SET(length_size, 1, 2, 4));
        assert(ret);

        /* This is the inverse of iovec_split(), and builds a length-prefixed data from iovec_wrapper.
         * Note, zero-length entries are silently dropped. */

        size_t sz = iovw_size(iovw);
        if (sz == 0) {
                *ret = (struct iovec) {};
                return 0;
        }
        if (sz == SIZE_MAX)
                return -E2BIG;

        if (size_multiply_overflow(length_size, iovw->count))
                return -E2BIG;

        sz = size_add(sz, iovw->count * length_size);
        if (sz == SIZE_MAX)
                return -E2BIG;

        _cleanup_free_ uint8_t *buf = new(uint8_t, sz);
        if (!buf)
                return -ENOMEM;

        uint8_t *p = buf;
        FOREACH_ARRAY(iov, iovw->iovec, iovw->count) {
                if (iov->iov_len == 0)
                        continue;

                switch (length_size) {
                case 1:
                        if (iov->iov_len > UINT8_MAX)
                                return -ERANGE;

                        *p = iov->iov_len;
                        break;
                case 2:
                        if (iov->iov_len > UINT16_MAX)
                                return -ERANGE;

                        unaligned_write_be16(p, iov->iov_len);
                        break;
                case 4:
                        if (iov->iov_len > UINT32_MAX)
                                return -ERANGE;

                        unaligned_write_be32(p, iov->iov_len);
                        break;
                default:
                        assert_not_reached();
                }
                p += length_size;

                p = mempcpy(p, iov->iov_base, iov->iov_len);
        }

        assert(sz >= (size_t) (p - buf));
        sz = p - buf;

        *ret = IOVEC_MAKE(TAKE_PTR(buf), sz);
        return 0;
}
