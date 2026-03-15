/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "string-util.h"

struct iovec_wrapper* iovw_new(void) {
        return new0(struct iovec_wrapper, 1);
}

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

struct iovec_wrapper* iovw_free_free(struct iovec_wrapper *iovw) {
        if (!iovw)
                return NULL;

        iovw_done_free(iovw);
        return mfree(iovw);
}

struct iovec_wrapper* iovw_free(struct iovec_wrapper *iovw) {
        if (!iovw)
                return NULL;

        iovw_done(iovw);
        return mfree(iovw);
}

int iovw_compare(const struct iovec_wrapper *a, const struct iovec_wrapper *b) {
        int r;

        if (a == b)
                return 0;

        if (!a || !b)
                return CMP((uintptr_t) a, (uintptr_t) b);

        for (size_t i = 0, n = MIN(a->count, b->count); i < n; i++) {
                r = iovec_memcmp(a->iovec + i, b->iovec + i);
                if (r != 0)
                        return r;
        }

        return CMP(a->count, b->count);
}

int iovw_put(struct iovec_wrapper *iovw, void *data, size_t len) {
        assert(iovw);

        if (len == 0)
                return 0;

        assert(data);

        if (iovw->count >= IOV_MAX)
                return -E2BIG;

        if (!GREEDY_REALLOC(iovw->iovec, iovw->count + 1))
                return -ENOMEM;

        iovw->iovec[iovw->count++] = IOVEC_MAKE(data, len);
        return 1;
}

int iovw_put_iov(struct iovec_wrapper *iovw, const struct iovec *iov) {
        assert(iovw);
        assert(iov);

        return iovw_put(iovw, iov->iov_base, iov->iov_len);
}

int iovw_put_iovw(struct iovec_wrapper *iovw, const struct iovec_wrapper *source) {
        assert(iovw);

        if (iovw_isempty(source))
                return 0;

        if (iovw->count + source->count > IOV_MAX)
                return -E2BIG;

        if (!GREEDY_REALLOC_APPEND(iovw->iovec, iovw->count, source->iovec, source->count))
                return -ENOMEM;

        return 0;
}

int iovw_consume(struct iovec_wrapper *iovw, void *data, size_t len) {
        /* Move data into iovw or free on error */
        int r;

        r = iovw_put(iovw, data, len);
        if (r <= 0)
                free(data);

        return r;
}

int iovw_consume_iov(struct iovec_wrapper *iovw, struct iovec *iov) {
        int r;

        r = iovw_put_iov(iovw, iov);
        if (r <= 0)
                iovec_done(iov);

        return r;
}

int iovw_extend(struct iovec_wrapper *iovw, const void *data, size_t len) {
        assert(iovw);

        if (len == 0)
                return 0;

        assert(data);

        void *copy = memdup(data, len);
        if (!copy)
                return -ENOMEM;

        return iovw_consume(iovw, copy, len);
}

int iovw_extend_iov(struct iovec_wrapper *iovw, const struct iovec *iov) {
        assert(iovw);
        assert(iov);

        return iovw_extend(iovw, iov->iov_base, iov->iov_len);
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
        if (!iovw)
                return 0;

        return iovec_total_size(iovw->iovec, iovw->count);
}

int iovw_append(struct iovec_wrapper *target, const struct iovec_wrapper *source) {
        size_t original_count;
        int r;

        assert(target);

        /* This duplicates the source and merges it into the target. */

        if (iovw_isempty(source))
                return 0;

        original_count = target->count;

        FOREACH_ARRAY(iovec, source->iovec, source->count) {
                r = iovw_extend_iov(target, iovec);
                if (r < 0)
                        goto rollback;
        }

        return 0;

rollback:
        for (size_t i = original_count; i < target->count; i++)
                iovec_done(target->iovec + i);

        target->count = original_count;
        return r;
}

int iovw_concat(const struct iovec_wrapper *iovw, struct iovec *ret) {
        assert(iovw);
        assert(ret);

        size_t len = 0;
        FOREACH_ARRAY(i, iovw->iovec, iovw->count) {
                if (len > SIZE_MAX - i->iov_len)
                        return -E2BIG;

                len += i->iov_len;
        }

        /* Always allocate one more byte to make the result can be used as NUL-terminated string. */
        _cleanup_free_ uint8_t *buf = malloc(len + 1);
        if (!buf)
                return -ENOMEM;

        uint8_t *p = buf;
        FOREACH_ARRAY(i, iovw->iovec, iovw->count)
                p = mempcpy(p, i->iov_base, i->iov_len);

        *p = 0;

        *ret = IOVEC_MAKE(TAKE_PTR(buf), len);
        return 0;
}
