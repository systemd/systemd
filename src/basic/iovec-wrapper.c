/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "string-util.h"

struct iovec_wrapper *iovw_new(void) {
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

struct iovec_wrapper *iovw_free_free(struct iovec_wrapper *iovw) {
        if (!iovw)
                return NULL;

        iovw_done_free(iovw);
        return mfree(iovw);
}

struct iovec_wrapper *iovw_free(struct iovec_wrapper *iovw) {
        if (!iovw)
                return NULL;

        iovw_done(iovw);
        return mfree(iovw);
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
        return 0;
}

int iovw_put_string_field(struct iovec_wrapper *iovw, const char *field, const char *value) {
        _cleanup_free_ char *x = NULL;
        int r;

        assert(iovw);

        x = strjoin(field, value);
        if (!x)
                return -ENOMEM;

        r = iovw_put(iovw, x, strlen(x));
        if (r >= 0)
                TAKE_PTR(x);

        return r;
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
                void *dup;

                dup = memdup(iovec->iov_base, iovec->iov_len);
                if (!dup) {
                        r = -ENOMEM;
                        goto rollback;
                }

                r = iovw_consume(target, dup, iovec->iov_len);
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
