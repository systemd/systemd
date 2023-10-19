/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "string-util.h"

struct iovec_wrapper *iovw_new(void) {
        return new0(struct iovec_wrapper, 1);
}

void iovw_free_contents(struct iovec_wrapper *iovw, bool free_vectors) {
        if (free_vectors)
                for (size_t i = 0; i < iovw->count; i++)
                        free(iovw->iovec[i].iov_base);

        iovw->iovec = mfree(iovw->iovec);
        iovw->count = 0;
}

struct iovec_wrapper *iovw_free_free(struct iovec_wrapper *iovw) {
        iovw_free_contents(iovw, true);

        return mfree(iovw);
}

struct iovec_wrapper *iovw_free(struct iovec_wrapper *iovw) {
        iovw_free_contents(iovw, false);

        return mfree(iovw);
}

int iovw_put(struct iovec_wrapper *iovw, void *data, size_t len) {
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

void iovw_rebase(struct iovec_wrapper *iovw, char *old, char *new) {
        for (size_t i = 0; i < iovw->count; i++)
                iovw->iovec[i].iov_base = (char *)iovw->iovec[i].iov_base - old + new;
}

size_t iovw_size(struct iovec_wrapper *iovw) {
        size_t n = 0;

        for (size_t i = 0; i < iovw->count; i++)
                n += iovw->iovec[i].iov_len;

        return n;
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
                free(target->iovec[i].iov_base);

        target->count = original_count;
        return r;
}
