/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "string-util.h"

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

int iovw_consume(struct iovec_wrapper *iovw, void *data, size_t len) {
        /* Move data into iovw or free on error */
        int r;

        r = iovw_put(iovw, data, len);
        if (r < 0)
                free(data);

        return r;
}

int iovw_append(struct iovec_wrapper *iovw, const void *data, size_t len) {
        if (len == 0)
                return 0;

        void *c = memdup(data, len);
        if (!c)
                return -ENOMEM;

        return iovw_consume(iovw, c, len);
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
        assert(iovw);

        return iovec_total_size(iovw->iovec, iovw->count);
}

int iovw_append_iovw(struct iovec_wrapper *target, const struct iovec_wrapper *source) {
        int r;

        assert(target);

        /* This duplicates the source and merges it into the target. */

        if (iovw_isempty(source))
                return 0;

        size_t original_count = target->count;

        FOREACH_ARRAY(iovec, source->iovec, source->count) {
                r = iovw_append(target, iovec->iov_base, iovec->iov_len);
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

char* iovw_to_cstring(const struct iovec_wrapper *iovw) {
        size_t size;
        char *p, *ans;

        assert(iovw);

        /* Squish a series of iovecs into a C string. Embedded NULs are not allowed.
         * The caller is expected to filter them out when populating the data. */

        size = iovw_size(iovw);
        if (size == SIZE_MAX)
                return NULL;  /* Prevent theoretical overflow */
        size ++;

        p = ans = new(char, size);
        if (!ans)
                return NULL;

        FOREACH_ARRAY(iovec, iovw->iovec, iovw->count) {
                assert(!memchr(iovec->iov_base, 0, iovec->iov_len));

                p = mempcpy(p, iovec->iov_base, iovec->iov_len);
        }

        *p = '\0';

        return ans;
}
