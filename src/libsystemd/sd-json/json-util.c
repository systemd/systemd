/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "glyph-util.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "path-util.h"
#include "string-util.h"
#include "user-util.h"

int json_dispatch_unbase64_iovec(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        _cleanup_free_ void *buffer = NULL;
        struct iovec *iov = ASSERT_PTR(userdata);
        size_t sz;
        int r;

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        r = sd_json_variant_unbase64(variant, &buffer, &sz);
        if (r < 0)
                return json_log(variant, flags, r, "JSON field '%s' is not valid Base64 data.", strna(name));

        free_and_replace(iov->iov_base, buffer);
        iov->iov_len = sz;
        return 0;
}

int json_dispatch_byte_array_iovec(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        _cleanup_free_ uint8_t *buffer = NULL;
        struct iovec *iov = ASSERT_PTR(userdata);
        size_t sz, k = 0;

        assert(variant);

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        sz = sd_json_variant_elements(variant);

        buffer = new(uint8_t, sz + 1);
        if (!buffer)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ENOMEM), "Out of memory.");

        sd_json_variant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, variant) {
                uint64_t b;

                if (!sd_json_variant_is_unsigned(i))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Element %zu of JSON field '%s' is not an unsigned integer.", k, strna(name));

                b = sd_json_variant_unsigned(i);
                if (b > 0xff)
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Element %zu of JSON field '%s' is out of range 0%s255.",
                                        k, strna(name), special_glyph(SPECIAL_GLYPH_ELLIPSIS));

                buffer[k++] = (uint8_t) b;
        }
        assert(k == sz);

        /* Append a NUL byte for safety, like we do in memdup_suffix0() and others. */
        buffer[sz] = 0;

        free_and_replace(iov->iov_base, buffer);
        iov->iov_len = sz;
        return 0;
}

int json_dispatch_user_group_name(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        char **s = userdata;
        const char *n;
        int r;

        if (sd_json_variant_is_null(variant)) {
                *s = mfree(*s);
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        n = sd_json_variant_string(variant);
        if (!valid_user_group_name(n, FLAGS_SET(flags, SD_JSON_RELAX) ? VALID_USER_RELAX : 0))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid user/group name.", strna(name));

        r = free_and_strdup(s, n);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to allocate string: %m");

        return 0;
}

int json_dispatch_in_addr(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        struct in_addr *address = ASSERT_PTR(userdata);
        _cleanup_(iovec_done) struct iovec iov = {};
        int r;

        r = json_dispatch_byte_array_iovec(name, variant, flags, &iov);
        if (r < 0)
                return r;

        if (iov.iov_len != sizeof(struct in_addr))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is array of unexpected size.", strna(name));

        memcpy(address, iov.iov_base, iov.iov_len);
        return 0;
}

int json_dispatch_path(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        char **p = ASSERT_PTR(userdata);
        const char *path;

        assert(variant);

        if (sd_json_variant_is_null(variant)) {
                *p = mfree(*p);
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        path = sd_json_variant_string(variant);
        if (!((flags & SD_JSON_STRICT) ? path_is_normalized(path) : path_is_valid(path)))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a normalized file system path.", strna(name));
        if (!path_is_absolute(path))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an absolute file system path.", strna(name));

        if (free_and_strdup(p, path) < 0)
                return json_log_oom(variant, flags);

        return 0;
}
