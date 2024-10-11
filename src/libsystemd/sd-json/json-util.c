/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "glyph-util.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
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
        char **s = ASSERT_PTR(userdata);
        const char *n;
        int r;

        r = json_dispatch_const_user_group_name(name, variant, flags, &n);
        if (r < 0)
                return r;

        r = free_and_strdup(s, n);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to allocate string: %m");

        return 0;
}

int json_dispatch_const_user_group_name(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        const char **s = ASSERT_PTR(userdata), *n;

        if (sd_json_variant_is_null(variant)) {
                *s = NULL;
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        n = sd_json_variant_string(variant);
        if (!valid_user_group_name(n, FLAGS_SET(flags, SD_JSON_RELAX) ? VALID_USER_RELAX : 0))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid user/group name.", strna(name));

        *s = n;
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

int json_variant_new_pidref(sd_json_variant **ret, PidRef *pidref) {
        sd_id128_t boot_id;
        int r;

        /* Turns a PidRef into a triplet of PID, pidfd inode nr, and the boot ID. The triplet should uniquely
         * identify the process globally, and be good enough to turn back into a pidfd + PidRef */

        if (!pidref_is_set(pidref))
                return sd_json_variant_new_null(ret);

        r = pidref_acquire_pidfd_id(pidref);
        if (r < 0 && !ERRNO_IS_NEG_NOT_SUPPORTED(r) && r != -ENOMEDIUM)
                return r;

        if (pidref->fd_id > 0) {
                /* If we have the pidfd inode number, also acquire the boot ID, to make things universally unique */
                r = sd_id128_get_boot(&boot_id);
                if (r < 0)
                        return r;
        }

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_INTEGER("pid", pidref->pid),
                        SD_JSON_BUILD_PAIR_CONDITION(pidref->fd_id > 0, "pidfdId", SD_JSON_BUILD_INTEGER(pidref->fd_id)),
                        SD_JSON_BUILD_PAIR_CONDITION(pidref->fd_id > 0, "bootId", SD_JSON_BUILD_ID128(boot_id)));
}

int json_dispatch_pidref(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        PidRef *p = ASSERT_PTR(userdata);
        int r;

        assert(variant);

        /* Turns a JSON PID triplet back into a PidRef, i.e. the reverse of json_variant_new_pidref()
         * above. If SD_JSON_STRICT is set this will acquire a pidfd for the process, and validate that the
         * auxiliary fields match it. Otherwise, this will just store the pid and the pidfd inode number (the
         * latter not if the provided boot id differs from the local one), and not attempt to get a pidfd for
         * it, or authenticate it. */

        if (sd_json_variant_is_null(variant)) {
                pidref_done(p);
                return 0;
        }

        struct {
                uint64_t pid, fd_id;
                sd_id128_t boot_id;
        } data = {};

        if (sd_json_variant_is_integer(variant))
                /* Permit a simple classic integer based format */
                data.pid = sd_json_variant_integer(variant);
        else if (sd_json_variant_is_string(variant)) {
                /* As usual, allow integers be encoded as strings too */
                r = safe_atou64(sd_json_variant_string(variant), &data.pid);
                if (r < 0)
                        return json_log(variant, flags, r, "JSON field '%s' is not a numeric PID.", strna(name));
        } else if (sd_json_variant_is_object(variant)) {

                static const sd_json_dispatch_field dispatch_table[] = {
                        { "pid",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, voffsetof(data, pid),     SD_JSON_MANDATORY },
                        { "pidfdId", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, voffsetof(data, fd_id),   0                 },
                        { "bootId",  SD_JSON_VARIANT_STRING,        sd_json_dispatch_id128,  voffsetof(data, boot_id), 0                 },
                        {}
                };

                r = sd_json_dispatch(variant, dispatch_table, flags, &data);
                if (r < 0)
                        return r;
        } else
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is neither a numeric PID nor a PID object.", strna(name));

        /* Before casting the 64bit data.pid field to pid_t, let's ensure it fits the pid_t range. */
        if (data.pid > PID_T_MAX || !pid_is_valid(data.pid))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' does not contain a valid PID.", strna(name));

        int local_boot_id = -1; /* tristate */
        if (!sd_id128_is_null(data.boot_id)) {
                sd_id128_t my_boot_id;

                r = sd_id128_get_boot(&my_boot_id);
                if (r < 0) {
                        json_log(variant, flags | (FLAGS_SET(flags, SD_JSON_STRICT) ? 0 : SD_JSON_DEBUG), r, "Unable to get local boot ID to validate JSON field '%s': %m", strna(name));
                        if (FLAGS_SET(flags, SD_JSON_STRICT))
                                return r;
                } else {
                        local_boot_id = sd_id128_equal(data.boot_id, my_boot_id);
                        if (!local_boot_id) {
                                json_log(variant, flags | (FLAGS_SET(flags, SD_JSON_STRICT) ? 0 : SD_JSON_DEBUG), 0, "JSON field '%s' refers to non-local PID.", strna(name));
                                if (FLAGS_SET(flags, SD_JSON_STRICT))
                                        return -ESRCH;
                        }
                }
        }

        _cleanup_(pidref_done) PidRef np = PIDREF_NULL;
        if (local_boot_id != 0) {
                /* Try to acquire a pidfd – unless this is definitely not a local PID */
                r = pidref_set_pid(&np, data.pid);
                if (r < 0) {
                        json_log(variant, flags | (FLAGS_SET(flags, SD_JSON_STRICT) ? 0 : SD_JSON_DEBUG), r, "Unable to get fd for PID in JSON field '%s': %m", strna(name));
                        if (FLAGS_SET(flags, SD_JSON_STRICT))
                                return r;
                }
        }

        /* If the the PID is dead or we otherwise can't get a pidfd of it, then store at least the PID number */
        if (!pidref_is_set(&np))
                np = PIDREF_MAKE_FROM_PID(data.pid);

        /* If the pidfd inode nr is specified, validate it or at least state */
        if (data.fd_id > 0) {
                if (np.fd >= 0) {
                        r = pidref_acquire_pidfd_id(&np);
                        if (r < 0 && !ERRNO_IS_NOT_SUPPORTED(r))
                                return json_log(variant, flags, r, "Unable to get pidfd ID to validate JSON field '%s': %m", strna(name));

                        if (data.fd_id != np.fd_id) {
                                json_log(variant, flags | (FLAGS_SET(flags, SD_JSON_STRICT) ? 0 : SD_JSON_DEBUG), 0, "JSON field '%s' references PID with non-matching inode number.", strna(name));
                                if (FLAGS_SET(flags, SD_JSON_STRICT))
                                        return -ESRCH;
                        }
                } else if (local_boot_id != 0) {
                        json_log(variant, flags|SD_JSON_DEBUG, 0, "Not validating PID inode number on JSON field '%s', because operating without pidfd.", strna(name));
                        np.fd_id = data.fd_id;
                }
        }

        pidref_done(p);
        *p = TAKE_PIDREF(np);

        return 0;
}
