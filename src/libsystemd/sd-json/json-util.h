/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <syslog.h>

#include "sd-json.h"

#include "log.h"
#include "sd-forward.h"
#include "string-util.h"        /* IWYU pragma: keep */

#define JSON_VARIANT_REPLACE(v, q)        \
        do {                              \
                typeof(v)* _v = &(v);     \
                typeof(q) _q = (q);       \
                sd_json_variant_unref(*_v);  \
                *_v = _q;                 \
        } while(false)

static inline int json_variant_set_field_non_null(sd_json_variant **v, const char *field, sd_json_variant *value) {
        return value && !sd_json_variant_is_null(value) ? sd_json_variant_set_field(v, field, value) : 0;
}

struct json_variant_foreach_state {
        sd_json_variant *variant;
        size_t idx;
};

#define _JSON_VARIANT_ARRAY_FOREACH(i, v, state)                        \
        for (struct json_variant_foreach_state state = { (v), 0 };      \
             sd_json_variant_is_array(state.variant) &&                    \
                     state.idx < sd_json_variant_elements(state.variant) && \
                     ({ i = sd_json_variant_by_index(state.variant, state.idx); \
                             true; });                                  \
             state.idx++)
#define JSON_VARIANT_ARRAY_FOREACH(i, v)                                \
        _JSON_VARIANT_ARRAY_FOREACH(i, v, UNIQ_T(state, UNIQ))

#define _JSON_VARIANT_OBJECT_FOREACH(k, e, v, state)                    \
        for (struct json_variant_foreach_state state = { (v), 0 };      \
             sd_json_variant_is_object(state.variant) &&                   \
                     state.idx < sd_json_variant_elements(state.variant) && \
                     ({ k = sd_json_variant_string(sd_json_variant_by_index(state.variant, state.idx)); \
                             e = sd_json_variant_by_index(state.variant, state.idx + 1); \
                             true; });                                  \
             state.idx += 2)
#define JSON_VARIANT_OBJECT_FOREACH(k, e, v)                            \
        _JSON_VARIANT_OBJECT_FOREACH(k, e, v, UNIQ_T(state, UNIQ))

#define JSON_DISPATCH_ENUM_DEFINE(name, type, func)                     \
        int name(const char *n, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) { \
                type *c = ASSERT_PTR(userdata);                         \
                                                                        \
                assert(variant);                                        \
                                                                        \
                if (sd_json_variant_is_null(variant)) {                 \
                        *c = (type) -EINVAL;                            \
                        return 0;                                       \
                }                                                       \
                                                                        \
                if (!sd_json_variant_is_string(variant))                \
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(n)); \
                                                                        \
                type cc = func(sd_json_variant_string(variant));        \
                if (cc < 0) {                                           \
                        /* Maybe this enum is recognizable if we replace "_" (i.e. Varlink syntax) with "-" (how we usually prefer it). */ \
                        _cleanup_free_ char *z = strdup(sd_json_variant_string(variant)); \
                        if (!z)                                         \
                                return json_log_oom(variant, flags);    \
                                                                        \
                        cc = func(json_dashify(z));                     \
                        if (cc < 0)                                     \
                                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Value of JSON field '%s' not recognized: %s", strna(n), sd_json_variant_string(variant)); \
                }                                                       \
                                                                        \
                *c = cc;                                                \
                return 0;                                               \
        }

static inline int json_dispatch_level(sd_json_dispatch_flags_t flags) {

        /* Did the user request no logging? If so, then never log higher than LOG_DEBUG. Also, if this is marked as
         * debug message, then also log at debug level. */

        if (!(flags & SD_JSON_LOG) ||
            (flags & SD_JSON_DEBUG))
                return LOG_DEBUG;

        /* Are we invoked in permissive mode, or is this explicitly marked as warning message? Then this should be
         * printed at LOG_WARNING */
        if (flags & (SD_JSON_PERMISSIVE|SD_JSON_WARNING))
                return LOG_WARNING;

        /* Otherwise it's an error. */
        return LOG_ERR;
}

int json_log_internal(sd_json_variant *variant, int level, int error, const char *file, int line, const char *func, const char *format, ...)  _printf_(7, 8);

#define json_log(variant, flags, error, ...)                            \
        ({                                                              \
                int _level = json_dispatch_level(flags), _e = (error);  \
                (log_get_max_level() >= LOG_PRI(_level))                \
                        ? json_log_internal(variant, _level, _e, PROJECT_FILE, __LINE__, __func__, __VA_ARGS__) \
                        : -ERRNO_VALUE(_e);                             \
        })

#define json_log_oom(variant, flags) \
        json_log(variant, flags, SYNTHETIC_ERRNO(ENOMEM), "Out of memory.")

int json_dispatch_unhex_iovec(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_unbase64_iovec(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_byte_array_iovec(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_user_group_name(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_const_user_group_name(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_const_unit_name(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_in_addr(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_path(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_const_path(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_strv_path(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_filename(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_const_filename(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_version(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_const_version(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_pidref(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_devnum(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_ifindex(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_log_level(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_strv_environment(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int json_dispatch_access_mode(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

static inline int json_variant_unbase64_iovec(sd_json_variant *v, struct iovec *ret) {
        return sd_json_variant_unbase64(v, ret ? &ret->iov_base : NULL, ret ? &ret->iov_len : NULL);
}

static inline int json_variant_unhex_iovec(sd_json_variant *v, struct iovec *ret) {
        return sd_json_variant_unhex(v, ret ? &ret->iov_base : NULL, ret ? &ret->iov_len : NULL);
}

#define JSON_VARIANT_STRING_CONST(x) _JSON_VARIANT_STRING_CONST(UNIQ, (x))

#define _JSON_VARIANT_STRING_CONST(xq, x)                               \
        ({                                                              \
                _align_(2) static const char UNIQ_T(json_string_const, xq)[] = (x); \
                assert((((uintptr_t) UNIQ_T(json_string_const, xq)) & 1) == 0); \
                (sd_json_variant*) ((uintptr_t) UNIQ_T(json_string_const, xq) + 1); \
        })

enum {
        /* This extends the _SD_JSON_BUILD_* enums we define in the public API with some additional values
         * that we want to keep private for now. (Mostly because the underlying structures are not public, or
         * because we aren't sure yet they are useful for others). */
        _JSON_BUILD_STRV_ENV_PAIR = _SD_JSON_BUILD_MAX,
        _JSON_BUILD_IOVEC_BASE64,
        _JSON_BUILD_IOVEC_HEX,
        _JSON_BUILD_HW_ADDR,
        _JSON_BUILD_STRING_SET,
        _JSON_BUILD_STRING_ORDERED_SET,
        _JSON_BUILD_STRING_UNDERSCORIFY,
        _JSON_BUILD_DUAL_TIMESTAMP,
        _JSON_BUILD_RATELIMIT,
        _JSON_BUILD_TRISTATE,
        _JSON_BUILD_PIDREF,
        _JSON_BUILD_DEVNUM,

        _JSON_BUILD_PAIR_INTEGER_NON_ZERO,
        _JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE,
        _JSON_BUILD_PAIR_UNSIGNED_NON_ZERO,
        _JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL,
        _JSON_BUILD_PAIR_FINITE_USEC,
        _JSON_BUILD_PAIR_STRING_NON_EMPTY,
        _JSON_BUILD_PAIR_STRV_NON_EMPTY,
        _JSON_BUILD_PAIR_STRV_ENV_PAIR_NON_EMPTY,
        _JSON_BUILD_PAIR_VARIANT_NON_NULL,
        _JSON_BUILD_PAIR_VARIANT_NON_EMPTY,
        /* _SD_JSON_BUILD_PAIR_VARIANT_ARRAY_NON_EMPTY, */
        _JSON_BUILD_PAIR_BYTE_ARRAY_NON_EMPTY,
        _JSON_BUILD_PAIR_IN_ADDR_NON_NULL,
        _JSON_BUILD_PAIR_IN_ADDR_WITH_STRING,
        _JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL,
        _JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL,
        _JSON_BUILD_PAIR_HW_ADDR_NON_NULL,
        _JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL,
        _JSON_BUILD_PAIR_RATELIMIT_ENABLED,
        _JSON_BUILD_PAIR_CALLBACK_NON_NULL,
        _JSON_BUILD_PAIR_BASE64_NON_EMPTY,
        _JSON_BUILD_PAIR_BASE32HEX_NON_EMPTY,
        _JSON_BUILD_PAIR_HEX_NON_EMPTY,
        _JSON_BUILD_PAIR_OCTESCAPE_NON_EMPTY,
        _JSON_BUILD_PAIR_TRISTATE_NON_NULL,
        _JSON_BUILD_PAIR_PIDREF_NON_NULL,
        _JSON_BUILD_PAIR_DEVNUM,

        _SD_JSON_BUILD_REALLYMAX,
};

#define JSON_BUILD_STRV_ENV_PAIR(l) _JSON_BUILD_STRV_ENV_PAIR, (char**) { l }
#define JSON_BUILD_IOVEC_BASE64(iov) _JSON_BUILD_IOVEC_BASE64, (const struct iovec*) { iov }
#define JSON_BUILD_IOVEC_HEX(iov) _JSON_BUILD_IOVEC_HEX, (const struct iovec*) { iov }
#define JSON_BUILD_CONST_STRING(s) _SD_JSON_BUILD_VARIANT, JSON_VARIANT_STRING_CONST(s)
#define JSON_BUILD_IN4_ADDR(v) SD_JSON_BUILD_BYTE_ARRAY((const struct in_addr*) { v }, sizeof(struct in_addr))
#define JSON_BUILD_IN6_ADDR(v) SD_JSON_BUILD_BYTE_ARRAY((const struct in6_addr*) { v }, sizeof(struct in6_addr))
#define JSON_BUILD_IN_ADDR(f, v) SD_JSON_BUILD_BYTE_ARRAY(((const union in_addr_union*) { v })->bytes, FAMILY_ADDRESS_SIZE_SAFE(f))
#define JSON_BUILD_ETHER_ADDR(v) SD_JSON_BUILD_BYTE_ARRAY(((const struct ether_addr*) { v })->ether_addr_octet, sizeof(struct ether_addr))
#define JSON_BUILD_HW_ADDR(v) _JSON_BUILD_HW_ADDR, (const struct hw_addr_data*) { v }
#define JSON_BUILD_STRING_SET(s) _JSON_BUILD_STRING_SET, (Set *) { s }
#define JSON_BUILD_STRING_ORDERED_SET(s) _JSON_BUILD_STRING_ORDERED_SET, (OrderedSet *) { s }
#define JSON_BUILD_STRING_UNDERSCORIFY(s) _JSON_BUILD_STRING_UNDERSCORIFY, (const char *) { s }
#define JSON_BUILD_DUAL_TIMESTAMP(t) _JSON_BUILD_DUAL_TIMESTAMP, (dual_timestamp*) { t }
#define JSON_BUILD_RATELIMIT(rl) _JSON_BUILD_RATELIMIT, (const RateLimit*) { rl }
#define JSON_BUILD_TRISTATE(i) _JSON_BUILD_TRISTATE, (int) { i }
#define JSON_BUILD_PIDREF(p) _JSON_BUILD_PIDREF, (const PidRef*) { p }
#define JSON_BUILD_DEVNUM(d) _JSON_BUILD_DEVNUM, (dev_t) { d }

#define JSON_BUILD_PAIR_INTEGER_NON_ZERO(name, i) _JSON_BUILD_PAIR_INTEGER_NON_ZERO, (const char*) { name }, (int64_t) { i }
#define JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE(name, i) _JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE, (const char*) { name }, (int64_t) { i }
#define JSON_BUILD_PAIR_UNSIGNED_NON_ZERO(name, u) _JSON_BUILD_PAIR_UNSIGNED_NON_ZERO, (const char*) { name }, (uint64_t) { u }
#define JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL(name, u, eq) _JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL, (const char*) { name }, (uint64_t) { u }, (uint64_t) { eq }
#define JSON_BUILD_PAIR_FINITE_USEC(name, u) _JSON_BUILD_PAIR_FINITE_USEC, (const char*) { name }, (usec_t) { u }
#define JSON_BUILD_PAIR_STRING_NON_EMPTY(name, s) _JSON_BUILD_PAIR_STRING_NON_EMPTY, (const char*) { name }, (const char*) { s }
#define JSON_BUILD_PAIR_STRV_NON_EMPTY(name, l) _JSON_BUILD_PAIR_STRV_NON_EMPTY, (const char*) { name }, (char**) { l }
#define JSON_BUILD_PAIR_STRV_ENV_PAIR_NON_EMPTY(name, l) _JSON_BUILD_PAIR_STRV_ENV_PAIR_NON_EMPTY, (const char*) { name }, (char**) { l }
#define JSON_BUILD_PAIR_VARIANT_NON_NULL(name, v) _JSON_BUILD_PAIR_VARIANT_NON_NULL, (const char*) { name }, (sd_json_variant*) { v }
#define JSON_BUILD_PAIR_VARIANT_NON_EMPTY(name, v) _JSON_BUILD_PAIR_VARIANT_NON_EMPTY, (const char*) { name }, (sd_json_variant*) { v }
#define JSON_BUILD_PAIR_BYTE_ARRAY_NON_EMPTY(name, v, n) _JSON_BUILD_PAIR_BYTE_ARRAY_NON_EMPTY, (const char*) { name }, (const void*) { v }, (size_t) { n }
#define JSON_BUILD_PAIR_IN_ADDR_NON_NULL(name, f, v) _JSON_BUILD_PAIR_IN_ADDR_NON_NULL, (const char*) { name }, (int) { f }, (const union in_addr_union*) { v }
#define JSON_BUILD_PAIR_IN4_ADDR_NON_NULL(name, v) _JSON_BUILD_PAIR_IN_ADDR_NON_NULL, (const char*) { name }, AF_INET, &(union in_addr_union) { .in = *(v) }
#define JSON_BUILD_PAIR_IN6_ADDR_NON_NULL(name, v) _JSON_BUILD_PAIR_IN_ADDR_NON_NULL, (const char*) { name }, AF_INET6, &(union in_addr_union) { .in6 = *(v) }
#define JSON_BUILD_PAIR_IN_ADDR_WITH_STRING(name, f, v) _JSON_BUILD_PAIR_IN_ADDR_WITH_STRING, (const char*) { name }, (int) { f }, (const union in_addr_union*) { v }
#define JSON_BUILD_PAIR_IN4_ADDR_WITH_STRING(name, v) _JSON_BUILD_PAIR_IN_ADDR_WITH_STRING, (const char*) { name }, AF_INET, &(union in_addr_union) { .in = *(v) }
#define JSON_BUILD_PAIR_IN6_ADDR_WITH_STRING(name, v) _JSON_BUILD_PAIR_IN_ADDR_WITH_STRING, (const char*) { name }, AF_INET6, &(union in_addr_union) { .in6 = *(v) }
#define JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL(name, f, v) _JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL, (const char*) { name }, (int) { f }, (const union in_addr_union*) { v }
#define JSON_BUILD_PAIR_IN4_ADDR_WITH_STRING_NON_NULL(name, v) _JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL, (const char*) { name }, AF_INET, &(union in_addr_union) { .in = *(v) }
#define JSON_BUILD_PAIR_IN6_ADDR_WITH_STRING_NON_NULL(name, v) _JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL, (const char*) { name }, AF_INET6, &(union in_addr_union) { .in6 = *(v) }
#define JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL(name, v) _JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL, (const char*) { name }, (const struct ether_addr*) { v }
#define JSON_BUILD_PAIR_HW_ADDR_NON_NULL(name, v) _JSON_BUILD_PAIR_HW_ADDR_NON_NULL, (const char*) { name }, (const struct hw_addr_data*) { v }
#define JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL(name, t) _JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL, (const char*) { name }, (dual_timestamp*) { t }
#define JSON_BUILD_PAIR_RATELIMIT_ENABLED(name, rl) _JSON_BUILD_PAIR_RATELIMIT_ENABLED, (const char*) { name }, (const RateLimit*) { rl }
#define JSON_BUILD_PAIR_CALLBACK_NON_NULL(name, c, u) _JSON_BUILD_PAIR_CALLBACK_NON_NULL, (const char*) { name }, (sd_json_build_callback_t) { c }, (void*) { u }
#define JSON_BUILD_PAIR_BASE64_NON_EMPTY(name, v, n) _JSON_BUILD_PAIR_BASE64_NON_EMPTY, (const char*) { name }, (const void*) { v }, (size_t) { n }
#define JSON_BUILD_PAIR_BASE32HEX_NON_EMPTY(name, v, n) _JSON_BUILD_PAIR_BASE32HEX_NON_EMPTY, (const char*) { name }, (const void*) { v }, (size_t) { n }
#define JSON_BUILD_PAIR_HEX_NON_EMPTY(name, v, n) _JSON_BUILD_PAIR_HEX_NON_EMPTY, (const char*) { name }, (const void*) { v }, (size_t) { n }
#define JSON_BUILD_PAIR_OCTESCAPE_NON_EMPTY(name, v, n) _JSON_BUILD_PAIR_HEX_NON_EMPTY, (const char*) { name }, (const void*) { v }, (size_t) { n }
#define JSON_BUILD_PAIR_TRISTATE_NON_NULL(name, i) _JSON_BUILD_PAIR_TRISTATE_NON_NULL, (const char*) { name }, (int) { i }
#define JSON_BUILD_PAIR_PIDREF_NON_NULL(name, p) _JSON_BUILD_PAIR_PIDREF_NON_NULL, (const char*) { name }, (const PidRef*) { p }

#define JSON_BUILD_PAIR_IOVEC_BASE64(name, iov) SD_JSON_BUILD_PAIR(name, JSON_BUILD_IOVEC_BASE64(iov))
#define JSON_BUILD_PAIR_IOVEC_HEX(name, iov) SD_JSON_BUILD_PAIR(name, JSON_BUILD_IOVEC_HEX(iov))
#define JSON_BUILD_PAIR_IN4_ADDR(name, v) SD_JSON_BUILD_PAIR(name, JSON_BUILD_IN4_ADDR(v))
#define JSON_BUILD_PAIR_IN6_ADDR(name, v) SD_JSON_BUILD_PAIR(name, JSON_BUILD_IN6_ADDR(v))
#define JSON_BUILD_PAIR_IN_ADDR(name, f, v) SD_JSON_BUILD_PAIR(name, JSON_BUILD_IN_ADDR(f, v))
#define JSON_BUILD_PAIR_ETHER_ADDR(name, v) SD_JSON_BUILD_PAIR(name, JSON_BUILD_ETHER_ADDR(v))
#define JSON_BUILD_PAIR_HW_ADDR(name, v) SD_JSON_BUILD_PAIR(name, JSON_BUILD_HW_ADDR(v))
#define JSON_BUILD_PAIR_STRING_SET(name, s) SD_JSON_BUILD_PAIR(name, JSON_BUILD_STRING_SET(s))
#define JSON_BUILD_PAIR_STRING_ORDERED_SET(name, s) SD_JSON_BUILD_PAIR(name, JSON_BUILD_STRING_ORDERED_SET(s))
#define JSON_BUILD_PAIR_DUAL_TIMESTAMP(name, t) SD_JSON_BUILD_PAIR(name, JSON_BUILD_DUAL_TIMESTAMP(t))
#define JSON_BUILD_PAIR_RATELIMIT(name, rl) SD_JSON_BUILD_PAIR(name, JSON_BUILD_RATELIMIT(rl))
#define JSON_BUILD_PAIR_TRISTATE(name, i) SD_JSON_BUILD_PAIR(name, JSON_BUILD_TRISTATE(i))
#define JSON_BUILD_PAIR_PIDREF(name, p) SD_JSON_BUILD_PAIR(name, JSON_BUILD_PIDREF(p))
#define JSON_BUILD_PAIR_DEVNUM(name, d) SD_JSON_BUILD_PAIR(name, JSON_BUILD_DEVNUM(d))
#define JSON_BUILD_PAIR_YES_NO(name, b) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_STRING(yes_no(b)))

#define JSON_BUILD_PAIR_CONDITION_UNSIGNED(condition, name, value) \
        SD_JSON_BUILD_PAIR_CONDITION(condition, name, SD_JSON_BUILD_UNSIGNED(value))
#define JSON_BUILD_PAIR_CONDITION_BOOLEAN(condition, name, value) \
        SD_JSON_BUILD_PAIR_CONDITION(condition, name, SD_JSON_BUILD_BOOLEAN(value))

int json_variant_new_pidref(sd_json_variant **ret, PidRef *pidref);
int json_variant_new_devnum(sd_json_variant **ret, dev_t devnum);
int json_variant_new_fd_info(sd_json_variant **ret, int fd);

char *json_underscorify(char *p);
char *json_dashify(char *p);
