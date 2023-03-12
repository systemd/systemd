/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"

typedef struct {
        const char *filename;
        uint32_t line;
        uint32_t column;
} SourceLocation;

/* Note that all ubsan handlers have a pointer to a type-specific struct passed as first argument.
 * Since we do not inspect the extra data in it we can just treat it as a SourceLocation struct
 * directly to keep things simple. */

#define HANDLER(name, ...)                                         \
        _used_ _noreturn_ void __ubsan_handle_##name(__VA_ARGS__); \
        void __ubsan_handle_##name(__VA_ARGS__) {                  \
                log_error("systemd-boot: %s in %s@%u:%u",          \
                          __func__,                                \
                          location->filename,                      \
                          location->line,                          \
                          location->column);                       \
                freeze();                                          \
        }

#define UNARY_HANDLER(name) HANDLER(name, SourceLocation *location, uintptr_t v)
#define BINARY_HANDLER(name) HANDLER(name, SourceLocation *location, uintptr_t v1, uintptr_t v2)

UNARY_HANDLER(load_invalid_value);
UNARY_HANDLER(negate_overflow);
UNARY_HANDLER(out_of_bounds);
UNARY_HANDLER(type_mismatch_v1);
UNARY_HANDLER(vla_bound_not_positive);

BINARY_HANDLER(add_overflow);
BINARY_HANDLER(divrem_overflow);
BINARY_HANDLER(implicit_conversion);
BINARY_HANDLER(mul_overflow);
BINARY_HANDLER(pointer_overflow);
BINARY_HANDLER(shift_out_of_bounds);
BINARY_HANDLER(sub_overflow);

HANDLER(builtin_unreachable, SourceLocation *location);
HANDLER(invalid_builtin, SourceLocation *location);
HANDLER(nonnull_arg, SourceLocation *location);
HANDLER(nonnull_return_v1, SourceLocation *attr_location, SourceLocation *location);
