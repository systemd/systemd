/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "macro.h"
#include "string-util.h"
#include "util.h"

/*
  In case you wonder why we have our own JSON implementation, here are a couple of reasons why this implementation has
  benefits over various other implementatins:

  - We need support for 64bit signed and unsigned integers, i.e. the full 64,5bit range of -9223372036854775808…18446744073709551615
  - All our variants are immutable after creation
  - Special values such as true, false, zero, null, empty strings, empty array, empty objects require zero dynamic memory
  - Progressive parsing
  - Our integer/real type implicitly converts, but only if that's safe and loss-lessly possible
  - There's a "builder" for putting together objects easily in varargs function calls
  - There's a "dispatcher" for mapping objects to C data structures
  - Every variant optionally carries parsing location information, which simplifies debugging and parse log error generation
  - Formatter has color, line, column support

  Limitations:
  - Doesn't allow embedded NUL in strings
  - Can't store integers outside of the -9223372036854775808…18446744073709551615 range (it will use 'long double' for
    values outside this range, which is lossy)
  - Can't store negative zero (will be treated identical to positive zero, and not retained across serialization)
  - Can't store non-integer numbers that can't be stored in "long double" losslessly
  - Allows creation and parsing of objects with duplicate keys. The "dispatcher" will refuse them however. This means
    we can parse and pass around such objects, but will carefully refuse them when we convert them into our own data.

  (These limitations should be pretty much in line with those of other JSON implementations, in fact might be less
  limiting in most cases even.)
*/

typedef struct JsonVariant JsonVariant;

typedef enum JsonVariantType {
        JSON_VARIANT_STRING,
        JSON_VARIANT_INTEGER,
        JSON_VARIANT_UNSIGNED,
        JSON_VARIANT_REAL,
        JSON_VARIANT_NUMBER, /* This a pseudo-type: we can never create variants of this type, but we use it as wildcard check for the above three types */
        JSON_VARIANT_BOOLEAN,
        JSON_VARIANT_ARRAY,
        JSON_VARIANT_OBJECT,
        JSON_VARIANT_NULL,
        _JSON_VARIANT_TYPE_MAX,
        _JSON_VARIANT_TYPE_INVALID = -1
} JsonVariantType;

int json_variant_new_stringn(JsonVariant **ret, const char *s, size_t n);
int json_variant_new_integer(JsonVariant **ret, intmax_t i);
int json_variant_new_unsigned(JsonVariant **ret, uintmax_t u);
int json_variant_new_real(JsonVariant **ret, long double d);
int json_variant_new_boolean(JsonVariant **ret, bool b);
int json_variant_new_array(JsonVariant **ret, JsonVariant **array, size_t n);
int json_variant_new_array_bytes(JsonVariant **ret, const void *p, size_t n);
int json_variant_new_array_strv(JsonVariant **ret, char **l);
int json_variant_new_object(JsonVariant **ret, JsonVariant **array, size_t n);
int json_variant_new_null(JsonVariant **ret);

static inline int json_variant_new_string(JsonVariant **ret, const char *s) {
        return json_variant_new_stringn(ret, s, strlen_ptr(s));
}

JsonVariant *json_variant_ref(JsonVariant *v);
JsonVariant *json_variant_unref(JsonVariant *v);
void json_variant_unref_many(JsonVariant **array, size_t n);

DEFINE_TRIVIAL_CLEANUP_FUNC(JsonVariant *, json_variant_unref);

const char *json_variant_string(JsonVariant *v);
intmax_t json_variant_integer(JsonVariant *v);
uintmax_t json_variant_unsigned(JsonVariant *v);
long double json_variant_real(JsonVariant *v);
bool json_variant_boolean(JsonVariant *v);

JsonVariantType json_variant_type(JsonVariant *v);
bool json_variant_has_type(JsonVariant *v, JsonVariantType type);

static inline bool json_variant_is_string(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_STRING);
}

static inline bool json_variant_is_integer(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_INTEGER);
}

static inline bool json_variant_is_unsigned(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_UNSIGNED);
}

static inline bool json_variant_is_real(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_REAL);
}

static inline bool json_variant_is_number(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_NUMBER);
}

static inline bool json_variant_is_boolean(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_BOOLEAN);
}

static inline bool json_variant_is_array(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_ARRAY);
}

static inline bool json_variant_is_object(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_OBJECT);
}

static inline bool json_variant_is_null(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_NULL);
}

bool json_variant_is_negative(JsonVariant *v);

size_t json_variant_elements(JsonVariant *v);
JsonVariant *json_variant_by_index(JsonVariant *v, size_t index);
JsonVariant *json_variant_by_key(JsonVariant *v, const char *key);
JsonVariant *json_variant_by_key_full(JsonVariant *v, const char *key, JsonVariant **ret_key);

bool json_variant_equal(JsonVariant *a, JsonVariant *b);

struct json_variant_foreach_state {
        JsonVariant *variant;
        size_t idx;
};

#define JSON_VARIANT_ARRAY_FOREACH(i, v)                                \
        for (struct json_variant_foreach_state _state = { (v), 0 };     \
             _state.idx < json_variant_elements(_state.variant) &&      \
                     ({ i = json_variant_by_index(_state.variant, _state.idx); \
                             true; });                                  \
             _state.idx++)

#define JSON_VARIANT_OBJECT_FOREACH(k, e, v)                            \
        for (struct json_variant_foreach_state _state = { (v), 0 };     \
             _state.idx < json_variant_elements(_state.variant) &&      \
                     ({ k = json_variant_by_index(_state.variant, _state.idx); \
                             e = json_variant_by_index(_state.variant, _state.idx + 1); \
                             true; });                                  \
             _state.idx += 2)

int json_variant_get_source(JsonVariant *v, const char **ret_source, unsigned *ret_line, unsigned *ret_column);

enum {
        JSON_FORMAT_NEWLINE = 1 << 0, /* suffix with newline */
        JSON_FORMAT_PRETTY  = 1 << 1, /* add internal whitespace to appeal to human readers */
        JSON_FORMAT_COLOR   = 1 << 2, /* insert ANSI color sequences */
        JSON_FORMAT_SOURCE  = 1 << 3, /* prefix with source filename/line/column */
        JSON_FORMAT_SSE     = 1 << 4, /* prefix/suffix with W3C server-sent events */
        JSON_FORMAT_SEQ     = 1 << 5, /* prefix/suffix with RFC 7464 application/json-seq */
};

int json_variant_format(JsonVariant *v, unsigned flags, char **ret);
void json_variant_dump(JsonVariant *v, unsigned flags, FILE *f, const char *prefix);

int json_parse(const char *string, JsonVariant **ret, unsigned *ret_line, unsigned *ret_column);
int json_parse_continue(const char **p, JsonVariant **ret, unsigned *ret_line, unsigned *ret_column);
int json_parse_file(FILE *f, const char *path, JsonVariant **ret, unsigned *ret_line, unsigned *ret_column);

enum {
        _JSON_BUILD_STRING,
        _JSON_BUILD_INTEGER,
        _JSON_BUILD_UNSIGNED,
        _JSON_BUILD_REAL,
        _JSON_BUILD_BOOLEAN,
        _JSON_BUILD_ARRAY_BEGIN,
        _JSON_BUILD_ARRAY_END,
        _JSON_BUILD_OBJECT_BEGIN,
        _JSON_BUILD_OBJECT_END,
        _JSON_BUILD_PAIR,
        _JSON_BUILD_NULL,
        _JSON_BUILD_VARIANT,
        _JSON_BUILD_LITERAL,
        _JSON_BUILD_STRV,
        _JSON_BUILD_MAX,
};

#define JSON_BUILD_STRING(s) _JSON_BUILD_STRING, ({ const char *_x = s; _x; })
#define JSON_BUILD_INTEGER(i) _JSON_BUILD_INTEGER, ({ intmax_t _x = i; _x; })
#define JSON_BUILD_UNSIGNED(u) _JSON_BUILD_UNSIGNED, ({ uintmax_t _x = u; _x; })
#define JSON_BUILD_REAL(d) _JSON_BUILD_REAL, ({ long double _x = d; _x; })
#define JSON_BUILD_BOOLEAN(b) _JSON_BUILD_BOOLEAN, ({ bool _x = b; _x; })
#define JSON_BUILD_ARRAY(...) _JSON_BUILD_ARRAY_BEGIN, __VA_ARGS__, _JSON_BUILD_ARRAY_END
#define JSON_BUILD_OBJECT(...) _JSON_BUILD_OBJECT_BEGIN, __VA_ARGS__, _JSON_BUILD_OBJECT_END
#define JSON_BUILD_PAIR(n, ...) _JSON_BUILD_PAIR, ({ const char *_x = n; _x; }), __VA_ARGS__
#define JSON_BUILD_NULL _JSON_BUILD_NULL
#define JSON_BUILD_VARIANT(v) _JSON_BUILD_VARIANT, ({ JsonVariant *_x = v; _x; })
#define JSON_BUILD_LITERAL(l) _JSON_BUILD_LITERAL, ({ const char *_x = l; _x; })
#define JSON_BUILD_STRV(l) _JSON_BUILD_STRV, ({ char **_x = l; _x; })

int json_build(JsonVariant **ret, ...);
int json_buildv(JsonVariant **ret, va_list ap);

/* A bitmask of flags used by the dispatch logic. Note that this is a combined bit mask, that is generated from the bit
 * mask originally passed into json_dispatch(), the individual bitmask associated with the static JsonDispatch callout
 * entry, as well the bitmask specified for json_log() calls */
typedef enum JsonDispatchFlags {
        /* The following three may be set in JsonDispatch's .flags field or the json_dispatch() flags parameter  */
        JSON_PERMISSIVE = 1 << 0, /* Shall parsing errors be considered fatal for this property? */
        JSON_MANDATORY  = 1 << 1, /* Should existance of this property be mandatory? */
        JSON_LOG        = 1 << 2, /* Should the parser log about errors? */

        /* The following two may be passed into log_json() in addition to the three above */
        JSON_DEBUG      = 1 << 3, /* Indicates that this log message is a debug message */
        JSON_WARNING    = 1 << 4, /* Indicates that this log message is a warning message */
} JsonDispatchFlags;

typedef int (*JsonDispatchCallback)(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);

typedef struct JsonDispatch {
        const char *name;
        JsonVariantType type;
        JsonDispatchCallback callback;
        size_t offset;
        JsonDispatchFlags flags;
} JsonDispatch;

int json_dispatch(JsonVariant *v, const JsonDispatch table[], JsonDispatchCallback bad, JsonDispatchFlags flags, void *userdata);

int json_dispatch_string(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_strv(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_boolean(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_tristate(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_variant(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_integer(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_unsigned(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_uint32(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_int32(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);

assert_cc(sizeof(uintmax_t) == sizeof(uint64_t))
#define json_dispatch_uint64 json_dispatch_unsigned

assert_cc(sizeof(intmax_t) == sizeof(int64_t))
#define json_dispatch_int64 json_dispatch_integer

static inline int json_dispatch_level(JsonDispatchFlags flags) {

        /* Did the user request no logging? If so, then never log higher than LOG_DEBUG. Also, if this is marked as
         * debug message, then also log at debug level. */

        if (!(flags & JSON_LOG) ||
            (flags & JSON_DEBUG))
                return LOG_DEBUG;

        /* Are we invoked in permissive mode, or is this explicitly marked as warning message? Then this should be
         * printed at LOG_WARNING */
        if (flags & (JSON_PERMISSIVE|JSON_WARNING))
                return LOG_WARNING;

        /* Otherwise it's an error. */
        return LOG_ERR;
}

int json_log_internal(JsonVariant *variant, int level, int error, const char *file, int line, const char *func, const char *format, ...)  _printf_(7, 8);

#define json_log(variant, flags, error, ...)                       \
        ({                                                              \
                int _level = json_dispatch_level(flags), _e = (error);    \
                (log_get_max_level() >= LOG_PRI(_level))                \
                        ? json_log_internal(variant, _level, _e, __FILE__, __LINE__, __func__, __VA_ARGS__) \
                        : -abs(_e);                                     \
        })

#define JSON_VARIANT_STRING_CONST(x) _JSON_VARIANT_STRING_CONST(UNIQ, (x))

#define _JSON_VARIANT_STRING_CONST(xq, x)                                       \
        ({                                                              \
                __attribute__((aligned(2))) static const char UNIQ_T(json_string_const, xq)[] = (x); \
                assert((((uintptr_t) UNIQ_T(json_string_const, xq)) & 1) == 0); \
                (JsonVariant*) ((uintptr_t) UNIQ_T(json_string_const, xq) + 1); \
        })

const char *json_variant_type_to_string(JsonVariantType t);
JsonVariantType json_variant_type_from_string(const char *s);
