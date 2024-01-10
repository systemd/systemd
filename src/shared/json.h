/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "sd-id128.h"

#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

/*
  In case you wonder why we have our own JSON implementation, here are a couple of reasons why this implementation has
  benefits over various other implementations:

  - We need support for 64-bit signed and unsigned integers, i.e. the full 64,5bit range of -9223372036854775808…18446744073709551615
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
  - Can't store integers outside of the -9223372036854775808…18446744073709551615 range (it will use 'double' for
    values outside this range, which is lossy)
  - Can't store negative zero (will be treated identical to positive zero, and not retained across serialization)
  - Can't store non-integer numbers that can't be stored in "double" losslessly
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
        _JSON_VARIANT_TYPE_INVALID = -EINVAL,
} JsonVariantType;

int json_variant_new_stringn(JsonVariant **ret, const char *s, size_t n);
int json_variant_new_base64(JsonVariant **ret, const void *p, size_t n);
int json_variant_new_base32hex(JsonVariant **ret, const void *p, size_t n);
int json_variant_new_hex(JsonVariant **ret, const void *p, size_t n);
int json_variant_new_octescape(JsonVariant **ret, const void *p, size_t n);
int json_variant_new_integer(JsonVariant **ret, int64_t i);
int json_variant_new_unsigned(JsonVariant **ret, uint64_t u);
int json_variant_new_real(JsonVariant **ret, double d);
int json_variant_new_boolean(JsonVariant **ret, bool b);
int json_variant_new_array(JsonVariant **ret, JsonVariant **array, size_t n);
int json_variant_new_array_bytes(JsonVariant **ret, const void *p, size_t n);
int json_variant_new_array_strv(JsonVariant **ret, char **l);
int json_variant_new_object(JsonVariant **ret, JsonVariant **array, size_t n);
int json_variant_new_null(JsonVariant **ret);
int json_variant_new_id128(JsonVariant **ret, sd_id128_t id);
int json_variant_new_uuid(JsonVariant **ret, sd_id128_t id);

static inline int json_variant_new_string(JsonVariant **ret, const char *s) {
        return json_variant_new_stringn(ret, s, SIZE_MAX);
}

JsonVariant *json_variant_ref(JsonVariant *v);
JsonVariant *json_variant_unref(JsonVariant *v);
void json_variant_unref_many(JsonVariant **array, size_t n);

#define JSON_VARIANT_REPLACE(v, q)        \
        do {                              \
                typeof(v)* _v = &(v);     \
                typeof(q) _q = (q);       \
                json_variant_unref(*_v);  \
                *_v = _q;                 \
        } while(0)

DEFINE_TRIVIAL_CLEANUP_FUNC(JsonVariant *, json_variant_unref);

const char *json_variant_string(JsonVariant *v);
int64_t json_variant_integer(JsonVariant *v);
uint64_t json_variant_unsigned(JsonVariant *v);
double json_variant_real(JsonVariant *v);
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
bool json_variant_is_blank_object(JsonVariant *v);
bool json_variant_is_blank_array(JsonVariant *v);
bool json_variant_is_normalized(JsonVariant *v);
bool json_variant_is_sorted(JsonVariant *v);

size_t json_variant_elements(JsonVariant *v);
JsonVariant *json_variant_by_index(JsonVariant *v, size_t index);
JsonVariant *json_variant_by_key(JsonVariant *v, const char *key);
JsonVariant *json_variant_by_key_full(JsonVariant *v, const char *key, JsonVariant **ret_key);

bool json_variant_equal(JsonVariant *a, JsonVariant *b);

void json_variant_sensitive(JsonVariant *v);
bool json_variant_is_sensitive(JsonVariant *v);

struct json_variant_foreach_state {
        JsonVariant *variant;
        size_t idx;
};

#define _JSON_VARIANT_ARRAY_FOREACH(i, v, state)                        \
        for (struct json_variant_foreach_state state = { (v), 0 };      \
             json_variant_is_array(state.variant) &&                    \
                     state.idx < json_variant_elements(state.variant) && \
                     ({ i = json_variant_by_index(state.variant, state.idx); \
                             true; });                                  \
             state.idx++)
#define JSON_VARIANT_ARRAY_FOREACH(i, v)                                \
        _JSON_VARIANT_ARRAY_FOREACH(i, v, UNIQ_T(state, UNIQ))

#define _JSON_VARIANT_OBJECT_FOREACH(k, e, v, state)                    \
        for (struct json_variant_foreach_state state = { (v), 0 };      \
             json_variant_is_object(state.variant) &&                   \
                     state.idx < json_variant_elements(state.variant) && \
                     ({ k = json_variant_string(json_variant_by_index(state.variant, state.idx)); \
                             e = json_variant_by_index(state.variant, state.idx + 1); \
                             true; });                                  \
             state.idx += 2)
#define JSON_VARIANT_OBJECT_FOREACH(k, e, v)                            \
        _JSON_VARIANT_OBJECT_FOREACH(k, e, v, UNIQ_T(state, UNIQ))

int json_variant_get_source(JsonVariant *v, const char **ret_source, unsigned *ret_line, unsigned *ret_column);

typedef enum JsonFormatFlags {
        JSON_FORMAT_NEWLINE          = 1 << 0, /* suffix with newline */
        JSON_FORMAT_PRETTY           = 1 << 1, /* add internal whitespace to appeal to human readers */
        JSON_FORMAT_PRETTY_AUTO      = 1 << 2, /* same, but only if connected to a tty (and JSON_FORMAT_NEWLINE otherwise) */
        JSON_FORMAT_COLOR            = 1 << 3, /* insert ANSI color sequences */
        JSON_FORMAT_COLOR_AUTO       = 1 << 4, /* insert ANSI color sequences if colors_enabled() says so */
        JSON_FORMAT_SOURCE           = 1 << 5, /* prefix with source filename/line/column */
        JSON_FORMAT_SSE              = 1 << 6, /* prefix/suffix with W3C server-sent events */
        JSON_FORMAT_SEQ              = 1 << 7, /* prefix/suffix with RFC 7464 application/json-seq */
        JSON_FORMAT_FLUSH            = 1 << 8, /* call fflush() after dumping JSON */
        JSON_FORMAT_EMPTY_ARRAY      = 1 << 9, /* output "[]" for empty input */
        JSON_FORMAT_OFF              = 1 << 10, /* make json_variant_format() fail with -ENOEXEC */
        JSON_FORMAT_REFUSE_SENSITIVE = 1 << 11, /* return EPERM if any node in the tree is marked as senstitive */
} JsonFormatFlags;

int json_variant_format(JsonVariant *v, JsonFormatFlags flags, char **ret);
int json_variant_dump(JsonVariant *v, JsonFormatFlags flags, FILE *f, const char *prefix);

int json_variant_filter(JsonVariant **v, char **to_remove);

int json_variant_set_field(JsonVariant **v, const char *field, JsonVariant *value);
int json_variant_set_fieldb(JsonVariant **v, const char *field, ...);
int json_variant_set_field_string(JsonVariant **v, const char *field, const char *value);
int json_variant_set_field_integer(JsonVariant **v, const char *field, int64_t value);
int json_variant_set_field_unsigned(JsonVariant **v, const char *field, uint64_t value);
int json_variant_set_field_boolean(JsonVariant **v, const char *field, bool b);
int json_variant_set_field_strv(JsonVariant **v, const char *field, char **l);

static inline int json_variant_set_field_non_null(JsonVariant **v, const char *field, JsonVariant *value) {
        return value && !json_variant_is_null(value) ? json_variant_set_field(v, field, value) : 0;
}

JsonVariant *json_variant_find(JsonVariant *haystack, JsonVariant *needle);

int json_variant_append_array(JsonVariant **v, JsonVariant *element);
int json_variant_append_arrayb(JsonVariant **v, ...);
int json_variant_append_array_nodup(JsonVariant **v, JsonVariant *element);

int json_variant_merge_object(JsonVariant **v, JsonVariant *m);
int json_variant_merge_objectb(JsonVariant **v, ...);

int json_variant_strv(JsonVariant *v, char ***ret);

int json_variant_sort(JsonVariant **v);
int json_variant_normalize(JsonVariant **v);

typedef enum JsonParseFlags {
        JSON_PARSE_SENSITIVE = 1 << 0, /* mark variant as "sensitive", i.e. something containing secret key material or such */
} JsonParseFlags;

int json_parse_with_source(const char *string, const char *source, JsonParseFlags flags, JsonVariant **ret, unsigned *ret_line, unsigned *ret_column);
int json_parse_with_source_continue(const char **p, const char *source, JsonParseFlags flags, JsonVariant **ret, unsigned *ret_line, unsigned *ret_column);

static inline int json_parse(const char *string, JsonParseFlags flags, JsonVariant **ret, unsigned *ret_line, unsigned *ret_column) {
        return json_parse_with_source(string, NULL, flags, ret, ret_line, ret_column);
}
static inline int json_parse_continue(const char **p, JsonParseFlags flags, JsonVariant **ret, unsigned *ret_line, unsigned *ret_column) {
        return json_parse_with_source_continue(p, NULL, flags, ret, ret_line, ret_column);
}

int json_parse_file_at(FILE *f, int dir_fd, const char *path, JsonParseFlags flags, JsonVariant **ret, unsigned *ret_line, unsigned *ret_column);

static inline int json_parse_file(FILE *f, const char *path, JsonParseFlags flags, JsonVariant **ret, unsigned *ret_line, unsigned *ret_column) {
        return json_parse_file_at(f, AT_FDCWD, path, flags, ret, ret_line, ret_column);
}

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
        _JSON_BUILD_PAIR_CONDITION,
        _JSON_BUILD_NULL,
        _JSON_BUILD_VARIANT,
        _JSON_BUILD_VARIANT_ARRAY,
        _JSON_BUILD_LITERAL,
        _JSON_BUILD_STRV,
        _JSON_BUILD_STRV_ENV_PAIR,
        _JSON_BUILD_BASE64,
        _JSON_BUILD_IOVEC_BASE64,
        _JSON_BUILD_BASE32HEX,
        _JSON_BUILD_HEX,
        _JSON_BUILD_IOVEC_HEX,
        _JSON_BUILD_OCTESCAPE,
        _JSON_BUILD_ID128,
        _JSON_BUILD_UUID,
        _JSON_BUILD_BYTE_ARRAY,
        _JSON_BUILD_HW_ADDR,
        _JSON_BUILD_STRING_SET,
        _JSON_BUILD_CALLBACK,
        _JSON_BUILD_PAIR_UNSIGNED_NON_ZERO,
        _JSON_BUILD_PAIR_FINITE_USEC,
        _JSON_BUILD_PAIR_STRING_NON_EMPTY,
        _JSON_BUILD_PAIR_STRV_NON_EMPTY,
        _JSON_BUILD_PAIR_VARIANT_NON_NULL,
        _JSON_BUILD_PAIR_VARIANT_ARRAY_NON_EMPTY,
        _JSON_BUILD_PAIR_IN4_ADDR_NON_NULL,
        _JSON_BUILD_PAIR_IN6_ADDR_NON_NULL,
        _JSON_BUILD_PAIR_IN_ADDR_NON_NULL,
        _JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL,
        _JSON_BUILD_PAIR_HW_ADDR_NON_NULL,
        _JSON_BUILD_MAX,
};

typedef int (*JsonBuildCallback)(JsonVariant **ret, const char *name, void *userdata);

#define JSON_BUILD_STRING(s) _JSON_BUILD_STRING, (const char*) { s }
#define JSON_BUILD_INTEGER(i) _JSON_BUILD_INTEGER, (int64_t) { i }
#define JSON_BUILD_UNSIGNED(u) _JSON_BUILD_UNSIGNED, (uint64_t) { u }
#define JSON_BUILD_REAL(d) _JSON_BUILD_REAL, (double) { d }
#define JSON_BUILD_BOOLEAN(b) _JSON_BUILD_BOOLEAN, (bool) { b }
#define JSON_BUILD_ARRAY(...) _JSON_BUILD_ARRAY_BEGIN, __VA_ARGS__, _JSON_BUILD_ARRAY_END
#define JSON_BUILD_EMPTY_ARRAY _JSON_BUILD_ARRAY_BEGIN, _JSON_BUILD_ARRAY_END
#define JSON_BUILD_OBJECT(...) _JSON_BUILD_OBJECT_BEGIN, __VA_ARGS__, _JSON_BUILD_OBJECT_END
#define JSON_BUILD_EMPTY_OBJECT _JSON_BUILD_OBJECT_BEGIN, _JSON_BUILD_OBJECT_END
#define JSON_BUILD_PAIR(n, ...) _JSON_BUILD_PAIR, (const char*) { n }, __VA_ARGS__
#define JSON_BUILD_PAIR_CONDITION(c, n, ...) _JSON_BUILD_PAIR_CONDITION, (bool) { c }, (const char*) { n }, __VA_ARGS__
#define JSON_BUILD_NULL _JSON_BUILD_NULL
#define JSON_BUILD_VARIANT(v) _JSON_BUILD_VARIANT, (JsonVariant*) { v }
#define JSON_BUILD_VARIANT_ARRAY(v, n) _JSON_BUILD_VARIANT_ARRAY, (JsonVariant **) { v }, (size_t) { n }
#define JSON_BUILD_LITERAL(l) _JSON_BUILD_LITERAL, (const char*) { l }
#define JSON_BUILD_STRV(l) _JSON_BUILD_STRV, (char**) { l }
#define JSON_BUILD_STRV_ENV_PAIR(l) _JSON_BUILD_STRV_ENV_PAIR, (char**) { l }
#define JSON_BUILD_BASE64(p, n) _JSON_BUILD_BASE64, (const void*) { p }, (size_t) { n }
#define JSON_BUILD_IOVEC_BASE64(iov) _JSON_BUILD_IOVEC_BASE64, (const struct iovec*) { iov }
#define JSON_BUILD_BASE32HEX(p, n) _JSON_BUILD_BASE32HEX, (const void*) { p }, (size_t) { n }
#define JSON_BUILD_HEX(p, n) _JSON_BUILD_HEX, (const void*) { p }, (size_t) { n }
#define JSON_BUILD_IOVEC_HEX(iov) _JSON_BUILD_IOVEC_HEX, (const struct iovec*) { iov }
#define JSON_BUILD_OCTESCAPE(p, n) _JSON_BUILD_OCTESCAPE, (const void*) { p }, (size_t) { n }
#define JSON_BUILD_ID128(id) _JSON_BUILD_ID128, (const sd_id128_t*) { &(id) }
#define JSON_BUILD_UUID(id) _JSON_BUILD_UUID, (const sd_id128_t*) { &(id) }
#define JSON_BUILD_BYTE_ARRAY(v, n) _JSON_BUILD_BYTE_ARRAY, (const void*) { v }, (size_t) { n }
#define JSON_BUILD_CONST_STRING(s) _JSON_BUILD_VARIANT, JSON_VARIANT_STRING_CONST(s)
#define JSON_BUILD_IN4_ADDR(v) JSON_BUILD_BYTE_ARRAY((const struct in_addr*) { v }, sizeof(struct in_addr))
#define JSON_BUILD_IN6_ADDR(v) JSON_BUILD_BYTE_ARRAY((const struct in6_addr*) { v }, sizeof(struct in6_addr))
#define JSON_BUILD_IN_ADDR(v, f) JSON_BUILD_BYTE_ARRAY(((const union in_addr_union*) { v })->bytes, FAMILY_ADDRESS_SIZE_SAFE(f))
#define JSON_BUILD_ETHER_ADDR(v) JSON_BUILD_BYTE_ARRAY(((const struct ether_addr*) { v })->ether_addr_octet, sizeof(struct ether_addr))
#define JSON_BUILD_HW_ADDR(v) _JSON_BUILD_HW_ADDR, (const struct hw_addr_data*) { v }
#define JSON_BUILD_STRING_SET(s) _JSON_BUILD_STRING_SET, (Set *) { s }
#define JSON_BUILD_CALLBACK(c, u) _JSON_BUILD_CALLBACK, (JsonBuildCallback) { c }, (void*) { u }

#define JSON_BUILD_PAIR_STRING(name, s) JSON_BUILD_PAIR(name, JSON_BUILD_STRING(s))
#define JSON_BUILD_PAIR_INTEGER(name, i) JSON_BUILD_PAIR(name, JSON_BUILD_INTEGER(i))
#define JSON_BUILD_PAIR_UNSIGNED(name, u) JSON_BUILD_PAIR(name, JSON_BUILD_UNSIGNED(u))
#define JSON_BUILD_PAIR_REAL(name, d) JSON_BUILD_PAIR(name, JSON_BUILD_REAL(d))
#define JSON_BUILD_PAIR_BOOLEAN(name, b) JSON_BUILD_PAIR(name, JSON_BUILD_BOOLEAN(b))
#define JSON_BUILD_PAIR_ARRAY(name, ...) JSON_BUILD_PAIR(name, JSON_BUILD_ARRAY(__VA_ARGS__))
#define JSON_BUILD_PAIR_EMPTY_ARRAY(name) JSON_BUILD_PAIR(name, JSON_BUILD_EMPTY_ARRAY)
#define JSON_BUILD_PAIR_OBJECT(name, ...) JSON_BUILD_PAIR(name, JSON_BUILD_OBJECT(__VA_ARGS__))
#define JSON_BUILD_PAIR_EMPTY_OBJECT(name) JSON_BUILD_PAIR(name, JSON_BUILD_EMPTY_OBJECT)
#define JSON_BUILD_PAIR_NULL(name) JSON_BUILD_PAIR(name, JSON_BUILD_NULL)
#define JSON_BUILD_PAIR_VARIANT(name, v) JSON_BUILD_PAIR(name, JSON_BUILD_VARIANT(v))
#define JSON_BUILD_PAIR_VARIANT_ARRAY(name, v, n) JSON_BUILD_PAIR(name, JSON_BUILD_VARIANT_ARRAY(v, n))
#define JSON_BUILD_PAIR_LITERAL(name, l) JSON_BUILD_PAIR(name, JSON_BUILD_LITERAL(l))
#define JSON_BUILD_PAIR_STRV(name, l) JSON_BUILD_PAIR(name, JSON_BUILD_STRV(l))
#define JSON_BUILD_PAIR_BASE64(name, p, n) JSON_BUILD_PAIR(name, JSON_BUILD_BASE64(p, n))
#define JSON_BUILD_PAIR_IOVEC_BASE64(name, iov) JSON_BUILD_PAIR(name, JSON_BUILD_IOVEC_BASE64(iov))
#define JSON_BUILD_PAIR_HEX(name, p, n) JSON_BUILD_PAIR(name, JSON_BUILD_HEX(p, n))
#define JSON_BUILD_PAIR_IOVEC_HEX(name, iov) JSON_BUILD_PAIR(name, JSON_BUILD_IOVEC_HEX(iov))
#define JSON_BUILD_PAIR_ID128(name, id) JSON_BUILD_PAIR(name, JSON_BUILD_ID128(id))
#define JSON_BUILD_PAIR_UUID(name, id) JSON_BUILD_PAIR(name, JSON_BUILD_UUID(id))
#define JSON_BUILD_PAIR_BYTE_ARRAY(name, v, n) JSON_BUILD_PAIR(name, JSON_BUILD_BYTE_ARRAY(v, n))
#define JSON_BUILD_PAIR_IN4_ADDR(name, v) JSON_BUILD_PAIR(name, JSON_BUILD_IN4_ADDR(v))
#define JSON_BUILD_PAIR_IN6_ADDR(name, v) JSON_BUILD_PAIR(name, JSON_BUILD_IN6_ADDR(v))
#define JSON_BUILD_PAIR_IN_ADDR(name, v, f) JSON_BUILD_PAIR(name, JSON_BUILD_IN_ADDR(v, f))
#define JSON_BUILD_PAIR_ETHER_ADDR(name, v) JSON_BUILD_PAIR(name, JSON_BUILD_ETHER_ADDR(v))
#define JSON_BUILD_PAIR_HW_ADDR(name, v) JSON_BUILD_PAIR(name, JSON_BUILD_HW_ADDR(v))
#define JSON_BUILD_PAIR_STRING_SET(name, s) JSON_BUILD_PAIR(name, JSON_BUILD_STRING_SET(s))
#define JSON_BUILD_PAIR_CALLBACK(name, c, u) JSON_BUILD_PAIR(name, JSON_BUILD_CALLBACK(c, u))

#define JSON_BUILD_PAIR_UNSIGNED_NON_ZERO(name, u) _JSON_BUILD_PAIR_UNSIGNED_NON_ZERO, (const char*) { name }, (uint64_t) { u }
#define JSON_BUILD_PAIR_FINITE_USEC(name, u) _JSON_BUILD_PAIR_FINITE_USEC, (const char*) { name }, (usec_t) { u }
#define JSON_BUILD_PAIR_STRING_NON_EMPTY(name, s) _JSON_BUILD_PAIR_STRING_NON_EMPTY, (const char*) { name }, (const char*) { s }
#define JSON_BUILD_PAIR_STRV_NON_EMPTY(name, l) _JSON_BUILD_PAIR_STRV_NON_EMPTY, (const char*) { name }, (char**) { l }
#define JSON_BUILD_PAIR_VARIANT_NON_NULL(name, v) _JSON_BUILD_PAIR_VARIANT_NON_NULL, (const char*) { name }, (JsonVariant*) { v }
#define JSON_BUILD_PAIR_IN4_ADDR_NON_NULL(name, v) _JSON_BUILD_PAIR_IN4_ADDR_NON_NULL, (const char*) { name }, (const struct in_addr*) { v }
#define JSON_BUILD_PAIR_IN6_ADDR_NON_NULL(name, v) _JSON_BUILD_PAIR_IN6_ADDR_NON_NULL, (const char*) { name }, (const struct in6_addr*) { v }
#define JSON_BUILD_PAIR_IN_ADDR_NON_NULL(name, v, f) _JSON_BUILD_PAIR_IN_ADDR_NON_NULL, (const char*) { name }, (const union in_addr_union*) { v }, (int) { f }
#define JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL(name, v) _JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL, (const char*) { name }, (const struct ether_addr*) { v }
#define JSON_BUILD_PAIR_HW_ADDR_NON_NULL(name, v) _JSON_BUILD_PAIR_HW_ADDR_NON_NULL, (const char*) { name }, (const struct hw_addr_data*) { v }

int json_build(JsonVariant **ret, ...);
int json_buildv(JsonVariant **ret, va_list ap);

/* A bitmask of flags used by the dispatch logic. Note that this is a combined bit mask, that is generated from the bit
 * mask originally passed into json_dispatch(), the individual bitmask associated with the static JsonDispatch callout
 * entry, as well the bitmask specified for json_log() calls */
typedef enum JsonDispatchFlags {
        /* The following three may be set in JsonDispatch's .flags field or the json_dispatch() flags parameter  */
        JSON_PERMISSIVE       = 1 << 0, /* Shall parsing errors be considered fatal for this field or object? */
        JSON_MANDATORY        = 1 << 1, /* Should existence of this property be mandatory? */
        JSON_LOG              = 1 << 2, /* Should the parser log about errors? */
        JSON_SAFE             = 1 << 3, /* Don't accept "unsafe" strings in json_dispatch_string() + json_dispatch_string() */
        JSON_RELAX            = 1 << 4, /* Use relaxed user name checking in json_dispatch_user_group_name */
        JSON_ALLOW_EXTENSIONS = 1 << 5, /* Subset of JSON_PERMISSIVE: allow additional fields, but no other permissive handling */

        /* The following two may be passed into log_json() in addition to those above */
        JSON_DEBUG            = 1 << 6, /* Indicates that this log message is a debug message */
        JSON_WARNING          = 1 << 7, /* Indicates that this log message is a warning message */
} JsonDispatchFlags;

typedef int (*JsonDispatchCallback)(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);

typedef struct JsonDispatch {
        const char *name;
        JsonVariantType type;
        JsonDispatchCallback callback;
        size_t offset;
        JsonDispatchFlags flags;
} JsonDispatch;

int json_dispatch_full(JsonVariant *v, const JsonDispatch table[], JsonDispatchCallback bad, JsonDispatchFlags flags, void *userdata, const char **reterr_bad_field);

static inline int json_dispatch(JsonVariant *v, const JsonDispatch table[], JsonDispatchFlags flags, void *userdata) {
        return json_dispatch_full(v, table, NULL, flags, userdata, NULL);
}

int json_dispatch_string(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_const_string(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_strv(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_boolean(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_tristate(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_variant(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_variant_noref(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_int64(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_uint64(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_uint32(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_int32(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_uint16(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_int16(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_uid_gid(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_user_group_name(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_id128(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_unsupported(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);
int json_dispatch_unbase64_iovec(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata);

assert_cc(sizeof(uint32_t) == sizeof(unsigned));
#define json_dispatch_uint json_dispatch_uint32

assert_cc(sizeof(int32_t) == sizeof(int));
#define json_dispatch_int json_dispatch_int32

#define JSON_DISPATCH_ENUM_DEFINE(name, type, func)                     \
        int name(const char *n, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) { \
                type *c = ASSERT_PTR(userdata);                         \
                                                                        \
                assert(variant);                                        \
                                                                        \
                if (json_variant_is_null(variant)) {                    \
                        *c = (type) -EINVAL;                            \
                        return 0;                                       \
                }                                                       \
                                                                        \
                if (!json_variant_is_string(variant))                   \
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(n)); \
                                                                        \
                type cc = func(json_variant_string(variant));           \
                if (cc < 0)                                             \
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Value of JSON field '%s' not recognized.", strna(n)); \
                                                                        \
                *c = cc;                                                \
                return 0;                                               \
        }

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

#define json_log(variant, flags, error, ...)                            \
        ({                                                              \
                int _level = json_dispatch_level(flags), _e = (error);  \
                (log_get_max_level() >= LOG_PRI(_level))                \
                        ? json_log_internal(variant, _level, _e, PROJECT_FILE, __LINE__, __func__, __VA_ARGS__) \
                        : -ERRNO_VALUE(_e);                             \
        })

#define json_log_oom(variant, flags) \
        json_log(variant, flags, SYNTHETIC_ERRNO(ENOMEM), "Out of memory.")

#define JSON_VARIANT_STRING_CONST(x) _JSON_VARIANT_STRING_CONST(UNIQ, (x))

#define _JSON_VARIANT_STRING_CONST(xq, x)                               \
        ({                                                              \
                _align_(2) static const char UNIQ_T(json_string_const, xq)[] = (x); \
                assert((((uintptr_t) UNIQ_T(json_string_const, xq)) & 1) == 0); \
                (JsonVariant*) ((uintptr_t) UNIQ_T(json_string_const, xq) + 1); \
        })

int json_variant_unbase64(JsonVariant *v, void **ret, size_t *ret_size);
int json_variant_unhex(JsonVariant *v, void **ret, size_t *ret_size);

static inline int json_variant_unbase64_iovec(JsonVariant *v, struct iovec *ret) {
        return json_variant_unbase64(v, ret ? &ret->iov_base : NULL, ret ? &ret->iov_len : NULL);
}

static inline int json_variant_unhex_iovec(JsonVariant *v, struct iovec *ret) {
        return json_variant_unhex(v, ret ? &ret->iov_base : NULL, ret ? &ret->iov_len : NULL);
}

const char *json_variant_type_to_string(JsonVariantType t);
JsonVariantType json_variant_type_from_string(const char *s);
