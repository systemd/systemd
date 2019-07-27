/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include "json.h"

/* This header should include all prototypes only the JSON parser itself and
 * its tests need access to. Normal code consuming the JSON parser should not
 * interface with this. */

typedef union JsonValue  {
        /* Encodes a simple value. On x86-64 this structure is 16 bytes wide (as long double is 128bit). */
        bool boolean;
        long double real;
        intmax_t integer;
        uintmax_t unsig;
} JsonValue;

/* Let's protect us against accidental structure size changes on our most relevant arch */
#ifdef __x86_64__
assert_cc(sizeof(JsonValue) == 16U);
#endif

#define JSON_VALUE_NULL ((JsonValue) {})

/* We use fake JsonVariant objects for some special values, in order to avoid memory allocations for them. Note that
 * effectively this means that there are multiple ways to encode the same objects: via these magic values or as
 * properly allocated JsonVariant. We convert between both on-the-fly as necessary. */
#define JSON_VARIANT_MAGIC_TRUE ((JsonVariant*) 1)
#define JSON_VARIANT_MAGIC_FALSE ((JsonVariant*) 2)
#define JSON_VARIANT_MAGIC_NULL ((JsonVariant*) 3)
#define JSON_VARIANT_MAGIC_ZERO_INTEGER ((JsonVariant*) 4)
#define JSON_VARIANT_MAGIC_ZERO_UNSIGNED ((JsonVariant*) 5)
#define JSON_VARIANT_MAGIC_ZERO_REAL ((JsonVariant*) 6)
#define JSON_VARIANT_MAGIC_EMPTY_STRING ((JsonVariant*) 7)
#define JSON_VARIANT_MAGIC_EMPTY_ARRAY ((JsonVariant*) 8)
#define JSON_VARIANT_MAGIC_EMPTY_OBJECT ((JsonVariant*) 9)
#define _JSON_VARIANT_MAGIC_MAX ((JsonVariant*) 10)

/* This is only safe as long as we don't define more than 4K magic pointers, i.e. the page size of the simplest
 * architectures we support. That's because we rely on the fact that malloc() will never allocate from the first memory
 * page, as it is a faulting page for catching NULL pointer dereferences. */
assert_cc((uintptr_t) _JSON_VARIANT_MAGIC_MAX < 4096U);

enum { /* JSON tokens */
        JSON_TOKEN_END,
        JSON_TOKEN_COLON,
        JSON_TOKEN_COMMA,
        JSON_TOKEN_OBJECT_OPEN,
        JSON_TOKEN_OBJECT_CLOSE,
        JSON_TOKEN_ARRAY_OPEN,
        JSON_TOKEN_ARRAY_CLOSE,
        JSON_TOKEN_STRING,
        JSON_TOKEN_REAL,
        JSON_TOKEN_INTEGER,
        JSON_TOKEN_UNSIGNED,
        JSON_TOKEN_BOOLEAN,
        JSON_TOKEN_NULL,
        _JSON_TOKEN_MAX,
        _JSON_TOKEN_INVALID = -1,
};

int json_tokenize(const char **p, char **ret_string, JsonValue *ret_value, unsigned *ret_line, unsigned *ret_column, void **state, unsigned *line, unsigned *column);
