/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include "json.h"
#include "macro.h"

typedef enum VarlinkSymbolType {
        VARLINK_ENUM_TYPE,
        VARLINK_STRUCT_TYPE,
        VARLINK_METHOD,
        VARLINK_ERROR,
        _VARLINK_SYMBOL_TYPE_MAX,
        _VARLINK_SYMBOL_TYPE_INVALID = -EINVAL,
} VarlinkSymbolType;

typedef enum VarlinkFieldType {
        _VARLINK_FIELD_TYPE_END_MARKER = 0,
        VARLINK_STRUCT,
        VARLINK_ENUM,
        VARLINK_NAMED_TYPE,
        VARLINK_BOOL,
        VARLINK_INT,
        VARLINK_FLOAT,
        VARLINK_STRING,
        VARLINK_OBJECT,
        VARLINK_ENUM_VALUE,
        _VARLINK_FIELD_TYPE_MAX,
        _VARLINK_FIELD_TYPE_INVALID = -EINVAL,
} VarlinkFieldType;

typedef enum VarlinkFieldFlags {
        VARLINK_ARRAY                = 1 << 0,
        VARLINK_MAP                  = 1 << 1,
        VARLINK_NULLABLE             = 1 << 2,
        _VARLINK_FIELD_FLAGS_MAX     = (1 << 3) - 1,
        _VARLINK_FIELD_FLAGS_INVALID = -EINVAL,
} VarlinkFieldFlags;

typedef struct VarlinkField VarlinkField;
typedef struct VarlinkSymbol VarlinkSymbol;
typedef struct VarlinkInterface VarlinkInterface;

/* Fields are the components making up symbols */
struct VarlinkField {
        const char *name;
        VarlinkFieldType field_type;
        VarlinkFieldFlags field_flags;
        int direction;                /* in case of method call fields: calls < 0 input, > 0 output */
        const VarlinkSymbol *symbol;  /* VARLINK_STRUCT, VARLINK_ENUM: anonymous symbol that carries the definitions, VARLINK_NAMED_TYPE: resolved symbol */
        const char *named_type;       /* VARLINK_NAMED_TYPE */
};

/* Symbols are primary named concepts in an interface, and are methods, errors or named types (either enum or struct). */
struct VarlinkSymbol {
        const char *name; /* most symbols have a name, but sometimes they are created on-the-fly for fields, in which case they are anonymous */
        VarlinkSymbolType symbol_type;
        VarlinkField fields[];
};

/* An interface definition has a name and consist of symbols */
struct VarlinkInterface {
        const char *name;
        const VarlinkSymbol *symbols[];
};

#define VARLINK_DEFINE_FIELD(_name, _field_type, _field_flags)        \
        { .name = #_name, .field_type = (_field_type), .field_flags = (_field_flags) }

#define VARLINK_DEFINE_FIELD_BY_TYPE(_name, _named_type, _field_flags) \
        { .name = #_name, .field_type = VARLINK_NAMED_TYPE, .named_type = #_named_type, .symbol = &vl_type_ ## _named_type, .field_flags = (_field_flags) }

#define VARLINK_DEFINE_INPUT(_name, _field_type, _field_flags)        \
        { .name = #_name, .field_type = (_field_type), .field_flags = (_field_flags), .direction = -1 }

#define VARLINK_DEFINE_INPUT_BY_TYPE(_name, _named_type, _field_flags) \
        { .name = #_name, .field_type = VARLINK_NAMED_TYPE, .named_type = #_named_type, .symbol = &vl_type_ ## _named_type, .field_flags = (_field_flags), .direction = -1 }

#define VARLINK_DEFINE_OUTPUT(_name, _field_type, _field_flags)        \
        { .name = #_name, .field_type = (_field_type), .field_flags = (_field_flags), .direction = 1 }

#define VARLINK_DEFINE_OUTPUT_BY_TYPE(_name, _named_type, _field_flags) \
        { .name = #_name, .field_type = VARLINK_NAMED_TYPE, .named_type = #_named_type, .symbol = &vl_type_ ## _named_type, .field_flags = (_field_flags), .direction = 1 }

#define VARLINK_DEFINE_ENUM_VALUE(_name) \
        { .name = #_name, .field_type = VARLINK_ENUM_VALUE }

#define VARLINK_DEFINE_METHOD(_name, ...)                               \
        const VarlinkSymbol vl_method_ ## _name = {                     \
                .name = #_name,                                         \
                .symbol_type = VARLINK_METHOD,                          \
                .fields = { __VA_ARGS__ __VA_OPT__(,) {}},              \
        }

#define VARLINK_DEFINE_ERROR(_name, ...)                                \
        const VarlinkSymbol vl_error_ ## _name = {                      \
                .name = #_name,                                         \
                .symbol_type = VARLINK_ERROR,                           \
                .fields = { __VA_ARGS__ __VA_OPT__(,) {}},              \
        }

#define VARLINK_DEFINE_STRUCT_TYPE(_name, ...)                          \
        const VarlinkSymbol vl_type_ ## _name = {                       \
                .name = #_name,                                         \
                .symbol_type = VARLINK_STRUCT_TYPE,                     \
                .fields = { __VA_ARGS__ __VA_OPT__(,) {}},              \
        }

#define VARLINK_DEFINE_ENUM_TYPE(_name, ...)                            \
        const VarlinkSymbol vl_type_ ## _name = {                       \
                .name = #_name,                                         \
                .symbol_type = VARLINK_ENUM_TYPE,                       \
                .fields = { __VA_ARGS__ __VA_OPT__(,) {}},              \
        }

#define VARLINK_DEFINE_INTERFACE(_name, _full_name, ...)                \
        const VarlinkInterface vl_interface_ ## _name = {               \
                .name = (_full_name),                                   \
                .symbols = { __VA_ARGS__ __VA_OPT__(,) NULL},           \
        }

int varlink_idl_dump(FILE *f, int use_colors, const VarlinkInterface *interface);
int varlink_idl_format(const VarlinkInterface *interface, char **ret);

int varlink_idl_parse(const char *text, unsigned *ret_line, unsigned *ret_column, VarlinkInterface **ret);
VarlinkInterface* varlink_interface_free(VarlinkInterface *interface);
DEFINE_TRIVIAL_CLEANUP_FUNC(VarlinkInterface*, varlink_interface_free);

bool varlink_idl_field_name_is_valid(const char *name);
bool varlink_idl_symbol_name_is_valid(const char *name);
bool varlink_idl_interface_name_is_valid(const char *name);

int varlink_idl_consistent(const VarlinkInterface *interface, bool level);

const VarlinkSymbol* varlink_idl_find_symbol(const VarlinkInterface *interface, VarlinkSymbolType type, const char *name);
const VarlinkField* varlink_idl_find_field(const VarlinkSymbol *symbol, const char *name);

int varlink_idl_validate_method_call(const VarlinkSymbol *method, JsonVariant *v, const char **bad_field);
int varlink_idl_validate_method_reply(const VarlinkSymbol *method, JsonVariant *v, const char **bad_field);
int varlink_idl_validate_error(const VarlinkSymbol *error, JsonVariant *v, const char **bad_field);
