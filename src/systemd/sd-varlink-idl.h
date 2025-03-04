/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdvarlinkidlhfoo
#define foosdvarlinkidlhfoo

/***
  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <stdio.h>

#include "sd-json.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

/* This implements the Varlink Interface Definition Language ("Varlink IDL"),
 * i.e. https://varlink.org/Interface-Definition
 *
 * Primarily allows encoding static interface definitions in C code, that can be converted to the textual IDL
 * format on-the-fly. Can also parse the textual format back to C structures. Validates the interface
 * definitions for internal consistency and validates JSON objects against the interface definitions. */

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_varlink_interface_flags_t) {
        _SD_VARLINK_INTERFACE_FLAGS_MAX     = (1 << 0) - 1,
        _SD_VARLINK_INTERFACE_FLAGS_INVALID = -EINVAL,
        _SD_ENUM_FORCE_S64(SD_VARLINK_INTERFACE_FLAGS)
} sd_varlink_interface_flags_t;

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_varlink_symbol_type_t) {
        SD_VARLINK_ENUM_TYPE,
        SD_VARLINK_STRUCT_TYPE,
        SD_VARLINK_METHOD,
        SD_VARLINK_ERROR,
        _SD_VARLINK_INTERFACE_COMMENT,     /* Not really a symbol, just a comment about the interface */
        _SD_VARLINK_SYMBOL_COMMENT,        /* Not really a symbol, just a comment about a symbol */
        _SD_VARLINK_SYMBOL_TYPE_MAX,
        _SD_VARLINK_SYMBOL_TYPE_INVALID = -EINVAL,
        _SD_ENUM_FORCE_S64(SD_VARLINK_SYMBOL)
} sd_varlink_symbol_type_t;

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_varlink_symbol_flags_t) {
        SD_VARLINK_SUPPORTS_MORE         = 1 << 0, /* Call supports "more" flag */
        SD_VARLINK_REQUIRES_MORE         = 1 << 1, /* Call requires "more" flag */
        _SD_VARLINK_SYMBOL_FLAGS_MAX     = (1 << 2) - 1,
        _SD_VARLINK_SYMBOL_FLAGS_INVALID = -EINVAL,
        _SD_ENUM_FORCE_S64(SD_VARLINK_SYMBOL_FLAGS)
} sd_varlink_symbol_flags_t;

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_varlink_field_type_t) {
        _SD_VARLINK_FIELD_TYPE_END_MARKER = 0, /* zero type means: this is the last entry in the fields[] array of sd_varlink_symbol */
        SD_VARLINK_STRUCT,
        SD_VARLINK_ENUM,
        SD_VARLINK_NAMED_TYPE,
        SD_VARLINK_BOOL,
        SD_VARLINK_INT,
        SD_VARLINK_FLOAT,
        SD_VARLINK_STRING,
        SD_VARLINK_OBJECT,
        SD_VARLINK_ENUM_VALUE,
        _SD_VARLINK_FIELD_COMMENT,        /* Not really a field, just a comment about a field */
        _SD_VARLINK_FIELD_TYPE_MAX,
        _SD_VARLINK_FIELD_TYPE_INVALID = -EINVAL,
        _SD_ENUM_FORCE_S64(SD_VARLINK_FIELD)
} sd_varlink_field_type_t;

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_varlink_field_direction_t) {
        SD_VARLINK_REGULAR,
        SD_VARLINK_INPUT,
        SD_VARLINK_OUTPUT,
        _SD_VARLINK_FIELD_DIRECTION_MAX,
        _SD_VARLINK_FIELD_DIRECTION_INVALID = -EINVAL,
        _SD_ENUM_FORCE_S64(SD_VARLINK_FIELD_DIRECTION)
} sd_varlink_field_direction_t;

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_varlink_field_flags_t) {
        SD_VARLINK_ARRAY                = 1 << 0,
        SD_VARLINK_MAP                  = 1 << 1,
        SD_VARLINK_NULLABLE             = 1 << 2,
        _SD_VARLINK_FIELD_FLAGS_MAX     = (1 << 3) - 1,
        _SD_VARLINK_FIELD_FLAGS_INVALID = -EINVAL,
        _SD_ENUM_FORCE_S64(SD_VARLINK_FIELD_FLAGS)
} sd_varlink_field_flags_t;

typedef struct sd_varlink_field sd_varlink_field;
typedef struct sd_varlink_symbol sd_varlink_symbol;
typedef struct sd_varlink_interface sd_varlink_interface;

/* Fields are the components making up symbols */
struct sd_varlink_field {
        const char *name;
        sd_varlink_field_type_t field_type;
        sd_varlink_field_flags_t field_flags;
        sd_varlink_field_direction_t field_direction; /* in case of method call fields: whether input or output argument */
        const sd_varlink_symbol *symbol;              /* VARLINK_STRUCT, VARLINK_ENUM: anonymous symbol that carries the definitions, VARLINK_NAMED_TYPE: resolved symbol */
        const char *named_type;                       /* VARLINK_NAMED_TYPE */
};

/* Symbols are primary named concepts in an interface, and are methods, errors or named types (either enum or struct). */
struct sd_varlink_symbol {
        const char *name; /* most symbols have a name, but sometimes they are created on-the-fly for fields, in which case they are anonymous */
        sd_varlink_symbol_type_t symbol_type;
        sd_varlink_symbol_flags_t symbol_flags;
#if __STDC_VERSION__ >= 199901L
        sd_varlink_field fields[];
#else
        sd_varlink_field fields[1];
#endif
};

/* An interface definition has a name and consist of symbols */
struct sd_varlink_interface {
        const char *name;
        sd_varlink_interface_flags_t interface_flags;
#if __STDC_VERSION__ >= 199901L
        const sd_varlink_symbol *symbols[];
#else
        const sd_varlink_symbol *symbols[1];
#endif
};

#define SD_VARLINK_DEFINE_FIELD(_name, _field_type, _field_flags)          \
        { .name = #_name, .field_type = (_field_type), .field_flags = (_field_flags) }

#define SD_VARLINK_DEFINE_FIELD_BY_TYPE(_name, _named_type, _field_flags)  \
        { .name = #_name, .field_type = SD_VARLINK_NAMED_TYPE, .named_type = #_named_type, .symbol = &vl_type_ ## _named_type, .field_flags = (_field_flags) }

#define SD_VARLINK_DEFINE_INPUT(_name, _field_type, _field_flags)          \
        { .name = #_name, .field_type = (_field_type), .field_flags = (_field_flags), .field_direction = SD_VARLINK_INPUT }

#define SD_VARLINK_DEFINE_INPUT_BY_TYPE(_name, _named_type, _field_flags)  \
        { .name = #_name, .field_type = SD_VARLINK_NAMED_TYPE, .named_type = #_named_type, .symbol = &vl_type_ ## _named_type, .field_flags = (_field_flags), .field_direction = SD_VARLINK_INPUT }

#define SD_VARLINK_DEFINE_OUTPUT(_name, _field_type, _field_flags)         \
        { .name = #_name, .field_type = (_field_type), .field_flags = (_field_flags), .field_direction = SD_VARLINK_OUTPUT }

#define SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(_name, _named_type, _field_flags) \
        { .name = #_name, .field_type = SD_VARLINK_NAMED_TYPE, .named_type = #_named_type, .symbol = &vl_type_ ## _named_type, .field_flags = (_field_flags), .field_direction = SD_VARLINK_OUTPUT }

#define SD_VARLINK_DEFINE_ENUM_VALUE(_name)                             \
        { .name = #_name, .field_type = SD_VARLINK_ENUM_VALUE }

#define SD_VARLINK_FIELD_COMMENT(text)                                  \
        { .name = "" text, .field_type = _SD_VARLINK_FIELD_COMMENT }

/* C++ older than C20+ does not support __VA_OPT__(), but we really need it here. */
#if (defined(__STDC_VERSION__) && ((__STDC_VERSION__ >= 202311L) || defined(_GNU_SOURCE))) || (defined(__cplusplus) && (__cplusplus >= 202002L))
#define SD_VARLINK_DEFINE_METHOD(_name, ...)                            \
        const sd_varlink_symbol vl_method_ ## _name = {                 \
                .name = #_name,                                         \
                .symbol_type = SD_VARLINK_METHOD,                       \
                .fields = { __VA_ARGS__ __VA_OPT__(,) {}},              \
        }

#define SD_VARLINK_DEFINE_METHOD_FULL(_name, _flags, ...)               \
        const sd_varlink_symbol vl_method_ ## _name = {                 \
                .name = #_name,                                         \
                .symbol_type = SD_VARLINK_METHOD,                       \
                .symbol_flags = _flags,                                 \
                .fields = { __VA_ARGS__ __VA_OPT__(,) {}},              \
        }

#define SD_VARLINK_DEFINE_ERROR(_name, ...)                             \
        const sd_varlink_symbol vl_error_ ## _name = {                  \
                .name = #_name,                                         \
                .symbol_type = SD_VARLINK_ERROR,                        \
                .fields = { __VA_ARGS__ __VA_OPT__(,) {}},              \
        }

#define SD_VARLINK_DEFINE_STRUCT_TYPE(_name, ...)                       \
        const sd_varlink_symbol vl_type_ ## _name = {                   \
                .name = #_name,                                         \
                .symbol_type = SD_VARLINK_STRUCT_TYPE,                  \
                .fields = { __VA_ARGS__ __VA_OPT__(,) {}},              \
        }

#define SD_VARLINK_DEFINE_ENUM_TYPE(_name, ...)                         \
        const sd_varlink_symbol vl_type_ ## _name = {                   \
                .name = #_name,                                         \
                .symbol_type = SD_VARLINK_ENUM_TYPE,                    \
                .fields = { __VA_ARGS__ __VA_OPT__(,) {}},              \
        }

#define SD_VARLINK_DEFINE_INTERFACE(_name, _full_name, ...)             \
        const sd_varlink_interface vl_interface_ ## _name = {           \
                .name = (_full_name),                                   \
                .symbols = { __VA_ARGS__ __VA_OPT__(,) NULL},           \
        }
#endif

#define SD_VARLINK_SYMBOL_COMMENT(text)                                 \
        &(const sd_varlink_symbol) {                                    \
                .name = "" text,                                        \
                .symbol_type = _SD_VARLINK_SYMBOL_COMMENT,              \
        }

#define SD_VARLINK_INTERFACE_COMMENT(text)                              \
        &(const sd_varlink_symbol) {                                    \
                .name = "" text,                                        \
                .symbol_type = _SD_VARLINK_INTERFACE_COMMENT,           \
        }

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_varlink_idl_format_flags_t) {
        SD_VARLINK_IDL_FORMAT_COLOR      = 1 << 0,
        SD_VARLINK_IDL_FORMAT_COLOR_AUTO = 1 << 1,
        _SD_ENUM_FORCE_S64(SD_VARLINK_IDL_FORMAT)
} sd_varlink_idl_format_flags_t;

int sd_varlink_idl_dump(FILE *f, const sd_varlink_interface *interface, sd_varlink_idl_format_flags_t flags, size_t cols);
int sd_varlink_idl_format_full(const sd_varlink_interface *interface, sd_varlink_idl_format_flags_t flags, size_t cols, char **ret);
int sd_varlink_idl_format(const sd_varlink_interface *interface, char **ret);

_SD_END_DECLARATIONS;

#endif
