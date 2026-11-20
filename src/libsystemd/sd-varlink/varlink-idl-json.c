/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Renders interface definitions as JSON. The key set is documented in sd_varlink_idl_format(3). */

#include "sd-json.h"
#include "sd-varlink-idl.h"

#include "alloc-util.h"
#include "json-util.h"
#include "string-table.h"
#include "string-util.h"

/* The array order is the canonical order in which method flags are emitted. */
static const struct {
        sd_varlink_symbol_flags_t flag;
        const char *name;
} varlink_symbol_flags[] = {
        { SD_VARLINK_SUPPORTS_MORE,    "supports-more"    },
        { SD_VARLINK_REQUIRES_MORE,    "requires-more"    },
        { SD_VARLINK_SUPPORTS_UPGRADE, "supports-upgrade" },
        { SD_VARLINK_REQUIRES_UPGRADE, "requires-upgrade" },
};

static const char* const varlink_field_type_table[_SD_VARLINK_FIELD_TYPE_MAX] = {
        [SD_VARLINK_BOOL]   = "bool",
        [SD_VARLINK_INT]    = "int",
        [SD_VARLINK_FLOAT]  = "float",
        [SD_VARLINK_STRING] = "string",
        [SD_VARLINK_OBJECT] = "object",
        [SD_VARLINK_ANY]    = "any",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(varlink_field_type, sd_varlink_field_type_t);

static const char* const varlink_symbol_type_table[_SD_VARLINK_SYMBOL_TYPE_MAX] = {
        [SD_VARLINK_ENUM_TYPE]   = "type",
        [SD_VARLINK_STRUCT_TYPE] = "type",
        [SD_VARLINK_METHOD]      = "method",
        [SD_VARLINK_ERROR]       = "error",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(varlink_symbol_type, sd_varlink_symbol_type_t);

static int varlink_idl_json_fields(const sd_varlink_symbol *symbol, sd_json_variant **ret);

/* Comments in the C macros attach to the element that follows them. Multiple consecutive
 * comments are joined with newlines, mirroring how they end up rendered in the textual IDL. */
static int comment_append(char **pending, const char *comment) {
        assert(pending);
        assert(comment);

        return strextend_with_separator(pending, "\n", comment) ? 0 : -ENOMEM;
}

static int varlink_idl_json_enum_values(const sd_varlink_symbol *symbol, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL;
        _cleanup_free_ char *comment = NULL;
        int r;

        assert(symbol);
        assert(symbol->symbol_type == SD_VARLINK_ENUM_TYPE);
        assert(ret);

        for (const sd_varlink_field *field = symbol->fields; field->field_type != _SD_VARLINK_FIELD_TYPE_END_MARKER; field++) {

                if (field->field_type == _SD_VARLINK_FIELD_COMMENT) {
                        r = comment_append(&comment, field->name);
                        if (r < 0)
                                return r;
                        continue;
                }

                assert(field->field_type == SD_VARLINK_ENUM_VALUE);

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                r = sd_json_variant_merge_objectbo(&v,
                                                   SD_JSON_BUILD_PAIR_STRING("name", field->name),
                                                   JSON_BUILD_PAIR_CONDITION_BOOLEAN(
                                                                   FLAGS_SET(field->field_flags, SD_VARLINK_EXPERIMENTAL),
                                                                   "experimental",
                                                                   true),
                                                   JSON_BUILD_PAIR_STRING_NON_EMPTY("comment", comment));
                if (r < 0)
                        return r;

                comment = mfree(comment);

                r = sd_json_variant_append_array(&a, v);
                if (r < 0)
                        return r;
        }

        /* Return an (empty) array even for enums without values, so that consumers can rely
         * on "values" always being present for enum types. */
        if (!a) {
                r = sd_json_variant_new_array(&a, /* array= */ NULL, 0);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(a);
        return 0;
}

static int varlink_idl_json_one_field(const sd_varlink_field *field, const char *comment, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(field);
        assert(ret);

        r = sd_json_variant_merge_objectbo(&v,
                                           SD_JSON_BUILD_PAIR_STRING("name", field->name),
                                           JSON_BUILD_PAIR_CONDITION_BOOLEAN(
                                                           FLAGS_SET(field->field_flags, SD_VARLINK_EXPERIMENTAL),
                                                           "experimental",
                                                           true));
        if (r < 0)
                return r;

        switch (field->field_type) {

        case SD_VARLINK_BOOL:
        case SD_VARLINK_INT:
        case SD_VARLINK_FLOAT:
        case SD_VARLINK_STRING:
        case SD_VARLINK_OBJECT:
        case SD_VARLINK_ANY:
                r = sd_json_variant_set_field_string(&v, "type", varlink_field_type_to_string(field->field_type));
                break;

        case SD_VARLINK_NAMED_TYPE:
                r = sd_json_variant_set_field_string(&v, "namedType", field->named_type);
                break;

        case SD_VARLINK_STRUCT: {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;

                r = varlink_idl_json_fields(field->symbol, &fields);
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field(&v, "struct", fields);
                break;
        }

        case SD_VARLINK_ENUM: {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *values = NULL;

                r = varlink_idl_json_enum_values(field->symbol, &values);
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field(&v, "enum", values);
                break;
        }

        default:
                assert_not_reached();
        }
        if (r < 0)
                return r;

        r = sd_json_variant_merge_objectbo(&v,
                                           JSON_BUILD_PAIR_CONDITION_BOOLEAN(field->field_flags & SD_VARLINK_NULLABLE, "nullable", true),
                                           JSON_BUILD_PAIR_CONDITION_BOOLEAN(field->field_flags & SD_VARLINK_ARRAY, "array", true),
                                           JSON_BUILD_PAIR_CONDITION_BOOLEAN(field->field_flags & SD_VARLINK_MAP, "map", true),
                                           JSON_BUILD_PAIR_STRING_NON_EMPTY("comment", comment));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

/* Serializes all fields of a struct type or error symbol, ignoring field direction. */
static int varlink_idl_json_fields(const sd_varlink_symbol *symbol, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL;
        _cleanup_free_ char *comment = NULL;
        int r;

        assert(symbol);
        assert(ret);

        for (const sd_varlink_field *field = symbol->fields; field->field_type != _SD_VARLINK_FIELD_TYPE_END_MARKER; field++) {

                if (field->field_type == _SD_VARLINK_FIELD_COMMENT) {
                        r = comment_append(&comment, field->name);
                        if (r < 0)
                                return r;
                        continue;
                }

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                r = varlink_idl_json_one_field(field, comment, &v);
                if (r < 0)
                        return r;

                comment = mfree(comment);

                r = sd_json_variant_append_array(&a, v);
                if (r < 0)
                        return r;
        }

        /* "fields" is always present, also for structs and errors without fields. */
        if (!a) {
                r = sd_json_variant_new_array(&a, /* array= */ NULL, 0);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(a);
        return 0;
}

static int varlink_idl_json_method_fields(
                const sd_varlink_symbol *symbol,
                sd_json_variant **ret_input,
                sd_json_variant **ret_output) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *input = NULL, *output = NULL;
        _cleanup_free_ char *comment = NULL;
        int r;

        assert(symbol);
        assert(symbol->symbol_type == SD_VARLINK_METHOD);
        assert(ret_input);
        assert(ret_output);

        for (const sd_varlink_field *field = symbol->fields; field->field_type != _SD_VARLINK_FIELD_TYPE_END_MARKER; field++) {

                if (field->field_type == _SD_VARLINK_FIELD_COMMENT) {
                        r = comment_append(&comment, field->name);
                        if (r < 0)
                                return r;
                        continue;
                }

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                r = varlink_idl_json_one_field(field, comment, &v);
                if (r < 0)
                        return r;

                comment = mfree(comment);

                /* A comment precedes the field it belongs to, regardless of direction. */
                switch (field->field_direction) {
                case SD_VARLINK_INPUT:
                        r = sd_json_variant_append_array(&input, v);
                        break;

                case SD_VARLINK_OUTPUT:
                        r = sd_json_variant_append_array(&output, v);
                        break;

                default:
                        assert_not_reached();
                }
                if (r < 0)
                        return r;
        }

        /* Return empty arrays rather than NULL, so that "input" and "output" are always present. */
        if (!input) {
                r = sd_json_variant_new_array(&input, /* array= */ NULL, 0);
                if (r < 0)
                        return r;
        }

        if (!output) {
                r = sd_json_variant_new_array(&output, /* array= */ NULL, 0);
                if (r < 0)
                        return r;
        }

        *ret_input = TAKE_PTR(input);
        *ret_output = TAKE_PTR(output);
        return 0;
}

static int varlink_idl_json_symbol(const sd_varlink_symbol *symbol, const char *comment, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(symbol);
        assert(ret);

        r = sd_json_variant_merge_objectbo(&v,
                                           SD_JSON_BUILD_PAIR_STRING("kind", varlink_symbol_type_to_string(symbol->symbol_type)),
                                           SD_JSON_BUILD_PAIR_STRING("name", symbol->name),
                                           JSON_BUILD_PAIR_CONDITION_BOOLEAN(
                                                           FLAGS_SET(symbol->symbol_flags, SD_VARLINK_EXPERIMENTAL),
                                                           "experimental",
                                                           true),
                                           JSON_BUILD_PAIR_STRING_NON_EMPTY("comment", comment));
        if (r < 0)
                return r;

        if (symbol->symbol_type == SD_VARLINK_METHOD || symbol->symbol_type == SD_VARLINK_ERROR) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *flags = NULL;

                FOREACH_ELEMENT(f, varlink_symbol_flags) {
                        if (!FLAGS_SET(symbol->symbol_flags, f->flag))
                                continue;

                        r = sd_json_variant_append_arrayb(&flags, SD_JSON_BUILD_STRING(f->name));
                        if (r < 0)
                                return r;
                }

                if (flags) {
                        r = sd_json_variant_set_field(&v, "flags", flags);
                        if (r < 0)
                                return r;
                }
        }

        switch (symbol->symbol_type) {

        case SD_VARLINK_METHOD: {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *input = NULL, *output = NULL;

                r = varlink_idl_json_method_fields(symbol, &input, &output);
                if (r < 0)
                        return r;

                /* Empty methods are legal (e.g. pure notification-style calls). Both keys are
                 * always present, so that consumers can rely on the key set. */
                r = sd_json_variant_merge_objectbo(&v,
                                                   SD_JSON_BUILD_PAIR_VARIANT("input", input),
                                                   SD_JSON_BUILD_PAIR_VARIANT("output", output));
                if (r < 0)
                        return r;

                break;
        }

        case SD_VARLINK_ERROR: {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;

                r = varlink_idl_json_fields(symbol, &fields);
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field(&v, "fields", fields);
                if (r < 0)
                        return r;

                break;
        }

        case SD_VARLINK_STRUCT_TYPE: {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;

                r = varlink_idl_json_fields(symbol, &fields);
                if (r < 0)
                        return r;

                r = sd_json_variant_merge_objectbo(&v,
                                                   SD_JSON_BUILD_PAIR_STRING("typeKind", "struct"),
                                                   SD_JSON_BUILD_PAIR_VARIANT("fields", fields));
                if (r < 0)
                        return r;

                break;
        }

        case SD_VARLINK_ENUM_TYPE: {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *values = NULL;

                r = varlink_idl_json_enum_values(symbol, &values);
                if (r < 0)
                        return r;

                r = sd_json_variant_merge_objectbo(&v,
                                                   SD_JSON_BUILD_PAIR_STRING("typeKind", "enum"),
                                                   SD_JSON_BUILD_PAIR_VARIANT("values", values));
                if (r < 0)
                        return r;

                break;
        }

        default:
                assert_not_reached();
        }

        *ret = TAKE_PTR(v);
        return 0;
}

_public_ int sd_varlink_idl_format_json(const sd_varlink_interface *interface, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *symbols = NULL;
        _cleanup_free_ char *interface_comment = NULL, *symbol_comment = NULL;
        int r;

        assert_return(interface, -EINVAL);
        assert_return(ret, -EINVAL);

        for (const sd_varlink_symbol *const*symbol = interface->symbols; *symbol; symbol++) {

                if ((*symbol)->symbol_type == _SD_VARLINK_INTERFACE_COMMENT) {
                        r = comment_append(&interface_comment, (*symbol)->name);
                        if (r < 0)
                                return r;
                        continue;
                }

                if ((*symbol)->symbol_type == _SD_VARLINK_SYMBOL_COMMENT) {
                        r = comment_append(&symbol_comment, (*symbol)->name);
                        if (r < 0)
                                return r;
                        continue;
                }

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *s = NULL;
                r = varlink_idl_json_symbol(*symbol, symbol_comment, &s);
                if (r < 0)
                        return r;

                symbol_comment = mfree(symbol_comment);

                r = sd_json_variant_append_array(&symbols, s);
                if (r < 0)
                        return r;
        }

        /* The key set is fixed, so an interface without symbols still carries an empty array. */
        if (!symbols) {
                r = sd_json_variant_new_array(&symbols, /* array= */ NULL, 0);
                if (r < 0)
                        return r;
        }

        r = sd_json_variant_merge_objectbo(
                        &v,
                        SD_JSON_BUILD_PAIR_STRING("name", interface->name),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(
                                        FLAGS_SET(interface->interface_flags, SD_VARLINK_EXPERIMENTAL),
                                        "experimental",
                                        true),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("comment", interface_comment),
                        SD_JSON_BUILD_PAIR_VARIANT("symbols", symbols));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}
