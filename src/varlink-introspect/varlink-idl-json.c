/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink-idl.h"

#include "alloc-util.h"
#include "string-util.h"
#include "varlink-idl-json.h"

static const char* const varlink_field_type_table[_SD_VARLINK_FIELD_TYPE_MAX] = {
        [SD_VARLINK_BOOL]   = "bool",
        [SD_VARLINK_INT]    = "int",
        [SD_VARLINK_FLOAT]  = "float",
        [SD_VARLINK_STRING] = "string",
        [SD_VARLINK_OBJECT] = "object",
        [SD_VARLINK_ANY]    = "any",
};

/* Comments in the C macros attach to the element that follows them. Multiple consecutive
 * comments are joined with newlines, mirroring how they end up rendered in the textual IDL. */
static int varlink_idl_json_fields(const sd_varlink_symbol *symbol, sd_json_variant **ret);

static int comment_append(char **pending, const char *comment) {
        _cleanup_free_ char *joined = NULL;

        assert(pending);
        assert(comment);

        if (!*pending)
                return free_and_strdup(pending, comment);

        joined = strjoin(*pending, "\n", comment);
        if (!joined)
                return -ENOMEM;

        return free_and_replace(*pending, joined);
}

static int json_set_string(sd_json_variant **v, const char *name, const char *s) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *e = NULL;
        int r;

        assert(v);
        assert(name);
        assert(s);

        r = sd_json_variant_new_string(&e, s);
        if (r < 0)
                return r;

        return sd_json_variant_set_field(v, name, e);
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
                r = sd_json_buildo(&v, SD_JSON_BUILD_PAIR_STRING("name", field->name));
                if (r < 0)
                        return r;

                if (comment) {
                        r = json_set_string(&v, "comment", comment);
                        if (r < 0)
                                return r;

                        comment = mfree(comment);
                }

                r = sd_json_variant_append_array(&a, v);
                if (r < 0)
                        return r;
        }

        /* Return an (empty) array even for enums without values, so that consumers can rely
         * on "values" always being present for enum types. */
        if (!a) {
                r = sd_json_variant_new_array(&a, NULL, 0);
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

        r = sd_json_buildo(&v, SD_JSON_BUILD_PAIR_STRING("name", field->name));
        if (r < 0)
                return r;

        switch (field->field_type) {

        case SD_VARLINK_BOOL:
        case SD_VARLINK_INT:
        case SD_VARLINK_FLOAT:
        case SD_VARLINK_STRING:
        case SD_VARLINK_OBJECT:
        case SD_VARLINK_ANY:
                r = json_set_string(&v, "type", varlink_field_type_table[field->field_type]);
                break;

        case SD_VARLINK_NAMED_TYPE:
                r = json_set_string(&v, "namedType", field->named_type);
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

        if (field->field_flags & SD_VARLINK_NULLABLE) {
                r = sd_json_variant_set_field_boolean(&v, "nullable", true);
                if (r < 0)
                        return r;
        }

        if (field->field_flags & SD_VARLINK_ARRAY) {
                r = sd_json_variant_set_field_boolean(&v, "array", true);
                if (r < 0)
                        return r;
        }

        if (field->field_flags & SD_VARLINK_MAP) {
                r = sd_json_variant_set_field_boolean(&v, "map", true);
                if (r < 0)
                        return r;
        }

        if (comment) {
                r = json_set_string(&v, "comment", comment);
                if (r < 0)
                        return r;
        }

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

        /* As above: return an (empty) array rather than NULL, so that consumers can rely on
         * "fields" being present whenever we emit the key at all. */
        if (!a) {
                r = sd_json_variant_new_array(&a, NULL, 0);
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

        *ret_input = TAKE_PTR(input);
        *ret_output = TAKE_PTR(output);
        return 0;
}

static int varlink_idl_json_symbol(const sd_varlink_symbol *symbol, const char *comment, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        const char *kind;
        int r;

        assert(symbol);
        assert(ret);

        switch (symbol->symbol_type) {
        case SD_VARLINK_METHOD:
                kind = "method";
                break;
        case SD_VARLINK_ERROR:
                kind = "error";
                break;
        case SD_VARLINK_ENUM_TYPE:
        case SD_VARLINK_STRUCT_TYPE:
                kind = "type";
                break;
        default:
                assert_not_reached();
        }

        r = sd_json_buildo(&v,
                           SD_JSON_BUILD_PAIR_STRING("kind", kind),
                           SD_JSON_BUILD_PAIR_STRING("name", symbol->name));
        if (r < 0)
                return r;

        if (comment) {
                r = json_set_string(&v, "comment", comment);
                if (r < 0)
                        return r;
        }

        if (symbol->symbol_type == SD_VARLINK_METHOD || symbol->symbol_type == SD_VARLINK_ERROR) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *flags = NULL;

                for (sd_varlink_symbol_flags_t flag = SD_VARLINK_SUPPORTS_MORE; flag <= _SD_VARLINK_SYMBOL_FLAGS_MAX; flag <<= 1) {
                        if (!(symbol->symbol_flags & flag))
                                continue;

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *e = NULL;
                        const char *s;

                        switch (flag) {
                        case SD_VARLINK_SUPPORTS_MORE:
                                s = "supports-more";
                                break;
                        case SD_VARLINK_REQUIRES_MORE:
                                s = "requires-more";
                                break;
                        case SD_VARLINK_SUPPORTS_UPGRADE:
                                s = "supports-upgrade";
                                break;
                        case SD_VARLINK_REQUIRES_UPGRADE:
                                s = "requires-upgrade";
                                break;
                        default:
                                assert_not_reached();
                        }

                        r = sd_json_variant_new_string(&e, s);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_append_array(&flags, e);
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

                /* Empty methods are legal (e.g. pure notification-style calls), but we omit
                 * empty input/output arrays to keep the output compact. */
                if (input) {
                        r = sd_json_variant_set_field(&v, "input", input);
                        if (r < 0)
                                return r;
                }
                if (output) {
                        r = sd_json_variant_set_field(&v, "output", output);
                        if (r < 0)
                                return r;
                }

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

                r = json_set_string(&v, "typeKind", "struct");
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field(&v, "fields", fields);
                if (r < 0)
                        return r;

                break;
        }

        case SD_VARLINK_ENUM_TYPE: {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *values = NULL;

                r = varlink_idl_json_enum_values(symbol, &values);
                if (r < 0)
                        return r;

                r = json_set_string(&v, "typeKind", "enum");
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field(&v, "values", values);
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

int varlink_idl_json_interface(const sd_varlink_interface *interface, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *symbols = NULL;
        _cleanup_free_ char *interface_comment = NULL, *symbol_comment = NULL;
        int r;

        assert(interface);
        assert(ret);

        r = sd_json_buildo(&v, SD_JSON_BUILD_PAIR_STRING("name", interface->name));
        if (r < 0)
                return r;

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

        if (interface_comment) {
                r = json_set_string(&v, "comment", interface_comment);
                if (r < 0)
                        return r;
        }

        if (symbols) {
                r = sd_json_variant_set_field(&v, "symbols", symbols);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}
