/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "memstream-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "varlink-idl.h"
#include "set.h"

#define DEPTH_MAX 64U

enum {
        COLOR_SYMBOL_TYPE,   /* interface, method, type, error */
        COLOR_FIELD_TYPE,    /* string, bool, … */
        COLOR_IDENTIFIER,
        COLOR_MARKS,         /* [], ->, ?, … */
        COLOR_RESET,
        _COLOR_MAX,
};

static int varlink_idl_format_all_fields(FILE *f, const VarlinkSymbol *symbol, VarlinkFieldDirection direction, const char *indent, const char *const colors[static _COLOR_MAX]);

static int varlink_idl_format_enum_values(
                FILE *f,
                const VarlinkSymbol *symbol,
                const char *indent,
                const char *const colors[static _COLOR_MAX]) {

        bool first = true;

        assert(f);
        assert(symbol);
        assert(symbol->symbol_type == VARLINK_ENUM_TYPE);

        for (const VarlinkField *field = symbol->fields; field->field_type != _VARLINK_FIELD_TYPE_END_MARKER; field++) {

                if (first) {
                        first = false;
                        fputs("(\n", f);
                } else
                        fputs(",\n", f);

                fputs(strempty(indent), f);
                fputs("\t", f);
                fputs(colors[COLOR_IDENTIFIER], f);
                fputs(field->name, f);
                fputs(colors[COLOR_RESET], f);
        }

        if (first)
                fputs("()", f);
        else {
                fputs("\n", f);
                fputs(strempty(indent), f);
                fputs(")", f);
        }

        return 0;
}

static int varlink_idl_format_field(
                FILE *f,
                const VarlinkField *field,
                const char *indent,
                const char *const colors[static _COLOR_MAX]) {

        assert(f);
        assert(field);

        fputs(strempty(indent), f);
        fputs(colors[COLOR_IDENTIFIER], f);
        fputs(field->name, f);
        fputs(colors[COLOR_RESET], f);
        fputs(": ", f);

        if (FLAGS_SET(field->field_flags, VARLINK_NULLABLE)) {
                fputs(colors[COLOR_MARKS], f);
                fputs("?", f);
                fputs(colors[COLOR_RESET], f);
        }

        switch (field->field_flags & (VARLINK_MAP|VARLINK_ARRAY)) {

        case VARLINK_MAP:
                fputs(colors[COLOR_MARKS], f);
                fputs("[", f);
                fputs(colors[COLOR_FIELD_TYPE], f);
                fputs("string", f);
                fputs(colors[COLOR_MARKS], f);
                fputs("]", f);
                fputs(colors[COLOR_RESET], f);
                break;

        case VARLINK_ARRAY:
                fputs(colors[COLOR_MARKS], f);
                fputs("[]", f);
                fputs(colors[COLOR_RESET], f);
                break;

        case 0:
                break;

        default:
                assert_not_reached();
        }

        switch (field->field_type) {

        case VARLINK_BOOL:
                fputs(colors[COLOR_FIELD_TYPE], f);
                fputs("bool", f);
                fputs(colors[COLOR_RESET], f);
                break;

        case VARLINK_INT:
                fputs(colors[COLOR_FIELD_TYPE], f);
                fputs("int", f);
                fputs(colors[COLOR_RESET], f);
                break;

        case VARLINK_FLOAT:
                fputs(colors[COLOR_FIELD_TYPE], f);
                fputs("float", f);
                fputs(colors[COLOR_RESET], f);
                break;

        case VARLINK_STRING:
                fputs(colors[COLOR_FIELD_TYPE], f);
                fputs("string", f);
                fputs(colors[COLOR_RESET], f);
                break;

        case VARLINK_OBJECT:
                fputs(colors[COLOR_FIELD_TYPE], f);
                fputs("object", f);
                fputs(colors[COLOR_RESET], f);
                break;

        case VARLINK_NAMED_TYPE:
                fputs(colors[COLOR_IDENTIFIER], f);
                fputs(ASSERT_PTR(field->named_type), f);
                fputs(colors[COLOR_RESET], f);
                break;

        case VARLINK_STRUCT:
                return varlink_idl_format_all_fields(f, ASSERT_PTR(field->symbol), VARLINK_REGULAR, indent, colors);

        case VARLINK_ENUM:
                return varlink_idl_format_enum_values(f, ASSERT_PTR(field->symbol), indent, colors);

        default:
                assert_not_reached();
        }

        return 0;
}

static int varlink_idl_format_all_fields(
                FILE *f,
                const VarlinkSymbol *symbol,
                VarlinkFieldDirection filter_direction,
                const char *indent,
                const char *const colors[static _COLOR_MAX]) {

        _cleanup_free_ char *indent2 = NULL;
        bool first = true;
        int r;

        assert(f);
        assert(symbol);
        assert(IN_SET(symbol->symbol_type, VARLINK_STRUCT_TYPE, VARLINK_METHOD, VARLINK_ERROR));

        indent2 = strjoin(strempty(indent), "\t");
        if (!indent2)
                return -ENOMEM;

        for (const VarlinkField *field = symbol->fields; field->field_type != _VARLINK_FIELD_TYPE_END_MARKER; field++) {

                if (field->field_direction != filter_direction)
                        continue;

                if (first) {
                        first = false;
                        fputs("(\n", f);
                } else
                        fputs(",\n", f);

                r = varlink_idl_format_field(f, field, indent2, colors);
                if (r < 0)
                        return r;
        }

        if (first)
                fputs("()", f);
        else {
                fputs("\n", f);
                fputs(strempty(indent), f);
                fputs(")", f);
        }

        return 0;
}

static int varlink_idl_format_symbol(
                FILE *f,
                const VarlinkSymbol *symbol,
                const char *const colors[static _COLOR_MAX]) {
        int r;

        assert(f);
        assert(symbol);

        switch (symbol->symbol_type) {

        case VARLINK_ENUM_TYPE:
                fputs(colors[COLOR_SYMBOL_TYPE], f);
                fputs("type ", f);
                fputs(colors[COLOR_IDENTIFIER], f);
                fputs(symbol->name, f);
                fputs(colors[COLOR_RESET], f);

                r = varlink_idl_format_enum_values(f, symbol, /* indent= */ NULL, colors);
                break;

        case VARLINK_STRUCT_TYPE:
                fputs(colors[COLOR_SYMBOL_TYPE], f);
                fputs("type ", f);
                fputs(colors[COLOR_IDENTIFIER], f);
                fputs(symbol->name, f);
                fputs(colors[COLOR_RESET], f);

                r = varlink_idl_format_all_fields(f, symbol, VARLINK_REGULAR, /* indent= */ NULL, colors);
                break;

        case VARLINK_METHOD:
                fputs(colors[COLOR_SYMBOL_TYPE], f);
                fputs("method ", f);
                fputs(colors[COLOR_IDENTIFIER], f);
                fputs(symbol->name, f);
                fputs(colors[COLOR_RESET], f);

                r = varlink_idl_format_all_fields(f, symbol, VARLINK_INPUT, /* indent= */ NULL, colors);
                if (r < 0)
                        return r;

                fputs(colors[COLOR_MARKS], f);
                fputs(" -> ", f);
                fputs(colors[COLOR_RESET], f);

                r = varlink_idl_format_all_fields(f, symbol, VARLINK_OUTPUT, /* indent= */ NULL, colors);
                break;

        case VARLINK_ERROR:
                fputs(colors[COLOR_SYMBOL_TYPE], f);
                fputs("error ", f);
                fputs(colors[COLOR_IDENTIFIER], f);
                fputs(symbol->name, f);
                fputs(colors[COLOR_RESET], f);

                r = varlink_idl_format_all_fields(f, symbol, VARLINK_REGULAR, /* indent= */ NULL, colors);
                break;

        default:
                assert_not_reached();
        }
        if (r < 0)
                return r;

        fputs("\n", f);
        return 0;
}

static int varlink_idl_format_all_symbols(
                FILE *f,
                const VarlinkInterface *interface,
                VarlinkSymbolType filter_type,
                const char *const colors[static _COLOR_MAX]) {

        int r;

        assert(f);
        assert(interface);

        for (const VarlinkSymbol *const*symbol = interface->symbols; *symbol; symbol++) {

                if ((*symbol)->symbol_type != filter_type)
                        continue;

                fputs("\n", f);

                r = varlink_idl_format_symbol(f, *symbol, colors);
                if (r < 0)
                        return r;
        }

        return 0;
}

int varlink_idl_dump(FILE *f, int use_colors, const VarlinkInterface *interface) {
        static const char* const color_table[_COLOR_MAX] = {
                [COLOR_SYMBOL_TYPE] = ANSI_HIGHLIGHT_GREEN,
                [COLOR_FIELD_TYPE]  = ANSI_HIGHLIGHT_BLUE,
                [COLOR_IDENTIFIER]  = ANSI_NORMAL,
                [COLOR_MARKS]       = ANSI_HIGHLIGHT_MAGENTA,
                [COLOR_RESET]       = ANSI_NORMAL,
        };

        static const char* const color_off[_COLOR_MAX] = {
                "", "", "", "", "",
        };

        int r;

        assert(interface);

        if (!f)
                f = stdout;

        if (use_colors < 0)
                use_colors = colors_enabled();

        const char *const *colors = use_colors ? color_table : color_off;

        fputs(colors[COLOR_SYMBOL_TYPE], f);
        fputs("interface ", f);
        fputs(colors[COLOR_IDENTIFIER], f);
        fputs(ASSERT_PTR(interface->name), f);
        fputs(colors[COLOR_RESET], f);
        fputs("\n", f);

        for (VarlinkSymbolType t = 0; t < _VARLINK_SYMBOL_TYPE_MAX; t++) {
                r = varlink_idl_format_all_symbols(f, interface, t, colors);
                if (r < 0)
                        return r;
        }

        return 0;
}

int varlink_idl_format(const VarlinkInterface *interface, char **ret) {
        _cleanup_(memstream_done) MemStream memstream = {};
        int r;

        if (!memstream_init(&memstream))
                return -errno;

        r = varlink_idl_dump(memstream.f, /* use_colors= */ false, interface);
        if (r < 0)
                return r;

        return memstream_finalize(&memstream, ret, NULL);
}

static VarlinkSymbol *varlink_symbol_free(VarlinkSymbol *symbol) {
        if (!symbol)
                return NULL;

        /* See comment in varlink_interface_free() regarding the casting away of `const` */

        free((char*) symbol->name);

        for (size_t i = 0; symbol->fields[i].field_type != _VARLINK_FIELD_TYPE_END_MARKER; i++) {
                VarlinkField *field = symbol->fields + i;

                free((void*) field->name);
                free((void*) field->named_type);

                /* The symbol pointer might either point to a named symbol, in which case that symbol is
                 * owned by the interface, or by an anomyous symbol, in which case it is owned by us, and we
                 * need to free it */
                if (field->symbol && field->field_type != VARLINK_NAMED_TYPE)
                        varlink_symbol_free((VarlinkSymbol*) field->symbol);
        }

        return mfree(symbol);
}

VarlinkInterface* varlink_interface_free(VarlinkInterface *interface) {
        if (!interface)
                return NULL;

        /* So here's the thing: in most cases we want that users of this define their interface descriptions
         * in C code, and hence the definitions are constant and immutable during the lifecycle of the
         * system. Because of that we define all structs with const* pointers. It makes it very nice and
         * straight-forward to populate these structs with literal C strings. However, in some not so common
         * cases we also want to allocate these structures dynamically on the heap, when parsing interface
         * descriptions. But given this should be the exceptional and not the common case, we decided to
         * simple cast away the 'const' where needed, even if it is ugly. */

        free((char*) interface->name);

        for (size_t i = 0; interface->symbols[i]; i++)
                varlink_symbol_free((VarlinkSymbol*) interface->symbols[i]);

        return mfree(interface);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(VarlinkSymbol*, varlink_symbol_free);

static int varlink_interface_realloc(VarlinkInterface **interface, size_t n_symbols) {
        VarlinkInterface *n;

        assert(interface);

        n_symbols++; /* Space for trailing NULL end marker symbol */

        /* Overflow check */
        if (n_symbols > (SIZE_MAX - offsetof(VarlinkInterface, symbols)) / sizeof(VarlinkSymbol*))
                return -ENOMEM;

        n = realloc0(*interface, offsetof(VarlinkInterface, symbols) + sizeof(VarlinkSymbol*) * n_symbols);
        if (!n)
                return -ENOMEM;

        *interface = n;
        return 0;
}

static int varlink_symbol_realloc(VarlinkSymbol **symbol, size_t n_fields) {
        VarlinkSymbol *n;

        assert(symbol);

        n_fields++; /* Space for trailing end marker field */

        /* Overflow check */
        if (n_fields > (SIZE_MAX - offsetof(VarlinkSymbol, fields)) / sizeof(VarlinkField))
                return -ENOMEM;

        n = realloc0(*symbol, offsetof(VarlinkSymbol, fields) + sizeof(VarlinkField) * n_fields);
        if (!n)
                return -ENOMEM;

        *symbol = n;
        return 0;
}

#define VALID_CHARS_IDENTIFIER ALPHANUMERICAL "_"
#define VALID_CHARS_RESERVED LOWERCASE_LETTERS
#define VALID_CHARS_INTERFACE_NAME ALPHANUMERICAL ".-"

static void advance_line_column(const char *p, size_t n, unsigned *line, unsigned *column) {

        assert(p);
        assert(line);
        assert(column);

        for (; n > 0; p++, n--) {

                if (*p == '\n') {
                        (*line)++;
                        *column = 1;
                } else
                        (*column)++;
        }
}

static size_t token_match(
                const char *p,
                const char *allowed_delimiters,
                const char *allowed_chars) {

        /* Checks if the string p begins either with one of the token characters in allowed_delimiters or
         * with a string consisting of allowed_chars. */

        assert(p);

        if (allowed_delimiters && strchr(allowed_delimiters, *p))
                return 1;

        if (!allowed_chars)
                return 0;

        return strspn(p, allowed_chars);
}

static int varlink_idl_subparse_token(
                const char **p,
                unsigned *line,
                unsigned *column,
                const char *allowed_delimiters,
                const char *allowed_chars,
                char **ret_token) {

        _cleanup_free_ char *t = NULL;
        size_t l;

        assert(p);
        assert(*p);
        assert(line);
        assert(column);
        assert(ret_token);

        if (**p == '\0') { /* eof */
                *ret_token = NULL;
                return 0;
        }

        l = token_match(*p, allowed_delimiters, allowed_chars);

        /* No token of the permitted character set found? Then let's try to skip over whitespace and try again */
        if (l == 0) {
                size_t ll;

                ll = strspn(*p, WHITESPACE);
                advance_line_column(*p, ll, line, column);
                *p += ll;

                if (**p == '\0') { /* eof */
                        *ret_token = NULL;
                        return 0;
                }

                l = token_match(*p, allowed_delimiters, allowed_chars);
                if (l == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Couldn't find token of allowed chars '%s' or allowed delimiters '%s'.", strempty(allowed_chars), strempty(allowed_delimiters));
        }

        t = strndup(*p, l);
        if (!t)
                return -ENOMEM;

        advance_line_column(*p, l, line, column);
        *p += l;

        *ret_token = TAKE_PTR(t);
        return 1;
}

static int varlink_idl_subparse_comment(
                const char **p,
                unsigned *line,
                unsigned *column) {

        size_t l;

        assert(p);
        assert(*p);
        assert(line);
        assert(column);

        l = strcspn(*p, NEWLINE);
        advance_line_column(*p, l + 1, line, column);
        *p += l;

        return 1;
}

static int varlink_idl_subparse_whitespace(
                const char **p,
                unsigned *line,
                unsigned *column) {

        size_t l;

        assert(p);
        assert(*p);
        assert(line);
        assert(column);

        l = strspn(*p, WHITESPACE);
        advance_line_column(*p, l, line, column);
        *p += l;

        return 1;
}

static int varlink_idl_subparse_struct_or_enum(const char **p, unsigned *line, unsigned *column, VarlinkSymbol **symbol, size_t *n_fields, VarlinkFieldDirection direction, unsigned depth);

static int varlink_idl_subparse_field_type(
                const char **p,
                unsigned *line,
                unsigned *column,
                VarlinkField *field,
                unsigned depth) {

        size_t l;
        int r;

        assert(p);
        assert(*p);
        assert(line);
        assert(field);

        r = varlink_idl_subparse_whitespace(p, line, column);
        if (r < 0)
                return r;

        if (startswith(*p, "?")) {
                field->field_flags |= VARLINK_NULLABLE;
                l = 1;
        } else {
                field->field_flags &= ~VARLINK_NULLABLE;
                l = 0;
        }

        advance_line_column(*p, l, line, column);
        *p += l;

        if (startswith(*p, "[]")) {
                l = 2;
                field->field_flags = (field->field_flags & ~VARLINK_MAP) | VARLINK_ARRAY;
        } else if (startswith(*p, "[string]")) {
                l = 8;
                field->field_flags = (field->field_flags & ~VARLINK_ARRAY) | VARLINK_MAP;
        } else {
                l = 0;
                field->field_flags = field->field_flags & ~(VARLINK_MAP | VARLINK_ARRAY);
        }

        advance_line_column(*p, l, line, column);
        *p += l;

        if (startswith(*p, "bool")) {
                l = 4;
                field->field_type = VARLINK_BOOL;
        } else if (startswith(*p, "int")) {
                l = 3;
                field->field_type = VARLINK_INT;
        } else if (startswith(*p, "float")) {
                l = 5;
                field->field_type = VARLINK_FLOAT;
        } else if (startswith(*p, "string")) {
                l = 6;
                field->field_type = VARLINK_STRING;
        } else if (startswith(*p, "object")) {
                l = 6;
                field->field_type = VARLINK_OBJECT;
        } else if (**p == '(') {
                _cleanup_(varlink_symbol_freep) VarlinkSymbol *symbol = NULL;
                size_t n_fields = 0;

                r = varlink_symbol_realloc(&symbol, n_fields);
                if (r < 0)
                        return r;

                symbol->symbol_type = _VARLINK_SYMBOL_TYPE_INVALID;

                r = varlink_idl_subparse_struct_or_enum(
                                p,
                                line,
                                column,
                                &symbol,
                                &n_fields,
                                VARLINK_REGULAR,
                                depth + 1);
                if (r < 0)
                        return r;

                if (symbol->symbol_type == VARLINK_STRUCT_TYPE)
                        field->field_type = VARLINK_STRUCT;
                else {
                        assert(symbol->symbol_type == VARLINK_ENUM_TYPE);
                        field->field_type = VARLINK_ENUM;
                }

                field->symbol = TAKE_PTR(symbol);
                l = 0;
        } else {
                _cleanup_free_ char *token = NULL;

                r = varlink_idl_subparse_token(p, line, column, /* valid_tokens= */ NULL, VALID_CHARS_IDENTIFIER, &token);
                if (r < 0)
                        return r;
                if (!token)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Premature EOF.", *line, *column);

                field->named_type = TAKE_PTR(token);
                field->field_type = VARLINK_NAMED_TYPE;
                l = 0;
        }

        advance_line_column(*p, l, line, column);
        *p += l;

        return 0;
}

static int varlink_idl_subparse_struct_or_enum(
                const char **p,
                unsigned *line,
                unsigned *column,
                VarlinkSymbol **symbol,
                size_t *n_fields,
                VarlinkFieldDirection direction,
                unsigned depth) {

        enum {
                STATE_OPEN,
                STATE_NAME,
                STATE_COLON,
                STATE_COMMA,
                STATE_DONE,
        } state = STATE_OPEN;
        _cleanup_free_ char *field_name = NULL;
        const char *allowed_delimiters = "(", *allowed_chars = NULL;
        int r;

        assert(p);
        assert(*p);
        assert(line);
        assert(column);
        assert(symbol);
        assert(*symbol);
        assert(n_fields);

        if (depth > DEPTH_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Maximum nesting depth reached (%u).", *line, *column, DEPTH_MAX);

        while (state != STATE_DONE) {
                _cleanup_free_ char *token = NULL;

                r = varlink_idl_subparse_token(
                                p,
                                line,
                                column,
                                allowed_delimiters,
                                allowed_chars,
                                &token);
                if (r < 0)
                        return r;

                switch (state) {

                case STATE_OPEN:
                        if (!token)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Premature EOF.", *line, *column);
                        if (!streq(token, "("))
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Unexpected token '%s'.", *line, *column, token);

                        state = STATE_NAME;
                        allowed_delimiters = ")";
                        allowed_chars = VALID_CHARS_IDENTIFIER;
                        break;

                case STATE_NAME:
                        assert(!field_name);

                        if (!token)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Premature EOF.", *line, *column);
                        if (streq(token, ")"))
                                state = STATE_DONE;
                        else {
                                field_name = TAKE_PTR(token);
                                state = STATE_COLON;
                                allowed_delimiters = ":,)";
                                allowed_chars = NULL;
                        }

                        break;

                case STATE_COLON:
                        assert(field_name);

                        if (!token)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Premature EOF.", *line, *column);

                        if (streq(token, ":")) {
                                VarlinkField *field;

                                if ((*symbol)->symbol_type < 0)
                                        (*symbol)->symbol_type = VARLINK_STRUCT_TYPE;
                                if ((*symbol)->symbol_type == VARLINK_ENUM_TYPE)
                                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Enum with struct fields, refusing.", *line, *column);

                                r = varlink_symbol_realloc(symbol, *n_fields + 1);
                                if (r < 0)
                                        return r;

                                field = (*symbol)->fields + (*n_fields)++;
                                *field = (VarlinkField) {
                                        .name = TAKE_PTR(field_name),
                                        .field_type = _VARLINK_FIELD_TYPE_INVALID,
                                        .field_direction = direction,
                                };

                                r = varlink_idl_subparse_field_type(p, line, column, field, depth);
                                if (r < 0)
                                        return r;

                                state = STATE_COMMA;
                                allowed_delimiters = ",)";
                                allowed_chars = NULL;

                        } else if (STR_IN_SET(token, ",", ")")) {
                                VarlinkField *field;

                                if ((*symbol)->symbol_type < 0)
                                        (*symbol)->symbol_type = VARLINK_ENUM_TYPE;
                                if ((*symbol)->symbol_type != VARLINK_ENUM_TYPE)
                                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Struct with enum fields, refusing.", *line, *column);

                                r = varlink_symbol_realloc(symbol, *n_fields + 1);
                                if (r < 0)
                                        return r;

                                field = (*symbol)->fields + (*n_fields)++;
                                *field = (VarlinkField) {
                                        .name = TAKE_PTR(field_name),
                                        .field_type = VARLINK_ENUM_VALUE,
                                };

                                if (streq(token, ",")) {
                                        state = STATE_NAME;
                                        allowed_delimiters = NULL;
                                        allowed_chars = VALID_CHARS_IDENTIFIER;
                                } else {
                                        assert(streq(token, ")"));
                                        state = STATE_DONE;
                                }
                        } else
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Unexpected token '%s'.", *line, *column, token);

                        break;

                case STATE_COMMA:
                        assert(!field_name);

                        if (!token)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Premature EOF.", *line, *column);
                        if (streq(token, ",")) {
                                state = STATE_NAME;
                                allowed_delimiters = NULL;
                                allowed_chars = VALID_CHARS_IDENTIFIER;
                        } else if (streq(token, ")"))
                                state = STATE_DONE;
                        else
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Unexpected token '%s'.", *line, *column, token);
                        break;

                default:
                        assert_not_reached();
                }
        }

        /* If we don't know the type of the symbol by now it was an empty () which doesn't allow us to
         * determine if we look at an enum or a struct */
        if ((*symbol)->symbol_type < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Ambiguous empty () enum/struct is not permitted.", *line, *column);

        return 0;
}

static int varlink_idl_resolve_symbol_types(VarlinkInterface *interface, VarlinkSymbol *symbol) {
        assert(interface);
        assert(symbol);

        for (VarlinkField *field = symbol->fields; field->field_type != _VARLINK_FIELD_TYPE_END_MARKER; field++) {
                const VarlinkSymbol *found;

                if (field->field_type != VARLINK_NAMED_TYPE)
                        continue;

                if (field->symbol) /* Already resolved */
                        continue;

                if (!field->named_type)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENETUNREACH), "Named type field lacking a type name.");

                found = varlink_idl_find_symbol(interface, _VARLINK_SYMBOL_TYPE_INVALID, field->named_type);
                if (!found)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENETUNREACH), "Failed to find type '%s'.", field->named_type);

                if (!IN_SET(found->symbol_type, VARLINK_STRUCT_TYPE, VARLINK_ENUM_TYPE))
                        return log_debug_errno(SYNTHETIC_ERRNO(ENETUNREACH), "Symbol '%s' is referenced as type but is not a type.", field->named_type);

                field->symbol = found;
        }

        return 0;
}

static int varlink_idl_resolve_types(VarlinkInterface *interface) {
        int r;

        assert(interface);

        for (VarlinkSymbol **symbol = (VarlinkSymbol**) interface->symbols; *symbol; symbol++) {
                r = varlink_idl_resolve_symbol_types(interface, *symbol);
                if (r < 0)
                        return r;
        }

        return 0;
}

int varlink_idl_parse(
                const char *text,
                unsigned *line,
                unsigned *column,
                VarlinkInterface **ret) {

        _cleanup_(varlink_interface_freep) VarlinkInterface *interface = NULL;
        _cleanup_(varlink_symbol_freep) VarlinkSymbol *symbol = NULL;
        enum {
                STATE_PRE_INTERFACE,
                STATE_INTERFACE,
                STATE_PRE_SYMBOL,
                STATE_METHOD,
                STATE_METHOD_NAME,
                STATE_METHOD_ARROW,
                STATE_TYPE,
                STATE_TYPE_NAME,
                STATE_ERROR,
                STATE_ERROR_NAME,
                STATE_DONE,
        } state = STATE_PRE_INTERFACE;
        const char *allowed_delimiters = "#", *allowed_chars = VALID_CHARS_RESERVED;
        size_t n_symbols = 0, n_fields = 1;
        unsigned _line = 0, _column = 1;
        const char **p = &text;
        int r;

        if (!line)
                line = &_line;
        if (!column)
                column = &_column;

        while (state != STATE_DONE) {
                _cleanup_free_ char *token = NULL;

                r = varlink_idl_subparse_token(
                                p,
                                line,
                                column,
                                allowed_delimiters,
                                allowed_chars,
                                &token);
                if (r < 0)
                        return r;

                switch (state) {

                case STATE_PRE_INTERFACE:
                        if (!token)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Premature EOF.", *line, *column);
                        if (streq(token, "#")) {
                                r = varlink_idl_subparse_comment(&text, line, column);
                                if (r < 0)
                                        return r;
                        } else if (streq(token, "interface")) {
                                state = STATE_INTERFACE;
                                allowed_delimiters = NULL;
                                allowed_chars = VALID_CHARS_INTERFACE_NAME;
                        } else
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Unexpected token '%s'.", *line, *column, token);
                        break;

                case STATE_INTERFACE:
                        assert(!interface);
                        assert(n_symbols == 0);

                        if (!token)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Premature EOF.", *line, *column);

                        r = varlink_interface_realloc(&interface, n_symbols);
                        if (r < 0)
                                return r;

                        interface->name = TAKE_PTR(token);
                        state = STATE_PRE_SYMBOL;
                        allowed_delimiters = "#";
                        allowed_chars = VALID_CHARS_RESERVED;
                        break;

                case STATE_PRE_SYMBOL:
                        if (!token) {
                                state = STATE_DONE;
                                break;
                        }

                        if (streq(token, "#")) {
                                r = varlink_idl_subparse_comment(&text, line, column);
                                if (r < 0)
                                        return r;
                        } else if (streq(token, "method")) {
                                state = STATE_METHOD;
                                allowed_chars = VALID_CHARS_IDENTIFIER;
                        } else if (streq(token, "type")) {
                                state = STATE_TYPE;
                                allowed_chars = VALID_CHARS_IDENTIFIER;
                        } else if (streq(token, "error")) {
                                state = STATE_ERROR;
                                allowed_chars = VALID_CHARS_IDENTIFIER;
                        } else
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Unexpected token '%s'.", *line, *column, token);

                        break;

                case STATE_METHOD:
                        assert(!symbol);
                        n_fields = 0;

                        if (!token)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Premature EOF.", *line, *column);

                        r = varlink_symbol_realloc(&symbol, n_fields);
                        if (r < 0)
                                return r;

                        symbol->symbol_type = VARLINK_METHOD;
                        symbol->name = TAKE_PTR(token);

                        r = varlink_idl_subparse_struct_or_enum(&text, line, column, &symbol, &n_fields, VARLINK_INPUT, 0);
                        if (r < 0)
                                return r;

                        state = STATE_METHOD_ARROW;
                        allowed_chars = "->";
                        break;

                case STATE_METHOD_ARROW:
                        assert(symbol);

                        if (!token)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Premature EOF.", *line, *column);

                        if (!streq(token, "->"))
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Unexpected token '%s'.", *line, *column, token);

                        r = varlink_idl_subparse_struct_or_enum(&text, line, column, &symbol, &n_fields, VARLINK_OUTPUT, 0);
                        if (r < 0)
                                return r;

                        r = varlink_interface_realloc(&interface, n_symbols + 1);
                        if (r < 0)
                                return r;

                        interface->symbols[n_symbols++] = TAKE_PTR(symbol);

                        state = STATE_PRE_SYMBOL;
                        allowed_chars = VALID_CHARS_RESERVED "#";
                        break;

                case STATE_TYPE:
                        assert(!symbol);
                        n_fields = 0;

                        if (!token)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Premature EOF.", *line, *column);

                        r = varlink_symbol_realloc(&symbol, n_fields);
                        if (r < 0)
                                return r;

                        symbol->symbol_type = _VARLINK_SYMBOL_TYPE_INVALID; /* don't know yet if enum or struct, will be field in by varlink_idl_subparse_struct_or_enum() */
                        symbol->name = TAKE_PTR(token);

                        r = varlink_idl_subparse_struct_or_enum(&text, line, column, &symbol, &n_fields, VARLINK_REGULAR, 0);
                        if (r < 0)
                                return r;

                        r = varlink_interface_realloc(&interface, n_symbols + 1);
                        if (r < 0)
                                return r;

                        interface->symbols[n_symbols++] = TAKE_PTR(symbol);

                        state = STATE_PRE_SYMBOL;
                        allowed_chars = VALID_CHARS_RESERVED "#";
                        break;

                case STATE_ERROR:
                        assert(!symbol);
                        n_fields = 0;

                        if (!token)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%u:%u: Premature EOF.", *line, *column);

                        r = varlink_symbol_realloc(&symbol, n_fields);
                        if (r < 0)
                                return r;

                        symbol->symbol_type = VARLINK_ERROR;
                        symbol->name = TAKE_PTR(token);

                        r = varlink_idl_subparse_struct_or_enum(&text, line, column, &symbol, &n_fields, VARLINK_REGULAR, 0);
                        if (r < 0)
                                return r;

                        r = varlink_interface_realloc(&interface, n_symbols + 1);
                        if (r < 0)
                                return r;

                        interface->symbols[n_symbols++] = TAKE_PTR(symbol);

                        state = STATE_PRE_SYMBOL;
                        allowed_chars = VALID_CHARS_RESERVED "#";
                        break;

                default:
                        assert_not_reached();
                }
        }

        r = varlink_idl_resolve_types(interface);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(interface);
        return 0;
}

bool varlink_idl_field_name_is_valid(const char *name) {
        if (isempty(name))
                return false;

        /* Field names may start with lower or uppercase char, but no numerals or underscore */
        if (!strchr(LETTERS, name[0]))
                return false;

        /* Otherwise fields may be alphanumerical or underscore, but no two underscore may immediately follow
         * each other or be trailing */
        bool underscore = false;
        for (const char *c = name + 1; *c; c++) {
                if (*c == '_') {
                        if (underscore)
                                return false;

                        underscore = true;
                        continue;
                }

                if (!strchr(ALPHANUMERICAL, *c))
                        return false;

                underscore = false;
        }

        if (underscore)
                return false;

        return true;
}

bool varlink_idl_symbol_name_is_valid(const char *name) {
        if (isempty(name))
                return false;

        /* We might want to reference VARLINK_STRUCT_TYPE and VARLINK_ENUM_TYPE symbols where we also
         * reference native types, hence make sure the native type names are refused as symbol names. */
        if (STR_IN_SET(name, "bool", "int", "float", "string", "object"))
                return false;

        /* Symbols must be named with an uppercase letter as first character */
        if (!strchr(UPPERCASE_LETTERS, name[0]))
                return false;

        for (const char *c = name + 1; *c; c++)
                if (!strchr(ALPHANUMERICAL, *c))
                        return false;

        return true;
}

bool varlink_idl_interface_name_is_valid(const char *name) {
        if (isempty(name))
                return false;

        /* Interface names must start with a letter, uppercase or lower case, but nothing else */
        if (!strchr(LETTERS, name[0]))
                return false;

        /* Otherwise it may be a series of non-empty dot separated labels, which are alphanumerical and may
         * contain single dashes in the middle */
        bool dot = false, dash = false;
        for (const char *c = name + 1; *c; c++) {
                switch (*c) {

                case '.':
                        if (dot || dash)
                                return false;

                        dot = true;
                        break;

                case '-':
                        if (dot || dash)
                                return false;

                        dash = true;
                        break;

                default:
                        if (!strchr(ALPHANUMERICAL, *c))
                                return false;

                        dot = dash = false;
                }
        }

        if (dot || dash)
                return false;

        return true;
}

static int varlink_idl_symbol_consistent(const VarlinkInterface *interface, const VarlinkSymbol *symbol, int level);

static int varlink_idl_field_consistent(
                const VarlinkInterface *interface,
                const VarlinkSymbol *symbol,
                const VarlinkField *field,
                int level) {

        const char *symbol_name;
        int r;

        assert(interface);
        assert(symbol);
        assert(field);
        assert(field->name);

        symbol_name = symbol->name ?: "<anonymous>";

        if (field->field_type <= 0 || field->field_type >= _VARLINK_FIELD_TYPE_MAX)
                return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Field type for '%s' in symbol '%s' is not valid, refusing.", field->name, symbol_name);

        if (field->field_type == VARLINK_ENUM_VALUE) {

                if (symbol->symbol_type != VARLINK_ENUM_TYPE)
                        return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Enum field type for '%s' in non-enum symbol '%s', refusing.", field->name, symbol_name);

                if (field->field_flags != 0)
                        return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Enum field '%s' in symbol '%s' has non-zero flags set, refusing.", field->name, symbol_name);
        } else {
                if (symbol->symbol_type == VARLINK_ENUM_TYPE)
                        return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Non-enum field type for '%s' in enum symbol '%s', refusing.", field->name, symbol_name);

                if (!IN_SET(field->field_flags & ~VARLINK_NULLABLE, 0, VARLINK_ARRAY, VARLINK_MAP))
                        return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Flags of field '%s' in symbol '%s' is invalid, refusing.", field->name, symbol_name);
        }

        if (symbol->symbol_type != VARLINK_METHOD) {
                if (field->field_direction != VARLINK_REGULAR)
                        return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Direction of '%s' in non-method symbol '%s' not regular, refusing.", field->name, symbol_name);
        } else {
                if (!IN_SET(field->field_direction, VARLINK_INPUT, VARLINK_OUTPUT))
                        return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Direction of '%s' in method symbol '%s' is not input or output, refusing.", field->name, symbol_name);
        }

        if (field->symbol) {
                if (!IN_SET(field->field_type, VARLINK_STRUCT, VARLINK_ENUM, VARLINK_NAMED_TYPE))
                        return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Target symbol for field '%s' in symbol '%s' defined for elemental field, refusing.", field->name, symbol_name);

                if (field->field_type == VARLINK_NAMED_TYPE) {
                        const VarlinkSymbol *found;

                        if (!field->symbol->name || !field->named_type || !streq(field->symbol->name, field->named_type))
                                return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Resolved symbol name and named type of field '%s' in symbol '%s' do do not match, refusing.", field->name, symbol_name);

                        /* If this is a named type, then check if it's properly part of the interface */
                        found = varlink_idl_find_symbol(interface, _VARLINK_SYMBOL_TYPE_INVALID, field->symbol->name);
                        if (!found)
                                return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Resolved symbol of named type of field '%s' in symbol '%s' is not part of the interface, refusing.", field->name, symbol_name);

                        if (!IN_SET(found->symbol_type, VARLINK_ENUM_TYPE, VARLINK_STRUCT_TYPE))
                                return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Resolved symbol of named type of field '%s' in symbol '%s' is not a type, refusing.", field->name, symbol_name);
                } else {
                        /* If this is an anonymous type, then we recursively check if it's consistent, since
                         * it's not part of the interface, and hence we won't validate it from there. */

                        r = varlink_idl_symbol_consistent(interface, field->symbol, level);
                        if (r < 0)
                                return r;
                }

        } else {
                if (IN_SET(field->field_type, VARLINK_STRUCT, VARLINK_ENUM, VARLINK_NAMED_TYPE))
                        return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "No target symbol for field '%s' in symbol '%s' defined for elemental field, refusing.", field->name, symbol_name);

                if (field->named_type)
                        return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Unresolved symbol in field '%s' in symbol '%s', refusing.", field->name, symbol_name);
        }

        if (field->named_type) {
                if (field->field_type != VARLINK_NAMED_TYPE)
                        return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Named type set for field '%s' in symbol '%s' but not a named type field, refusing.", field->name, symbol_name);
        } else {
                if (field->field_type == VARLINK_NAMED_TYPE)
                        return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "No named type set for field '%s' in symbol '%s' but field is a named type field, refusing.", field->name, symbol_name);
        }

        return 0;
}

static bool varlink_symbol_is_empty(const VarlinkSymbol *symbol) {
        assert(symbol);

        return symbol->fields[0].field_type == _VARLINK_FIELD_TYPE_END_MARKER;
}

static int varlink_idl_symbol_consistent(
                const VarlinkInterface *interface,
                const VarlinkSymbol *symbol,
                int level) {

        _cleanup_(set_freep) Set *input_set = NULL, *output_set = NULL;
        const char *symbol_name;
        int r;

        assert(interface);
        assert(symbol);

        symbol_name = symbol->name ?: "<anonymous>";

        if (symbol->symbol_type < 0 || symbol->symbol_type >= _VARLINK_SYMBOL_TYPE_MAX)
                return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Symbol type for '%s' is not valid, refusing.", symbol_name);

        if (IN_SET(symbol->symbol_type, VARLINK_STRUCT_TYPE, VARLINK_ENUM_TYPE) && varlink_symbol_is_empty(symbol))
                return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Symbol '%s' is empty, refusing.", symbol_name);

        for (const VarlinkField *field = symbol->fields; field->field_type != _VARLINK_FIELD_TYPE_END_MARKER; field++) {
                Set **name_set = field->field_direction == VARLINK_OUTPUT ? &output_set : &input_set; /* for the method case we need two separate sets, otherwise we use the same */

                if (!varlink_idl_field_name_is_valid(field->name))
                        return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Field name '%s' in symbol '%s' not valid, refusing.", field->name, symbol_name);

                if (set_contains(*name_set, field->name))
                        return log_full_errno(level, SYNTHETIC_ERRNO(ENOTUNIQ), "Field '%s' defined twice in symbol '%s', refusing.", field->name, symbol_name);

                if (set_ensure_put(name_set, &string_hash_ops, field->name) < 0)
                        return log_oom();

                r = varlink_idl_field_consistent(interface, symbol, field, level);
                if (r < 0)
                        return r;
        }

        return 0;
}

int varlink_idl_consistent(const VarlinkInterface *interface, int level) {
        _cleanup_(set_freep) Set *name_set = NULL;
        int r;

        assert(interface);

        if (!varlink_idl_interface_name_is_valid(interface->name))
                return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Interface name '%s' is not valid, refusing.", interface->name);

        for (const VarlinkSymbol *const *symbol = interface->symbols; *symbol; symbol++) {

                if (!varlink_idl_symbol_name_is_valid((*symbol)->name))
                        return log_full_errno(level, SYNTHETIC_ERRNO(EUCLEAN), "Symbol name '%s' is not valid, refusing.", strempty((*symbol)->name));

                if (set_contains(name_set, (*symbol)->name))
                        return log_full_errno(level, SYNTHETIC_ERRNO(ENOTUNIQ), "Symbol '%s' defined twice in interface, refusing.", (*symbol)->name);

                if (set_ensure_put(&name_set, &string_hash_ops, (*symbol)->name) < 0)
                        return log_oom();

                r = varlink_idl_symbol_consistent(interface, *symbol, level);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int varlink_idl_validate_symbol(const VarlinkSymbol *symbol, JsonVariant *v, VarlinkFieldDirection direction, const char **bad_field);

static int varlink_idl_validate_field_element_type(const VarlinkField *field, JsonVariant *v) {
        assert(field);

        switch (field->field_type) {

        case VARLINK_STRUCT:
        case VARLINK_ENUM:
        case VARLINK_NAMED_TYPE:
                return varlink_idl_validate_symbol(field->symbol, v, VARLINK_REGULAR, NULL);

        case VARLINK_BOOL:
                if (!json_variant_is_boolean(v))
                        return log_debug_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Field '%s' should be a bool, but it is not, refusing.", strna(field->name));

                break;

        case VARLINK_INT:
                if (!json_variant_is_integer(v) && !json_variant_is_unsigned(v))
                        return log_debug_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Field '%s' should be an int, but it is not, refusing.", strna(field->name));

                break;

        case VARLINK_FLOAT:
                if (!json_variant_is_number(v))
                        return log_debug_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Field '%s' should be a float, but it is not, refusing.", strna(field->name));

                break;

        case VARLINK_STRING:
                if (!json_variant_is_string(v))
                        return log_debug_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Field '%s' should be a string, but it is not, refusing.", strna(field->name));

                break;

        case VARLINK_OBJECT:
                if (!json_variant_is_object(v))
                        return log_debug_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Field '%s' should be an object, but it is not, refusing.", strna(field->name));

                break;

        default:
                assert_not_reached();
        }

        return 0;
}

static int varlink_idl_validate_field(const VarlinkField *field, JsonVariant *v) {
        int r;

        assert(field);

        if (!v || json_variant_is_null(v)) {

                if (!FLAGS_SET(field->field_flags, VARLINK_NULLABLE))
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOANO), "Mandatory field '%s' is null or missing on object, refusing.", strna(field->name));

        } else if (FLAGS_SET(field->field_flags, VARLINK_ARRAY)) {
                JsonVariant *i;

                if (!json_variant_is_array(v))
                        return log_debug_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Field '%s' should be an array, but it is not, refusing.", strna(field->name));

                JSON_VARIANT_ARRAY_FOREACH(i, v) {
                        r = varlink_idl_validate_field_element_type(field, i);
                        if (r < 0)
                                return r;
                }

        } else if (FLAGS_SET(field->field_flags, VARLINK_MAP)) {
                _unused_ const char *k;
                JsonVariant *e;

                if (!json_variant_is_object(v))
                        return log_debug_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Field '%s' should be an object, but it is not, refusing.", strna(field->name));

                JSON_VARIANT_OBJECT_FOREACH(k, e, v) {
                        r = varlink_idl_validate_field_element_type(field, e);
                        if (r < 0)
                                return r;
                }
        } else {

                r = varlink_idl_validate_field_element_type(field, v);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int varlink_idl_validate_symbol(const VarlinkSymbol *symbol, JsonVariant *v, VarlinkFieldDirection direction, const char **bad_field) {
        int r;

        assert(symbol);

        if (!v) {
                if (bad_field)
                        *bad_field = NULL;
                return log_debug_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Null object passed, refusing.");
        }

        switch (symbol->symbol_type) {

        case VARLINK_ENUM_TYPE: {
                bool found = false;
                const char *s;

                if (!json_variant_is_string(v)) {
                        if (bad_field)
                                *bad_field = symbol->name;
                        return log_debug_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Passed non-string to enum field '%s', refusing.", strna(symbol->name));
                }

                assert_se(s = json_variant_string(v));

                for (const VarlinkField *field = symbol->fields; field->field_type != _VARLINK_FIELD_TYPE_END_MARKER; field++) {

                        assert(field->field_type == VARLINK_ENUM_VALUE);

                        if (streq_ptr(field->name, s)) {
                                found = true;
                                break;
                        }
                }

                if (!found) {
                        if (bad_field)
                                *bad_field = s;
                        return log_debug_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Passed unrecognized string '%s' to enum field '%s', refusing.", s, strna(symbol->name));
                }

                break;
        }

        case VARLINK_STRUCT_TYPE:
        case VARLINK_METHOD:
        case VARLINK_ERROR: {
                if (!json_variant_is_object(v)) {
                        if (bad_field)
                                *bad_field = symbol->name;
                        return log_debug_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Passed non-object to field '%s', refusing.", strna(symbol->name));
                }

                for (const VarlinkField *field = symbol->fields; field->field_type != _VARLINK_FIELD_TYPE_END_MARKER; field++) {

                        if (field->field_direction != direction)
                                continue;

                        r = varlink_idl_validate_field(field, json_variant_by_key(v, field->name));
                        if (r < 0) {
                                if (bad_field)
                                        *bad_field = field->name;
                                return r;
                        }
                }

                _unused_ JsonVariant *e;
                const char *name;
                JSON_VARIANT_OBJECT_FOREACH(name, e, v) {
                        if (!varlink_idl_find_field(symbol, name)) {
                                if (bad_field)
                                        *bad_field = name;
                                return log_debug_errno(SYNTHETIC_ERRNO(EBUSY), "Field '%s' not defined for object, refusing.", name);
                        }
                }

                break;
        }

        default:
                assert_not_reached();
        }

        return 1; /* validated */
}

static int varlink_idl_validate_method(const VarlinkSymbol *method, JsonVariant *v, VarlinkFieldDirection direction, const char **bad_field) {
        assert(IN_SET(direction, VARLINK_INPUT, VARLINK_OUTPUT));

        if (!method)
                return 0; /* Can't validate */
        if (method->symbol_type != VARLINK_METHOD)
                return -EBADMSG;

        return varlink_idl_validate_symbol(method, v, direction, bad_field);
}

int varlink_idl_validate_method_call(const VarlinkSymbol *method, JsonVariant *v, const char **bad_field) {
        return varlink_idl_validate_method(method, v, VARLINK_INPUT, bad_field);
}

int varlink_idl_validate_method_reply(const VarlinkSymbol *method, JsonVariant *v, const char **bad_field) {
        return varlink_idl_validate_method(method, v, VARLINK_OUTPUT, bad_field);
}

int varlink_idl_validate_error(const VarlinkSymbol *error, JsonVariant *v, const char **bad_field) {
        if (!error)
                return 0; /* Can't validate */
        if (error->symbol_type != VARLINK_ERROR)
                return -EBADMSG;

        return varlink_idl_validate_symbol(error, v, VARLINK_REGULAR, bad_field);
}

const VarlinkSymbol* varlink_idl_find_symbol(
                const VarlinkInterface *interface,
                VarlinkSymbolType type,
                const char *name) {

        assert(interface);
        assert(type < _VARLINK_SYMBOL_TYPE_MAX);

        if (isempty(name))
                return NULL;

        for (const VarlinkSymbol *const*symbol = interface->symbols; *symbol; symbol++) {
                if (type >= 0 && (*symbol)->symbol_type != type)
                        continue;

                if (streq_ptr((*symbol)->name, name))
                        return *symbol;
        }

        return NULL;
}

const VarlinkField* varlink_idl_find_field(
                const VarlinkSymbol *symbol,
                const char *name) {

        assert(symbol);

        if (isempty(name))
                return NULL;

        for (const VarlinkField *field = symbol->fields; field->field_type != _VARLINK_FIELD_TYPE_END_MARKER; field++)
                if (streq_ptr(field->name, name))
                        return field;

        return NULL;
}
