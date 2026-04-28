/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink-idl.h"

#include "json-util.h"
#include "string-util.h"

static inline void test_enum_to_string_name(const char *n, const sd_varlink_symbol *symbol) {
        assert(n);
        assert(symbol);

        assert(symbol->symbol_type == SD_VARLINK_ENUM_TYPE);
        _cleanup_free_ char *m = ASSERT_PTR(json_underscorify(strdup(n)));

        bool found = false;
        for (const sd_varlink_field *f = symbol->fields; f->name; f++) {
                if (f->field_type == _SD_VARLINK_FIELD_COMMENT)
                        continue;

                assert(f->field_type == SD_VARLINK_ENUM_VALUE);
                if (streq(m, f->name)) {
                        found = true;
                        break;
                }
        }

        log_debug("'%s' found in '%s': %s", m, strna(symbol->name), yes_no(found));
        assert(found);
}

#define TEST_IDL_ENUM_TO_STRING(type, ename, symbol)     \
        for (type t = 0;; t++) {                         \
                const char *n = ename##_to_string(t);    \
                if (!n)                                  \
                        break;                           \
                test_enum_to_string_name(n, &(symbol));  \
        }

#define TEST_IDL_ENUM_FROM_STRING(type, ename, symbol)                  \
        for (const sd_varlink_field *f = (symbol).fields; f->name; f++) { \
                if (f->field_type == _SD_VARLINK_FIELD_COMMENT)         \
                        continue;                                       \
                assert(f->field_type == SD_VARLINK_ENUM_VALUE);         \
                _cleanup_free_ char *m = ASSERT_PTR(json_dashify(strdup(f->name))); \
                type t = ename##_from_string(m);                        \
                log_debug("'%s' of '%s' translates: %s", f->name, strna((symbol).name), yes_no(t >= 0)); \
                assert(t >= 0);                                         \
        }

#define TEST_IDL_ENUM(type, name, symbol)                       \
        do {                                                    \
                TEST_IDL_ENUM_TO_STRING(type, name, symbol);    \
                TEST_IDL_ENUM_FROM_STRING(type, name, symbol);  \
        } while (false)
