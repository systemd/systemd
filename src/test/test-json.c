/* SPDX-License-Identifier: LGPL-2.1+ */

#include <math.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "json-internal.h"
#include "json.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "util.h"

static void test_tokenizer(const char *data, ...) {
        unsigned line = 0, column = 0;
        void *state = NULL;
        va_list ap;

        va_start(ap, data);

        for (;;) {
                unsigned token_line, token_column;
                _cleanup_free_ char *str = NULL;
                JsonValue v = JSON_VALUE_NULL;
                int t, tt;

                t = json_tokenize(&data, &str, &v, &token_line, &token_column, &state, &line, &column);
                tt = va_arg(ap, int);

                assert_se(t == tt);

                if (t == JSON_TOKEN_END || t < 0)
                        break;

                else if (t == JSON_TOKEN_STRING) {
                        const char *nn;

                        nn = va_arg(ap, const char *);
                        assert_se(streq_ptr(nn, str));

                } else if (t == JSON_TOKEN_REAL) {
                        long double d;

                        d = va_arg(ap, long double);

                        /* Valgrind doesn't support long double calculations and automatically downgrades to 80bit:
                         * http://www.valgrind.org/docs/manual/manual-core.html#manual-core.limits.
                         * Some architectures might not support long double either.
                         */

                        assert_se(fabsl(d - v.real) < 1e-10 ||
                                  fabsl((d - v.real) / v.real) < 1e-10);

                } else if (t == JSON_TOKEN_INTEGER) {
                        intmax_t i;

                        i = va_arg(ap, intmax_t);
                        assert_se(i == v.integer);

                } else if (t == JSON_TOKEN_UNSIGNED) {
                        uintmax_t u;

                        u = va_arg(ap, uintmax_t);
                        assert_se(u == v.unsig);

                } else if (t == JSON_TOKEN_BOOLEAN) {
                        bool b;

                        b = va_arg(ap, int);
                        assert_se(b == v.boolean);
                }
        }

        va_end(ap);
}

typedef void (*Test)(JsonVariant *);

static void test_variant(const char *data, Test test) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *w = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        r = json_parse(data, &v, NULL, NULL);
        assert_se(r == 0);
        assert_se(v);

        r = json_variant_format(v, 0, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));

        log_info("formatted normally: %s\n", s);

        r = json_parse(data, &w, NULL, NULL);
        assert_se(r == 0);
        assert_se(w);
        assert_se(json_variant_has_type(v, json_variant_type(w)));
        assert_se(json_variant_has_type(w, json_variant_type(v)));
        assert_se(json_variant_equal(v, w));

        s = mfree(s);
        w = json_variant_unref(w);

        r = json_variant_format(v, JSON_FORMAT_PRETTY, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));

        log_info("formatted prettily:\n%s", s);

        r = json_parse(data, &w, NULL, NULL);
        assert_se(r == 0);
        assert_se(w);

        assert_se(json_variant_has_type(v, json_variant_type(w)));
        assert_se(json_variant_has_type(w, json_variant_type(v)));
        assert_se(json_variant_equal(v, w));

        s = mfree(s);
        r = json_variant_format(v, JSON_FORMAT_COLOR, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));
        printf("Normal with color: %s\n", s);

        s = mfree(s);
        r = json_variant_format(v, JSON_FORMAT_COLOR|JSON_FORMAT_PRETTY, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));
        printf("Pretty with color:\n%s\n", s);

        if (test)
                test(v);
}

static void test_1(JsonVariant *v) {
        JsonVariant *p, *q;
        unsigned i;

        /* 3 keys + 3 values */
        assert_se(json_variant_elements(v) == 6);

        /* has k */
        p = json_variant_by_key(v, "k");
        assert_se(p && json_variant_type(p) == JSON_VARIANT_STRING);

        /* k equals v */
        assert_se(streq(json_variant_string(p), "v"));

        /* has foo */
        p = json_variant_by_key(v, "foo");
        assert_se(p && json_variant_type(p) == JSON_VARIANT_ARRAY && json_variant_elements(p) == 3);

        /* check  foo[0] = 1, foo[1] = 2, foo[2] = 3 */
        for (i = 0; i < 3; ++i) {
                q = json_variant_by_index(p, i);
                assert_se(q && json_variant_type(q) == JSON_VARIANT_UNSIGNED && json_variant_unsigned(q) == (i+1));
                assert_se(q && json_variant_has_type(q, JSON_VARIANT_INTEGER) && json_variant_integer(q) == (i+1));
        }

        /* has bar */
        p = json_variant_by_key(v, "bar");
        assert_se(p && json_variant_type(p) == JSON_VARIANT_OBJECT && json_variant_elements(p) == 2);

        /* zap is null */
        q = json_variant_by_key(p, "zap");
        assert_se(q && json_variant_type(q) == JSON_VARIANT_NULL);
}

static void test_2(JsonVariant *v) {
        JsonVariant *p, *q;

        /* 2 keys + 2 values */
        assert_se(json_variant_elements(v) == 4);

        /* has mutant */
        p = json_variant_by_key(v, "mutant");
        assert_se(p && json_variant_type(p) == JSON_VARIANT_ARRAY && json_variant_elements(p) == 4);

        /* mutant[0] == 1 */
        q = json_variant_by_index(p, 0);
        assert_se(q && json_variant_type(q) == JSON_VARIANT_UNSIGNED && json_variant_unsigned(q) == 1);
        assert_se(q && json_variant_has_type(q, JSON_VARIANT_INTEGER) && json_variant_integer(q) == 1);

        /* mutant[1] == null */
        q = json_variant_by_index(p, 1);
        assert_se(q && json_variant_type(q) == JSON_VARIANT_NULL);

        /* mutant[2] == "1" */
        q = json_variant_by_index(p, 2);
        assert_se(q && json_variant_type(q) == JSON_VARIANT_STRING && streq(json_variant_string(q), "1"));

        /* mutant[3] == JSON_VARIANT_OBJECT */
        q = json_variant_by_index(p, 3);
        assert_se(q && json_variant_type(q) == JSON_VARIANT_OBJECT && json_variant_elements(q) == 2);

        /* has 1 */
        p = json_variant_by_key(q, "1");
        assert_se(p && json_variant_type(p) == JSON_VARIANT_ARRAY && json_variant_elements(p) == 2);

        /* "1"[0] == 1 */
        q = json_variant_by_index(p, 0);
        assert_se(q && json_variant_type(q) == JSON_VARIANT_UNSIGNED && json_variant_unsigned(q) == 1);
        assert_se(q && json_variant_has_type(q, JSON_VARIANT_INTEGER) && json_variant_integer(q) == 1);

        /* "1"[1] == "1" */
        q = json_variant_by_index(p, 1);
        assert_se(q && json_variant_type(q) == JSON_VARIANT_STRING && streq(json_variant_string(q), "1"));

        /* has thisisaverylongproperty */
        p = json_variant_by_key(v, "thisisaverylongproperty");
        assert_se(p && json_variant_type(p) == JSON_VARIANT_REAL && fabsl(json_variant_real(p) - 1.27) < 0.001);
}

static void test_zeroes(JsonVariant *v) {
        size_t i;

        /* Make sure zero is how we expect it. */

        assert_se(json_variant_elements(v) == 13);

        for (i = 0; i < json_variant_elements(v); i++) {
                JsonVariant *w;
                size_t j;

                assert_se(w = json_variant_by_index(v, i));

                assert_se(json_variant_integer(w) == 0);
                assert_se(json_variant_unsigned(w) == 0U);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
                assert_se(json_variant_real(w) == 0.0L);
#pragma GCC diagnostic pop

                assert_se(json_variant_is_integer(w));
                assert_se(json_variant_is_unsigned(w));
                assert_se(json_variant_is_real(w));
                assert_se(json_variant_is_number(w));

                assert_se(!json_variant_is_negative(w));

                assert_se(IN_SET(json_variant_type(w), JSON_VARIANT_INTEGER, JSON_VARIANT_UNSIGNED, JSON_VARIANT_REAL));

                for (j = 0; j < json_variant_elements(v); j++) {
                        JsonVariant *q;

                        assert_se(q = json_variant_by_index(v, j));

                        assert_se(json_variant_equal(w, q));
                }
        }
}

static void test_build(void) {
        _cleanup_(json_variant_unrefp) JsonVariant *a = NULL, *b = NULL;
        _cleanup_free_ char *s = NULL, *t = NULL;

        assert_se(json_build(&a, JSON_BUILD_STRING("hallo")) >= 0);
        assert_se(json_build(&b, JSON_BUILD_LITERAL(" \"hallo\"   ")) >= 0);
        assert_se(json_variant_equal(a, b));

        b = json_variant_unref(b);

        assert_se(json_build(&b, JSON_BUILD_VARIANT(a)) >= 0);
        assert_se(json_variant_equal(a, b));

        b = json_variant_unref(b);
        assert_se(json_build(&b, JSON_BUILD_STRING("pief")) >= 0);
        assert_se(!json_variant_equal(a, b));

        a = json_variant_unref(a);
        b = json_variant_unref(b);

        assert_se(json_build(&a, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("one", JSON_BUILD_INTEGER(7)),
                                                   JSON_BUILD_PAIR("two", JSON_BUILD_REAL(2.0)),
                                                   JSON_BUILD_PAIR("three", JSON_BUILD_INTEGER(0)))) >= 0);

        assert_se(json_build(&b, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("two", JSON_BUILD_INTEGER(2)),
                                                   JSON_BUILD_PAIR("three", JSON_BUILD_REAL(0)),
                                                   JSON_BUILD_PAIR("one", JSON_BUILD_REAL(7)))) >= 0);

        assert_se(json_variant_equal(a, b));

        a = json_variant_unref(a);
        b = json_variant_unref(b);

        const char* arr_1234[] = {"one", "two", "three", "four", NULL};
        assert_se(json_build(&a, JSON_BUILD_ARRAY(JSON_BUILD_OBJECT(JSON_BUILD_PAIR("x", JSON_BUILD_BOOLEAN(true)),
                                                                    JSON_BUILD_PAIR("y", JSON_BUILD_OBJECT(JSON_BUILD_PAIR("this", JSON_BUILD_NULL)))),
                                                  JSON_BUILD_VARIANT(NULL),
                                                  JSON_BUILD_LITERAL(NULL),
                                                  JSON_BUILD_STRING(NULL),
                                                  JSON_BUILD_NULL,
                                                  JSON_BUILD_INTEGER(77),
                                                  JSON_BUILD_ARRAY(JSON_BUILD_VARIANT(JSON_VARIANT_STRING_CONST("foobar")),
                                                                   JSON_BUILD_VARIANT(JSON_VARIANT_STRING_CONST("zzz"))),
                                                  JSON_BUILD_STRV((char**) arr_1234))) >= 0);

        assert_se(json_variant_format(a, 0, &s) >= 0);
        log_info("GOT: %s\n", s);
        assert_se(json_parse(s, &b, NULL, NULL) >= 0);
        assert_se(json_variant_equal(a, b));

        a = json_variant_unref(a);
        b = json_variant_unref(b);

        assert_se(json_build(&a, JSON_BUILD_REAL(M_PIl)) >= 0);

        s = mfree(s);
        assert_se(json_variant_format(a, 0, &s) >= 0);
        log_info("GOT: %s\n", s);
        assert_se(json_parse(s, &b, NULL, NULL) >= 0);
        assert_se(json_variant_format(b, 0, &t) >= 0);
        log_info("GOT: %s\n", t);

        assert_se(streq(s, t));

        a = json_variant_unref(a);
        b = json_variant_unref(b);

        assert_se(json_build(&a, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR("x", JSON_BUILD_STRING("y")),
                                             JSON_BUILD_PAIR("z", JSON_BUILD_STRING("a")),
                                             JSON_BUILD_PAIR("b", JSON_BUILD_STRING("c"))
                             )) >= 0);

        assert_se(json_build(&b, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR("x", JSON_BUILD_STRING("y")),
                                             JSON_BUILD_PAIR_CONDITION(false, "p", JSON_BUILD_STRING("q")),
                                             JSON_BUILD_PAIR_CONDITION(true, "z", JSON_BUILD_STRING("a")),
                                             JSON_BUILD_PAIR_CONDITION(false, "j", JSON_BUILD_ARRAY(JSON_BUILD_STRING("k"), JSON_BUILD_STRING("u"), JSON_BUILD_STRING("i"))),
                                             JSON_BUILD_PAIR("b", JSON_BUILD_STRING("c"))
                             )) >= 0);

        assert_se(json_variant_equal(a, b));
}

static void test_source(void) {
        static const char data[] =
                "\n"
                "\n"
                "{\n"
                "\"foo\" : \"bar\", \n"
                "\"qüüx\" : [ 1, 2, 3,\n"
                "4,\n"
                "5 ],\n"
                "\"miep\" : { \"hallo\" : 1 },\n"
                "\n"
                "\"zzzzzz\" \n"
                ":\n"
                "[ true, \n"
                "false, 7.5, {} ]\n"
                "}\n";

        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        printf("--- original begin ---\n"
               "%s"
               "--- original end ---\n", data);

        assert_se(f = fmemopen_unlocked((void*) data, strlen(data), "r"));

        assert_se(json_parse_file(f, "waldo", &v, NULL, NULL) >= 0);

        printf("--- non-pretty begin ---\n");
        json_variant_dump(v, 0, stdout, NULL);
        printf("\n--- non-pretty end ---\n");

        printf("--- pretty begin ---\n");
        json_variant_dump(v, JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR|JSON_FORMAT_SOURCE, stdout, NULL);
        printf("--- pretty end ---\n");
}

static void test_depth(void) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        unsigned i;
        int r;

        v = JSON_VARIANT_STRING_CONST("start");

        /* Let's verify that the maximum depth checks work */

        for (i = 0;; i++) {
                _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;

                assert_se(i <= UINT16_MAX);
                if (i & 1)
                        r = json_variant_new_array(&w, &v, 1);
                else
                        r = json_variant_new_object(&w, (JsonVariant*[]) { JSON_VARIANT_STRING_CONST("key"), v }, 2);
                if (r == -ELNRNG) {
                        log_info("max depth at %u", i);
                        break;
                }
#if HAS_FEATURE_MEMORY_SANITIZER
                /* msan doesn't like the stack nesting to be too deep. Let's quit early. */
                if (i >= 128) {
                        log_info("quitting early at depth %u", i);
                        break;
                }
#endif

                assert_se(r >= 0);

                json_variant_unref(v);
                v = TAKE_PTR(w);
        }

        json_variant_dump(v, 0, stdout, NULL);
        fputs("\n", stdout);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_tokenizer("x", -EINVAL);
        test_tokenizer("", JSON_TOKEN_END);
        test_tokenizer(" ", JSON_TOKEN_END);
        test_tokenizer("0", JSON_TOKEN_UNSIGNED, (uintmax_t) 0, JSON_TOKEN_END);
        test_tokenizer("-0", JSON_TOKEN_INTEGER, (intmax_t) 0, JSON_TOKEN_END);
        test_tokenizer("1234", JSON_TOKEN_UNSIGNED, (uintmax_t) 1234, JSON_TOKEN_END);
        test_tokenizer("-1234", JSON_TOKEN_INTEGER, (intmax_t) -1234, JSON_TOKEN_END);
        test_tokenizer("18446744073709551615", JSON_TOKEN_UNSIGNED, (uintmax_t) UINT64_MAX, JSON_TOKEN_END);
        test_tokenizer("-9223372036854775808", JSON_TOKEN_INTEGER, (intmax_t) INT64_MIN, JSON_TOKEN_END);
        test_tokenizer("18446744073709551616", JSON_TOKEN_REAL, (long double) 18446744073709551616.0L, JSON_TOKEN_END);
        test_tokenizer("-9223372036854775809", JSON_TOKEN_REAL, (long double) -9223372036854775809.0L, JSON_TOKEN_END);
        test_tokenizer("-1234", JSON_TOKEN_INTEGER, (intmax_t) -1234, JSON_TOKEN_END);
        test_tokenizer("3.141", JSON_TOKEN_REAL, (long double) 3.141, JSON_TOKEN_END);
        test_tokenizer("0.0", JSON_TOKEN_REAL, (long double) 0.0, JSON_TOKEN_END);
        test_tokenizer("7e3", JSON_TOKEN_REAL, (long double) 7e3, JSON_TOKEN_END);
        test_tokenizer("-7e-3", JSON_TOKEN_REAL, (long double) -7e-3, JSON_TOKEN_END);
        test_tokenizer("true", JSON_TOKEN_BOOLEAN, true, JSON_TOKEN_END);
        test_tokenizer("false", JSON_TOKEN_BOOLEAN, false, JSON_TOKEN_END);
        test_tokenizer("null", JSON_TOKEN_NULL, JSON_TOKEN_END);
        test_tokenizer("{}", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer("\t {\n} \n", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer("[]", JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_END);
        test_tokenizer("\t [] \n\n", JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_END);
        test_tokenizer("\"\"", JSON_TOKEN_STRING, "", JSON_TOKEN_END);
        test_tokenizer("\"foo\"", JSON_TOKEN_STRING, "foo", JSON_TOKEN_END);
        test_tokenizer("\"foo\\nfoo\"", JSON_TOKEN_STRING, "foo\nfoo", JSON_TOKEN_END);
        test_tokenizer("{\"foo\" : \"bar\"}", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_STRING, "foo", JSON_TOKEN_COLON, JSON_TOKEN_STRING, "bar", JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer("{\"foo\" : [true, false]}", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_STRING, "foo", JSON_TOKEN_COLON, JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_BOOLEAN, true, JSON_TOKEN_COMMA, JSON_TOKEN_BOOLEAN, false, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer("\"\xef\xbf\xbd\"", JSON_TOKEN_STRING, "\xef\xbf\xbd", JSON_TOKEN_END);
        test_tokenizer("\"\\ufffd\"", JSON_TOKEN_STRING, "\xef\xbf\xbd", JSON_TOKEN_END);
        test_tokenizer("\"\\uf\"", -EINVAL);
        test_tokenizer("\"\\ud800a\"", -EINVAL);
        test_tokenizer("\"\\udc00\\udc00\"", -EINVAL);
        test_tokenizer("\"\\ud801\\udc37\"", JSON_TOKEN_STRING, "\xf0\x90\x90\xb7", JSON_TOKEN_END);

        test_tokenizer("[1, 2, -3]", JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_UNSIGNED, (uintmax_t) 1, JSON_TOKEN_COMMA, JSON_TOKEN_UNSIGNED, (uintmax_t) 2, JSON_TOKEN_COMMA, JSON_TOKEN_INTEGER, (intmax_t) -3, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_END);

        test_variant("{\"k\": \"v\", \"foo\": [1, 2, 3], \"bar\": {\"zap\": null}}", test_1);
        test_variant("{\"mutant\": [1, null, \"1\", {\"1\": [1, \"1\"]}], \"thisisaverylongproperty\": 1.27}", test_2);
        test_variant("{\"foo\" : \"\\uDBFF\\uDFFF\\\"\\uD9FF\\uDFFFFFF\\\"\\uDBFF\\uDFFF\\\"\\uD9FF\\uDFFF\\uDBFF\\uDFFFF\\uDBFF\\uDFFF\\uDBFF\\uDFFF\\uDBFF\\uDFFF\\uDBFF\\uDFFF\\\"\\uD9FF\\uDFFFFF\\\"\\uDBFF\\uDFFF\\\"\\uD9FF\\uDFFF\\uDBFF\\uDFFF\"}", NULL);

        test_variant("[ 0, -0, 0.0, -0.0, 0.000, -0.000, 0e0, -0e0, 0e+0, -0e-0, 0e-0, -0e000, 0e+000 ]", test_zeroes);

        test_build();

        test_source();

        test_depth();

        return 0;
}
