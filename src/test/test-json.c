/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <float.h>

#include "alloc-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "iovec-util.h"
#include "json-internal.h"
#include "json.h"
#include "math-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static void test_tokenizer_one(const char *data, ...) {
        unsigned line = 0, column = 0;
        void *state = NULL;
        va_list ap;

        _cleanup_free_ char *cdata = NULL;
        assert_se(cdata = cescape(data));
        log_info("/* %s data=\"%s\" */", __func__, cdata);

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
                        double d;

                        d = va_arg(ap, double);

                        assert_se(fabs(d - v.real) < 1e-10 ||
                                  fabs((d - v.real) / v.real) < 1e-10);

                } else if (t == JSON_TOKEN_INTEGER) {
                        int64_t i;

                        i = va_arg(ap, int64_t);
                        assert_se(i == v.integer);

                } else if (t == JSON_TOKEN_UNSIGNED) {
                        uint64_t u;

                        u = va_arg(ap, uint64_t);
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

static void test_variant_one(const char *data, Test test) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *w = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        _cleanup_free_ char *cdata;
        assert_se(cdata = cescape(data));
        log_info("/* %s data=\"%s\" */", __func__, cdata);

        r = json_parse(data, 0, &v, NULL, NULL);
        assert_se(r == 0);
        assert_se(v);

        r = json_variant_format(v, 0, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));

        log_info("formatted normally: %s", s);

        r = json_parse(data, JSON_PARSE_SENSITIVE, &w, NULL, NULL);
        assert_se(r == 0);
        assert_se(w);
        assert_se(json_variant_has_type(v, json_variant_type(w)));
        assert_se(json_variant_has_type(w, json_variant_type(v)));
        assert_se(json_variant_equal(v, w));

        s = mfree(s);
        r = json_variant_format(w, JSON_FORMAT_REFUSE_SENSITIVE, &s);
        assert_se(r == -EPERM);
        assert_se(!s);

        s = mfree(s);
        r = json_variant_format(w, JSON_FORMAT_PRETTY, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));

        s = mfree(s);
        w = json_variant_unref(w);

        r = json_variant_format(v, JSON_FORMAT_PRETTY, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));

        log_info("formatted prettily:\n%s", s);

        r = json_parse(data, 0, &w, NULL, NULL);
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

        log_info("/* %s */", __func__);

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

        log_info("/* %s */", __func__);

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
        assert_se(p && json_variant_type(p) == JSON_VARIANT_REAL && fabs(json_variant_real(p) - 1.27) < 0.001);
}

static void test_zeroes(JsonVariant *v) {
        /* Make sure zero is how we expect it. */
        log_info("/* %s */", __func__);

        assert_se(json_variant_elements(v) == 13);

        for (size_t i = 0; i < json_variant_elements(v); i++) {
                JsonVariant *w;
                size_t j;

                assert_se(w = json_variant_by_index(v, i));

                assert_se(json_variant_integer(w) == 0);
                assert_se(json_variant_unsigned(w) == 0U);

                assert_se(iszero_safe(json_variant_real(w)));

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

TEST(build) {
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
        log_info("GOT: %s", s);
        assert_se(json_parse(s, 0, &b, NULL, NULL) >= 0);
        assert_se(json_variant_equal(a, b));

        a = json_variant_unref(a);
        b = json_variant_unref(b);

        assert_se(json_build(&a, JSON_BUILD_REAL(M_PI)) >= 0);

        s = mfree(s);
        assert_se(json_variant_format(a, 0, &s) >= 0);
        log_info("GOT: %s", s);
        assert_se(json_parse(s, 0, &b, NULL, NULL) >= 0);
        assert_se(json_variant_format(b, 0, &t) >= 0);
        log_info("GOT: %s", t);

        assert_se(streq(s, t));

        a = json_variant_unref(a);
        b = json_variant_unref(b);

        assert_se(json_build(&a, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR("x", JSON_BUILD_STRING("y")),
                                             JSON_BUILD_PAIR("z", JSON_BUILD_CONST_STRING("a")),
                                             JSON_BUILD_PAIR("b", JSON_BUILD_CONST_STRING("c"))
                             )) >= 0);

        assert_se(json_build(&b, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR("x", JSON_BUILD_STRING("y")),
                                             JSON_BUILD_PAIR_CONDITION(false, "p", JSON_BUILD_STRING("q")),
                                             JSON_BUILD_PAIR_CONDITION(true, "z", JSON_BUILD_CONST_STRING("a")),
                                             JSON_BUILD_PAIR_CONDITION(false, "j", JSON_BUILD_ARRAY(JSON_BUILD_STRING("k"), JSON_BUILD_CONST_STRING("u"), JSON_BUILD_CONST_STRING("i"))),
                                             JSON_BUILD_PAIR("b", JSON_BUILD_CONST_STRING("c"))
                             )) >= 0);

        assert_se(json_variant_equal(a, b));
}

TEST(json_parse_file_empty) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        assert_se(fopen_unlocked("/dev/null", "re", &f) >= 0);
        assert_se(json_parse_file(f, "waldo", 0, &v, NULL, NULL) == -ENODATA);
        assert_se(v == NULL);
}

TEST(json_parse_file_invalid) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        assert_se(f = fmemopen_unlocked((void*) "kookoo", 6, "r"));
        assert_se(json_parse_file(f, "waldo", 0, &v, NULL, NULL) == -EINVAL);
        assert_se(v == NULL);
}

TEST(source) {
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

        assert_se(json_parse_file(f, "waldo", 0, &v, NULL, NULL) >= 0);

        printf("--- non-pretty begin ---\n");
        json_variant_dump(v, 0, stdout, NULL);
        printf("\n--- non-pretty end ---\n");

        printf("--- pretty begin ---\n");
        json_variant_dump(v, JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR|JSON_FORMAT_SOURCE, stdout, NULL);
        printf("--- pretty end ---\n");
}

TEST(depth) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        v = JSON_VARIANT_STRING_CONST("start");

        /* Let's verify that the maximum depth checks work */

        for (unsigned i = 0;; i++) {
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

TEST(normalize) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *w = NULL;
        _cleanup_free_ char *t = NULL;

        assert_se(json_build(&v, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR("b", JSON_BUILD_STRING("x")),
                                             JSON_BUILD_PAIR("c", JSON_BUILD_CONST_STRING("y")),
                                             JSON_BUILD_PAIR("a", JSON_BUILD_CONST_STRING("z")))) >= 0);

        assert_se(!json_variant_is_sorted(v));
        assert_se(!json_variant_is_normalized(v));

        assert_se(json_variant_format(v, 0, &t) >= 0);
        assert_se(streq(t, "{\"b\":\"x\",\"c\":\"y\",\"a\":\"z\"}"));
        t = mfree(t);

        assert_se(json_build(&w, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR("bar", JSON_BUILD_STRING("zzz")),
                                             JSON_BUILD_PAIR("foo", JSON_BUILD_VARIANT(v)))) >= 0);

        assert_se(json_variant_is_sorted(w));
        assert_se(!json_variant_is_normalized(w));

        assert_se(json_variant_format(w, 0, &t) >= 0);
        assert_se(streq(t, "{\"bar\":\"zzz\",\"foo\":{\"b\":\"x\",\"c\":\"y\",\"a\":\"z\"}}"));
        t = mfree(t);

        assert_se(json_variant_sort(&v) >= 0);
        assert_se(json_variant_is_sorted(v));
        assert_se(json_variant_is_normalized(v));

        assert_se(json_variant_format(v, 0, &t) >= 0);
        assert_se(streq(t, "{\"a\":\"z\",\"b\":\"x\",\"c\":\"y\"}"));
        t = mfree(t);

        assert_se(json_variant_normalize(&w) >= 0);
        assert_se(json_variant_is_sorted(w));
        assert_se(json_variant_is_normalized(w));

        assert_se(json_variant_format(w, 0, &t) >= 0);
        assert_se(streq(t, "{\"bar\":\"zzz\",\"foo\":{\"a\":\"z\",\"b\":\"x\",\"c\":\"y\"}}"));
        t = mfree(t);
}

TEST(bisect) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        /* Tests the bisection logic in json_variant_by_key() */

        for (char c = 'z'; c >= 'a'; c--) {

                if ((c % 3) == 0)
                        continue;

                _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
                assert_se(json_variant_new_stringn(&w, (char[4]) { '<', c, c, '>' }, 4) >= 0);
                assert_se(json_variant_set_field(&v, (char[2]) { c, 0 }, w) >= 0);
        }

        json_variant_dump(v, JSON_FORMAT_COLOR|JSON_FORMAT_PRETTY, NULL, NULL);

        assert_se(!json_variant_is_sorted(v));
        assert_se(!json_variant_is_normalized(v));
        assert_se(json_variant_normalize(&v) >= 0);
        assert_se(json_variant_is_sorted(v));
        assert_se(json_variant_is_normalized(v));

        json_variant_dump(v, JSON_FORMAT_COLOR|JSON_FORMAT_PRETTY, NULL, NULL);

        for (char c = 'a'; c <= 'z'; c++) {
                JsonVariant *k;
                const char *z;

                k = json_variant_by_key(v, (char[2]) { c, 0 });
                assert_se(!k == ((c % 3) == 0));

                if (!k)
                        continue;

                assert_se(json_variant_is_string(k));

                z = (char[5]){ '<', c, c, '>', 0};
                assert_se(streq(json_variant_string(k), z));
        }
}

static void test_float_match(JsonVariant *v) {
        const double delta = 0.0001;

        assert_se(json_variant_is_array(v));
        assert_se(json_variant_elements(v) == 11);
        assert_se(fabs(1.0 - (DBL_MIN / json_variant_real(json_variant_by_index(v, 0)))) <= delta);
        assert_se(fabs(1.0 - (DBL_MAX / json_variant_real(json_variant_by_index(v, 1)))) <= delta);
        assert_se(json_variant_is_null(json_variant_by_index(v, 2))); /* nan is not supported by json → null */
        assert_se(json_variant_is_null(json_variant_by_index(v, 3))); /* +inf is not supported by json → null */
        assert_se(json_variant_is_null(json_variant_by_index(v, 4))); /* -inf is not supported by json → null */
        assert_se(json_variant_is_null(json_variant_by_index(v, 5)) ||
                  fabs(1.0 - (HUGE_VAL / json_variant_real(json_variant_by_index(v, 5)))) <= delta); /* HUGE_VAL might be +inf, but might also be something else */
        assert_se(json_variant_is_real(json_variant_by_index(v, 6)) &&
                  json_variant_is_integer(json_variant_by_index(v, 6)) &&
                  json_variant_integer(json_variant_by_index(v, 6)) == 0);
        assert_se(json_variant_is_real(json_variant_by_index(v, 7)) &&
                  json_variant_is_integer(json_variant_by_index(v, 7)) &&
                  json_variant_integer(json_variant_by_index(v, 7)) == 10);
        assert_se(json_variant_is_real(json_variant_by_index(v, 8)) &&
                  json_variant_is_integer(json_variant_by_index(v, 8)) &&
                  json_variant_integer(json_variant_by_index(v, 8)) == -10);
        assert_se(json_variant_is_real(json_variant_by_index(v, 9)) &&
                  !json_variant_is_integer(json_variant_by_index(v, 9)));
        assert_se(fabs(1.0 - (DBL_MIN / 2 / json_variant_real(json_variant_by_index(v, 9)))) <= delta);
        assert_se(json_variant_is_real(json_variant_by_index(v, 10)) &&
                  !json_variant_is_integer(json_variant_by_index(v, 10)));
        assert_se(fabs(1.0 - (-DBL_MIN / 2 / json_variant_real(json_variant_by_index(v, 10)))) <= delta);
}

TEST(float) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *w = NULL;
        _cleanup_free_ char *text = NULL;

        assert_se(json_build(&v, JSON_BUILD_ARRAY(
                                             JSON_BUILD_REAL(DBL_MIN),
                                             JSON_BUILD_REAL(DBL_MAX),
                                             JSON_BUILD_REAL(NAN),
                                             JSON_BUILD_REAL(INFINITY),
                                             JSON_BUILD_REAL(-INFINITY),
                                             JSON_BUILD_REAL(HUGE_VAL),
                                             JSON_BUILD_REAL(0),
                                             JSON_BUILD_REAL(10),
                                             JSON_BUILD_REAL(-10),
                                             JSON_BUILD_REAL(DBL_MIN / 2),
                                             JSON_BUILD_REAL(-DBL_MIN / 2))) >= 0);

        json_variant_dump(v, JSON_FORMAT_COLOR|JSON_FORMAT_PRETTY, NULL, NULL);

        test_float_match(v);

        assert_se(json_variant_format(v, 0, &text) >= 0);
        assert_se(json_parse(text, 0, &w, NULL, NULL) >= 0);

        json_variant_dump(w, JSON_FORMAT_COLOR|JSON_FORMAT_PRETTY, NULL, NULL);

        test_float_match(w);
}

static void test_equal_text(JsonVariant *v, const char *text) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;

        assert_se(json_parse(text, 0, &w, NULL, NULL) >= 0);
        assert_se(json_variant_equal(v, w) || (!v && json_variant_is_null(w)));
}

TEST(set_field) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        test_equal_text(v, "null");
        assert_se(json_variant_set_field(&v, "foo", NULL) >= 0);
        test_equal_text(v, "{\"foo\" : null}");
        assert_se(json_variant_set_field(&v, "bar", JSON_VARIANT_STRING_CONST("quux")) >= 0);
        test_equal_text(v, "{\"foo\" : null, \"bar\" : \"quux\"}");
        assert_se(json_variant_set_field(&v, "foo", JSON_VARIANT_STRING_CONST("quux2")) >= 0);
        test_equal_text(v, "{\"foo\" : \"quux2\", \"bar\" : \"quux\"}");
        assert_se(json_variant_set_field(&v, "bar", NULL) >= 0);
        test_equal_text(v, "{\"foo\" : \"quux2\", \"bar\" : null}");
}

TEST(tokenizer) {
        test_tokenizer_one("x", -EINVAL);
        test_tokenizer_one("", JSON_TOKEN_END);
        test_tokenizer_one(" ", JSON_TOKEN_END);
        test_tokenizer_one("0", JSON_TOKEN_UNSIGNED, (uint64_t) 0, JSON_TOKEN_END);
        test_tokenizer_one("-0", JSON_TOKEN_INTEGER, (int64_t) 0, JSON_TOKEN_END);
        test_tokenizer_one("1234", JSON_TOKEN_UNSIGNED, (uint64_t) 1234, JSON_TOKEN_END);
        test_tokenizer_one("-1234", JSON_TOKEN_INTEGER, (int64_t) -1234, JSON_TOKEN_END);
        test_tokenizer_one("18446744073709551615", JSON_TOKEN_UNSIGNED, (uint64_t) UINT64_MAX, JSON_TOKEN_END);
        test_tokenizer_one("-9223372036854775808", JSON_TOKEN_INTEGER, (int64_t) INT64_MIN, JSON_TOKEN_END);
        test_tokenizer_one("18446744073709551616", JSON_TOKEN_REAL, (double) 18446744073709551616.0L, JSON_TOKEN_END);
        test_tokenizer_one("-9223372036854775809", JSON_TOKEN_REAL, (double) -9223372036854775809.0L, JSON_TOKEN_END);
        test_tokenizer_one("-1234", JSON_TOKEN_INTEGER, (int64_t) -1234, JSON_TOKEN_END);
        test_tokenizer_one("3.141", JSON_TOKEN_REAL, (double) 3.141, JSON_TOKEN_END);
        test_tokenizer_one("0.0", JSON_TOKEN_REAL, (double) 0.0, JSON_TOKEN_END);
        test_tokenizer_one("7e3", JSON_TOKEN_REAL, (double) 7e3, JSON_TOKEN_END);
        test_tokenizer_one("-7e-3", JSON_TOKEN_REAL, (double) -7e-3, JSON_TOKEN_END);
        test_tokenizer_one("true", JSON_TOKEN_BOOLEAN, true, JSON_TOKEN_END);
        test_tokenizer_one("false", JSON_TOKEN_BOOLEAN, false, JSON_TOKEN_END);
        test_tokenizer_one("null", JSON_TOKEN_NULL, JSON_TOKEN_END);
        test_tokenizer_one("{}", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer_one("\t {\n} \n", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer_one("[]", JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_END);
        test_tokenizer_one("\t [] \n\n", JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_END);
        test_tokenizer_one("\"\"", JSON_TOKEN_STRING, "", JSON_TOKEN_END);
        test_tokenizer_one("\"foo\"", JSON_TOKEN_STRING, "foo", JSON_TOKEN_END);
        test_tokenizer_one("\"foo\\nfoo\"", JSON_TOKEN_STRING, "foo\nfoo", JSON_TOKEN_END);
        test_tokenizer_one("{\"foo\" : \"bar\"}", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_STRING, "foo", JSON_TOKEN_COLON, JSON_TOKEN_STRING, "bar", JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer_one("{\"foo\" : [true, false]}", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_STRING, "foo", JSON_TOKEN_COLON, JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_BOOLEAN, true, JSON_TOKEN_COMMA, JSON_TOKEN_BOOLEAN, false, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer_one("\"\xef\xbf\xbd\"", JSON_TOKEN_STRING, "\xef\xbf\xbd", JSON_TOKEN_END);
        test_tokenizer_one("\"\\ufffd\"", JSON_TOKEN_STRING, "\xef\xbf\xbd", JSON_TOKEN_END);
        test_tokenizer_one("\"\\uf\"", -EINVAL);
        test_tokenizer_one("\"\\ud800a\"", -EINVAL);
        test_tokenizer_one("\"\\udc00\\udc00\"", -EINVAL);
        test_tokenizer_one("\"\\ud801\\udc37\"", JSON_TOKEN_STRING, "\xf0\x90\x90\xb7", JSON_TOKEN_END);

        test_tokenizer_one("[1, 2, -3]", JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_UNSIGNED, (uint64_t) 1, JSON_TOKEN_COMMA, JSON_TOKEN_UNSIGNED, (uint64_t) 2, JSON_TOKEN_COMMA, JSON_TOKEN_INTEGER, (int64_t) -3, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_END);
}

TEST(variant) {
        test_variant_one("{\"k\": \"v\", \"foo\": [1, 2, 3], \"bar\": {\"zap\": null}}", test_1);
        test_variant_one("{\"mutant\": [1, null, \"1\", {\"1\": [1, \"1\"]}], \"thisisaverylongproperty\": 1.27}", test_2);
        test_variant_one("{\"foo\" : \"\\u0935\\u093f\\u0935\\u0947\\u0915\\u0916\\u094d\\u092f\\u093e\\u0924\\u093f\\u0930\\u0935\\u093f\\u092a\\u094d\\u0932\\u0935\\u093e\\u0020\\u0939\\u093e\\u0928\\u094b\\u092a\\u093e\\u092f\\u0903\\u0964\"}", NULL);

        test_variant_one("[ 0, -0, 0.0, -0.0, 0.000, -0.000, 0e0, -0e0, 0e+0, -0e-0, 0e-0, -0e000, 0e+000 ]", test_zeroes);
}

TEST(json_variant_merge_objectb) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *w = NULL;

        assert_se(json_build(&v, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR("b", JSON_BUILD_STRING("x")),
                                             JSON_BUILD_PAIR("c", JSON_BUILD_CONST_STRING("y")),
                                             JSON_BUILD_PAIR("a", JSON_BUILD_CONST_STRING("z")))) >= 0);

        assert_se(json_variant_merge_objectb(&w, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("b", JSON_BUILD_STRING("x")))) >= 0);
        assert_se(json_variant_merge_objectb(&w, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("c", JSON_BUILD_STRING("y")))) >= 0);
        assert_se(json_variant_merge_objectb(&w, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("a", JSON_BUILD_STRING("z")))) >= 0);

        assert_se(json_variant_equal(v, w));
}

static void json_array_append_with_source_one(bool source) {
        _cleanup_(json_variant_unrefp) JsonVariant *a, *b;

        /* Parse two sources, each with a different name and line/column numbers */

        assert_se(json_parse_with_source(" [41]", source ? "string 1" : NULL, 0,
                                         &a, NULL, NULL) >= 0);
        assert_se(json_parse_with_source("\n\n   [42]", source ? "string 2" : NULL, 0,
                                         &b, NULL, NULL) >= 0);

        assert_se(json_variant_is_array(a));
        assert_se(json_variant_elements(a) == 1);
        assert_se(json_variant_is_array(b));
        assert_se(json_variant_elements(b) == 1);

        /* Verify source information */

        const char *s1, *s2;
        unsigned line1, col1, line2, col2;
        assert_se(json_variant_get_source(a, &s1, &line1, &col1) >= 0);
        assert_se(json_variant_get_source(b, &s2, &line2, &col2) >= 0);

        assert_se(streq_ptr(s1, source ? "string 1" : NULL));
        assert_se(streq_ptr(s2, source ? "string 2" : NULL));
        assert_se(line1 == 1);
        assert_se(col1 == 2);
        assert_se(line2 == 3);
        assert_se(col2 == 4);

        /* Append one elem from the second array (and source) to the first. */

        JsonVariant *elem;
        assert_se(elem = json_variant_by_index(b, 0));
        assert_se(json_variant_is_integer(elem));
        assert_se(json_variant_elements(elem) == 0);

        assert_se(json_variant_append_array(&a, elem) >= 0);

        assert_se(json_variant_is_array(a));
        assert_se(json_variant_elements(a) == 2);

        /* Verify that source information was propagated correctly */

        assert_se(json_variant_get_source(elem, &s1, &line1, &col1) >= 0);
        assert_se(elem = json_variant_by_index(a, 1));
        assert_se(json_variant_get_source(elem, &s2, &line2, &col2) >= 0);

        assert_se(streq_ptr(s1, source ? "string 2" : NULL));
        assert_se(streq_ptr(s2, source ? "string 2" : NULL));
        assert_se(line1 == 3);
        assert_se(col1 == 5);
        assert_se(line2 == 3);
        assert_se(col2 == 5);
}

TEST(json_array_append_with_source) {
        json_array_append_with_source_one(true);
}

TEST(json_array_append_without_source) {
        json_array_append_with_source_one(false);
}

TEST(json_array_append_nodup) {
        _cleanup_(json_variant_unrefp) JsonVariant *l = NULL, *s = NULL, *wd = NULL, *nd = NULL;

        assert_se(json_build(&l, JSON_BUILD_STRV(STRV_MAKE("foo", "bar", "baz", "bar", "baz", "foo", "qux", "baz"))) >= 0);
        assert_se(json_build(&s, JSON_BUILD_STRV(STRV_MAKE("foo", "bar", "baz", "qux"))) >= 0);

        assert_se(!json_variant_equal(l, s));
        assert_se(json_variant_elements(l) == 8);
        assert_se(json_variant_elements(s) == 4);

        JsonVariant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, l) {
                assert_se(json_variant_append_array(&wd, i) >= 0);
                assert_se(json_variant_append_array_nodup(&nd, i) >= 0);
        }

        assert_se(json_variant_elements(wd) == 8);
        assert_se(json_variant_equal(l, wd));
        assert_se(!json_variant_equal(s, wd));

        assert_se(json_variant_elements(nd) == 4);
        assert_se(!json_variant_equal(l, nd));
        assert_se(json_variant_equal(s, nd));
}

TEST(json_dispatch) {
        struct foobar {
                uint64_t a, b;
                int64_t c, d;
                uint32_t e, f;
                int32_t g, h;
                uint16_t i, j;
                int16_t k, l;
        } foobar = {};

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        assert_se(json_build(&v, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR("a", JSON_BUILD_UNSIGNED(UINT64_MAX)),
                                             JSON_BUILD_PAIR("b", JSON_BUILD_STRING("18446744073709551615")),
                                             JSON_BUILD_PAIR("c", JSON_BUILD_INTEGER(INT64_MIN)),
                                             JSON_BUILD_PAIR("d", JSON_BUILD_STRING("-9223372036854775808")),
                                             JSON_BUILD_PAIR("e", JSON_BUILD_UNSIGNED(UINT32_MAX)),
                                             JSON_BUILD_PAIR("f", JSON_BUILD_STRING("4294967295")),
                                             JSON_BUILD_PAIR("g", JSON_BUILD_INTEGER(INT32_MIN)),
                                             JSON_BUILD_PAIR("h", JSON_BUILD_STRING("-2147483648")),
                                             JSON_BUILD_PAIR("i", JSON_BUILD_UNSIGNED(UINT16_MAX)),
                                             JSON_BUILD_PAIR("j", JSON_BUILD_STRING("65535")),
                                             JSON_BUILD_PAIR("k", JSON_BUILD_INTEGER(INT16_MIN)),
                                             JSON_BUILD_PAIR("l", JSON_BUILD_STRING("-32768")))) >= 0);

        assert_se(json_variant_dump(v, JSON_FORMAT_PRETTY_AUTO|JSON_FORMAT_COLOR_AUTO, stdout, /* prefix= */ NULL) >= 0);

        JsonDispatch table[] = {
                { "a", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64, offsetof(struct foobar, a) },
                { "b", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64, offsetof(struct foobar, b) },
                { "c", _JSON_VARIANT_TYPE_INVALID, json_dispatch_int64,  offsetof(struct foobar, c) },
                { "d", _JSON_VARIANT_TYPE_INVALID, json_dispatch_int64,  offsetof(struct foobar, d) },
                { "e", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint32, offsetof(struct foobar, e) },
                { "f", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint32, offsetof(struct foobar, f) },
                { "g", _JSON_VARIANT_TYPE_INVALID, json_dispatch_int32,  offsetof(struct foobar, g) },
                { "h", _JSON_VARIANT_TYPE_INVALID, json_dispatch_int32,  offsetof(struct foobar, h) },
                { "i", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint16, offsetof(struct foobar, i) },
                { "j", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint16, offsetof(struct foobar, j) },
                { "k", _JSON_VARIANT_TYPE_INVALID, json_dispatch_int16,  offsetof(struct foobar, k) },
                { "l", _JSON_VARIANT_TYPE_INVALID, json_dispatch_int16,  offsetof(struct foobar, l) },
                {}
        };

        assert_se(json_dispatch(v, table, JSON_LOG, &foobar) >= 0);

        assert_se(foobar.a == UINT64_MAX);
        assert_se(foobar.b == UINT64_MAX);
        assert_se(foobar.c == INT64_MIN);
        assert_se(foobar.d == INT64_MIN);

        assert_se(foobar.e == UINT32_MAX);
        assert_se(foobar.f == UINT32_MAX);
        assert_se(foobar.g == INT32_MIN);
        assert_se(foobar.h == INT32_MIN);

        assert_se(foobar.i == UINT16_MAX);
        assert_se(foobar.j == UINT16_MAX);
        assert_se(foobar.k == INT16_MIN);
        assert_se(foobar.l == INT16_MIN);
}

TEST(json_sensitive) {
        _cleanup_(json_variant_unrefp) JsonVariant *a = NULL, *b = NULL, *v = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        assert_se(json_build(&a, JSON_BUILD_STRV(STRV_MAKE("foo", "bar", "baz", "bar", "baz", "foo", "qux", "baz"))) >= 0);
        assert_se(json_build(&b, JSON_BUILD_STRV(STRV_MAKE("foo", "bar", "baz", "qux"))) >= 0);

        json_variant_sensitive(a);

        assert_se(json_variant_format(a, JSON_FORMAT_REFUSE_SENSITIVE, &s) == -EPERM);
        assert_se(!s);

        r = json_variant_format(b, JSON_FORMAT_REFUSE_SENSITIVE, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));
        s = mfree(s);

        assert_se(json_build(&v, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR("c", JSON_BUILD_INTEGER(INT64_MIN)),
                                             JSON_BUILD_PAIR("d", JSON_BUILD_STRING("-9223372036854775808")),
                                             JSON_BUILD_PAIR("e", JSON_BUILD_EMPTY_OBJECT))) >= 0);
        json_variant_dump(v, JSON_FORMAT_COLOR|JSON_FORMAT_PRETTY, NULL, NULL);

        r = json_variant_format(v, JSON_FORMAT_REFUSE_SENSITIVE, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));
        s = mfree(s);
        v = json_variant_unref(v);

        assert_se(json_build(&v, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR_VARIANT("b", b),
                                             JSON_BUILD_PAIR("c", JSON_BUILD_INTEGER(INT64_MIN)),
                                             JSON_BUILD_PAIR("d", JSON_BUILD_STRING("-9223372036854775808")),
                                             JSON_BUILD_PAIR("e", JSON_BUILD_EMPTY_OBJECT))) >= 0);
        json_variant_dump(v, JSON_FORMAT_COLOR|JSON_FORMAT_PRETTY, NULL, NULL);

        r = json_variant_format(v, JSON_FORMAT_REFUSE_SENSITIVE, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));
        s = mfree(s);
        v = json_variant_unref(v);

        assert_se(json_build(&v, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR_VARIANT("b", b),
                                             JSON_BUILD_PAIR_VARIANT("a", a),
                                             JSON_BUILD_PAIR("c", JSON_BUILD_INTEGER(INT64_MIN)),
                                             JSON_BUILD_PAIR("d", JSON_BUILD_STRING("-9223372036854775808")),
                                             JSON_BUILD_PAIR("e", JSON_BUILD_EMPTY_OBJECT))) >= 0);
        json_variant_dump(v, JSON_FORMAT_COLOR|JSON_FORMAT_PRETTY, NULL, NULL);

        assert_se(json_variant_format(v, JSON_FORMAT_REFUSE_SENSITIVE, &s) == -EPERM);
        assert_se(!s);
        v = json_variant_unref(v);

        assert_se(json_build(&v, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR_VARIANT("b", b),
                                             JSON_BUILD_PAIR("c", JSON_BUILD_INTEGER(INT64_MIN)),
                                             JSON_BUILD_PAIR_VARIANT("a", a),
                                             JSON_BUILD_PAIR("d", JSON_BUILD_STRING("-9223372036854775808")),
                                             JSON_BUILD_PAIR("e", JSON_BUILD_EMPTY_OBJECT))) >= 0);
        json_variant_dump(v, JSON_FORMAT_COLOR|JSON_FORMAT_PRETTY, NULL, NULL);

        assert_se(json_variant_format(v, JSON_FORMAT_REFUSE_SENSITIVE, &s) == -EPERM);
        assert_se(!s);
        v = json_variant_unref(v);

        assert_se(json_build(&v, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR_VARIANT("b", b),
                                             JSON_BUILD_PAIR("c", JSON_BUILD_INTEGER(INT64_MIN)),
                                             JSON_BUILD_PAIR("d", JSON_BUILD_STRING("-9223372036854775808")),
                                             JSON_BUILD_PAIR_VARIANT("a", a),
                                             JSON_BUILD_PAIR("e", JSON_BUILD_EMPTY_OBJECT))) >= 0);
        json_variant_dump(v, JSON_FORMAT_COLOR|JSON_FORMAT_PRETTY, NULL, NULL);

        assert_se(json_variant_format(v, JSON_FORMAT_REFUSE_SENSITIVE, &s) == -EPERM);
        assert_se(!s);
        v = json_variant_unref(v);

        assert_se(json_build(&v, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR_VARIANT("b", b),
                                             JSON_BUILD_PAIR("c", JSON_BUILD_INTEGER(INT64_MIN)),
                                             JSON_BUILD_PAIR("d", JSON_BUILD_STRING("-9223372036854775808")),
                                             JSON_BUILD_PAIR("e", JSON_BUILD_EMPTY_OBJECT),
                                             JSON_BUILD_PAIR_VARIANT("a", a))) >= 0);
        json_variant_dump(v, JSON_FORMAT_COLOR|JSON_FORMAT_PRETTY, NULL, NULL);

        assert_se(json_variant_format(v, JSON_FORMAT_REFUSE_SENSITIVE, &s) == -EPERM);
        assert_se(!s);
}

TEST(json_iovec) {
        struct iovec iov1 = CONST_IOVEC_MAKE_STRING("üxknürz"), iov2 = CONST_IOVEC_MAKE_STRING("wuffwuffmiau");

        _cleanup_(json_variant_unrefp) JsonVariant *j = NULL;
        assert_se(json_build(&j, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR("nr1", JSON_BUILD_IOVEC_BASE64(&iov1)),
                                             JSON_BUILD_PAIR("nr2", JSON_BUILD_IOVEC_HEX(&iov2)))) >= 0);

        json_variant_dump(j, JSON_FORMAT_PRETTY_AUTO|JSON_FORMAT_COLOR_AUTO, /* f= */ NULL, /* prefix= */ NULL);

        _cleanup_(iovec_done) struct iovec a = {}, b = {};
        assert_se(json_variant_unbase64_iovec(json_variant_by_key(j, "nr1"), &a) >= 0);
        assert_se(json_variant_unhex_iovec(json_variant_by_key(j, "nr2"), &b) >= 0);

        assert_se(iovec_memcmp(&iov1, &a) == 0);
        assert_se(iovec_memcmp(&iov2, &b) == 0);
        assert_se(iovec_memcmp(&iov2, &a) < 0);
        assert_se(iovec_memcmp(&iov1, &b) > 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
