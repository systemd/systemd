/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <float.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "escape.h"
#include "fd-util.h"
#include "format-util.h"
#include "fileio.h"
#include "iovec-util.h"
#include "json-internal.h"
#include "json-util.h"
#include "math-util.h"
#include "ordered-set.h"
#include "pidref.h"
#include "set.h"
#include "string-table.h"
#include "tests.h"
#include "tmpfile-util.h"

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
                        ASSERT_STREQ(nn, str);

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

typedef void (*Test)(sd_json_variant *);

static void test_variant_one(const char *data, Test test) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        _cleanup_free_ char *cdata;
        assert_se(cdata = cescape(data));
        log_info("/* %s data=\"%s\" */", __func__, cdata);

        r = sd_json_parse(data, 0, &v, NULL, NULL);
        assert_se(r == 0);
        assert_se(v);

        r = sd_json_variant_format(v, 0, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));

        log_info("formatted normally: %s", s);

        r = sd_json_parse(data, SD_JSON_PARSE_SENSITIVE, &w, NULL, NULL);
        assert_se(r == 0);
        assert_se(w);
        assert_se(sd_json_variant_has_type(v, sd_json_variant_type(w)));
        assert_se(sd_json_variant_has_type(w, sd_json_variant_type(v)));
        assert_se(sd_json_variant_equal(v, w));

        s = mfree(s);
        r = sd_json_variant_format(w, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s);
        assert_se(s);
        ASSERT_STREQ(s, "\"<sensitive data>\"");

        s = mfree(s);
        r = sd_json_variant_format(w, SD_JSON_FORMAT_PRETTY, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));

        s = mfree(s);
        w = sd_json_variant_unref(w);

        r = sd_json_variant_format(v, SD_JSON_FORMAT_PRETTY, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));

        log_info("formatted prettily:\n%s", s);

        r = sd_json_parse(data, 0, &w, NULL, NULL);
        assert_se(r == 0);
        assert_se(w);

        assert_se(sd_json_variant_has_type(v, sd_json_variant_type(w)));
        assert_se(sd_json_variant_has_type(w, sd_json_variant_type(v)));
        assert_se(sd_json_variant_equal(v, w));

        s = mfree(s);
        r = sd_json_variant_format(v, SD_JSON_FORMAT_COLOR, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));
        printf("Normal with color: %s\n", s);

        s = mfree(s);
        r = sd_json_variant_format(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));
        printf("Pretty with color:\n%s\n", s);

        if (test)
                test(v);
}

static void test_1(sd_json_variant *v) {
        sd_json_variant *p, *q;
        unsigned i;

        log_info("/* %s */", __func__);

        /* 3 keys + 3 values */
        assert_se(sd_json_variant_elements(v) == 6);

        /* has k */
        p = sd_json_variant_by_key(v, "k");
        assert_se(p && sd_json_variant_type(p) == SD_JSON_VARIANT_STRING);

        /* k equals v */
        ASSERT_STREQ(sd_json_variant_string(p), "v");

        /* has foo */
        p = sd_json_variant_by_key(v, "foo");
        assert_se(p && sd_json_variant_type(p) == SD_JSON_VARIANT_ARRAY && sd_json_variant_elements(p) == 3);

        /* check  foo[0] = 1, foo[1] = 2, foo[2] = 3 */
        for (i = 0; i < 3; ++i) {
                q = sd_json_variant_by_index(p, i);
                assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_UNSIGNED && sd_json_variant_unsigned(q) == (i+1));
                assert_se(q && sd_json_variant_has_type(q, SD_JSON_VARIANT_INTEGER) && sd_json_variant_integer(q) == (i+1));
        }

        /* has bar */
        p = sd_json_variant_by_key(v, "bar");
        assert_se(p && sd_json_variant_type(p) == SD_JSON_VARIANT_OBJECT && sd_json_variant_elements(p) == 2);

        /* zap is null */
        q = sd_json_variant_by_key(p, "zap");
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_NULL);
}

static void test_2(sd_json_variant *v) {
        sd_json_variant *p, *q;

        log_info("/* %s */", __func__);

        /* 2 keys + 2 values */
        assert_se(sd_json_variant_elements(v) == 4);

        /* has mutant */
        p = sd_json_variant_by_key(v, "mutant");
        assert_se(p && sd_json_variant_type(p) == SD_JSON_VARIANT_ARRAY && sd_json_variant_elements(p) == 4);

        /* mutant[0] == 1 */
        q = sd_json_variant_by_index(p, 0);
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_UNSIGNED && sd_json_variant_unsigned(q) == 1);
        assert_se(q && sd_json_variant_has_type(q, SD_JSON_VARIANT_INTEGER) && sd_json_variant_integer(q) == 1);

        /* mutant[1] == null */
        q = sd_json_variant_by_index(p, 1);
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_NULL);

        /* mutant[2] == "1" */
        q = sd_json_variant_by_index(p, 2);
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_STRING && streq(sd_json_variant_string(q), "1"));

        /* mutant[3] == SD_JSON_VARIANT_OBJECT */
        q = sd_json_variant_by_index(p, 3);
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_OBJECT && sd_json_variant_elements(q) == 2);

        /* has 1 */
        p = sd_json_variant_by_key(q, "1");
        assert_se(p && sd_json_variant_type(p) == SD_JSON_VARIANT_ARRAY && sd_json_variant_elements(p) == 2);

        /* "1"[0] == 1 */
        q = sd_json_variant_by_index(p, 0);
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_UNSIGNED && sd_json_variant_unsigned(q) == 1);
        assert_se(q && sd_json_variant_has_type(q, SD_JSON_VARIANT_INTEGER) && sd_json_variant_integer(q) == 1);

        /* "1"[1] == "1" */
        q = sd_json_variant_by_index(p, 1);
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_STRING && streq(sd_json_variant_string(q), "1"));

        /* has thisisaverylongproperty */
        p = sd_json_variant_by_key(v, "thisisaverylongproperty");
        assert_se(p && sd_json_variant_type(p) == SD_JSON_VARIANT_REAL && fabs(sd_json_variant_real(p) - 1.27) < 0.001);
}

static void test_zeroes(sd_json_variant *v) {
        /* Make sure zero is how we expect it. */
        log_info("/* %s */", __func__);

        assert_se(sd_json_variant_elements(v) == 13);

        for (size_t i = 0; i < sd_json_variant_elements(v); i++) {
                sd_json_variant *w;
                size_t j;

                assert_se(w = sd_json_variant_by_index(v, i));

                assert_se(sd_json_variant_integer(w) == 0);
                assert_se(sd_json_variant_unsigned(w) == 0U);

                assert_se(iszero_safe(sd_json_variant_real(w)));

                assert_se(sd_json_variant_is_integer(w));
                assert_se(sd_json_variant_is_unsigned(w));
                assert_se(sd_json_variant_is_real(w));
                assert_se(sd_json_variant_is_number(w));

                assert_se(!sd_json_variant_is_negative(w));

                assert_se(IN_SET(sd_json_variant_type(w), SD_JSON_VARIANT_INTEGER, SD_JSON_VARIANT_UNSIGNED, SD_JSON_VARIANT_REAL));

                for (j = 0; j < sd_json_variant_elements(v); j++) {
                        sd_json_variant *q;

                        assert_se(q = sd_json_variant_by_index(v, j));

                        assert_se(sd_json_variant_equal(w, q));
                }
        }
}

static int test_callback(sd_json_variant **ret, const char *name, void *userdata) {

        if (streq_ptr(name, "mypid1"))
                assert_se(PTR_TO_INT(userdata) == 4711);
        else if (streq_ptr(name, "mypid2"))
                assert_se(PTR_TO_INT(userdata) == 4712);
        else if (streq_ptr(name, "mypid3"))
                return 0;
        else
                assert_not_reached();

        return sd_json_build(ret, SD_JSON_BUILD_INTEGER(getpid()));
}

TEST(build) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL, *b = NULL;
        _cleanup_free_ char *s = NULL, *t = NULL;

        assert_se(sd_json_build(&a, SD_JSON_BUILD_STRING("hallo")) >= 0);
        assert_se(sd_json_build(&b, SD_JSON_BUILD_LITERAL(" \"hallo\"   ")) >= 0);
        assert_se(sd_json_variant_equal(a, b));

        b = sd_json_variant_unref(b);

        assert_se(sd_json_build(&b, SD_JSON_BUILD_VARIANT(a)) >= 0);
        assert_se(sd_json_variant_equal(a, b));

        b = sd_json_variant_unref(b);
        assert_se(sd_json_build(&b, SD_JSON_BUILD_STRING("pief")) >= 0);
        assert_se(!sd_json_variant_equal(a, b));

        a = sd_json_variant_unref(a);
        b = sd_json_variant_unref(b);

        assert_se(sd_json_buildo(&a,
                                 SD_JSON_BUILD_PAIR("one", SD_JSON_BUILD_INTEGER(7)),
                                 SD_JSON_BUILD_PAIR("two", SD_JSON_BUILD_REAL(2.0)),
                                 SD_JSON_BUILD_PAIR("four", JSON_BUILD_STRING_UNDERSCORIFY("foo-bar-baz")),
                                 SD_JSON_BUILD_PAIR("three", SD_JSON_BUILD_INTEGER(0))) >= 0);

        assert_se(sd_json_buildo(&b,
                                 SD_JSON_BUILD_PAIR("two", SD_JSON_BUILD_INTEGER(2)),
                                 SD_JSON_BUILD_PAIR("four", SD_JSON_BUILD_STRING("foo_bar_baz")),
                                 SD_JSON_BUILD_PAIR("three", SD_JSON_BUILD_REAL(0)),
                                 SD_JSON_BUILD_PAIR("one", SD_JSON_BUILD_REAL(7))) >= 0);

        assert_se(sd_json_variant_equal(a, b));

        a = sd_json_variant_unref(a);
        b = sd_json_variant_unref(b);

        const char* arr_1234[] = {"one", "two", "three", "four", NULL};
        assert_se(sd_json_build(&a, SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("x", SD_JSON_BUILD_BOOLEAN(true)),
                                                                    SD_JSON_BUILD_PAIR("y", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("this", SD_JSON_BUILD_NULL)))),
                                                  SD_JSON_BUILD_VARIANT(NULL),
                                                  SD_JSON_BUILD_LITERAL(NULL),
                                                  SD_JSON_BUILD_STRING(NULL),
                                                  SD_JSON_BUILD_NULL,
                                                  SD_JSON_BUILD_INTEGER(77),
                                                  SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_VARIANT(JSON_VARIANT_STRING_CONST("foobar")),
                                                                   SD_JSON_BUILD_VARIANT(JSON_VARIANT_STRING_CONST("zzz"))),
                                                  SD_JSON_BUILD_STRV((char**) arr_1234))) >= 0);

        assert_se(sd_json_variant_format(a, 0, &s) >= 0);
        log_info("GOT: %s", s);
        assert_se(sd_json_parse(s, 0, &b, NULL, NULL) >= 0);
        assert_se(sd_json_variant_equal(a, b));

        a = sd_json_variant_unref(a);
        b = sd_json_variant_unref(b);

        assert_se(sd_json_build(&a, SD_JSON_BUILD_REAL(M_PI)) >= 0);

        s = mfree(s);
        assert_se(sd_json_variant_format(a, 0, &s) >= 0);
        log_info("GOT: %s", s);
        assert_se(sd_json_parse(s, 0, &b, NULL, NULL) >= 0);
        assert_se(sd_json_variant_format(b, 0, &t) >= 0);
        log_info("GOT: %s", t);

        ASSERT_STREQ(s, t);

        a = sd_json_variant_unref(a);
        b = sd_json_variant_unref(b);

        assert_se(sd_json_build(&a, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("x", SD_JSON_BUILD_STRING("y")),
                                             SD_JSON_BUILD_PAIR("z", JSON_BUILD_CONST_STRING("a")),
                                             SD_JSON_BUILD_PAIR("b", JSON_BUILD_CONST_STRING("c"))
                             )) >= 0);

        assert_se(sd_json_build(&b, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("x", SD_JSON_BUILD_STRING("y")),
                                             SD_JSON_BUILD_PAIR_CONDITION(false, "p", SD_JSON_BUILD_STRING("q")),
                                             SD_JSON_BUILD_PAIR_CONDITION(true, "z", JSON_BUILD_CONST_STRING("a")),
                                             SD_JSON_BUILD_PAIR_CONDITION(false, "j", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_STRING("k"), JSON_BUILD_CONST_STRING("u"), JSON_BUILD_CONST_STRING("i"))),
                                             SD_JSON_BUILD_PAIR("b", JSON_BUILD_CONST_STRING("c"))
                             )) >= 0);

        assert_se(sd_json_variant_equal(a, b));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *x = NULL;
        assert_se(sd_json_build(&x, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("foo", SD_JSON_BUILD_INTEGER(77)),
                                                         SD_JSON_BUILD_PAIR("bar", SD_JSON_BUILD_INTEGER(88)))) >= 0);

        sd_json_variant *array[] = { a, a, b, b, x, x };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *va = NULL;

        assert_se(sd_json_build(&va, SD_JSON_BUILD_VARIANT_ARRAY(array, ELEMENTSOF(array))) >= 0);

        assert_se(sd_json_variant_is_array(va));
        assert_se(sd_json_variant_elements(va) == 6);
        assert_se(sd_json_variant_equal(sd_json_variant_by_index(va, 0), a));
        assert_se(sd_json_variant_equal(sd_json_variant_by_index(va, 1), b));
        assert_se(sd_json_variant_equal(sd_json_variant_by_index(va, 2), a));
        assert_se(sd_json_variant_equal(sd_json_variant_by_index(va, 3), b));
        assert_se(sd_json_variant_equal(sd_json_variant_by_index(va, 4), x));
        assert_se(sd_json_variant_equal(sd_json_variant_by_index(va, 5), x));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *y = NULL;
        assert_se(sd_json_build(&y, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("mypid1", SD_JSON_BUILD_CALLBACK(test_callback, INT_TO_PTR(4711))),
                                                         SD_JSON_BUILD_PAIR("mypid2", SD_JSON_BUILD_CALLBACK(test_callback, INT_TO_PTR(4712))))) >= 0);

        _cleanup_free_ char *f1 = NULL, *f2 = NULL;
        assert_se(asprintf(&f1, "{\"mypid1\":" PID_FMT ",\"mypid2\":" PID_FMT "}", getpid(), getpid()) >= 0);

        assert_se(sd_json_variant_format(y, /* flags= */ 0, &f2));
        ASSERT_STREQ(f1, f2);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *z = NULL;
        ASSERT_OK(sd_json_build(&z, SD_JSON_BUILD_OBJECT(JSON_BUILD_PAIR_CALLBACK_NON_NULL("mypid3", test_callback, INT_TO_PTR(4713)))));
        ASSERT_TRUE(sd_json_variant_is_blank_object(z));
        z = sd_json_variant_unref(z);
        f2 = mfree(f2);
        ASSERT_OK(sd_json_build(&z, SD_JSON_BUILD_OBJECT(JSON_BUILD_PAIR_CALLBACK_NON_NULL("mypid1", test_callback, INT_TO_PTR(4711)),
                                                         JSON_BUILD_PAIR_CALLBACK_NON_NULL("mypid2", test_callback, INT_TO_PTR(4712)))));
        ASSERT_OK(sd_json_variant_format(z, /* flags= */ 0, &f2));
        ASSERT_STREQ(f1, f2);

        _cleanup_set_free_ Set *ss = NULL;
        assert_se(set_ensure_put(&ss, &string_hash_ops_free, ASSERT_PTR(strdup("pief"))) >= 0);
        assert_se(set_ensure_put(&ss, &string_hash_ops_free, ASSERT_PTR(strdup("xxxx"))) >= 0);
        assert_se(set_ensure_put(&ss, &string_hash_ops_free, ASSERT_PTR(strdup("kawumm"))) >= 0);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ssv = NULL;
        assert_se(sd_json_build(&ssv, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("zzz", JSON_BUILD_STRING_SET(ss)))) >= 0);
        assert_se(sd_json_variant_sort(&ssv) >= 0);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ssv2 = NULL;
        assert_se(sd_json_build(&ssv2, SD_JSON_BUILD_LITERAL("{\"zzz\":[\"kawumm\",\"pief\",\"xxxx\"]}")) >= 0);

        assert_se(sd_json_variant_equal(ssv, ssv2));

        _cleanup_ordered_set_free_ OrderedSet *oss = NULL;
        assert_se(ordered_set_ensure_put(&oss, &string_hash_ops_free, ASSERT_PTR(strdup("pief"))) >= 0);
        assert_se(ordered_set_ensure_put(&oss, &string_hash_ops_free, ASSERT_PTR(strdup("xxxx"))) >= 0);
        assert_se(ordered_set_ensure_put(&oss, &string_hash_ops_free, ASSERT_PTR(strdup("kawumm"))) >= 0);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ossv = NULL;
        assert_se(sd_json_build(&ossv, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("zzz", JSON_BUILD_STRING_ORDERED_SET(oss)))) >= 0);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ossv2 = NULL;
        assert_se(sd_json_build(&ossv2, SD_JSON_BUILD_LITERAL("{\"zzz\":[\"pief\",\"xxxx\",\"kawumm\"]}")) >= 0);

        assert_se(sd_json_variant_equal(ossv, ossv2));
}

TEST(json_buildo) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL, *b = NULL;

        assert_se(sd_json_buildo(&a,
                                 SD_JSON_BUILD_PAIR("foo", SD_JSON_BUILD_INTEGER(4711)),
                                 SD_JSON_BUILD_PAIR("bar", SD_JSON_BUILD_STRING("xxxx"))) >= 0);

        assert_se(sd_json_build(&b,
                                SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR("bar", SD_JSON_BUILD_STRING("xxxx")),
                                                SD_JSON_BUILD_PAIR("foo", SD_JSON_BUILD_INTEGER(4711)))) >= 0);

        assert_se(sd_json_variant_equal(a, b));
}

TEST(json_parse_file_empty) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        assert_se(fopen_unlocked("/dev/null", "re", &f) >= 0);
        assert_se(sd_json_parse_file(f, "waldo", 0, &v, NULL, NULL) == -ENODATA);
        ASSERT_NULL(v);
}

TEST(json_parse_file_invalid) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        assert_se(f = fmemopen_unlocked((void*) "kookoo", 6, "r"));
        assert_se(sd_json_parse_file(f, "waldo", 0, &v, NULL, NULL) == -EINVAL);
        ASSERT_NULL(v);
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
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        printf("--- original begin ---\n"
               "%s"
               "--- original end ---\n", data);

        assert_se(f = fmemopen_unlocked((void*) data, strlen(data), "r"));

        assert_se(sd_json_parse_file(f, "waldo", 0, &v, NULL, NULL) >= 0);

        printf("--- non-pretty begin ---\n");
        sd_json_variant_dump(v, 0, stdout, NULL);
        printf("\n--- non-pretty end ---\n");

        printf("--- pretty begin ---\n");
        sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_SOURCE, stdout, NULL);
        printf("--- pretty end ---\n");
}

TEST(depth) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        v = JSON_VARIANT_STRING_CONST("start");

        /* Let's verify that the maximum depth checks work */

        for (unsigned i = 0;; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;

                assert_se(i <= UINT16_MAX);
                if (i & 1)
                        r = sd_json_variant_new_array(&w, &v, 1);
                else
                        r = sd_json_variant_new_object(&w, (sd_json_variant*[]) { JSON_VARIANT_STRING_CONST("key"), v }, 2);
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

                sd_json_variant_unref(v);
                v = TAKE_PTR(w);
        }

        sd_json_variant_dump(v, 0, stdout, NULL);
        fputs("\n", stdout);
}

TEST(normalize) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
        _cleanup_free_ char *t = NULL;

        assert_se(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_STRING("x")),
                                             SD_JSON_BUILD_PAIR("c", JSON_BUILD_CONST_STRING("y")),
                                             SD_JSON_BUILD_PAIR("a", JSON_BUILD_CONST_STRING("z")))) >= 0);

        assert_se(!sd_json_variant_is_sorted(v));
        assert_se(!sd_json_variant_is_normalized(v));

        assert_se(sd_json_variant_format(v, 0, &t) >= 0);
        ASSERT_STREQ(t, "{\"b\":\"x\",\"c\":\"y\",\"a\":\"z\"}");
        t = mfree(t);

        assert_se(sd_json_build(&w, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("bar", SD_JSON_BUILD_STRING("zzz")),
                                             SD_JSON_BUILD_PAIR("foo", SD_JSON_BUILD_VARIANT(v)))) >= 0);

        assert_se(sd_json_variant_is_sorted(w));
        assert_se(!sd_json_variant_is_normalized(w));

        assert_se(sd_json_variant_format(w, 0, &t) >= 0);
        ASSERT_STREQ(t, "{\"bar\":\"zzz\",\"foo\":{\"b\":\"x\",\"c\":\"y\",\"a\":\"z\"}}");
        t = mfree(t);

        assert_se(sd_json_variant_sort(&v) >= 0);
        assert_se(sd_json_variant_is_sorted(v));
        assert_se(sd_json_variant_is_normalized(v));

        assert_se(sd_json_variant_format(v, 0, &t) >= 0);
        ASSERT_STREQ(t, "{\"a\":\"z\",\"b\":\"x\",\"c\":\"y\"}");
        t = mfree(t);

        assert_se(sd_json_variant_normalize(&w) >= 0);
        assert_se(sd_json_variant_is_sorted(w));
        assert_se(sd_json_variant_is_normalized(w));

        assert_se(sd_json_variant_format(w, 0, &t) >= 0);
        ASSERT_STREQ(t, "{\"bar\":\"zzz\",\"foo\":{\"a\":\"z\",\"b\":\"x\",\"c\":\"y\"}}");
        t = mfree(t);
}

TEST(bisect) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        /* Tests the bisection logic in sd_json_variant_by_key() */

        for (char c = 'z'; c >= 'a'; c--) {

                if ((c % 3) == 0)
                        continue;

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
                assert_se(sd_json_variant_new_stringn(&w, (char[4]) { '<', c, c, '>' }, 4) >= 0);
                assert_se(sd_json_variant_set_field(&v, (char[2]) { c, 0 }, w) >= 0);
        }

        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        assert_se(!sd_json_variant_is_sorted(v));
        assert_se(!sd_json_variant_is_normalized(v));
        assert_se(sd_json_variant_normalize(&v) >= 0);
        assert_se(sd_json_variant_is_sorted(v));
        assert_se(sd_json_variant_is_normalized(v));

        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        for (char c = 'a'; c <= 'z'; c++) {
                sd_json_variant *k;
                const char *z;

                k = sd_json_variant_by_key(v, (char[2]) { c, 0 });
                assert_se(!k == ((c % 3) == 0));

                if (!k)
                        continue;

                assert_se(sd_json_variant_is_string(k));

                z = (char[5]){ '<', c, c, '>', 0};
                ASSERT_STREQ(sd_json_variant_string(k), z);
        }
}

static void test_float_match(sd_json_variant *v) {
        const double delta = 0.0001;

        assert_se(sd_json_variant_is_array(v));
        assert_se(sd_json_variant_elements(v) == 11);
        assert_se(fabs(1.0 - (DBL_MIN / sd_json_variant_real(sd_json_variant_by_index(v, 0)))) <= delta);
        assert_se(fabs(1.0 - (DBL_MAX / sd_json_variant_real(sd_json_variant_by_index(v, 1)))) <= delta);
        assert_se(sd_json_variant_is_null(sd_json_variant_by_index(v, 2))); /* nan is not supported by json → null */
        assert_se(sd_json_variant_is_null(sd_json_variant_by_index(v, 3))); /* +inf is not supported by json → null */
        assert_se(sd_json_variant_is_null(sd_json_variant_by_index(v, 4))); /* -inf is not supported by json → null */
        assert_se(sd_json_variant_is_null(sd_json_variant_by_index(v, 5)) ||
                  fabs(1.0 - (HUGE_VAL / sd_json_variant_real(sd_json_variant_by_index(v, 5)))) <= delta); /* HUGE_VAL might be +inf, but might also be something else */
        assert_se(sd_json_variant_is_real(sd_json_variant_by_index(v, 6)) &&
                  sd_json_variant_is_integer(sd_json_variant_by_index(v, 6)) &&
                  sd_json_variant_integer(sd_json_variant_by_index(v, 6)) == 0);
        assert_se(sd_json_variant_is_real(sd_json_variant_by_index(v, 7)) &&
                  sd_json_variant_is_integer(sd_json_variant_by_index(v, 7)) &&
                  sd_json_variant_integer(sd_json_variant_by_index(v, 7)) == 10);
        assert_se(sd_json_variant_is_real(sd_json_variant_by_index(v, 8)) &&
                  sd_json_variant_is_integer(sd_json_variant_by_index(v, 8)) &&
                  sd_json_variant_integer(sd_json_variant_by_index(v, 8)) == -10);
        assert_se(sd_json_variant_is_real(sd_json_variant_by_index(v, 9)) &&
                  !sd_json_variant_is_integer(sd_json_variant_by_index(v, 9)));
        assert_se(fabs(1.0 - (DBL_MIN / 2 / sd_json_variant_real(sd_json_variant_by_index(v, 9)))) <= delta);
        assert_se(sd_json_variant_is_real(sd_json_variant_by_index(v, 10)) &&
                  !sd_json_variant_is_integer(sd_json_variant_by_index(v, 10)));
        assert_se(!iszero_safe(sd_json_variant_real(sd_json_variant_by_index(v, 10))));
        assert_se(fabs(1.0 - (-DBL_MIN / 2 / sd_json_variant_real(sd_json_variant_by_index(v, 10)))) <= delta);
}

TEST(float) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
        _cleanup_free_ char *text = NULL;

        assert_se(sd_json_build(&v, SD_JSON_BUILD_ARRAY(
                                             SD_JSON_BUILD_REAL(DBL_MIN),
                                             SD_JSON_BUILD_REAL(DBL_MAX),
                                             SD_JSON_BUILD_REAL(NAN),
                                             SD_JSON_BUILD_REAL(INFINITY),
                                             SD_JSON_BUILD_REAL(-INFINITY),
                                             SD_JSON_BUILD_REAL(HUGE_VAL),
                                             SD_JSON_BUILD_REAL(0),
                                             SD_JSON_BUILD_REAL(10),
                                             SD_JSON_BUILD_REAL(-10),
                                             SD_JSON_BUILD_REAL(DBL_MIN / 2),
                                             SD_JSON_BUILD_REAL(-DBL_MIN / 2))) >= 0);

        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        test_float_match(v);

        assert_se(sd_json_variant_format(v, 0, &text) >= 0);
        assert_se(sd_json_parse(text, 0, &w, NULL, NULL) >= 0);

        sd_json_variant_dump(w, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        test_float_match(w);
}

static void test_equal_text(sd_json_variant *v, const char *text) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;

        assert_se(sd_json_parse(text, 0, &w, NULL, NULL) >= 0);
        assert_se(sd_json_variant_equal(v, w) || (!v && sd_json_variant_is_null(w)));
}

TEST(set_field) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        test_equal_text(v, "null");
        assert_se(sd_json_variant_set_field(&v, "foo", NULL) >= 0);
        test_equal_text(v, "{\"foo\" : null}");
        assert_se(sd_json_variant_set_field(&v, "bar", JSON_VARIANT_STRING_CONST("quux")) >= 0);
        test_equal_text(v, "{\"foo\" : null, \"bar\" : \"quux\"}");
        assert_se(sd_json_variant_set_field(&v, "foo", JSON_VARIANT_STRING_CONST("quux2")) >= 0);
        test_equal_text(v, "{\"foo\" : \"quux2\", \"bar\" : \"quux\"}");
        assert_se(sd_json_variant_set_field(&v, "bar", NULL) >= 0);
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
        test_tokenizer_one("3.141", JSON_TOKEN_REAL, 3.141, JSON_TOKEN_END);
        test_tokenizer_one("0.0", JSON_TOKEN_REAL, 0.0, JSON_TOKEN_END);
        test_tokenizer_one("7e3", JSON_TOKEN_REAL, 7e3, JSON_TOKEN_END);
        test_tokenizer_one("-7e-3", JSON_TOKEN_REAL, -7e-3, JSON_TOKEN_END);
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
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;

        assert_se(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_STRING("x")),
                                             SD_JSON_BUILD_PAIR("c", JSON_BUILD_CONST_STRING("y")),
                                             SD_JSON_BUILD_PAIR("a", JSON_BUILD_CONST_STRING("z")))) >= 0);

        assert_se(sd_json_variant_merge_objectb(&w, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_STRING("x")))) >= 0);
        assert_se(sd_json_variant_merge_objectb(&w, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_STRING("y")))) >= 0);
        assert_se(sd_json_variant_merge_objectb(&w, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("a", SD_JSON_BUILD_STRING("z")))) >= 0);

        assert_se(sd_json_variant_equal(v, w));
}

static void json_array_append_with_source_one(bool source) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a, *b;

        /* Parse two sources, each with a different name and line/column numbers */

        assert_se(sd_json_parse_with_source(" [41]", source ? "string 1" : NULL, 0,
                                         &a, NULL, NULL) >= 0);
        assert_se(sd_json_parse_with_source("\n\n   [42]", source ? "string 2" : NULL, 0,
                                         &b, NULL, NULL) >= 0);

        assert_se(sd_json_variant_is_array(a));
        assert_se(sd_json_variant_elements(a) == 1);
        assert_se(sd_json_variant_is_array(b));
        assert_se(sd_json_variant_elements(b) == 1);

        /* Verify source information */

        const char *s1, *s2;
        unsigned line1, col1, line2, col2;
        assert_se(sd_json_variant_get_source(a, &s1, &line1, &col1) >= 0);
        assert_se(sd_json_variant_get_source(b, &s2, &line2, &col2) >= 0);

        ASSERT_STREQ(s1, source ? "string 1" : NULL);
        ASSERT_STREQ(s2, source ? "string 2" : NULL);
        assert_se(line1 == 1);
        assert_se(col1 == 2);
        assert_se(line2 == 3);
        assert_se(col2 == 4);

        /* Append one elem from the second array (and source) to the first. */

        sd_json_variant *elem;
        assert_se(elem = sd_json_variant_by_index(b, 0));
        assert_se(sd_json_variant_is_integer(elem));
        assert_se(sd_json_variant_elements(elem) == 0);

        assert_se(sd_json_variant_append_array(&a, elem) >= 0);

        assert_se(sd_json_variant_is_array(a));
        assert_se(sd_json_variant_elements(a) == 2);

        /* Verify that source information was propagated correctly */

        assert_se(sd_json_variant_get_source(elem, &s1, &line1, &col1) >= 0);
        assert_se(elem = sd_json_variant_by_index(a, 1));
        assert_se(sd_json_variant_get_source(elem, &s2, &line2, &col2) >= 0);

        ASSERT_STREQ(s1, source ? "string 2" : NULL);
        ASSERT_STREQ(s2, source ? "string 2" : NULL);
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
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *l = NULL, *s = NULL, *wd = NULL, *nd = NULL;

        assert_se(sd_json_build(&l, SD_JSON_BUILD_STRV(STRV_MAKE("foo", "bar", "baz", "bar", "baz", "foo", "qux", "baz"))) >= 0);
        assert_se(sd_json_build(&s, SD_JSON_BUILD_STRV(STRV_MAKE("foo", "bar", "baz", "qux"))) >= 0);

        assert_se(!sd_json_variant_equal(l, s));
        assert_se(sd_json_variant_elements(l) == 8);
        assert_se(sd_json_variant_elements(s) == 4);

        sd_json_variant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, l) {
                assert_se(sd_json_variant_append_array(&wd, i) >= 0);
                assert_se(sd_json_variant_append_array_nodup(&nd, i) >= 0);
        }

        assert_se(sd_json_variant_elements(wd) == 8);
        assert_se(sd_json_variant_equal(l, wd));
        assert_se(!sd_json_variant_equal(s, wd));

        assert_se(sd_json_variant_elements(nd) == 4);
        assert_se(!sd_json_variant_equal(l, nd));
        assert_se(sd_json_variant_equal(s, nd));
}

TEST(json_dispatch) {
        struct foobar {
                uint64_t a, b;
                int64_t c, d;
                uint32_t e, f;
                int32_t g, h;
                uint16_t i, j;
                int16_t k, l;
                uint8_t m, n;
                int8_t o, p;
        } foobar = {};

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        assert_se(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("a", SD_JSON_BUILD_UNSIGNED(UINT64_MAX)),
                                             SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_STRING("18446744073709551615")),
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(INT64_MIN)),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_STRING("-9223372036854775808")),
                                             SD_JSON_BUILD_PAIR("e", SD_JSON_BUILD_UNSIGNED(UINT32_MAX)),
                                             SD_JSON_BUILD_PAIR("f", SD_JSON_BUILD_STRING("4294967295")),
                                             SD_JSON_BUILD_PAIR("g", SD_JSON_BUILD_INTEGER(INT32_MIN)),
                                             SD_JSON_BUILD_PAIR("h", SD_JSON_BUILD_STRING("-2147483648")),
                                             SD_JSON_BUILD_PAIR("i", SD_JSON_BUILD_UNSIGNED(UINT16_MAX)),
                                             SD_JSON_BUILD_PAIR("j", SD_JSON_BUILD_STRING("65535")),
                                             SD_JSON_BUILD_PAIR("k", SD_JSON_BUILD_INTEGER(INT16_MIN)),
                                             SD_JSON_BUILD_PAIR("l", SD_JSON_BUILD_STRING("-32768")),
                                             SD_JSON_BUILD_PAIR("m", SD_JSON_BUILD_INTEGER(UINT8_MAX)),
                                             SD_JSON_BUILD_PAIR("n", SD_JSON_BUILD_STRING("255")),
                                             SD_JSON_BUILD_PAIR("o", SD_JSON_BUILD_INTEGER(INT8_MIN)),
                                             SD_JSON_BUILD_PAIR("p", SD_JSON_BUILD_STRING("-128")))) >= 0);

        assert_se(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO, stdout, /* prefix= */ NULL) >= 0);

        sd_json_dispatch_field table[] = {
                { "a", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct foobar, a) },
                { "b", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct foobar, b) },
                { "c", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int64,  offsetof(struct foobar, c) },
                { "d", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int64,  offsetof(struct foobar, d) },
                { "e", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32, offsetof(struct foobar, e) },
                { "f", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32, offsetof(struct foobar, f) },
                { "g", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int32,  offsetof(struct foobar, g) },
                { "h", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int32,  offsetof(struct foobar, h) },
                { "i", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16, offsetof(struct foobar, i) },
                { "j", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16, offsetof(struct foobar, j) },
                { "k", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int16,  offsetof(struct foobar, k) },
                { "l", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int16,  offsetof(struct foobar, l) },
                { "m", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,  offsetof(struct foobar, m) },
                { "n", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,  offsetof(struct foobar, n) },
                { "o", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int8,   offsetof(struct foobar, o) },
                { "p", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int8,   offsetof(struct foobar, p) },
                {}
        };

        assert_se(sd_json_dispatch(v, table, SD_JSON_LOG, &foobar) >= 0);

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

        assert_se(foobar.m == UINT8_MAX);
        assert_se(foobar.n == UINT8_MAX);
        assert_se(foobar.o == INT8_MIN);
        assert_se(foobar.p == INT8_MIN);
}

typedef enum mytestenum {
        myfoo, mybar, mybaz, with_some_dashes, _mymax, _myinvalid = -EINVAL,
} mytestenum;

static const char *mytestenum_table[_mymax] = {
        [myfoo] = "myfoo",
        [mybar] = "mybar",
        [mybaz] = "mybaz",
        [with_some_dashes] = "with-some-dashes",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(mytestenum, mytestenum);

static JSON_DISPATCH_ENUM_DEFINE(dispatch_mytestenum, mytestenum, mytestenum_from_string);

TEST(json_dispatch_enum_define) {

        struct data {
                mytestenum a, b, c, d, e;
        } data = {
                .a = _myinvalid,
                .b = _myinvalid,
                .c = _myinvalid,
                .d = mybar,
                .e = _myinvalid,
        };

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;

        assert_se(sd_json_buildo(&j,
                                 SD_JSON_BUILD_PAIR("a", SD_JSON_BUILD_STRING("mybaz")),
                                 SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_STRING("mybar")),
                                 SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_STRING("myfoo")),
                                 SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_NULL),
                                 SD_JSON_BUILD_PAIR("e", JSON_BUILD_STRING_UNDERSCORIFY(mytestenum_to_string(with_some_dashes)))) >= 0);

        assert_se(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "a", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_mytestenum, offsetof(struct data, a), 0 },
                                        { "b", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_mytestenum, offsetof(struct data, b), 0 },
                                        { "c", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_mytestenum, offsetof(struct data, c), 0 },
                                        { "d", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_mytestenum, offsetof(struct data, d), 0 },
                                        { "e", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_mytestenum, offsetof(struct data, e), 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &data) >= 0);

        assert(data.a == mybaz);
        assert(data.b == mybar);
        assert(data.c == myfoo);
        assert(data.d < 0);
        assert(data.e == with_some_dashes);
}

TEST(json_dispatch_double) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;

        assert_se(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("x1", SD_JSON_BUILD_REAL(0.5)),
                                             SD_JSON_BUILD_PAIR("x2", SD_JSON_BUILD_REAL(-0.5)),
                                             SD_JSON_BUILD_PAIR("x3", JSON_BUILD_CONST_STRING("infinity")),
                                             SD_JSON_BUILD_PAIR("x4", JSON_BUILD_CONST_STRING("-infinity")),
                                             SD_JSON_BUILD_PAIR("x5", JSON_BUILD_CONST_STRING("nan")),
                                             SD_JSON_BUILD_PAIR("x6", JSON_BUILD_CONST_STRING("inf")),
                                             SD_JSON_BUILD_PAIR("x7", JSON_BUILD_CONST_STRING("-inf")))) >= 0);

        struct data {
                double x1, x2, x3, x4, x5, x6, x7;
        } data = {};

        assert_se(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "x1", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_double, offsetof(struct data, x1), 0 },
                                        { "x2", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_double, offsetof(struct data, x2), 0 },
                                        { "x3", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_double, offsetof(struct data, x3), 0 },
                                        { "x4", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_double, offsetof(struct data, x4), 0 },
                                        { "x5", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_double, offsetof(struct data, x5), 0 },
                                        { "x6", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_double, offsetof(struct data, x6), 0 },
                                        { "x7", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_double, offsetof(struct data, x7), 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &data) >= 0);

        assert_se(fabs(data.x1 - 0.5) < 0.01);
        assert_se(fabs(data.x2 + 0.5) < 0.01);
        assert_se(isinf(data.x3));
        assert_se(data.x3 > 0);
        assert_se(isinf(data.x4));
        assert_se(data.x4 < 0);
        assert_se(isnan(data.x5));
        assert_se(isinf(data.x6));
        assert_se(data.x6 > 0);
        assert_se(isinf(data.x7));
        assert_se(data.x7 < 0);
}

TEST(json_sensitive) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL, *b = NULL, *v = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        assert_se(sd_json_build(&a, SD_JSON_BUILD_STRV(STRV_MAKE("foo", "bar", "baz", "bar", "baz", "foo", "qux", "baz"))) >= 0);
        assert_se(sd_json_build(&b, SD_JSON_BUILD_STRV(STRV_MAKE("foo", "bar", "baz", "qux"))) >= 0);

        sd_json_variant_sensitive(a);

        assert_se(sd_json_variant_format(a, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s) >= 0);
        ASSERT_STREQ(s, "\"<sensitive data>\"");
        s = mfree(s);

        r = sd_json_variant_format(b, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));
        s = mfree(s);

        assert_se(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(INT64_MIN)),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_STRING("-9223372036854775808")),
                                             SD_JSON_BUILD_PAIR("e", SD_JSON_BUILD_EMPTY_OBJECT))) >= 0);
        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        r = sd_json_variant_format(v, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));
        s = mfree(s);
        v = sd_json_variant_unref(v);

        assert_se(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR_VARIANT("b", b),
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(INT64_MIN)),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_STRING("-9223372036854775808")),
                                             SD_JSON_BUILD_PAIR("e", SD_JSON_BUILD_EMPTY_OBJECT))) >= 0);
        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        r = sd_json_variant_format(v, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));
        s = mfree(s);
        v = sd_json_variant_unref(v);

        assert_se(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR_VARIANT("b", b),
                                             SD_JSON_BUILD_PAIR_VARIANT("a", a),
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(INT64_MIN)),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_STRING("-9223372036854775808")),
                                             SD_JSON_BUILD_PAIR("e", SD_JSON_BUILD_EMPTY_OBJECT))) >= 0);
        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        assert_se(sd_json_variant_format(v, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s) >= 0);
        ASSERT_STREQ(s, "{\"b\":[\"foo\",\"bar\",\"baz\",\"qux\"],\"a\":\"<sensitive data>\",\"c\":-9223372036854775808,\"d\":\"-9223372036854775808\",\"e\":{}}");
        s = mfree(s);
        v = sd_json_variant_unref(v);

        assert_se(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR_VARIANT("b", b),
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(INT64_MIN)),
                                             SD_JSON_BUILD_PAIR_VARIANT("a", a),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_STRING("-9223372036854775808")),
                                             SD_JSON_BUILD_PAIR("e", SD_JSON_BUILD_EMPTY_OBJECT))) >= 0);
        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        assert_se(sd_json_variant_format(v, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s) >= 0);
        ASSERT_STREQ(s, "{\"b\":[\"foo\",\"bar\",\"baz\",\"qux\"],\"c\":-9223372036854775808,\"a\":\"<sensitive data>\",\"d\":\"-9223372036854775808\",\"e\":{}}");
        s = mfree(s);
        v = sd_json_variant_unref(v);

        assert_se(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR_VARIANT("b", b),
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(INT64_MIN)),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_STRING("-9223372036854775808")),
                                             SD_JSON_BUILD_PAIR_VARIANT("a", a),
                                             SD_JSON_BUILD_PAIR("e", SD_JSON_BUILD_EMPTY_OBJECT))) >= 0);
        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        assert_se(sd_json_variant_format(v, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s) >= 0);
        ASSERT_STREQ(s, "{\"b\":[\"foo\",\"bar\",\"baz\",\"qux\"],\"c\":-9223372036854775808,\"d\":\"-9223372036854775808\",\"a\":\"<sensitive data>\",\"e\":{}}");
        s = mfree(s);
        v = sd_json_variant_unref(v);

        assert_se(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR_VARIANT("b", b),
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(INT64_MIN)),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_STRING("-9223372036854775808")),
                                             SD_JSON_BUILD_PAIR("e", SD_JSON_BUILD_EMPTY_OBJECT),
                                             SD_JSON_BUILD_PAIR_VARIANT("a", a))) >= 0);
        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        assert_se(sd_json_variant_format(v, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s) >= 0);
        ASSERT_STREQ(s, "{\"b\":[\"foo\",\"bar\",\"baz\",\"qux\"],\"c\":-9223372036854775808,\"d\":\"-9223372036854775808\",\"e\":{},\"a\":\"<sensitive data>\"}");
}

TEST(json_iovec) {
        struct iovec iov1 = CONST_IOVEC_MAKE_STRING("üxknürz"), iov2 = CONST_IOVEC_MAKE_STRING("wuffwuffmiau");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        assert_se(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("nr1", JSON_BUILD_IOVEC_BASE64(&iov1)),
                                             SD_JSON_BUILD_PAIR("nr2", JSON_BUILD_IOVEC_HEX(&iov2)))) >= 0);

        sd_json_variant_dump(j, SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO, /* f= */ NULL, /* prefix= */ NULL);

        _cleanup_(iovec_done) struct iovec a = {}, b = {};
        assert_se(json_variant_unbase64_iovec(sd_json_variant_by_key(j, "nr1"), &a) >= 0);
        assert_se(json_variant_unhex_iovec(sd_json_variant_by_key(j, "nr2"), &b) >= 0);

        assert_se(iovec_memcmp(&iov1, &a) == 0);
        assert_se(iovec_memcmp(&iov2, &b) == 0);
        assert_se(iovec_memcmp(&iov2, &a) < 0);
        assert_se(iovec_memcmp(&iov1, &b) > 0);
}

TEST(json_dispatch_nullable) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;

        assert_se(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("x1", JSON_BUILD_CONST_STRING("foo")),
                                             SD_JSON_BUILD_PAIR("x2", JSON_BUILD_CONST_STRING("bar")),
                                             SD_JSON_BUILD_PAIR("x3", JSON_BUILD_CONST_STRING("waldo")),
                                             SD_JSON_BUILD_PAIR("x4", JSON_BUILD_CONST_STRING("foo2")),
                                             SD_JSON_BUILD_PAIR("x5", JSON_BUILD_CONST_STRING("bar2")),
                                             SD_JSON_BUILD_PAIR("x6", JSON_BUILD_CONST_STRING("waldo2")),
                                             SD_JSON_BUILD_PAIR("x7", SD_JSON_BUILD_NULL),
                                             SD_JSON_BUILD_PAIR("x8", SD_JSON_BUILD_NULL),
                                             SD_JSON_BUILD_PAIR("x9", SD_JSON_BUILD_NULL))) >= 0);

        struct data {
                const char *x1, *x2, *x3, *x4, *x5, *x6, *x7, *x8, *x9;
        } data = {
                .x1 = POINTER_MAX,
                .x2 = POINTER_MAX,
                .x3 = POINTER_MAX,
                .x4 = POINTER_MAX,
                .x5 = POINTER_MAX,
                .x6 = POINTER_MAX,
                .x7 = POINTER_MAX,
                .x8 = POINTER_MAX,
                .x9 = POINTER_MAX,
        };

        assert_se(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "x1", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_const_string, offsetof(struct data, x1), SD_JSON_NULLABLE    },
                                        { "x2", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_const_string, offsetof(struct data, x2), SD_JSON_REFUSE_NULL },
                                        { "x3", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_const_string, offsetof(struct data, x3), 0                   },
                                        { "x4", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(struct data, x4), SD_JSON_NULLABLE    },
                                        { "x5", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(struct data, x5), SD_JSON_REFUSE_NULL },
                                        { "x6", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(struct data, x6), 0                   },
                                        { "x7", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_const_string, offsetof(struct data, x7), SD_JSON_NULLABLE    },
                                        { "x8", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_const_string, offsetof(struct data, x8), 0                   },
                                        { "x9", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(struct data, x9), SD_JSON_NULLABLE    },
                                        {},
                                },
                                /* flags= */ 0,
                                &data) >= 0);

        assert_se(streq_ptr(data.x1, "foo"));
        assert_se(streq_ptr(data.x2, "bar"));
        assert_se(streq_ptr(data.x3, "waldo"));
        assert_se(streq_ptr(data.x4, "foo2"));
        assert_se(streq_ptr(data.x5, "bar2"));
        assert_se(streq_ptr(data.x6, "waldo2"));
        assert_se(!data.x7);
        assert_se(!data.x8);
        assert_se(!data.x9);

        assert_se(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "x7", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_const_string, offsetof(struct data, x7), SD_JSON_REFUSE_NULL },
                                        {},
                                },
                                /* flags= */ SD_JSON_ALLOW_EXTENSIONS,
                                &data) == -EINVAL);

        assert_se(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "x7", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(struct data, x7), SD_JSON_REFUSE_NULL },
                                        {},
                                },
                                /* flags= */ SD_JSON_ALLOW_EXTENSIONS,
                                &data) == -EINVAL);

        assert_se(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "x7", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(struct data, x7), 0 },
                                        {},
                                },
                                /* flags= */ SD_JSON_ALLOW_EXTENSIONS,
                                &data) == -EINVAL);
}

TEST(parse_continue) {
        unsigned line = 23, column = 43;

        /* First try to parse with continue logic off, this should fail */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *x = NULL;
        assert_se(sd_json_parse_with_source("4711 512", "piff", /* flags= */ 0, &x, &line, &column) == -EINVAL);
        assert_se(line == 1);
        assert_se(column == 6);

        /* Then try to parse with continue logic on, which should yield two numbers */
        const char *p = "4711 512";
        assert_se(sd_json_parse_with_source_continue(&p, "piff", /* flags= */ 0, &x, &line, &column) >= 0);
        assert_se(sd_json_variant_is_unsigned(x));
        assert_se(sd_json_variant_unsigned(x) == 4711);
        x = sd_json_variant_unref(x);

        assert_se(streq_ptr(p, " 512"));
        assert_se(sd_json_parse_with_source_continue(&p, "piff", /* flags= */ 0, &x, &line, &column) >= 0);
        assert_se(sd_json_variant_is_unsigned(x));
        assert_se(sd_json_variant_unsigned(x) == 512);

        assert_se(isempty(p));
        assert_se(sd_json_parse_with_source_continue(&p, "piff", /* flags= */ 0, &x, &line, &column) == -EINVAL);
}

TEST(pidref) {
        _cleanup_(pidref_done) PidRef myself = PIDREF_NULL, pid1 = PIDREF_NULL;

        assert_se(pidref_set_pid(&myself, 0) >= 0);
        assert_se(pidref_set_pid(&pid1, 1) >= 0);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        sd_id128_t randomized_boot_id;
        assert_se(sd_id128_randomize(&randomized_boot_id) >= 0);
        assert_se(sd_json_buildo(&v,
                                 JSON_BUILD_PAIR_PIDREF("myself", &myself),
                                 JSON_BUILD_PAIR_PIDREF("pid1", &pid1),
                                 SD_JSON_BUILD_PAIR("remote", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR_UNSIGNED("pid", 1),
                                                                                   SD_JSON_BUILD_PAIR_UNSIGNED("pidfdId", 4711),
                                                                                   SD_JSON_BUILD_PAIR_ID128("bootId", randomized_boot_id))),
                                 SD_JSON_BUILD_PAIR("automatic", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR_UNSIGNED("pid", 0)))) >= 0);

        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        struct {
                PidRef myself, pid1, remote, automatic;
        } data = {
                .myself = PIDREF_NULL,
                .pid1 = PIDREF_NULL,
                .remote = PIDREF_NULL,
                .automatic = PIDREF_NULL,
        };

        assert_se(sd_json_dispatch(
                                  v,
                                  (const sd_json_dispatch_field[]) {
                                          { "myself",    _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref, voffsetof(data, myself),    SD_JSON_STRICT },
                                          { "pid1",      _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref, voffsetof(data, pid1),      SD_JSON_STRICT },
                                          { "remote",    _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref, voffsetof(data, remote),    0              },
                                          { "automatic", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref, voffsetof(data, automatic), SD_JSON_RELAX  },
                                          {},
                                  },
                                  /* flags= */ 0,
                                  &data) >= 0);

        assert_se(pidref_equal(&myself, &data.myself));
        assert_se(pidref_equal(&pid1, &data.pid1));

        assert_se(!pidref_equal(&myself, &data.pid1));
        assert_se(!pidref_equal(&pid1, &data.myself));
        assert_se(!pidref_equal(&myself, &data.remote));
        assert_se(!pidref_equal(&pid1, &data.remote));

        assert_se((myself.fd_id > 0) == (data.myself.fd_id > 0));
        assert_se((pid1.fd_id > 0) == (data.pid1.fd_id > 0));

        assert_se(!pidref_is_set(&data.automatic));
        assert_se(pidref_is_automatic(&data.automatic));
        assert_se(pidref_is_set(&data.remote));
        assert_se(pidref_is_remote(&data.remote));

        pidref_done(&data.myself);
        pidref_done(&data.pid1);
        pidref_done(&data.remote);
}

TEST(devnum) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        dev_t dev = makedev(123, 456), parsed;

        ASSERT_OK(json_variant_new_devnum(&v, dev));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL));
        ASSERT_OK(json_dispatch_devnum("devnum", v, /* flags= */ 0, &parsed));
        ASSERT_EQ(major(parsed), major(dev));
        ASSERT_EQ(minor(parsed), minor(dev));
        v = sd_json_variant_unref(v);

        dev = makedev(1 << 12, 456);
        ASSERT_OK(json_variant_new_devnum(&v, dev));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL));
        ASSERT_FAIL(json_dispatch_devnum("devnum", v, /* flags= */ 0, &parsed));
        v = sd_json_variant_unref(v);

        dev = makedev(123, 1 << 20);
        ASSERT_OK(json_variant_new_devnum(&v, dev));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL));
        ASSERT_FAIL(json_dispatch_devnum("devnum", v, /* flags= */ 0, &parsed));
}

TEST(fd_info) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        _cleanup_close_ int fd = -EBADF;

        /* directories */
        ASSERT_OK(json_variant_new_fd_info(&v, AT_FDCWD));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL));
        v = sd_json_variant_unref(v);

        ASSERT_OK_ERRNO(fd = openat(AT_FDCWD, ".", O_CLOEXEC | O_DIRECTORY | O_PATH));
        ASSERT_OK(json_variant_new_fd_info(&v, fd));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL));
        v = sd_json_variant_unref(v);
        fd = safe_close(fd);

        /* regular file */
        ASSERT_OK(fd = open_tmpfile_unlinkable(NULL, O_RDWR));
        ASSERT_OK(json_variant_new_fd_info(&v, fd));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL));
        v = sd_json_variant_unref(v);
        fd = safe_close(fd);

        fd = open("/sys/class/net/lo/uevent", O_CLOEXEC | O_PATH);
        if (fd >= 0) {
                ASSERT_OK(json_variant_new_fd_info(&v, fd));
                ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL));
                v = sd_json_variant_unref(v);
                fd = safe_close(fd);
        }

        /* block device */
        fd = open("/dev/sda", O_CLOEXEC | O_PATH);
        if (fd >= 0) {
                ASSERT_OK(json_variant_new_fd_info(&v, fd));
                ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL));
                v = sd_json_variant_unref(v);
                fd = safe_close(fd);
        }

        /* stream */
        ASSERT_OK(json_variant_new_fd_info(&v, fileno(stdout)));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL));
        v = sd_json_variant_unref(v);

        /* socket */
        ASSERT_OK_ERRNO(fd = socket(AF_INET, SOCK_DGRAM, 0));
        ASSERT_OK(json_variant_new_fd_info(&v, fd));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL));
        v = sd_json_variant_unref(v);
        fd = safe_close(fd);

        /* pidfd */
        ASSERT_OK(pidref_set_pid(&pidref, 0));
        if (pidref.fd >= 0) {
                ASSERT_OK(json_variant_new_fd_info(&v, pidref.fd));
                ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL));
                v = sd_json_variant_unref(v);
        }
        pidref_done(&pidref);

        ASSERT_OK(pidref_set_pid(&pidref, 1));
        if (pidref.fd >= 0) {
                ASSERT_OK(json_variant_new_fd_info(&v, pidref.fd));
                ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL));
                v = sd_json_variant_unref(v);
        }
        pidref_done(&pidref);
}

TEST(unit_name) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ASSERT_OK(sd_json_buildo(&v,
                                 SD_JSON_BUILD_PAIR_STRING("plain", "myservice.service"),
                                 SD_JSON_BUILD_PAIR_STRING("instance", "myservice@instance1.service"),
                                 SD_JSON_BUILD_PAIR_STRING("template", "myservice@.service")));

        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        struct {
                const char *plain, *instance, *template;
        } data = {};

        ASSERT_OK(sd_json_dispatch(
                                  v,
                                  (const sd_json_dispatch_field[]) {
                                          { "plain",    SD_JSON_VARIANT_STRING, json_dispatch_const_unit_name, voffsetof(data, plain),    SD_JSON_STRICT },
                                          { "instance", SD_JSON_VARIANT_STRING, json_dispatch_const_unit_name, voffsetof(data, instance), 0              },
                                          { "template", SD_JSON_VARIANT_STRING, json_dispatch_const_unit_name, voffsetof(data, template), SD_JSON_RELAX  },
                                          {},
                                  },
                                  /* flags= */ 0,
                                  &data));

        ASSERT_STREQ(data.plain, "myservice.service");
        ASSERT_STREQ(data.instance, "myservice@instance1.service");
        ASSERT_STREQ(data.template, "myservice@.service");

        ASSERT_ERROR(sd_json_dispatch(
                                  v,
                                  (const sd_json_dispatch_field[]) {
                                          { "plain",    SD_JSON_VARIANT_STRING, json_dispatch_const_unit_name, voffsetof(data, plain),    SD_JSON_RELAX  },
                                          /* instance value is not allowed with SD_JSON_STRICT */
                                          { "instance", SD_JSON_VARIANT_STRING, json_dispatch_const_unit_name, voffsetof(data, instance), SD_JSON_STRICT },
                                          { "template", SD_JSON_VARIANT_STRING, json_dispatch_const_unit_name, voffsetof(data, template), SD_JSON_RELAX  },
                                          {},
                                  },
                                  /* flags= */ 0,
                                  &data), EINVAL);

        ASSERT_ERROR(sd_json_dispatch(
                                  v,
                                  (const sd_json_dispatch_field[]) {
                                          { "plain",    SD_JSON_VARIANT_STRING, json_dispatch_const_unit_name, voffsetof(data, plain),    SD_JSON_RELAX  },
                                          { "instance", SD_JSON_VARIANT_STRING, json_dispatch_const_unit_name, voffsetof(data, instance), SD_JSON_RELAX  },
                                          /* template value is not allowed by default */
                                          { "template", SD_JSON_VARIANT_STRING, json_dispatch_const_unit_name, voffsetof(data, template), 0 },
                                          {},
                                  },
                                  /* flags= */ 0,
                                  &data), EINVAL);
}

TEST(access_mode) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ASSERT_OK(sd_json_parse("{"
                                " \"a\" : \"0755\", "
                                " \"b\" : 448, "
                                " \"c\" : null, "
                                " \"d\" : \"01755\" "
                                "}",
                                /* flags= */ 0,
                                &v,
                                /* reterr_line= */ NULL,
                                /* reterr_column= */ NULL));

        struct {
                mode_t a, b, c, d;
        } mm = { 1, 2, 3, 4 };

        ASSERT_OK(sd_json_dispatch(
                                  v,
                                  (const sd_json_dispatch_field[]) {
                                          { "a", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_access_mode, voffsetof(mm, a), 0 },
                                          { "b", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_access_mode, voffsetof(mm, b), 0 },
                                          { "c", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_access_mode, voffsetof(mm, c), 0 },
                                          { "d", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_access_mode, voffsetof(mm, d), 0 },
                                          {},
                                  },
                                  /* flags= */ 0,
                                  &mm));

        ASSERT_EQ(mm.a, (mode_t) 0755);
        ASSERT_EQ(mm.b, (mode_t) 0700);
        ASSERT_EQ(mm.c, MODE_INVALID);
        ASSERT_EQ(mm.d, (mode_t) 01755);

        /* retry with SD_JSON_STRICT, where 'd' should not parse anymore */
        ASSERT_ERROR(sd_json_dispatch(
                                  v,
                                  (const sd_json_dispatch_field[]) {
                                          { "d", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_access_mode, voffsetof(mm, d), SD_JSON_STRICT },
                                          {},
                                  },
                                  /* flags= */ SD_JSON_ALLOW_EXTENSIONS,
                                  &mm), ERANGE);
}

static void test_json_variant_compare_one(const char *a, const char *b, int expected) {
        int r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *aa = NULL;
        if (!isempty(a))
                ASSERT_OK(sd_json_parse(a, /* flags= */ 0, &aa, /* reterr_line= */ NULL, /* reterr_column= */ NULL));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *bb = NULL;
        if (!isempty(b))
                ASSERT_OK(sd_json_parse(b, /* flags= */ 0, &bb, /* reterr_line= */ NULL, /* reterr_column= */ NULL));

        r = json_variant_compare(aa, bb);

        log_debug("%s vs %s → %i (expected %i)", a, b, r, expected);

        if (expected < 0)
                ASSERT_LT(r, 0);
        else if (expected > 0)
                ASSERT_GT(r, 0);
        else
                ASSERT_EQ(r, 0);

        r = json_variant_compare(bb, aa);

        if (expected < 0)
                ASSERT_GT(r, 0);
        else if (expected > 0)
                ASSERT_LT(r, 0);
        else
                ASSERT_EQ(r, 0);
}

TEST(json_variant_compare) {
        test_json_variant_compare_one("null", "\"a\"", -1);
        test_json_variant_compare_one(NULL, "\"a\"", -1);
        test_json_variant_compare_one("0", "1", -1);
        test_json_variant_compare_one("1", "0", 1);
        test_json_variant_compare_one("0", "0", 0);
        test_json_variant_compare_one("1", "1", 0);
        test_json_variant_compare_one("1", "null", 1);
        test_json_variant_compare_one("null", "1", -1);
        test_json_variant_compare_one("null", "null", 0);
        test_json_variant_compare_one("false", "true", -1);
        test_json_variant_compare_one("true", "false", 1);
        test_json_variant_compare_one("true", "true", 0);
        test_json_variant_compare_one("false", "false", 0);
        test_json_variant_compare_one("\"a\"", "\"b\"", -1);
        test_json_variant_compare_one("\"b\"", "\"a\"", 1);
        test_json_variant_compare_one("18446744073709551615", "0", 1);
        test_json_variant_compare_one("0", "18446744073709551615", -1);
        test_json_variant_compare_one("18446744073709551615", "18446744073709551615", 0);
        test_json_variant_compare_one("-9223372036854775808", "18446744073709551615", -1);
        test_json_variant_compare_one("18446744073709551615", "-9223372036854775808", 1);
        test_json_variant_compare_one("1.1", "3.4", -1);
        test_json_variant_compare_one("1", "3.4", -1);
        test_json_variant_compare_one("[1,2]", "[1,2]", 0);
        test_json_variant_compare_one("[1,2]", "[2,1]", -1);
        test_json_variant_compare_one("[1,2]", "[1,2,3]", -1);
        test_json_variant_compare_one("{}", "{\"a\":\"b\"}", -1);
        test_json_variant_compare_one("{\"a\":\"b\"}", "{\"a\":\"b\"}", 0);
        test_json_variant_compare_one("{\"a\":\"b\"}", "{\"b\":\"c\"}", 1);
        test_json_variant_compare_one("{\"a\":\"b\",\"b\":\"c\"}", "{\"b\":\"c\",\"a\":\"b\"}", 0);
        test_json_variant_compare_one("{\"a\":\"b\",\"b\":\"c\"}", "{\"a\":\"b\"}", 1);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
