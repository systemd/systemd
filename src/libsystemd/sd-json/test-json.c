/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <float.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "escape.h"
#include "fd-util.h"
#include "format-util.h"
#include "fileio.h"
#include "in-addr-util.h"
#include "io-util.h"
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
        ASSERT_NOT_NULL(cdata = cescape(data));
        log_info("/* %s data=\"%s\" */", __func__, cdata);

        va_start(ap, data);

        for (;;) {
                unsigned token_line, token_column;
                _cleanup_free_ char *str = NULL;
                JsonValue v = JSON_VALUE_NULL;
                int t, tt;

                t = json_tokenize(&data, &str, &v, &token_line, &token_column, &state, &line, &column);
                tt = va_arg(ap, int);

                ASSERT_EQ(t, tt);

                if (t == JSON_TOKEN_END || t < 0)
                        break;

                else if (t == JSON_TOKEN_STRING) {
                        const char *nn;

                        nn = va_arg(ap, const char *);
                        ASSERT_STREQ(nn, str);

                } else if (t == JSON_TOKEN_REAL) {
                        double d;

                        d = va_arg(ap, double);

                        ASSERT_TRUE(ABS(d - v.real) < 1e-10 ||
                                    ABS((d - v.real) / v.real) < 1e-10);

                } else if (t == JSON_TOKEN_INTEGER) {
                        int64_t i;

                        i = va_arg(ap, int64_t);
                        ASSERT_EQ(i, v.integer);

                } else if (t == JSON_TOKEN_UNSIGNED) {
                        uint64_t u;

                        u = va_arg(ap, uint64_t);
                        ASSERT_EQ(u, v.unsig);

                } else if (t == JSON_TOKEN_BOOLEAN) {
                        bool b;

                        b = va_arg(ap, int);
                        ASSERT_EQ(b, v.boolean);
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
        ASSERT_NOT_NULL(cdata = cescape(data));
        log_info("/* %s data=\"%s\" */", __func__, cdata);

        r = ASSERT_OK_ZERO(sd_json_parse(data, /* flags= */ 0, &v,
                                         /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_NOT_NULL(v);

        r = ASSERT_OK(sd_json_variant_format(v, /* flags= */ 0, &s));
        ASSERT_NOT_NULL(s);
        ASSERT_EQ((size_t) r, strlen(s));

        log_info("formatted normally: %s", s);

        r = ASSERT_OK_ZERO(sd_json_parse(data, SD_JSON_PARSE_SENSITIVE, &w, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_NOT_NULL(w);
        ASSERT_TRUE(sd_json_variant_has_type(v, sd_json_variant_type(w)));
        ASSERT_TRUE(sd_json_variant_has_type(w, sd_json_variant_type(v)));
        ASSERT_TRUE(sd_json_variant_equal(v, w));

        s = mfree(s);
        r = sd_json_variant_format(w, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s);
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "\"<sensitive data>\"");

        s = mfree(s);
        r = ASSERT_OK(sd_json_variant_format(w, SD_JSON_FORMAT_PRETTY, &s));
        ASSERT_NOT_NULL(s);
        ASSERT_EQ((size_t) r, strlen(s));

        s = mfree(s);
        w = sd_json_variant_unref(w);

        r = ASSERT_OK(sd_json_variant_format(v, SD_JSON_FORMAT_PRETTY, &s));
        ASSERT_NOT_NULL(s);
        ASSERT_EQ((size_t) r, strlen(s));

        log_info("formatted prettily:\n%s", s);

        r = ASSERT_OK_ZERO(sd_json_parse(data, /* flags= */ 0, &w,
                                         /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_NOT_NULL(w);

        ASSERT_TRUE(sd_json_variant_has_type(v, sd_json_variant_type(w)));
        ASSERT_TRUE(sd_json_variant_has_type(w, sd_json_variant_type(v)));
        ASSERT_TRUE(sd_json_variant_equal(v, w));

        s = mfree(s);
        r = ASSERT_OK(sd_json_variant_format(v, SD_JSON_FORMAT_COLOR, &s));
        ASSERT_NOT_NULL(s);
        ASSERT_EQ((size_t) r, strlen(s));
        printf("Normal with color: %s\n", s);

        s = mfree(s);
        r = ASSERT_OK(sd_json_variant_format(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, &s));
        ASSERT_NOT_NULL(s);
        ASSERT_EQ((size_t) r, strlen(s));
        printf("Pretty with color:\n%s\n", s);

        if (test)
                test(v);
}

static void test_1(sd_json_variant *v) {
        sd_json_variant *p, *q;
        unsigned i;

        log_info("/* %s */", __func__);

        /* 3 keys + 3 values */
        ASSERT_EQ(sd_json_variant_elements(v), 6U);

        /* has k */
        p = sd_json_variant_by_key(v, "k");
        ASSERT_NOT_NULL(p);
        ASSERT_EQ((int) sd_json_variant_type(p), SD_JSON_VARIANT_STRING);

        /* k equals v */
        ASSERT_STREQ(sd_json_variant_string(p), "v");

        /* has foo */
        p = sd_json_variant_by_key(v, "foo");
        ASSERT_NOT_NULL(p);
        ASSERT_EQ((int) sd_json_variant_type(p), SD_JSON_VARIANT_ARRAY);
        ASSERT_EQ(sd_json_variant_elements(p), 3U);

        /* check  foo[0] = 1, foo[1] = 2, foo[2] = 3 */
        for (i = 0; i < 3; ++i) {
                q = sd_json_variant_by_index(p, i);
                ASSERT_NOT_NULL(q);
                ASSERT_EQ((int) sd_json_variant_type(q), SD_JSON_VARIANT_UNSIGNED);
                ASSERT_EQ(sd_json_variant_unsigned(q), i+1);
                ASSERT_TRUE(sd_json_variant_has_type(q, SD_JSON_VARIANT_INTEGER));
                ASSERT_EQ(sd_json_variant_integer(q), i+1);
        }

        /* has bar */
        p = sd_json_variant_by_key(v, "bar");
        ASSERT_NOT_NULL(p);
        ASSERT_EQ((int) sd_json_variant_type(p), SD_JSON_VARIANT_OBJECT);
        ASSERT_EQ(sd_json_variant_elements(p), 2U);

        /* zap is null */
        q = sd_json_variant_by_key(p, "zap");
        ASSERT_NOT_NULL(q);
        ASSERT_EQ((int) sd_json_variant_type(q), SD_JSON_VARIANT_NULL);
}

static void test_2(sd_json_variant *v) {
        sd_json_variant *p, *q;

        log_info("/* %s */", __func__);

        /* 2 keys + 2 values */
        ASSERT_EQ(sd_json_variant_elements(v), 4U);

        /* has mutant */
        p = sd_json_variant_by_key(v, "mutant");
        ASSERT_NOT_NULL(p);
        ASSERT_EQ((int) sd_json_variant_type(p), SD_JSON_VARIANT_ARRAY);
        ASSERT_EQ(sd_json_variant_elements(p), 4U);

        /* mutant[0] == 1 */
        q = sd_json_variant_by_index(p, /* index= */ 0);
        ASSERT_NOT_NULL(q);
        ASSERT_EQ((int) sd_json_variant_type(q), SD_JSON_VARIANT_UNSIGNED);
        ASSERT_EQ(sd_json_variant_unsigned(q), 1U);
        ASSERT_TRUE(sd_json_variant_has_type(q, SD_JSON_VARIANT_INTEGER));
        ASSERT_EQ(sd_json_variant_integer(q), 1);

        /* mutant[1] == null */
        q = sd_json_variant_by_index(p, 1);
        ASSERT_NOT_NULL(q);
        ASSERT_EQ((int) sd_json_variant_type(q), SD_JSON_VARIANT_NULL);

        /* mutant[2] == "1" */
        q = sd_json_variant_by_index(p, 2);
        ASSERT_NOT_NULL(q);
        ASSERT_EQ((int) sd_json_variant_type(q), SD_JSON_VARIANT_STRING);
        ASSERT_STREQ(sd_json_variant_string(q), "1");

        /* mutant[3] == SD_JSON_VARIANT_OBJECT */
        q = sd_json_variant_by_index(p, 3);
        ASSERT_NOT_NULL(q);
        ASSERT_EQ((int) sd_json_variant_type(q), SD_JSON_VARIANT_OBJECT);
        ASSERT_EQ(sd_json_variant_elements(q), 2U);

        /* has 1 */
        p = sd_json_variant_by_key(q, "1");
        ASSERT_NOT_NULL(p);
        ASSERT_EQ((int) sd_json_variant_type(p), SD_JSON_VARIANT_ARRAY);
        ASSERT_EQ(sd_json_variant_elements(p), 2U);

        /* "1"[0] == 1 */
        q = sd_json_variant_by_index(p, /* index= */ 0);
        ASSERT_NOT_NULL(q);
        ASSERT_EQ((int) sd_json_variant_type(q), SD_JSON_VARIANT_UNSIGNED);
        ASSERT_EQ(sd_json_variant_unsigned(q), 1U);
        ASSERT_TRUE(sd_json_variant_has_type(q, SD_JSON_VARIANT_INTEGER));
        ASSERT_EQ(sd_json_variant_integer(q), 1);

        /* "1"[1] == "1" */
        q = sd_json_variant_by_index(p, 1);
        ASSERT_NOT_NULL(q);
        ASSERT_EQ((int) sd_json_variant_type(q), SD_JSON_VARIANT_STRING);
        ASSERT_STREQ(sd_json_variant_string(q), "1");

        /* has thisisaverylongproperty */
        p = sd_json_variant_by_key(v, "thisisaverylongproperty");
        ASSERT_NOT_NULL(p);
        ASSERT_EQ((int) sd_json_variant_type(p), SD_JSON_VARIANT_REAL);
        ASSERT_TRUE(ABS(sd_json_variant_real(p) - 1.27) < 0.001);
}

static void test_zeroes(sd_json_variant *v) {
        /* Make sure zero is how we expect it. */
        log_info("/* %s */", __func__);

        ASSERT_EQ(sd_json_variant_elements(v), 13U);

        for (size_t i = 0; i < sd_json_variant_elements(v); i++) {
                sd_json_variant *w;
                size_t j;

                ASSERT_NOT_NULL(w = sd_json_variant_by_index(v, i));

                ASSERT_EQ(sd_json_variant_integer(w), 0);
                ASSERT_EQ(sd_json_variant_unsigned(w), 0U);

                ASSERT_TRUE(iszero_safe(sd_json_variant_real(w)));

                ASSERT_TRUE(sd_json_variant_is_integer(w));
                ASSERT_TRUE(sd_json_variant_is_unsigned(w));
                ASSERT_TRUE(sd_json_variant_is_real(w));
                ASSERT_TRUE(sd_json_variant_is_number(w));

                ASSERT_FALSE(sd_json_variant_is_negative(w));

                ASSERT_TRUE(IN_SET(sd_json_variant_type(w), SD_JSON_VARIANT_INTEGER, SD_JSON_VARIANT_UNSIGNED, SD_JSON_VARIANT_REAL));

                for (j = 0; j < sd_json_variant_elements(v); j++) {
                        sd_json_variant *q;

                        ASSERT_NOT_NULL(q = sd_json_variant_by_index(v, j));

                        ASSERT_TRUE(sd_json_variant_equal(w, q));
                }
        }
}

static int test_callback(sd_json_variant **ret, const char *name, void *userdata) {

        if (streq_ptr(name, "mypid1"))
                ASSERT_EQ(PTR_TO_INT(userdata), 4711);
        else if (streq_ptr(name, "mypid2"))
                ASSERT_EQ(PTR_TO_INT(userdata), 4712);
        else if (streq_ptr(name, "mypid3"))
                return 0;
        else
                assert_not_reached();

        return sd_json_build(ret, SD_JSON_BUILD_INTEGER(getpid()));
}

TEST(build) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL, *b = NULL;
        _cleanup_free_ char *s = NULL, *t = NULL;

        ASSERT_OK(sd_json_build(&a, SD_JSON_BUILD_STRING("hallo")));
        ASSERT_OK(sd_json_build(&b, SD_JSON_BUILD_LITERAL(" \"hallo\"   ")));
        ASSERT_TRUE(sd_json_variant_equal(a, b));

        b = sd_json_variant_unref(b);

        ASSERT_OK(sd_json_build(&b, SD_JSON_BUILD_VARIANT(a)));
        ASSERT_TRUE(sd_json_variant_equal(a, b));

        b = sd_json_variant_unref(b);
        ASSERT_OK(sd_json_build(&b, SD_JSON_BUILD_STRING("pief")));
        ASSERT_FALSE(sd_json_variant_equal(a, b));

        a = sd_json_variant_unref(a);
        b = sd_json_variant_unref(b);

        ASSERT_OK(sd_json_buildo(&a,
                                 SD_JSON_BUILD_PAIR("one", SD_JSON_BUILD_INTEGER(7)),
                                 SD_JSON_BUILD_PAIR("two", SD_JSON_BUILD_REAL(2.0)),
                                 SD_JSON_BUILD_PAIR("four", JSON_BUILD_STRING_UNDERSCORIFY("foo-bar-baz")),
                                 SD_JSON_BUILD_PAIR("three", SD_JSON_BUILD_INTEGER(0))));

        ASSERT_OK(sd_json_buildo(&b,
                                 SD_JSON_BUILD_PAIR("two", SD_JSON_BUILD_INTEGER(2)),
                                 SD_JSON_BUILD_PAIR("four", SD_JSON_BUILD_STRING("foo_bar_baz")),
                                 SD_JSON_BUILD_PAIR("three", SD_JSON_BUILD_REAL(0)),
                                 SD_JSON_BUILD_PAIR("one", SD_JSON_BUILD_REAL(7))));

        ASSERT_TRUE(sd_json_variant_equal(a, b));

        a = sd_json_variant_unref(a);
        b = sd_json_variant_unref(b);

        const char* arr_1234[] = {"one", "two", "three", "four", NULL};
        ASSERT_OK(sd_json_build(&a, SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("x", SD_JSON_BUILD_BOOLEAN(true)),
                                                                    SD_JSON_BUILD_PAIR("y", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("this", SD_JSON_BUILD_NULL)))),
                                                  SD_JSON_BUILD_VARIANT(NULL),
                                                  SD_JSON_BUILD_LITERAL(NULL),
                                                  SD_JSON_BUILD_STRING(NULL),
                                                  SD_JSON_BUILD_NULL,
                                                  SD_JSON_BUILD_INTEGER(77),
                                                  SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_VARIANT(JSON_VARIANT_STRING_CONST("foobar")),
                                                                   SD_JSON_BUILD_VARIANT(JSON_VARIANT_STRING_CONST("zzz"))),
                                                  SD_JSON_BUILD_STRV((char**) arr_1234))));

        ASSERT_OK(sd_json_variant_format(a, /* flags= */ 0, &s));
        log_info("GOT: %s", s);
        ASSERT_OK(sd_json_parse(s, /* flags= */ 0, &b, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_TRUE(sd_json_variant_equal(a, b));

        a = sd_json_variant_unref(a);
        b = sd_json_variant_unref(b);

        ASSERT_OK(sd_json_build(&a, SD_JSON_BUILD_REAL(M_PI)));

        s = mfree(s);
        ASSERT_OK(sd_json_variant_format(a, /* flags= */ 0, &s));
        log_info("GOT: %s", s);
        ASSERT_OK(sd_json_parse(s, /* flags= */ 0, &b, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_OK(sd_json_variant_format(b, /* flags= */ 0, &t));
        log_info("GOT: %s", t);

        ASSERT_STREQ(s, t);

        a = sd_json_variant_unref(a);
        b = sd_json_variant_unref(b);

        ASSERT_OK(sd_json_build(&a, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("x", SD_JSON_BUILD_STRING("y")),
                                             SD_JSON_BUILD_PAIR("z", JSON_BUILD_CONST_STRING("a")),
                                             SD_JSON_BUILD_PAIR("b", JSON_BUILD_CONST_STRING("c"))
                             )));

        ASSERT_OK(sd_json_build(&b, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("x", SD_JSON_BUILD_STRING("y")),
                                             SD_JSON_BUILD_PAIR_CONDITION(false, "p", SD_JSON_BUILD_STRING("q")),
                                             SD_JSON_BUILD_PAIR_CONDITION(true, "z", JSON_BUILD_CONST_STRING("a")),
                                             SD_JSON_BUILD_PAIR_CONDITION(false, "j", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_STRING("k"), JSON_BUILD_CONST_STRING("u"), JSON_BUILD_CONST_STRING("i"))),
                                             SD_JSON_BUILD_PAIR("b", JSON_BUILD_CONST_STRING("c"))
                             )));

        ASSERT_TRUE(sd_json_variant_equal(a, b));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *x = NULL;
        ASSERT_OK(sd_json_build(&x, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("foo", SD_JSON_BUILD_INTEGER(77)),
                                                         SD_JSON_BUILD_PAIR("bar", SD_JSON_BUILD_INTEGER(88)))));

        sd_json_variant *array[] = { a, a, b, b, x, x };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *va = NULL;

        ASSERT_OK(sd_json_build(&va, SD_JSON_BUILD_VARIANT_ARRAY(array, ELEMENTSOF(array))));

        ASSERT_TRUE(sd_json_variant_is_array(va));
        ASSERT_EQ(sd_json_variant_elements(va), 6U);
        ASSERT_TRUE(sd_json_variant_equal(sd_json_variant_by_index(va, /* index= */ 0), a));
        ASSERT_TRUE(sd_json_variant_equal(sd_json_variant_by_index(va, 1), b));
        ASSERT_TRUE(sd_json_variant_equal(sd_json_variant_by_index(va, 2), a));
        ASSERT_TRUE(sd_json_variant_equal(sd_json_variant_by_index(va, 3), b));
        ASSERT_TRUE(sd_json_variant_equal(sd_json_variant_by_index(va, 4), x));
        ASSERT_TRUE(sd_json_variant_equal(sd_json_variant_by_index(va, 5), x));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *y = NULL;
        ASSERT_OK(sd_json_build(&y, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("mypid1", SD_JSON_BUILD_CALLBACK(test_callback, INT_TO_PTR(4711))),
                                                         SD_JSON_BUILD_PAIR("mypid2", SD_JSON_BUILD_CALLBACK(test_callback, INT_TO_PTR(4712))))));

        _cleanup_free_ char *f1 = NULL, *f2 = NULL;
        ASSERT_OK_ERRNO(asprintf(&f1, "{\"mypid1\":" PID_FMT ",\"mypid2\":" PID_FMT "}",
                                 getpid(), getpid()));

        ASSERT_OK_POSITIVE(sd_json_variant_format(y, /* flags= */ 0, &f2));
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
        ASSERT_OK(set_ensure_put(&ss, &string_hash_ops_free, ASSERT_PTR(strdup("pief"))));
        ASSERT_OK(set_ensure_put(&ss, &string_hash_ops_free, ASSERT_PTR(strdup("xxxx"))));
        ASSERT_OK(set_ensure_put(&ss, &string_hash_ops_free, ASSERT_PTR(strdup("kawumm"))));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ssv = NULL;
        ASSERT_OK(sd_json_build(&ssv, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("zzz", JSON_BUILD_STRING_SET(ss)))));
        ASSERT_OK(sd_json_variant_sort(&ssv));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ssv2 = NULL;
        ASSERT_OK(sd_json_build(&ssv2, SD_JSON_BUILD_LITERAL("{\"zzz\":[\"kawumm\",\"pief\",\"xxxx\"]}")));

        ASSERT_TRUE(sd_json_variant_equal(ssv, ssv2));

        _cleanup_ordered_set_free_ OrderedSet *oss = NULL;
        ASSERT_OK(ordered_set_ensure_put(&oss, &string_hash_ops_free, ASSERT_PTR(strdup("pief"))));
        ASSERT_OK(ordered_set_ensure_put(&oss, &string_hash_ops_free, ASSERT_PTR(strdup("xxxx"))));
        ASSERT_OK(ordered_set_ensure_put(&oss, &string_hash_ops_free, ASSERT_PTR(strdup("kawumm"))));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ossv = NULL;
        ASSERT_OK(sd_json_build(&ossv, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("zzz", JSON_BUILD_STRING_ORDERED_SET(oss)))));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ossv2 = NULL;
        ASSERT_OK(sd_json_build(&ossv2, SD_JSON_BUILD_LITERAL("{\"zzz\":[\"pief\",\"xxxx\",\"kawumm\"]}")));

        ASSERT_TRUE(sd_json_variant_equal(ossv, ossv2));
}

TEST(json_buildo) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL, *b = NULL;

        ASSERT_OK(sd_json_buildo(&a,
                                 SD_JSON_BUILD_PAIR("foo", SD_JSON_BUILD_INTEGER(4711)),
                                 SD_JSON_BUILD_PAIR("bar", SD_JSON_BUILD_STRING("xxxx"))));

        ASSERT_OK(sd_json_build(&b,
                                SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR("bar", SD_JSON_BUILD_STRING("xxxx")),
                                                SD_JSON_BUILD_PAIR("foo", SD_JSON_BUILD_INTEGER(4711)))));

        ASSERT_TRUE(sd_json_variant_equal(a, b));
}

TEST(json_parse_file_empty) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        ASSERT_OK(fopen_unlocked("/dev/null", "re", &f));
        ASSERT_ERROR(sd_json_parse_file(f, "waldo", /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL), ENODATA);
        ASSERT_NULL(v);
}

TEST(json_parse_file_invalid) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        ASSERT_NOT_NULL(f = fmemopen_unlocked((void*) "kookoo", 6, "r"));
        ASSERT_ERROR(sd_json_parse_file(f, "waldo", /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
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

        ASSERT_NOT_NULL(f = fmemopen_unlocked((void*) data, strlen(data), "r"));

        ASSERT_OK(sd_json_parse_file(f, "waldo", /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL));

        printf("--- non-pretty begin ---\n");
        sd_json_variant_dump(v, /* flags= */ 0, stdout, /* prefix= */ NULL);
        printf("\n--- non-pretty end ---\n");

        printf("--- pretty begin ---\n");
        sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_SOURCE, stdout, /* prefix= */ NULL);
        printf("--- pretty end ---\n");
}

TEST(parse_fd) {
        static const char data[] = "{ \"foo\" : \"bar\", \"baz\" : 4711 }";

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_close_ int fd = -EBADF;

        ASSERT_OK(fd = open_tmpfile_unlinkable(/* directory= */ NULL, O_RDWR));
        ASSERT_OK(loop_write(fd, data, strlen(data)));

        /* By default the fd is internally duplicated, the caller's fd stays open and the JSON text is
         * read starting at the current file offset. */
        ASSERT_OK_ERRNO(lseek(fd, 0, SEEK_SET));
        ASSERT_OK(sd_json_parse_fd("tmpfile", fd, /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_OK(fd_validate(fd));     /* still open, we only got a duplicate */
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(v, "foo")), "bar");
        ASSERT_EQ(sd_json_variant_unsigned(sd_json_variant_by_key(v, "baz")), UINT64_C(4711));
        v = sd_json_variant_unref(v);

        /* Without SD_JSON_PARSE_SEEK0 and with the offset left at EOF there is nothing to read. */
        ASSERT_OK_ERRNO(lseek(fd, 0, SEEK_END));
        ASSERT_ERROR(sd_json_parse_fd("tmpfile", fd, /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL), ENODATA);
        ASSERT_NULL(v);
        ASSERT_OK(fd_validate(fd));

        /* SD_JSON_PARSE_SEEK0 rewinds to the beginning first, so the stale offset no longer matters. */
        ASSERT_OK(sd_json_parse_fd("tmpfile", fd, SD_JSON_PARSE_SEEK0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_OK(fd_validate(fd));
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(v, "foo")), "bar");
        v = sd_json_variant_unref(v);

        /* SD_JSON_PARSE_REOPEN_FD reopens the fd internally (starting at offset 0), the caller's fd and
         * its offset are left untouched. */
        ASSERT_OK_ERRNO(lseek(fd, 0, SEEK_END));
        ASSERT_OK(sd_json_parse_fd("tmpfile", fd, SD_JSON_PARSE_REOPEN_FD, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_OK(fd_validate(fd));
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(v, "foo")), "bar");
        v = sd_json_variant_unref(v);

        /* SD_JSON_PARSE_REOPEN_FD and SD_JSON_PARSE_DONATE_FD are mutually exclusive. */
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_json_parse_fd("tmpfile", fd, SD_JSON_PARSE_REOPEN_FD|SD_JSON_PARSE_DONATE_FD, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL));
        ASSERT_OK(fd_validate(fd));     /* not consumed on the -EINVAL path */

        /* SD_JSON_PARSE_DONATE_FD passes ownership into the call: the fd is consumed and closed even on
         * success. */
        ASSERT_OK_ERRNO(lseek(fd, 0, SEEK_SET));
        ASSERT_OK(sd_json_parse_fd("tmpfile", fd, SD_JSON_PARSE_DONATE_FD, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_ERROR(fd_validate(fd), EBADF);
        TAKE_FD(fd);                    /* already closed by the call, don't double-close */
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(v, "foo")), "bar");
        v = sd_json_variant_unref(v);

        /* SD_JSON_PARSE_DONATE_FD also consumes the fd when parsing fails. */
        _cleanup_close_ int fd2 = -EBADF;
        ASSERT_OK(fd2 = open_tmpfile_unlinkable(/* directory= */ NULL, O_RDWR));
        ASSERT_OK(loop_write(fd2, "kookoo", strlen("kookoo")));
        ASSERT_OK_ERRNO(lseek(fd2, 0, SEEK_SET));
        ASSERT_ERROR(sd_json_parse_fd("tmpfile", fd2, SD_JSON_PARSE_DONATE_FD, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_ERROR(fd_validate(fd2), EBADF);
        TAKE_FD(fd2);
        ASSERT_NULL(v);
}

TEST(depth) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        v = JSON_VARIANT_STRING_CONST("start");

        /* Let's verify that the maximum depth checks work */

        for (unsigned i = 0;; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;

                ASSERT_LE(i, (unsigned) UINT16_MAX);
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

                ASSERT_OK(r);

                json_variant_unref_and_replace(v, w);
        }

        sd_json_variant_dump(v, /* flags= */ 0, stdout, /* prefix= */ NULL);
        fputs("\n", stdout);
}

static char *prepare_nested_json(const char *open, unsigned depth) {
        char *s, *p;
        size_t olen;

        ASSERT_NOT_NULL(open);

        olen = strlen(open);
        s = p = new(char, olen * depth + 1);
        if (!s)
                return NULL;

        for (unsigned i = 0; i < depth; i++)
                p = mempcpy(p, open, olen);
        *p = '\0';

        return s;
}

TEST(parse_depth) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *s = NULL;

        /* Refuse parsing > DEPTH_MAX (currently 2048) levels of nested arrays */
        s = prepare_nested_json("[", 2049);
        ASSERT_ERROR(sd_json_parse(s, /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL), ELNRNG);
        s = mfree(s);

        /* Same for nested objects */
        s = prepare_nested_json("{\"a\":", 2049);
        ASSERT_ERROR(sd_json_parse(s, /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL), ELNRNG);
        s = mfree(s);

        /* <= DEPTH_MAX levels of nested arrays should be refused by EINVAL
         * later in the parsing process */
        s = prepare_nested_json("[", 2048);
        ASSERT_ERROR(sd_json_parse(s, /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        s = mfree(s);

        /* And the same for nested objects */
        s = prepare_nested_json("{\"a\":", 2048);
        ASSERT_ERROR(sd_json_parse(s, /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
}

TEST(normalize) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
        _cleanup_free_ char *t = NULL;

        ASSERT_OK(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_STRING("x")),
                                             SD_JSON_BUILD_PAIR("c", JSON_BUILD_CONST_STRING("y")),
                                             SD_JSON_BUILD_PAIR("a", JSON_BUILD_CONST_STRING("z")))));

        ASSERT_FALSE(sd_json_variant_is_sorted(v));
        ASSERT_FALSE(sd_json_variant_is_normalized(v));

        ASSERT_OK(sd_json_variant_format(v, /* flags= */ 0, &t));
        ASSERT_STREQ(t, "{\"b\":\"x\",\"c\":\"y\",\"a\":\"z\"}");
        t = mfree(t);

        ASSERT_OK(sd_json_build(&w, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("bar", SD_JSON_BUILD_STRING("zzz")),
                                             SD_JSON_BUILD_PAIR("foo", SD_JSON_BUILD_VARIANT(v)))));

        ASSERT_TRUE(sd_json_variant_is_sorted(w));
        ASSERT_FALSE(sd_json_variant_is_normalized(w));

        ASSERT_OK(sd_json_variant_format(w, /* flags= */ 0, &t));
        ASSERT_STREQ(t, "{\"bar\":\"zzz\",\"foo\":{\"b\":\"x\",\"c\":\"y\",\"a\":\"z\"}}");
        t = mfree(t);

        ASSERT_OK(sd_json_variant_sort(&v));
        ASSERT_TRUE(sd_json_variant_is_sorted(v));
        ASSERT_TRUE(sd_json_variant_is_normalized(v));

        ASSERT_OK(sd_json_variant_format(v, /* flags= */ 0, &t));
        ASSERT_STREQ(t, "{\"a\":\"z\",\"b\":\"x\",\"c\":\"y\"}");
        t = mfree(t);

        ASSERT_OK(sd_json_variant_normalize(&w));
        ASSERT_TRUE(sd_json_variant_is_sorted(w));
        ASSERT_TRUE(sd_json_variant_is_normalized(w));

        ASSERT_OK(sd_json_variant_format(w, /* flags= */ 0, &t));
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
                ASSERT_OK(sd_json_variant_new_stringn(&w, (char[4]) { '<', c, c, '>' }, 4));
                ASSERT_OK(sd_json_variant_set_field(&v, (char[2]) { c, 0 }, w));
        }

        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, /* prefix= */ NULL);

        ASSERT_FALSE(sd_json_variant_is_sorted(v));
        ASSERT_FALSE(sd_json_variant_is_normalized(v));
        ASSERT_OK(sd_json_variant_normalize(&v));
        ASSERT_TRUE(sd_json_variant_is_sorted(v));
        ASSERT_TRUE(sd_json_variant_is_normalized(v));

        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, /* prefix= */ NULL);

        for (char c = 'a'; c <= 'z'; c++) {
                sd_json_variant *k;
                const char *z;

                k = sd_json_variant_by_key(v, (char[2]) { c, 0 });
                ASSERT_EQ(!k, (c % 3) == 0);

                if (!k)
                        continue;

                ASSERT_TRUE(sd_json_variant_is_string(k));

                z = (char[5]){ '<', c, c, '>', 0};
                ASSERT_STREQ(sd_json_variant_string(k), z);
        }
}

static void test_float_match(sd_json_variant *v) {
        const double delta = 0.0001;

        ASSERT_TRUE(sd_json_variant_is_array(v));
        ASSERT_EQ(sd_json_variant_elements(v), 11U);
        ASSERT_FALSE(iszero_safe(sd_json_variant_real(sd_json_variant_by_index(v, /* index= */ 0))));
        ASSERT_TRUE(ABS(1.0 - (DBL_MIN / sd_json_variant_real(sd_json_variant_by_index(v, /* index= */ 0)))) <= delta);
        ASSERT_FALSE(iszero_safe(sd_json_variant_real(sd_json_variant_by_index(v, 1))));
        ASSERT_TRUE(ABS(1.0 - (DBL_MAX / sd_json_variant_real(sd_json_variant_by_index(v, 1)))) <= delta);
        ASSERT_TRUE(sd_json_variant_is_null(sd_json_variant_by_index(v, 2))); /* nan is not supported by json → null */
        ASSERT_TRUE(sd_json_variant_is_null(sd_json_variant_by_index(v, 3))); /* +inf is not supported by json → null */
        ASSERT_TRUE(sd_json_variant_is_null(sd_json_variant_by_index(v, 4))); /* -inf is not supported by json → null */
        ASSERT_TRUE(sd_json_variant_is_null(sd_json_variant_by_index(v, 5)) ||
                    ABS(1.0 - (HUGE_VAL / sd_json_variant_real(sd_json_variant_by_index(v, 5)))) <= delta); /* HUGE_VAL might be +inf, but might also be something else */
        ASSERT_TRUE(sd_json_variant_is_real(sd_json_variant_by_index(v, 6)));
        ASSERT_TRUE(sd_json_variant_is_integer(sd_json_variant_by_index(v, 6)));
        ASSERT_EQ(sd_json_variant_integer(sd_json_variant_by_index(v, 6)), 0);
        ASSERT_TRUE(sd_json_variant_is_real(sd_json_variant_by_index(v, 7)));
        ASSERT_TRUE(sd_json_variant_is_integer(sd_json_variant_by_index(v, 7)));
        ASSERT_EQ(sd_json_variant_integer(sd_json_variant_by_index(v, 7)), 10);
        ASSERT_TRUE(sd_json_variant_is_real(sd_json_variant_by_index(v, 8)));
        ASSERT_TRUE(sd_json_variant_is_integer(sd_json_variant_by_index(v, 8)));
        ASSERT_EQ(sd_json_variant_integer(sd_json_variant_by_index(v, 8)), -10);
        ASSERT_TRUE(sd_json_variant_is_real(sd_json_variant_by_index(v, 9)));
        ASSERT_FALSE(sd_json_variant_is_integer(sd_json_variant_by_index(v, 9)));
        ASSERT_FALSE(iszero_safe(sd_json_variant_real(sd_json_variant_by_index(v, 9))));
        ASSERT_TRUE(ABS(1.0 - (DBL_MIN / 2 / sd_json_variant_real(sd_json_variant_by_index(v, 9)))) <= delta);
        ASSERT_TRUE(sd_json_variant_is_real(sd_json_variant_by_index(v, 10)));
        ASSERT_FALSE(sd_json_variant_is_integer(sd_json_variant_by_index(v, 10)));
        ASSERT_FALSE(iszero_safe(sd_json_variant_real(sd_json_variant_by_index(v, 10))));
        ASSERT_TRUE(ABS(1.0 - (-DBL_MIN / 2 / sd_json_variant_real(sd_json_variant_by_index(v, 10)))) <= delta);
}

TEST(float) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
        _cleanup_free_ char *text = NULL;

        ASSERT_OK(sd_json_build(&v, SD_JSON_BUILD_ARRAY(
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
                                             SD_JSON_BUILD_REAL(-DBL_MIN / 2))));

        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, /* prefix= */ NULL);

        test_float_match(v);

        ASSERT_OK(sd_json_variant_format(v, /* flags= */ 0, &text));
        ASSERT_OK(sd_json_parse(text, /* flags= */ 0, &w, /* reterr_line= */ NULL, /* reterr_column= */ NULL));

        sd_json_variant_dump(w, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, /* prefix= */ NULL);

        test_float_match(w);
}

static void test_equal_text(sd_json_variant *v, const char *text) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;

        ASSERT_OK(sd_json_parse(text, /* flags= */ 0, &w, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_TRUE(sd_json_variant_equal(v, w) || (!v && sd_json_variant_is_null(w)));
}

TEST(set_field) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        test_equal_text(v, "null");
        ASSERT_OK(sd_json_variant_set_field(&v, "foo", /* value= */ NULL));
        test_equal_text(v, "{\"foo\" : null}");
        ASSERT_OK(sd_json_variant_set_field(&v, "bar", JSON_VARIANT_STRING_CONST("quux")));
        test_equal_text(v, "{\"foo\" : null, \"bar\" : \"quux\"}");
        ASSERT_OK(sd_json_variant_set_field(&v, "foo", JSON_VARIANT_STRING_CONST("quux2")));
        test_equal_text(v, "{\"foo\" : \"quux2\", \"bar\" : \"quux\"}");
        ASSERT_OK(sd_json_variant_set_field(&v, "bar", /* value= */ NULL));
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
        test_variant_one(
                        "{\"foo\" : \"\\u0935\\u093f\\u0935\\u0947\\u0915\\u0916\\u094d\\u092f\\u093e\\u0924\\u093f\\u0930\\u0935\\u093f\\u092a\\u094d\\u0932\\u0935\\u093e\\u0020\\u0939\\u093e\\u0928\\u094b\\u092a\\u093e\\u092f\\u0903\\u0964\"}",
                        /* test= */ NULL);

        test_variant_one("[ 0, -0, 0.0, -0.0, 0.000, -0.000, 0e0, -0e0, 0e+0, -0e-0, 0e-0, -0e000, 0e+000 ]", test_zeroes);
}

TEST(json_variant_merge_objectb) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;

        ASSERT_OK(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_STRING("x")),
                                             SD_JSON_BUILD_PAIR("c", JSON_BUILD_CONST_STRING("y")),
                                             SD_JSON_BUILD_PAIR("a", JSON_BUILD_CONST_STRING("z")))));

        ASSERT_OK(sd_json_variant_merge_objectb(&w, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_STRING("x")))));
        ASSERT_OK(sd_json_variant_merge_objectb(&w, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_STRING("y")))));
        ASSERT_OK(sd_json_variant_merge_objectb(&w, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("a", SD_JSON_BUILD_STRING("z")))));

        ASSERT_TRUE(sd_json_variant_equal(v, w));
}

static void json_array_append_with_source_one(bool source) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a, *b;

        /* Parse two sources, each with a different name and line/column numbers */

        ASSERT_OK(sd_json_parse_with_source(" [41]", source ? "string 1" : NULL, /* flags= */ 0,
                                         &a, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_OK(sd_json_parse_with_source("\n\n   [42]", source ? "string 2" : NULL, /* flags= */ 0,
                                         &b, /* reterr_line= */ NULL, /* reterr_column= */ NULL));

        ASSERT_TRUE(sd_json_variant_is_array(a));
        ASSERT_EQ(sd_json_variant_elements(a), 1U);
        ASSERT_TRUE(sd_json_variant_is_array(b));
        ASSERT_EQ(sd_json_variant_elements(b), 1U);

        /* Verify source information */

        const char *s1, *s2;
        unsigned line1, col1, line2, col2;
        ASSERT_OK(sd_json_variant_get_source(a, &s1, &line1, &col1));
        ASSERT_OK(sd_json_variant_get_source(b, &s2, &line2, &col2));

        ASSERT_STREQ(s1, source ? "string 1" : NULL);
        ASSERT_STREQ(s2, source ? "string 2" : NULL);
        ASSERT_EQ(line1, 1U);
        ASSERT_EQ(col1, 2U);
        ASSERT_EQ(line2, 3U);
        ASSERT_EQ(col2, 4U);

        /* Append one elem from the second array (and source) to the first. */

        sd_json_variant *elem;
        ASSERT_NOT_NULL(elem = sd_json_variant_by_index(b, /* index= */ 0));
        ASSERT_TRUE(sd_json_variant_is_integer(elem));
        ASSERT_EQ(sd_json_variant_elements(elem), 0U);

        ASSERT_OK(sd_json_variant_append_array(&a, elem));

        ASSERT_TRUE(sd_json_variant_is_array(a));
        ASSERT_EQ(sd_json_variant_elements(a), 2U);

        /* Verify that source information was propagated correctly */

        ASSERT_OK(sd_json_variant_get_source(elem, &s1, &line1, &col1));
        ASSERT_NOT_NULL(elem = sd_json_variant_by_index(a, 1));
        ASSERT_OK(sd_json_variant_get_source(elem, &s2, &line2, &col2));

        ASSERT_STREQ(s1, source ? "string 2" : NULL);
        ASSERT_STREQ(s2, source ? "string 2" : NULL);
        ASSERT_EQ(line1, 3U);
        ASSERT_EQ(col1, 5U);
        ASSERT_EQ(line2, 3U);
        ASSERT_EQ(col2, 5U);
}

TEST(json_array_append_with_source) {
        json_array_append_with_source_one(/* source= */ true);
}

TEST(json_array_append_without_source) {
        json_array_append_with_source_one(/* source= */ false);
}

TEST(json_array_append_nodup) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *l = NULL, *s = NULL, *wd = NULL, *nd = NULL;

        ASSERT_OK(sd_json_build(&l, SD_JSON_BUILD_STRV(STRV_MAKE("foo", "bar", "baz", "bar", "baz", "foo", "qux", "baz"))));
        ASSERT_OK(sd_json_build(&s, SD_JSON_BUILD_STRV(STRV_MAKE("foo", "bar", "baz", "qux"))));

        ASSERT_FALSE(sd_json_variant_equal(l, s));
        ASSERT_EQ(sd_json_variant_elements(l), 8U);
        ASSERT_EQ(sd_json_variant_elements(s), 4U);

        sd_json_variant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, l) {
                ASSERT_OK(sd_json_variant_append_array(&wd, i));
                ASSERT_OK(sd_json_variant_append_array_nodup(&nd, i));
        }

        ASSERT_EQ(sd_json_variant_elements(wd), 8U);
        ASSERT_TRUE(sd_json_variant_equal(l, wd));
        ASSERT_FALSE(sd_json_variant_equal(s, wd));

        ASSERT_EQ(sd_json_variant_elements(nd), 4U);
        ASSERT_FALSE(sd_json_variant_equal(l, nd));
        ASSERT_TRUE(sd_json_variant_equal(s, nd));
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

        ASSERT_OK(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
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
                                             SD_JSON_BUILD_PAIR("p", SD_JSON_BUILD_STRING("-128")))));

        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO, stdout, /* prefix= */ NULL));

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

        ASSERT_OK(sd_json_dispatch(v, table, SD_JSON_LOG, &foobar));

        ASSERT_EQ(foobar.a, UINT64_MAX);
        ASSERT_EQ(foobar.b, UINT64_MAX);
        ASSERT_EQ(foobar.c, INT64_MIN);
        ASSERT_EQ(foobar.d, INT64_MIN);

        ASSERT_EQ(foobar.e, UINT32_MAX);
        ASSERT_EQ(foobar.f, UINT32_MAX);
        ASSERT_EQ(foobar.g, INT32_MIN);
        ASSERT_EQ(foobar.h, INT32_MIN);

        ASSERT_EQ(foobar.i, UINT16_MAX);
        ASSERT_EQ(foobar.j, UINT16_MAX);
        ASSERT_EQ(foobar.k, INT16_MIN);
        ASSERT_EQ(foobar.l, INT16_MIN);

        ASSERT_EQ(foobar.m, UINT8_MAX);
        ASSERT_EQ(foobar.n, UINT8_MAX);
        ASSERT_EQ(foobar.o, INT8_MIN);
        ASSERT_EQ(foobar.p, INT8_MIN);
}

TEST(json_dispatch_null_to_zero) {
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

        ASSERT_OK(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR_NULL("a"),
                                             SD_JSON_BUILD_PAIR_NULL("b"),
                                             SD_JSON_BUILD_PAIR_NULL("c"),
                                             SD_JSON_BUILD_PAIR_NULL("d"),
                                             SD_JSON_BUILD_PAIR_NULL("e"),
                                             SD_JSON_BUILD_PAIR_NULL("f"),
                                             SD_JSON_BUILD_PAIR_NULL("g"),
                                             SD_JSON_BUILD_PAIR_NULL("h"),
                                             SD_JSON_BUILD_PAIR_NULL("i"),
                                             SD_JSON_BUILD_PAIR_NULL("j"),
                                             SD_JSON_BUILD_PAIR_NULL("k"),
                                             SD_JSON_BUILD_PAIR_NULL("l"),
                                             SD_JSON_BUILD_PAIR_NULL("m"),
                                             SD_JSON_BUILD_PAIR_NULL("n"),
                                             SD_JSON_BUILD_PAIR_NULL("o"),
                                             SD_JSON_BUILD_PAIR_NULL("p"))));

        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO, stdout, /* prefix= */ NULL));

        sd_json_dispatch_field table[] = {
                { "a", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct foobar, a), SD_JSON_NULL_TO_ZERO },
                { "b", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(struct foobar, b), 0                    },
                { "c", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int64,  offsetof(struct foobar, c), SD_JSON_NULL_TO_ZERO },
                { "d", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int64,  offsetof(struct foobar, d), 0                    },
                { "e", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32, offsetof(struct foobar, e), SD_JSON_NULL_TO_ZERO },
                { "f", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32, offsetof(struct foobar, f), 0                    },
                { "g", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int32,  offsetof(struct foobar, g), SD_JSON_NULL_TO_ZERO },
                { "h", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int32,  offsetof(struct foobar, h), 0                    },
                { "i", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16, offsetof(struct foobar, i), SD_JSON_NULL_TO_ZERO },
                { "j", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16, offsetof(struct foobar, j), 0                    },
                { "k", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int16,  offsetof(struct foobar, k), SD_JSON_NULL_TO_ZERO },
                { "l", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int16,  offsetof(struct foobar, l), 0                    },
                { "m", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,  offsetof(struct foobar, m), SD_JSON_NULL_TO_ZERO },
                { "n", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,  offsetof(struct foobar, n), 0                    },
                { "o", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int8,   offsetof(struct foobar, o), SD_JSON_NULL_TO_ZERO },
                { "p", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int8,   offsetof(struct foobar, p), 0                    },
                {}
        };

        ASSERT_OK(sd_json_dispatch(v, table, SD_JSON_LOG, &foobar));

        ASSERT_EQ(foobar.a, 0U);
        ASSERT_EQ(foobar.b, UINT64_MAX);
        ASSERT_EQ(foobar.c, 0);
        ASSERT_EQ(foobar.d, -1);

        ASSERT_EQ(foobar.e, 0U);
        ASSERT_EQ(foobar.f, UINT32_MAX);
        ASSERT_EQ(foobar.g, 0);
        ASSERT_EQ(foobar.h, -1);

        ASSERT_EQ(foobar.i, 0U);
        ASSERT_EQ(foobar.j, UINT16_MAX);
        ASSERT_EQ(foobar.k, 0);
        ASSERT_EQ(foobar.l, -1);

        ASSERT_EQ(foobar.m, 0U);
        ASSERT_EQ(foobar.n, UINT8_MAX);
        ASSERT_EQ(foobar.o, 0);
        ASSERT_EQ(foobar.p, -1);
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

        ASSERT_OK(sd_json_buildo(&j,
                                 SD_JSON_BUILD_PAIR("a", SD_JSON_BUILD_STRING("mybaz")),
                                 SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_STRING("mybar")),
                                 SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_STRING("myfoo")),
                                 SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_NULL),
                                 SD_JSON_BUILD_PAIR("e", JSON_BUILD_STRING_UNDERSCORIFY(mytestenum_to_string(with_some_dashes)))));

        ASSERT_OK(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "a", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_mytestenum, offsetof(struct data, a), 0 },
                                        { "b", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_mytestenum, offsetof(struct data, b), 0 },
                                        { "c", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_mytestenum, offsetof(struct data, c), 0 },
                                        { "d", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_mytestenum, offsetof(struct data, d), 0 },
                                        { "e", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_mytestenum, offsetof(struct data, e), 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &data));

        assert(data.a == mybaz);
        assert(data.b == mybar);
        assert(data.c == myfoo);
        assert(data.d < 0);
        assert(data.e == with_some_dashes);
}

TEST(json_dispatch_double) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;

        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("x1", SD_JSON_BUILD_REAL(0.5)),
                                             SD_JSON_BUILD_PAIR("x2", SD_JSON_BUILD_REAL(-0.5)),
                                             SD_JSON_BUILD_PAIR("x3", JSON_BUILD_CONST_STRING("infinity")),
                                             SD_JSON_BUILD_PAIR("x4", JSON_BUILD_CONST_STRING("-infinity")),
                                             SD_JSON_BUILD_PAIR("x5", JSON_BUILD_CONST_STRING("nan")),
                                             SD_JSON_BUILD_PAIR("x6", JSON_BUILD_CONST_STRING("inf")),
                                             SD_JSON_BUILD_PAIR("x7", JSON_BUILD_CONST_STRING("-inf")))));

        struct data {
                double x1, x2, x3, x4, x5, x6, x7;
        } data = {};

        ASSERT_OK(sd_json_dispatch(j,
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
                                &data));

        ASSERT_TRUE(ABS(data.x1 - 0.5) < 0.01);
        ASSERT_TRUE(ABS(data.x2 + 0.5) < 0.01);
        ASSERT_TRUE(isinf(data.x3));
        ASSERT_TRUE(data.x3 > 0);
        ASSERT_TRUE(isinf(data.x4));
        ASSERT_TRUE(data.x4 < 0);
        ASSERT_TRUE(isnan(data.x5));
        ASSERT_TRUE(isinf(data.x6));
        ASSERT_TRUE(data.x6 > 0);
        ASSERT_TRUE(isinf(data.x7));
        ASSERT_TRUE(data.x7 < 0);
}

TEST(json_sensitive) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL, *b = NULL, *v = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        ASSERT_OK(sd_json_build(&a, SD_JSON_BUILD_STRV(STRV_MAKE("foo", "bar", "baz", "bar", "baz", "foo", "qux", "baz"))));
        ASSERT_OK(sd_json_build(&b, SD_JSON_BUILD_STRV(STRV_MAKE("foo", "bar", "baz", "qux"))));

        sd_json_variant_sensitive(a);

        ASSERT_OK(sd_json_variant_format(a, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s));
        ASSERT_STREQ(s, "\"<sensitive data>\"");
        s = mfree(s);

        r = ASSERT_OK(sd_json_variant_format(b, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s));
        ASSERT_NOT_NULL(s);
        ASSERT_EQ((size_t) r, strlen(s));
        s = mfree(s);

        ASSERT_OK(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(INT64_MIN)),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_STRING("-9223372036854775808")),
                                             SD_JSON_BUILD_PAIR("e", SD_JSON_BUILD_EMPTY_OBJECT))));
        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, /* prefix= */ NULL);

        r = ASSERT_OK(sd_json_variant_format(v, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s));
        ASSERT_NOT_NULL(s);
        ASSERT_EQ((size_t) r, strlen(s));
        s = mfree(s);
        v = sd_json_variant_unref(v);

        ASSERT_OK(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR_VARIANT("b", b),
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(INT64_MIN)),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_STRING("-9223372036854775808")),
                                             SD_JSON_BUILD_PAIR("e", SD_JSON_BUILD_EMPTY_OBJECT))));
        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, /* prefix= */ NULL);

        r = ASSERT_OK(sd_json_variant_format(v, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s));
        ASSERT_NOT_NULL(s);
        ASSERT_EQ((size_t) r, strlen(s));
        s = mfree(s);
        v = sd_json_variant_unref(v);

        ASSERT_OK(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR_VARIANT("b", b),
                                             SD_JSON_BUILD_PAIR_VARIANT("a", a),
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(INT64_MIN)),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_STRING("-9223372036854775808")),
                                             SD_JSON_BUILD_PAIR("e", SD_JSON_BUILD_EMPTY_OBJECT))));
        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, /* prefix= */ NULL);

        ASSERT_OK(sd_json_variant_format(v, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s));
        ASSERT_STREQ(s, "{\"b\":[\"foo\",\"bar\",\"baz\",\"qux\"],\"a\":\"<sensitive data>\",\"c\":-9223372036854775808,\"d\":\"-9223372036854775808\",\"e\":{}}");
        s = mfree(s);
        v = sd_json_variant_unref(v);

        ASSERT_OK(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR_VARIANT("b", b),
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(INT64_MIN)),
                                             SD_JSON_BUILD_PAIR_VARIANT("a", a),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_STRING("-9223372036854775808")),
                                             SD_JSON_BUILD_PAIR("e", SD_JSON_BUILD_EMPTY_OBJECT))));
        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, /* prefix= */ NULL);

        ASSERT_OK(sd_json_variant_format(v, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s));
        ASSERT_STREQ(s, "{\"b\":[\"foo\",\"bar\",\"baz\",\"qux\"],\"c\":-9223372036854775808,\"a\":\"<sensitive data>\",\"d\":\"-9223372036854775808\",\"e\":{}}");
        s = mfree(s);
        v = sd_json_variant_unref(v);

        ASSERT_OK(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR_VARIANT("b", b),
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(INT64_MIN)),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_STRING("-9223372036854775808")),
                                             SD_JSON_BUILD_PAIR_VARIANT("a", a),
                                             SD_JSON_BUILD_PAIR("e", SD_JSON_BUILD_EMPTY_OBJECT))));
        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, /* prefix= */ NULL);

        ASSERT_OK(sd_json_variant_format(v, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s));
        ASSERT_STREQ(s, "{\"b\":[\"foo\",\"bar\",\"baz\",\"qux\"],\"c\":-9223372036854775808,\"d\":\"-9223372036854775808\",\"a\":\"<sensitive data>\",\"e\":{}}");
        s = mfree(s);
        v = sd_json_variant_unref(v);

        ASSERT_OK(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR_VARIANT("b", b),
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(INT64_MIN)),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_STRING("-9223372036854775808")),
                                             SD_JSON_BUILD_PAIR("e", SD_JSON_BUILD_EMPTY_OBJECT),
                                             SD_JSON_BUILD_PAIR_VARIANT("a", a))));
        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, /* prefix= */ NULL);

        ASSERT_OK(sd_json_variant_format(v, SD_JSON_FORMAT_CENSOR_SENSITIVE, &s));
        ASSERT_STREQ(s, "{\"b\":[\"foo\",\"bar\",\"baz\",\"qux\"],\"c\":-9223372036854775808,\"d\":\"-9223372036854775808\",\"e\":{},\"a\":\"<sensitive data>\"}");
}

TEST(json_iovec) {
        struct iovec iov1 = CONST_IOVEC_MAKE_STRING("üxknürz"), iov2 = CONST_IOVEC_MAKE_STRING("wuffwuffmiau");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("nr1", JSON_BUILD_IOVEC_BASE64(&iov1)),
                                             SD_JSON_BUILD_PAIR("nr2", JSON_BUILD_IOVEC_HEX(&iov2)))));

        sd_json_variant_dump(j, SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO, /* f= */ NULL, /* prefix= */ NULL);

        _cleanup_(iovec_done) struct iovec a = {}, b = {};
        ASSERT_OK(json_variant_unbase64_iovec(sd_json_variant_by_key(j, "nr1"), &a));
        ASSERT_OK(json_variant_unhex_iovec(sd_json_variant_by_key(j, "nr2"), &b));

        ASSERT_TRUE(iovec_equal(&iov1, &a));
        ASSERT_TRUE(iovec_equal(&iov2, &b));
        ASSERT_LT(iovec_memcmp(&iov2, &a), 0);
        ASSERT_GT(iovec_memcmp(&iov1, &b), 0);
}

TEST(json_dispatch_nullable) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;

        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("x1", JSON_BUILD_CONST_STRING("foo")),
                                             SD_JSON_BUILD_PAIR("x2", JSON_BUILD_CONST_STRING("bar")),
                                             SD_JSON_BUILD_PAIR("x3", JSON_BUILD_CONST_STRING("waldo")),
                                             SD_JSON_BUILD_PAIR("x4", JSON_BUILD_CONST_STRING("foo2")),
                                             SD_JSON_BUILD_PAIR("x5", JSON_BUILD_CONST_STRING("bar2")),
                                             SD_JSON_BUILD_PAIR("x6", JSON_BUILD_CONST_STRING("waldo2")),
                                             SD_JSON_BUILD_PAIR("x7", SD_JSON_BUILD_NULL),
                                             SD_JSON_BUILD_PAIR("x8", SD_JSON_BUILD_NULL),
                                             SD_JSON_BUILD_PAIR("x9", SD_JSON_BUILD_NULL))));

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

        ASSERT_OK(sd_json_dispatch(j,
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
                                &data));

        ASSERT_STREQ(data.x1, "foo");
        ASSERT_STREQ(data.x2, "bar");
        ASSERT_STREQ(data.x3, "waldo");
        ASSERT_STREQ(data.x4, "foo2");
        ASSERT_STREQ(data.x5, "bar2");
        ASSERT_STREQ(data.x6, "waldo2");
        ASSERT_NULL(data.x7);
        ASSERT_NULL(data.x8);
        ASSERT_NULL(data.x9);

        ASSERT_ERROR(sd_json_dispatch(j,
                                   (const sd_json_dispatch_field[]) {
                                           { "x7", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_const_string, offsetof(struct data, x7), SD_JSON_REFUSE_NULL },
                                           {},
                                   },
                                   /* flags= */ SD_JSON_ALLOW_EXTENSIONS,
                                   &data), EINVAL);

        ASSERT_ERROR(sd_json_dispatch(j,
                                   (const sd_json_dispatch_field[]) {
                                           { "x7", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(struct data, x7), SD_JSON_REFUSE_NULL },
                                           {},
                                   },
                                   /* flags= */ SD_JSON_ALLOW_EXTENSIONS,
                                   &data), EINVAL);

        ASSERT_ERROR(sd_json_dispatch(j,
                                   (const sd_json_dispatch_field[]) {
                                           { "x7", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(struct data, x7), 0 },
                                           {},
                                   },
                                   /* flags= */ SD_JSON_ALLOW_EXTENSIONS,
                                   &data), EINVAL);
}

TEST(parse_continue) {
        unsigned line = 23, column = 43;

        /* First try to parse with continue logic off, this should fail */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *x = NULL;
        ASSERT_ERROR(sd_json_parse_with_source("4711 512", "piff", /* flags= */ 0, &x, &line, &column), EINVAL);
        ASSERT_EQ(line, 1U);
        ASSERT_EQ(column, 6U);

        /* Then try to parse with continue logic on, which should yield two numbers */
        const char *p = "4711 512";
        ASSERT_OK(sd_json_parse_with_source_continue(&p, "piff", /* flags= */ 0, &x, &line, &column));
        ASSERT_TRUE(sd_json_variant_is_unsigned(x));
        ASSERT_EQ(sd_json_variant_unsigned(x), 4711U);
        x = sd_json_variant_unref(x);

        ASSERT_STREQ(p, " 512");
        ASSERT_OK(sd_json_parse_with_source_continue(&p, "piff", /* flags= */ 0, &x, &line, &column));
        ASSERT_TRUE(sd_json_variant_is_unsigned(x));
        ASSERT_EQ(sd_json_variant_unsigned(x), 512U);

        ASSERT_STREQ(p, "");
        ASSERT_ERROR(sd_json_parse_with_source_continue(&p, "piff", /* flags= */ 0, &x, &line, &column), EINVAL);
}

TEST(pidref) {
        _cleanup_(pidref_done) PidRef myself = PIDREF_NULL, pid1 = PIDREF_NULL;

        ASSERT_OK(pidref_set_pid(&myself, /* pid= */ 0));
        ASSERT_OK(pidref_set_pid(&pid1, 1));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        sd_id128_t randomized_boot_id;
        ASSERT_OK(sd_id128_randomize(&randomized_boot_id));
        ASSERT_OK(sd_json_buildo(&v,
                                 JSON_BUILD_PAIR_PIDREF("myself", &myself),
                                 JSON_BUILD_PAIR_PIDREF("pid1", &pid1),
                                 SD_JSON_BUILD_PAIR("remote", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR_UNSIGNED("pid", 1),
                                                                                   SD_JSON_BUILD_PAIR_UNSIGNED("pidfdId", 4711),
                                                                                   SD_JSON_BUILD_PAIR_ID128("bootId", randomized_boot_id))),
                                 SD_JSON_BUILD_PAIR("automatic", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR_UNSIGNED("pid", 0)))));

        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, /* prefix= */ NULL);

        struct {
                PidRef myself, pid1, remote, automatic;
        } data = {
                .myself = PIDREF_NULL,
                .pid1 = PIDREF_NULL,
                .remote = PIDREF_NULL,
                .automatic = PIDREF_NULL,
        };

        ASSERT_OK(sd_json_dispatch(
                                  v,
                                  (const sd_json_dispatch_field[]) {
                                          { "myself",    _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref, voffsetof(data, myself),    SD_JSON_STRICT },
                                          { "pid1",      _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref, voffsetof(data, pid1),      SD_JSON_STRICT },
                                          { "remote",    _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref, voffsetof(data, remote),    0              },
                                          { "automatic", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref, voffsetof(data, automatic), SD_JSON_RELAX  },
                                          {},
                                  },
                                  /* flags= */ 0,
                                  &data));

        ASSERT_TRUE(pidref_equal(&myself, &data.myself));
        ASSERT_TRUE(pidref_equal(&pid1, &data.pid1));

        ASSERT_FALSE(pidref_equal(&myself, &data.pid1));
        ASSERT_FALSE(pidref_equal(&pid1, &data.myself));
        ASSERT_FALSE(pidref_equal(&myself, &data.remote));
        ASSERT_FALSE(pidref_equal(&pid1, &data.remote));

        ASSERT_EQ(myself.fd_id > 0, data.myself.fd_id > 0);
        ASSERT_EQ(pid1.fd_id > 0, data.pid1.fd_id > 0);

        ASSERT_FALSE(pidref_is_set(&data.automatic));
        ASSERT_TRUE(pidref_is_automatic(&data.automatic));
        ASSERT_TRUE(pidref_is_set(&data.remote));
        ASSERT_TRUE(pidref_is_remote(&data.remote));

        pidref_done(&data.myself);
        pidref_done(&data.pid1);
        pidref_done(&data.remote);
}

TEST(devnum) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        dev_t dev = makedev(123, 456), parsed;

        ASSERT_OK(json_variant_new_devnum(&v, dev));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, /* prefix= */ NULL));
        ASSERT_OK(json_dispatch_devnum("devnum", v, /* flags= */ 0, &parsed));
        ASSERT_EQ(major(parsed), major(dev));
        ASSERT_EQ(minor(parsed), minor(dev));
        v = sd_json_variant_unref(v);

        dev = makedev(1 << 12, 456);
        ASSERT_OK(json_variant_new_devnum(&v, dev));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, /* prefix= */ NULL));
        ASSERT_FAIL(json_dispatch_devnum("devnum", v, /* flags= */ 0, &parsed));
        v = sd_json_variant_unref(v);

        dev = makedev(123, 1 << 20);
        ASSERT_OK(json_variant_new_devnum(&v, dev));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, /* prefix= */ NULL));
        ASSERT_FAIL(json_dispatch_devnum("devnum", v, /* flags= */ 0, &parsed));
}

TEST(fd_info) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        _cleanup_close_ int fd = -EBADF;

        /* directories */
        ASSERT_OK(json_variant_new_fd_info(&v, AT_FDCWD));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, /* prefix= */ NULL));
        v = sd_json_variant_unref(v);

        ASSERT_OK_ERRNO(fd = openat(AT_FDCWD, ".", O_CLOEXEC | O_DIRECTORY | O_PATH));
        ASSERT_OK(json_variant_new_fd_info(&v, fd));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, /* prefix= */ NULL));
        v = sd_json_variant_unref(v);
        fd = safe_close(fd);

        /* regular file */
        ASSERT_OK(fd = open_tmpfile_unlinkable(/* directory= */ NULL, O_RDWR));
        ASSERT_OK(json_variant_new_fd_info(&v, fd));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, /* prefix= */ NULL));
        v = sd_json_variant_unref(v);
        fd = safe_close(fd);

        fd = open("/sys/class/net/lo/uevent", O_CLOEXEC | O_PATH);
        if (fd >= 0) {
                ASSERT_OK(json_variant_new_fd_info(&v, fd));
                ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, /* prefix= */ NULL));
                v = sd_json_variant_unref(v);
                fd = safe_close(fd);
        }

        /* block device */
        fd = open("/dev/sda", O_CLOEXEC | O_PATH);
        if (fd >= 0) {
                ASSERT_OK(json_variant_new_fd_info(&v, fd));
                ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, /* prefix= */ NULL));
                v = sd_json_variant_unref(v);
                fd = safe_close(fd);
        }

        /* stream */
        ASSERT_OK(json_variant_new_fd_info(&v, fileno(stdout)));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, /* prefix= */ NULL));
        v = sd_json_variant_unref(v);

        /* socket */
        ASSERT_OK_ERRNO(fd = socket(AF_INET, SOCK_DGRAM, 0));
        ASSERT_OK(json_variant_new_fd_info(&v, fd));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, /* prefix= */ NULL));
        v = sd_json_variant_unref(v);
        fd = safe_close(fd);

        /* pidfd */
        ASSERT_OK(pidref_set_pid(&pidref, /* pid= */ 0));
        if (pidref.fd >= 0) {
                ASSERT_OK(json_variant_new_fd_info(&v, pidref.fd));
                ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, /* prefix= */ NULL));
                v = sd_json_variant_unref(v);
        }
        pidref_done(&pidref);

        ASSERT_OK(pidref_set_pid(&pidref, 1));
        if (pidref.fd >= 0) {
                ASSERT_OK(json_variant_new_fd_info(&v, pidref.fd));
                ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO, NULL, /* prefix= */ NULL));
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

        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, /* prefix= */ NULL);

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

TEST(job_id) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        ASSERT_OK(sd_json_parse("{\"a\": 1, \"b\": 4294967295, \"c\": null}",
                                /* flags= */ 0,
                                &v,
                                /* reterr_line= */ NULL,
                                /* reterr_column= */ NULL));

        struct {
                uint32_t a, b, c;
        } data = { 99, 99, 99 };

        ASSERT_OK(sd_json_dispatch(
                                  v,
                                  (const sd_json_dispatch_field[]) {
                                          { "a", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_job_id, voffsetof(data, a), 0 },
                                          { "b", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_job_id, voffsetof(data, b), 0 },
                                          { "c", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_job_id, voffsetof(data, c), 0 },
                                          {},
                                  },
                                  /* flags= */ 0,
                                  &data));

        ASSERT_EQ(data.a, UINT32_C(1));
        ASSERT_EQ(data.b, UINT32_MAX);
        ASSERT_EQ(data.c, UINT32_C(0));

        /* Zero is not a valid job ID */
        sd_json_variant_unrefp(&v);
        ASSERT_OK(sd_json_parse("{\"a\": 0}",
                                /* flags= */ 0,
                                &v,
                                /* reterr_line= */ NULL,
                                /* reterr_column= */ NULL));

        ASSERT_ERROR(sd_json_dispatch(
                                  v,
                                  (const sd_json_dispatch_field[]) {
                                          { "a", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_job_id, voffsetof(data, a), 0 },
                                          {},
                                  },
                                  /* flags= */ 0,
                                  &data), EINVAL);

        /* Negative values are not valid */
        sd_json_variant_unrefp(&v);
        ASSERT_OK(sd_json_parse("{\"a\": -1}",
                                /* flags= */ 0,
                                &v,
                                /* reterr_line= */ NULL,
                                /* reterr_column= */ NULL));

        ASSERT_ERROR(sd_json_dispatch(
                                  v,
                                  (const sd_json_dispatch_field[]) {
                                          { "a", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_job_id, voffsetof(data, a), 0 },
                                          {},
                                  },
                                  /* flags= */ 0,
                                  &data), EINVAL);
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
        test_json_variant_compare_one("0", "0", /* expected= */ 0);
        test_json_variant_compare_one("1", "1", /* expected= */ 0);
        test_json_variant_compare_one("1", "null", 1);
        test_json_variant_compare_one("null", "1", -1);
        test_json_variant_compare_one("null", "null", /* expected= */ 0);
        test_json_variant_compare_one("false", "true", -1);
        test_json_variant_compare_one("true", "false", 1);
        test_json_variant_compare_one("true", "true", /* expected= */ 0);
        test_json_variant_compare_one("false", "false", /* expected= */ 0);
        test_json_variant_compare_one("\"a\"", "\"b\"", -1);
        test_json_variant_compare_one("\"b\"", "\"a\"", 1);
        test_json_variant_compare_one("18446744073709551615", "0", 1);
        test_json_variant_compare_one("0", "18446744073709551615", -1);
        test_json_variant_compare_one("18446744073709551615", "18446744073709551615", /* expected= */ 0);
        test_json_variant_compare_one("-9223372036854775808", "18446744073709551615", -1);
        test_json_variant_compare_one("18446744073709551615", "-9223372036854775808", 1);
        test_json_variant_compare_one("1.1", "3.4", -1);
        test_json_variant_compare_one("1", "3.4", -1);
        test_json_variant_compare_one("[1,2]", "[1,2]", /* expected= */ 0);
        test_json_variant_compare_one("[1,2]", "[2,1]", -1);
        test_json_variant_compare_one("[1,2]", "[1,2,3]", -1);
        test_json_variant_compare_one("{}", "{\"a\":\"b\"}", -1);
        test_json_variant_compare_one("{\"a\":\"b\"}", "{\"a\":\"b\"}", /* expected= */ 0);
        test_json_variant_compare_one("{\"a\":\"b\"}", "{\"b\":\"c\"}", 1);
        test_json_variant_compare_one("{\"a\":\"b\",\"b\":\"c\"}", "{\"b\":\"c\",\"a\":\"b\"}", /* expected= */ 0);
        test_json_variant_compare_one("{\"a\":\"b\",\"b\":\"c\"}", "{\"a\":\"b\"}", 1);
}

TEST(must_be) {
        ASSERT_OK(sd_json_parse("null", /* flags= */ 0, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_ERROR(sd_json_parse("null", SD_JSON_PARSE_MUST_BE_OBJECT, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_ERROR(sd_json_parse("null", SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_ERROR(sd_json_parse("null", SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);

        ASSERT_OK(sd_json_parse("true", /* flags= */ 0, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_ERROR(sd_json_parse("true", SD_JSON_PARSE_MUST_BE_OBJECT, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_ERROR(sd_json_parse("true", SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_ERROR(sd_json_parse("true", SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);

        ASSERT_OK(sd_json_parse("\"foo\"", /* flags= */ 0, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_ERROR(sd_json_parse("\"foo\"", SD_JSON_PARSE_MUST_BE_OBJECT, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_ERROR(sd_json_parse("\"foo\"", SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_ERROR(sd_json_parse("\"foo\"", SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);

        ASSERT_OK(sd_json_parse("4711", /* flags= */ 0, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_ERROR(sd_json_parse("4711", SD_JSON_PARSE_MUST_BE_OBJECT, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_ERROR(sd_json_parse("4711", SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_ERROR(sd_json_parse("4711", SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);

        ASSERT_OK(sd_json_parse("-4711", /* flags= */ 0, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_ERROR(sd_json_parse("-4711", SD_JSON_PARSE_MUST_BE_OBJECT, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_ERROR(sd_json_parse("-4711", SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_ERROR(sd_json_parse("-4711", SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);

        ASSERT_OK(sd_json_parse("-4.5", /* flags= */ 0, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_ERROR(sd_json_parse("-4.5", SD_JSON_PARSE_MUST_BE_OBJECT, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_ERROR(sd_json_parse("-4.5", SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_ERROR(sd_json_parse("-4.5", SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);

        ASSERT_OK(sd_json_parse("{}", /* flags= */ 0, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_OK(sd_json_parse("{}", SD_JSON_PARSE_MUST_BE_OBJECT, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_ERROR(sd_json_parse("{}", SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_OK(sd_json_parse("{}", SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL));

        ASSERT_OK(sd_json_parse("[]", /* flags= */ 0, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_ERROR(sd_json_parse("[]", SD_JSON_PARSE_MUST_BE_OBJECT, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL), EINVAL);
        ASSERT_OK(sd_json_parse("[]", SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_OK(sd_json_parse("[]", SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_MUST_BE_ARRAY, /* ret= */ NULL, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
}

TEST(json_dispatch_in_addr) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;

        /* 192.168.1.1 = { 192, 168, 1, 1 } */
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", JSON_BUILD_IN4_ADDR(&(const struct in_addr) { .s_addr = htobe32(0xC0A80101U) })),
                                             SD_JSON_BUILD_PAIR("null_addr", SD_JSON_BUILD_NULL))));

        struct {
                struct in_addr addr;
                struct in_addr null_addr;
        } data = {};

        ASSERT_OK(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr",      _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr, offsetof(typeof(data), addr)      },
                                        { "null_addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr, offsetof(typeof(data), null_addr) },
                                        {},
                                },
                                /* flags= */ 0,
                                &data));

        ASSERT_EQ(be32toh(data.addr.s_addr), 0xC0A80101U);
        ASSERT_EQ(data.null_addr.s_addr, 0U);

        struct in_addr dummy = {};

        /* Too few bytes (3 instead of 4) */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(192), SD_JSON_BUILD_UNSIGNED(168), SD_JSON_BUILD_UNSIGNED(1))))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* Too many bytes (5 instead of 4) */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(192), SD_JSON_BUILD_UNSIGNED(168), SD_JSON_BUILD_UNSIGNED(1), SD_JSON_BUILD_UNSIGNED(1), SD_JSON_BUILD_UNSIGNED(0))))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* Not an array or string */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_BOOLEAN(true)))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* A string */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", JSON_BUILD_CONST_STRING("192.168.1.1")))));
        zero(data);
        ASSERT_OK(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &data));
        ASSERT_EQ(be32toh(data.addr.s_addr), 0xC0A80101U);

        /* Byte value out of range (> 255) */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(256), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(1))))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* Negative element */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_INTEGER(-1), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(1))))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);
}

TEST(json_dispatch_in6_addr) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;

        /* ::1 */
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", JSON_BUILD_IN6_ADDR(&(const struct in6_addr) { .s6_addr = { [15] = 1 } })),
                                             SD_JSON_BUILD_PAIR("null_addr", SD_JSON_BUILD_NULL))));

        struct {
                struct in6_addr addr;
                struct in6_addr null_addr;
        } data = {};

        ASSERT_OK(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr",      _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in6_addr, offsetof(typeof(data), addr)      },
                                        { "null_addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in6_addr, offsetof(typeof(data), null_addr) },
                                        {},
                                },
                                /* flags= */ 0,
                                &data));

        ASSERT_EQ(data.addr.s6_addr[15], 1);
        for (size_t i = 0; i < 15; i++)
                ASSERT_EQ(data.addr.s6_addr[i], 0);
        for (size_t i = 0; i < 16; i++)
                ASSERT_EQ(data.null_addr.s6_addr[i], 0);

        struct in6_addr dummy = {};

        /* Too few bytes (15 instead of 16) */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_ARRAY(
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0),
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0),
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0),
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(1))))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in6_addr, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* Too many bytes (17 instead of 16) */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_ARRAY(
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0),
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0),
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0),
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(1),
                                                                                SD_JSON_BUILD_UNSIGNED(0))))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in6_addr, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* Not an array */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_BOOLEAN(true)))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in6_addr, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* A string */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", JSON_BUILD_CONST_STRING("::1")))));

        zero(data);
        ASSERT_OK(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in6_addr, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &data));

        ASSERT_EQ(data.addr.s6_addr[15], 1);
        for (size_t i = 0; i < 15; i++)
                ASSERT_EQ(data.addr.s6_addr[i], 0);
}

TEST(json_dispatch_in_addr_data) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;

        /* 192.168.1.1 = { 192, 168, 1, 1 } */
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", JSON_BUILD_IN4_ADDR(&(const struct in_addr) { .s_addr = htobe32(0xC0A80101U) })),
                                             SD_JSON_BUILD_PAIR("null_addr", SD_JSON_BUILD_NULL))));

        struct {
                struct in_addr_data addr;
                struct in_addr_data null_addr;
        } data = {};

        ASSERT_OK(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr",      _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, offsetof(typeof(data), addr)      },
                                        { "null_addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, offsetof(typeof(data), null_addr) },
                                        {},
                                },
                                /* flags= */ 0,
                                &data));

        ASSERT_EQ(be32toh(data.addr.address.in.s_addr), 0xC0A80101U);
        ASSERT_EQ(data.null_addr.address.in.s_addr, 0U);
        ASSERT_EQ(data.addr.family, AF_INET);
        ASSERT_EQ(data.null_addr.family, AF_UNSPEC);

        struct in_addr_data dummy = {};

        /* Too few bytes (3 instead of 4) */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(192), SD_JSON_BUILD_UNSIGNED(168), SD_JSON_BUILD_UNSIGNED(1))))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* Too many bytes (5 instead of 4) */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(192), SD_JSON_BUILD_UNSIGNED(168), SD_JSON_BUILD_UNSIGNED(1), SD_JSON_BUILD_UNSIGNED(1), SD_JSON_BUILD_UNSIGNED(0))))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* Not an array or string */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_BOOLEAN(true)))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* A string */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", JSON_BUILD_CONST_STRING("192.168.1.1")))));
        zero(data);
        ASSERT_OK(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &data));
        ASSERT_EQ(be32toh(data.addr.address.in.s_addr), 0xC0A80101U);
        ASSERT_EQ(data.addr.family, AF_INET);

        /* Byte value out of range (> 255) */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(256), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(1))))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* Negative element */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_INTEGER(-1), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(1))))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* ::1 */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", JSON_BUILD_IN6_ADDR(&(const struct in6_addr) { .s6_addr = { [15] = 1 } })),
                                             SD_JSON_BUILD_PAIR("null_addr", SD_JSON_BUILD_NULL))));

        zero(data);
        ASSERT_OK(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr",      _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, offsetof(typeof(data), addr)      },
                                        { "null_addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, offsetof(typeof(data), null_addr) },
                                        {},
                                },
                                /* flags= */ 0,
                                &data));

        ASSERT_EQ(data.addr.address.in6.s6_addr[15], 1);
        for (size_t i = 0; i < 15; i++)
                ASSERT_EQ(data.addr.address.in6.s6_addr[i], 0);
        for (size_t i = 0; i < 16; i++)
                ASSERT_EQ(data.null_addr.address.in6.s6_addr[i], 0);
        ASSERT_EQ(data.addr.family, AF_INET6);
        ASSERT_EQ(data.null_addr.family, AF_UNSPEC);

        /* Too few bytes (15 instead of 16) */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_ARRAY(
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0),
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0),
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0),
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(1))))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* Too many bytes (17 instead of 16) */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_ARRAY(
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0),
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0),
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0),
                                                                                SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(0), SD_JSON_BUILD_UNSIGNED(1),
                                                                                SD_JSON_BUILD_UNSIGNED(0))))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* Not an array */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_BOOLEAN(true)))));
        ASSERT_ERROR(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &dummy), EINVAL);

        /* A string */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_build(&j, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("addr", JSON_BUILD_CONST_STRING("::1")))));

        zero(data);
        ASSERT_OK(sd_json_dispatch(j,
                                (const sd_json_dispatch_field[]) {
                                        { "addr", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data, 0 },
                                        {},
                                },
                                /* flags= */ 0,
                                &data));

        ASSERT_EQ(data.addr.address.in6.s6_addr[15], 1);
        for (size_t i = 0; i < 15; i++)
                ASSERT_EQ(data.addr.address.in6.s6_addr[i], 0);
        ASSERT_EQ(data.addr.family, AF_INET6);
}

TEST(json_seq_extract) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL, *b = NULL, *c = NULL;
        _cleanup_free_ char *s = NULL;
        sd_json_variant *v;

        ASSERT_OK(sd_json_buildo(&a, SD_JSON_BUILD_PAIR_STRING("foo", "bar")));
        ASSERT_OK(sd_json_build(&b, SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(4711), SD_JSON_BUILD_BOOLEAN(true))));
        ASSERT_OK(sd_json_build(&c, SD_JSON_BUILD_STRING("waldo")));

        FOREACH_ARGUMENT(v, a, b, c) {
                _cleanup_free_ char *f = NULL;

                ASSERT_OK(sd_json_variant_format(v, SD_JSON_FORMAT_SEQ, &f));
                ASSERT_NOT_NULL(strextend(&s, f));
        }

        /* Without EOL the last object is incomplete, and must be left in the buffer */
        const char *p = s;
        size_t left = strlen(s);
        FOREACH_ARGUMENT(v, a, b) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *x = NULL;

                ASSERT_OK_POSITIVE(json_seq_extract(&p, &left, /* flags= */ 0, /* eol= */ false, &x));
                ASSERT_TRUE(sd_json_variant_equal(x, v));
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *y = NULL;
        ASSERT_OK_ZERO(json_seq_extract(&p, &left, /* flags= */ 0, /* eol= */ false, &y));
        ASSERT_NULL(y);

        /* With EOL it is parsed as the final object */
        ASSERT_OK_POSITIVE(json_seq_extract(&p, &left, /* flags= */ 0, /* eol= */ true, &y));
        ASSERT_TRUE(sd_json_variant_equal(y, c));
        ASSERT_EQ(left, 0U);

        y = sd_json_variant_unref(y);
        ASSERT_OK_ZERO(json_seq_extract(&p, &left, /* flags= */ 0, /* eol= */ true, &y));
        ASSERT_NULL(y);

        /* Empty and whitespace-only records are skipped */
        p = "\x1e\x1e \n\x1e\"foo\"\n\x1e\x1e\t";
        left = strlen(p);
        ASSERT_OK_POSITIVE(json_seq_extract(&p, &left, /* flags= */ 0, /* eol= */ true, &y));
        ASSERT_STREQ(sd_json_variant_string(y), "foo");
        y = sd_json_variant_unref(y);
        ASSERT_OK_ZERO(json_seq_extract(&p, &left, /* flags= */ 0, /* eol= */ true, &y));
        ASSERT_NULL(y);
        ASSERT_EQ(left, 0U);

        /* Garbage instead of a record separator is refused */
        p = "{}";
        left = strlen(p);
        ASSERT_ERROR(json_seq_extract(&p, &left, /* flags= */ 0, /* eol= */ true, &y), EBADMSG);
}

TEST(json_dispatch_unhex_iovec32) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        uint8_t buf[33];

        for (size_t i = 0; i < sizeof(buf); i++)
                buf[i] = i * 7;

        ASSERT_OK(sd_json_buildo(&j,
                                 SD_JSON_BUILD_PAIR_HEX("digest", buf, 32),
                                 SD_JSON_BUILD_PAIR_NULL("null_digest")));

        typedef struct Digests {
                struct iovec digest;
                struct iovec null_digest;
        } Digests;

        static const sd_json_dispatch_field table[] = {
                { "digest",      SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec32, offsetof(Digests, digest),      0 },
                { "null_digest", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_unhex_iovec32, offsetof(Digests, null_digest), 0 },
                {},
        };

        Digests data = {};

        /* Pre-initialize the null field, to verify it is reset */
        ASSERT_NOT_NULL(iovec_memdup(&IOVEC_MAKE(buf, 5), &data.null_digest));

        ASSERT_OK(sd_json_dispatch(j, table, /* flags= */ 0, &data));
        ASSERT_EQ(data.digest.iov_len, 32U);
        ASSERT_EQ(memcmp(data.digest.iov_base, buf, 32), 0);
        ASSERT_FALSE(iovec_is_set(&data.null_digest));

        /* Dispatching again replaces the old value */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_buildo(&j, SD_JSON_BUILD_PAIR_HEX("digest", buf + 1, 32)));
        ASSERT_OK(sd_json_dispatch(j, table, /* flags= */ 0, &data));
        ASSERT_EQ(data.digest.iov_len, 32U);
        ASSERT_EQ(memcmp(data.digest.iov_base, buf + 1, 32), 0);

        /* Wrong sizes are refused, and leave the old value in place */
        size_t n;
        FOREACH_ARGUMENT(n, 0, 1, 31, 33) {
                j = sd_json_variant_unref(j);
                ASSERT_OK(sd_json_buildo(&j, SD_JSON_BUILD_PAIR_HEX("digest", buf, n)));
                ASSERT_ERROR(sd_json_dispatch(j, table, /* flags= */ 0, &data), EINVAL);
                ASSERT_EQ(data.digest.iov_len, 32U);
                ASSERT_EQ(memcmp(data.digest.iov_base, buf + 1, 32), 0);
        }

        /* Invalid hex strings are refused too */
        j = sd_json_variant_unref(j);
        ASSERT_OK(sd_json_buildo(&j, SD_JSON_BUILD_PAIR_STRING("digest", "xyz")));
        ASSERT_ERROR(sd_json_dispatch(j, table, /* flags= */ 0, &data), EINVAL);
        ASSERT_EQ(data.digest.iov_len, 32U);

        iovec_done(&data.digest);
        iovec_done(&data.null_digest);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
