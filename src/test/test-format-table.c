/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "format-table.h"
#include "json-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tests.h"
#include "time-util.h"

TEST(issue_9549) {
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *formatted = NULL;

        ASSERT_NOT_NULL(table = table_new("name", "type", "ro", "usage", "created", "modified"));
        ASSERT_OK(table_set_align_percent(table, TABLE_HEADER_CELL(3), 100));
        ASSERT_OK(table_add_many(table,
                                 TABLE_STRING, "foooo",
                                 TABLE_STRING, "raw",
                                 TABLE_BOOLEAN, false,
                                 TABLE_SIZE, (uint64_t) (673.7*1024*1024),
                                 TABLE_STRING, "Wed 2018-07-11 00:10:33 JST",
                                 TABLE_STRING, "Wed 2018-07-11 00:16:00 JST"));

        table_set_width(table, 75);
        ASSERT_OK(table_format(table, &formatted));

        printf("%s\n", formatted);
        ASSERT_STREQ(formatted,
                     "NAME  TYPE RO  USAGE CREATED                    MODIFIED\n"
                     "foooo raw  no 673.6M Wed 2018-07-11 00:10:33 J… Wed 2018-07-11 00:16:00 JST\n");
}

TEST(multiline) {
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *formatted = NULL;

        ASSERT_NOT_NULL(table = table_new("foo", "bar"));

        ASSERT_OK(table_set_align_percent(table, TABLE_HEADER_CELL(1), 100));

        ASSERT_OK(table_add_many(table,
                                 TABLE_STRING, "three\ndifferent\nlines",
                                 TABLE_STRING, "two\nlines\n"));

        table_set_cell_height_max(table, 1);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO     BAR\n"
                     "three… two…\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 2);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO          BAR\n"
                     "three        two\n"
                     "different… lines\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 3);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO         BAR\n"
                     "three       two\n"
                     "different lines\n"
                     "lines     \n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, SIZE_MAX);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO         BAR\n"
                     "three       two\n"
                     "different lines\n"
                     "lines     \n");
        formatted = mfree(formatted);

        ASSERT_OK(table_add_many(table,
                                 TABLE_STRING, "short",
                                 TABLE_STRING, "a\npair"));

        ASSERT_OK(table_add_many(table,
                                 TABLE_STRING, "short2\n",
                                 TABLE_STRING, "a\nfour\nline\ncell"));

        table_set_cell_height_max(table, 1);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO     BAR\n"
                     "three… two…\n"
                     "short    a…\n"
                     "short2   a…\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 2);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO          BAR\n"
                     "three        two\n"
                     "different… lines\n"
                     "short          a\n"
                     "            pair\n"
                     "short2         a\n"
                     "           four…\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 3);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO         BAR\n"
                     "three       two\n"
                     "different lines\n"
                     "lines     \n"
                     "short         a\n"
                     "           pair\n"
                     "short2        a\n"
                     "           four\n"
                     "          line…\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, SIZE_MAX);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO         BAR\n"
                     "three       two\n"
                     "different lines\n"
                     "lines     \n"
                     "short         a\n"
                     "           pair\n"
                     "short2        a\n"
                     "           four\n"
                     "           line\n"
                     "           cell\n");
        formatted = mfree(formatted);
}

TEST(strv) {
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *formatted = NULL;

        ASSERT_NOT_NULL(table = table_new("foo", "bar"));

        ASSERT_OK(table_set_align_percent(table, TABLE_HEADER_CELL(1), 100));

        ASSERT_OK(table_add_many(table,
                                 TABLE_STRV, STRV_MAKE("three", "different", "lines"),
                                 TABLE_STRV, STRV_MAKE("two", "lines")));

        table_set_cell_height_max(table, 1);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO     BAR\n"
                     "three… two…\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 2);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO          BAR\n"
                     "three        two\n"
                     "different… lines\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 3);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO         BAR\n"
                     "three       two\n"
                     "different lines\n"
                     "lines     \n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, SIZE_MAX);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO         BAR\n"
                     "three       two\n"
                     "different lines\n"
                     "lines     \n");
        formatted = mfree(formatted);

        ASSERT_OK(table_add_many(table,
                                 TABLE_STRING, "short",
                                 TABLE_STRV, STRV_MAKE("a", "pair")));

        ASSERT_OK(table_add_many(table,
                                 TABLE_STRV, STRV_MAKE("short2"),
                                 TABLE_STRV, STRV_MAKE("a", "four", "line", "cell")));

        table_set_cell_height_max(table, 1);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                        "FOO     BAR\n"
                        "three… two…\n"
                        "short    a…\n"
                        "short2   a…\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 2);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO          BAR\n"
                     "three        two\n"
                     "different… lines\n"
                     "short          a\n"
                     "            pair\n"
                     "short2         a\n"
                     "           four…\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 3);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO         BAR\n"
                     "three       two\n"
                     "different lines\n"
                     "lines     \n"
                     "short         a\n"
                     "           pair\n"
                     "short2        a\n"
                     "           four\n"
                     "          line…\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, SIZE_MAX);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO         BAR\n"
                     "three       two\n"
                     "different lines\n"
                     "lines     \n"
                     "short         a\n"
                     "           pair\n"
                     "short2        a\n"
                     "           four\n"
                     "           line\n"
                     "           cell\n");
        formatted = mfree(formatted);
}

TEST(strv_wrapped) {
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *formatted = NULL;

        ASSERT_NOT_NULL(table = table_new("foo", "bar"));

        ASSERT_OK(table_set_align_percent(table, TABLE_HEADER_CELL(1), 100));

        ASSERT_OK(table_add_many(table,
                                 TABLE_STRV_WRAPPED, STRV_MAKE("three", "different", "lines"),
                                 TABLE_STRV_WRAPPED, STRV_MAKE("two", "lines")));

        table_set_cell_height_max(table, 1);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO                         BAR\n"
                     "three different lines two lines\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 2);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO                         BAR\n"
                     "three different lines two lines\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 3);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO                         BAR\n"
                     "three different lines two lines\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, SIZE_MAX);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO                         BAR\n"
                     "three different lines two lines\n");
        formatted = mfree(formatted);

        ASSERT_OK(table_add_many(table,
                                 TABLE_STRING, "short",
                                 TABLE_STRV_WRAPPED, STRV_MAKE("a", "pair")));

        ASSERT_OK(table_add_many(table,
                                 TABLE_STRV_WRAPPED, STRV_MAKE("short2"),
                                 TABLE_STRV_WRAPPED, STRV_MAKE("a", "eight", "line", "ćęłł",
                                                               "___5___", "___6___", "___7___", "___8___")));

        table_set_cell_height_max(table, 1);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO                             BAR\n"
                     "three different…          two lines\n"
                     "short                        a pair\n"
                     "short2           a eight line ćęłł…\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 2);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO                           BAR\n"
                     "three different         two lines\n"
                     "lines           \n"
                     "short                      a pair\n"
                     "short2          a eight line ćęłł\n"
                     "                 ___5___ ___6___…\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 3);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO                           BAR\n"
                     "three different         two lines\n"
                     "lines           \n"
                     "short                      a pair\n"
                     "short2          a eight line ćęłł\n"
                     "                  ___5___ ___6___\n"
                     "                  ___7___ ___8___\n");
        formatted = mfree(formatted);

        table_set_cell_height_max(table, SIZE_MAX);
        ASSERT_OK(table_format(table, &formatted));
        fputs(formatted, stdout);
        ASSERT_STREQ(formatted,
                     "FOO                           BAR\n"
                     "three different         two lines\n"
                     "lines           \n"
                     "short                      a pair\n"
                     "short2          a eight line ćęłł\n"
                     "                  ___5___ ___6___\n"
                     "                  ___7___ ___8___\n");
        formatted = mfree(formatted);
}

TEST(json) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;

        ASSERT_NOT_NULL(t = table_new_raw(4));

        ASSERT_OK(table_add_many(t,
                                 TABLE_HEADER, "foo bar",
                                 TABLE_HEADER, "quux",
                                 TABLE_HEADER, "piep miau",
                                 TABLE_HEADER, "asdf",
                                 TABLE_SET_JSON_FIELD_NAME, "asdf-custom"));
        ASSERT_OK(table_set_json_field_name(t, 2, "ZZZ"));
        ASSERT_OK(table_set_json_field_name(t, 2, NULL));
        ASSERT_OK(table_set_json_field_name(t, 2, "zzz"));

        ASSERT_OK(table_add_many(t,
                                 TABLE_STRING, "v1",
                                 TABLE_UINT64, UINT64_C(4711),
                                 TABLE_BOOLEAN, true,
                                 TABLE_EMPTY));

        ASSERT_OK(table_add_many(t,
                                 TABLE_STRV, STRV_MAKE("a", "b", "c"),
                                 TABLE_EMPTY,
                                 TABLE_MODE, 0755,
                                 TABLE_EMPTY));

        ASSERT_OK(table_to_json(t, &v));

        ASSERT_OK(sd_json_build(&w,
                             SD_JSON_BUILD_ARRAY(
                                             SD_JSON_BUILD_OBJECT(
                                                             SD_JSON_BUILD_PAIR("foo_bar", JSON_BUILD_CONST_STRING("v1")),
                                                             SD_JSON_BUILD_PAIR("quux", SD_JSON_BUILD_UNSIGNED(4711)),
                                                             SD_JSON_BUILD_PAIR("zzz", SD_JSON_BUILD_BOOLEAN(true)),
                                                             SD_JSON_BUILD_PAIR("asdf-custom", SD_JSON_BUILD_NULL)),
                                             SD_JSON_BUILD_OBJECT(
                                                             SD_JSON_BUILD_PAIR("foo_bar", SD_JSON_BUILD_STRV(STRV_MAKE("a", "b", "c"))),
                                                             SD_JSON_BUILD_PAIR("quux", SD_JSON_BUILD_NULL),
                                                             SD_JSON_BUILD_PAIR("zzz", SD_JSON_BUILD_UNSIGNED(0755)),
                                                             SD_JSON_BUILD_PAIR("asdf-custom", SD_JSON_BUILD_NULL)))));

        ASSERT_TRUE(sd_json_variant_equal(v, w));
}

TEST(json_mangling) {
        static const struct {
                const char *arg;
                const char *exp;
        } cases[] = {
                /* Not Mangled */
                { "foo", "foo" },
                { "foo_bar", "foo_bar" },
                { "fooBar", "fooBar" },
                { "fooBar123", "fooBar123" },
                { "foo_bar123", "foo_bar123" },
                { ALPHANUMERICAL, ALPHANUMERICAL },
                { "_123", "_123" },

                /* Mangled */
                { "Foo Bar", "foo_bar" },
                { "Foo-Bar", "foo_bar" },
                { "Foo@Bar", "foo_bar" },
                { "Foo (Bar)", "foo__bar_"},
                { "MixedCase ALLCAPS", "mixedCase_ALLCAPS" },
                { "_X", "_x" },
                { "_Foo", "_foo" },
        };

        FOREACH_ELEMENT(i, cases) {
                _cleanup_free_ char *ret = NULL;
                ASSERT_NOT_NULL(ret = table_mangle_to_json_field_name(i->arg));
                printf("\"%s\" -> \"%s\"\n", i->arg, ret);
                ASSERT_STREQ(ret, i->exp);
        }
}

TEST(table) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *formatted = NULL;

        ASSERT_NOT_NULL(t = table_new("one", "two", "three", "four"));

        ASSERT_OK(table_set_align_percent(t, TABLE_HEADER_CELL(3), 100));

        ASSERT_OK(table_add_many(t,
                                 TABLE_STRING, "xxx",
                                 TABLE_STRING, "yyy",
                                 TABLE_BOOLEAN, true,
                                 TABLE_INT, -1));

        ASSERT_OK(table_add_many(t,
                                 TABLE_STRING, "a long field",
                                 TABLE_STRING, "yyy",
                                 TABLE_SET_UPPERCASE, 1,
                                 TABLE_BOOLEAN, false,
                                 TABLE_INT, -999999));

        ASSERT_OK(table_format(t, &formatted));
        printf("%s\n", formatted);

        ASSERT_STREQ(formatted,
                     "ONE          TWO THREE    FOUR\n"
                     "xxx          yyy yes        -1\n"
                     "a long field YYY no    -999999\n");

        formatted = mfree(formatted);

        table_set_width(t, 40);

        ASSERT_OK(table_format(t, &formatted));
        printf("%s\n", formatted);

        ASSERT_STREQ(formatted,
                     "ONE            TWO   THREE          FOUR\n"
                     "xxx            yyy   yes              -1\n"
                     "a long field   YYY   no          -999999\n");

        formatted = mfree(formatted);

        table_set_width(t, 15);
        ASSERT_OK(table_format(t, &formatted));
        printf("%s\n", formatted);

        ASSERT_STREQ(formatted,
                     "ONE TWO TH… FO…\n"
                     "xxx yyy yes  -1\n"
                     "a … YYY no  -9…\n");

        formatted = mfree(formatted);

        table_set_width(t, 5);
        ASSERT_OK(table_format(t, &formatted));
        printf("%s\n", formatted);

        ASSERT_STREQ(formatted,
                     "… … … …\n"
                     "… … … …\n"
                     "… … … …\n");

        formatted = mfree(formatted);

        table_set_width(t, 3);
        ASSERT_OK(table_format(t, &formatted));
        printf("%s\n", formatted);

        ASSERT_STREQ(formatted,
                     "… … … …\n"
                     "… … … …\n"
                     "… … … …\n");

        formatted = mfree(formatted);

        table_set_width(t, SIZE_MAX);
        ASSERT_OK(table_set_sort(t, (size_t) 0, (size_t) 2, SIZE_MAX));

        ASSERT_OK(table_format(t, &formatted));
        printf("%s\n", formatted);

        ASSERT_STREQ(formatted,
                     "ONE          TWO THREE    FOUR\n"
                     "a long field YYY no    -999999\n"
                     "xxx          yyy yes        -1\n");

        formatted = mfree(formatted);

        table_set_header(t, false);

        ASSERT_OK(table_add_many(t,
                                 TABLE_STRING, "fäää",
                                 TABLE_STRING, "uuu",
                                 TABLE_BOOLEAN, true,
                                 TABLE_INT, 42));

        ASSERT_OK(table_add_many(t,
                                 TABLE_STRING, "fäää",
                                 TABLE_STRING, "zzz",
                                 TABLE_BOOLEAN, false,
                                 TABLE_INT, 0));

        ASSERT_OK(table_add_many(t,
                                 TABLE_EMPTY,
                                 TABLE_SIZE, (uint64_t) 4711,
                                 TABLE_TIMESPAN, (usec_t) 5*USEC_PER_MINUTE,
                                 TABLE_INT64, (uint64_t) -123456789));

        ASSERT_OK(table_format(t, &formatted));
        printf("%s\n", formatted);

        ASSERT_STREQ(formatted,
                     "a long field YYY  no      -999999\n"
                     "fäää         zzz  no            0\n"
                     "fäää         uuu  yes          42\n"
                     "xxx          yyy  yes          -1\n"
                     "             4.6K 5min -123456789\n");

        formatted = mfree(formatted);

        ASSERT_OK(table_set_display(t, (size_t) 2, (size_t) 0, (size_t) 2, (size_t) 0, (size_t) 0, SIZE_MAX));

        ASSERT_OK(table_format(t, &formatted));
        printf("%s\n", formatted);

        if (isatty_safe(STDOUT_FILENO))
                ASSERT_STREQ(formatted,
                             "no   a long f… no   a long f… a long fi…\n"
                             "no   fäää      no   fäää      fäää\n"
                             "yes  fäää      yes  fäää      fäää\n"
                             "yes  xxx       yes  xxx       xxx\n"
                             "5min           5min           \n");
        else
                ASSERT_STREQ(formatted,
                             "no   a long field no   a long field a long field\n"
                             "no   fäää         no   fäää         fäää\n"
                             "yes  fäää         yes  fäää         fäää\n"
                             "yes  xxx          yes  xxx          xxx\n"
                             "5min              5min              \n");
}

TEST(signed_integers) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *formatted = NULL;

        ASSERT_NOT_NULL(t = table_new("int", "int8", "int16", "int32", "int64"));
        table_set_width(t, 0);

        ASSERT_OK(table_add_many(t,
                                 TABLE_INT, -1,
                                 TABLE_INT8, INT8_C(-1),
                                 TABLE_INT16, INT16_C(-1),
                                 TABLE_INT32, INT32_C(-1),
                                 TABLE_INT64, INT64_C(-1)));
        ASSERT_OK(table_add_many(t,
                                 TABLE_INT, INT_MAX,
                                 TABLE_INT8, INT8_MAX,
                                 TABLE_INT16, INT16_MAX,
                                 TABLE_INT32, INT32_MAX,
                                 TABLE_INT64, INT64_MAX));
        ASSERT_OK(table_add_many(t,
                                 TABLE_INT, INT_MIN,
                                 TABLE_INT8, INT8_MIN,
                                 TABLE_INT16, INT16_MIN,
                                 TABLE_INT32, INT32_MIN,
                                 TABLE_INT64, INT64_MIN));

        ASSERT_OK(table_format(t, &formatted));
        printf("%s\n", formatted);

        ASSERT_STREQ(formatted,
                     "INT         INT8 INT16  INT32       INT64\n"
                     "-1          -1   -1     -1          -1\n"
                     "2147483647  127  32767  2147483647  9223372036854775807\n"
                     "-2147483648 -128 -32768 -2147483648 -9223372036854775808\n");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL, *b = NULL;
        ASSERT_OK(table_to_json(t, &a));

        table_print_json(t, /*f=*/ NULL, SD_JSON_FORMAT_NEWLINE);

        ASSERT_OK(sd_json_build(&b,
                                SD_JSON_BUILD_ARRAY(
                                  SD_JSON_BUILD_OBJECT(
                                    SD_JSON_BUILD_PAIR("int", SD_JSON_BUILD_INTEGER(-1)),
                                    SD_JSON_BUILD_PAIR("int8", SD_JSON_BUILD_INTEGER(-1)),
                                    SD_JSON_BUILD_PAIR("int16", SD_JSON_BUILD_INTEGER(-1)),
                                    SD_JSON_BUILD_PAIR("int32", SD_JSON_BUILD_INTEGER(-1)),
                                    SD_JSON_BUILD_PAIR("int64", SD_JSON_BUILD_INTEGER(-1))),
                                  SD_JSON_BUILD_OBJECT(
                                    SD_JSON_BUILD_PAIR("int", SD_JSON_BUILD_INTEGER(INT_MAX)),
                                    SD_JSON_BUILD_PAIR("int8", SD_JSON_BUILD_INTEGER(INT8_MAX)),
                                    SD_JSON_BUILD_PAIR("int16", SD_JSON_BUILD_INTEGER(INT16_MAX)),
                                    SD_JSON_BUILD_PAIR("int32", SD_JSON_BUILD_INTEGER(INT32_MAX)),
                                    SD_JSON_BUILD_PAIR("int64", SD_JSON_BUILD_INTEGER(INT64_MAX))),
                                  SD_JSON_BUILD_OBJECT(
                                    SD_JSON_BUILD_PAIR("int", SD_JSON_BUILD_INTEGER(INT_MIN)),
                                    SD_JSON_BUILD_PAIR("int8", SD_JSON_BUILD_INTEGER(INT8_MIN)),
                                    SD_JSON_BUILD_PAIR("int16", SD_JSON_BUILD_INTEGER(INT16_MIN)),
                                    SD_JSON_BUILD_PAIR("int32", SD_JSON_BUILD_INTEGER(INT32_MIN)),
                                    SD_JSON_BUILD_PAIR("int64", SD_JSON_BUILD_INTEGER(INT64_MIN))))));
        sd_json_variant_dump(b, SD_JSON_FORMAT_NEWLINE, stdout, NULL);

        ASSERT_TRUE(sd_json_variant_equal(a, b));
}

TEST(unsigned_integers) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *formatted = NULL;

        ASSERT_NOT_NULL(t = table_new("uint", "uint8", "uint16", "uint32", "uhex32", "uint64", "uhex64"));
        table_set_width(t, 0);

        ASSERT_OK(table_add_many(t,
                                 TABLE_UINT, 0,
                                 TABLE_UINT8, UINT8_C(0),
                                 TABLE_UINT16, UINT16_C(0),
                                 TABLE_UINT32, UINT32_C(0),
                                 TABLE_UINT32_HEX, UINT32_C(0),
                                 TABLE_UINT64, UINT64_C(0),
                                 TABLE_UINT64_HEX, UINT64_C(0)));
        ASSERT_OK(table_add_many(t,
                                 TABLE_UINT, UINT_MAX,
                                 TABLE_UINT8, UINT8_MAX,
                                 TABLE_UINT16, UINT16_MAX,
                                 TABLE_UINT32, UINT32_MAX,
                                 TABLE_UINT32_HEX, UINT32_MAX,
                                 TABLE_UINT64, UINT64_MAX,
                                 TABLE_UINT64_HEX, UINT64_MAX));

        ASSERT_OK(table_format(t, &formatted));
        printf("%s\n", formatted);

        ASSERT_STREQ(formatted,
                     "UINT       UINT8 UINT16 UINT32     UHEX32   UINT64               UHEX64\n"
                     "0          0     0      0          0        0                    0\n"
                     "4294967295 255   65535  4294967295 ffffffff 18446744073709551615 ffffffffffffffff\n");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL, *b = NULL;
        ASSERT_OK(table_to_json(t, &a));

        table_print_json(t, /*f=*/ NULL, SD_JSON_FORMAT_NEWLINE);

        ASSERT_OK(sd_json_build(&b,
                                SD_JSON_BUILD_ARRAY(
                                  SD_JSON_BUILD_OBJECT(
                                    SD_JSON_BUILD_PAIR("uint", SD_JSON_BUILD_UNSIGNED(0)),
                                    SD_JSON_BUILD_PAIR("uint8", SD_JSON_BUILD_UNSIGNED(0)),
                                    SD_JSON_BUILD_PAIR("uint16", SD_JSON_BUILD_UNSIGNED(0)),
                                    SD_JSON_BUILD_PAIR("uint32", SD_JSON_BUILD_UNSIGNED(0)),
                                    SD_JSON_BUILD_PAIR("uhex32", SD_JSON_BUILD_UNSIGNED(0)),
                                    SD_JSON_BUILD_PAIR("uint64", SD_JSON_BUILD_UNSIGNED(0)),
                                    SD_JSON_BUILD_PAIR("uhex64", SD_JSON_BUILD_UNSIGNED(0))),
                                  SD_JSON_BUILD_OBJECT(
                                    SD_JSON_BUILD_PAIR("uint", SD_JSON_BUILD_UNSIGNED(UINT_MAX)),
                                    SD_JSON_BUILD_PAIR("uint8", SD_JSON_BUILD_UNSIGNED(UINT8_MAX)),
                                    SD_JSON_BUILD_PAIR("uint16", SD_JSON_BUILD_UNSIGNED(UINT16_MAX)),
                                    SD_JSON_BUILD_PAIR("uint32", SD_JSON_BUILD_UNSIGNED(UINT32_MAX)),
                                    SD_JSON_BUILD_PAIR("uhex32", SD_JSON_BUILD_UNSIGNED(UINT32_MAX)),
                                    SD_JSON_BUILD_PAIR("uint64", SD_JSON_BUILD_UNSIGNED(UINT64_MAX)),
                                    SD_JSON_BUILD_PAIR("uhex64", SD_JSON_BUILD_UNSIGNED(UINT64_MAX))))));
        sd_json_variant_dump(b, SD_JSON_FORMAT_NEWLINE, stdout, NULL);

        ASSERT_TRUE(sd_json_variant_equal(a, b));
}

TEST(vertical) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *formatted = NULL;

        ASSERT_NOT_NULL(t = table_new_vertical());

        ASSERT_OK(table_add_many(t,
                                 TABLE_FIELD, "pfft aa", TABLE_STRING, "foo",
                                 TABLE_FIELD, "uuu o", TABLE_SIZE, UINT64_C(1024),
                                 TABLE_FIELD, "quux", TABLE_STRING, "asdf", TABLE_SET_JSON_FIELD_NAME, "custom-quux",
                                 TABLE_FIELD, "lllllllllllo", TABLE_STRING, "jjjjjjjjjjjjjjjjj"));

        ASSERT_OK(table_set_json_field_name(t, 1, "DIMPFELMOSER"));
        ASSERT_OK(table_set_json_field_name(t, 1, NULL));
        ASSERT_OK(table_set_json_field_name(t, 1, "dimpfelmoser"));

        ASSERT_OK(table_format(t, &formatted));

        ASSERT_STREQ(formatted,
                     "     pfft aa: foo\n"
                     "       uuu o: 1K\n"
                     "        quux: asdf\n"
                     "lllllllllllo: jjjjjjjjjjjjjjjjj\n");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL, *b = NULL;
        ASSERT_OK(table_to_json(t, &a));

        ASSERT_OK(sd_json_build(&b, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("pfft_aa", SD_JSON_BUILD_STRING("foo")),
                                             SD_JSON_BUILD_PAIR("dimpfelmoser", SD_JSON_BUILD_UNSIGNED(1024)),
                                             SD_JSON_BUILD_PAIR("custom-quux", SD_JSON_BUILD_STRING("asdf")),
                                             SD_JSON_BUILD_PAIR("lllllllllllo", SD_JSON_BUILD_STRING("jjjjjjjjjjjjjjjjj")))));

        ASSERT_TRUE(sd_json_variant_equal(a, b));
}

TEST(path_basename) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *formatted = NULL;

        ASSERT_NOT_NULL(t = table_new("x"));

        table_set_header(t, false);

        ASSERT_OK(table_add_many(t,
                                 TABLE_PATH_BASENAME, "/foo/bar",
                                 TABLE_PATH_BASENAME, "/quux/bar",
                                 TABLE_PATH_BASENAME, "/foo/baz"));

        ASSERT_OK(table_format(t, &formatted));

        ASSERT_STREQ(formatted, "bar\nbar\nbaz\n");
}

TEST(dup_cell) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *formatted = NULL;

        ASSERT_NOT_NULL(t = table_new("foo", "bar", "x", "baz", ".", "%", "!", "~", "+"));
        table_set_width(t, 75);

        ASSERT_OK(table_add_many(t,
                                 TABLE_STRING, "hello",
                                 TABLE_UINT8, UINT8_C(42),
                                 TABLE_UINT16, UINT16_C(666),
                                 TABLE_UINT32, UINT32_C(253),
                                 TABLE_PERCENT, 0,
                                 TABLE_PATH_BASENAME, "/foo/bar",
                                 TABLE_STRING, "aaa",
                                 TABLE_STRING, "bbb",
                                 TABLE_STRING, "ccc"));

        /* Add the second row by duping cells */
        for (size_t i = 0; i < table_get_columns(t); i++)
                ASSERT_OK(table_dup_cell(t, table_get_cell(t, 1, i)));

        /* Another row, but dupe the last three strings from the same cell */
        ASSERT_OK(table_add_many(t,
                                 TABLE_STRING, "aaa",
                                 TABLE_UINT8, UINT8_C(0),
                                 TABLE_UINT16, UINT16_C(65535),
                                 TABLE_UINT32, UINT32_C(4294967295),
                                 TABLE_PERCENT, 100,
                                 TABLE_PATH_BASENAME, "../"));

        for (size_t i = 6; i < table_get_columns(t); i++)
                ASSERT_OK(table_dup_cell(t, table_get_cell(t, 2, 0)));

        ASSERT_OK(table_format(t, &formatted));
        printf("%s\n", formatted);
        ASSERT_STREQ(formatted,
                     "FOO     BAR   X       BAZ          .      %      !        ~        +\n"
                     "hello   42    666     253          0%     bar    aaa      bbb      ccc\n"
                     "hello   42    666     253          0%     bar    aaa      bbb      ccc\n"
                     "aaa     0     65535   4294967295   100%   ../    hello    hello    hello\n");
}

TEST(table_bps) {
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *formatted = NULL;

        ASSERT_NOT_NULL(table = table_new("uint64", "size", "bps"));
        uint64_t v;
        FOREACH_ARGUMENT(v,
                         2500,
                         10000000,
                         20000000,
                         25000000,
                         1000000000,
                         2000000000,
                         2500000000)
                ASSERT_OK(table_add_many(table,
                                         TABLE_UINT64, v,
                                         TABLE_SIZE, v,
                                         TABLE_BPS, v));

        table_set_width(table, 50);
        ASSERT_OK(table_format(table, &formatted));

        printf("%s", formatted);
        ASSERT_STREQ(formatted,
                     "UINT64             SIZE           BPS\n"
                     "2500               2.4K           2.5Kbps\n"
                     "10000000           9.5M           10Mbps\n"
                     "20000000           19M            20Mbps\n"
                     "25000000           23.8M          25Mbps\n"
                     "1000000000         953.6M         1Gbps\n"
                     "2000000000         1.8G           2Gbps\n"
                     "2500000000         2.3G           2.5Gbps\n");
}

static int intro(void) {
        ASSERT_OK(setenv("SYSTEMD_COLORS", "0", 1));
        ASSERT_OK(setenv("COLUMNS", "40", 1));
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
