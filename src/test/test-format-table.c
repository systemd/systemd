/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "format-table.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

TEST(issue_9549) {
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *formatted = NULL;

        assert_se(table = table_new("name", "type", "ro", "usage", "created", "modified"));
        assert_se(table_set_align_percent(table, TABLE_HEADER_CELL(3), 100) >= 0);
        assert_se(table_add_many(table,
                                 TABLE_STRING, "foooo",
                                 TABLE_STRING, "raw",
                                 TABLE_BOOLEAN, false,
                                 TABLE_SIZE, (uint64_t) (673.7*1024*1024),
                                 TABLE_STRING, "Wed 2018-07-11 00:10:33 JST",
                                 TABLE_STRING, "Wed 2018-07-11 00:16:00 JST") >= 0);

        table_set_width(table, 75);
        assert_se(table_format(table, &formatted) >= 0);

        printf("%s\n", formatted);
        assert_se(streq(formatted,
                        "NAME  TYPE RO  USAGE CREATED                    MODIFIED\n"
                        "foooo raw  no 673.6M Wed 2018-07-11 00:10:33 J… Wed 2018-07-11 00:16:00 JST\n"
                        ));
}

TEST(multiline) {
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *formatted = NULL;

        assert_se(table = table_new("foo", "bar"));

        assert_se(table_set_align_percent(table, TABLE_HEADER_CELL(1), 100) >= 0);

        assert_se(table_add_many(table,
                                 TABLE_STRING, "three\ndifferent\nlines",
                                 TABLE_STRING, "two\nlines\n") >= 0);

        table_set_cell_height_max(table, 1);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO     BAR\n"
                        "three… two…\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 2);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO          BAR\n"
                        "three        two\n"
                        "different… lines\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 3);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO         BAR\n"
                        "three       two\n"
                        "different lines\n"
                        "lines     \n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, SIZE_MAX);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO         BAR\n"
                        "three       two\n"
                        "different lines\n"
                        "lines     \n"));
        formatted = mfree(formatted);

        assert_se(table_add_many(table,
                                 TABLE_STRING, "short",
                                 TABLE_STRING, "a\npair") >= 0);

        assert_se(table_add_many(table,
                                 TABLE_STRING, "short2\n",
                                 TABLE_STRING, "a\nfour\nline\ncell") >= 0);

        table_set_cell_height_max(table, 1);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO     BAR\n"
                        "three… two…\n"
                        "short    a…\n"
                        "short2   a…\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 2);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO          BAR\n"
                        "three        two\n"
                        "different… lines\n"
                        "short          a\n"
                        "            pair\n"
                        "short2         a\n"
                        "           four…\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 3);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO         BAR\n"
                        "three       two\n"
                        "different lines\n"
                        "lines     \n"
                        "short         a\n"
                        "           pair\n"
                        "short2        a\n"
                        "           four\n"
                        "          line…\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, SIZE_MAX);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO         BAR\n"
                        "three       two\n"
                        "different lines\n"
                        "lines     \n"
                        "short         a\n"
                        "           pair\n"
                        "short2        a\n"
                        "           four\n"
                        "           line\n"
                        "           cell\n"));
        formatted = mfree(formatted);
}

TEST(strv) {
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *formatted = NULL;

        assert_se(table = table_new("foo", "bar"));

        assert_se(table_set_align_percent(table, TABLE_HEADER_CELL(1), 100) >= 0);

        assert_se(table_add_many(table,
                                 TABLE_STRV, STRV_MAKE("three", "different", "lines"),
                                 TABLE_STRV, STRV_MAKE("two", "lines")) >= 0);

        table_set_cell_height_max(table, 1);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO     BAR\n"
                        "three… two…\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 2);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO          BAR\n"
                        "three        two\n"
                        "different… lines\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 3);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO         BAR\n"
                        "three       two\n"
                        "different lines\n"
                        "lines     \n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, SIZE_MAX);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO         BAR\n"
                        "three       two\n"
                        "different lines\n"
                        "lines     \n"));
        formatted = mfree(formatted);

        assert_se(table_add_many(table,
                                 TABLE_STRING, "short",
                                 TABLE_STRV, STRV_MAKE("a", "pair")) >= 0);

        assert_se(table_add_many(table,
                                 TABLE_STRV, STRV_MAKE("short2"),
                                 TABLE_STRV, STRV_MAKE("a", "four", "line", "cell")) >= 0);

        table_set_cell_height_max(table, 1);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO     BAR\n"
                        "three… two…\n"
                        "short    a…\n"
                        "short2   a…\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 2);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO          BAR\n"
                        "three        two\n"
                        "different… lines\n"
                        "short          a\n"
                        "            pair\n"
                        "short2         a\n"
                        "           four…\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 3);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO         BAR\n"
                        "three       two\n"
                        "different lines\n"
                        "lines     \n"
                        "short         a\n"
                        "           pair\n"
                        "short2        a\n"
                        "           four\n"
                        "          line…\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, SIZE_MAX);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO         BAR\n"
                        "three       two\n"
                        "different lines\n"
                        "lines     \n"
                        "short         a\n"
                        "           pair\n"
                        "short2        a\n"
                        "           four\n"
                        "           line\n"
                        "           cell\n"));
        formatted = mfree(formatted);
}

TEST(strv_wrapped) {
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *formatted = NULL;

        assert_se(table = table_new("foo", "bar"));

        assert_se(table_set_align_percent(table, TABLE_HEADER_CELL(1), 100) >= 0);

        assert_se(table_add_many(table,
                                 TABLE_STRV_WRAPPED, STRV_MAKE("three", "different", "lines"),
                                 TABLE_STRV_WRAPPED, STRV_MAKE("two", "lines")) >= 0);

        table_set_cell_height_max(table, 1);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO                         BAR\n"
                        "three different lines two lines\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 2);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO                         BAR\n"
                        "three different lines two lines\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 3);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO                         BAR\n"
                        "three different lines two lines\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, SIZE_MAX);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO                         BAR\n"
                        "three different lines two lines\n"));
        formatted = mfree(formatted);

        assert_se(table_add_many(table,
                                 TABLE_STRING, "short",
                                 TABLE_STRV_WRAPPED, STRV_MAKE("a", "pair")) >= 0);

        assert_se(table_add_many(table,
                                 TABLE_STRV_WRAPPED, STRV_MAKE("short2"),
                                 TABLE_STRV_WRAPPED, STRV_MAKE("a", "eight", "line", "ćęłł",
                                                               "___5___", "___6___", "___7___", "___8___")) >= 0);

        table_set_cell_height_max(table, 1);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO                             BAR\n"
                        "three different…          two lines\n"
                        "short                        a pair\n"
                        "short2           a eight line ćęłł…\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 2);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO                           BAR\n"
                        "three different         two lines\n"
                        "lines           \n"
                        "short                      a pair\n"
                        "short2          a eight line ćęłł\n"
                        "                 ___5___ ___6___…\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, 3);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO                           BAR\n"
                        "three different         two lines\n"
                        "lines           \n"
                        "short                      a pair\n"
                        "short2          a eight line ćęłł\n"
                        "                  ___5___ ___6___\n"
                        "                  ___7___ ___8___\n"));
        formatted = mfree(formatted);

        table_set_cell_height_max(table, SIZE_MAX);
        assert_se(table_format(table, &formatted) >= 0);
        fputs(formatted, stdout);
        assert_se(streq(formatted,
                        "FOO                           BAR\n"
                        "three different         two lines\n"
                        "lines           \n"
                        "short                      a pair\n"
                        "short2          a eight line ćęłł\n"
                        "                  ___5___ ___6___\n"
                        "                  ___7___ ___8___\n"));
        formatted = mfree(formatted);
}

TEST(json) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *w = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;

        assert_se(t = table_new("foo bar", "quux", "piep miau"));
        assert_se(table_set_json_field_name(t, 2, "zzz") >= 0);

        assert_se(table_add_many(t,
                                 TABLE_STRING, "v1",
                                 TABLE_UINT64, UINT64_C(4711),
                                 TABLE_BOOLEAN, true) >= 0);

        assert_se(table_add_many(t,
                                 TABLE_STRV, STRV_MAKE("a", "b", "c"),
                                 TABLE_EMPTY,
                                 TABLE_MODE, 0755) >= 0);

        assert_se(table_to_json(t, &v) >= 0);

        assert_se(json_build(&w,
                             JSON_BUILD_ARRAY(
                                             JSON_BUILD_OBJECT(
                                                             JSON_BUILD_PAIR("foo_bar", JSON_BUILD_CONST_STRING("v1")),
                                                             JSON_BUILD_PAIR("quux", JSON_BUILD_UNSIGNED(4711)),
                                                             JSON_BUILD_PAIR("zzz", JSON_BUILD_BOOLEAN(true))),
                                             JSON_BUILD_OBJECT(
                                                             JSON_BUILD_PAIR("foo_bar", JSON_BUILD_STRV(STRV_MAKE("a", "b", "c"))),
                                                             JSON_BUILD_PAIR("quux", JSON_BUILD_NULL),
                                                             JSON_BUILD_PAIR("zzz", JSON_BUILD_UNSIGNED(0755))))) >= 0);

        assert_se(json_variant_equal(v, w));
}

TEST(table) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *formatted = NULL;

        assert_se(t = table_new("one", "two", "three", "four"));

        assert_se(table_set_align_percent(t, TABLE_HEADER_CELL(3), 100) >= 0);

        assert_se(table_add_many(t,
                                 TABLE_STRING, "xxx",
                                 TABLE_STRING, "yyy",
                                 TABLE_BOOLEAN, true,
                                 TABLE_INT, -1) >= 0);

        assert_se(table_add_many(t,
                                 TABLE_STRING, "a long field",
                                 TABLE_STRING, "yyy",
                                 TABLE_SET_UPPERCASE, 1,
                                 TABLE_BOOLEAN, false,
                                 TABLE_INT, -999999) >= 0);

        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "ONE          TWO THREE    FOUR\n"
                        "xxx          yyy yes        -1\n"
                        "a long field YYY no    -999999\n"));

        formatted = mfree(formatted);

        table_set_width(t, 40);

        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "ONE            TWO   THREE          FOUR\n"
                        "xxx            yyy   yes              -1\n"
                        "a long field   YYY   no          -999999\n"));

        formatted = mfree(formatted);

        table_set_width(t, 15);
        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "ONE TWO TH… FO…\n"
                        "xxx yyy yes  -1\n"
                        "a … YYY no  -9…\n"));

        formatted = mfree(formatted);

        table_set_width(t, 5);
        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "… … … …\n"
                        "… … … …\n"
                        "… … … …\n"));

        formatted = mfree(formatted);

        table_set_width(t, 3);
        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "… … … …\n"
                        "… … … …\n"
                        "… … … …\n"));

        formatted = mfree(formatted);

        table_set_width(t, SIZE_MAX);
        assert_se(table_set_sort(t, (size_t) 0, (size_t) 2, SIZE_MAX) >= 0);

        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "ONE          TWO THREE    FOUR\n"
                        "a long field YYY no    -999999\n"
                        "xxx          yyy yes        -1\n"));

        formatted = mfree(formatted);

        table_set_header(t, false);

        assert_se(table_add_many(t,
                                 TABLE_STRING, "fäää",
                                 TABLE_STRING, "uuu",
                                 TABLE_BOOLEAN, true,
                                 TABLE_INT, 42) >= 0);

        assert_se(table_add_many(t,
                                 TABLE_STRING, "fäää",
                                 TABLE_STRING, "zzz",
                                 TABLE_BOOLEAN, false,
                                 TABLE_INT, 0) >= 0);

        assert_se(table_add_many(t,
                                 TABLE_EMPTY,
                                 TABLE_SIZE, (uint64_t) 4711,
                                 TABLE_TIMESPAN, (usec_t) 5*USEC_PER_MINUTE,
                                 TABLE_INT64, (uint64_t) -123456789) >= 0);

        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "a long field YYY  no      -999999\n"
                        "fäää         zzz  no            0\n"
                        "fäää         uuu  yes          42\n"
                        "xxx          yyy  yes          -1\n"
                        "             4.6K 5min -123456789\n"));

        formatted = mfree(formatted);

        assert_se(table_set_display(t, (size_t) 2, (size_t) 0, (size_t) 2, (size_t) 0, (size_t) 0, SIZE_MAX) >= 0);

        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        if (isatty(STDOUT_FILENO))
                assert_se(streq(formatted,
                                "no   a long f… no   a long f… a long fi…\n"
                                "no   fäää      no   fäää      fäää\n"
                                "yes  fäää      yes  fäää      fäää\n"
                                "yes  xxx       yes  xxx       xxx\n"
                                "5min           5min           \n"));
        else
                assert_se(streq(formatted,
                                "no   a long field no   a long field a long field\n"
                                "no   fäää         no   fäää         fäää\n"
                                "yes  fäää         yes  fäää         fäää\n"
                                "yes  xxx          yes  xxx          xxx\n"
                                "5min              5min              \n"));
}

static int intro(void) {
        assert_se(setenv("SYSTEMD_COLORS", "0", 1) >= 0);
        assert_se(setenv("COLUMNS", "40", 1) >= 0);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
