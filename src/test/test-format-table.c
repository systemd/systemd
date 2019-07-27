/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "format-table.h"
#include "string-util.h"
#include "time-util.h"

static void test_issue_9549(void) {
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
                        "NAME  TYPE RO  USAGE CREATED                    MODIFIED                   \n"
                        "foooo raw  no 673.6M Wed 2018-07-11 00:10:33 J… Wed 2018-07-11 00:16:00 JST\n"
                        ));
}

int main(int argc, char *argv[]) {

        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *formatted = NULL;

        assert_se(setenv("SYSTEMD_COLORS", "0", 1) >= 0);
        assert_se(setenv("COLUMNS", "40", 1) >= 0);

        assert_se(t = table_new("one", "two", "three"));

        assert_se(table_set_align_percent(t, TABLE_HEADER_CELL(2), 100) >= 0);

        assert_se(table_add_many(t,
                                 TABLE_STRING, "xxx",
                                 TABLE_STRING, "yyy",
                                 TABLE_BOOLEAN, true) >= 0);

        assert_se(table_add_many(t,
                                 TABLE_STRING, "a long field",
                                 TABLE_STRING, "yyy",
                                 TABLE_SET_UPPERCASE, 1,
                                 TABLE_BOOLEAN, false) >= 0);

        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "ONE          TWO THREE\n"
                        "xxx          yyy   yes\n"
                        "a long field YYY    no\n"));

        formatted = mfree(formatted);

        table_set_width(t, 40);

        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "ONE                TWO             THREE\n"
                        "xxx                yyy               yes\n"
                        "a long field       YYY                no\n"));

        formatted = mfree(formatted);

        table_set_width(t, 12);
        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "ONE TWO THR…\n"
                        "xxx yyy  yes\n"
                        "a … YYY   no\n"));

        formatted = mfree(formatted);

        table_set_width(t, 5);
        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "… … …\n"
                        "… … …\n"
                        "… … …\n"));

        formatted = mfree(formatted);

        table_set_width(t, 3);
        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "… … …\n"
                        "… … …\n"
                        "… … …\n"));

        formatted = mfree(formatted);

        table_set_width(t, (size_t) -1);
        assert_se(table_set_sort(t, (size_t) 0, (size_t) 2, (size_t) -1) >= 0);

        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "ONE          TWO THREE\n"
                        "a long field YYY    no\n"
                        "xxx          yyy   yes\n"));

        formatted = mfree(formatted);

        table_set_header(t, false);

        assert_se(table_add_many(t,
                                 TABLE_STRING, "fäää",
                                 TABLE_STRING, "uuu",
                                 TABLE_BOOLEAN, true) >= 0);

        assert_se(table_add_many(t,
                                 TABLE_STRING, "fäää",
                                 TABLE_STRING, "zzz",
                                 TABLE_BOOLEAN, false) >= 0);

        assert_se(table_add_many(t,
                                 TABLE_EMPTY,
                                 TABLE_SIZE, (uint64_t) 4711,
                                 TABLE_TIMESPAN, (usec_t) 5*USEC_PER_MINUTE) >= 0);

        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "a long field YYY    no\n"
                        "fäää         zzz    no\n"
                        "fäää         uuu   yes\n"
                        "xxx          yyy   yes\n"
                        "             4.6K 5min\n"));

        formatted = mfree(formatted);

        assert_se(table_set_display(t, (size_t) 2, (size_t) 0, (size_t) 2, (size_t) 0, (size_t) 0, (size_t) -1) >= 0);

        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "  no a long f…   no a long f… a long fi…\n"
                        "  no fäää        no fäää      fäää      \n"
                        " yes fäää       yes fäää      fäää      \n"
                        " yes xxx        yes xxx       xxx       \n"
                        "5min           5min                     \n"));

        test_issue_9549();

        return 0;
}
