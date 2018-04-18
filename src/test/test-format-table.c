/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "format-table.h"
#include "string-util.h"
#include "time-util.h"

int main(int argc, char *argv[]) {

        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *formatted = NULL;

        assert_se(setenv("COLUMNS", "40", 1) >= 0);

        assert_se(t = table_new("ONE", "TWO", "THREE"));

        assert_se(table_set_align_percent(t, TABLE_HEADER_CELL(2), 100) >= 0);

        assert_se(table_add_many(t,
                                 TABLE_STRING, "xxx",
                                 TABLE_STRING, "yyy",
                                 TABLE_BOOLEAN, true) >= 0);

        assert_se(table_add_many(t,
                                 TABLE_STRING, "a long field",
                                 TABLE_STRING, "yyy",
                                 TABLE_BOOLEAN, false) >= 0);

        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "ONE          TWO THREE\n"
                        "xxx          yyy   yes\n"
                        "a long field yyy    no\n"));

        formatted = mfree(formatted);

        table_set_width(t, 40);

        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "ONE                TWO             THREE\n"
                        "xxx                yyy               yes\n"
                        "a long field       yyy                no\n"));

        formatted = mfree(formatted);

        table_set_width(t, 12);
        assert_se(table_format(t, &formatted) >= 0);
        printf("%s\n", formatted);

        assert_se(streq(formatted,
                        "ONE TWO THR…\n"
                        "xxx yyy  yes\n"
                        "a … yyy   no\n"));

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
                        "a long field yyy    no\n"
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
                        "a long field yyy    no\n"
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

        return 0;
}
