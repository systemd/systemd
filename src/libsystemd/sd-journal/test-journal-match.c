/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "journal-internal.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_free_ char *t;

        test_setup_logging(LOG_DEBUG);

        assert_se(sd_journal_open(&j, SD_JOURNAL_ASSUME_IMMUTABLE) >= 0);

        assert_se(sd_journal_add_match(j, "foobar", SIZE_MAX) < 0);
        assert_se(sd_journal_add_match(j, "foobar=waldo", SIZE_MAX) < 0);
        assert_se(sd_journal_add_match(j, "", SIZE_MAX) < 0);
        assert_se(sd_journal_add_match(j, "=", SIZE_MAX) < 0);
        assert_se(sd_journal_add_match(j, "=xxxxx", SIZE_MAX) < 0);
        assert_se(sd_journal_add_match(j, (uint8_t[4]){'A', '=', '\1', '\2'}, 4) >= 0);
        assert_se(sd_journal_add_match(j, (uint8_t[5]){'B', '=', 'C', '\0', 'D'}, 5) >= 0);
        assert_se(sd_journal_add_match(j, "HALLO=WALDO", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "QUUX=mmmm", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "QUUX=xxxxx", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "HALLO=", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "QUUX=xxxxx", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "QUUX=yyyyy", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "PIFF=paff", SIZE_MAX) >= 0);

        assert_se(sd_journal_add_disjunction(j) >= 0);

        assert_se(sd_journal_add_match(j, "ONE=one", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "ONE=two", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "TWO=two", SIZE_MAX) >= 0);

        assert_se(sd_journal_add_conjunction(j) >= 0);

        assert_se(sd_journal_add_match(j, "L4_1=yes", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "L4_1=ok", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "L4_2=yes", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "L4_2=ok", SIZE_MAX) >= 0);

        assert_se(sd_journal_add_disjunction(j) >= 0);

        assert_se(sd_journal_add_match(j, "L3=yes", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "L3=ok", SIZE_MAX) >= 0);

        assert_se(t = journal_make_match_string(j));

        printf("resulting match expression is: %s\n", t);

        assert_se(streq(t, "(((L3=ok OR L3=yes) OR ((L4_2=ok OR L4_2=yes) AND (L4_1=ok OR L4_1=yes))) AND ((TWO=two AND (ONE=two OR ONE=one)) OR (PIFF=paff AND (QUUX=yyyyy OR QUUX=xxxxx OR QUUX=mmmm) AND (HALLO= OR HALLO=WALDO) AND B=C\\000D AND A=\\001\\002)))"));

        return 0;
}
