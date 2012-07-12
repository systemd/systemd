/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>

#include <systemd/sd-journal.h>

#include "journal-internal.h"
#include "util.h"
#include "log.h"

int main(int argc, char *argv[]) {
        sd_journal *j;
        char *t;

        log_set_max_level(LOG_DEBUG);

        assert_se(sd_journal_open(&j, 0) >= 0);

        assert_se(sd_journal_add_match(j, "foobar", 0) < 0);
        assert_se(sd_journal_add_match(j, "foobar=waldo", 0) < 0);
        assert_se(sd_journal_add_match(j, "", 0) < 0);
        assert_se(sd_journal_add_match(j, "=", 0) < 0);
        assert_se(sd_journal_add_match(j, "=xxxxx", 0) < 0);
        assert_se(sd_journal_add_match(j, "HALLO=WALDO", 0) >= 0);
        assert_se(sd_journal_add_match(j, "QUUX=mmmm", 0) >= 0);
        assert_se(sd_journal_add_match(j, "QUUX=xxxxx", 0) >= 0);
        assert_se(sd_journal_add_match(j, "HALLO=", 0) >= 0);
        assert_se(sd_journal_add_match(j, "QUUX=xxxxx", 0) >= 0);
        assert_se(sd_journal_add_match(j, "QUUX=yyyyy", 0) >= 0);
        assert_se(sd_journal_add_match(j, "PIFF=paff", 0) >= 0);

        assert_se(sd_journal_add_disjunction(j) >= 0);

        assert_se(sd_journal_add_match(j, "ONE=one", 0) >= 0);
        assert_se(sd_journal_add_match(j, "ONE=two", 0) >= 0);
        assert_se(sd_journal_add_match(j, "TWO=two", 0) >= 0);

        assert_se(t = journal_make_match_string(j));

        assert_se(streq(t, "((TWO=two AND (ONE=two OR ONE=one)) OR (PIFF=paff AND (QUUX=yyyyy OR QUUX=xxxxx OR QUUX=mmmm) AND (HALLO= OR HALLO=WALDO)))"));

        printf("resulting match expression is: %s\n", t);
        free(t);

        sd_journal_close(j);

        return 0;
}
