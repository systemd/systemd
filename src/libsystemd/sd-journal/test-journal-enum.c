/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-journal.h"

#include "tests.h"

TEST(journal_enum) {
        unsigned n = 0;
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;

        ASSERT_OK(sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_ASSUME_IMMUTABLE));

        ASSERT_OK(sd_journal_add_match(j, "_TRANSPORT=syslog", SIZE_MAX));
        ASSERT_OK(sd_journal_add_match(j, "_UID=0", SIZE_MAX));

        SD_JOURNAL_FOREACH_BACKWARDS(j) {
                const void *d;
                size_t l;

                ASSERT_OK(sd_journal_get_data(j, "MESSAGE", &d, &l));

                printf("%.*s\n", (int) l, (char*) d);

                n++;
                if (n >= 10)
                        break;
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
