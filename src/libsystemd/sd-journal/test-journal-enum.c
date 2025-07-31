/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-journal.h"

#include "tests.h"

int main(int argc, char *argv[]) {
        unsigned n = 0;
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;

        test_setup_logging(LOG_DEBUG);

        assert_se(sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_ASSUME_IMMUTABLE) >= 0);

        assert_se(sd_journal_add_match(j, "_TRANSPORT=syslog", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "_UID=0", SIZE_MAX) >= 0);

        SD_JOURNAL_FOREACH_BACKWARDS(j) {
                const void *d;
                size_t l;

                assert_se(sd_journal_get_data(j, "MESSAGE", &d, &l) >= 0);

                printf("%.*s\n", (int) l, (char*) d);

                n++;
                if (n >= 10)
                        break;
        }

        return 0;
}
