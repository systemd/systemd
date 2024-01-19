/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-journal.h"

#include "chattr-util.h"
#include "journal-internal.h"
#include "log.h"
#include "parse-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        sd_journal *j;
        int r, i, I = 100;
        char t[] = "/var/tmp/journal-stream-XXXXXX";

        test_setup_logging(LOG_DEBUG);

        if (argc >= 2) {
                r = safe_atoi(argv[1], &I);
                if (r < 0)
                        log_info("Could not parse loop count argument. Using default.");
        }

        log_info("Running %d loops", I);

        assert_se(mkdtemp(t));
        (void) chattr_path(t, FS_NOCOW_FL, FS_NOCOW_FL, NULL);

        for (i = 0; i < I; i++) {
                r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_READ_TAIL_TIMESTAMP_ONCE);
                assert_se(r == 0);

                sd_journal_close(j);

                r = sd_journal_open_directory(&j, t, SD_JOURNAL_READ_TAIL_TIMESTAMP_ONCE);
                assert_se(r == 0);

                assert_se(sd_journal_seek_head(j) == 0);
                assert_se(j->current_location.type == LOCATION_HEAD);

                r = safe_fork("(journal-fork-test)", FORK_WAIT|FORK_LOG, NULL);
                if (r == 0) {
                        assert_se(j);
                        ASSERT_RETURN_EXPECTED_SE(sd_journal_get_realtime_usec(j, NULL) == -ECHILD);
                        ASSERT_RETURN_EXPECTED_SE(sd_journal_seek_tail(j) == -ECHILD);
                        assert_se(j->current_location.type == LOCATION_HEAD);
                        sd_journal_close(j);
                        _exit(EXIT_SUCCESS);
                }

                assert_se(r >= 0);

                sd_journal_close(j);

                j = NULL;
                ASSERT_RETURN_EXPECTED(assert_se(sd_journal_open_directory(&j, t, SD_JOURNAL_LOCAL_ONLY) == -EINVAL));
                assert_se(j == NULL);
        }

        assert_se(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);

        return 0;
}
