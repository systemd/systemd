/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "chattr-util.h"
#include "journal-file-util.h"
#include "journal-internal.h"
#include "macro.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_journal_flush_one(int argc, char *argv[]) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_free_ char *fn = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *dn = NULL;
        _cleanup_(journal_file_offline_closep) JournalFile *new_journal = NULL;
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        unsigned n, limit;
        int r;

        assert_se(m = mmap_cache_new());
        assert_se(mkdtemp_malloc("/var/tmp/test-journal-flush.XXXXXX", &dn) >= 0);
        (void) chattr_path(dn, FS_NOCOW_FL, FS_NOCOW_FL, NULL);

        assert_se(fn = path_join(dn, "test.journal"));

        r = journal_file_open(-1, fn, O_CREAT|O_RDWR, 0, 0644, 0, NULL, m, NULL, &new_journal);
        assert_se(r >= 0);

        if (argc > 1)
                r = sd_journal_open_files(&j, (const char **) strv_skip(argv, 1), 0);
        else
                r = sd_journal_open(&j, 0);
        assert_se(r == 0);

        sd_journal_set_data_threshold(j, 0);

        n = 0;
        limit = slow_tests_enabled() ? 10000 : 1000;
        SD_JOURNAL_FOREACH(j) {
                Object *o;
                JournalFile *f;

                f = j->current_file;
                assert_se(f && f->current_offset > 0);

                r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
                if (r < 0)
                        log_error_errno(r, "journal_file_move_to_object failed: %m");
                assert_se(r >= 0);

                r = journal_file_copy_entry(f, new_journal, o, f->current_offset, NULL, NULL);
                if (r < 0)
                        log_warning_errno(r, "journal_file_copy_entry failed: %m");
                assert_se(r >= 0 ||
                          IN_SET(r, -EBADMSG,         /* corrupted file */
                                    -EPROTONOSUPPORT, /* unsupported compression */
                                    -EIO,             /* file rotated */
                                    -EREMCHG));       /* clock rollback */

                if (++n >= limit)
                        break;
        }
}

TEST(journal_flush) {
        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1) >= 0);
        test_journal_flush_one(saved_argc, saved_argv);
}

TEST(journal_flush_compact) {
        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1) >= 0);
        test_journal_flush_one(saved_argc, saved_argv);
}

DEFINE_TEST_MAIN(LOG_INFO);
