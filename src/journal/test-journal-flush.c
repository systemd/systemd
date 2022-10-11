/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "chattr-util.h"
#include "journal-internal.h"
#include "macro.h"
#include "managed-journal-file.h"
#include "path-util.h"
#include "string-util.h"

static void test_journal_flush(int argc, char *argv[]) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_free_ char *fn = NULL;
        char dn[] = "/var/tmp/test-journal-flush.XXXXXX";
        ManagedJournalFile *new_journal = NULL;
        sd_journal *j = NULL;
        unsigned n = 0;
        int r;

        m = mmap_cache_new();
        assert_se(m != NULL);
        assert_se(mkdtemp(dn));
        (void) chattr_path(dn, FS_NOCOW_FL, FS_NOCOW_FL, NULL);

        fn = path_join(dn, "test.journal");

        r = managed_journal_file_open(-1, fn, O_CREAT|O_RDWR, 0, 0644, 0, NULL, m, NULL, NULL, &new_journal);
        assert_se(r >= 0);

        if (argc > 1)
                r = sd_journal_open_files(&j, (const char **) strv_skip(argv, 1), 0);
        else
                r = sd_journal_open(&j, 0);
        assert_se(r == 0);

        sd_journal_set_data_threshold(j, 0);

        SD_JOURNAL_FOREACH(j) {
                Object *o;
                JournalFile *f;

                f = j->current_file;
                assert_se(f && f->current_offset > 0);

                r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
                if (r < 0)
                        log_error_errno(r, "journal_file_move_to_object failed: %m");
                assert_se(r >= 0);

                r = journal_file_copy_entry(f, new_journal->file, o, f->current_offset);
                if (r < 0)
                        log_warning_errno(r, "journal_file_copy_entry failed: %m");
                assert_se(r >= 0 ||
                          IN_SET(r, -EBADMSG,         /* corrupted file */
                                    -EPROTONOSUPPORT, /* unsupported compression */
                                    -EIO));           /* file rotated */

                if (++n >= 10000)
                        break;
        }

        sd_journal_close(j);

        (void) managed_journal_file_close(new_journal);

        unlink(fn);
        assert_se(rmdir(dn) == 0);
}

int main(int argc, char *argv[]) {
        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1) >= 0);
        test_journal_flush(argc, argv);

        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1) >= 0);
        test_journal_flush(argc, argv);

        return 0;
}
