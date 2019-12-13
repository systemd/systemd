/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "chattr-util.h"
#include "journal-file.h"
#include "journal-internal.h"
#include "macro.h"
#include "path-util.h"
#include "string-util.h"

int main(int argc, char *argv[]) {
        _cleanup_free_ char *fn = NULL;
        char dn[] = "/var/tmp/test-journal-flush.XXXXXX";
        JournalFile *new_journal = NULL;
        sd_journal *j = NULL;
        unsigned n = 0;
        int r;

        assert_se(mkdtemp(dn));
        (void) chattr_path(dn, FS_NOCOW_FL, FS_NOCOW_FL, NULL);

        fn = path_join(dn, "test.journal");

        r = journal_file_open(-1, fn, O_CREAT|O_RDWR, 0644, false, 0, false, NULL, NULL, NULL, NULL, &new_journal);
        assert_se(r >= 0);

        r = sd_journal_open(&j, 0);
        assert_se(r >= 0);

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

                r = journal_file_copy_entry(f, new_journal, o, f->current_offset);
                if (r < 0)
                        log_error_errno(r, "journal_file_copy_entry failed: %m");
                assert_se(r >= 0);

                if (++n >= 10000)
                        break;
        }

        sd_journal_close(j);

        (void) journal_file_close(new_journal);

        unlink(fn);
        assert_se(rmdir(dn) == 0);

        return 0;
}
