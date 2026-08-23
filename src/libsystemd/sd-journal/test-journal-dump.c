/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "journal-file.h"
#include "log.h"
#include "main-func.h"
#include "pager.h"
#include "strv.h"

static int run(int argc, char *argv[]) {
        int r = 0;
        unsigned n = 0;

        _cleanup_(mmap_cache_unrefp) MMapCache *m = mmap_cache_new();
        assert_se(m);

        pager_open(/* flags= */ 0);

        STRV_FOREACH(s, strv_skip(argv, 1)) {
                JournalFile *f = NULL;

                int k = journal_file_open(
                                /* fd= */ -EBADF,
                                *s,
                                O_RDONLY,
                                /* file_flags= */ 0,
                                0666,
                                /* compress_threshold_bytes= */ UINT64_MAX,
                                /* metrics= */ NULL,
                                m,
                                /* template= */ NULL,
                                &f);
                if (k < 0)
                        RET_GATHER(r, log_error_errno(k, "Failed to open %s, continuing: %m", *s));

                if (n++ > 0)
                        puts("");

                journal_file_print_header(f);
                journal_file_close(f);
        }

        return r;
}

DEFINE_MAIN_FUNCTION(run);
