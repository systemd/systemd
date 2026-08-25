/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "chattr-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "iovec-util.h"
#include "journal-file-util.h"
#include "journal-internal.h"
#include "log.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "tests.h"

static void test_tail_timestamp_archived_fallback(void) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *path = NULL;
        dual_timestamp ts = {};
        sd_journal *j;
        JournalFile *f;
        le64_t v;
        uint8_t state;
        char t[] = "/var/tmp/journal-tail-XXXXXX";

        /* An archived file's tail entry timestamps are not validated on a read-only open, so the
         * header fallback in journal_file_read_tail_timestamp() must validate them at use, and read
         * the last entry instead when they are invalid. */

        ASSERT_NOT_NULL(mkdtemp(t));
        (void) chattr_path(t, FS_NOCOW_FL, FS_NOCOW_FL);
        ASSERT_NOT_NULL(path = path_join(t, "test.journal"));

        ASSERT_NOT_NULL(m = mmap_cache_new());
        ASSERT_OK_ZERO(journal_file_open(
                        -EBADF, path, O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0666, UINT64_MAX,
                        /* metrics= */ NULL, m, /* template= */ NULL, &f));

        for (unsigned i = 0; i < 5; i++) {
                struct iovec iovec = IOVEC_MAKE_STRING("LINE=x");
                ts.monotonic = 100 + i;
                ts.realtime = 1000 + i;
                ASSERT_OK_ZERO(journal_file_append_entry(
                                f, &ts, /* boot_id= */ NULL, &iovec, 1,
                                /* seqnum= */ NULL, /* seqnum_id= */ NULL,
                                /* ret_object= */ NULL, /* ret_offset= */ NULL));
        }

        (void) journal_file_offline_close(f);

        /* The fallback requires an archived file whose tail_entry_offset does not resolve to an
         * entry object: point it at the first object after the header, which is a hash table, and
         * make tail_entry_realtime invalid. */
        ASSERT_OK_ERRNO(fd = open(path, O_RDWR|O_CLOEXEC));
        state = STATE_ARCHIVED;
        ASSERT_OK_EQ_ERRNO(pwrite(fd, &state, sizeof(state), offsetof(Header, state)),
                           (ssize_t) sizeof(state));
        ASSERT_OK_EQ_ERRNO(pread(fd, &v, sizeof(v), offsetof(Header, header_size)),
                           (ssize_t) sizeof(v));
        ASSERT_OK_EQ_ERRNO(pwrite(fd, &v, sizeof(v), offsetof(Header, tail_entry_offset)),
                           (ssize_t) sizeof(v));
        v = htole64(UINT64_MAX);
        ASSERT_OK_EQ_ERRNO(pwrite(fd, &v, sizeof(v), offsetof(Header, tail_entry_realtime)),
                           (ssize_t) sizeof(v));

        ASSERT_OK_ZERO(sd_journal_open_files(&j, (const char**) STRV_MAKE(path), 0));
        ASSERT_OK(sd_journal_next(j));

        /* The newest-entry cache must hold the last entry's timestamps, not the doctored header
         * value. */
        ASSERT_NOT_NULL(f = ordered_hashmap_first(j->files));
        ASSERT_EQ(f->newest_realtime_usec, UINT64_C(1004));
        ASSERT_EQ(f->newest_monotonic_usec, UINT64_C(104));

        sd_journal_close(j);
        ASSERT_OK(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL));
}

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

        ASSERT_NOT_NULL(mkdtemp(t));
        (void) chattr_path(t, FS_NOCOW_FL, FS_NOCOW_FL);

        for (i = 0; i < I; i++) {
                ASSERT_OK_ZERO(sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_ASSUME_IMMUTABLE));

                sd_journal_close(j);

                ASSERT_OK_ZERO(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));

                ASSERT_OK_ZERO(sd_journal_seek_head(j));
                ASSERT_EQ(j->current_location.type, (LocationType) LOCATION_HEAD);

                r = pidref_safe_fork("(journal-fork-test)", FORK_WAIT|FORK_LOG, NULL);
                if (r == 0) {
                        ASSERT_NOT_NULL(j);
                        ASSERT_RETURN_EXPECTED_SE(sd_journal_get_realtime_usec(j, NULL) == -ECHILD);
                        ASSERT_RETURN_EXPECTED_SE(sd_journal_seek_tail(j) == -ECHILD);
                        ASSERT_EQ(j->current_location.type, (LocationType) LOCATION_HEAD);
                        sd_journal_close(j);
                        _exit(EXIT_SUCCESS);
                }

                ASSERT_OK(r);

                sd_journal_close(j);

                j = NULL;
                ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_journal_open_directory(&j, t, SD_JOURNAL_LOCAL_ONLY), EINVAL));
                ASSERT_NULL(j);
        }

        ASSERT_OK(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL));

        test_tail_timestamp_archived_fallback();

        return 0;
}
