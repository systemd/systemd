/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "chattr-util.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "journal-file-util.h"
#include "journal-internal.h"
#include "log.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

static void test_open_files_incomplete_header(const char *root) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_free_ char *empty = NULL, *truncated = NULL, *garbage = NULL, *valid = NULL;
        _cleanup_close_ int fd = -EBADF;
        struct iovec iovec = IOVEC_MAKE_STRING("MESSAGE=hello");
        sd_journal *j = NULL;
        JournalFile *vf;
        dual_timestamp ts;
        char buf[300];

        /* Journal writers create journal files empty at their final name, and write the header in a
         * second step. Opening such a nascent file shall succeed and behave as if the file didn't exist
         * yet, while a file with an incomplete or invalid header shall keep reporting an error. */

        ASSERT_NOT_NULL(empty = path_join(root, "empty.journal"));
        ASSERT_OK_ERRNO(fd = open(empty, O_CREAT|O_WRONLY|O_CLOEXEC, 0644));
        fd = safe_close(fd);

        ASSERT_OK_ZERO(sd_journal_open_files(&j, (const char**) STRV_MAKE(empty), 0));
        ASSERT_OK_ZERO(sd_journal_seek_head(j));
        ASSERT_OK_ZERO(sd_journal_next(j));
        sd_journal_close(j);
        j = NULL;

        /* An empty file among valid ones is skipped, and doesn't affect the valid ones. */
        ASSERT_NOT_NULL(m = mmap_cache_new());
        ASSERT_NOT_NULL(valid = path_join(root, "valid.journal"));
        ASSERT_OK_ZERO(journal_file_open(-EBADF, valid, O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0644, UINT64_MAX,
                                         /* metrics= */ NULL, m, /* template= */ NULL, &vf));
        dual_timestamp_now(&ts);
        ASSERT_OK_ZERO(journal_file_append_entry(vf, &ts, /* boot_id= */ NULL, &iovec, 1,
                                                 /* seqnum= */ NULL, /* seqnum_id= */ NULL,
                                                 /* ret_object= */ NULL, /* ret_offset= */ NULL));
        (void) journal_file_offline_close(vf);

        ASSERT_OK_ZERO(sd_journal_open_files(&j, (const char**) STRV_MAKE(empty, valid), 0));
        ASSERT_OK_ZERO(sd_journal_seek_head(j));
        ASSERT_EQ(sd_journal_next(j), 1);
        ASSERT_OK_ZERO(sd_journal_next(j));
        sd_journal_close(j);
        j = NULL;

        /* For caller provided fds the error is kept, since skipping the file would leave the fd's
         * ownership in limbo. The fd shall remain open, as for any other failure. */
        ASSERT_OK_ERRNO(fd = open(empty, O_RDONLY|O_CLOEXEC));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_journal_open_files_fd(&j, (int[]) { fd }, 1, 0), ENODATA));
        ASSERT_NULL(j);
        ASSERT_OK_ERRNO(fcntl(fd, F_GETFD));
        fd = safe_close(fd);

        ASSERT_NOT_NULL(truncated = path_join(root, "truncated.journal"));
        ASSERT_OK_ERRNO(fd = open(truncated, O_CREAT|O_WRONLY|O_CLOEXEC, 0644));
        ASSERT_EQ(write(fd, "x", 1), (ssize_t) 1);
        fd = safe_close(fd);

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_journal_open_files(&j, (const char**) STRV_MAKE(truncated), 0), ENODATA));
        ASSERT_NULL(j);

        ASSERT_NOT_NULL(garbage = path_join(root, "garbage.journal"));
        ASSERT_OK_ERRNO(fd = open(garbage, O_CREAT|O_WRONLY|O_CLOEXEC, 0644));
        memset(buf, 'x', sizeof(buf));
        ASSERT_EQ(write(fd, buf, sizeof(buf)), (ssize_t) sizeof(buf));
        fd = safe_close(fd);

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_journal_open_files(&j, (const char**) STRV_MAKE(garbage), 0), EBADMSG));
        ASSERT_NULL(j);
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

        test_open_files_incomplete_header(t);

        ASSERT_OK(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL));

        return 0;
}
