/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
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
         * second step. With SD_JOURNAL_ASSUME_IMMUTABLE the caller declared it won't wait for changes,
         * hence opening such a nascent file shall succeed, skip the file, and record the skip in the
         * error map. Without the flag the caller may wait for the file to become readable, but
         * sd_journal_open_files() pins the file set, so a file skipped at open time would be ignored
         * forever: the open shall keep failing instead. A file with an incomplete or invalid header
         * shall keep reporting an error in any case. */

        ASSERT_NOT_NULL(empty = path_join(root, "empty.journal"));
        ASSERT_OK_ERRNO(fd = open(empty, O_CREAT|O_WRONLY|O_CLOEXEC, 0644));
        fd = safe_close(fd);

        ASSERT_OK_ZERO(sd_journal_open_files(&j, (const char**) STRV_MAKE(empty), SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_TRUE(ordered_hashmap_isempty(j->files));
        ASSERT_TRUE(hashmap_contains(j->errors, INT_TO_PTR(-ENODATA)));
        ASSERT_OK_ZERO(sd_journal_seek_head(j));
        ASSERT_OK_ZERO(sd_journal_next(j));
        sd_journal_close(j);
        j = NULL;

        ASSERT_ERROR(sd_journal_open_files(&j, (const char**) STRV_MAKE(empty), 0), ENODATA);
        ASSERT_NULL(j);

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

        ASSERT_OK_ZERO(sd_journal_open_files(&j, (const char**) STRV_MAKE(empty, valid), SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_EQ(ordered_hashmap_size(j->files), 1u);
        ASSERT_TRUE(hashmap_contains(j->errors, INT_TO_PTR(-ENODATA)));
        ASSERT_OK_ZERO(sd_journal_seek_head(j));
        ASSERT_EQ(sd_journal_next(j), 1);
        ASSERT_OK_ZERO(sd_journal_next(j));
        sd_journal_close(j);
        j = NULL;

        ASSERT_ERROR(sd_journal_open_files(&j, (const char**) STRV_MAKE(empty, valid), 0), ENODATA);
        ASSERT_NULL(j);

        /* For caller provided fds the error is kept even with SD_JOURNAL_ASSUME_IMMUTABLE, since
         * skipping the file would leave the fd's ownership in limbo. The fd shall remain open, as for
         * any other failure. */
        ASSERT_OK_ERRNO(fd = open(empty, O_RDONLY|O_CLOEXEC));
        ASSERT_ERROR(sd_journal_open_files_fd(&j, (int[]) { fd }, 1, SD_JOURNAL_ASSUME_IMMUTABLE), ENODATA);
        ASSERT_NULL(j);
        ASSERT_OK_ERRNO(fcntl(fd, F_GETFD));
        fd = safe_close(fd);

        /* Only a zero size file counts as nascent: a nonzero file shorter than the header lost data to
         * truncation, and keeps failing even with SD_JOURNAL_ASSUME_IMMUTABLE. */
        ASSERT_NOT_NULL(truncated = path_join(root, "truncated.journal"));
        ASSERT_OK_ERRNO(fd = open(truncated, O_CREAT|O_WRONLY|O_CLOEXEC, 0644));
        ASSERT_EQ(write(fd, "x", 1), (ssize_t) 1);
        fd = safe_close(fd);

        ASSERT_ERROR(sd_journal_open_files(&j, (const char**) STRV_MAKE(truncated), SD_JOURNAL_ASSUME_IMMUTABLE), ENODATA);
        ASSERT_NULL(j);
        ASSERT_ERROR(sd_journal_open_files(&j, (const char**) STRV_MAKE(truncated), 0), ENODATA);
        ASSERT_NULL(j);

        ASSERT_NOT_NULL(garbage = path_join(root, "garbage.journal"));
        ASSERT_OK_ERRNO(fd = open(garbage, O_CREAT|O_WRONLY|O_CLOEXEC, 0644));
        memset(buf, 'x', sizeof(buf));
        ASSERT_EQ(write(fd, buf, sizeof(buf)), (ssize_t) sizeof(buf));
        fd = safe_close(fd);

        ASSERT_ERROR(sd_journal_open_files(&j, (const char**) STRV_MAKE(garbage), SD_JOURNAL_ASSUME_IMMUTABLE), EBADMSG);
        ASSERT_NULL(j);
        ASSERT_ERROR(sd_journal_open_files(&j, (const char**) STRV_MAKE(garbage), 0), EBADMSG);
        ASSERT_NULL(j);
}

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

        test_open_files_incomplete_header(t);

        ASSERT_OK(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL));

        test_tail_timestamp_archived_fallback();

        return 0;
}
