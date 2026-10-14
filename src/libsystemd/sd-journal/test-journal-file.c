/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-journal.h"

#include "journal-file-util.h"
#include "journal-test-util.h"
#include "journal-verify.h"
#include "mmap-cache.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"

static void test_journal_file_parse_uid_from_filename_simple(
                const char *path,
                uid_t expected_uid,
                int expected_error) {

        uid_t uid = UID_INVALID;
        int r;

        log_info("testing %s", path);

        r = journal_file_parse_uid_from_filename(path, &uid);
        ASSERT_EQ(r, expected_error);
        if (r < 0)
                ASSERT_EQ(uid, UID_INVALID);
        else
                ASSERT_EQ(uid, expected_uid);
}

TEST(journal_file_parse_uid_from_filename) {

        test_journal_file_parse_uid_from_filename_simple("/var/log/journal/", 0, -EISDIR);

        /* The helper should return -EREMOTE for any filenames that don't look like an online or offline user
         * journals. This includes archived and disposed journal files. */
        test_journal_file_parse_uid_from_filename_simple("/etc/password", 0, -EREMOTE);
        test_journal_file_parse_uid_from_filename_simple("system.journal", 0, -EREMOTE);
        test_journal_file_parse_uid_from_filename_simple("user-1000@0005d26980bdce6e-2f2a4939583822ef.journal~", 0, -EREMOTE);
        test_journal_file_parse_uid_from_filename_simple("user-1000@xxx-yyy-zzz.journal", 0, -EREMOTE);

        test_journal_file_parse_uid_from_filename_simple("user-1000.journal", 1000, 0);
        test_journal_file_parse_uid_from_filename_simple("user-foo.journal", 0, -EINVAL);
        test_journal_file_parse_uid_from_filename_simple("user-65535.journal", 0, -ENXIO);
}

TEST(append_and_read) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        JournalFile *f, *g;

        if (!journal_test_setup(&directory))
                return;
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = journal_test_open(m, "test.journal", O_RDWR|O_CREAT, 128 * U64_MB);
        model_assert_file(f, &model);

        for (uint64_t i = 0; i < 300; i++) {
                model_append_generated(f, &model, i);

                if (i < 10 || i % 100 == 0)
                        model_assert_file(f, &model);
        }

        /* The same field twice */
        model_append(f, &model, MODEL_REALTIME_BASE + 300 * 10, 5000 + 300 * 10, MODEL_BOOT_A,
                     STRV_MAKE("MESSAGE=foo", "A=b", "A=b", "_X=y", "MESSAGE=foo", "A=c", "_BOOT_ID=a1a2a3a4a5a6a7a8a9aaabacadaeafa0"));
        model_assert_file(f, &model);

        /* A second reader while the file is written */
        g = journal_test_open(m, "test.journal", O_RDONLY, 0);
        model_assert_file(g, &model);

        model_append_generated(f, &model, 301);
        model_assert_file(g, &model);
        g = journal_file_close(g);

        /* Close and continue */
        f = journal_file_offline_close(f);
        f = journal_test_open(m, "test.journal", O_RDWR, 128 * U64_MB);
        model_assert_file(f, &model);

        for (uint64_t i = 302; i < 400; i++)
                model_append_generated(f, &model, i);
        model_assert_file(f, &model);
        f = journal_file_offline_close(f);
}

TEST(seek_before_first_entry) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        const char *match = "_HOSTNAME=test";
        JournalFile *f;
        Object *o;

        if (!journal_test_setup(&directory))
                return;
        ASSERT_NOT_NULL(m = mmap_cache_new());

        /* An offset within the header. sd-journal passes the offset of the current entry minus one when it
         * looks for the previous match. */
        f = journal_test_open(m, "test.journal", O_RDWR|O_CREAT, 2 * U64_MB);
        model_append_generated(f, &model, 0);
        ASSERT_OK_ZERO(journal_file_seek_for_match(f, match, strlen(match), JOURNAL_SEEK_OFFSET, /* boot_id= */ SD_ID128_NULL,
                                                   le64toh(f->header->header_size) - 1, DIRECTION_UP, &o, NULL));
        ASSERT_OK_POSITIVE(journal_file_seek_for_match(f, match, strlen(match), JOURNAL_SEEK_OFFSET, /* boot_id= */ SD_ID128_NULL,
                                                       le64toh(f->header->header_size) - 1, DIRECTION_DOWN, &o, NULL));
        f = journal_file_offline_close(f);
}

TEST(sync_and_archive) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        _cleanup_free_ char *path = NULL;
        JournalFile *f, *g, *follower;

        if (!journal_test_setup(&directory))
                return;
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = journal_test_open(m, "test.journal", O_RDWR|O_CREAT, 3 * U64_MB);
        follower = journal_test_open(m, "test.journal", O_RDONLY, 0);

        for (uint64_t i = 0; i < 3000; i++) {
                model_append_generated(f, &model, i);

                if (i % 500 == 0) {
                        model_assert_file(f, &model);
                        model_assert_file(follower, &model);
                }
        }

        model_assert_file(f, &model);
        model_assert_file(follower, &model);

        /* Before and after a sync */
        g = journal_test_open(m, "test.journal", O_RDONLY, 0);
        model_assert_file(g, &model);
        g = journal_file_close(g);

        ASSERT_OK(journal_file_set_offline(f, /* wait= */ true));
        g = journal_test_open(m, "test.journal", O_RDONLY, 0);
        model_assert_file(g, &model);
        g = journal_file_close(g);

        /* Same, in the background */
        for (uint64_t i = 3000; i < 5000; i++)
                model_append_generated(f, &model, i);
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ false));
        for (uint64_t i = 5000; i < 5100; i++)
                model_append_generated(f, &model, i);
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ true));
        model_assert_file(f, &model);

        /* Continue the file */
        f = journal_file_offline_close(f);
        f = journal_test_open(m, "test.journal", O_RDWR, 3 * U64_MB);
        model_assert_file(f, &model);

        for (uint64_t i = 5100; i < 6000; i++)
                model_append_generated(f, &model, i);
        model_assert_file(f, &model);

        /* Archive it */
        ASSERT_OK(journal_file_archive(f, /* ret_previous_path= */ NULL));
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ true));
        ASSERT_EQ(f->header->state, STATE_ARCHIVED);
        ASSERT_NOT_NULL(path = strdup(f->path));
        f = journal_file_offline_close(f);

        g = journal_test_open(m, path, O_RDONLY, 0);
        ASSERT_EQ(g->header->state, STATE_ARCHIVED);
        model_assert_file(g, &model);
        g = journal_file_close(g);

        /* The follower kept the file open throughout */
        ASSERT_EQ(follower->header->state, STATE_ARCHIVED);
        model_assert_file(follower, &model);
        follower = journal_file_close(follower);

        ASSERT_ERROR(journal_file_open(
                                     /* fd= */ -EBADF,
                                     path,
                                     O_RDWR,
                                     /* file_flags= */ 0,
                                     0644,
                                     /* compress_threshold_bytes= */ UINT64_MAX,
                                     /* metrics= */ NULL,
                                     m,
                                     /* template= */ NULL,
                                     &g),
                     ESHUTDOWN);
}

static void test_sync_then_archive_one(bool sync_done) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        _cleanup_free_ char *path = NULL;
        JournalFile *f, *g;

        if (!journal_test_setup(&directory))
                return;
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = journal_test_open(m, "test.journal", O_RDWR|O_CREAT, 2 * U64_MB);

        for (uint64_t i = 0; i < 3000; i++)
                model_append_generated(f, &model, i);

        /* A sync in the background that nobody joins, followed by a rotation, the way journald does it.
         * Without waiting, the sync thread may still run when the file is archived. */
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ false));
        if (sync_done) {
                for (unsigned i = 0; i < 1000 && journal_file_is_offlining(f); i++)
                        usleep_safe(10 * USEC_PER_MSEC);
                ASSERT_FALSE(journal_file_is_offlining(f));
        }

        ASSERT_OK(journal_file_archive(f, /* ret_previous_path= */ NULL));
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ false));
        ASSERT_EQ(memcmp(f->header->signature, HEADER_SIGNATURE, sizeof(f->header->signature)), 0);
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ true));
        ASSERT_EQ(f->header->state, STATE_ARCHIVED);
        model_assert_file(f, &model);

        ASSERT_NOT_NULL(path = strdup(f->path));
        f = journal_file_offline_close(f);

        g = journal_test_open(m, path, O_RDONLY, 0);
        ASSERT_EQ(g->header->state, STATE_ARCHIVED);
        model_assert_file(g, &model);
        ASSERT_OK(journal_file_verify(
                                  g,
                                  /* key= */ NULL,
                                  /* ret_first_contained= */ NULL,
                                  /* ret_last_validated= */ NULL,
                                  /* ret_last_contained= */ NULL,
                                  /* show_progress= */ false));
        g = journal_file_close(g);
}

TEST(sync_then_archive) {
        test_sync_then_archive_one(/* sync_done= */ true);
        test_sync_then_archive_one(/* sync_done= */ false);
}

TEST(read_deleted) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        JournalFile *f, *follower;

        if (!journal_test_setup(&directory))
                return;
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = journal_test_open(m, "test.journal", O_RDWR|O_CREAT, 2 * U64_MB);
        model_append_generated(f, &model, 0);
        follower = journal_test_open(m, "test.journal", O_RDONLY, 0);

        /* A reader can still read a file that was deleted, including entries appended since */
        model_append_generated(f, &model, 1);
        ASSERT_OK_ERRNO(unlink("test.journal"));
        model_assert_file(follower, &model);

        follower = journal_file_close(follower);
        f = journal_file_offline_close(f);
}

TEST(enumerate_live) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_(model_done) Model model = {};
        bool found = false;
        const char *name;
        JournalFile *f;

        if (!journal_test_setup(&directory))
                return;
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = journal_test_open(m, "test.journal", O_RDWR|O_CREAT, 2 * U64_MB);
        model_append_generated(f, &model, 0);

        ASSERT_OK(sd_journal_open_files(&j, (const char*[]) { "test.journal", NULL }, 0));
        SD_JOURNAL_FOREACH_FIELD(j, name)
                ASSERT_FALSE(streq(name, "NEWFIELD"));

        /* Enumeration finds fields that were appended since */
        model_append(f, NULL, MODEL_REALTIME_BASE + 10, 5010, MODEL_BOOT_A, STRV_MAKE("NEWFIELD=1"));

        SD_JOURNAL_FOREACH_FIELD(j, name)
                found = found || streq(name, "NEWFIELD");
        ASSERT_TRUE(found);

        f = journal_file_offline_close(f);
}

TEST(seek_tail_live) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_(model_done) Model model = {};
        uint64_t realtime;
        JournalFile *f;

        if (!journal_test_setup(&directory))
                return;
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = journal_test_open(m, "test.journal", O_RDWR|O_CREAT, 2 * U64_MB);
        model_append_generated(f, &model, 0);

        ASSERT_OK(sd_journal_open_files(&j, (const char*[]) { "test.journal", NULL }, 0));
        ASSERT_OK(sd_journal_seek_tail(j));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));

        /* Seeking finds entries that were appended since, even without sd_journal_process() */
        model_append_generated(f, &model, 1);

        ASSERT_OK(sd_journal_seek_tail(j));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));
        ASSERT_OK(sd_journal_get_realtime_usec(j, &realtime));
        ASSERT_EQ(realtime, model.realtime[1]);

        f = journal_file_offline_close(f);
}

DEFINE_TEST_MAIN(LOG_INFO);
