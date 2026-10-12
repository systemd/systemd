/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "journal-file-util.h"
#include "journal-test-util.h"
#include "mmap-cache.h"
#include "rm-rf.h"
#include "strv.h"
#include "tests.h"

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

        journal_test_setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = journal_test_open(m, "test.journal", O_RDWR|O_CREAT, 128 * U64_MB);
        model_assert_file(f, &model);

        for (uint64_t i = 0; i < 300; i++) {
                model_append_generated(f, &model, i);

                if (i < 10 || i % 100 == 0)
                        model_assert_file(f, &model);
        }

        /* The same field twice */
        model_append(f, &model, model_realtime_base + 300 * 10, 5000 + 300 * 10, MODEL_BOOT_A,
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

        journal_test_setup(&directory);
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

static int intro(void) {
        /* journal_file_open() requires a valid machine id */
        if (sd_id128_get_machine(NULL) < 0)
                return log_tests_skipped("No valid machine ID found");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
