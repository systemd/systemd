/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "chattr-util.h"
#include "io-util.h"
#include "journal-authenticate.h"
#include "journal-vacuum.h"
#include "log.h"
#include "managed-journal-file.h"
#include "rm-rf.h"
#include "tests.h"

static bool arg_keep = false;

static void mkdtemp_chdir_chattr(char *path) {
        assert_se(mkdtemp(path));
        assert_se(chdir(path) >= 0);

        /* Speed up things a bit on btrfs, ensuring that CoW is turned off for all files created in our
         * directory during the test run */
        (void) chattr_path(path, FS_NOCOW_FL, FS_NOCOW_FL, NULL);
}

static void test_non_empty_one(void) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        dual_timestamp ts;
        ManagedJournalFile *f;
        struct iovec iovec;
        static const char test[] = "TEST1=1", test2[] = "TEST2=2";
        Object *o, *d;
        uint64_t p;
        sd_id128_t fake_boot_id;
        char t[] = "/var/tmp/journal-XXXXXX";

        m = mmap_cache_new();
        assert_se(m != NULL);

        mkdtemp_chdir_chattr(t);

        assert_se(managed_journal_file_open(-1, "test.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS|JOURNAL_SEAL, 0666, UINT64_MAX, NULL, m, NULL, NULL, &f) == 0);

        assert_se(dual_timestamp_get(&ts));
        assert_se(sd_id128_randomize(&fake_boot_id) == 0);

        iovec = IOVEC_MAKE_STRING(test);
        assert_se(journal_file_append_entry(f->file, &ts, NULL, &iovec, 1, NULL, NULL, NULL) == 0);

        iovec = IOVEC_MAKE_STRING(test2);
        assert_se(journal_file_append_entry(f->file, &ts, NULL, &iovec, 1, NULL, NULL, NULL) == 0);

        iovec = IOVEC_MAKE_STRING(test);
        assert_se(journal_file_append_entry(f->file, &ts, &fake_boot_id, &iovec, 1, NULL, NULL, NULL) == 0);

#if HAVE_GCRYPT
        journal_file_append_tag(f->file);
#endif
        journal_file_dump(f->file);

        assert_se(journal_file_next_entry(f->file, 0, DIRECTION_DOWN, &o, &p) == 1);
        assert_se(le64toh(o->entry.seqnum) == 1);

        assert_se(journal_file_next_entry(f->file, p, DIRECTION_DOWN, &o, &p) == 1);
        assert_se(le64toh(o->entry.seqnum) == 2);

        assert_se(journal_file_next_entry(f->file, p, DIRECTION_DOWN, &o, &p) == 1);
        assert_se(le64toh(o->entry.seqnum) == 3);
        assert_se(sd_id128_equal(o->entry.boot_id, fake_boot_id));

        assert_se(journal_file_next_entry(f->file, p, DIRECTION_DOWN, &o, &p) == 0);

        assert_se(journal_file_next_entry(f->file, 0, DIRECTION_DOWN, &o, &p) == 1);
        assert_se(le64toh(o->entry.seqnum) == 1);

        assert_se(journal_file_find_data_object(f->file, test, strlen(test), &d, NULL) == 1);
        assert_se(journal_file_next_entry_for_data(f->file, d, DIRECTION_DOWN, &o, NULL) == 1);
        assert_se(le64toh(o->entry.seqnum) == 1);

        assert_se(journal_file_next_entry_for_data(f->file, d, DIRECTION_UP, &o, NULL) == 1);
        assert_se(le64toh(o->entry.seqnum) == 3);

        assert_se(journal_file_find_data_object(f->file, test2, strlen(test2), &d, NULL) == 1);
        assert_se(journal_file_next_entry_for_data(f->file, d, DIRECTION_UP, &o, NULL) == 1);
        assert_se(le64toh(o->entry.seqnum) == 2);

        assert_se(journal_file_next_entry_for_data(f->file, d, DIRECTION_DOWN, &o, NULL) == 1);
        assert_se(le64toh(o->entry.seqnum) == 2);

        assert_se(journal_file_find_data_object(f->file, "quux", 4, &d, NULL) == 0);

        assert_se(journal_file_move_to_entry_by_seqnum(f->file, 1, DIRECTION_DOWN, &o, NULL) == 1);
        assert_se(le64toh(o->entry.seqnum) == 1);

        assert_se(journal_file_move_to_entry_by_seqnum(f->file, 3, DIRECTION_DOWN, &o, NULL) == 1);
        assert_se(le64toh(o->entry.seqnum) == 3);

        assert_se(journal_file_move_to_entry_by_seqnum(f->file, 2, DIRECTION_DOWN, &o, NULL) == 1);
        assert_se(le64toh(o->entry.seqnum) == 2);

        assert_se(journal_file_move_to_entry_by_seqnum(f->file, 10, DIRECTION_DOWN, &o, NULL) == 0);

        managed_journal_file_rotate(&f, m, JOURNAL_SEAL|JOURNAL_COMPRESS, UINT64_MAX, NULL);
        managed_journal_file_rotate(&f, m, JOURNAL_SEAL|JOURNAL_COMPRESS, UINT64_MAX, NULL);

        (void) managed_journal_file_close(f);

        log_info("Done...");

        if (arg_keep)
                log_info("Not removing %s", t);
        else {
                journal_directory_vacuum(".", 3000000, 0, 0, NULL, true);

                assert_se(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
        }

        puts("------------------------------------------------------------");
}

TEST(non_empty) {
        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1) >= 0);
        test_non_empty_one();

        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1) >= 0);
        test_non_empty_one();
}

static void test_empty_one(void) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        ManagedJournalFile *f1, *f2, *f3, *f4;
        char t[] = "/var/tmp/journal-XXXXXX";

        m = mmap_cache_new();
        assert_se(m != NULL);

        mkdtemp_chdir_chattr(t);

        assert_se(managed_journal_file_open(-1, "test.journal", O_RDWR|O_CREAT, 0, 0666, UINT64_MAX, NULL, m, NULL, NULL, &f1) == 0);
        assert_se(managed_journal_file_open(-1, "test-compress.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0666, UINT64_MAX, NULL, m, NULL, NULL, &f2) == 0);
        assert_se(managed_journal_file_open(-1, "test-seal.journal", O_RDWR|O_CREAT, JOURNAL_SEAL, 0666, UINT64_MAX, NULL, m, NULL, NULL, &f3) == 0);
        assert_se(managed_journal_file_open(-1, "test-seal-compress.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS|JOURNAL_SEAL, 0666, UINT64_MAX, NULL, m, NULL, NULL, &f4) == 0);

        journal_file_print_header(f1->file);
        puts("");
        journal_file_print_header(f2->file);
        puts("");
        journal_file_print_header(f3->file);
        puts("");
        journal_file_print_header(f4->file);
        puts("");

        log_info("Done...");

        if (arg_keep)
                log_info("Not removing %s", t);
        else {
                journal_directory_vacuum(".", 3000000, 0, 0, NULL, true);

                assert_se(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
        }

        (void) managed_journal_file_close(f1);
        (void) managed_journal_file_close(f2);
        (void) managed_journal_file_close(f3);
        (void) managed_journal_file_close(f4);
}

TEST(empty) {
        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1) >= 0);
        test_empty_one();

        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1) >= 0);
        test_empty_one();
}

#if HAVE_COMPRESSION
static bool check_compressed(uint64_t compress_threshold, uint64_t data_size) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        dual_timestamp ts;
        ManagedJournalFile *f;
        struct iovec iovec;
        Object *o;
        uint64_t p;
        char t[] = "/var/tmp/journal-XXXXXX";
        char data[2048] = "FIELD=";
        bool is_compressed;
        int r;

        assert_se(data_size <= sizeof(data));

        m = mmap_cache_new();
        assert_se(m != NULL);

        mkdtemp_chdir_chattr(t);

        assert_se(managed_journal_file_open(-1, "test.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS|JOURNAL_SEAL, 0666, compress_threshold, NULL, m, NULL, NULL, &f) == 0);

        dual_timestamp_get(&ts);

        iovec = IOVEC_MAKE(data, data_size);
        assert_se(journal_file_append_entry(f->file, &ts, NULL, &iovec, 1, NULL, NULL, NULL) == 0);

#if HAVE_GCRYPT
        journal_file_append_tag(f->file);
#endif
        journal_file_dump(f->file);

        /* We have to partially reimplement some of the dump logic, because the normal next_entry does the
         * decompression for us. */
        p = le64toh(f->file->header->header_size);
        for (;;) {
                r = journal_file_move_to_object(f->file, OBJECT_UNUSED, p, &o);
                assert_se(r == 0);
                if (o->object.type == OBJECT_DATA)
                        break;

                assert_se(p < le64toh(f->file->header->tail_object_offset));
                p = p + ALIGN64(le64toh(o->object.size));
        }

        is_compressed = COMPRESSION_FROM_OBJECT(o) != COMPRESSION_NONE;

        (void) managed_journal_file_close(f);

        log_info("Done...");

        if (arg_keep)
                log_info("Not removing %s", t);
        else {
                journal_directory_vacuum(".", 3000000, 0, 0, NULL, true);

                assert_se(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
        }

        puts("------------------------------------------------------------");

        return is_compressed;
}

static void test_min_compress_size_one(void) {
        /* Note that XZ will actually fail to compress anything under 80 bytes, so you have to choose the limits
         * carefully */

        /* DEFAULT_MIN_COMPRESS_SIZE is 512 */
        assert_se(!check_compressed(UINT64_MAX, 255));
        assert_se(check_compressed(UINT64_MAX, 513));

        /* compress everything */
        assert_se(check_compressed(0, 96));
        assert_se(check_compressed(8, 96));

        /* Ensure we don't try to compress less than 8 bytes */
        assert_se(!check_compressed(0, 7));

        /* check boundary conditions */
        assert_se(check_compressed(256, 256));
        assert_se(!check_compressed(256, 255));
}

TEST(min_compress_size) {
        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1) >= 0);
        test_min_compress_size_one();

        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1) >= 0);
        test_min_compress_size_one();
}
#endif

static int intro(void) {
        arg_keep = saved_argc > 1;

        /* managed_journal_file_open requires a valid machine id */
        if (access("/etc/machine-id", F_OK) != 0)
                return log_tests_skipped("/etc/machine-id not found");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
