/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "argv-util.h"
#include "chattr-util.h"
#include "iovec-util.h"
#include "journal-authenticate.h"
#include "journal-file-util.h"
#include "journal-vacuum.h"
#include "log.h"
#include "rm-rf.h"
#include "tests.h"
#include "time-util.h"

static bool arg_keep = false;

static void mkdtemp_chdir_chattr(char *path) {
        ASSERT_NOT_NULL(mkdtemp(path));
        ASSERT_OK_ERRNO(chdir(path));

        /* Speed up things a bit on btrfs, ensuring that CoW is turned off for all files created in our
         * directory during the test run */
        (void) chattr_path(path, FS_NOCOW_FL, FS_NOCOW_FL);
}

static void test_non_empty_one(void) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        dual_timestamp ts;
        JournalFile *f;
        struct iovec iovec;
        static const char test[] = "TEST1=1", test2[] = "TEST2=2";
        Object *o, *d;
        uint64_t p;
        sd_id128_t fake_boot_id;
        char t[] = "/var/tmp/journal-XXXXXX";

        ASSERT_NOT_NULL(m = mmap_cache_new());

        mkdtemp_chdir_chattr(t);

        ASSERT_OK_ZERO(journal_file_open(-EBADF, "test.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS|JOURNAL_SEAL, 0666, UINT64_MAX, NULL, m, NULL, &f));

        ASSERT_NOT_NULL(dual_timestamp_now(&ts));
        ASSERT_OK_ZERO(sd_id128_randomize(&fake_boot_id));

        iovec = IOVEC_MAKE_STRING(test);
        ASSERT_OK_ZERO(journal_file_append_entry(f, &ts, NULL, &iovec, 1, NULL, NULL, NULL, NULL));

        iovec = IOVEC_MAKE_STRING(test2);
        ASSERT_OK_ZERO(journal_file_append_entry(f, &ts, NULL, &iovec, 1, NULL, NULL, NULL, NULL));

        iovec = IOVEC_MAKE_STRING(test);
        ASSERT_OK_ZERO(journal_file_append_entry(f, &ts, &fake_boot_id, &iovec, 1, NULL, NULL, NULL, NULL));

#if HAVE_GCRYPT
        journal_file_append_tag(f);
#endif
        journal_file_dump(f);

        ASSERT_EQ(journal_file_next_entry(f, 0, DIRECTION_DOWN, &o, &p), 1);
        ASSERT_EQ(le64toh(o->entry.seqnum), UINT64_C(1));

        ASSERT_EQ(journal_file_next_entry(f, p, DIRECTION_DOWN, &o, &p), 1);
        ASSERT_EQ(le64toh(o->entry.seqnum), UINT64_C(2));

        ASSERT_EQ(journal_file_next_entry(f, p, DIRECTION_DOWN, &o, &p), 1);
        ASSERT_EQ(le64toh(o->entry.seqnum), UINT64_C(3));
        ASSERT_EQ_ID128(o->entry.boot_id, fake_boot_id);

        ASSERT_OK_ZERO(journal_file_next_entry(f, p, DIRECTION_DOWN, &o, &p));

        ASSERT_EQ(journal_file_next_entry(f, 0, DIRECTION_DOWN, &o, &p), 1);
        ASSERT_EQ(le64toh(o->entry.seqnum), UINT64_C(1));

        ASSERT_EQ(journal_file_find_data_object(f, test, strlen(test), &d, NULL), 1);
        ASSERT_EQ(journal_file_move_to_entry_for_data(f, d, DIRECTION_DOWN, &o, NULL), 1);
        ASSERT_EQ(le64toh(o->entry.seqnum), UINT64_C(1));

        ASSERT_EQ(journal_file_move_to_entry_for_data(f, d, DIRECTION_UP, &o, NULL), 1);
        ASSERT_EQ(le64toh(o->entry.seqnum), UINT64_C(3));

        ASSERT_EQ(journal_file_find_data_object(f, test2, strlen(test2), &d, NULL), 1);
        ASSERT_EQ(journal_file_move_to_entry_for_data(f, d, DIRECTION_UP, &o, NULL), 1);
        ASSERT_EQ(le64toh(o->entry.seqnum), UINT64_C(2));

        ASSERT_EQ(journal_file_move_to_entry_for_data(f, d, DIRECTION_DOWN, &o, NULL), 1);
        ASSERT_EQ(le64toh(o->entry.seqnum), UINT64_C(2));

        ASSERT_OK_ZERO(journal_file_find_data_object(f, "quux", 4, &d, NULL));

        ASSERT_EQ(journal_file_move_to_entry_by_seqnum(f, 1, DIRECTION_DOWN, &o, NULL), 1);
        ASSERT_EQ(le64toh(o->entry.seqnum), UINT64_C(1));

        ASSERT_EQ(journal_file_move_to_entry_by_seqnum(f, 3, DIRECTION_DOWN, &o, NULL), 1);
        ASSERT_EQ(le64toh(o->entry.seqnum), UINT64_C(3));

        ASSERT_EQ(journal_file_move_to_entry_by_seqnum(f, 2, DIRECTION_DOWN, &o, NULL), 1);
        ASSERT_EQ(le64toh(o->entry.seqnum), UINT64_C(2));

        ASSERT_OK_ZERO(journal_file_move_to_entry_by_seqnum(f, 10, DIRECTION_DOWN, &o, NULL));

        journal_file_rotate(&f, m, JOURNAL_SEAL|JOURNAL_COMPRESS, UINT64_MAX, NULL);
        journal_file_rotate(&f, m, JOURNAL_SEAL|JOURNAL_COMPRESS, UINT64_MAX, NULL);

        (void) journal_file_offline_close(f);

        log_info("Done...");

        if (arg_keep)
                log_info("Not removing %s", t);
        else {
                journal_directory_vacuum(".", 3000000, 0, 0, NULL, true);

                ASSERT_OK(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL));
        }

        puts("------------------------------------------------------------");
}

TEST(non_empty) {
        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1));
        test_non_empty_one();

        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1));
        test_non_empty_one();
}

static void test_empty_one(void) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        JournalFile *f1, *f2, *f3, *f4;
        char t[] = "/var/tmp/journal-XXXXXX";

        ASSERT_NOT_NULL(m = mmap_cache_new());

        mkdtemp_chdir_chattr(t);

        ASSERT_OK_ZERO(journal_file_open(-EBADF, "test.journal", O_RDWR|O_CREAT, 0, 0666, UINT64_MAX, NULL, m, NULL, &f1));
        ASSERT_OK_ZERO(journal_file_open(-EBADF, "test-compress.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0666, UINT64_MAX, NULL, m, NULL, &f2));
        ASSERT_OK_ZERO(journal_file_open(-EBADF, "test-seal.journal", O_RDWR|O_CREAT, JOURNAL_SEAL, 0666, UINT64_MAX, NULL, m, NULL, &f3));
        ASSERT_OK_ZERO(journal_file_open(-EBADF, "test-seal-compress.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS|JOURNAL_SEAL, 0666, UINT64_MAX, NULL, m, NULL, &f4));

        journal_file_print_header(f1);
        puts("");
        journal_file_print_header(f2);
        puts("");
        journal_file_print_header(f3);
        puts("");
        journal_file_print_header(f4);
        puts("");

        log_info("Done...");

        if (arg_keep)
                log_info("Not removing %s", t);
        else {
                journal_directory_vacuum(".", 3000000, 0, 0, NULL, true);

                ASSERT_OK(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL));
        }

        (void) journal_file_offline_close(f1);
        (void) journal_file_offline_close(f2);
        (void) journal_file_offline_close(f3);
        (void) journal_file_offline_close(f4);
}

TEST(empty) {
        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1));
        test_empty_one();

        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1));
        test_empty_one();
}

#if HAVE_COMPRESSION
static bool check_compressed(uint64_t compress_threshold, uint64_t data_size) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        dual_timestamp ts;
        JournalFile *f;
        struct iovec iovec;
        Object *o;
        uint64_t p;
        char t[] = "/var/tmp/journal-XXXXXX";
        char data[2048] = "FIELD=";
        bool is_compressed;

        ASSERT_LE(data_size, sizeof(data));

        ASSERT_NOT_NULL(m = mmap_cache_new());

        mkdtemp_chdir_chattr(t);

        ASSERT_OK_ZERO(journal_file_open(-EBADF, "test.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS|JOURNAL_SEAL, 0666, compress_threshold, NULL, m, NULL, &f));

        dual_timestamp_now(&ts);

        iovec = IOVEC_MAKE(data, data_size);
        ASSERT_OK_ZERO(journal_file_append_entry(f, &ts, NULL, &iovec, 1, NULL, NULL, NULL, NULL));

#if HAVE_GCRYPT
        journal_file_append_tag(f);
#endif
        journal_file_dump(f);

        /* We have to partially reimplement some of the dump logic, because the normal next_entry does the
         * decompression for us. */
        p = le64toh(f->header->header_size);
        for (;;) {
                ASSERT_OK_ZERO(journal_file_move_to_object(f, OBJECT_UNUSED, p, &o));
                if (o->object.type == OBJECT_DATA)
                        break;

                ASSERT_LT(p, le64toh(f->header->tail_object_offset));
                p = p + ALIGN64(le64toh(o->object.size));
        }

        is_compressed = COMPRESSION_FROM_OBJECT(o) != COMPRESSION_NONE;

        (void) journal_file_offline_close(f);

        log_info("Done...");

        if (arg_keep)
                log_info("Not removing %s", t);
        else {
                journal_directory_vacuum(".", 3000000, 0, 0, NULL, true);

                ASSERT_OK(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL));
        }

        puts("------------------------------------------------------------");

        return is_compressed;
}

static void test_min_compress_size_one(void) {
        /* Note that XZ will actually fail to compress anything under 80 bytes, so you have to choose the limits
         * carefully */

        /* DEFAULT_MIN_COMPRESS_SIZE is 512 */
        ASSERT_FALSE(check_compressed(UINT64_MAX, 255));
        ASSERT_TRUE(check_compressed(UINT64_MAX, 513));

        /* compress everything */
        ASSERT_TRUE(check_compressed(0, 96));
        ASSERT_TRUE(check_compressed(8, 96));

        /* Ensure we don't try to compress less than 8 bytes */
        ASSERT_FALSE(check_compressed(0, 7));

        /* check boundary conditions */
        ASSERT_TRUE(check_compressed(256, 256));
        ASSERT_FALSE(check_compressed(256, 255));
}

TEST(min_compress_size) {
        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1));
        test_min_compress_size_one();

        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1));
        test_min_compress_size_one();
}
#endif

static int intro(void) {
        arg_keep = saved_argc > 1;

        /* journal_file_open() requires a valid machine id */
        if (access("/etc/machine-id", F_OK) != 0)
                return log_tests_skipped("/etc/machine-id not found");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
