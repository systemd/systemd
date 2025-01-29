/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-id128.h"
#include "sd-journal.h"

#include "alloc-util.h"
#include "chattr-util.h"
#include "iovec-util.h"
#include "journal-file-util.h"
#include "journal-vacuum.h"
#include "log.h"
#include "logs-show.h"
#include "parse-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "tmpfile-util.h"
#include "tests.h"

/* This program tests skipping around in a multi-file journal. */

static bool arg_keep = false;
static dual_timestamp previous_ts = {};

static JournalFile* test_open_internal(const char *name, JournalFileFlags flags) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        JournalFile *f;

        ASSERT_NOT_NULL(m = mmap_cache_new());
        ASSERT_OK(journal_file_open(-EBADF, name, O_RDWR|O_CREAT, flags, 0644, UINT64_MAX, NULL, m, NULL, &f));
        return f;
}

static JournalFile* test_open(const char *name) {
        return test_open_internal(name, JOURNAL_COMPRESS);
}

static JournalFile* test_open_strict(const char *name) {
        return test_open_internal(name, JOURNAL_COMPRESS | JOURNAL_STRICT_ORDER);
}

static char* test_done(char *t) {
        if (!t)
                return NULL;

        log_info("Done...");

        if (arg_keep)
                log_info("Not removing %s", t);
        else {
                journal_directory_vacuum(".", 3000000, 0, 0, NULL, true);

                ASSERT_OK(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL));
        }

        log_info("------------------------------------------------------------");
        return mfree(t);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(char*, test_done);

static void append_number(JournalFile *f, unsigned n, const sd_id128_t *boot_id, uint64_t *seqnum, uint64_t *ret_offset) {
        _cleanup_free_ char *p = NULL, *q = NULL, *s = NULL;
        dual_timestamp ts;
        struct iovec iovec[3];
        size_t n_iov = 0;

        dual_timestamp_now(&ts);

        if (ts.monotonic <= previous_ts.monotonic)
                ts.monotonic = previous_ts.monotonic + 1;

        if (ts.realtime <= previous_ts.realtime)
                ts.realtime = previous_ts.realtime + 1;

        previous_ts = ts;

        ASSERT_OK(asprintf(&p, "NUMBER=%u", n));
        iovec[n_iov++] = IOVEC_MAKE_STRING(p);

        ASSERT_NOT_NULL(s = strjoin("LESS_THAN_FIVE=", yes_no(n < 5)));
        iovec[n_iov++] = IOVEC_MAKE_STRING(s);

        if (boot_id) {
                ASSERT_NOT_NULL(q = strjoin("_BOOT_ID=", SD_ID128_TO_STRING(*boot_id)));
                iovec[n_iov++] = IOVEC_MAKE_STRING(q);
        }

        ASSERT_OK(journal_file_append_entry(f, &ts, boot_id, iovec, n_iov, seqnum, NULL, NULL, ret_offset));
}

static void append_unreferenced_data(JournalFile *f, const sd_id128_t *boot_id) {
        _cleanup_free_ char *q = NULL;
        dual_timestamp ts;
        struct iovec iovec;

        assert(boot_id);

        ts.monotonic = usec_sub_unsigned(previous_ts.monotonic, 10);
        ts.realtime = usec_sub_unsigned(previous_ts.realtime, 10);

        ASSERT_NOT_NULL(q = strjoin("_BOOT_ID=", SD_ID128_TO_STRING(*boot_id)));
        iovec = IOVEC_MAKE_STRING(q);

        ASSERT_ERROR(journal_file_append_entry(f, &ts, boot_id, &iovec, 1, NULL, NULL, NULL, NULL), EREMCHG);
}

static void test_check_number(sd_journal *j, unsigned expected) {
        sd_id128_t boot_id;
        const void *d;
        size_t l;

        ASSERT_OK(sd_journal_get_monotonic_usec(j, NULL, &boot_id));
        ASSERT_OK(sd_journal_get_data(j, "NUMBER", &d, &l));

        _cleanup_free_ char *k = NULL;
        ASSERT_NOT_NULL(k = strndup(d, l));
        printf("%s %s (expected=%u)\n", SD_ID128_TO_STRING(boot_id), k, expected);

        unsigned x;
        ASSERT_OK(safe_atou(k + STRLEN("NUMBER="), &x));
        ASSERT_EQ(x, expected);
}

static void test_check_numbers_down(sd_journal *j, unsigned count) {
        for (unsigned i = 1; i <= count; i++) {
                test_check_number(j, i);
                if (i == count)
                        ASSERT_OK_ZERO(sd_journal_next(j));
                else
                        ASSERT_OK_POSITIVE(sd_journal_next(j));
        }
}

static void test_check_numbers_up(sd_journal *j, unsigned count) {
        for (unsigned i = count; i >= 1; i--) {
                test_check_number(j, i);
                if (i == 1)
                        ASSERT_OK_ZERO(sd_journal_previous(j));
                else
                        ASSERT_OK_POSITIVE(sd_journal_previous(j));
        }
}

static void setup_sequential(void) {
        _cleanup_(journal_file_offline_closep) JournalFile *f1 = NULL, *f2 = NULL, *f3 = NULL;
        sd_id128_t id;

        f1 = test_open("one.journal");
        f2 = test_open("two.journal");
        f3 = test_open("three.journal");
        ASSERT_OK(sd_id128_randomize(&id));
        log_info("boot_id: %s", SD_ID128_TO_STRING(id));
        append_number(f1, 1, &id, NULL, NULL);
        append_number(f1, 2, &id, NULL, NULL);
        append_number(f1, 3, &id, NULL, NULL);
        append_number(f2, 4, &id, NULL, NULL);
        ASSERT_OK(sd_id128_randomize(&id));
        log_info("boot_id: %s", SD_ID128_TO_STRING(id));
        append_number(f2, 5, &id, NULL, NULL);
        append_number(f2, 6, &id, NULL, NULL);
        append_number(f3, 7, &id, NULL, NULL);
        append_number(f3, 8, &id, NULL, NULL);
        ASSERT_OK(sd_id128_randomize(&id));
        log_info("boot_id: %s", SD_ID128_TO_STRING(id));
        append_number(f3, 9, &id, NULL, NULL);
}

static void setup_interleaved(void) {
        _cleanup_(journal_file_offline_closep) JournalFile *f1 = NULL, *f2 = NULL, *f3 = NULL;
        sd_id128_t id;

        f1 = test_open("one.journal");
        f2 = test_open("two.journal");
        f3 = test_open("three.journal");
        ASSERT_OK(sd_id128_randomize(&id));
        log_info("boot_id: %s", SD_ID128_TO_STRING(id));
        append_number(f1, 1, &id, NULL, NULL);
        append_number(f2, 2, &id, NULL, NULL);
        append_number(f3, 3, &id, NULL, NULL);
        append_number(f1, 4, &id, NULL, NULL);
        append_number(f2, 5, &id, NULL, NULL);
        append_number(f3, 6, &id, NULL, NULL);
        append_number(f1, 7, &id, NULL, NULL);
        append_number(f2, 8, &id, NULL, NULL);
        append_number(f3, 9, &id, NULL, NULL);
}

static void setup_unreferenced_data(void) {
        _cleanup_(journal_file_offline_closep) JournalFile *f1 = NULL, *f2 = NULL, *f3 = NULL;
        sd_id128_t id;

        /* For issue #29275. */

        f1 = test_open_strict("one.journal");
        f2 = test_open_strict("two.journal");
        f3 = test_open_strict("three.journal");
        ASSERT_OK(sd_id128_randomize(&id));
        log_info("boot_id: %s", SD_ID128_TO_STRING(id));
        append_number(f1, 1, &id, NULL, NULL);
        append_number(f1, 2, &id, NULL, NULL);
        append_number(f1, 3, &id, NULL, NULL);
        ASSERT_OK(sd_id128_randomize(&id));
        log_info("boot_id: %s", SD_ID128_TO_STRING(id));
        append_unreferenced_data(f1, &id);
        append_number(f2, 4, &id, NULL, NULL);
        append_number(f2, 5, &id, NULL, NULL);
        append_number(f2, 6, &id, NULL, NULL);
        ASSERT_OK(sd_id128_randomize(&id));
        log_info("boot_id: %s", SD_ID128_TO_STRING(id));
        append_unreferenced_data(f2, &id);
        append_number(f3, 7, &id, NULL, NULL);
        append_number(f3, 8, &id, NULL, NULL);
        append_number(f3, 9, &id, NULL, NULL);
}

static void mkdtemp_chdir_chattr(const char *template, char **ret) {
        _cleanup_(rm_rf_physical_and_freep) char *path = NULL;

        ASSERT_OK(mkdtemp_malloc(template, &path));
        ASSERT_OK_ERRNO(chdir(path));

        /* Speed up things a bit on btrfs, ensuring that CoW is turned off for all files created in our
         * directory during the test run */
        (void) chattr_path(path, FS_NOCOW_FL, FS_NOCOW_FL, NULL);

        *ret = TAKE_PTR(path);
}

static void test_cursor(sd_journal *j) {
        _cleanup_strv_free_ char **cursors = NULL;
        int r;

        ASSERT_OK(sd_journal_seek_head(j));

        for (;;) {
                ASSERT_OK(r = sd_journal_next(j));
                if (r == 0)
                        break;

                _cleanup_free_ char *cursor = NULL;
                ASSERT_OK(sd_journal_get_cursor(j, &cursor));
                ASSERT_OK_POSITIVE(sd_journal_test_cursor(j, cursor));
                ASSERT_OK(strv_consume(&cursors, TAKE_PTR(cursor)));
        }

        STRV_FOREACH(c, cursors) {
                ASSERT_OK(sd_journal_seek_cursor(j, *c));
                ASSERT_OK(sd_journal_next(j));
                ASSERT_OK_POSITIVE(sd_journal_test_cursor(j, *c));
        }

        ASSERT_OK(sd_journal_seek_head(j));
        STRV_FOREACH(c, cursors) {
                ASSERT_OK(sd_journal_next(j));
                ASSERT_OK_POSITIVE(sd_journal_test_cursor(j, *c));
        }
}

static void test_skip_one(void (*setup)(void)) {
        _cleanup_(test_donep) char *t = NULL;
        sd_journal *j;

        mkdtemp_chdir_chattr("/var/tmp/journal-skip-XXXXXX", &t);

        setup();

        /* Seek to head, iterate down. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_seek_head(j));
        ASSERT_OK_POSITIVE(sd_journal_next(j));       /* pointing to the first entry */
        test_check_numbers_down(j, 9);
        sd_journal_close(j);

        /* Seek to head, iterate down. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_seek_head(j));
        ASSERT_OK_POSITIVE(sd_journal_next(j));       /* pointing to the first entry */
        ASSERT_OK_ZERO(sd_journal_previous(j));       /* no-op */
        test_check_numbers_down(j, 9);
        sd_journal_close(j);

        /* Seek to head twice, iterate down. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_seek_head(j));
        ASSERT_OK_POSITIVE(sd_journal_next(j));       /* pointing to the first entry */
        ASSERT_OK(sd_journal_seek_head(j));
        ASSERT_OK_POSITIVE(sd_journal_next(j));       /* pointing to the first entry */
        test_check_numbers_down(j, 9);
        sd_journal_close(j);

        /* Seek to head, move to previous, then iterate down. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_seek_head(j));
        ASSERT_OK_ZERO(sd_journal_previous(j));       /* no-op */
        ASSERT_OK_POSITIVE(sd_journal_next(j));       /* pointing to the first entry */
        test_check_numbers_down(j, 9);
        sd_journal_close(j);

        /* Seek to head, walk several steps, then iterate down. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_seek_head(j));
        ASSERT_OK_ZERO(sd_journal_previous(j));       /* no-op */
        ASSERT_OK_ZERO(sd_journal_previous(j));       /* no-op */
        ASSERT_OK_ZERO(sd_journal_previous(j));       /* no-op */
        ASSERT_OK_POSITIVE(sd_journal_next(j));       /* pointing to the first entry */
        ASSERT_OK_ZERO(sd_journal_previous(j));       /* no-op */
        ASSERT_OK_ZERO(sd_journal_previous(j));       /* no-op */
        test_check_numbers_down(j, 9);
        sd_journal_close(j);

        /* Seek to tail, iterate up. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_seek_tail(j));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));   /* pointing to the last entry */
        test_check_numbers_up(j, 9);
        sd_journal_close(j);

        /* Seek to tail twice, iterate up. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_seek_tail(j));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));   /* pointing to the last entry */
        ASSERT_OK(sd_journal_seek_tail(j));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));   /* pointing to the last entry */
        test_check_numbers_up(j, 9);
        sd_journal_close(j);

        /* Seek to tail, move to next, then iterate up. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_seek_tail(j));
        ASSERT_OK_ZERO(sd_journal_next(j));           /* no-op */
        ASSERT_OK_POSITIVE(sd_journal_previous(j));   /* pointing to the last entry */
        test_check_numbers_up(j, 9);
        sd_journal_close(j);

        /* Seek to tail, walk several steps, then iterate up. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_seek_tail(j));
        ASSERT_OK_ZERO(sd_journal_next(j));           /* no-op */
        ASSERT_OK_ZERO(sd_journal_next(j));           /* no-op */
        ASSERT_OK_ZERO(sd_journal_next(j));           /* no-op */
        ASSERT_OK_POSITIVE(sd_journal_previous(j));   /* pointing to the last entry. */
        ASSERT_OK_ZERO(sd_journal_next(j));           /* no-op */
        ASSERT_OK_ZERO(sd_journal_next(j));           /* no-op */
        test_check_numbers_up(j, 9);
        sd_journal_close(j);

        /* Seek to tail, skip to head, iterate down. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_seek_tail(j));
        ASSERT_EQ(sd_journal_previous_skip(j, 9), 9); /* pointing to the first entry. */
        test_check_numbers_down(j, 9);
        sd_journal_close(j);

        /* Seek to tail, skip to head in a more complex way, then iterate down. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_seek_tail(j));
        ASSERT_OK_ZERO(sd_journal_next(j));
        ASSERT_EQ(sd_journal_previous_skip(j, 4), 4);
        ASSERT_EQ(sd_journal_previous_skip(j, 5), 5);
        ASSERT_OK_ZERO(sd_journal_previous(j));
        ASSERT_OK_ZERO(sd_journal_previous_skip(j, 5));
        ASSERT_OK_POSITIVE(sd_journal_next(j));
        ASSERT_OK_POSITIVE(sd_journal_previous_skip(j, 5));
        ASSERT_OK_POSITIVE(sd_journal_next(j));
        ASSERT_OK_POSITIVE(sd_journal_next(j));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));
        ASSERT_OK_POSITIVE(sd_journal_next(j));
        ASSERT_OK_POSITIVE(sd_journal_next(j));
        ASSERT_EQ(sd_journal_previous_skip(j, 5), 3);
        test_check_numbers_down(j, 9);
        sd_journal_close(j);

        /* Seek to head, skip to tail, iterate up. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_seek_head(j));
        ASSERT_EQ(sd_journal_next_skip(j, 9), 9);
        test_check_numbers_up(j, 9);
        sd_journal_close(j);

        /* Seek to head, skip to tail in a more complex way, then iterate up. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_seek_head(j));
        ASSERT_OK_ZERO(sd_journal_previous(j));
        ASSERT_EQ(sd_journal_next_skip(j, 4), 4);
        ASSERT_EQ(sd_journal_next_skip(j, 5), 5);
        ASSERT_OK_ZERO(sd_journal_next(j));
        ASSERT_OK_ZERO(sd_journal_next_skip(j, 5));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));
        ASSERT_OK_POSITIVE(sd_journal_next_skip(j, 5));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));
        ASSERT_OK_POSITIVE(sd_journal_next(j));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));
        ASSERT_EQ(sd_journal_next_skip(j, 5), 3);
        test_check_numbers_up(j, 9);
        sd_journal_close(j);

        /* For issue #31516. */
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        test_cursor(j);
        sd_journal_flush_matches(j);
        ASSERT_OK(sd_journal_add_match(j, "LESS_THAN_FIVE=yes", SIZE_MAX));
        test_cursor(j);
        sd_journal_flush_matches(j);
        ASSERT_OK(sd_journal_add_match(j, "LESS_THAN_FIVE=no", SIZE_MAX));
        test_cursor(j);
        sd_journal_flush_matches(j);
        ASSERT_OK(sd_journal_add_match(j, "LESS_THAN_FIVE=hoge", SIZE_MAX));
        test_cursor(j);
        sd_journal_flush_matches(j);
        ASSERT_OK(sd_journal_add_match(j, "LESS_THAN_FIVE=yes", SIZE_MAX));
        ASSERT_OK(sd_journal_add_match(j, "NUMBER=3", SIZE_MAX));
        test_cursor(j);
        sd_journal_flush_matches(j);
        ASSERT_OK(sd_journal_add_match(j, "LESS_THAN_FIVE=yes", SIZE_MAX));
        ASSERT_OK(sd_journal_add_match(j, "NUMBER=3", SIZE_MAX));
        ASSERT_OK(sd_journal_add_match(j, "NUMBER=4", SIZE_MAX));
        ASSERT_OK(sd_journal_add_match(j, "NUMBER=5", SIZE_MAX));
        ASSERT_OK(sd_journal_add_match(j, "NUMBER=6", SIZE_MAX));
        test_cursor(j);
        sd_journal_close(j);
}

TEST(skip) {
        test_skip_one(setup_sequential);
        test_skip_one(setup_interleaved);
}

static void test_boot_id_one(void (*setup)(void), size_t n_ids_expected) {
        _cleanup_(test_donep) char *t = NULL;
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_free_ LogId *ids = NULL;
        size_t n_ids;

        mkdtemp_chdir_chattr("/var/tmp/journal-boot-id-XXXXXX", &t);

        setup();

        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(journal_get_boots(
                                j,
                                /* advance_older = */ false, /* max_ids = */ SIZE_MAX,
                                &ids, &n_ids));
        ASSERT_NOT_NULL(ids);
        ASSERT_EQ(n_ids, n_ids_expected);

        for (size_t i = 0; i < n_ids; i++) {
                sd_id128_t id;

                /* positive offset */
                ASSERT_OK_POSITIVE(journal_find_boot(j, SD_ID128_NULL, (int) (i + 1), &id));
                ASSERT_EQ_ID128(id, ids[i].id);

                /* negative offset */
                ASSERT_OK_POSITIVE(journal_find_boot(j, SD_ID128_NULL, (int) (i + 1) - (int) n_ids, &id));
                ASSERT_EQ_ID128(id, ids[i].id);

                for (size_t k = 0; k < n_ids; k++) {
                        int offset = (int) k - (int) i;

                        /* relative offset */
                        ASSERT_OK_POSITIVE(journal_find_boot(j, ids[i].id, offset, &id));
                        ASSERT_EQ_ID128(id, ids[k].id);
                }
        }

        for (size_t i = 0; i <= n_ids_expected + 1; i++) {
                _cleanup_free_ LogId *ids_limited = NULL;
                size_t n_ids_limited;

                ASSERT_OK(journal_get_boots(
                                        j,
                                        /* advance_older = */ false, /* max_ids = */ i,
                                        &ids_limited, &n_ids_limited));
                ASSERT_TRUE(ids_limited || i == 0);
                ASSERT_EQ(n_ids_limited, MIN(i, n_ids_expected));
                ASSERT_EQ(memcmp_safe(ids, ids_limited, n_ids_limited * sizeof(LogId)), 0);
        }

        for (size_t i = 0; i <= n_ids_expected + 1; i++) {
                _cleanup_free_ LogId *ids_limited = NULL;
                size_t n_ids_limited;

                ASSERT_OK(journal_get_boots(
                                        j,
                                        /* advance_older = */ true, /* max_ids = */ i,
                                        &ids_limited, &n_ids_limited));
                ASSERT_TRUE(ids_limited || i == 0);
                ASSERT_EQ(n_ids_limited, MIN(i, n_ids_expected));
                for (size_t k = 0; k < n_ids_limited; k++)
                        ASSERT_EQ(memcmp(&ids[n_ids - k - 1], &ids_limited[k], sizeof(LogId)), 0);
        }
}

TEST(boot_id) {
        test_boot_id_one(setup_sequential, 3);
        test_boot_id_one(setup_unreferenced_data, 3);
}

static void test_sequence_numbers_one(void) {
        _cleanup_(test_donep) char *t = NULL;
        _cleanup_(journal_file_offline_closep) JournalFile *one = NULL, *two = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        uint64_t seqnum = 0;
        sd_id128_t seqnum_id;

        ASSERT_NOT_NULL(m = mmap_cache_new());

        mkdtemp_chdir_chattr("/var/tmp/journal-seq-XXXXXX", &t);

        ASSERT_OK(journal_file_open(-EBADF, "one.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0644,
                                    UINT64_MAX, NULL, m, NULL, &one));

        append_number(one, 1, NULL, &seqnum, NULL);
        printf("seqnum=%"PRIu64"\n", seqnum);
        ASSERT_EQ(seqnum, UINT64_C(1));
        append_number(one, 2, NULL, &seqnum, NULL);
        printf("seqnum=%"PRIu64"\n", seqnum);
        ASSERT_EQ(seqnum, UINT64_C(2));

        ASSERT_EQ(one->header->state, STATE_ONLINE);
        ASSERT_NE_ID128(one->header->file_id, one->header->machine_id);
        ASSERT_NE_ID128(one->header->file_id, one->header->tail_entry_boot_id);
        ASSERT_EQ_ID128(one->header->file_id, one->header->seqnum_id);

        memcpy(&seqnum_id, &one->header->seqnum_id, sizeof(sd_id128_t));

        ASSERT_OK(journal_file_open(-EBADF, "two.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0644,
                                    UINT64_MAX, NULL, m, one, &two));

        ASSERT_EQ(two->header->state, STATE_ONLINE);
        ASSERT_NE_ID128(two->header->file_id, one->header->file_id);
        ASSERT_EQ_ID128(two->header->machine_id, one->header->machine_id);
        ASSERT_EQ_ID128(two->header->tail_entry_boot_id, SD_ID128_NULL); /* Not written yet. */
        ASSERT_EQ_ID128(two->header->seqnum_id, one->header->seqnum_id);

        append_number(two, 3, NULL, &seqnum, NULL);
        printf("seqnum=%"PRIu64"\n", seqnum);
        ASSERT_EQ(seqnum, UINT64_C(3));
        append_number(two, 4, NULL, &seqnum, NULL);
        printf("seqnum=%"PRIu64"\n", seqnum);
        ASSERT_EQ(seqnum, UINT64_C(4));

        /* Verify tail_entry_boot_id. */
        ASSERT_EQ_ID128(two->header->tail_entry_boot_id, one->header->tail_entry_boot_id);

        append_number(one, 5, NULL, &seqnum, NULL);
        printf("seqnum=%"PRIu64"\n", seqnum);
        ASSERT_EQ(seqnum, UINT64_C(5));

        append_number(one, 6, NULL, &seqnum, NULL);
        printf("seqnum=%"PRIu64"\n", seqnum);
        ASSERT_EQ(seqnum, UINT64_C(6));

        /* If the machine-id is not initialized, the header file verification
         * (which happens when reopening a journal file) will fail. */
        if (sd_id128_get_machine(NULL) >= 0) {
                two = journal_file_offline_close(two);

                /* restart server */
                seqnum = 0;

                ASSERT_OK(journal_file_open(-EBADF, "two.journal", O_RDWR, JOURNAL_COMPRESS, 0,
                                            UINT64_MAX, NULL, m, NULL, &two));

                ASSERT_EQ_ID128(two->header->seqnum_id, seqnum_id);

                append_number(two, 7, NULL, &seqnum, NULL);
                printf("seqnum=%"PRIu64"\n", seqnum);
                ASSERT_EQ(seqnum, UINT64_C(5));

                /* So..., here we have the same seqnum in two files with the same seqnum_id. */
        }
}

TEST(sequence_numbers) {
        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1));
        test_sequence_numbers_one();

        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1));
        test_sequence_numbers_one();

        ASSERT_OK_ERRNO(unsetenv("SYSTEMD_JOURNAL_COMPACT"));
}

static int expected_result(uint64_t needle, const uint64_t *candidates, const uint64_t *offset, size_t n, direction_t direction, uint64_t *ret) {
        switch (direction) {
        case DIRECTION_DOWN:
                for (size_t i = 0; i < n; i++) {
                        if (candidates[i] == 0) {
                                *ret = 0;
                                return 0;
                        }
                        if (needle <= candidates[i]) {
                                *ret = offset[i];
                                return 1;
                        }
                }
                *ret = 0;
                return 0;

        case DIRECTION_UP:
                for (size_t i = 0; i < n; i++)
                        if (needle < candidates[i] || candidates[i] == 0) {
                                if (i == 0) {
                                        *ret = 0;
                                        return 0;
                                }
                                *ret = offset[i - 1];
                                return 1;
                        }
                *ret = offset[n - 1];
                return 1;

        default:
                assert_not_reached();
        }
}

static int expected_result_next(uint64_t needle, const uint64_t *candidates, const uint64_t *offset, size_t n, direction_t direction, uint64_t *ret) {
        switch (direction) {
        case DIRECTION_DOWN:
                for (size_t i = 0; i < n; i++)
                        if (needle < offset[i]) {
                                *ret = candidates[i];
                                return candidates[i] > 0;
                        }
                *ret = 0;
                return 0;

        case DIRECTION_UP:
                for (size_t i = 0; i < n; i++)
                        if (needle <= offset[i]) {
                                n = i;
                                break;
                        }

                for (; n > 0 && candidates[n - 1] == 0; n--)
                        ;

                if (n == 0) {
                        *ret = 0;
                        return 0;
                }

                *ret = candidates[n - 1];
                return candidates[n - 1] > 0;

        default:
                assert_not_reached();
        }
}

static void verify(JournalFile *f, const uint64_t *seqnum, const uint64_t *offset_candidates, const uint64_t *offset, size_t n) {
        uint64_t p, q;
        int r, e;

        /* by seqnum (sequential) */
        for (uint64_t i = 0; i < n + 2; i++) {
                p = 0;
                r = journal_file_move_to_entry_by_seqnum(f, i, DIRECTION_DOWN, NULL, &p);
                e = expected_result(i, seqnum, offset, n, DIRECTION_DOWN, &q);
                ASSERT_EQ(r, e);
                ASSERT_EQ(p, q);

                p = 0;
                r = journal_file_move_to_entry_by_seqnum(f, i, DIRECTION_UP, NULL, &p);
                e = expected_result(i, seqnum, offset, n, DIRECTION_UP, &q);
                ASSERT_EQ(r, e);
                ASSERT_EQ(p, q);
        }

        /* by seqnum (random) */
        for (size_t trial = 0; trial < 3 * n; trial++) {
                uint64_t i = random_u64_range(n + 2);

                p = 0;
                r = journal_file_move_to_entry_by_seqnum(f, i, DIRECTION_DOWN, NULL, &p);
                e = expected_result(i, seqnum, offset, n, DIRECTION_DOWN, &q);
                ASSERT_EQ(r, e);
                ASSERT_EQ(p, q);
        }
        for (size_t trial = 0; trial < 3 * n; trial++) {
                uint64_t i = random_u64_range(n + 2);

                p = 0;
                r = journal_file_move_to_entry_by_seqnum(f, i, DIRECTION_UP, NULL, &p);
                e = expected_result(i, seqnum, offset, n, DIRECTION_UP, &q);
                ASSERT_EQ(r, e);
                ASSERT_EQ(p, q);
        }

        /* by offset (sequential) */
        for (size_t i = 0; i < n; i++) {
                p = 0;
                r = journal_file_move_to_entry_by_offset(f, offset[i] - 1, DIRECTION_DOWN, NULL, &p);
                e = expected_result(offset[i] - 1, offset, offset, n, DIRECTION_DOWN, &q);
                ASSERT_EQ(r, e);
                ASSERT_EQ(p, q);

                p = 0;
                r = journal_file_move_to_entry_by_offset(f, offset[i], DIRECTION_DOWN, NULL, &p);
                e = expected_result(offset[i], offset, offset, n, DIRECTION_DOWN, &q);
                ASSERT_EQ(r, e);
                ASSERT_EQ(p, q);

                p = 0;
                r = journal_file_move_to_entry_by_offset(f, offset[i] + 1, DIRECTION_DOWN, NULL, &p);
                e = expected_result(offset[i] + 1, offset, offset, n, DIRECTION_DOWN, &q);
                ASSERT_EQ(r, e);
                ASSERT_EQ(p, q);

                p = 0;
                r = journal_file_move_to_entry_by_offset(f, offset[i] - 1, DIRECTION_UP, NULL, &p);
                e = expected_result(offset[i] - 1, offset, offset, n, DIRECTION_UP, &q);
                ASSERT_EQ(r, e);
                ASSERT_EQ(p, q);

                p = 0;
                r = journal_file_move_to_entry_by_offset(f, offset[i], DIRECTION_UP, NULL, &p);
                e = expected_result(offset[i], offset, offset, n, DIRECTION_UP, &q);
                ASSERT_EQ(r, e);
                ASSERT_EQ(p, q);

                p = 0;
                r = journal_file_move_to_entry_by_offset(f, offset[i] + 1, DIRECTION_UP, NULL, &p);
                e = expected_result(offset[i] + 1, offset, offset, n, DIRECTION_UP, &q);
                ASSERT_EQ(r, e);
                ASSERT_EQ(p, q);
        }

        /* by offset (random) */
        for (size_t trial = 0; trial < 3 * n; trial++) {
                uint64_t i = offset[0] - 1 + random_u64_range(offset[n-1] - offset[0] + 2);

                p = 0;
                r = journal_file_move_to_entry_by_offset(f, i, DIRECTION_DOWN, NULL, &p);
                e = expected_result(i, offset, offset, n, DIRECTION_DOWN, &q);
                ASSERT_EQ(r, e);
                ASSERT_EQ(p, q);
        }
        for (size_t trial = 0; trial < 3 * n; trial++) {
                uint64_t i = offset[0] - 1 + random_u64_range(offset[n-1] - offset[0] + 2);

                p = 0;
                r = journal_file_move_to_entry_by_offset(f, i, DIRECTION_UP, NULL, &p);
                e = expected_result(i, offset, offset, n, DIRECTION_UP, &q);
                ASSERT_EQ(r, e);
                ASSERT_EQ(p, q);
        }

        /* by journal_file_next_entry() */
        for (size_t i = 0; i < n; i++) {
                p = 0;
                r = journal_file_next_entry(f, offset[i] - 2, DIRECTION_DOWN, NULL, &p);
                e = expected_result_next(offset[i] - 2, offset_candidates, offset, n, DIRECTION_DOWN, &q);
                ASSERT_EQ(e == 0, r <= 0);
                ASSERT_EQ(p, q);

                p = 0;
                r = journal_file_next_entry(f, offset[i] - 1, DIRECTION_DOWN, NULL, &p);
                e = expected_result_next(offset[i] - 1, offset_candidates, offset, n, DIRECTION_DOWN, &q);
                ASSERT_EQ(e == 0, r <= 0);
                ASSERT_EQ(p, q);

                p = 0;
                r = journal_file_next_entry(f, offset[i], DIRECTION_DOWN, NULL, &p);
                e = expected_result_next(offset[i], offset_candidates, offset, n, DIRECTION_DOWN, &q);
                ASSERT_EQ(e == 0, r <= 0);
                ASSERT_EQ(p, q);

                p = 0;
                r = journal_file_next_entry(f, offset[i] + 1, DIRECTION_DOWN, NULL, &p);
                e = expected_result_next(offset[i] + 1, offset_candidates, offset, n, DIRECTION_DOWN, &q);
                ASSERT_EQ(e == 0, r <= 0);
                ASSERT_EQ(p, q);

                p = 0;
                r = journal_file_next_entry(f, offset[i] - 1, DIRECTION_UP, NULL, &p);
                e = expected_result_next(offset[i] - 1, offset_candidates, offset, n, DIRECTION_UP, &q);
                ASSERT_EQ(e == 0, r <= 0);
                ASSERT_EQ(p, q);

                p = 0;
                r = journal_file_next_entry(f, offset[i], DIRECTION_UP, NULL, &p);
                e = expected_result_next(offset[i], offset_candidates, offset, n, DIRECTION_UP, &q);
                ASSERT_EQ(e == 0, r <= 0);
                ASSERT_EQ(p, q);

                p = 0;
                r = journal_file_next_entry(f, offset[i] + 1, DIRECTION_UP, NULL, &p);
                e = expected_result_next(offset[i] + 1, offset_candidates, offset, n, DIRECTION_UP, &q);
                ASSERT_EQ(e == 0, r <= 0);
                ASSERT_EQ(p, q);

                p = 0;
                r = journal_file_next_entry(f, offset[i] + 2, DIRECTION_UP, NULL, &p);
                e = expected_result_next(offset[i] + 2, offset_candidates, offset, n, DIRECTION_UP, &q);
                ASSERT_EQ(e == 0, r <= 0);
                ASSERT_EQ(p, q);
        }
        for (size_t trial = 0; trial < 3 * n; trial++) {
                uint64_t i = offset[0] - 1 + random_u64_range(offset[n-1] - offset[0] + 2);

                p = 0;
                r = journal_file_next_entry(f, i, DIRECTION_DOWN, NULL, &p);
                e = expected_result_next(i, offset_candidates, offset, n, DIRECTION_DOWN, &q);
                ASSERT_EQ(e == 0, r <= 0);
                ASSERT_EQ(p, q);
        }
        for (size_t trial = 0; trial < 3 * n; trial++) {
                uint64_t i = offset[0] - 1 + random_u64_range(offset[n-1] - offset[0] + 2);

                p = 0;
                r = journal_file_next_entry(f, i, DIRECTION_UP, NULL, &p);
                e = expected_result_next(i, offset_candidates, offset, n, DIRECTION_UP, &q);
                ASSERT_EQ(e == 0, r <= 0);
                ASSERT_EQ(p, q);
        }
}

static void test_generic_array_bisect_one(size_t n, size_t num_corrupted) {
        _cleanup_(test_donep) char *t = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_free_ uint64_t *seqnum = NULL, *offset = NULL, *offset_candidates = NULL;
        _cleanup_(journal_file_offline_closep) JournalFile *f = NULL;

        log_info("/* %s(%zu, %zu) */", __func__, n, num_corrupted);

        ASSERT_NOT_NULL(m = mmap_cache_new());

        mkdtemp_chdir_chattr("/var/tmp/journal-seq-XXXXXX", &t);

        ASSERT_OK(journal_file_open(-EBADF, "test.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0644,
                                    UINT64_MAX, NULL, m, NULL, &f));

        ASSERT_NOT_NULL(seqnum = new0(uint64_t, n));
        ASSERT_NOT_NULL(offset = new0(uint64_t, n));

        for (size_t i = 0; i < n; i++) {
                append_number(f, i, NULL, seqnum + i, offset + i);
                ASSERT_GT(seqnum[i], i == 0 ? 0 : seqnum[i-1]);
                ASSERT_GT(offset[i], i == 0 ? 0 : offset[i-1]);
        }

        ASSERT_NOT_NULL(offset_candidates = newdup(uint64_t, offset, n));

        verify(f, seqnum, offset_candidates, offset, n);

        /* Reset chain cache. */
        ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_offset(f, offset[0], DIRECTION_DOWN, NULL, NULL));

        /* make journal corrupted by clearing seqnum. */
        for (size_t i = n - num_corrupted; i < n; i++) {
                Object *o;

                ASSERT_OK(journal_file_move_to_object(f, OBJECT_ENTRY, offset[i], &o));
                ASSERT_NOT_NULL(o);
                o->entry.seqnum = 0;
                seqnum[i] = 0;
                offset_candidates[i] = 0;
        }

        verify(f, seqnum, offset_candidates, offset, n);
}

TEST(generic_array_bisect) {
        for (size_t n = 1; n < 10; n++)
                for (size_t m = 1; m <= n; m++)
                        test_generic_array_bisect_one(n, m);

        test_generic_array_bisect_one(100, 40);
}

typedef struct TestEntry {
        uint64_t seqnum;
        sd_id128_t seqnum_id;
        sd_id128_t boot_id;
        dual_timestamp ts;
        unsigned number;
        unsigned data;
} TestEntry;

static bool find_entry_monotonic_one(
                const TestEntry *e,
                bool next,
                sd_id128_t boot_id,
                usec_t usec,
                unsigned data,
                bool *boot_found) {

        assert(e);
        assert(boot_found);

        if (sd_id128_equal(boot_id, e->boot_id))
                *boot_found = true;

        if (data != 0 && data != e->data)
                return false;

        if (sd_id128_equal(boot_id, e->boot_id))
                return next ? usec <= e->ts.monotonic : usec >= e->ts.monotonic;

        return *boot_found;
}

static size_t find_entry_monotonic(
                const TestEntry *entries,
                size_t n_entries,
                bool next,
                sd_id128_t boot_id,
                usec_t usec,
                unsigned data) {

        bool boot_found = false;

        assert(entries || n_entries == 0);

        for (size_t i = 0; i < n_entries; i++) {
                size_t j = next ? i : n_entries - i - 1;
                const TestEntry *e = &entries[j];

                if (find_entry_monotonic_one(e, next, boot_id, usec, data, &boot_found))
                        return j;
        }

        return SIZE_MAX;
}

static size_t find_entry_realtime(
                const TestEntry *entries,
                size_t n_entries,
                bool next,
                usec_t usec,
                unsigned data) {

        assert(entries || n_entries == 0);

        for (size_t i = 0; i < n_entries; i++) {
                size_t j = next ? i : n_entries - i - 1;
                const TestEntry *e = &entries[j];

                if (data != 0 && data != e->data)
                        continue;

                if (next ? usec <= e->ts.realtime : usec >= e->ts.realtime)
                        return j;
        }

        return SIZE_MAX;
}

static size_t next_entry(
                const TestEntry *entries,
                size_t n_entries,
                bool next,
                size_t prev,
                unsigned data) {

        assert(entries || n_entries == 0);

        if (next)
                for (size_t i = prev + 1; i < n_entries; i++) {
                        const TestEntry *e = &entries[i];

                        if (data != 0 && data != e->data)
                                continue;

                        return i;
                }
        else
                for (size_t i = prev; i > 0; i--) {
                        const TestEntry *e = &entries[i-1];

                        if (data != 0 && data != e->data)
                                continue;

                        return i-1;
                }

        return SIZE_MAX;
}

static void verify_entry(sd_journal *j, const TestEntry *entry) {
        _cleanup_free_ char *s = NULL, *e = NULL;
        sd_id128_t id;
        usec_t t;
        const void *d;
        size_t l;

        assert(j);
        assert(entry);

        ASSERT_OK(sd_journal_get_monotonic_usec(j, &t, &id));
        ASSERT_EQ_ID128(id, entry->boot_id);
        ASSERT_EQ(t, entry->ts.monotonic);

        ASSERT_OK(sd_journal_get_realtime_usec(j, &t));
        ASSERT_EQ(t, entry->ts.realtime);

        ASSERT_OK(sd_journal_get_data(j, "NUMBER", &d, &l));
        ASSERT_NOT_NULL(s = strndup(d, l));
        ASSERT_OK(asprintf(&e, "NUMBER=%u", entry->number));
        ASSERT_STREQ(s, e);

        s = mfree(s);
        e = mfree(e);

        ASSERT_OK(sd_journal_get_data(j, "DATA", &d, &l));
        ASSERT_NOT_NULL(s = strndup(d, l));
        ASSERT_OK(asprintf(&e, "DATA=%u", entry->data));
        ASSERT_STREQ(s, e);
}

static void test_sd_journal_seek_monotonic_usec(
                sd_journal *j,
                const TestEntry *entries,
                size_t n_entries,
                bool next,
                sd_id128_t boot_id,
                usec_t usec,
                unsigned data) {

        assert(j);
        assert(entries || n_entries == 0);

        log_debug("/* %s(next=%s, boot_id=%s, usec="USEC_FMT") */",
                  __func__, yes_no(next), SD_ID128_TO_STRING(boot_id), usec);

        ASSERT_OK(sd_journal_seek_monotonic_usec(j, boot_id, usec));

        for (size_t i = find_entry_monotonic(entries, n_entries, next, boot_id, usec, data);
             i != SIZE_MAX;
             i = next_entry(entries, n_entries, next, i, data)) {

                if (next)
                        ASSERT_OK_POSITIVE(sd_journal_next(j));
                else
                        ASSERT_OK_POSITIVE(sd_journal_previous(j));

                verify_entry(j, &entries[i]);
        }

        if (next)
                ASSERT_OK_ZERO(sd_journal_next(j));
        else
                ASSERT_OK_ZERO(sd_journal_previous(j));
}

static void test_sd_journal_seek_realtime_usec(
                sd_journal *j,
                const TestEntry *entries,
                size_t n_entries,
                bool next,
                usec_t usec,
                unsigned data) {

        assert(j);
        assert(entries || n_entries == 0);

        log_debug("/* %s(next=%s, usec="USEC_FMT") */",
                  __func__, yes_no(next), usec);

        ASSERT_OK(sd_journal_seek_realtime_usec(j, usec));

        for (size_t i = find_entry_realtime(entries, n_entries, next, usec, data);
             i != SIZE_MAX;
             i = next_entry(entries, n_entries, next, i, data)) {

                if (next)
                        ASSERT_OK_POSITIVE(sd_journal_next(j));
                else
                        ASSERT_OK_POSITIVE(sd_journal_previous(j));

                verify_entry(j, &entries[i]);
        }

        if (next)
                ASSERT_OK_ZERO(sd_journal_next(j));
        else
                ASSERT_OK_ZERO(sd_journal_previous(j));
}

static void append_test_entry_full(
                JournalFile **f,
                MMapCache *m,
                TestEntry **entries,
                size_t *n_entries,
                uint64_t *seqnum,
                sd_id128_t *seqnum_id,
                const sd_id128_t *boot_id,
                const dual_timestamp *ts,
                unsigned *number,
                unsigned data,
                bool expect_rotate) {

        struct iovec iovec[3];
        size_t n_iovec = 0;

        assert(f);
        assert(*f);
        assert(entries);
        assert(n_entries);
        assert(*entries || *n_entries == 0);
        assert(seqnum);
        assert(seqnum_id);
        assert(boot_id);
        assert(ts);
        assert(number);

        (*number)++;

        const char *q = strjoina("_BOOT_ID=", SD_ID128_TO_STRING(*boot_id));
        iovec[n_iovec++] = IOVEC_MAKE_STRING(q);

        _cleanup_free_ char *n = NULL;
        ASSERT_OK(asprintf(&n, "NUMBER=%u", *number));
        iovec[n_iovec++] = IOVEC_MAKE_STRING(n);

        _cleanup_free_ char *d = NULL;
        ASSERT_OK(asprintf(&d, "DATA=%u", data));
        iovec[n_iovec++] = IOVEC_MAKE_STRING(d);

        if (expect_rotate) {
                ASSERT_ERROR(journal_file_append_entry(
                                        *f,
                                        ts,
                                        boot_id,
                                        iovec, n_iovec,
                                        seqnum,
                                        seqnum_id,
                                        /* ret_object = */ NULL,
                                        /* ret_offset = */ NULL), EREMCHG);

                ASSERT_OK(journal_file_rotate(
                                        f,
                                        m,
                                        /* file_flags = */ JOURNAL_STRICT_ORDER,
                                        /* compress_threshold_bytes = */ UINT64_MAX,
                                        /* deferred_closes = */ NULL));
        }

        ASSERT_OK(journal_file_append_entry(
                                *f,
                                ts,
                                boot_id,
                                iovec, n_iovec,
                                seqnum,
                                seqnum_id,
                                /* ret_object = */ NULL,
                                /* ret_offset = */ NULL));

        ASSERT_NOT_NULL(GREEDY_REALLOC(*entries, *n_entries + 1));
        (*entries)[(*n_entries)++] = (TestEntry) {
                .seqnum = *seqnum,
                .seqnum_id = *seqnum_id,
                .boot_id = *boot_id,
                .ts = *ts,
                .number = *number,
                .data = data,
        };
}

static void append_test_entry(
                JournalFile *f,
                TestEntry **entries,
                size_t *n_entries,
                uint64_t *seqnum,
                sd_id128_t *seqnum_id,
                const sd_id128_t *boot_id,
                const dual_timestamp *ts,
                unsigned *number,
                unsigned data) {

        append_test_entry_full(&f, NULL, entries, n_entries, seqnum, seqnum_id, boot_id, ts, number, data, /* expect_rotate = */ false);
}

TEST(seek_time) {
        _cleanup_(test_donep) char *t = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_free_ TestEntry *entries = NULL;
        size_t n_entries = 0;
        JournalFile *f;

        mkdtemp_chdir_chattr("/var/tmp/journal-seek-time-XXXXXX", &t);

        ASSERT_NOT_NULL(m = mmap_cache_new());

        ASSERT_OK(journal_file_open(
                                  -EBADF,
                                  "test.journal",
                                  O_RDWR|O_CREAT,
                                  JOURNAL_STRICT_ORDER,
                                  0644,
                                  /* compress_threshold_bytes = */ UINT64_MAX,
                                  /* metrics = */ NULL,
                                  m,
                                  /* template = */ NULL,
                                  &f));

        uint64_t seqnum = 1;
        sd_id128_t seqnum_id, boot_id;
        ASSERT_OK(sd_id128_randomize(&seqnum_id));
        ASSERT_OK(sd_id128_randomize(&boot_id));

        dual_timestamp base, ts;
        dual_timestamp_now(&base);

        unsigned n = 0;

        ts = base;
        append_test_entry(f, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 100);

        ts.realtime += 10;
        ts.monotonic += 10;
        append_test_entry(f, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 100);

        ts.realtime += 10;
        ts.monotonic += 10;
        append_test_entry(f, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 200);

        /* realtime goes to backward */
        ts.realtime -= 100;
        ts.monotonic += 10;
        append_test_entry_full(&f, m, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 200, /* expect_rotate = */ true);

        ts.realtime += 10;
        ts.monotonic += 10;
        append_test_entry(f, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 200);

        ts.realtime += 10;
        ts.monotonic += 10;
        append_test_entry(f, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 100);

        /* realtime goes to forward */
        ts.realtime += 100;
        ts.monotonic += 10;
        append_test_entry(f, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 100);

        ts.realtime += 10;
        ts.monotonic += 10;
        append_test_entry(f, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 200);

        ts.realtime += 10;
        ts.monotonic += 10;
        append_test_entry(f, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 100);

        /* reboot */
        ASSERT_OK(sd_id128_randomize(&boot_id));
        ts.realtime += 10;
        ts.monotonic -= 1000;
        append_test_entry(f, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 100);

        ts.realtime += 10;
        ts.monotonic += 10;
        append_test_entry(f, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 100);

        ts.realtime += 10;
        ts.monotonic += 10;
        append_test_entry(f, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 200);

        ts.realtime += 10;
        ts.monotonic += 10;
        append_test_entry(f, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 200);

        /* reboot */
        ASSERT_OK(sd_id128_randomize(&boot_id));
        ts.realtime += 10;
        ts.monotonic -= 2000;
        append_test_entry(f, &entries, &n_entries, &seqnum, &seqnum_id, &boot_id, &ts, &n, 100);

        journal_file_offline_close(f);

        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));

        log_debug("Testing sequential read");
        ASSERT_OK(sd_journal_seek_head(j));
        ASSERT_OK_POSITIVE(sd_journal_next(j));
        test_check_numbers_down(j, n);

        ASSERT_OK(sd_journal_seek_tail(j));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));
        test_check_numbers_up(j, n);

        unsigned data;
        FOREACH_ARGUMENT(data, 0, 100, 200, 300) {

                sd_journal_flush_matches(j);

                if (data == 0)
                        log_info("no match");
                else {
                        log_info("match: DATA=%u", data);
                        _cleanup_free_ char *match_str = NULL;
                        ASSERT_OK(asprintf(&match_str, "DATA=%u", data));
                        ASSERT_OK(sd_journal_add_match(j, match_str, SIZE_MAX));
                }

                FOREACH_ARRAY(e, entries, n_entries) {
                        test_sd_journal_seek_monotonic_usec(j, entries, n_entries, /* next = */ true,  e->boot_id, e->ts.monotonic - 1, data);
                        test_sd_journal_seek_monotonic_usec(j, entries, n_entries, /* next = */ true,  e->boot_id, e->ts.monotonic,     data);
                        test_sd_journal_seek_monotonic_usec(j, entries, n_entries, /* next = */ true,  e->boot_id, e->ts.monotonic + 1, data);
                        test_sd_journal_seek_monotonic_usec(j, entries, n_entries, /* next = */ false, e->boot_id, e->ts.monotonic - 1, data);
                        test_sd_journal_seek_monotonic_usec(j, entries, n_entries, /* next = */ false, e->boot_id, e->ts.monotonic,     data);
                        test_sd_journal_seek_monotonic_usec(j, entries, n_entries, /* next = */ false, e->boot_id, e->ts.monotonic + 1, data);

                        test_sd_journal_seek_realtime_usec(j, entries, n_entries, /* next = */ true,  e->ts.monotonic - 1, data);
                        test_sd_journal_seek_realtime_usec(j, entries, n_entries, /* next = */ true,  e->ts.monotonic,     data);
                        test_sd_journal_seek_realtime_usec(j, entries, n_entries, /* next = */ true,  e->ts.monotonic + 1, data);
                        test_sd_journal_seek_realtime_usec(j, entries, n_entries, /* next = */ false, e->ts.monotonic - 1, data);
                        test_sd_journal_seek_realtime_usec(j, entries, n_entries, /* next = */ false, e->ts.monotonic,     data);
                        test_sd_journal_seek_realtime_usec(j, entries, n_entries, /* next = */ false, e->ts.monotonic + 1, data);
                }
        }
}

static int intro(void) {
        /* journal_file_open() requires a valid machine id */
        if (access("/etc/machine-id", F_OK) != 0)
                return log_tests_skipped("/etc/machine-id not found");

        arg_keep = saved_argc > 1;

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
