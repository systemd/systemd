/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "iovec-util.h"
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

        test_journal_file_parse_uid_from_filename_simple("/var/log/journal/", /* expected_uid= */ 0, -EISDIR);

        /* The helper should return -EREMOTE for any filenames that don't look like an online or offline user
         * journals. This includes archived and disposed journal files. */
        test_journal_file_parse_uid_from_filename_simple("/etc/password", /* expected_uid= */ 0, -EREMOTE);
        test_journal_file_parse_uid_from_filename_simple("system.journal", /* expected_uid= */ 0, -EREMOTE);
        test_journal_file_parse_uid_from_filename_simple("user-1000@0005d26980bdce6e-2f2a4939583822ef.journal~", /* expected_uid= */ 0, -EREMOTE);
        test_journal_file_parse_uid_from_filename_simple("user-1000@xxx-yyy-zzz.journal", /* expected_uid= */ 0, -EREMOTE);

        test_journal_file_parse_uid_from_filename_simple("user-1000.journal", 1000, /* expected_error= */ 0);
        test_journal_file_parse_uid_from_filename_simple("user-foo.journal", /* expected_uid= */ 0, -EINVAL);
        test_journal_file_parse_uid_from_filename_simple("user-65535.journal", /* expected_uid= */ 0, -ENXIO);
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
        g = journal_test_open(m, "test.journal", O_RDONLY, /* max_size= */ 0);
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
                                                   le64toh(f->header->header_size) - 1, DIRECTION_UP, &o, /* ret_offset= */ NULL));
        ASSERT_OK_POSITIVE(journal_file_seek_for_match(f, match, strlen(match), JOURNAL_SEEK_OFFSET, /* boot_id= */ SD_ID128_NULL,
                                                       le64toh(f->header->header_size) - 1, DIRECTION_DOWN, &o, /* ret_offset= */ NULL));
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
        follower = journal_test_open(m, "test.journal", O_RDONLY, /* max_size= */ 0);

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
        g = journal_test_open(m, "test.journal", O_RDONLY, /* max_size= */ 0);
        model_assert_file(g, &model);
        g = journal_file_close(g);

        ASSERT_OK(journal_file_set_offline(f, /* wait= */ true));
        g = journal_test_open(m, "test.journal", O_RDONLY, /* max_size= */ 0);
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

        g = journal_test_open(m, path, O_RDONLY, /* max_size= */ 0);
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
        ASSERT_MEMEQ(f->header->signature, HEADER_SIGNATURE, sizeof(f->header->signature));
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ true));
        ASSERT_EQ(f->header->state, STATE_ARCHIVED);
        model_assert_file(f, &model);

        ASSERT_NOT_NULL(path = strdup(f->path));
        f = journal_file_offline_close(f);

        g = journal_test_open(m, path, O_RDONLY, /* max_size= */ 0);
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
        follower = journal_test_open(m, "test.journal", O_RDONLY, /* max_size= */ 0);

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

        ASSERT_OK(sd_journal_open_files(&j, (const char*[]) { "test.journal", NULL }, /* flags= */ 0));
        SD_JOURNAL_FOREACH_FIELD(j, name)
                ASSERT_FALSE(streq(name, "NEWFIELD"));

        /* Enumeration finds fields that were appended since */
        model_append(f, /* model= */ NULL, MODEL_REALTIME_BASE + 10, 5010, MODEL_BOOT_A, STRV_MAKE("NEWFIELD=1"));

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

        ASSERT_OK(sd_journal_open_files(&j, (const char*[]) { "test.journal", NULL }, /* flags= */ 0));
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

TEST(seqnum_id) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        sd_id128_t a, b;
        JournalFile *f, *g;

        if (!journal_test_setup(&directory))
                return;
        ASSERT_NOT_NULL(m = mmap_cache_new());
        ASSERT_OK(sd_id128_randomize(&a));
        ASSERT_OK(sd_id128_randomize(&b));

        /* Without a sequence number ID a new file uses its file ID */
        f = journal_test_open(m, "a.journal", O_RDWR|O_CREAT, 2 * U64_MB);
        ASSERT_EQ_ID128(f->header->seqnum_id, f->header->file_id);

        /* journal_file_open_full() writes the ID that it gets to the header of the new file, and ignores the
         * ID of the template */
        ASSERT_OK(journal_file_open_full(
                                  /* fd= */ -EBADF,
                                  "b.journal",
                                  O_RDWR|O_CREAT,
                                  JOURNAL_COMPRESS,
                                  0644,
                                  /* compress_threshold_bytes= */ UINT64_MAX,
                                  /* metrics= */ NULL,
                                  m,
                                  /* template= */ f,
                                  &a,
                                  &g));
        ASSERT_EQ_ID128(g->header->seqnum_id, a);

        /* The file that replaces a rotated file gets the ID passed to the rotation */
        ASSERT_OK(journal_file_rotate(
                                  &g,
                                  m,
                                  JOURNAL_COMPRESS,
                                  /* compress_threshold_bytes= */ UINT64_MAX,
                                  &b,
                                  /* deferred_closes= */ NULL));
        ASSERT_EQ_ID128(g->header->seqnum_id, b);

        /* journald passes a null ID after it resets its sequence number data. The file that replaces a
         * rotated file then takes the ID of the rotated file. */
        ASSERT_OK(journal_file_rotate(
                                  &g,
                                  m,
                                  JOURNAL_COMPRESS,
                                  /* compress_threshold_bytes= */ UINT64_MAX,
                                  &SD_ID128_NULL,
                                  /* deferred_closes= */ NULL));
        ASSERT_EQ_ID128(g->header->seqnum_id, b);

        g = journal_file_offline_close(g);
        f = journal_file_offline_close(f);
}

static void append_boottime_entry(JournalFile *f, unsigned i, usec_t monotonic, usec_t boottime) {
        _cleanup_free_ char *s = NULL;
        struct iovec iovec;

        triple_timestamp ts = {
                .realtime = MODEL_REALTIME_BASE + i,
                .monotonic = monotonic,
                .boottime = boottime,
        };

        ASSERT_OK(asprintf(&s, "NUMBER=%u", i));
        iovec = IOVEC_MAKE_STRING(s);

        ASSERT_OK(journal_file_append_entry(
                                  f,
                                  &ts,
                                  &MODEL_BOOT_A,
                                  &iovec, 1,
                                  /* seqnum= */ NULL,
                                  /* seqnum_id= */ NULL,
                                  /* ret_object= */ NULL,
                                  /* ret_offset= */ NULL));
}

#define BOOTTIME_MONOTONIC_BASE (1000 * USEC_PER_SEC)

static const struct {
        usec_t monotonic;
        usec_t boottime; /* as passed in */
        usec_t expected; /* as read back, USEC_INFINITY if not available */
} boottime_table[] = {
        /* Time spent in suspend */
        { BOOTTIME_MONOTONIC_BASE,      BOOTTIME_MONOTONIC_BASE + 5 * USEC_PER_SEC,    BOOTTIME_MONOTONIC_BASE + 5 * USEC_PER_SEC },
        /* No suspend so far, offset zero */
        { BOOTTIME_MONOTONIC_BASE + 1,  BOOTTIME_MONOTONIC_BASE + 1,                    BOOTTIME_MONOTONIC_BASE + 1 },
        /* Boottime not known */
        { BOOTTIME_MONOTONIC_BASE + 2,  USEC_INFINITY,                                  USEC_INFINITY },
        { BOOTTIME_MONOTONIC_BASE + 3,  0,                                              USEC_INFINITY },
        /* Boottime before monotonic, which makes no sense */
        { BOOTTIME_MONOTONIC_BASE + 4,  BOOTTIME_MONOTONIC_BASE,                        USEC_INFINITY },
        /* Largest offset we can store */
        { BOOTTIME_MONOTONIC_BASE + 5,  BOOTTIME_MONOTONIC_BASE + 5 + ENTRY_BOOTTIME_OFFSET_MAX,     BOOTTIME_MONOTONIC_BASE + 5 + ENTRY_BOOTTIME_OFFSET_MAX },
        /* Too large an offset */
        { BOOTTIME_MONOTONIC_BASE + 6,  BOOTTIME_MONOTONIC_BASE + 6 + ENTRY_BOOTTIME_OFFSET_MAX + 1, USEC_INFINITY },
};

static void assert_boottime_file(JournalFile *f, bool supported) {
        uint64_t p = 0;
        size_t i = 0;
        Object *o;

        for (;;) {
                uint64_t t;
                int r;

                r = journal_file_next_entry(f, p, DIRECTION_DOWN, &o, &p);
                ASSERT_OK(r);
                if (r == 0)
                        break;

                ASSERT_LT(i, ELEMENTSOF(boottime_table));
                ASSERT_EQ(le64toh(o->entry.monotonic), boottime_table[i].monotonic);

                r = journal_file_entry_boottime(f, o, &t);
                if (!supported || boottime_table[i].expected == USEC_INFINITY)
                        ASSERT_ERROR(r, ENODATA);
                else {
                        ASSERT_OK(r);
                        ASSERT_EQ(t, boottime_table[i].expected);
                }

                i++;
        }

        ASSERT_EQ(i, ELEMENTSOF(boottime_table));
}

TEST(boottime) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        JournalFile *f, *g, *old;
        sd_id128_t boot_id;
        uint64_t t, p = 0;
        Object *o;
        size_t i = 0;
        int r;

        if (!journal_test_setup(&directory))
                return;
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = journal_test_open(m, "test.journal", O_RDWR|O_CREAT, 2 * U64_MB);
        ASSERT_TRUE(JOURNAL_HEADER_BOOTTIME(f->header));

        /* A file created by an older version, which doesn't know about the boottime offset */
        old = journal_test_open(m, "old.journal", O_RDWR|O_CREAT, 2 * U64_MB);
        old->header->compatible_flags = htole32(le32toh(old->header->compatible_flags) & ~HEADER_COMPATIBLE_BOOTTIME);
        ASSERT_FALSE(JOURNAL_HEADER_BOOTTIME(old->header));

        FOREACH_ELEMENT(e, boottime_table) {
                append_boottime_entry(f, e - boottime_table, e->monotonic, e->boottime);
                append_boottime_entry(old, e - boottime_table, e->monotonic, e->boottime);
        }

        assert_boottime_file(f, /* supported= */ true);
        assert_boottime_file(old, /* supported= */ false);

        /* Copying entries retains the boottime timestamp */
        g = journal_test_open(m, "copy.journal", O_RDWR|O_CREAT, 2 * U64_MB);
        for (;;) {
                r = journal_file_next_entry(f, p, DIRECTION_DOWN, &o, &p);
                ASSERT_OK(r);
                if (r == 0)
                        break;

                ASSERT_OK(journal_file_copy_entry(f, g, o, p, /* seqnum= */ NULL, /* seqnum_id= */ NULL));
        }
        assert_boottime_file(g, /* supported= */ true);

        /* Copying entries from a file without boottime into one with it marks them as unknown */
        p = 0;
        g = journal_file_offline_close(g);
        ASSERT_OK_ERRNO(unlink("copy.journal"));
        g = journal_test_open(m, "copy.journal", O_RDWR|O_CREAT, 2 * U64_MB);
        for (;;) {
                r = journal_file_next_entry(old, p, DIRECTION_DOWN, &o, &p);
                ASSERT_OK(r);
                if (r == 0)
                        break;

                ASSERT_OK(journal_file_copy_entry(old, g, o, p, /* seqnum= */ NULL, /* seqnum_id= */ NULL));
        }
        assert_boottime_file(g, /* supported= */ false);

        g = journal_file_offline_close(g);
        old = journal_file_offline_close(old);
        f = journal_file_offline_close(f);

        /* The files pass verification, i.e. the boottime offset field is accepted where it is defined */
        FOREACH_STRING(path, "test.journal", "old.journal", "copy.journal") {
                f = journal_test_open(m, path, O_RDONLY, /* max_size= */ 0);
                /* copy.journal at this point contains the entries copied from old.journal */
                assert_boottime_file(f, /* supported= */ streq(path, "test.journal"));
                ASSERT_OK(journal_file_verify(
                                          f,
                                          /* key= */ NULL,
                                          /* ret_first_contained= */ NULL,
                                          /* ret_last_validated= */ NULL,
                                          /* ret_last_contained= */ NULL,
                                          /* show_progress= */ false));
                f = journal_file_close(f);
        }

        /* And via the public API */
        ASSERT_OK(sd_journal_open_files(&j, (const char*[]) { "test.journal", NULL }, /* flags= */ 0));
        SD_JOURNAL_FOREACH(j) {
                ASSERT_LT(i, ELEMENTSOF(boottime_table));

                r = sd_journal_get_boottime_usec(j, &t, &boot_id);
                if (boottime_table[i].expected == USEC_INFINITY)
                        ASSERT_ERROR(r, ENODATA);
                else {
                        ASSERT_OK(r);
                        ASSERT_EQ(t, boottime_table[i].expected);
                        ASSERT_EQ_ID128(boot_id, MODEL_BOOT_A);
                }

                /* The entries are from a different boot than ours */
                ASSERT_ERROR(sd_journal_get_boottime_usec(j, &t, /* ret_boot_id= */ NULL), ESTALE);

                i++;
        }
        ASSERT_EQ(i, ELEMENTSOF(boottime_table));
}

DEFINE_TEST_MAIN(LOG_INFO);
