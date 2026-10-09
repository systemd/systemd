/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-id128.h"
#include "sd-journal.h"

#include "alloc-util.h"
#include "copy.h"
#include "fd-util.h"
#include "fileio.h"
#include "iovec-util.h"
#include "journal-authenticate.h"
#include "journal-file-util.h"
#include "journal-segmented.h"
#include "journal-segmented-internal.h"
#include "journal-vacuum.h"
#include "journal-verify.h"
#include "log.h"
#include "memory-util.h"
#include "mmap-cache.h"
#include "random-util.h"
#include "rm-rf.h"
#include "siphash24.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

static const sd_id128_t boot_a = SD_ID128_MAKE(a1,a2,a3,a4,a5,a6,a7,a8,a9,aa,ab,ac,ad,ae,af,a0),
        boot_b = SD_ID128_MAKE(b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf,b0);

/* Where the timestamps of generated entries start */
static usec_t realtime_base = 1000000;

static const uint8_t digest_key[16] = {
        0x74, 0x65, 0x73, 0x74, 0x2d, 0x61, 0x70, 0x70, 0x65, 0x6e, 0x64, 0x2d, 0x6f, 0x6e, 0x6c, 0x79,
};

typedef struct Model {
        /* Expected contents of a file */
        char ***entries;
        usec_t *realtime;
        usec_t *monotonic;
        size_t n_entries;
} Model;

static void model_done(Model *m) {
        assert(m);

        FOREACH_ARRAY(e, m->entries, m->n_entries)
                strv_free(*e);

        free(m->entries);
        free(m->realtime);
        free(m->monotonic);
}

static void setup(char **ret_directory) {
        ASSERT_OK(mkdtemp_malloc("/var/tmp/journal-segmented-XXXXXX", ret_directory));
        ASSERT_OK_ERRNO(chdir(*ret_directory));
}

static JournalFile* open_file(MMapCache *m, const char *name, int flags, bool segmented, uint64_t max_size) {
        JournalMetrics metrics = {
                .max_size = max_size,
                .min_size = UINT64_MAX,
                .max_use = 0,
                .min_use = UINT64_MAX,
                .keep_free = 0,
                .n_max_files = UINT64_MAX,
        };
        JournalFile *f;

        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_SEGMENTED", one_zero(segmented), /* overwrite= */ true));

        ASSERT_OK(journal_file_open(
                                  /* fd= */ -EBADF,
                                  name,
                                  flags,
                                  JOURNAL_COMPRESS,
                                  0644,
                                  /* compress_threshold_bytes= */ UINT64_MAX,
                                  (flags & O_ACCMODE_STRICT) == O_RDONLY ? NULL : &metrics,
                                  m,
                                  /* template= */ NULL,
                                  &f));

        return f;
}

static void append(JournalFile *f, Model *model, usec_t realtime, usec_t monotonic, sd_id128_t boot_id, char **fields) {
        _cleanup_free_ struct iovec *iovec = NULL;
        dual_timestamp ts = {
                .realtime = realtime,
                .monotonic = monotonic,
        };
        size_t n = 0;

        ASSERT_NOT_NULL(iovec = new(struct iovec, strv_length(fields)));

        STRV_FOREACH(i, fields)
                iovec[n++] = IOVEC_MAKE_STRING(*i);

        ASSERT_OK(journal_file_append_entry(f, &ts, &boot_id, iovec, n, NULL, NULL, NULL, NULL));

        if (!model)
                return;

        ASSERT_NOT_NULL(GREEDY_REALLOC(model->entries, model->n_entries + 1));
        ASSERT_NOT_NULL(GREEDY_REALLOC(model->realtime, model->n_entries + 1));
        ASSERT_NOT_NULL(GREEDY_REALLOC(model->monotonic, model->n_entries + 1));

        ASSERT_NOT_NULL(model->entries[model->n_entries] = strv_copy(fields));
        strv_sort_uniq(model->entries[model->n_entries]);
        model->realtime[model->n_entries] = realtime;
        model->monotonic[model->n_entries] = monotonic;
        model->n_entries++;
}

static void append_generated(JournalFile *f, Model *model, uint64_t i) {
        _cleanup_strv_free_ char **fields = NULL;
        unsigned service = i % 7 == 0 ? 3 : (i / 5) % 4;

        /* A couple of services that log in bursts, with metadata that does not change */

        ASSERT_OK(strv_extendf(&fields, "MESSAGE=This is message %" PRIu64 " of 17", i % 17 == 0 ? i : i % 17));
        ASSERT_OK(strv_extendf(&fields, "PRIORITY=%" PRIu64, i % 3 + 4));
        ASSERT_OK(strv_extendf(&fields, "SYSLOG_IDENTIFIER=service%u", service));
        ASSERT_OK(strv_extendf(&fields, "NUMBER=%" PRIu64, i));
        ASSERT_OK(strv_extendf(&fields, "_PID=%u", 100 + service));
        ASSERT_OK(strv_extendf(&fields, "_UID=%u", service == 0 ? 1000U : 0U));
        ASSERT_OK(strv_extendf(&fields, "_COMM=service%u", service));
        ASSERT_OK(strv_extendf(&fields, "_SYSTEMD_UNIT=service%u.service", service));
        ASSERT_OK(strv_extendf(&fields, "_SOURCE_REALTIME_TIMESTAMP=%" PRIu64, realtime_base + i * 10 - 3));
        ASSERT_OK(strv_extendf(&fields, "_BOOT_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(boot_a)));
        ASSERT_OK(strv_extend(&fields, "_HOSTNAME=test"));

        if (i % 50 == 0) {
                _cleanup_free_ char *large = NULL;

                /* Large values: one that compresses well, one that compresses poorly */
                ASSERT_NOT_NULL(large = strrep("x", 3999));
                ASSERT_OK(strv_extendf(&fields, "LARGE=%s%" PRIu64, large, i % 100));

                for (size_t k = 0; k < 3999; k++)
                        large[k] = 'a' + (siphash24(&k, sizeof(k), digest_key) + i % 200) % 26;
                ASSERT_OK(strv_extendf(&fields, "RANDOM=%s", large));
        }

        append(f, model, realtime_base + i * 10, 5000 + i * 10, boot_a, fields);
}

static void assert_entry(JournalFile *f, Object *o, uint64_t offset, const Model *model, size_t i) {
        _cleanup_strv_free_ char **fields = NULL;
        uint64_t n;

        ASSERT_LT(i, model->n_entries);
        ASSERT_EQ(o->object.type, OBJECT_ENTRY);
        ASSERT_EQ(le64toh(o->entry.realtime), model->realtime[i]);

        ASSERT_OK(journal_file_entry_n_fields(f, o, offset, &n));

        for (uint64_t k = 0; k < n; k++) {
                const void *data;
                size_t size;

                ASSERT_OK(journal_file_move_to_object(f, OBJECT_ENTRY, offset, &o));
                ASSERT_OK_POSITIVE(journal_file_entry_field_payload(f, o, offset, k, NULL, 0, 0, &data, &size));
                char *copy = ASSERT_NOT_NULL(strndup(data, size));
                ASSERT_OK(strv_consume(&fields, copy));
        }

        strv_sort(fields);
        ASSERT_TRUE(strv_equal(fields, model->entries[i]));
}

static bool model_matches(const Model *model, size_t i, const char *match) {
        return !match || strv_contains(model->entries[i], match);
}

static void assert_file(JournalFile *f, const Model *model) {
        static const char * const matches[] = {
                NULL,
                "_SYSTEMD_UNIT=service3.service",       /* in a context */
                "_UID=1000",
                "PRIORITY=5",                            /* frequent */
                "NUMBER=77",                             /* once */
                "NUMBER=100000000",                      /* never */
                "MESSAGE=This is message 3 of 17",       /* not indexed */
                "MESSAGE=This is message 170 of 17",
                "_SOURCE_REALTIME_TIMESTAMP=1000697",    /* inline */
                "_HOSTNAME=test",                        /* all */
                "NOSUCHFIELD=1",
        };
        uint64_t p;
        Object *o;
        size_t i;
        int r;

        ASSERT_EQ(le64toh(f->header->n_entries), model->n_entries);

        /* Forwards and backwards, without and with matches */
        FOREACH_ELEMENT(match, matches) {
                size_t l = strlen_ptr(*match);

                for (i = 0, p = 0; i < model->n_entries; i++) {
                        if (!model_matches(model, i, *match))
                                continue;

                        if (!*match)
                                r = journal_file_next_entry(f, p, DIRECTION_DOWN, &o, &p);
                        else if (p == 0)
                                r = journal_file_seek_for_match(f, *match, l, JOURNAL_SEEK_FIRST, SD_ID128_NULL, 0, DIRECTION_DOWN, &o, &p);
                        else
                                r = journal_file_seek_for_match(f, *match, l, JOURNAL_SEEK_OFFSET, SD_ID128_NULL, p + 1, DIRECTION_DOWN, &o, &p);
                        ASSERT_OK_POSITIVE(r);
                        assert_entry(f, o, p, model, i);
                }

                if (!*match)
                        r = journal_file_next_entry(f, p, DIRECTION_DOWN, &o, &p);
                else if (p == 0)
                        r = journal_file_seek_for_match(f, *match, l, JOURNAL_SEEK_FIRST, SD_ID128_NULL, 0, DIRECTION_DOWN, &o, &p);
                else
                        r = journal_file_seek_for_match(f, *match, l, JOURNAL_SEEK_OFFSET, SD_ID128_NULL, p + 1, DIRECTION_DOWN, &o, &p);
                ASSERT_OK_ZERO(r);

                for (i = model->n_entries, p = 0; i > 0; i--) {
                        if (!model_matches(model, i - 1, *match))
                                continue;

                        if (!*match)
                                r = journal_file_next_entry(f, p, DIRECTION_UP, &o, &p);
                        else if (p == 0)
                                r = journal_file_seek_for_match(f, *match, l, JOURNAL_SEEK_FIRST, SD_ID128_NULL, 0, DIRECTION_UP, &o, &p);
                        else
                                r = journal_file_seek_for_match(f, *match, l, JOURNAL_SEEK_OFFSET, SD_ID128_NULL, p - 1, DIRECTION_UP, &o, &p);
                        ASSERT_OK_POSITIVE(r);
                        assert_entry(f, o, p, model, i - 1);
                }
        }

        /* Seeking */
        for (unsigned k = 0; k < 50 && model->n_entries > 0; k++) {
                i = random_u64_range(model->n_entries);

                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_realtime(f, model->realtime[i], DIRECTION_DOWN, &o, &p));
                assert_entry(f, o, p, model, i);
                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_realtime(f, model->realtime[i] - 1, DIRECTION_DOWN, &o, &p));
                assert_entry(f, o, p, model, i);
                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_realtime(f, model->realtime[i] + 1, DIRECTION_UP, &o, &p));
                assert_entry(f, o, p, model, i);

                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_seqnum(f, i + 1, DIRECTION_DOWN, &o, &p));
                assert_entry(f, o, p, model, i);
                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_seqnum(f, i + 1, DIRECTION_UP, &o, &p));
                assert_entry(f, o, p, model, i);

                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_monotonic(f, boot_a, model->monotonic[i], DIRECTION_DOWN, &o, &p));
                assert_entry(f, o, p, model, i);

                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_offset(f, p, DIRECTION_DOWN, &o, &p));
                assert_entry(f, o, p, model, i);
                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_offset(f, p + 1, DIRECTION_UP, &o, &p));
                assert_entry(f, o, p, model, i);
        }

        if (model->n_entries > 0) {
                ASSERT_OK_ZERO(journal_file_move_to_entry_by_realtime(f, model->realtime[model->n_entries - 1] + 1, DIRECTION_DOWN, &o, &p));
                ASSERT_OK_ZERO(journal_file_move_to_entry_by_realtime(f, model->realtime[0] - 1, DIRECTION_UP, &o, &p));
                ASSERT_OK_ZERO(journal_file_move_to_entry_by_monotonic(f, boot_b, 0, DIRECTION_DOWN, &o, &p));
        }
}

TEST(basic) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        JournalFile *f;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 128 * U64_MB);
        ASSERT_NOT_NULL(f->segmented);
        ASSERT_TRUE(JOURNAL_HEADER_SEGMENTED(f->header));
        ASSERT_TRUE(JOURNAL_HEADER_COMPACT(f->header));
        ASSERT_TRUE(JOURNAL_HEADER_KEYED_HASH(f->header));
        assert_file(f, &model);

        for (uint64_t i = 0; i < 300; i++) {
                append_generated(f, &model, i);

                if (i < 10 || i % 100 == 0)
                        assert_file(f, &model);
        }

        /* The same field twice */
        append(f, &model, 1000000 + 300 * 10, 5000 + 300 * 10, boot_a,
               STRV_MAKE("MESSAGE=foo", "A=b", "A=b", "_X=y", "MESSAGE=foo", "A=c", "_BOOT_ID=a1a2a3a4a5a6a7a8a9aaabacadaeafa0"));
        assert_file(f, &model);

        ASSERT_EQ(f->segmented->n_indexes, 0U);
        /* Everything that is neither an entry nor a data object is a context */
        uint64_t n_contexts = le64toh(f->header->n_objects) - le64toh(f->header->n_entries) - le64toh(f->header->n_data);
        ASSERT_GT(n_contexts, 0U);
        ASSERT_LT(n_contexts, 20U);
        ASSERT_EQ(f->header->state, STATE_ONLINE);
        ASSERT_EQ(f->segmented->disk_header->state, STATE_OFFLINE);

        /* A second reader while the file is written */
        JournalFile *g = open_file(m, "test.journal", O_RDONLY, /* segmented= */ false, 0);
        ASSERT_NOT_NULL(g->segmented);
        assert_file(g, &model);

        append_generated(f, &model, 301);
        g->segmented->refresh_pending = true;
        ASSERT_OK_POSITIVE(segmented_refresh(g, USEC_INFINITY));
        g->segmented->refresh_pending = true;
        ASSERT_OK_ZERO(segmented_refresh(g, USEC_INFINITY));
        assert_file(g, &model);
        g = journal_file_close(g);

        /* Close and continue */
        f = journal_file_offline_close(f);
        f = open_file(m, "test.journal", O_RDWR, /* segmented= */ false, 128 * U64_MB);
        ASSERT_NOT_NULL(f->segmented);
        assert_file(f, &model);

        for (uint64_t i = 302; i < 400; i++)
                append_generated(f, &model, i);
        assert_file(f, &model);

        /* Without proper closing */
        f = journal_file_close(f);
        f = open_file(m, "test.journal", O_RDWR, /* segmented= */ false, 128 * U64_MB);
        assert_file(f, &model);
        append_generated(f, &model, 400);
        assert_file(f, &model);
        f = journal_file_offline_close(f);
}

TEST(indexes) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        JournalFile *f, *g, *follower;
        uint64_t size;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        /* With a 3 MiB file, a checkpoint writes an index every 192 KiB */
        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 3 * U64_MB);
        follower = open_file(m, "test.journal", O_RDONLY, /* segmented= */ false, 0);

        for (uint64_t i = 0; i < 3000; i++) {
                append_generated(f, &model, i);

                if (i % 500 == 0) {
                        assert_file(f, &model);

                        follower->segmented->refresh_pending = true;
                        ASSERT_OK_POSITIVE(segmented_refresh(follower, USEC_INFINITY));
                        assert_file(follower, &model);
                }
        }

        ASSERT_GT(f->segmented->n_indexes, 2U);
        ASSERT_LT(f->segmented->scan_offset - f->segmented->tail_offset, 384 * U64_KB);
        assert_file(f, &model);

        follower->segmented->refresh_pending = true;
        ASSERT_OK_POSITIVE(segmented_refresh(follower, USEC_INFINITY));
        ASSERT_EQ(follower->segmented->n_indexes, f->segmented->n_indexes);
        assert_file(follower, &model);

        /* The header names no index yet, as nothing was synced */
        ASSERT_EQ(le64toh(f->segmented->disk_header->synced_index_offset), 0U);
        g = open_file(m, "test.journal", O_RDONLY, /* segmented= */ false, 0);
        ASSERT_EQ(g->segmented->n_indexes, f->segmented->n_indexes);
        assert_file(g, &model);
        g = journal_file_close(g);

        ASSERT_OK(journal_file_set_offline(f, /* wait= */ true));
        ASSERT_EQ(le64toh(f->segmented->disk_header->synced_index_offset), f->segmented->indexes[f->segmented->n_indexes - 1].offset);
        g = open_file(m, "test.journal", O_RDONLY, /* segmented= */ false, 0);
        ASSERT_EQ(g->segmented->n_indexes, f->segmented->n_indexes);
        assert_file(g, &model);
        g = journal_file_close(g);

        /* Same, in the background */
        for (uint64_t i = 3000; i < 5000; i++)
                append_generated(f, &model, i);
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ false));
        for (uint64_t i = 5000; i < 5100; i++)
                append_generated(f, &model, i);
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ true));
        assert_file(f, &model);

        /* Continue the file */
        size_t n_indexes = f->segmented->n_indexes;
        f = journal_file_offline_close(f);
        f = open_file(m, "test.journal", O_RDWR, /* segmented= */ false, 3 * U64_MB);
        ASSERT_GE(f->segmented->n_indexes, n_indexes);
        assert_file(f, &model);

        for (uint64_t i = 5100; i < 6000; i++)
                append_generated(f, &model, i);
        assert_file(f, &model);

        /* Archive it, which merges the indexes */
        ASSERT_GT(f->segmented->n_indexes, 4U);
        size = f->segmented->scan_offset;
        ASSERT_OK(journal_file_archive(f, NULL));
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ true));
        ASSERT_EQ(f->header->state, STATE_ARCHIVED);
        ASSERT_ERROR(journal_file_append_entry(f, NULL, NULL, &IOVEC_MAKE_STRING("A=b"), 1, NULL, NULL, NULL, NULL), ESHUTDOWN);

        _cleanup_free_ char *path = NULL;
        ASSERT_NOT_NULL(path = strdup(f->path));
        f = journal_file_offline_close(f);

        g = open_file(m, path, O_RDONLY, /* segmented= */ false, 0);
        ASSERT_GT((uint64_t) g->last_stat.st_size, size);
        ASSERT_EQ(g->header->state, STATE_ARCHIVED);
        ASSERT_EQ(g->segmented->n_indexes, 1U);
        ASSERT_EQ(g->segmented->n_tail_entries, 0U);
        assert_file(g, &model);
        g = journal_file_close(g);

        /* The follower kept the file open throughout. Normally inotify triggers its refresh. */
        follower->segmented->refresh_pending = true;
        ASSERT_OK(segmented_refresh(follower, USEC_INFINITY));
        ASSERT_EQ(follower->header->state, STATE_ARCHIVED);
        ASSERT_EQ(follower->segmented->n_indexes, 1U);
        assert_file(follower, &model);
        follower = journal_file_close(follower);

        ASSERT_ERROR(journal_file_open(-EBADF, path, O_RDWR, 0, 0644, UINT64_MAX, NULL, m, NULL, &g), ESHUTDOWN);
}

static void test_sync_then_archive_one(bool sync_done) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        _cleanup_free_ char *path = NULL;
        JournalFile *f, *g;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);

        for (uint64_t i = 0; i < 3000; i++)
                append_generated(f, &model, i);
        ASSERT_GT(f->segmented->n_indexes, 1U);

        /* A sync in the background that nobody joins, followed by a rotation, the way journald does it.
         * Without waiting, the sync thread may still run and archive the file when it is done. */
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ false));
        if (sync_done) {
                for (unsigned i = 0; i < 1000 && __atomic_load_n(&f->offline_state, __ATOMIC_SEQ_CST) != OFFLINE_DONE; i++)
                        usleep_safe(10 * USEC_PER_MSEC);
                ASSERT_EQ((int) __atomic_load_n(&f->offline_state, __ATOMIC_SEQ_CST), (int) OFFLINE_DONE);
        }

        ASSERT_OK(journal_file_archive(f, NULL));
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ false));
        ASSERT_EQ(memcmp(f->header->signature, HEADER_SIGNATURE, sizeof(f->header->signature)), 0);
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ true));
        ASSERT_EQ(f->header->state, STATE_ARCHIVED);
        ASSERT_EQ(f->segmented->disk_header->state, STATE_ARCHIVED);
        assert_file(f, &model);

        ASSERT_NOT_NULL(path = strdup(f->path));
        f = journal_file_offline_close(f);

        g = open_file(m, path, O_RDONLY, /* segmented= */ false, 0);
        ASSERT_EQ(g->header->state, STATE_ARCHIVED);
        ASSERT_EQ(g->segmented->n_indexes, 1U);
        assert_file(g, &model);
        ASSERT_OK(journal_file_verify(g, NULL, NULL, NULL, NULL, false));
        g = journal_file_close(g);
}

TEST(sync_then_archive) {
        test_sync_then_archive_one(/* sync_done= */ true);
        test_sync_then_archive_one(/* sync_done= */ false);
}

TEST(rotate_seqnum_id) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        sd_id128_t other = SD_ID128_MAKE(c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf,c0), id;
        dual_timestamp ts = { .realtime = realtime_base, .monotonic = 5000 };
        struct iovec iovec = IOVEC_MAKE_STRING("MESSAGE=foo");
        JournalFile *f;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        /* The header is never rewritten, so a file refuses entries with another sequence number ID. A
         * rotation with the caller's ID has to take it, or the caller could never write again. */
        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        id = SD_ID128_NULL;
        ASSERT_OK(journal_file_append_entry(f, &ts, &boot_a, &iovec, 1, NULL, &id, NULL, NULL));

        id = other;
        ASSERT_ERROR(journal_file_append_entry(f, &ts, &boot_a, &iovec, 1, NULL, &id, NULL, NULL), EILSEQ);

        ASSERT_OK(journal_file_rotate(&f, m, JOURNAL_COMPRESS, UINT64_MAX, &other, /* deferred_closes= */ NULL));
        ASSERT_OK(journal_file_append_entry(f, &ts, &boot_a, &iovec, 1, NULL, &id, NULL, NULL));
        ASSERT_TRUE(sd_id128_equal(f->header->seqnum_id, other));

        f = journal_file_offline_close(f);
}

static void copy_truncated(const char *from, const char *to, uint64_t size) {
        (void) unlink(to);
        ASSERT_OK(copy_file(from, to, O_EXCL, 0644, /* copy_flags= */ 0));
        ASSERT_OK_ERRNO(truncate(to, size));
}

TEST(truncated) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        _cleanup_free_ uint64_t *sizes = NULL;
        JournalFile *f, *g;
        uint64_t size, n_good = 0;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        /* At least one index, and enough tail behind it */
        for (uint64_t i = 0; i < 1200 || f->segmented->scan_offset - f->segmented->tail_offset < 4000; i++) {
                append_generated(f, &model, i);

                ASSERT_NOT_NULL(GREEDY_REALLOC(sizes, i + 1));
                sizes[i] = f->segmented->scan_offset;
        }

        ASSERT_GE(f->segmented->n_indexes, 1U);
        size = f->segmented->scan_offset;
        f = journal_file_close(f);

        /* Cut the file off at all kinds of places. Whatever is complete has to be there. */
        for (uint64_t cut = size; cut > size - 3000; cut -= cut > size - 300 ? 1 : 29) {
                _cleanup_(model_done) Model expected = {};
                size_t n = 0;
                int r;

                copy_truncated("test.journal", "cut.journal", cut);

                while (n < model.n_entries && sizes[n] <= cut)
                        n++;

                ASSERT_NOT_NULL(expected.entries = new0(char**, n + 1));
                ASSERT_NOT_NULL(expected.realtime = new0(usec_t, n + 1));
                ASSERT_NOT_NULL(expected.monotonic = new0(usec_t, n + 1));
                expected.n_entries = n;
                for (size_t i = 0; i < n; i++) {
                        ASSERT_NOT_NULL(expected.entries[i] = strv_copy(model.entries[i]));
                        expected.realtime[i] = model.realtime[i];
                        expected.monotonic[i] = model.monotonic[i];
                }

                g = open_file(m, "cut.journal", O_RDONLY, /* segmented= */ false, 0);
                assert_file(g, &expected);
                ASSERT_OK(journal_file_verify(g, NULL, NULL, NULL, NULL, false));
                g = journal_file_close(g);

                r = journal_file_open(-EBADF, "cut.journal", O_RDWR, JOURNAL_COMPRESS, 0644, UINT64_MAX, NULL, m, NULL, &g);
                if (r < 0) {
                        ASSERT_ERROR(r, EBADMSG);
                        continue;
                }

                /* The cut was between two objects */
                n_good++;
                assert_file(g, &expected);
                append_generated(g, &expected, 5000);
                assert_file(g, &expected);
                g = journal_file_offline_close(g);
        }

        ASSERT_GT(n_good, 3U);
}

static void flip(const char *path, uint64_t offset) {
        _cleanup_close_ int fd = -EBADF;
        uint8_t b;

        ASSERT_OK_ERRNO(fd = open(path, O_RDWR|O_CLOEXEC));
        ASSERT_EQ(pread(fd, &b, 1, offset), 1);
        b ^= 0x40;
        ASSERT_EQ(pwrite(fd, &b, 1, offset), 1);
}

static void set_synced_index(const char *path, uint64_t offset) {
        _cleanup_close_ int fd = -EBADF;
        le64_t v = htole64(offset);

        ASSERT_OK_ERRNO(fd = open(path, O_WRONLY|O_CLOEXEC));
        ASSERT_EQ(pwrite(fd, &v, sizeof(v), offsetof(Header, synced_index_offset)), (ssize_t) sizeof(v));
}

static bool ok_or_damaged(int r) {
        /* Readers fail on an index whose content is damaged, like on damaged entry arrays of classic files */
        return r >= 0 || r == -EBADMSG;
}

TEST(damaged) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        JournalFile *f, *g;
        SegmentedIndex first, second, older, newest;
        uint64_t size, tail, offset;
        int r;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        for (uint64_t i = 0; i < 5000; i++)
                append_generated(f, &model, i);

        ASSERT_GT(f->segmented->n_indexes, 4U);
        first = f->segmented->indexes[0];
        second = f->segmented->indexes[1];
        older = f->segmented->indexes[f->segmented->n_indexes - 2];
        newest = f->segmented->indexes[f->segmented->n_indexes - 1];
        tail = f->segmented->tail_entries[f->segmented->n_tail_entries / 2];

        /* Syncing and closing write no index, so the file keeps a tail */
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ true));
        size = f->segmented->scan_offset;

        /* The sync made the header name the newest index */
        ASSERT_EQ(le64toh(f->segmented->disk_header->synced_index_offset), newest.offset);
        f = journal_file_close(f);

        /* Damage in the fixed part of an index: readers drop it and the indexes that build on it. */
        FOREACH_ARGUMENT(offset,
                         second.offset + offsetof(IndexObject, n_index_entries),
                         second.offset + offsetof(IndexObject, object.checksum),
                         second.offset + offsetof(IndexObject, data_table_offset),
                         first.offset + offsetof(IndexObject, n_entries)) {

                copy_truncated("test.journal", "damaged.journal", size);
                flip("damaged.journal", offset);

                g = open_file(m, "damaged.journal", O_RDONLY, /* segmented= */ false, 0);
                ASSERT_LT(g->segmented->n_indexes, 2U);
                assert_file(g, &model);
                g = journal_file_close(g);

                /* Writers refuse to continue such a file */
                ASSERT_ERROR(journal_file_open(-EBADF, "damaged.journal", O_RDWR, JOURNAL_COMPRESS, 0644, UINT64_MAX, NULL, m, NULL, &g), EBADMSG);
        }

        /* Damage in the payload of an index that no sync vouches for: caught by the payload checksum on
         * open. */
        for (offset = second.offset + sizeof(IndexObject); offset < second.offset + second.size; offset += 4099) {
                copy_truncated("test.journal", "damaged.journal", size);
                set_synced_index("damaged.journal", 0);
                flip("damaged.journal", offset);

                g = open_file(m, "damaged.journal", O_RDONLY, /* segmented= */ false, 0);
                ASSERT_EQ(g->segmented->n_indexes, 1U);
                assert_file(g, &model);
                g = journal_file_close(g);
        }

        /* The payload of an index that a sync vouches for is trusted. Damage there may or may not be noticed.
         * Reading fails with -EBADMSG when it is noticed. */
        for (offset = second.offset + sizeof(IndexObject); offset < second.offset + second.size; offset += 257) {
                uint64_t p = 0, n = 0;
                Object *o;

                copy_truncated("test.journal", "damaged.journal", size);
                flip("damaged.journal", offset);

                g = open_file(m, "damaged.journal", O_RDONLY, /* segmented= */ false, 0);
                ASSERT_GT(g->segmented->n_indexes, 2U);

                while ((r = journal_file_next_entry(g, p, DIRECTION_DOWN, &o, &p)) > 0)
                        n++;
                ASSERT_TRUE(ok_or_damaged(r));
                ASSERT_LE(n, model.n_entries);

                FOREACH_STRING(match, "_SYSTEMD_UNIT=service3.service", "PRIORITY=5", "NUMBER=1700", "MESSAGE=This is message 3 of 17") {
                        p = 0;

                        do
                                r = journal_file_seek_for_match(g, match, strlen(match), JOURNAL_SEEK_OFFSET, SD_ID128_NULL, p + 1, DIRECTION_DOWN, &o, &p);
                        while (r > 0);
                        ASSERT_TRUE(ok_or_damaged(r));
                }

                SegmentedCursor c = {};
                const void *d;
                size_t l;

                while ((r = segmented_enumerate_fields(g, &c, &d, &l)) > 0)
                        ;
                ASSERT_TRUE(ok_or_damaged(r));

                c = (SegmentedCursor) {};
                while ((r = segmented_enumerate_unique(g, "_SYSTEMD_UNIT", STRLEN("_SYSTEMD_UNIT"), 0, &c, &d, &l)) > 0)
                        ;
                ASSERT_TRUE(ok_or_damaged(r));

                g = journal_file_close(g);
        }

        /* A field name outside of an index that a sync vouches for. Enumeration notices and fails. */
        copy_truncated("test.journal", "damaged.journal", size);
        flip("damaged.journal", second.offset + second.field_table_offset + offsetof(IndexFieldItem, name_offset) + 3);

        g = open_file(m, "damaged.journal", O_RDONLY, /* segmented= */ false, 0);
        FOREACH_STRING(field, "PRIORITY", "_SYSTEMD_UNIT") {
                SegmentedCursor c = {};
                const void *d;
                size_t l;

                while ((r = segmented_enumerate_fields(g, &c, &d, &l)) > 0)
                        ;
                ASSERT_TRUE(ok_or_damaged(r));

                c = (SegmentedCursor) {};
                while ((r = segmented_enumerate_unique(g, field, strlen(field), 0, &c, &d, &l)) > 0)
                        ;
                ASSERT_TRUE(ok_or_damaged(r));
        }
        g = journal_file_close(g);

        /* An index whose record of the file disagrees with the log, under a checksum that matches. Readers
         * trust it, verification must not. */
        copy_truncated("test.journal", "damaged.journal", size);
        {
                _cleanup_close_ int fd = -EBADF;
                IndexObject index;
                Header header;

                ASSERT_OK_ERRNO(fd = open("damaged.journal", O_RDWR|O_CLOEXEC));
                ASSERT_EQ(pread(fd, &header, sizeof(header), 0), (ssize_t) sizeof(header));
                ASSERT_EQ(pread(fd, &index, sizeof(index), second.offset), (ssize_t) sizeof(index));
                index.n_data = htole64(le64toh(index.n_data) - 1);
                index.object.checksum = htole32(segmented_checksum_with_file_id(header.file_id, second.offset, &index, sizeof(index)));
                ASSERT_EQ(pwrite(fd, &index, sizeof(index), second.offset), (ssize_t) sizeof(index));
        }

        g = open_file(m, "damaged.journal", O_RDONLY, /* segmented= */ false, 0);
        ASSERT_FAIL(journal_file_verify(g, NULL, NULL, NULL, NULL, false));
        g = journal_file_close(g);

        /* Damage in the payload of the newest index, which no sync vouches for. Readers skip it, but a
         * writer must not continue a tail that spans two segments. */
        copy_truncated("test.journal", "damaged.journal", size);
        set_synced_index("damaged.journal", older.offset);
        flip("damaged.journal", newest.offset + sizeof(IndexObject) + 1);

        g = open_file(m, "damaged.journal", O_RDONLY, /* segmented= */ false, 0);
        assert_file(g, &model);
        g = journal_file_close(g);

        ASSERT_ERROR(journal_file_open(-EBADF, "damaged.journal", O_RDWR, JOURNAL_COMPRESS, 0644, UINT64_MAX, NULL, m, NULL, &g), EBADMSG);

        /* Damage to an entry in the tail: the entries before it remain readable */
        copy_truncated("test.journal", "damaged.journal", size);
        flip("damaged.journal", tail + offsetof(Object, entry.xor_hash));

        g = open_file(m, "damaged.journal", O_RDONLY, /* segmented= */ false, 0);
        ASSERT_LT(le64toh(g->header->n_entries), model.n_entries);
        ASSERT_GT(le64toh(g->header->n_entries), model.n_entries - 1024);
        model.n_entries = le64toh(g->header->n_entries);
        assert_file(g, &model);
        g = journal_file_close(g);

        r = journal_file_open(-EBADF, "damaged.journal", O_RDWR, JOURNAL_COMPRESS, 0644, UINT64_MAX, NULL, m, NULL, &g);
        ASSERT_ERROR(r, EBADMSG);

        model.n_entries = 5000;
}

TEST(damaged_archived) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        _cleanup_free_ char *path = NULL;
        SegmentedIndex merged;
        JournalFile *f, *g;
        uint64_t size, offset;
        Object *o;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        for (uint64_t i = 0; i < 3000; i++)
                append_generated(f, &model, i);
        ASSERT_GT(f->segmented->n_indexes, 1U);

        ASSERT_OK(journal_file_archive(f, NULL));
        ASSERT_OK(journal_file_set_offline(f, /* wait= */ true));
        ASSERT_NOT_NULL(path = strdup(f->path));
        f = journal_file_offline_close(f);

        g = open_file(m, path, O_RDONLY, /* segmented= */ false, 0);
        ASSERT_EQ(g->segmented->n_indexes, 1U);
        merged = g->segmented->indexes[0];
        size = g->last_stat.st_size;

        /* The header names the merged index and says that the file is archived */
        ASSERT_EQ(le64toh(g->segmented->disk_header->synced_index_offset), merged.offset);
        ASSERT_EQ(g->segmented->disk_header->state, STATE_ARCHIVED);
        g = journal_file_close(g);

        /* Entry offsets in the merged index that point elsewhere. Reading skips the entries or fails, and
         * searches fail or still find what they look for. */
        FOREACH_ARGUMENT(offset,
                         merged.offset + merged.entry_array_offset + 7 * sizeof(le32_t),
                         merged.offset + merged.entry_array_offset + merged.n_index_entries / 2 * sizeof(le32_t) + 3) {
                uint64_t p = 0, n = 0;
                int r;

                copy_truncated(path, "damaged.journal", size);
                flip("damaged.journal", offset);

                g = open_file(m, "damaged.journal", O_RDONLY, /* segmented= */ false, 0);
                ASSERT_EQ(g->header->state, STATE_ARCHIVED);

                while ((r = journal_file_next_entry(g, p, DIRECTION_DOWN, &o, &p)) > 0)
                        n++;
                ASSERT_TRUE(ok_or_damaged(r));
                ASSERT_LE(n, model.n_entries);

                r = journal_file_move_to_entry_by_monotonic(g, boot_a, model.monotonic[model.n_entries - 1], DIRECTION_UP, &o, NULL);
                ASSERT_TRUE(ok_or_damaged(r));

                const char *message = "MESSAGE=This is message 9 of 17";
                r = journal_file_seek_for_match(g, message, strlen(message), JOURNAL_SEEK_MONOTONIC, boot_a,
                                                model.monotonic[merged.n_index_entries / 2], DIRECTION_DOWN, &o, NULL);
                ASSERT_TRUE(ok_or_damaged(r));

                g = journal_file_close(g);
        }

        /* A damaged state in the header. The writer only ever writes STATE_OFFLINE and STATE_ARCHIVED. */
        uint8_t state;
        FOREACH_ARGUMENT(state, STATE_ONLINE, STATE_OFFLINE, _STATE_MAX) {
                _cleanup_close_ int fd = -EBADF;

                copy_truncated(path, "damaged.journal", size);
                ASSERT_OK_ERRNO(fd = open("damaged.journal", O_WRONLY|O_CLOEXEC));
                ASSERT_EQ(pwrite(fd, &(uint8_t) { state }, 1, offsetof(Header, state)), 1);

                g = open_file(m, "damaged.journal", O_RDONLY, /* segmented= */ false, 0);
                assert_file(g, &model);
                ASSERT_EQ(g->header->state, STATE_OFFLINE);
                if (state == STATE_OFFLINE)
                        ASSERT_OK(journal_file_verify(g, NULL, NULL, NULL, NULL, false));
                else
                        ASSERT_ERROR(journal_file_verify(g, NULL, NULL, NULL, NULL, false), EBADMSG);
                g = journal_file_close(g);
        }

        /* A damaged data object loses its value, but not the index that refers to it. */
        const char *number = "NUMBER=77";
        IndexFieldItem field;
        IndexDataItem item;

        g = open_file(m, path, O_RDONLY, /* segmented= */ false, 0);
        ASSERT_OK_POSITIVE(segmented_index_find_field(g, &merged, "NUMBER", STRLEN("NUMBER"), &field));
        ASSERT_OK_POSITIVE(segmented_index_find_data(g, &merged, &field, number, strlen(number),
                                                       journal_file_hash_data(g, number, strlen(number)), &item));
        g = journal_file_close(g);

        copy_truncated(path, "damaged.journal", size);
        flip("damaged.journal", le32toh(item.data_offset) + offsetof(ObjectHeader, type));

        g = open_file(m, "damaged.journal", O_RDONLY, /* segmented= */ false, 0);
        ASSERT_ERROR(journal_file_move_to_object(g, OBJECT_DATA, le32toh(item.data_offset), &o), EBADMSG);
        ASSERT_OK_ZERO(journal_file_seek_for_match(g, number, strlen(number), JOURNAL_SEEK_FIRST, SD_ID128_NULL, 0, DIRECTION_DOWN, &o, NULL));
        ASSERT_EQ(g->segmented->n_indexes, 1U);
        ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_seqnum(g, model.n_entries, DIRECTION_DOWN, &o, NULL));
        ASSERT_EQ(le64toh(o->entry.realtime), model.realtime[model.n_entries - 1]);
        g = journal_file_close(g);

        /* The same data object damaged, and an entry offset in the merged index that refers to a later
         * entry. A match that reads every entry must not crash. */
        copy_truncated(path, "damaged.journal", size);
        flip("damaged.journal", le32toh(item.data_offset) + offsetof(ObjectHeader, type));
        flip("damaged.journal", merged.offset + merged.entry_array_offset + merged.n_index_entries / 2 * sizeof(le32_t) + 3);

        _cleanup_free_ char *inline_match = NULL;
        ASSERT_OK(asprintf(&inline_match, "_SOURCE_REALTIME_TIMESTAMP=%" PRIu64, realtime_base + (model.n_entries - 1) * 10 - 3));

        g = open_file(m, "damaged.journal", O_RDONLY, /* segmented= */ false, 0);
        ASSERT_TRUE(ok_or_damaged(journal_file_seek_for_match(g, inline_match, strlen(inline_match), JOURNAL_SEEK_FIRST, SD_ID128_NULL, 0, DIRECTION_DOWN, &o, NULL)));
        g = journal_file_close(g);
}

TEST(vacuum_empty) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        _cleanup_free_ char *empty = NULL, *full = NULL;
        _cleanup_close_ int fd = -EBADF;
        JournalFile *f;
        struct stat st;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        /* An archived file without entries. The two tags stand in for those of a sealed file. */
        f = open_file(m, "empty.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        ASSERT_OK(journal_file_archive(f, NULL));
        ASSERT_NOT_NULL(empty = strdup(f->path));
        f = journal_file_offline_close(f);

        TagObject tag = {
                .object.type = OBJECT_TAG,
                .object.size = htole64(sizeof(TagObject)),
        };
        ASSERT_OK_ERRNO(fd = open(empty, O_WRONLY|O_APPEND|O_CLOEXEC));
        ASSERT_EQ(write(fd, &tag, sizeof(tag)), (ssize_t) sizeof(tag));
        ASSERT_EQ(write(fd, &tag, sizeof(tag)), (ssize_t) sizeof(tag));

        f = open_file(m, "full.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        append_generated(f, &model, 0);
        ASSERT_OK(journal_file_archive(f, NULL));
        ASSERT_NOT_NULL(full = strdup(f->path));
        f = journal_file_offline_close(f);

        ASSERT_OK(journal_directory_vacuum(directory, UINT64_MAX, 0, 0, NULL, false));
        ASSERT_ERROR_ERRNO(stat(empty, &st), ENOENT);
        ASSERT_OK_ERRNO(stat(full, &st));
}

TEST(damaged_state) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        _cleanup_close_ int fd = -EBADF;
        JournalMetrics metrics = {
                .max_size = 2 * U64_MB,
                .min_size = UINT64_MAX,
                .min_use = UINT64_MAX,
                .n_max_files = UINT64_MAX,
        };
        JournalFile *f;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        append_generated(f, &model, 0);
        f = journal_file_offline_close(f);

        ASSERT_OK_ERRNO(fd = open("test.journal", O_WRONLY|O_CLOEXEC));
        ASSERT_EQ(pwrite(fd, &(uint8_t) { STATE_ONLINE }, 1, offsetof(Header, state)), 1);

        /* Readers ignore the damaged state, a writer does not continue the file */
        f = open_file(m, "test.journal", O_RDONLY, /* segmented= */ false, 0);
        assert_file(f, &model);
        f = journal_file_close(f);

        ASSERT_ERROR(journal_file_open(/* fd= */ -EBADF, "test.journal", O_RDWR, JOURNAL_COMPRESS, 0644,
                                       /* compress_threshold_bytes= */ UINT64_MAX, &metrics, m,
                                       /* template= */ NULL, &f), EBADMSG);

        /* journalctl --verify does not accept extensions it does not know, as for classic files */
        le32_t flags = htole32(UINT32_C(1) << 31);
        ASSERT_EQ(pwrite(fd, &(uint8_t) { STATE_OFFLINE }, 1, offsetof(Header, state)), 1);
        ASSERT_EQ(pwrite(fd, &flags, sizeof(flags), offsetof(Header, compatible_flags)), (ssize_t) sizeof(flags));
        f = open_file(m, "test.journal", O_RDONLY, /* segmented= */ false, 0);
        ASSERT_ERROR(journal_file_verify(f, NULL, NULL, NULL, NULL, false), EOPNOTSUPP);
        f = journal_file_close(f);
}

TEST(refresh_deleted) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        JournalFile *f, *follower;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        append_generated(f, &model, 0);
        follower = open_file(m, "test.journal", O_RDONLY, /* segmented= */ false, 0);

        /* A deleted file can still be read, as with classic files */
        append_generated(f, &model, 1);
        ASSERT_OK_ERRNO(unlink("test.journal"));
        follower->segmented->refresh_pending = true;
        ASSERT_OK_POSITIVE(segmented_refresh(follower, USEC_INFINITY));
        assert_file(follower, &model);

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

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        append_generated(f, &model, 0);

        ASSERT_OK(sd_journal_open_files(&j, (const char*[]) { "test.journal", NULL }, 0));
        SD_JOURNAL_FOREACH_FIELD(j, name)
                ASSERT_FALSE(streq(name, "NEWFIELD"));

        /* Enumeration finds fields that were appended since, as with classic files */
        append(f, NULL, realtime_base + 10, 5010, boot_a, STRV_MAKE("NEWFIELD=1"));
        usleep_safe(2 * SEGMENTED_REFRESH_USEC);

        SD_JOURNAL_FOREACH_FIELD(j, name)
                found = found || streq(name, "NEWFIELD");
        ASSERT_TRUE(found);

        f = journal_file_offline_close(f);
}

TEST(seek_before_first_entry) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        const char *match = "_HOSTNAME=test";
        JournalFile *f;
        Object *o;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        /* An offset within the header of a file without indexes. sd-journal passes the offset of the
         * current entry minus one when it looks for the previous match. */
        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        append_generated(f, &model, 0);
        ASSERT_EQ(f->segmented->n_indexes, 0U);
        ASSERT_OK_ZERO(journal_file_seek_for_match(f, match, strlen(match), JOURNAL_SEEK_OFFSET, SD_ID128_NULL,
                                                   le64toh(f->header->header_size) - 1, DIRECTION_UP, &o, NULL));
        ASSERT_OK_POSITIVE(journal_file_seek_for_match(f, match, strlen(match), JOURNAL_SEEK_OFFSET, SD_ID128_NULL,
                                                       le64toh(f->header->header_size) - 1, DIRECTION_DOWN, &o, NULL));
        f = journal_file_offline_close(f);
}

TEST(seek_tail_live) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_(model_done) Model model = {};
        uint64_t realtime;
        JournalFile *f;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        append_generated(f, &model, 0);

        ASSERT_OK(sd_journal_open_files(&j, (const char*[]) { "test.journal", NULL }, 0));
        ASSERT_OK(sd_journal_seek_tail(j));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));

        /* Seeking finds entries that were appended since, as with classic files, even without
         * sd_journal_process(). */
        append_generated(f, &model, 1);
        usleep_safe(2 * SEGMENTED_REFRESH_USEC);

        ASSERT_OK(sd_journal_seek_tail(j));
        ASSERT_OK_POSITIVE(sd_journal_previous(j));
        ASSERT_OK(sd_journal_get_realtime_usec(j, &realtime));
        ASSERT_EQ(realtime, model.realtime[1]);

        f = journal_file_offline_close(f);
}

TEST(damaged_field_name) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_free_ char *data = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *name, *p;
        size_t size, n = 0;
        JournalFile *f;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        f = open_file(m, "classic.journal", O_RDWR|O_CREAT, /* segmented= */ false, 2 * U64_MB);
        append_generated(f, &model, 0);
        f = journal_file_offline_close(f);

        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        append_generated(f, &model, 1);
        f = journal_file_offline_close(f);

        /* Data objects in the tail whose payloads start with '=' or an invalid field name. Enumeration
         * skips them. An empty name must not be looked up in the classic file. */
        ASSERT_OK(read_full_file("test.journal", &data, &size));
        ASSERT_OK_ERRNO(fd = open("test.journal", O_RDWR|O_CLOEXEC));
        ASSERT_NOT_NULL(p = memmem_safe(data, size, "_HOSTNAME=test", STRLEN("_HOSTNAME=test")));
        ASSERT_EQ(pwrite(fd, "=", 1, p - data), 1);
        ASSERT_NOT_NULL(p = memmem_safe(data, size, "_COMM=service", STRLEN("_COMM=service")));
        ASSERT_EQ(pwrite(fd, "c", 1, p - data + 1), 1);

        ASSERT_OK(sd_journal_open_files(&j, (const char*[]) { "classic.journal", "test.journal", NULL }, 0));
        while (ASSERT_OK(sd_journal_enumerate_fields(j, &name)) > 0)
                n++;
        ASSERT_GT(n, 0U);
}

static uint64_t digest_entry(sd_journal *j) {
        uint64_t realtime, monotonic, h = 0;
        sd_id128_t boot_id;
        const void *data;
        size_t size;

        ASSERT_OK(sd_journal_get_realtime_usec(j, &realtime));
        ASSERT_OK(sd_journal_get_monotonic_usec(j, &monotonic, &boot_id));

        SD_JOURNAL_FOREACH_DATA(j, data, size)
                h += siphash24(data, size, digest_key);

        return h + realtime * 3 + monotonic * 5 + siphash24(&boot_id, sizeof(boot_id), digest_key);
}

typedef struct Query {
        const char * const *matches; /* "" is a disjunction, "+" a conjunction */
        int seek;                    /* 0: head, 1: tail, 2: realtime, 3: monotonic of boot a, 4: monotonic of boot b, 5: cursor */
        uint64_t needle;
        bool backwards;
} Query;

static void run_query(const char *path, const Query *q, const char *cursor, uint64_t **ret, size_t *ret_n, char **ret_cursor) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_free_ uint64_t *digests = NULL;
        size_t n = 0;
        int r;

        ASSERT_OK(sd_journal_open_files(&j, (const char*[]) { path, NULL }, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_set_data_threshold(j, 0));

        STRV_FOREACH(m, (char**) q->matches)
                if (isempty(*m))
                        ASSERT_OK(sd_journal_add_disjunction(j));
                else if (streq(*m, "+"))
                        ASSERT_OK(sd_journal_add_conjunction(j));
                else
                        ASSERT_OK(sd_journal_add_match(j, *m, SIZE_MAX));

        switch (q->seek) {
        case 0:
                ASSERT_OK(sd_journal_seek_head(j));
                break;
        case 1:
                ASSERT_OK(sd_journal_seek_tail(j));
                break;
        case 2:
                ASSERT_OK(sd_journal_seek_realtime_usec(j, q->needle));
                break;
        case 3:
                ASSERT_OK(sd_journal_seek_monotonic_usec(j, boot_a, q->needle));
                break;
        case 4:
                ASSERT_OK(sd_journal_seek_monotonic_usec(j, boot_b, q->needle));
                break;
        case 5:
                ASSERT_OK(sd_journal_seek_cursor(j, cursor));
                break;
        default:
                assert_not_reached();
        }

        /* The first results are what matters for seeking, iteration is covered elsewhere. */
        while (n < 150) {
                r = q->backwards ? sd_journal_previous(j) : sd_journal_next(j);
                ASSERT_OK(r);
                if (r == 0)
                        break;

                ASSERT_NOT_NULL(GREEDY_REALLOC(digests, n + 1));
                digests[n++] = digest_entry(j);

                if (ret_cursor && n == 10)
                        ASSERT_OK(sd_journal_get_cursor(j, ret_cursor));
        }

        *ret = TAKE_PTR(digests);
        *ret_n = n;
}

static void run_unique(const char *path, const char *field, uint64_t *ret_digest, size_t *ret_n) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        uint64_t digest = 0;
        const void *data;
        size_t size, n = 0;
        const char *name;

        ASSERT_OK(sd_journal_open_files(&j, (const char*[]) { path, NULL }, SD_JOURNAL_ASSUME_IMMUTABLE));
        ASSERT_OK(sd_journal_set_data_threshold(j, 0));

        if (field) {
                ASSERT_OK(sd_journal_query_unique(j, field));
                SD_JOURNAL_FOREACH_UNIQUE(j, data, size) {
                        digest += siphash24(data, size, digest_key);
                        n++;
                }
        } else
                SD_JOURNAL_FOREACH_FIELD(j, name) {
                        digest += siphash24_string(name, digest_key);
                        n++;
                }

        /* Enumerating again without a restart starts over, as with classic files */
        size_t again = 0;
        if (field)
                while (ASSERT_OK(sd_journal_enumerate_unique(j, &data, &size)) > 0)
                        again++;
        else
                while (ASSERT_OK(sd_journal_enumerate_fields(j, &name)) > 0)
                        again++;
        ASSERT_EQ(again, n);

        *ret_digest = digest;
        *ret_n = n;
}

static void append_both(JournalFile *classic, JournalFile *segmented, usec_t realtime, usec_t monotonic, sd_id128_t boot_id, char **fields) {
        append(classic, NULL, realtime, monotonic, boot_id, fields);
        append(segmented, NULL, realtime, monotonic, boot_id, fields);
}

static void test_differential_one(bool interleaved) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_free_ char *large = NULL;
        JournalFile *classic, *segmented;
        uint64_t seed = 4711, needle;
        const char *field;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        classic = open_file(m, "classic.journal", O_RDWR|O_CREAT, /* segmented= */ false, 2 * U64_MB);
        segmented = open_file(m, "segmented.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        ASSERT_NULL(classic->segmented);
        ASSERT_NOT_NULL(segmented->segmented);

        ASSERT_NOT_NULL(large = strrep("z", 19999));

        for (uint64_t i = 0; i < 4000; i++) {
                _cleanup_strv_free_ char **fields = NULL;
                unsigned service;
                sd_id128_t boot;
                usec_t monotonic;

                seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
                service = (seed >> 33) % 5;

                /* Either one boot after the other, or two machines that write into the same file */
                if (interleaved)
                        boot = service < 2 ? boot_a : boot_b;
                else
                        boot = i < 2500 ? boot_a : boot_b;
                monotonic = sd_id128_equal(boot, boot_a) ? 100 + i * 10 : 50 + i * 10;

                ASSERT_OK(strv_extendf(&fields, "MESSAGE=Message %" PRIu64, (seed >> 40) % 64));
                ASSERT_OK(strv_extendf(&fields, "PRIORITY=%" PRIu64, (seed >> 20) % 8));
                ASSERT_OK(strv_extendf(&fields, "_PID=%u", 100 + service));
                ASSERT_OK(strv_extendf(&fields, "_COMM=service%u", service));
                ASSERT_OK(strv_extendf(&fields, "_SYSTEMD_UNIT=service%u.service", service));
                ASSERT_OK(strv_extendf(&fields, "_SOURCE_REALTIME_TIMESTAMP=%" PRIu64, 1000000 + i * 10 - 3));
                ASSERT_OK(strv_extendf(&fields, "_BOOT_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(boot)));
                ASSERT_OK(strv_extend(&fields, "_HOSTNAME=test"));
                if (i % 300 == 7)
                        ASSERT_OK(strv_extendf(&fields, "MESSAGE=%s", large));
                if (i % 450 == 9)
                        ASSERT_OK(strv_extendf(&fields, "LARGE=%s", large));

                append_both(classic, segmented, 1000000 + i * 10, monotonic, boot, fields);
        }

        ASSERT_GT(segmented->segmented->n_indexes, 2U);
        ASSERT_GT(segmented->segmented->n_tail_entries, 0U);

        /* Once with a file that is still written to, once with an archived one */
        for (unsigned round = 0; round < 2; round++) {
                const char *a = classic->path, *b = segmented->path;
                _cleanup_free_ char *large_message = NULL, *large_field = NULL;

                ASSERT_NOT_NULL(large_message = strjoin("MESSAGE=", large));
                ASSERT_NOT_NULL(large_field = strjoin("LARGE=", large));

                const char * const * const matches[] = {
                        STRV_MAKE_CONST("_HOSTNAME=test"),
                        STRV_MAKE_CONST("_SYSTEMD_UNIT=service1.service"),
                        STRV_MAKE_CONST("_SYSTEMD_UNIT=service1.service", "_SYSTEMD_UNIT=service4.service"),
                        STRV_MAKE_CONST("_SYSTEMD_UNIT=service1.service", "PRIORITY=3"),
                        STRV_MAKE_CONST("_SYSTEMD_UNIT=service1.service", "PRIORITY=3", "PRIORITY=4", "", "_PID=103", "MESSAGE=Message 7"),
                        STRV_MAKE_CONST("PRIORITY=0", "PRIORITY=1", "+", "_COMM=service0", "_COMM=service2", "", "_PID=104"),
                        STRV_MAKE_CONST("_BOOT_ID=a1a2a3a4a5a6a7a8a9aaabacadaeafa0", "PRIORITY=6"),
                        STRV_MAKE_CONST("MESSAGE=Message 7"),
                        STRV_MAKE_CONST("MESSAGE=Message 7", "MESSAGE=Message 9", "MESSAGE=Message 100"),
                        STRV_MAKE_CONST("MESSAGE=Message 7", "_PID=101"),
                        STRV_MAKE_CONST(large_message),
                        STRV_MAKE_CONST(large_field),
                        STRV_MAKE_CONST("_SOURCE_REALTIME_TIMESTAMP=1019997"),
                        STRV_MAKE_CONST("_SOURCE_REALTIME_TIMESTAMP=1019997", "_SOURCE_REALTIME_TIMESTAMP=1000007", "_SOURCE_REALTIME_TIMESTAMP=5"),
                        STRV_MAKE_CONST("_SOURCE_REALTIME_TIMESTAMP=1019997", "", "_PID=102", "PRIORITY=2"),
                        STRV_MAKE_CONST("_PID=999"),
                        STRV_MAKE_CONST("NOSUCHFIELD=1"),
                        STRV_MAKE_CONST("NOSUCHFIELD=1", "", "_PID=100"),
                        NULL,
                };

                for (size_t k = 0; k < ELEMENTSOF(matches); k++)
                        for (int seek = 0; seek <= 5; seek++)
                                for (int backwards = 0; backwards <= 1; backwards++)
                                        FOREACH_ARGUMENT(needle, UINT64_C(1000000) + 17 * 10 + 5, UINT64_C(1000000) + 2600 * 10, UINT64_C(100) + 1234 * 10, UINT64_C(50) + 3000 * 10 + 1, UINT64_C(1) << 30) {
                                                _cleanup_free_ uint64_t *x = NULL, *y = NULL;
                                                _cleanup_free_ char *cursor = NULL;
                                                size_t n_x, n_y;
                                                Query q = {
                                                        .matches = matches[k],
                                                        .seek = seek,
                                                        .needle = needle,
                                                        .backwards = backwards,
                                                };

                                                if (seek == 5) {
                                                        /* Take a cursor from the middle of the results */
                                                        Query c = q;
                                                        c.seek = 0;
                                                        c.backwards = false;

                                                        run_query(a, &c, NULL, &x, &n_x, &cursor);
                                                        x = mfree(x);
                                                        if (!cursor)
                                                                break;
                                                }

                                                /* With entries of several boots in arbitrary order,
                                                 * seeking by monotonic time with more than one value may
                                                 * give a different result, see JOURNAL_SEGMENTED.md. */
                                                if (interleaved && IN_SET(seek, 3, 4) && strv_length((char**) matches[k]) > 1)
                                                        break;

                                                log_debug("round=%u matches=%zu seek=%i backwards=%i needle=%" PRIu64, round, k, seek, backwards, needle);

                                                run_query(a, &q, cursor, &x, &n_x, NULL);
                                                run_query(b, &q, cursor, &y, &n_y, NULL);

                                                ASSERT_EQ(n_x, n_y);
                                                ASSERT_EQ(memcmp_nn(x, n_x * sizeof(uint64_t), y, n_y * sizeof(uint64_t)), 0);

                                                if (IN_SET(seek, 0, 1, 5))
                                                        break; /* these do not take a needle */
                                        }

                FOREACH_ARGUMENT(field, "MESSAGE", "_PID", "_SOURCE_REALTIME_TIMESTAMP", "LARGE", "NOSUCHFIELD", (const char*) NULL) {
                        uint64_t x, y;
                        size_t n_x, n_y;

                        run_unique(a, field, &x, &n_x);
                        run_unique(b, field, &y, &n_y);

                        ASSERT_EQ(n_x, n_y);
                        ASSERT_EQ(x, y);
                }

                if (round > 0)
                        break;

                ASSERT_OK(journal_file_archive(classic, NULL));
                ASSERT_OK(journal_file_archive(segmented, NULL));
                ASSERT_OK(journal_file_set_offline(classic, /* wait= */ true));
                ASSERT_OK(journal_file_set_offline(segmented, /* wait= */ true));
        }

        classic = journal_file_offline_close(classic);
        segmented = journal_file_offline_close(segmented);
}

TEST(differential) {
        test_differential_one(/* interleaved= */ false);
        test_differential_one(/* interleaved= */ true);
}

TEST(copy) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        JournalFile *classic, *segmented, *copy;
        uint64_t p = 0;
        Object *o;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        segmented = open_file(m, "segmented.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        for (uint64_t i = 0; i < 1500; i++)
                append_generated(segmented, &model, i);

        /* From segmented to classic, and back */
        classic = open_file(m, "classic.journal", O_RDWR|O_CREAT, /* segmented= */ false, 64 * U64_MB);
        ASSERT_NULL(classic->segmented);
        for (size_t i = 0; i < model.n_entries; i++) {
                ASSERT_OK_POSITIVE(journal_file_next_entry(segmented, p, DIRECTION_DOWN, &o, &p));
                ASSERT_OK(journal_file_copy_entry(segmented, classic, o, p, NULL, NULL));
        }
        assert_file(classic, &model);

        copy = open_file(m, "copy.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        p = 0;
        for (size_t i = 0; i < model.n_entries; i++) {
                ASSERT_OK_POSITIVE(journal_file_next_entry(classic, p, DIRECTION_DOWN, &o, &p));
                ASSERT_OK(journal_file_copy_entry(classic, copy, o, p, NULL, NULL));
        }
        assert_file(copy, &model);

        classic = journal_file_offline_close(classic);
        segmented = journal_file_offline_close(segmented);
        copy = journal_file_offline_close(copy);
}

TEST(batch) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(model_done) Model model = {};
        JournalFile *f, *g;

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());
        ASSERT_OK(sd_event_new(&e));

        /* With a post-change timer, entries are written when the timer fires. The event loop never runs
         * here, so the test calls journal_file_post_change() itself. */
        f = open_file(m, "test.journal", O_RDWR|O_CREAT, /* segmented= */ true, 2 * U64_MB);
        ASSERT_OK(journal_file_enable_post_change_timer(f, e, 250 * USEC_PER_MSEC));

        /* Values repeat within the batch, among them large ones that are compressed */
        for (uint64_t i = 0; i < 150; i++)
                append_generated(f, &model, i);

        g = open_file(m, "test.journal", O_RDONLY, /* segmented= */ false, 0);
        ASSERT_EQ(le64toh(g->header->n_entries), 0U);
        g = journal_file_close(g);

        journal_file_post_change(f);
        assert_file(f, &model);

        g = open_file(m, "test.journal", O_RDONLY, /* segmented= */ false, 0);
        assert_file(g, &model);
        g = journal_file_close(g);

        /* A batch larger than the limit is written right away */
        for (uint64_t i = 150; i < 3000; i++)
                append_generated(f, &model, i);

        g = open_file(m, "test.journal", O_RDONLY, /* segmented= */ false, 0);
        ASSERT_GT(le64toh(g->header->n_entries), 150U);
        ASSERT_LT(le64toh(g->header->n_entries), model.n_entries);
        g = journal_file_close(g);

        /* Closing writes the rest */
        f = journal_file_offline_close(f);

        g = open_file(m, "test.journal", O_RDONLY, /* segmented= */ false, 0);
        assert_file(g, &model);
        ASSERT_OK(journal_file_verify(g, NULL, NULL, NULL, NULL, false));
        g = journal_file_close(g);
}

TEST(sealed) {
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(model_done) Model model = {};
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_free_ char *fss = NULL;
        JournalFile *f;
        JournalMetrics metrics = {
                .max_size = 2 * U64_MB,
                .min_size = UINT64_MAX,
                .min_use = UINT64_MAX,
                .n_max_files = UINT64_MAX,
        };
        const char *key;
        usec_t from, to, total;
        sd_id128_t machine;
        uint64_t size, offset;
        int r;

        /* The sealing key lives in /var/log/journal, which is usually not writable. Hence only run if a key
         * was prepared and $SYSTEMD_TEST_FSS_KEY holds its verification key. */

        key = getenv("SYSTEMD_TEST_FSS_KEY");
        ASSERT_OK(sd_id128_get_machine(&machine));
        ASSERT_OK_ERRNO(asprintf(&fss, "/var/log/journal/" SD_ID128_FORMAT_STR "/fss", SD_ID128_FORMAT_VAL(machine)));
        if (!key || access(fss, R_OK) < 0 || !journal_auth_supported()) {
                log_tests_skipped("No sealing key or no sealing support");
                return;
        }

        setup(&directory);
        ASSERT_NOT_NULL(m = mmap_cache_new());

        /* Tags vouch for the time the entries were written, hence use the real time */
        realtime_base = now(CLOCK_REALTIME);

        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_SEGMENTED", "1", 1));
        ASSERT_OK(journal_file_open(-EBADF, "test.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS|JOURNAL_SEAL, 0644, UINT64_MAX, &metrics, m, NULL, &f));
        ASSERT_NOT_NULL(f->segmented);
        ASSERT_TRUE(JOURNAL_HEADER_SEALED(f->header));
        ASSERT_EQ(le64toh(f->header->n_tags), 1U);

        /* Batch the entries, so that tags are appended while entries are not written yet */
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(journal_file_enable_post_change_timer(f, e, 250 * USEC_PER_MSEC));

        for (uint64_t i = 0; i < 1500; i++) {
                append_generated(f, &model, i);

                if (i % 500 == 0) {
                        /* Span a few epochs. Entry timestamps have to follow the clock. */
                        (void) usleep_safe(USEC_PER_SEC);
                        realtime_base += USEC_PER_SEC;
                }
        }

        ASSERT_GT(f->segmented->n_indexes, 0U);
        journal_file_post_change(f);
        assert_file(f, &model);
        f = journal_file_offline_close(f);

        /* Continuing a sealed file requires a tag at its end. Close without appending another one: two
         * tags with the same epoch fail verification, for either format. */
        ASSERT_OK(journal_file_open(-EBADF, "test.journal", O_RDWR, JOURNAL_COMPRESS|JOURNAL_SEAL, 0644, UINT64_MAX, &metrics, m, NULL, &f));
        assert_file(f, &model);
        f = journal_file_close(f);

        ASSERT_OK(journal_file_open(-EBADF, "test.journal", O_RDONLY, 0, 0644, UINT64_MAX, NULL, m, NULL, &f));
        ASSERT_GT(le64toh(f->header->n_tags), 2U);
        ASSERT_OK(journal_file_verify(f, key, &from, &to, &total, false));
        ASSERT_EQ(from, model.realtime[0]);
        ASSERT_GT(to, 0U);
        size = f->segmented->scan_offset;
        f = journal_file_close(f);

        /* Damage things in the covered part, and see whether that is noticed */
        FOREACH_ARGUMENT(offset, size - 100, size / 2, size / 3, size / 5 + 7) {
                copy_truncated("test.journal", "damaged.journal", size);
                flip("damaged.journal", offset);

                r = journal_file_open(-EBADF, "damaged.journal", O_RDONLY, 0, 0644, UINT64_MAX, NULL, m, NULL, &f);
                if (r < 0) {
                        ASSERT_ERROR(r, EBADMSG);
                        continue;
                }

                ASSERT_FAIL(journal_file_verify(f, key, NULL, NULL, NULL, false));
                f = journal_file_close(f);
        }

        /* A file that does not end with a tag is not continued */
        copy_truncated("test.journal", "cut.journal", size - sizeof(TagObject));
        ASSERT_ERROR(journal_file_open(-EBADF, "cut.journal", O_RDWR, JOURNAL_COMPRESS|JOURNAL_SEAL, 0644, UINT64_MAX, NULL, m, NULL, &f), EBUSY);

        ASSERT_OK_ERRNO(unsetenv("SYSTEMD_JOURNAL_SEGMENTED"));
        realtime_base = 1000000;
}

static int intro(void) {
        /* journal_file_open() requires a valid machine id */
        if (sd_id128_get_machine(NULL) < 0)
                return log_tests_skipped("No valid machine ID found");

        journal_auth_init();

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
