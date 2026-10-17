/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "journal-test-util.h"
#include "random-util.h"
#include "siphash24.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

static const uint8_t generate_key[16] = {
        0x74, 0x65, 0x73, 0x74, 0x2d, 0x61, 0x70, 0x70, 0x65, 0x6e, 0x64, 0x2d, 0x6f, 0x6e, 0x6c, 0x79,
};

void model_done(Model *m) {
        assert(m);

        FOREACH_ARRAY(e, m->entries, m->n_entries)
                strv_free(*e);

        free(m->entries);
        free(m->realtime);
        free(m->monotonic);
}

bool journal_test_setup(char **ret_directory) {
        assert(ret_directory);

        /* journal_file_open() requires a valid machine ID */
        if (sd_id128_get_machine(NULL) < 0) {
                (void) log_tests_skipped("No valid machine ID found");
                return false;
        }

        ASSERT_OK(mkdtemp_malloc("/var/tmp/journal-test-XXXXXX", ret_directory));
        ASSERT_OK_ERRNO(chdir(*ret_directory));
        return true;
}

JournalFile* journal_test_open(MMapCache *m, const char *name, int flags, uint64_t max_size) {
        JournalMetrics metrics = {
                .max_size = max_size,
                .min_size = UINT64_MAX,
                .max_use = 0,
                .min_use = UINT64_MAX,
                .keep_free = 0,
                .n_max_files = UINT64_MAX,
        };
        JournalFile *f;

        assert(m);
        assert(name);

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

void model_append(JournalFile *f, Model *model, usec_t realtime, usec_t monotonic, sd_id128_t boot_id, char **fields) {
        _cleanup_free_ struct iovec *iovec = NULL;
        dual_timestamp ts = {
                .realtime = realtime,
                .monotonic = monotonic,
        };
        size_t n = 0;

        assert(f);

        ASSERT_NOT_NULL(iovec = new(struct iovec, strv_length(fields)));

        STRV_FOREACH(i, fields)
                iovec[n++] = IOVEC_MAKE_STRING(*i);

        ASSERT_OK(journal_file_append_entry(f, &ts, &boot_id, iovec, n,
                                            /* seqnum= */ NULL, /* seqnum_id= */ NULL,
                                            /* ret_object= */ NULL, /* ret_offset= */ NULL));

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

void model_append_generated(JournalFile *f, Model *model, uint64_t i) {
        _cleanup_strv_free_ char **fields = NULL;
        unsigned service = i % 7 == 0 ? 3 : (i / 5) % 4;

        assert(f);

        /* A couple of services that log in bursts, with metadata that does not change */

        ASSERT_OK(strv_extendf(&fields, "MESSAGE=This is message %" PRIu64 " of 17", i % 17 == 0 ? i : i % 17));
        ASSERT_OK(strv_extendf(&fields, "PRIORITY=%" PRIu64, i % 3 + 4));
        ASSERT_OK(strv_extendf(&fields, "SYSLOG_IDENTIFIER=service%u", service));
        ASSERT_OK(strv_extendf(&fields, "NUMBER=%" PRIu64, i));
        ASSERT_OK(strv_extendf(&fields, "_PID=%u", 100 + service));
        ASSERT_OK(strv_extendf(&fields, "_UID=%u", service == 0 ? 1000U : 0U));
        ASSERT_OK(strv_extendf(&fields, "_COMM=service%u", service));
        ASSERT_OK(strv_extendf(&fields, "_SYSTEMD_UNIT=service%u.service", service));
        ASSERT_OK(strv_extendf(&fields, "_SOURCE_REALTIME_TIMESTAMP=%" PRIu64, MODEL_REALTIME_BASE + i * 10 - 3));
        ASSERT_OK(strv_extendf(&fields, "_BOOT_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(MODEL_BOOT_A)));
        ASSERT_OK(strv_extend(&fields, "_HOSTNAME=test"));

        if (i % 50 == 0) {
                _cleanup_free_ char *large = NULL;

                /* Large values: one that compresses well, one that compresses poorly */
                ASSERT_NOT_NULL(large = strrep("x", 3999));
                ASSERT_OK(strv_extendf(&fields, "LARGE=%s%" PRIu64, large, i % 100));

                for (size_t k = 0; k < 3999; k++)
                        large[k] = 'a' + (siphash24(&k, sizeof(k), generate_key) + i % 200) % 26;
                ASSERT_OK(strv_extendf(&fields, "RANDOM=%s", large));
        }

        model_append(f, model, MODEL_REALTIME_BASE + i * 10, 5000 + i * 10, MODEL_BOOT_A, fields);
}

void model_assert_entry(JournalFile *f, Object *o, uint64_t offset, const Model *model, size_t i) {
        _cleanup_strv_free_ char **fields = NULL;
        uint64_t n;

        assert(f);
        assert(o);
        assert(model);

        ASSERT_LT(i, model->n_entries);
        ASSERT_EQ(o->object.type, OBJECT_ENTRY);
        ASSERT_EQ(le64toh(o->entry.realtime), model->realtime[i]);

        ASSERT_OK(journal_file_entry_n_fields(f, o, offset, &n));

        for (uint64_t k = 0; k < n; k++) {
                const void *data;
                size_t size;

                ASSERT_OK(journal_file_move_to_object(f, OBJECT_ENTRY, offset, &o));
                ASSERT_OK_POSITIVE(journal_file_entry_field_payload(f, o, offset, k, /* field= */ NULL, /* field_length= */ 0,
                                                                    &data, &size));
                char *copy = ASSERT_NOT_NULL(strndup(data, size));
                ASSERT_OK(strv_consume(&fields, copy));
        }

        strv_sort(fields);
        ASSERT_TRUE(strv_equal(fields, model->entries[i]));
}

static bool model_matches(const Model *model, size_t i, const char *match) {
        return !match || strv_contains(model->entries[i], match);
}

static int seek_next(JournalFile *f, const char *match, direction_t direction, Object **o, uint64_t *p) {
        assert(f);
        assert(p);

        if (!match)
                return journal_file_next_entry(f, *p, direction, o, p);
        if (*p == 0)
                return journal_file_seek_for_match(f, match, strlen(match), JOURNAL_SEEK_FIRST, /* boot_id= */ SD_ID128_NULL,
                                                   /* needle= */ 0, direction, o, p);

        return journal_file_seek_for_match(f, match, strlen(match), JOURNAL_SEEK_OFFSET, /* boot_id= */ SD_ID128_NULL,
                                           direction == DIRECTION_DOWN ? *p + 1 : *p - 1, direction, o, p);
}

void model_assert_file(JournalFile *f, const Model *model) {
        static const char * const matches[] = {
                NULL,
                "_SYSTEMD_UNIT=service3.service",
                "_UID=1000",
                "PRIORITY=5",                            /* frequent */
                "NUMBER=77",                             /* once */
                "NUMBER=100000000",                      /* never */
                "MESSAGE=This is message 3 of 17",
                "MESSAGE=This is message 170 of 17",
                "_SOURCE_REALTIME_TIMESTAMP=1000697",
                "_HOSTNAME=test",                        /* all */
                "NOSUCHFIELD=1",
        };
        uint64_t p;
        Object *o;
        size_t i;

        assert(f);
        assert(model);

        ASSERT_EQ(le64toh(f->header->n_entries), model->n_entries);

        /* Forwards and backwards, without and with matches */
        FOREACH_ELEMENT(match, matches) {
                for (i = 0, p = 0; i < model->n_entries; i++) {
                        if (!model_matches(model, i, *match))
                                continue;

                        ASSERT_OK_POSITIVE(seek_next(f, *match, DIRECTION_DOWN, &o, &p));
                        model_assert_entry(f, o, p, model, i);
                }

                ASSERT_OK_ZERO(seek_next(f, *match, DIRECTION_DOWN, &o, &p));

                for (i = model->n_entries, p = 0; i > 0; i--) {
                        if (!model_matches(model, i - 1, *match))
                                continue;

                        ASSERT_OK_POSITIVE(seek_next(f, *match, DIRECTION_UP, &o, &p));
                        model_assert_entry(f, o, p, model, i - 1);
                }

                ASSERT_OK_ZERO(seek_next(f, *match, DIRECTION_UP, &o, &p));
        }

        /* Seeking */
        for (unsigned k = 0; k < 50 && model->n_entries > 0; k++) {
                i = random_u64_range(model->n_entries);

                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_realtime(f, model->realtime[i], DIRECTION_DOWN, &o, &p));
                model_assert_entry(f, o, p, model, i);
                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_realtime(f, model->realtime[i] - 1, DIRECTION_DOWN, &o, &p));
                model_assert_entry(f, o, p, model, i);
                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_realtime(f, model->realtime[i] + 1, DIRECTION_UP, &o, &p));
                model_assert_entry(f, o, p, model, i);

                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_seqnum(f, i + 1, DIRECTION_DOWN, &o, &p));
                model_assert_entry(f, o, p, model, i);
                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_seqnum(f, i + 1, DIRECTION_UP, &o, &p));
                model_assert_entry(f, o, p, model, i);

                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_monotonic(f, MODEL_BOOT_A, model->monotonic[i], DIRECTION_DOWN, &o, &p));
                model_assert_entry(f, o, p, model, i);

                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_offset(f, p, DIRECTION_DOWN, &o, &p));
                model_assert_entry(f, o, p, model, i);
                ASSERT_OK_POSITIVE(journal_file_move_to_entry_by_offset(f, p + 1, DIRECTION_UP, &o, &p));
                model_assert_entry(f, o, p, model, i);
        }

        if (model->n_entries > 0) {
                ASSERT_OK_ZERO(journal_file_move_to_entry_by_realtime(f, model->realtime[model->n_entries - 1] + 1, DIRECTION_DOWN, &o, &p));
                ASSERT_OK_ZERO(journal_file_move_to_entry_by_realtime(f, model->realtime[0] - 1, DIRECTION_UP, &o, &p));
                ASSERT_OK_ZERO(journal_file_move_to_entry_by_monotonic(f, MODEL_BOOT_B, 0, DIRECTION_DOWN, &o, &p));
        }
}
