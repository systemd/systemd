/* SPDX-License-Identifier: LGPL-2.1-or-later */


#include "alloc-util.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-internal.h"
#include "journal-segmented.h"
#include "journal-segmented-internal.h"
#include "log.h"
#include "memory-util.h"

#ifdef __clang__
#  pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

/* Reading indexes */

static int index_map(JournalFile *f, const SegmentedIndex *i, ObjectType type, uint64_t offset, uint64_t size, void **ret) {
        assert(f);
        assert(i);

        if (offset > i->size || size > i->size - offset)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Index at %" PRIu64 " of %s refers to something outside of itself.",
                                       i->offset, f->path);

        return journal_file_move_to(f, type, /* keep_always= */ false, i->offset + offset, size, ret);
}

int segmented_index_field(JournalFile *f, const SegmentedIndex *i, uint32_t k, IndexFieldItem *ret) {
        IndexFieldItem *item;
        int r;

        assert(ret);

        if (k >= i->n_fields)
                return -EADDRNOTAVAIL;

        r = index_map(f, i, OBJECT_INDEX, i->field_table_offset + (uint64_t) k * sizeof(IndexFieldItem), sizeof(IndexFieldItem), (void**) &item);
        if (r < 0)
                return r;

        *ret = *item;
        return 0;
}

int segmented_index_field_name(JournalFile *f, const SegmentedIndex *i, const IndexFieldItem *item, const void **ret) {
        int r;

        assert(item);
        assert(ret);

        if (le32toh(item->name_size) == 0)
                return -EBADMSG;

        r = index_map(f, i, OBJECT_INDEX, le32toh(item->name_offset), le32toh(item->name_size), (void**) ret);
        if (r < 0)
                return r;

        if (!journal_field_valid(*ret, le32toh(item->name_size), /* allow_protected= */ true))
                return -EBADMSG;

        return 0;
}

int segmented_index_find_field(
                JournalFile *f,
                const SegmentedIndex *i,
                const void *name,
                size_t size,
                IndexFieldItem *ret) {

        uint64_t hash = journal_file_hash_data(f, name, size);
        uint32_t left = 0, right = i->n_fields;
        int r;

        while (left < right) {
                uint32_t m = left + (right - left) / 2;
                IndexFieldItem item;

                r = segmented_index_field(f, i, m, &item);
                if (r < 0)
                        return r;

                if (le64toh(item.hash) < hash)
                        left = m + 1;
                else
                        right = m;
        }

        for (; left < i->n_fields; left++) {
                IndexFieldItem item;
                const void *p;

                r = segmented_index_field(f, i, left, &item);
                if (r < 0)
                        return r;

                if (le64toh(item.hash) != hash)
                        break;

                if (le32toh(item.name_size) != size)
                        continue;

                r = segmented_index_field_name(f, i, &item, &p);
                if (r < 0)
                        return r;

                if (memcmp(p, name, size) != 0)
                        continue;

                if (ret)
                        *ret = item;
                return 1;
        }

        return 0;
}

int segmented_index_data(JournalFile *f, const SegmentedIndex *i, uint32_t k, IndexDataItem *ret) {
        IndexDataItem *item;
        int r;

        assert(ret);

        if (k >= i->n_data_items)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Index at %" PRIu64 " of %s refers to a value it does not have.",
                                       i->offset, f->path);

        r = index_map(f, i, OBJECT_INDEX, i->data_table_offset + (uint64_t) k * sizeof(IndexDataItem), sizeof(IndexDataItem), (void**) &item);
        if (r < 0)
                return r;

        *ret = *item;
        return 0;
}

int segmented_data_payload_equal(JournalFile *f, uint64_t offset, const void *data, size_t size) {
        const void *d;
        size_t l;
        int r;

        r = journal_file_data_payload(f, /* o= */ NULL, offset, /* field= */ NULL, 0, /* data_threshold= */ 0, &d, &l);
        if (r < 0)
                return r;

        return memcmp_nn(data, size, d, l) == 0;
}

int segmented_index_find_data(
                JournalFile *f,
                const SegmentedIndex *i,
                const IndexFieldItem *field,
                const void *data,
                size_t size,
                uint64_t hash,
                IndexDataItem *ret) {

        uint32_t left, right;
        uint64_t hash2;
        int r;

        assert(field);

        /* The values of a field are together in the data table, sorted by hash */

        left = le32toh(field->first_data);
        right = le32toh(field->n_data);

        if (left > i->n_data_items || right > i->n_data_items - left)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Index at %" PRIu64 " of %s has a field with invalid values.", i->offset, f->path);

        right += left;

        uint32_t end = right;
        while (left < right) {
                uint32_t m = left + (right - left) / 2;
                IndexDataItem item;

                r = segmented_index_data(f, i, m, &item);
                if (r < 0)
                        return r;

                if (le64toh(item.hash) < hash)
                        left = m + 1;
                else
                        right = m;
        }

        hash2 = segmented_hash2(f, data, size);

        for (; left < end; left++) {
                IndexDataItem item;

                r = segmented_index_data(f, i, left, &item);
                if (r < 0)
                        return r;

                if (le64toh(item.hash) != hash)
                        break;
                if (le64toh(item.hash2) != hash2)
                        continue;

                if (le32toh(item.data_offset) >= i->offset)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Index at %" PRIu64 " of %s refers to data it does not cover.",
                                               i->offset, f->path);

                /* The file ID that keys the hashes is not secret, so a collision can be crafted. A damaged
                 * data object only loses its value, the index is fine. */
                r = segmented_data_payload_equal(f, le32toh(item.data_offset), data, size);
                if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL))
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (ret)
                        *ret = item;
                return 1;
        }

        return 0;
}

int segmented_index_postings(JournalFile *f, const SegmentedIndex *i, const IndexDataItem *item, PostingDecoder *ret) {
        PostingEncoding encoding;
        uint64_t size;
        void *p = NULL;
        int r;

        assert(item);
        assert(ret);

        encoding = le32toh(item->postings_size) >> INDEX_POSTINGS_ENCODING_SHIFT;
        size = le32toh(item->postings_size) & INDEX_POSTINGS_SIZE_MASK;

        if (encoding == POSTING_INLINE) {
                if (le32toh(item->n_entries) != 1)
                        return -EBADMSG;
        } else if (size > 0) {
                r = index_map(f, i, OBJECT_ENTRY_ARRAY, le32toh(item->postings_offset), size, &p);
                if (r < 0)
                        return r;
        }

        return posting_decoder_init(ret, encoding, p, size, le32toh(item->postings_offset), i->n_index_entries);
}

/* Walking the log */

static int walk(JournalFile *f, uint64_t *p, uint64_t end, ObjectHeader *ret, uint64_t *ret_offset) {
        ObjectHeader *h;
        uint64_t size;
        int r;

        assert(f);
        assert(p);
        assert(ret);
        assert(ret_offset);

        end = MIN(end, (uint64_t) f->last_stat.st_size);

        if (*p > end || end - *p < sizeof(ObjectHeader))
                return 0;

        r = journal_file_move_to(f, OBJECT_UNUSED, /* keep_always= */ false, *p, sizeof(ObjectHeader), (void**) &h);
        if (r < 0)
                return r;

        size = le64toh(READ_NOW(h->size));
        if (!IN_SET(h->type, OBJECT_DATA, OBJECT_ENTRY, OBJECT_TAG, OBJECT_CONTEXT, OBJECT_INDEX) ||
            size < sizeof(ObjectHeader) ||
            size > end - *p)
                return 0;

        *ret = *h;
        *ret_offset = *p;
        *p += ALIGN64(size);
        return 1;
}

static int data_hash(JournalFile *f, uint64_t offset, uint64_t *ret) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        SegmentedDataHash *c;
        Object *o;
        int r;

        assert(ret);

        if (!a->data_hashes) {
                a->data_hashes = new0(SegmentedDataHash, SEGMENTED_DATA_HASHES_MAX);
                if (!a->data_hashes)
                        return -ENOMEM;
        }

        c = a->data_hashes + (offset / 8) % SEGMENTED_DATA_HASHES_MAX;
        if (c->offset == offset) {
                *ret = c->hash;
                return 0;
        }

        r = journal_file_move_to_object(f, OBJECT_DATA, offset, &o);
        if (r < 0)
                return r;

        *c = (SegmentedDataHash) {
                .offset = offset,
                .hash = le64toh(o->segmented_data.hash),
        };

        *ret = c->hash;
        return 0;
}

/* Match expressions */

void segmented_result_done(SegmentedResult *result) {
        assert(result);

        posting_bitmap_done(&result->candidates);
        free(result->hashes);
        free(result->confirmed);
        free(result->value);

        *result = (SegmentedResult) {};
}

static int result_add_values(JournalFile *f, SegmentedResult *result, Match *m) {
        int r;

        assert(result);
        assert(m);

        if (m->type != MATCH_DISCRETE) {
                LIST_FOREACH(matches, i, m->matches) {
                        r = result_add_values(f, result, i);
                        if (r < 0)
                                return r;
                }

                return 0;
        }

        if (!GREEDY_REALLOC(result->hashes, result->n_values + 1) ||
            !GREEDY_REALLOC(result->confirmed, result->n_values + 1))
                return -ENOMEM;

        result->hashes[result->n_values] = journal_file_hash_data(f, m->data, m->size);
        result->confirmed[result->n_values] = 0;
        result->n_values++;
        return 0;
}

static void bitmap_combine(PostingBitmap *a, const PostingBitmap *b, bool intersect) {
        assert(a);
        assert(b);
        assert(a->n_bits == b->n_bits);

        for (size_t i = 0; i < POSTING_BITMAP_WORDS(a->n_bits); i++)
                if (intersect)
                        a->words[i] &= b->words[i];
                else
                        a->words[i] |= b->words[i];
}

static void bitmap_merge_shifted(PostingBitmap *to, uint64_t offset, const PostingBitmap *from, uint64_t skip) {
        assert(to);
        assert(from);

        /* Sets all bits of 'from' that are not below 'skip' in 'to', moved up by 'offset'. */

        for (uint64_t w = skip / 64; w < POSTING_BITMAP_WORDS(from->n_bits); w++) {
                uint64_t x = from->words[w], p = offset + w * 64;

                if (w == skip / 64 && skip % 64 != 0)
                        x &= UINT64_MAX << (skip % 64);
                if (x == 0)
                        continue;

                to->words[p / 64] |= x << (p % 64);
                if (p % 64 != 0 && (x >> (64 - p % 64)) != 0)
                        to->words[p / 64 + 1] |= x >> (64 - p % 64);
        }
}

static int evaluate_index(
                JournalFile *f,
                const SegmentedIndex *i,
                SegmentedResult *result,
                Match *m,
                size_t *value,
                PostingBitmap *ret) {

        int r;

        assert(m);
        assert(value);
        assert(ret);

        /* Sets the bits of the matching entries in 'ret', by ordinal relative to the segment. 'ret' must be
         * zeroed and have one bit per entry of the segment. */

        if (m->type == MATCH_DISCRETE) {
                uint64_t hash = result->hashes[(*value)++];
                IndexFieldItem field;
                IndexDataItem item;
                PostingDecoder d;
                const char *e;

                e = memchr(m->data, '=', m->size);
                if (!e)
                        return 0;

                r = segmented_index_find_field(f, i, m->data, e - m->data, &field);
                if (r <= 0)
                        return r;

                r = segmented_index_find_data(f, i, &field, m->data, m->size, hash, &item);
                if (r <= 0)
                        return r;

                r = segmented_index_postings(f, i, &item, &d);
                if (r < 0)
                        return r;

                uint64_t n;
                r = posting_decoder_to_bitmap(&d, ret, &n);
                if (r < 0)
                        return r;

                if (n != le32toh(item.n_entries))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Index at %" PRIu64 " of %s has posting list of wrong size.",
                                               i->offset, f->path);

                return 0;
        }

        bool first = true;

        LIST_FOREACH(matches, c, m->matches) {
                _cleanup_(posting_bitmap_done) PostingBitmap b = {};

                if (first) {
                        r = evaluate_index(f, i, result, c, value, ret);
                        if (r < 0)
                                return r;

                        first = false;
                        continue;
                }

                r = posting_bitmap_resize(&b, ret->n_bits);
                if (r < 0)
                        return r;

                r = evaluate_index(f, i, result, c, value, &b);
                if (r < 0)
                        return r;

                bitmap_combine(ret, &b, m->type == MATCH_AND_TERM);
        }

        return 0;
}

typedef struct EntryFields {
        const SegmentedField *fields;
        uint64_t *hashes;
        size_t n_fields;
} EntryFields;

static int evaluate_entry(
                JournalFile *f,
                SegmentedResult *result,
                const EntryFields *e,
                Match *m,
                size_t *value) {

        int r;

        assert(e);
        assert(m);
        assert(value);

        /* Checks the fields of the entry itself. Returns > 0 if it matches. */

        if (m->type == MATCH_DISCRETE) {
                size_t v = (*value)++;

                for (size_t i = 0; i < e->n_fields; i++) {
                        if (e->hashes[i] != result->hashes[v])
                                continue;

                        if (result->confirmed[v] == e->fields[i].offset)
                                return 1;

                        r = segmented_data_payload_equal(f, e->fields[i].offset, m->data, m->size);
                        if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL))
                                continue;
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                result->confirmed[v] = e->fields[i].offset;
                                return 1;
                        }
                }

                return 0;
        }

        /* No short circuit: each value has to advance 'value', even if the outcome is known. */
        bool all = true, any = false, empty = true;

        LIST_FOREACH(matches, c, m->matches) {
                r = evaluate_entry(f, result, e, c, value);
                if (r < 0)
                        return r;

                empty = false;
                all = all && r > 0;
                any = any || r > 0;
        }

        if (empty)
                return 0;

        return m->type == MATCH_AND_TERM ? all : any;
}

static int evaluate_ordinal(JournalFile *f, SegmentedResult *result, Match *m, uint64_t ordinal) {
        _cleanup_free_ uint64_t *hashes = NULL;
        EntryFields e = {};
        size_t value = 0;
        uint64_t p;
        Object *o;
        int r;

        /* Returns > 0 if the entry matches, 0 if it does not or if it cannot be read. */

        r = segmented_entry_at(f, ordinal, &o, &p);
        if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL))
                return 0;
        if (r < 0)
                return r;

        r = segmented_entry_fields(f, o, p, &e.fields, &e.n_fields);
        if (r < 0)
                return r;

        hashes = new(uint64_t, e.n_fields);
        if (!hashes)
                return -ENOMEM;

        for (size_t i = 0; i < e.n_fields; i++) {
                hashes[i] = 0;

                r = data_hash(f, e.fields[i].offset, hashes + i);
                if (r < 0 && !IN_SET(r, -EBADMSG, -EADDRNOTAVAIL))
                        return r;
        }

        e.hashes = hashes;

        return evaluate_entry(f, result, &e, m, &value);
}

static Match* result_match(SegmentedResult *result, Match *m, Match *storage) {
        assert(result);
        assert(storage);

        /* A result for a single value keeps a copy of it, so it can be rebuilt without the match */

        if (m || !result->value)
                return m;

        *storage = (Match) {
                .type = MATCH_DISCRETE,
                .data = result->value,
                .size = result->value_size,
        };

        return storage;
}

static int result_extend(JournalFile *f, SegmentedResult *result, Match *m) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint64_t n;
        Match storage;
        int r;

        assert(result);

        m = ASSERT_PTR(result_match(result, m, &storage));

        n = segmented_n_entries(f);

        if (result->n_evaluated >= n)
                return 0;

        r = posting_bitmap_resize(&result->candidates, n);
        if (r < 0)
                return r;

        for (size_t k = 0; k < a->n_indexes; k++) {
                _cleanup_(posting_bitmap_done) PostingBitmap b = {};
                const SegmentedIndex *i = a->indexes + k;
                size_t value = 0;
                uint64_t skip;

                if (i->n_entries <= result->n_evaluated || i->n_index_entries == 0)
                        continue;

                r = posting_bitmap_resize(&b, i->n_index_entries);
                if (r < 0)
                        return r;

                r = evaluate_index(f, i, result, m, &value, &b);
                if (r < 0)
                        return r;

                skip = LESS_BY(result->n_evaluated, i->first_ordinal);

                bitmap_merge_shifted(&result->candidates, i->first_ordinal, &b, skip);
                result->n_evaluated = i->n_entries;
        }

        for (uint64_t o = MAX(result->n_evaluated, a->n_indexed_entries); o < n; o++) {
                r = evaluate_ordinal(f, result, m, o);
                if (r < 0)
                        return r;
                if (r > 0)
                        posting_bitmap_set_range(&result->candidates, o, 1);
        }

        result->n_evaluated = n;
        return 0;
}

static int result_acquire(JournalFile *f, Match *m, const uint64_t key[static 2], SegmentedResult **ret) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        SegmentedResult *result = NULL;
        int r;

        assert(m);
        assert(key);
        assert(ret);

        FOREACH_ELEMENT(i, a->results) {
                if (i->used && i->key[0] == key[0] && i->key[1] == key[1]) {
                        result = i;
                        break;
                }

                if (!result || !i->used || (result->used && i->last_used < result->last_used))
                        result = result && !result->used ? result : i;
        }

        if (!result->used || result->key[0] != key[0] || result->key[1] != key[1]) {
                segmented_result_done(result);

                result->used = true;
                result->key[0] = key[0];
                result->key[1] = key[1];

                r = result_add_values(f, result, m);
                if (r < 0) {
                        segmented_result_done(result);
                        return r;
                }

                if (m->type == MATCH_DISCRETE) {
                        result->value = memdup_suffix0(m->data, m->size);
                        if (!result->value) {
                                segmented_result_done(result);
                                return -ENOMEM;
                        }

                        result->value_size = m->size;
                }
        }

        result->last_used = ++a->result_counter;

        r = result_extend(f, result, m);
        if (r < 0) {
                /* The result might be partially built */
                segmented_result_done(result);
                return r;
        }

        *ret = result;
        return 0;
}

static bool result_find(const SegmentedResult *result, uint64_t from, direction_t direction, uint64_t *ret) {
        assert(result);
        assert(ret);

        /* Finds the first match at or after 'from', or with DIRECTION_UP the last one at or before it. */

        if (direction == DIRECTION_DOWN)
                return posting_bitmap_find_first(&result->candidates, from, UINT64_MAX, ret);

        return posting_bitmap_find_last(&result->candidates, 0, from == UINT64_MAX ? from : from + 1, ret);
}

static int result_ensure(JournalFile *f, SegmentedResult *result, Match *m, SegmentedResult *among) {
        int r;

        assert(result);

        /* Extends the results to the entries that were found since they were built */

        if (result->n_evaluated < segmented_n_entries(f)) {
                r = result_extend(f, result, m);
                if (r < 0)
                        return r;
        }

        if (among && among->n_evaluated < segmented_n_entries(f)) {
                r = result_extend(f, among, /* m= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int result_load(
                JournalFile *f,
                SegmentedResult *result,
                Match *m,
                SegmentedResult *among,
                uint64_t from,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        uint64_t o;
        int r;

        /* Like result_find(), but returns the entry, and skips entries that can't be read or that are not
         * in 'among'. */

        r = result_ensure(f, result, m, among);
        if (r < 0)
                return r;

        for (;;) {
                if (!result_find(result, from, direction, &o))
                        return 0;

                if (!among || posting_bitmap_isset(&among->candidates, o)) {
                        r = segmented_entry_at(f, o, ret_object, ret_offset);
                        if (r >= 0)
                                return 1;
                        if (!IN_SET(r, -EBADMSG, -EADDRNOTAVAIL))
                                return r;
                }

                if (direction == DIRECTION_DOWN)
                        from = o + 1;
                else {
                        if (o == 0)
                                return 0;
                        from = o - 1;
                }
        }
}

static int boot_acquire(JournalFile *f, sd_id128_t boot_id, SegmentedResult **ret) {
        char t[STRLEN("_BOOT_ID=") + SD_ID128_STRING_MAX] = "_BOOT_ID=";
        SegmentedResult *result;
        int r;

        sd_id128_to_string(boot_id, t + STRLEN("_BOOT_ID="));

        Match m = {
                .type = MATCH_DISCRETE,
                .data = t,
                .size = strlen(t),
        };
        uint64_t key[2] = {
                SEGMENTED_KEY_VALUE,
                segmented_process_hash(m.data, m.size),
        };

        r = result_acquire(f, &m, key, &result);
        if (r < 0)
                return r;

        *ret = result;
        return 0;
}

static int bisect_monotonic(
                JournalFile *f,
                sd_id128_t boot_id,
                uint64_t needle,
                direction_t direction,
                SegmentedResult **ret_boot,
                uint64_t *ret) {

        SegmentedResult *boot;
        int r;

        r = boot_acquire(f, boot_id, &boot);
        if (r < 0)
                return r;

        r = segmented_bisect(f, SEGMENTED_KEY_MONOTONIC, needle, &boot->candidates, direction, ret);
        if (r < 0)
                return r;

        *ret_boot = boot;
        return r;
}

int segmented_move_to_entry_by_monotonic(
                JournalFile *f,
                sd_id128_t boot_id,
                uint64_t monotonic,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        SegmentedResult *boot;
        uint64_t o;
        int r;

        r = bisect_monotonic(f, boot_id, monotonic, direction, &boot, &o);
        if (r <= 0)
                return r;

        return result_load(f, boot, /* m= */ NULL, /* among= */ NULL, o, direction, ret_object, ret_offset);
}

int segmented_get_cutoff_monotonic_usec(JournalFile *f, sd_id128_t boot_id, usec_t *ret_from, usec_t *ret_to) {
        SegmentedResult *boot;
        Object *o;
        int r;

        r = boot_acquire(f, boot_id, &boot);
        if (r < 0)
                return r;

        if (ret_from) {
                r = result_load(f, boot, /* m= */ NULL, /* among= */ NULL, 0, DIRECTION_DOWN, &o, NULL);
                if (r <= 0)
                        return r;

                *ret_from = le64toh(o->entry.monotonic);
        }

        if (ret_to) {
                r = result_load(f, boot, /* m= */ NULL, /* among= */ NULL, UINT64_MAX, DIRECTION_UP, &o, NULL);
                if (r <= 0)
                        return r;

                *ret_to = le64toh(o->entry.monotonic);
        }

        return 1;
}

static int seek(
                JournalFile *f,
                SegmentedResult *result,
                Match *m,
                JournalSeek where,
                sd_id128_t boot_id,
                uint64_t needle,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        SegmentedResult *boot = NULL;
        uint64_t o;
        int r;

        switch (where) {

        case JOURNAL_SEEK_FIRST:
                o = direction == DIRECTION_DOWN ? 0 : UINT64_MAX;
                r = 1;
                break;

        case JOURNAL_SEEK_OFFSET:
                r = segmented_entry_ordinal(f, needle, direction, &o);
                break;

        case JOURNAL_SEEK_SEQNUM:
                r = segmented_bisect(f, SEGMENTED_KEY_SEQNUM, needle, /* among= */ NULL, direction, &o);
                break;

        case JOURNAL_SEEK_REALTIME:
                r = segmented_bisect(f, SEGMENTED_KEY_REALTIME, needle, /* among= */ NULL, direction, &o);
                break;

        case JOURNAL_SEEK_MONOTONIC:
                r = bisect_monotonic(f, boot_id, needle, direction, &boot, &o);
                break;

        default:
                assert_not_reached();
        }
        if (r <= 0)
                return r;

        return result_load(f, result, m, boot, o, direction, ret_object, ret_offset);
}

int segmented_seek(
                JournalFile *f,
                Match *m,
                const uint64_t key[static 2],
                JournalSeek where,
                sd_id128_t boot_id,
                uint64_t needle,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        SegmentedResult *result;
        int r;

        r = result_acquire(f, m, key, &result);
        if (r < 0)
                return r;

        return seek(f, result, m, where, boot_id, needle, direction, ret_object, ret_offset);
}

int segmented_move_to_entry_for_match(
                JournalFile *f,
                const void *data,
                uint64_t size,
                JournalSeek where,
                sd_id128_t boot_id,
                uint64_t needle,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        assert(data || size == 0);

        Match m = {
                .type = MATCH_DISCRETE,
                .data = (char*) data,
                .size = size,
        };

        return segmented_seek(f, &m, (const uint64_t[2]) { SEGMENTED_KEY_VALUE, segmented_process_hash(data, size) },
                                where, boot_id, needle, direction, ret_object, ret_offset);
}

/* Enumeration */

enum {
        STAGE_INDEXES,
        STAGE_TAIL,
        STAGE_DONE,
};

static int enumerate_objects(
                JournalFile *f,
                SegmentedCursor *c,
                uint64_t end,
                const char *field,
                size_t field_length,
                size_t data_threshold,
                const void **ret_data,
                size_t *ret_size) {

        int r;

        /* Returns the payload of the next data object in the range [c->position, end). If a field is
         * specified, only the values of this field are returned. */

        for (;;) {
                uint64_t p = c->position, q;
                ObjectHeader h;

                r = walk(f, &p, end, &h, &q);
                if (r <= 0)
                        return r;

                c->position = p;

                if (h.type != OBJECT_DATA)
                        continue;

                /* Classic files only read the values of the requested field, and take field names from
                 * field objects. This walk reads all data objects, so skip the ones that cannot be read. */
                r = journal_file_data_payload_pinned(f, q, field, field_length, data_threshold, ret_data, ret_size);
                if (r < 0 && r != -ENOMEM)
                        continue;
                if (r != 0)
                        return r;
        }
}

static void cursor_check(Segmented *a, SegmentedCursor *c) {
        assert(a);
        assert(c);

        /* Positions refer to the live indexes, hence start over if those changed. The caller removes
         * values that are returned twice. */
        if (c->generation != a->indexes_generation)
                *c = (SegmentedCursor) {
                        .generation = a->indexes_generation,
                };
}

static void cursor_next_stage(SegmentedCursor *c) {
        assert(c);

        c->index = 0;
        c->position = 0;
        c->stage++;
}

int segmented_enumerate_fields(JournalFile *f, SegmentedCursor *c, const void **ret_name, size_t *ret_size) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        int r;

        assert(c);
        assert(ret_name);
        assert(ret_size);

        /* A field might be returned more than once. */

        cursor_check(a, c);

        if (c->stage == STAGE_INDEXES) {
                for (; c->index < a->n_indexes; c->index++, c->position = 0) {
                        const SegmentedIndex *i = a->indexes + c->index;
                        IndexFieldItem item;

                        if (c->position >= i->n_fields)
                                continue;

                        r = segmented_index_field(f, i, c->position++, &item);
                        if (r >= 0)
                                r = segmented_index_field_name(f, i, &item, ret_name);
                        if (r < 0)
                                return r;

                        *ret_size = le32toh(item.name_size);
                        return 1;
                }

                cursor_next_stage(c);
                c->position = a->tail_offset;
        }

        if (c->stage == STAGE_TAIL) {
                const void *d;
                const char *e;
                size_t l;

                for (;;) {
                        r = enumerate_objects(f, c, a->scan_offset, /* field= */ NULL, 0, /* data_threshold= */ 0, &d, &l);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        /* The payload may be damaged, readers do not check its hash */
                        e = memchr(d, '=', l);
                        if (!e || !journal_field_valid(d, e - (const char*) d, /* allow_protected= */ true))
                                continue;

                        *ret_name = d;
                        *ret_size = e - (const char*) d;
                        return 1;
                }

                cursor_next_stage(c);
        }

        return 0;
}

int segmented_enumerate_unique(
                JournalFile *f,
                const char *field,
                size_t field_length,
                size_t data_threshold,
                SegmentedCursor *c,
                const void **ret_data,
                size_t *ret_size) {

        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        int r;

        assert(field);
        assert(c);
        assert(ret_data);
        assert(ret_size);

        /* A value might be returned more than once. */

        cursor_check(a, c);

        if (c->stage == STAGE_INDEXES) {
                for (; c->index < a->n_indexes; c->index++, c->position = 0) {
                        const SegmentedIndex *i = a->indexes + c->index;
                        IndexFieldItem item;

                        r = segmented_index_find_field(f, i, field, field_length, &item);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        while (c->position < le32toh(item.n_data)) {
                                IndexDataItem data;

                                r = segmented_index_data(f, i, le32toh(item.first_data) + c->position, &data);
                                if (r < 0)
                                        return r;

                                c->position++;

                                r = journal_file_data_payload_pinned(
                                                f,
                                                le32toh(data.data_offset),
                                                field, field_length,
                                                data_threshold,
                                                ret_data, ret_size);
                                if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL))
                                        continue;
                                if (r != 0)
                                        return r;
                        }
                }

                cursor_next_stage(c);
                c->position = a->tail_offset;
        }

        if (c->stage == STAGE_TAIL) {
                r = enumerate_objects(f, c, a->scan_offset, field, field_length, data_threshold, ret_data, ret_size);
                if (r != 0)
                        return r;

                cursor_next_stage(c);
        }

        return 0;
}
