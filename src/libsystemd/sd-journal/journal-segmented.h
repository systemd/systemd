/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journal-file.h"
#include "journal-postings.h"

/* The segmented journal file format, see docs/JOURNAL_SEGMENTED.md. */

typedef struct Match Match;
typedef struct SegmentedWriter SegmentedWriter;

/* Inline values have to be smaller than this */
#define SEGMENTED_INLINE_SIZE_MAX 256U

/* Readers refresh a file at most this often, unless inotify says it changed */
#define SEGMENTED_REFRESH_USEC (10 * USEC_PER_MSEC)

#define SEGMENTED_RESULTS_MAX 4U

typedef struct SegmentedIndex {
        uint64_t offset;
        uint64_t size;
        uint64_t head_offset;
        uint64_t n_entries;      /* entries of the file up to the index */
        uint64_t first_ordinal;  /* ordinal of the first entry of the segment */

        uint32_t n_index_entries;
        uint32_t entry_array_offset;
        uint32_t n_fields;
        uint32_t field_table_offset;
        uint32_t n_data_items;
        uint32_t data_table_offset;
        uint32_t n_unindexed;
        uint32_t unindexed_offset;
        uint32_t payload_checksum;
} SegmentedIndex;

typedef enum SegmentedFieldType {
        SEGMENTED_FIELD_DATA,
        SEGMENTED_FIELD_INLINE,
} SegmentedFieldType;

typedef struct SegmentedField {
        SegmentedFieldType type;
        uint64_t offset; /* of the data object, or of the InlineData structure */
} SegmentedField;

typedef struct SegmentedResult {
        uint64_t key[2];
        uint64_t last_used;
        bool used;

        uint64_t n_evaluated; /* the ordinals below this are covered by the bitmaps */
        bool exact;           /* if false, candidates need to be verified before they are returned */
        PostingBitmap candidates;
        PostingBitmap verified;

        /* For each value of the match expression, in the order they appear in it */
        uint64_t *hashes;
        uint64_t *confirmed; /* offset of a data object known to have this value, or 0 */
        size_t n_values;

        /* For a single value, so that the result can be rebuilt without the match */
        char *value;
        size_t value_size;
} SegmentedResult;

typedef struct SegmentedDataHash {
        uint64_t offset;
        uint64_t hash;
} SegmentedDataHash;

#define SEGMENTED_DATA_HASHES_MAX 1024U

/* The two kinds of keys for match results: expressions of sd_journal objects are identified by a counter,
 * single values by their hash. */
#define SEGMENTED_KEY_EXPRESSION UINT64_C(1)
#define SEGMENTED_KEY_VALUE UINT64_C(2)

typedef struct Segmented {
        Header *disk_header;

        /* The live indexes, ordered by offset */
        SegmentedIndex *indexes;
        size_t n_indexes;

        /* Changes whenever live indexes are replaced, which moves the positions of the others */
        unsigned indexes_generation;

        /* The tail. Its first entry has the ordinal n_indexed_entries. */
        uint64_t n_indexed_entries;
        uint64_t tail_offset;  /* the newest index, which counts as the first tail object, or the end of the header */
        uint64_t scan_offset;  /* where scanning continues */
        uint32_t *tail_entries;
        size_t n_tail_entries;

        usec_t last_refresh_usec;
        bool refresh_pending;

        /* The entry that was loaded last */
        uint64_t current_offset;
        uint64_t current_ordinal;

        /* The fields of the entry at fields_offset */
        uint64_t fields_offset;

        /* The entry whose items were checked last. sd-journal loads an entry again for each field. */
        uint64_t checked_entry_offset;
        SegmentedField *fields;
        size_t n_fields;

        uint8_t *inline_buffer;
        SegmentedDataHash *data_hashes;

        SegmentedResult results[SEGMENTED_RESULTS_MAX];
        uint64_t result_counter;

        SegmentedWriter *writer;
} Segmented;

bool segmented_requested(void);

/* Low level */
uint64_t segmented_object_size_min(uint8_t type);
uint32_t segmented_checksum(JournalFile *f, uint64_t offset, const void *object, size_t size);
size_t segmented_checked_size(const ObjectHeader *h);
int segmented_check_object(JournalFile *f, Object *o, uint64_t offset, size_t available);
int segmented_index_parse(JournalFile *f, const IndexObject *o, uint64_t offset, SegmentedIndex *ret);

/* Opening, closing, and refreshing */
int segmented_open(JournalFile *f, bool newly_created);
void segmented_close(JournalFile *f);
int segmented_verify_header(JournalFile *f);
int segmented_refresh(JournalFile *f, usec_t ts);

/* Entries */
int segmented_entry_field_payload(
                JournalFile *f,
                Object *o,
                uint64_t offset,
                uint64_t i,
                const char *field,
                size_t field_length,
                size_t data_threshold,
                const void **ret_data,
                size_t *ret_size);

typedef enum SegmentedKey {
        SEGMENTED_KEY_SEQNUM,
        SEGMENTED_KEY_REALTIME,
        SEGMENTED_KEY_MONOTONIC,
} SegmentedKey;

uint64_t segmented_n_entries(JournalFile *f);
int segmented_entry_load(JournalFile *f, uint64_t ordinal, direction_t direction, Object **ret_object, uint64_t *ret_offset);
int segmented_bisect(JournalFile *f, SegmentedKey key, uint64_t needle, const PostingBitmap *among, direction_t direction, uint64_t *ret);
int segmented_entry_fields(JournalFile *f, Object *o, uint64_t offset, const SegmentedField **ret, size_t *ret_n);
int segmented_inline_payload(JournalFile *f, uint64_t offset, const char *field, size_t field_length, const void **ret_data, size_t *ret_size);
int segmented_entry_ordinal(JournalFile *f, uint64_t offset, direction_t direction, uint64_t *ret);
int segmented_next_entry(JournalFile *f, uint64_t p, direction_t direction, Object **ret_object, uint64_t *ret_offset);
int segmented_move_to_entry_by_seqnum(JournalFile *f, uint64_t seqnum, direction_t direction, Object **ret_object, uint64_t *ret_offset);
int segmented_move_to_entry_by_realtime(JournalFile *f, uint64_t realtime, direction_t direction, Object **ret_object, uint64_t *ret_offset);
int segmented_move_to_entry_by_monotonic(JournalFile *f, sd_id128_t boot_id, uint64_t monotonic, direction_t direction, Object **ret_object, uint64_t *ret_offset);

/* Matches */
void segmented_result_done(SegmentedResult *result);
int segmented_seek(
                JournalFile *f,
                Match *m,
                const uint64_t key[static 2],
                JournalSeek where,
                sd_id128_t boot_id,
                uint64_t needle,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset);
int segmented_move_to_entry_for_match(
                JournalFile *f,
                const void *data,
                uint64_t size,
                JournalSeek where,
                sd_id128_t boot_id,
                uint64_t needle,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset);

int segmented_get_cutoff_monotonic_usec(JournalFile *f, sd_id128_t boot_id, usec_t *ret_from, usec_t *ret_to);

/* Cursor for enumerating fields and the values of a field. Opaque, starts out zeroed. */
typedef struct SegmentedCursor {
        unsigned generation;
        uint64_t stage;
        uint64_t index;
        uint64_t position;
        uint64_t item;
} SegmentedCursor;

int segmented_enumerate_fields(JournalFile *f, SegmentedCursor *c, const void **ret_name, size_t *ret_size);
int segmented_enumerate_unique(
                JournalFile *f,
                const char *field,
                size_t field_length,
                size_t data_threshold,
                SegmentedCursor *c,
                const void **ret_data,
                size_t *ret_size);

/* Writing */
int segmented_append_entry(
                JournalFile *f,
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const struct iovec iovec[],
                size_t n_iovec,
                uint64_t *seqnum,
                sd_id128_t *seqnum_id,
                Object **ret_object,
                uint64_t *ret_offset);
int segmented_append_tag(JournalFile *f, TagObject *tag);
int segmented_checkpoint(JournalFile *f);
int segmented_flush(JournalFile *f);

/* The steps of journal_file_set_offline(). Only segmented_offline() may run in the offline thread. It
 * returns true if it archived the file. */
void segmented_offline_prepare(JournalFile *f);
bool segmented_offline(JournalFile *f);
int segmented_offline_finish(JournalFile *f);
