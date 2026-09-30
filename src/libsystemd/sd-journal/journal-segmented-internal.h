/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journal-segmented.h"

uint64_t segmented_hash2(JournalFile *f, const void *data, size_t size);
uint64_t segmented_process_hash(const void *data, size_t size);
uint32_t segmented_checksum_with_file_id(sd_id128_t file_id, uint64_t offset, const void *object, size_t size);
uint32_t segmented_payload_checksum(sd_id128_t file_id, const void *payload, size_t size);
int segmented_data_payload_equal(JournalFile *f, uint64_t offset, const void *data, size_t size);
void segmented_header_add_object(Header *h, uint8_t type, uint64_t offset, uint64_t end);
void segmented_header_add_entry(Header *h, uint64_t offset, uint64_t seqnum, uint64_t realtime, uint64_t monotonic, sd_id128_t boot_id);

int segmented_index_entry_offset(JournalFile *f, const SegmentedIndex *i, uint64_t local, uint64_t *ret);
int segmented_entry_at(JournalFile *f, uint64_t ordinal, Object **ret_object, uint64_t *ret_offset);
int segmented_index_field(JournalFile *f, const SegmentedIndex *i, uint32_t k, IndexFieldItem *ret);
int segmented_index_field_name(JournalFile *f, const SegmentedIndex *i, const IndexFieldItem *item, const void **ret);
int segmented_index_data(JournalFile *f, const SegmentedIndex *i, uint32_t k, IndexDataItem *ret);
int segmented_index_postings(JournalFile *f, const SegmentedIndex *i, const IndexDataItem *item, PostingDecoder *ret);
int segmented_index_find_field(JournalFile *f, const SegmentedIndex *i, const void *name, size_t size, IndexFieldItem *ret);
int segmented_index_find_data(JournalFile *f, const SegmentedIndex *i, const IndexFieldItem *field, const void *data, size_t size, uint64_t hash, IndexDataItem *ret);
int segmented_index_has_unindexed(JournalFile *f, const SegmentedIndex *i, uint64_t hash);
int segmented_index_payload_verify(JournalFile *f, const SegmentedIndex *i);

/* An index before it is serialized. index_builder_finish() sorts it the way the format requires. */

typedef struct IndexBuilderData {
        uint64_t hash;
        uint64_t hash2;
        uint64_t data_offset;
        uint64_t n_entries;
        PostingEncoding encoding;
        void *postings;          /* for POSTING_INLINE this is unused, and 'ordinal' is set instead */
        size_t postings_size;
        uint64_t ordinal;
        uint32_t field;          /* position in the fields array */
} IndexBuilderData;

typedef struct IndexBuilderField {
        uint64_t hash;
        const char *name;
        size_t name_size;
        uint32_t flags;
        uint32_t first_data;     /* position of the first data item of the field, once sorted */
        uint32_t n_data;
} IndexBuilderField;

typedef struct IndexBuilder {
        uint32_t *entries;
        size_t n_entries;

        IndexBuilderData *data;
        size_t n_data;

        IndexBuilderField *fields;
        size_t n_fields;

        uint64_t *unindexed;
        size_t n_unindexed;
} IndexBuilder;

void index_builder_done(IndexBuilder *b);
int index_builder_add_postings(IndexBuilder *b, IndexBuilderData *d, PostingEncoder *e);
int index_builder_finish(IndexBuilder *b);
int index_builder_serialize(
                IndexBuilder *b,
                const Header *header,   /* the state of the file at the offset of the index */
                uint64_t offset,
                uint64_t head_offset,
                void **ret,
                size_t *ret_size);

int segmented_index_merge(
                int fd,
                const Header *header,
                const SegmentedIndex *indexes,
                size_t n_indexes,
                uint64_t offset,
                void **ret,
                size_t *ret_size);

int segmented_writer_open(JournalFile *f, bool newly_created);
void segmented_writer_close(JournalFile *f);
