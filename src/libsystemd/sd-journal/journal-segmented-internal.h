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
int segmented_index_payload_verify(JournalFile *f, const SegmentedIndex *i);
