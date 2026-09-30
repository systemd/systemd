/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "hash-funcs.h"
#include "journal-def.h"
#include "journal-segmented-internal.h"
#include "memory-util.h"
#include "prioq.h"
#include "sort-util.h"
#include "unaligned.h"

#ifdef __clang__
#  pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

void index_builder_done(IndexBuilder *b) {
        assert(b);

        FOREACH_ARRAY(d, b->data, b->n_data)
                free(d->postings);

        free(b->entries);
        free(b->data);
        free(b->fields);

        *b = (IndexBuilder) {};
}

int index_builder_add_postings(IndexBuilder *b, IndexBuilderData *d, PostingEncoder *e) {
        int r;

        assert(b);
        assert(d);
        assert(e);

        /* Picks the smallest encoding. Might take over the buffer of the encoder, which the caller still
         * has to free with posting_encoder_done(). */

        r = posting_encoder_finish(e);
        if (r < 0)
                return r;

        d->n_entries = e->n_postings;

        if (e->n_postings == 1) {
                assert(e->previous_end > 0);

                d->encoding = POSTING_INLINE;
                d->ordinal = e->previous_end - 1;
                return 0;
        }

        if (e->size <= POSTING_BITMAP_BYTES(b->n_entries)) {
                d->encoding = POSTING_RLE;
                d->postings = TAKE_PTR(e->buffer);
                d->postings_size = e->size;
                return 0;
        }

        _cleanup_(posting_bitmap_done) PostingBitmap bitmap = {};
        PostingDecoder decoder;

        r = posting_bitmap_resize(&bitmap, b->n_entries);
        if (r < 0)
                return r;

        r = posting_decoder_init(&decoder, POSTING_RLE, e->buffer, e->size, 0, b->n_entries);
        if (r < 0)
                return r;

        r = posting_decoder_to_bitmap(&decoder, &bitmap, /* ret_n= */ NULL);
        if (r < 0)
                return r;

        for (size_t i = 0; i < POSTING_BITMAP_WORDS(bitmap.n_bits); i++)
                bitmap.words[i] = htole64(bitmap.words[i]);

        d->encoding = POSTING_BITMAP;
        d->postings = TAKE_PTR(bitmap.words);
        d->postings_size = POSTING_BITMAP_BYTES(b->n_entries);
        return 0;
}

static int builder_data_compare(const IndexBuilderData *a, const IndexBuilderData *b) {
        int r;

        r = CMP(a->field, b->field);
        if (r != 0)
                return r;

        r = CMP(a->hash, b->hash);
        if (r != 0)
                return r;

        return CMP(a->hash2, b->hash2);
}

static int builder_field_compare(const IndexBuilderField *a, const IndexBuilderField *b) {
        int r;

        r = CMP(a->hash, b->hash);
        if (r != 0)
                return r;

        return memcmp_nn(a->name, a->name_size, b->name, b->name_size);
}

int index_builder_finish(IndexBuilder *b) {
        _cleanup_free_ uint32_t *positions = NULL;

        assert(b);

        /* Data items refer to their field by position, so track where each field ends up after sorting. */

        positions = new(uint32_t, b->n_fields);
        if (!positions)
                return -ENOMEM;

        FOREACH_ARRAY(field, b->fields, b->n_fields)
                field->first_data = field - b->fields; /* temporarily the position before sorting */

        typesafe_qsort(b->fields, b->n_fields, builder_field_compare);

        FOREACH_ARRAY(field, b->fields, b->n_fields) {
                positions[field->first_data] = field - b->fields;
                field->first_data = field->n_data = 0;
        }

        FOREACH_ARRAY(d, b->data, b->n_data) {
                assert(d->field < b->n_fields);
                d->field = positions[d->field];
        }

        typesafe_qsort(b->data, b->n_data, builder_data_compare);

        FOREACH_ARRAY(d, b->data, b->n_data) {
                IndexBuilderField *field = b->fields + d->field;

                if (field->n_data == 0)
                        field->first_data = d - b->data;
                field->n_data++;
        }

        /* Fields without values point to where their values would be */
        uint32_t next = 0;
        FOREACH_ARRAY(field, b->fields, b->n_fields) {
                if (field->n_data == 0)
                        field->first_data = next;
                next = field->first_data + field->n_data;
        }

        return 0;
}

int index_builder_serialize(
                IndexBuilder *b,
                const Header *header,
                uint64_t offset,
                uint64_t head_offset,
                void **ret,
                size_t *ret_size) {

        uint64_t size, entry_array_offset, field_table_offset, names_offset, data_table_offset,
                postings_offset, p;
        _cleanup_free_ uint8_t *buffer = NULL;
        IndexObject *o;

        assert(b);
        assert(header);
        assert(ret);
        assert(ret_size);

        size = sizeof(IndexObject);

        entry_array_offset = size;
        size += ALIGN64(b->n_entries * sizeof(le32_t));

        field_table_offset = size;
        size += b->n_fields * sizeof(IndexFieldItem);

        names_offset = size;
        FOREACH_ARRAY(i, b->fields, b->n_fields)
                size += i->name_size;
        size = ALIGN64(size);

        data_table_offset = size;
        size += b->n_data * sizeof(IndexDataItem);

        postings_offset = size;
        FOREACH_ARRAY(d, b->data, b->n_data)
                if (d->encoding != POSTING_INLINE)
                        size += ALIGN64(d->postings_size);

        if (size > UINT32_MAX || b->n_entries > UINT32_MAX || b->n_data > UINT32_MAX)
                return -E2BIG;

        assert(size == ALIGN64(size));

        buffer = malloc0(size);
        if (!buffer)
                return -ENOMEM;

        o = (IndexObject*) buffer;
        *o = (IndexObject) {
                .object.type = OBJECT_INDEX,
                .object.size = htole64(size),
                .head_offset = htole64(head_offset),
                .n_objects = header->n_objects,
                .n_entries = header->n_entries,
                .n_data = header->n_data,
                .n_tags = header->n_tags,
                .head_entry_seqnum = header->head_entry_seqnum,
                .tail_entry_seqnum = header->tail_entry_seqnum,
                .head_entry_realtime = header->head_entry_realtime,
                .tail_entry_realtime = header->tail_entry_realtime,
                .tail_entry_monotonic = header->tail_entry_monotonic,
                .tail_entry_boot_id = header->tail_entry_boot_id,
                .tail_entry_offset = header->tail_entry_offset,
                .n_index_entries = htole32(b->n_entries),
                .entry_array_offset = htole32(entry_array_offset),
                .n_fields = htole32(b->n_fields),
                .field_table_offset = htole32(field_table_offset),
                .n_data_items = htole32(b->n_data),
                .data_table_offset = htole32(data_table_offset),
        };

        for (size_t i = 0; i < b->n_entries; i++)
                unaligned_write_le32(buffer + entry_array_offset + i * sizeof(le32_t), b->entries[i]);

        uint64_t names = names_offset;
        for (size_t i = 0; i < b->n_fields; i++) {
                const IndexBuilderField *field = b->fields + i;
                IndexFieldItem item = {
                        .hash = htole64(field->hash),
                        .name_offset = htole32(names),
                        .name_size = htole32(field->name_size),
                        .flags = htole32(field->flags),
                        .n_data = htole32(field->n_data),
                        .first_data = htole32(field->first_data),
                };

                memcpy(buffer + field_table_offset + i * sizeof(IndexFieldItem), &item, sizeof(item));
                memcpy(buffer + names, field->name, field->name_size);
                names += field->name_size;
        }

        p = postings_offset;
        for (size_t i = 0; i < b->n_data; i++) {
                const IndexBuilderData *d = b->data + i;
                IndexDataItem item = {
                        .hash = htole64(d->hash),
                        .hash2 = htole64(d->hash2),
                        .data_offset = htole32(d->data_offset),
                        .n_entries = htole32(d->n_entries),
                };

                if (d->data_offset > UINT32_MAX || d->n_entries > UINT32_MAX || d->postings_size > INDEX_POSTINGS_SIZE_MASK)
                        return -E2BIG;

                if (d->encoding == POSTING_INLINE) {
                        item.postings_offset = htole32(d->ordinal);
                        item.postings_size = htole32((uint32_t) POSTING_INLINE << INDEX_POSTINGS_ENCODING_SHIFT);
                } else {
                        item.postings_offset = htole32(p);
                        item.postings_size = htole32(((uint32_t) d->encoding << INDEX_POSTINGS_ENCODING_SHIFT) | d->postings_size);

                        memcpy(buffer + p, d->postings, d->postings_size);
                        p += ALIGN64(d->postings_size);
                }

                memcpy(buffer + data_table_offset + i * sizeof(IndexDataItem), &item, sizeof(item));
        }

        assert(p == size);

        o->payload_checksum = htole32(segmented_payload_checksum(header->file_id, buffer + sizeof(IndexObject), size - sizeof(IndexObject)));
        o->object.checksum = htole32(segmented_checksum_with_file_id(header->file_id, offset, buffer, sizeof(IndexObject)));

        *ret = TAKE_PTR(buffer);
        *ret_size = size;
        return 0;
}

typedef struct MergeInput {
        uint8_t *buffer;
        SegmentedIndex index;
        uint32_t *data_field;   /* per data item, the position of its field among the merged fields */
        uint32_t position;      /* next data item to merge */
        uint64_t postings_end;  /* end of the posting lists merged so far */
        unsigned queue_idx;
} MergeInput;

static void merge_inputs_free(MergeInput *inputs, size_t n) {
        FOREACH_ARRAY(i, inputs, n) {
                free(i->buffer);
                free(i->data_field);
        }

        free(inputs);
}

static const IndexDataItem* merge_input_item(const MergeInput *i, uint32_t position) {
        return (const IndexDataItem*) (i->buffer + i->index.data_table_offset + (uint64_t) position * sizeof(IndexDataItem));
}

static int merge_input_compare(const void *_a, const void *_b) {
        const MergeInput *a = _a, *b = _b;
        const IndexDataItem *x = merge_input_item(a, a->position), *y = merge_input_item(b, b->position);
        int r;

        r = CMP(a->data_field[a->position], b->data_field[b->position]);
        if (r != 0)
                return r;

        r = CMP(le64toh(x->hash), le64toh(y->hash));
        if (r != 0)
                return r;

        r = CMP(le64toh(x->hash2), le64toh(y->hash2));
        if (r != 0)
                return r;

        /* Older indexes first, since the encoder needs postings in ascending order */
        return CMP(a->index.first_ordinal, b->index.first_ordinal);
}

static int merge_input_load(int fd, sd_id128_t file_id, const SegmentedIndex *index, MergeInput *ret) {
        _cleanup_free_ uint8_t *buffer = NULL;
        ssize_t n;

        assert(fd >= 0);
        assert(index);
        assert(ret);

        if (index->size > SSIZE_MAX)
                return -E2BIG;

        buffer = malloc(index->size);
        if (!buffer)
                return -ENOMEM;

        for (uint64_t done = 0; done < index->size; done += n) {
                n = pread(fd, buffer + done, index->size - done, index->offset + done);
                if (n < 0)
                        return -errno;
                if (n == 0)
                        return -EIO;
        }

        /* The index that the header names became live without a payload checksum check. A damaged index must
         * not end up in the merged one. */
        if (segmented_checksum_with_file_id(file_id, index->offset, buffer, sizeof(IndexObject)) !=
            le32toh(((const IndexObject*) buffer)->object.checksum) ||
            segmented_payload_checksum(file_id, buffer + sizeof(IndexObject), index->size - sizeof(IndexObject)) !=
            le32toh(((const IndexObject*) buffer)->payload_checksum))
                return -EBADMSG;

        *ret = (MergeInput) {
                .buffer = TAKE_PTR(buffer),
                .index = *index,
        };
        return 0;
}

typedef struct MergeField {
        const MergeInput *input;
        IndexFieldItem item;
} MergeField;

static int merge_field_compare(const MergeField *a, const MergeField *b) {
        int r;

        r = CMP(le64toh(a->item.hash), le64toh(b->item.hash));
        if (r != 0)
                return r;

        return memcmp_nn(a->input->buffer + le32toh(a->item.name_offset), le32toh(a->item.name_size),
                         b->input->buffer + le32toh(b->item.name_offset), le32toh(b->item.name_size));
}

static bool range_is_valid(const SegmentedIndex *i, uint64_t offset, uint64_t n, uint64_t item_size) {
        return offset <= i->size && n <= (i->size - offset) / item_size;
}

static int merge_fields(MergeInput *inputs, size_t n_inputs, IndexBuilder *b) {
        _cleanup_free_ MergeField *fields = NULL;
        size_t n_fields = 0;

        FOREACH_ARRAY(input, inputs, n_inputs) {
                if (!GREEDY_REALLOC(fields, n_fields + input->index.n_fields))
                        return -ENOMEM;

                input->data_field = new(uint32_t, input->index.n_data_items);
                if (!input->data_field)
                        return -ENOMEM;

                for (uint32_t k = 0; k < input->index.n_data_items; k++)
                        input->data_field[k] = UINT32_MAX;

                for (uint32_t k = 0; k < input->index.n_fields; k++) {
                        MergeField *field = fields + n_fields++;

                        *field = (MergeField) {
                                .input = input,
                        };

                        memcpy(&field->item, input->buffer + input->index.field_table_offset + (uint64_t) k * sizeof(IndexFieldItem), sizeof(IndexFieldItem));

                        if (le32toh(field->item.name_size) == 0 ||
                            !range_is_valid(&input->index, le32toh(field->item.name_offset), le32toh(field->item.name_size), 1) ||
                            le32toh(field->item.first_data) > input->index.n_data_items ||
                            le32toh(field->item.n_data) > input->index.n_data_items - le32toh(field->item.first_data))
                                return -EBADMSG;
                }
        }

        typesafe_qsort(fields, n_fields, merge_field_compare);

        FOREACH_ARRAY(field, fields, n_fields) {
                IndexBuilderField *merged;

                if (field == fields || merge_field_compare(field - 1, field) != 0) {
                        if (!GREEDY_REALLOC(b->fields, b->n_fields + 1))
                                return -ENOMEM;

                        b->fields[b->n_fields++] = (IndexBuilderField) {
                                .hash = le64toh(field->item.hash),
                                .name = (const char*) field->input->buffer + le32toh(field->item.name_offset),
                                .name_size = le32toh(field->item.name_size),
                        };
                }

                merged = b->fields + b->n_fields - 1;
                merged->flags |= le32toh(field->item.flags);

                for (uint32_t k = 0; k < le32toh(field->item.n_data); k++) {
                        uint32_t *df = ((MergeInput*) field->input)->data_field + le32toh(field->item.first_data) + k;

                        /* Overlapping ranges would make the merge quadratic. */
                        if (*df != UINT32_MAX)
                                return -EBADMSG;

                        *df = b->n_fields - 1;
                }
        }

        return 0;
}

static int merge_postings(MergeInput *input, const IndexDataItem *item, PostingEncoder *e) {
        uint64_t size, start, length, n = 0;
        PostingEncoding encoding;
        const uint8_t *p = NULL;
        PostingDecoder d;
        int r;

        encoding = le32toh(item->postings_size) >> INDEX_POSTINGS_ENCODING_SHIFT;
        size = le32toh(item->postings_size) & INDEX_POSTINGS_SIZE_MASK;

        if (encoding != POSTING_INLINE) {
                /* Posting lists follow each other in the order of the data table. Shared ones would make
                 * the merge quadratic. */
                if (!range_is_valid(&input->index, le32toh(item->postings_offset), size, 1) ||
                    le32toh(item->postings_offset) < input->postings_end)
                        return -EBADMSG;

                input->postings_end = le32toh(item->postings_offset) + size;

                p = input->buffer + le32toh(item->postings_offset);
        }

        r = posting_decoder_init(&d, encoding, p, size, le32toh(item->postings_offset), input->index.n_index_entries);
        if (r < 0)
                return r;

        while ((r = posting_decoder_next(&d, &start, &length)) > 0) {
                r = posting_encoder_add_run(e, input->index.first_ordinal + start, length);
                if (r < 0)
                        return r == -EINVAL ? -EBADMSG : r;

                n += length;
        }
        if (r < 0)
                return r;

        if (n != le32toh(item->n_entries))
                return -EBADMSG;

        return 0;
}

int segmented_index_merge(
                int fd,
                const Header *header,
                const SegmentedIndex *indexes,
                size_t n_indexes,
                uint64_t offset,
                void **ret,
                size_t *ret_size) {

        _cleanup_(index_builder_done) IndexBuilder b = {};
        MergeInput *inputs = NULL, *input;
        size_t n_inputs = 0;
        uint64_t header_size;
        int r;

        assert(fd >= 0);
        assert(header);
        assert(indexes || n_indexes == 0);
        assert(ret);
        assert(ret_size);

        /* May run in the offline thread, hence reads only the indexes, with pread(), and never the log or the
         * mmap cache. */

        CLEANUP_ARRAY(inputs, n_inputs, merge_inputs_free);

        /* Declared after the inputs, so that it is freed first: freeing it writes to the inputs */
        _cleanup_(prioq_freep) Prioq *queue = NULL;

        header_size = le64toh(header->header_size);

        inputs = new0(MergeInput, n_indexes);
        queue = prioq_new(merge_input_compare);
        if (!inputs || !queue)
                return -ENOMEM;

        FOREACH_ARRAY(i, indexes, n_indexes) {
                input = inputs + n_inputs;

                r = merge_input_load(fd, header->file_id, i, input);
                if (r < 0)
                        return r;

                n_inputs++;

                if (i->first_ordinal != b.n_entries)
                        return -EBADMSG;

                if (!GREEDY_REALLOC(b.entries, b.n_entries + i->n_index_entries))
                        return -ENOMEM;

                for (uint32_t k = 0; k < i->n_index_entries; k++)
                        b.entries[b.n_entries++] = unaligned_read_le32(input->buffer + i->entry_array_offset + (uint64_t) k * sizeof(le32_t));

        }

        /* Comparing inputs requires the field positions */
        r = merge_fields(inputs, n_inputs, &b);
        if (r < 0)
                return r;

        FOREACH_ARRAY(i, inputs, n_inputs)
                if (i->index.n_data_items > 0) {
                        r = prioq_put(queue, i, &i->queue_idx);
                        if (r < 0)
                                return r;
                }

        while ((input = prioq_peek(queue))) {
                _cleanup_(posting_encoder_done) PostingEncoder e = {};
                const IndexDataItem *first = merge_input_item(input, input->position);
                IndexBuilderData d = {
                        .hash = le64toh(first->hash),
                        .hash2 = le64toh(first->hash2),
                        .data_offset = le32toh(first->data_offset),
                        .field = input->data_field[input->position],
                };

                if (d.field == UINT32_MAX)
                        return -EBADMSG; /* A value that belongs to no field */

                /* Items with the same field, hash, and hash2 are the same payload */
                while ((input = prioq_peek(queue))) {
                        const IndexDataItem *item = merge_input_item(input, input->position);

                        if (input->data_field[input->position] != d.field ||
                            le64toh(item->hash) != d.hash || le64toh(item->hash2) != d.hash2)
                                break;

                        r = merge_postings(input, item, &e);
                        if (r < 0)
                                return r;

                        if (++input->position >= input->index.n_data_items)
                                assert_se(prioq_pop(queue) == input);
                        else
                                prioq_reshuffle(queue, input, &input->queue_idx);
                }

                if (!GREEDY_REALLOC(b.data, b.n_data + 1))
                        return -ENOMEM;

                r = index_builder_add_postings(&b, &d, &e);
                if (r < 0)
                        return r;

                b.data[b.n_data++] = d;
        }

        r = index_builder_finish(&b);
        if (r < 0)
                return r;

        return index_builder_serialize(&b, header, offset, header_size, ret, ret_size);
}
