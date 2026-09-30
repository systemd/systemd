/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "journal-def.h"
#include "journal-segmented-internal.h"
#include "memory-util.h"
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

int index_builder_add_postings(IndexBuilderData *d, PostingEncoder *e) {
        int r;

        assert(d);
        assert(e);

        /* The data item takes over the buffer of the encoder */

        r = posting_encoder_finish(e);
        if (r < 0)
                return r;

        d->n_entries = e->n_postings;
        d->postings = TAKE_PTR(e->buffer);
        d->postings_size = e->size;
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
                size += ALIGN64(d->postings_size);

        if (size > UINT32_MAX)
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
                .n_index_entries = htole32(b->n_entries),
                .entry_array_offset = htole32(entry_array_offset),
                .n_fields = htole32(b->n_fields),
                .field_table_offset = htole32(field_table_offset),
                .n_data_items = htole32(b->n_data),
                .data_table_offset = htole32(data_table_offset),
        };
        index_object_set_state(o, header);

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
                        .postings_offset = htole32(p),
                        .postings_size = htole32(d->postings_size),
                };

                /* Files are smaller than 4 GiB, hence offsets, entry counts, and posting lists fit */
                assert(d->data_offset <= UINT32_MAX);
                assert(d->n_entries <= b->n_entries);

                memcpy(buffer + p, d->postings, d->postings_size);
                p += ALIGN64(d->postings_size);

                memcpy(buffer + data_table_offset + i * sizeof(IndexDataItem), &item, sizeof(item));
        }

        assert(p == size);

        o->payload_checksum = htole32(segmented_payload_checksum(header->file_id, buffer + sizeof(IndexObject), size - sizeof(IndexObject)));
        o->object.checksum = htole32(segmented_checksum_with_file_id(header->file_id, offset, buffer, sizeof(IndexObject)));

        *ret = TAKE_PTR(buffer);
        *ret_size = size;
        return 0;
}
