/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "compress.h"
#include "hashmap.h"
#include "io-util.h"
#include "iovec-util.h"
#include "journal-authenticate-internal.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-segmented-internal.h"
#include "log.h"
#include "lookup3.h"
#include "memory-util.h"
#include "sort-util.h"
#include "string-util.h"
#include "time-util.h"

#ifdef __clang__
#  pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

/* The free space is checked in steps of this size, not for each entry */
#define CHECK_STEP (8 * U64_MB)

/* Write a checkpoint when the tail reaches this size, or a sixteenth of the maximum file size if that is
 * smaller. Without the second limit, a small file would get no index until it is archived. */
#define TAIL_SIZE_MAX (4 * U64_MB)

/* The batch is written once it reaches this size, and otherwise by journal_file_post_change() */
#define BATCH_SIZE_MAX (256 * U64_KB)

/* A buffer larger than this is freed after each batch, so that one large payload does not keep its memory
 * allocated until the file is closed */
#define BUFFER_KEEP_MAX (1 * U64_MB)


#define CONTEXTS_MAX 1024U

/* A context is only worth it if it replaces at least this many items */
#define CONTEXT_ITEMS_MIN 2U

/* A value of an inline field is stored as a data object if the field name, the '=', and the value take this
 * many bytes or more */
#define INLINE_SIZE_MAX 256U

typedef struct SegmentField {
        char *name;
        size_t name_size;
        uint64_t hash;
        bool in_line;    /* values smaller than INLINE_SIZE_MAX are stored in the entry */
        uint32_t flags;  /* INDEX_FIELD_xyz */
        uint32_t next; /* see table_put() */
        bool referenced; /* by an entry of the segment */
} SegmentField;

typedef struct SegmentData {
        uint64_t hash;
        uint64_t hash2;
        uint64_t jenkins;
        uint64_t offset;
        uint64_t size;   /* of the payload, before compression */
        uint32_t field;
        uint64_t entry;  /* entry_counter of the last entry that referred to it */
        uint32_t next; /* see table_put() */
        bool referenced;
        PostingEncoder postings;
} SegmentData;

typedef struct SegmentContext {
        uint64_t offset; /* 0 until the set is seen a second time and written */
        uint32_t *items; /* positions in the data array, ordered by offset */
        size_t n_items;
        uint32_t next; /* see table_put() */
} SegmentContext;

typedef struct Pending {
        SegmentData data;
        const void *payload;
        uint64_t end;
} Pending;

typedef struct BatchObject {
        uint64_t offset;
        uint8_t type;
} BatchObject;

struct SegmentedWriter {
        uint64_t checked;             /* the file size up to which the free space was checked */
        bool failed;
        bool tag_failed;              /* a later tag could not cover what the failed one covers */
        bool archived;
        uint64_t checkpoint_retry_at; /* retry a failed checkpoint when the tail reaches this size */

        /* Set by segmented_offline_prepare() while a sync may run in the offline thread, which then
         * archives the file when it is done. Accessed atomically. */
        bool offline_archive;
        bool archive_done;            /* set by segmented_offline() */

        /* The newest index that segmented_offline_prepare() recorded. The main thread may record a newer
         * one while a sync runs, hence it is accessed atomically. */
        uint64_t sync_index_offset;
        /* The index that the header names. Only the offline thread changes it while it runs. */
        uint64_t synced_index_offset;
        bool sync_failed;             /* ever: the kernel reports a writeback error only once */

        /* The segment */
        SegmentData *data;
        size_t n_data;
        Hashmap *data_by_hash;
        Hashmap *data_by_offset; /* only while the tail is replayed */

        SegmentField *fields;
        size_t n_fields;
        Hashmap *fields_by_name;

        SegmentContext *contexts;
        size_t n_contexts;
        Hashmap *contexts_by_hash;

        /* The objects that are not written yet. They follow each other in the file from 'flushed' on. */
        uint64_t flushed;
        uint8_t *buffer;
        size_t buffer_size;
        BatchObject *objects;   /* for the HMAC */
        size_t n_objects;

        /* The data objects of the entry that is being added */
        Pending *pending;
        size_t n_pending;

        /* Incremented for each entry that is added. An entry that refers to the same data object twice
         * finds its own value in SegmentData.entry the second time. */
        uint64_t entry_counter;
};

static uint32_t table_get(Hashmap *h, uint64_t key) {
        /* Returns the position plus one of the element that was put last under the key, or 0 */
        return PTR_TO_UINT32(hashmap_get(h, UINT64_TO_PTR(key)));
}

static int table_put(Hashmap **h, uint64_t key, size_t position, uint32_t *ret_next) {
        uint32_t next;
        int r;

        assert(h);

        /* The keys are hashes, and two elements can have the same hash. UINT64_TO_PTR() also cuts a key to
         * 32 bits on 32-bit architectures. Each element therefore stores the position plus one of the
         * element that was put before it under the same key, which table_put() returns in ret_next. */

        assert(position < UINT32_MAX);

        next = table_get(*h, key);

        r = hashmap_ensure_replace(h, &trivial_hash_ops, UINT64_TO_PTR(key), UINT32_TO_PTR(position + 1));
        if (r < 0)
                return r;

        if (ret_next)
                *ret_next = next;

        return 0;
}

/* The segment */

static void segment_data_done(SegmentData *d) {
        assert(d);

        posting_encoder_done(&d->postings);
}

static void segment_context_done(SegmentContext *c) {
        assert(c);

        free(c->items);
}

static void segment_contexts_clear(SegmentedWriter *w) {
        assert(w);

        FOREACH_ARRAY(c, w->contexts, w->n_contexts)
                segment_context_done(c);

        w->n_contexts = 0;
        w->contexts_by_hash = hashmap_free(w->contexts_by_hash);
}

static int segment_data_reference(SegmentedWriter *w, size_t position, uint64_t ordinal) {
        SegmentData *d = w->data + position;

        /* The entry may refer to the data directly or through a context */

        d->referenced = true;
        w->fields[d->field].referenced = true;

        return posting_encoder_add(&d->postings, ordinal);
}

static int segment_data_index(SegmentedWriter *w, size_t position) {
        return table_put(&w->data_by_hash, w->data[position].hash, position, &w->data[position].next);
}


static bool field_is_inline(const char *name, size_t size) {
        static const char * const in_line[] = {
                "_SOURCE_REALTIME_TIMESTAMP",
                "_SOURCE_MONOTONIC_TIMESTAMP",
                "_SOURCE_BOOTTIME_TIMESTAMP",
        };

        FOREACH_ELEMENT(i, in_line)
                if (memcmp_nn(name, size, *i, strlen(*i)) == 0)
                        return true;

        return false;
}

static int segment_field_acquire(JournalFile *f, const char *name, size_t size, uint32_t *ret) {
        SegmentedWriter *w = ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(f)->segmented)->writer);
        uint64_t key = segmented_process_hash(name, size);
        int r;

        assert(name);
        assert(ret);

        for (uint32_t v = table_get(w->fields_by_name, key); v > 0; v = w->fields[v - 1].next)
                if (memcmp_nn(w->fields[v - 1].name, w->fields[v - 1].name_size, name, size) == 0) {
                        *ret = v - 1;
                        return 0;
                }

        if (!journal_field_valid(name, size, /* allow_protected= */ true))
                return -EUCLEAN; /* Not the file's fault, unless it is replayed */

        if (!GREEDY_REALLOC(w->fields, w->n_fields + 1))
                return -ENOMEM;

        SegmentField field = {
                .name = memdup(name, size),
                .name_size = size,
                .hash = journal_file_hash_data(f, name, size),
                .in_line = field_is_inline(name, size),
        };
        if (!field.name)
                return -ENOMEM;

        r = table_put(&w->fields_by_name, key, w->n_fields, &field.next);
        if (r < 0) {
                free(field.name);
                return r;
        }

        w->fields[w->n_fields] = field;
        *ret = w->n_fields++;
        return 0;
}

static void segment_fields_clear(SegmentedWriter *w) {
        FOREACH_ARRAY(i, w->fields, w->n_fields)
                free(i->name);

        w->n_fields = 0;
        w->fields_by_name = hashmap_free(w->fields_by_name);
}

static void segment_clear(SegmentedWriter *w) {
        segment_contexts_clear(w);

        FOREACH_ARRAY(d, w->data, w->n_data)
                segment_data_done(d);

        w->n_data = 0;
        w->data_by_hash = hashmap_free(w->data_by_hash);
        w->data_by_offset = hashmap_free(w->data_by_offset);

        segment_fields_clear(w);
}

static int segment_inline_reference(JournalFile *f, const char *data, size_t size) {
        SegmentedWriter *w = ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(f)->segmented)->writer);
        const char *eq;
        uint32_t k;
        int r;

        eq = memchr(data, '=', size);
        if (!eq)
                return -EBADMSG;

        r = segment_field_acquire(f, data, eq - data, &k);
        if (r < 0)
                return r;

        w->fields[k].referenced = true;
        w->fields[k].flags |= INDEX_FIELD_INLINE;
        return 0;
}
/* Writing objects */

static void entry_reset(SegmentedWriter *w) {
        assert(w);

        FOREACH_ARRAY(p, w->pending, w->n_pending)
                segment_data_done(&p->data);

        w->n_pending = 0;
}

static void batch_clear(SegmentedWriter *w) {
        assert(w);

        if (MALLOC_SIZEOF_SAFE(w->buffer) > BUFFER_KEEP_MAX)
                w->buffer = mfree(w->buffer);

        w->buffer_size = 0;
        w->n_objects = 0;
}

typedef struct BatchState {
        SegmentedWriter *writer;
        size_t buffer_size;
        size_t n_objects;
} BatchState;

static BatchState batch_save(SegmentedWriter *w) {
        assert(w);

        return (BatchState) {
                .writer = w,
                .buffer_size = w->buffer_size,
                .n_objects = w->n_objects,
        };
}

static void batch_restore(BatchState *s) {
        SegmentedWriter *w;

        assert(s);

        /* Drops what was added to the batch since batch_save(), unless the caller cleared 'writer' */

        w = s->writer;
        if (!w)
                return;

        w->buffer_size = s->buffer_size;
        w->n_objects = s->n_objects;
}

static int batch_add(SegmentedWriter *w, size_t size, size_t *ret_offset) {
        assert(w);

        if (!GREEDY_REALLOC(w->buffer, w->buffer_size + size))
                return -ENOMEM;

        memzero(w->buffer + w->buffer_size, size);

        if (ret_offset)
                *ret_offset = w->buffer_size;

        w->buffer_size += size;
        return 0;
}

static int batch_add_object(SegmentedWriter *w, uint64_t offset, uint8_t type) {
        assert(w);

        /* Remembers an object of the batch, so that it is added to the HMAC once it is written */

        if (!GREEDY_REALLOC(w->objects, w->n_objects + 1))
                return -ENOMEM;

        w->objects[w->n_objects++] = (BatchObject) {
                .offset = offset,
                .type = type,
        };

        return 0;
}

static int writer_check_space(JournalFile *f, uint64_t end, bool use_reserve) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        SegmentedWriter *w = ASSERT_PTR(a->writer);
        uint64_t n, reserve = 0;
        int r;

        if (end > UINT32_MAX)
                return -E2BIG;

        if (!use_reserve) {
                /* Leave room for the index of the tail that the next checkpoint writes. Indexes and tags
                 * may use that room. */
                reserve = (end - a->tail_offset) / 8;

                if (f->metrics.max_size > 0 && (end > f->metrics.max_size || reserve > f->metrics.max_size - end))
                        return -E2BIG;
        }

        if (end <= w->checked) {
                /* Check now and then whether the file is still around. */
                if (f->last_stat_usec + 5 * USEC_PER_SEC > now(CLOCK_MONOTONIC))
                        return 0;

                return journal_file_fstat(f);
        }

        /* The space is not preallocated with fallocate(). btrfs never compresses a file that was
         * preallocated, and gives a file with copy-on-write twice as many extents. */
        n = ROUND_UP(end, CHECK_STEP);
        if (f->metrics.max_size > 0 && n > f->metrics.max_size)
                n = MAX(end, f->metrics.max_size);
        n = MIN(n, (uint64_t) UINT32_MAX);

        r = journal_file_check_keep_free(f, MAX(w->checked, a->scan_offset), n);
        if (r < 0)
                return r;

        w->checked = n;

        return journal_file_fstat(f);
}

static void writer_undo(JournalFile *f, uint64_t offset) {
        SegmentedWriter *w = ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(f)->segmented)->writer);

        /* Nothing can follow a partial object. Cut it off, so that the next write starts at 'offset' again.
         * If that fails, refuse further writes, so that the file is rotated. */

        if (ftruncate(f->fd, offset) >= 0)
                return;

        log_debug_errno(errno, "Failed to cut off partial write to %s at %" PRIu64 ", giving up on the file: %m", f->path, offset);
        w->failed = true;
}

static void writer_written(JournalFile *f, uint64_t end) {
        SegmentedWriter *w = ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(f)->segmented)->writer);

        w->flushed = end;
        f->last_stat.st_size = MAX((uint64_t) f->last_stat.st_size, end);
}

int segmented_flush(JournalFile *f) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        SegmentedWriter *w = a->writer;
        uint64_t written = 0;
        int r;

        /* Writes the batch with one system call. The batch holds the entries that were appended since
         * the last call. journald makes the call once its event loop has nothing else to do, and at
         * most 250 ms after the first entry of the batch. */

        if (!w || w->buffer_size == 0)
                return 0;
        if (w->failed)
                return -EIO;

        r = pwritev_full(f->fd, &IOVEC_MAKE(w->buffer, w->buffer_size), 1, w->flushed, &written);
        if (r < 0) {
                if (written > 0)
                        writer_undo(f, w->flushed);
                return r;
        }

        assert(w->flushed + written == a->scan_offset);
        writer_written(f, a->scan_offset);

        /* The HMAC must see every object that was written, in log order */
        if (JOURNAL_HEADER_SEALED(f->header))
                FOREACH_ARRAY(o, w->objects, w->n_objects) {
                        r = journal_file_auth_put_object(f, o->type, NULL, o->offset);
                        if (r < 0) {
                                /* A later tag could not cover what follows */
                                w->failed = true;
                                return r;
                        }
                }

        batch_clear(w);
        return 0;
}

static void object_done(JournalFile *f, uint8_t type, uint64_t offset, uint64_t end) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);

        assert(offset == a->scan_offset);

        a->scan_offset = end;

        segmented_header_add_object(f->header, type, offset, end);
}

static int writer_append_object(JournalFile *f, uint8_t type, const void *object, size_t size) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint64_t offset, written = 0;
        int r;

        assert(object);
        assert(size % 8 == 0);

        /* Appends an object that is complete, checksum included: an index or a tag. These may use the room
         * reserved for the index that archiving writes. The batch is written first, since it
         * comes before the object. */

        r = segmented_flush(f);
        if (r < 0)
                return r;

        offset = a->scan_offset;

        r = writer_check_space(f, offset + size, /* use_reserve= */ true);
        if (r < 0)
                return r;

        r = pwritev_full(f->fd, &IOVEC_MAKE((void*) object, size), 1, offset, &written);
        if (r < 0) {
                if (written > 0)
                        writer_undo(f, offset);
                return r;
        }

        object_done(f, type, offset, offset + size);
        writer_written(f, offset + size);
        return 0;
}

/* Indexes */

static int segment_index(JournalFile *f, IndexBuilder *b) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        SegmentedWriter *w = ASSERT_PTR(a->writer);
        _cleanup_free_ uint32_t *fields = NULL;
        int r;

        assert(b);

        /* Must not modify the segment state: if the index cannot be written, the writer continues
         * without it. */

        if (a->n_tail_entries > 0) {
                b->entries = newdup(uint32_t, a->tail_entries, a->n_tail_entries);
                if (!b->entries)
                        return -ENOMEM;

                b->n_entries = a->n_tail_entries;
        }

        fields = new(uint32_t, w->n_fields);
        if (!fields)
                return -ENOMEM;

        for (size_t i = 0; i < w->n_fields; i++) {
                const SegmentField *field = w->fields + i;

                fields[i] = UINT32_MAX;

                if (!field->referenced)
                        continue;

                if (!GREEDY_REALLOC(b->fields, b->n_fields + 1))
                        return -ENOMEM;

                fields[i] = b->n_fields;
                b->fields[b->n_fields++] = (IndexBuilderField) {
                        .hash = field->hash,
                        .name = field->name,
                        .name_size = field->name_size,
                        .flags = field->flags,
                };
        }

        for (size_t i = 0; i < w->n_data; i++) {
                _cleanup_(posting_encoder_done) PostingEncoder e = {};
                SegmentData *d = w->data + i;

                if (!d->referenced)
                        continue;

                assert(fields[d->field] != UINT32_MAX);

                r = posting_encoder_snapshot(&d->postings, &e);
                if (r < 0)
                        return r;

                if (e.n_postings == 0)
                        continue;

                if (!GREEDY_REALLOC(b->data, b->n_data + 1))
                        return -ENOMEM;

                IndexBuilderData item = {
                        .hash = d->hash,
                        .hash2 = d->hash2,
                        .data_offset = d->offset,
                        .field = fields[d->field],
                };

                r = index_builder_add_postings(&item, &e);
                if (r < 0)
                        return r;

                b->data[b->n_data++] = item;
        }

        return index_builder_finish(b);
}

int segmented_checkpoint(JournalFile *f) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        SegmentedWriter *w = ASSERT_PTR(a->writer);
        _cleanup_(index_builder_done) IndexBuilder b = {};
        _cleanup_free_ void *buffer = NULL;
        uint64_t offset;
        SegmentedIndex index;
        size_t size;
        int r;

        if (w->failed)
                return -EIO;
        if (w->archived)
                return -ESHUTDOWN;

        /* An index without entries is of no use */
        if (a->n_tail_entries == 0)
                return 0;

        offset = a->scan_offset;

        r = segment_index(f, &b);
        if (r < 0)
                return r;

        r = index_builder_serialize(
                        &b,
                        f->header,
                        offset,
                        a->tail_offset,
                        &buffer, &size);
        if (r < 0)
                return r;

        r = segmented_index_parse(f, buffer, offset, &index);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC(a->indexes, a->n_indexes + 1))
                return -ENOMEM;

        r = writer_append_object(f, OBJECT_INDEX, buffer, size);
        if (r < 0)
                return r;

        a->indexes[a->n_indexes++] = index;
        a->tail_offset = offset;
        a->n_indexed_entries = index.n_entries;
        a->n_tail_entries = 0;
        w->checkpoint_retry_at = 0;

        segment_clear(w);
        return 0;
}

static uint64_t tail_size_max(JournalFile *f) {
        if (f->metrics.max_size == 0)
                return TAIL_SIZE_MAX;

        return MIN(TAIL_SIZE_MAX, f->metrics.max_size / 16);
}

/* Entries */

static int segment_data_equal(JournalFile *f, const SegmentData *d, const void *data, uint64_t size) {
        SegmentedWriter *w = ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(f)->segmented)->writer);
        const void *payload;
        size_t l;
        int r;

        if (d->size != size)
                return false;

        if (d->offset < w->flushed)
                return segmented_data_payload_equal(f, d->offset, data, size);

        /* The object is not written yet. The buffer contains the objects of the batch in file order, so the
         * object starts at its offset minus the offset of the batch. */
        r = journal_file_data_payload(f, (Object*) (w->buffer + (d->offset - w->flushed)), d->offset,
                                      /* field= */ NULL, 0, /* data_threshold= */ 0, &payload, &l);
        if (r < 0)
                return r;

        return memcmp_nn(data, size, payload, l) == 0;
}

static int batch_add_data(
                JournalFile *f,
                uint64_t *p,
                uint32_t field,
                const void *data,
                uint64_t size,
                uint64_t hash,
                size_t *ret) {

        SegmentedWriter *w = ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(f)->segmented)->writer);
        uint8_t flags = 0;
        size_t header, payload = 0, stored = size;
        Pending *pending;
        int r;

        assert(p);
        assert(ret);

        r = batch_add(w, offsetof(SegmentedDataObject, payload), &header);
        if (r < 0)
                return r;

        if (JOURNAL_FILE_COMPRESSION(f) != COMPRESSION_NONE && size >= f->compress_threshold_bytes) {
                Compression c;
                size_t rsize = 0;

                r = batch_add(w, size - 1, &payload);
                if (r < 0)
                        return r;

                r = journal_file_maybe_compress_payload(f, w->buffer + payload, data, size, &rsize, &c);
                if (r > 0) {
                        flags |= COMPRESSION_TO_OBJECT_FLAG(c);
                        stored = rsize;
                } else
                        stored = 0;

                /* Shrink the reserved room to the compressed size, or drop it if the payload stays uncompressed */
                w->buffer_size -= size - 1 - stored;

                if (stored == 0)
                        stored = size;
        }

        if (!(flags & _OBJECT_COMPRESSED_MASK)) {
                r = batch_add(w, size, &payload);
                if (r < 0)
                        return r;

                memcpy_safe(w->buffer + payload, data, size);
        }

        uint64_t osize = offsetof(SegmentedDataObject, payload) + stored;

        r = batch_add(w, ALIGN64(osize) - osize, NULL);
        if (r < 0)
                return r;

        SegmentedDataObject o = {
                .object.type = OBJECT_DATA,
                .object.flags = flags,
                .object.size = htole64(osize),
                .hash = htole64(hash),
        };

        o.object.checksum = htole32(segmented_checksum(f, *p, &o, offsetof(SegmentedDataObject, payload)));
        memcpy(w->buffer + header, &o, offsetof(SegmentedDataObject, payload));

        r = batch_add_object(w, *p, OBJECT_DATA);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC(w->pending, w->n_pending + 1))
                return -ENOMEM;

        pending = w->pending + w->n_pending;
        *pending = (Pending) {
                .data = {
                        .hash = hash,
                        .hash2 = segmented_hash2(f, data, size),
                        .jenkins = jenkins_hash64(data, size),
                        .offset = *p,
                        .size = size,
                        .field = field,
                },
                .payload = data,
                .end = *p + ALIGN64(osize),
        };

        *p = pending->end;
        *ret = w->n_data + w->n_pending++;
        return 0;
}

static int segment_data_acquire(
                JournalFile *f,
                uint64_t *p,
                uint32_t field,
                const void *data,
                uint64_t size,
                size_t *ret) {

        SegmentedWriter *w = ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(f)->segmented)->writer);
        uint64_t hash = journal_file_hash_data(f, data, size);
        int r;

        assert(ret);

        for (uint32_t v = table_get(w->data_by_hash, hash); v > 0; v = w->data[v - 1].next) {
                r = segment_data_equal(f, w->data + v - 1, data, size);
                if (r < 0)
                        return r;
                if (r > 0) {
                        *ret = v - 1;
                        return 0;
                }
        }

        /* The entry may have the same payload more than once */
        for (size_t i = 0; i < w->n_pending; i++)
                if (w->pending[i].data.hash == hash &&
                    memcmp_nn(w->pending[i].payload, w->pending[i].data.size, data, size) == 0) {
                        *ret = w->n_data + i;
                        return 0;
                }

        return batch_add_data(f, p, field, data, size, hash, ret);
}

static SegmentData* writer_data(SegmentedWriter *w, size_t position) {
        assert(w);

        if (position < w->n_data)
                return w->data + position;

        assert(position - w->n_data < w->n_pending);
        return &w->pending[position - w->n_data].data;
}

static int batch_commit(JournalFile *f) {
        SegmentedWriter *w = ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(f)->segmented)->writer);
        int r;

        /* Adds the data objects of the batch to the segment */

        FOREACH_ARRAY(p, w->pending, w->n_pending) {
                if (!GREEDY_REALLOC(w->data, w->n_data + 1))
                        return -ENOMEM;

                w->data[w->n_data] = TAKE_STRUCT(p->data);

                r = segment_data_index(w, w->n_data);
                if (r < 0)
                        return r;

                object_done(f, OBJECT_DATA, w->data[w->n_data].offset, p->end);
                w->n_data++;
        }

        return 0;
}

typedef struct DataReference {
        uint64_t position; /* not size_t, the struct is hashed and must not have padding */
        uint64_t offset;
} DataReference;

static int data_reference_compare(const DataReference *a, const DataReference *b) {
        return CMP(a->offset, b->offset);
}

static SegmentContext* context_find(
                SegmentedWriter *w,
                const DataReference *references,
                size_t n,
                uint64_t hash) {

        for (uint32_t v = table_get(w->contexts_by_hash, hash); v > 0; v = w->contexts[v - 1].next) {
                SegmentContext *c = w->contexts + v - 1;
                bool equal = c->n_items == n;

                for (size_t i = 0; equal && i < n; i++)
                        equal = c->items[i] == references[i].position;

                if (equal)
                        return c;
        }

        return NULL;
}

static int context_add(
                SegmentedWriter *w,
                const DataReference *references,
                size_t n,
                uint64_t hash) {

        int r;

        if (w->n_contexts >= CONTEXTS_MAX)
                segment_contexts_clear(w);

        if (!GREEDY_REALLOC(w->contexts, w->n_contexts + 1))
                return -ENOMEM;

        SegmentContext c = {
                .n_items = n,
                .items = new(uint32_t, n),
        };
        if (!c.items)
                return -ENOMEM;

        for (size_t i = 0; i < n; i++)
                c.items[i] = references[i].position;

        r = table_put(&w->contexts_by_hash, hash, w->n_contexts, &c.next);
        if (r < 0) {
                free(c.items);
                return r;
        }

        w->contexts[w->n_contexts++] = c;
        return 0;
}

int segmented_append_entry(
                JournalFile *f,
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const struct iovec iovec[],
                size_t n_iovec,
                uint64_t *seqnum,
                sd_id128_t *seqnum_id,
                Object **ret_object,
                uint64_t *ret_offset) {

        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        SegmentedWriter *w = a->writer;
        _cleanup_free_ DataReference *direct = NULL, *shared = NULL;
        _cleanup_free_ size_t *in_line = NULL;
        _cleanup_free_ uint32_t *items = NULL;
        _cleanup_(batch_restore) BatchState saved = {};
        size_t n_direct = 0, n_shared = 0, n_inline = 0, n_items, inline_size = 0, entry;
        uint64_t p, xor_hash = 0, context_hash = 0, context_offset = 0, entry_offset, entry_size, next_seqnum;
        SegmentContext *context = NULL;
        bool new_context = false;
        Header *h = f->header;
        int r;

        assert(ts);
        assert(boot_id);
        assert(iovec);
        assert(n_iovec > 0);

        if (!w)
                return -EPERM;
        if (w->failed || w->tag_failed)
                return -EIO;
        if (w->archived)
                return -ESHUTDOWN;

        r = journal_file_check_entry_order(f, ts, boot_id);
        if (r < 0)
                return r;

        /* The header is never rewritten, so a different sequence number ID is refused instead of adopted */
        if (seqnum_id) {
                if (sd_id128_is_null(*seqnum_id))
                        *seqnum_id = h->seqnum_id;
                else if (!sd_id128_equal(*seqnum_id, h->seqnum_id))
                        return log_debug_errno(SYNTHETIC_ERRNO(EILSEQ),
                                               "Sequence number IDs don't match, refusing entry.");
        }

        assert(a->n_tail_entries < UINT32_MAX); /* Files are smaller than 4 GiB, hence have fewer entries */

        /* An entry stores the number of its items in 16 bits, and each field becomes at most one item */
        if (n_iovec > UINT16_MAX)
                return -E2BIG;

        entry_reset(w);
        saved = batch_save(w);
        w->entry_counter++;

        direct = new(DataReference, n_iovec);
        shared = new(DataReference, n_iovec);
        in_line = new(size_t, n_iovec);
        if (!direct || !shared || !in_line)
                return -ENOMEM;

        p = a->scan_offset;

        for (size_t i = 0; i < n_iovec; i++) {
                const char *data = iovec[i].iov_base, *eq;
                uint64_t size = iovec[i].iov_len;
                SegmentField *field;
                SegmentData *d;
                uint32_t k;
                size_t q;

                if (!data || size == 0)
                        return -EUCLEAN;

                eq = memchr(data, '=', size);
                if (!eq)
                        return -EUCLEAN;

                r = segment_field_acquire(f, data, eq - data, &k);
                if (r < 0)
                        return r;

                field = w->fields + k;

                if (field->in_line && size < INLINE_SIZE_MAX) {
                        bool duplicate = false;

                        /* As in classic files, xor_hash covers each payload passed, duplicates included */
                        xor_hash ^= jenkins_hash64(data, size);

                        for (size_t j = 0; j < n_inline && !duplicate; j++)
                                duplicate = iovec_equal(iovec + in_line[j], iovec + i);
                        if (duplicate)
                                continue;

                        inline_size += ALIGN64(sizeof(InlineData) + size);
                        in_line[n_inline++] = i;
                        continue;
                }

                r = segment_data_acquire(f, &p, k, data, size, &q);
                if (r < 0)
                        return r;

                d = writer_data(w, q);
                xor_hash ^= d->jenkins;

                if (d->entry == w->entry_counter)
                        continue;
                d->entry = w->entry_counter;

                /* Trusted fields other than _SOURCE_* tend to be the same for all entries of a process */
                if (data[0] == '_' && !memory_startswith(data, size, "_SOURCE_"))
                        shared[n_shared++] = (DataReference) { q, d->offset };
                else
                        direct[n_direct++] = (DataReference) { q, d->offset };
        }

        if (n_shared >= CONTEXT_ITEMS_MIN) {
                typesafe_qsort(shared, n_shared, data_reference_compare);

                context_hash = segmented_process_hash(shared, n_shared * sizeof(DataReference));

                context = context_find(w, shared, n_shared, context_hash);
                if (!context)
                        new_context = true;
                else if (context->offset == 0 && n_shared <= ENTRY_FIELD_COUNT_MAX) {
                        /* The set was seen before, write the context */
                        size_t q;

                        uint64_t size = offsetof(ContextObject, items) + n_shared * sizeof(le32_t);

                        r = batch_add(w, ALIGN64(size), &q);
                        if (r < 0)
                                return r;

                        ContextObject *o = (ContextObject*) (w->buffer + q);

                        o->object = (ObjectHeader) {
                                .type = OBJECT_CONTEXT,
                                .aux = htole16(n_shared),
                                .size = htole64(size),
                        };

                        for (size_t i = 0; i < n_shared; i++)
                                o->items[i] = htole32(shared[i].offset);

                        o->object.checksum = htole32(segmented_checksum(f, p, o, size));

                        r = batch_add_object(w, p, OBJECT_CONTEXT);
                        if (r < 0)
                                return r;

                        context_offset = p;
                        p += ALIGN64(size);
                } else
                        context_offset = context->offset;
        }

        if (context_offset == 0) {
                /* No context, all data is referenced directly */
                memcpy(direct + n_direct, shared, n_shared * sizeof(DataReference));
                n_direct += n_shared;
        }

        n_items = n_direct + n_inline + (context_offset != 0);
        if (n_items == 0)
                return -EUCLEAN;

        entry_offset = p;
        entry_size = offsetof(Object, entry.items) + ALIGN64(n_items * sizeof(le32_t)) + inline_size;
        p += ALIGN64(entry_size);

        r = batch_add(w, ALIGN64(entry_size), &entry);
        if (r < 0)
                return r;

        items = new(uint32_t, n_items);
        if (!items)
                return -ENOMEM;

        n_items = 0;
        FOREACH_ARRAY(i, direct, n_direct)
                items[n_items++] = i->offset | ENTRY_ITEM_DATA;
        if (context_offset != 0)
                items[n_items++] = context_offset | ENTRY_ITEM_CONTEXT;

        uint64_t q = offsetof(Object, entry.items) + ALIGN64((n_items + n_inline) * sizeof(le32_t));
        FOREACH_ARRAY(i, in_line, n_inline) {
                InlineData *d = (InlineData*) (w->buffer + entry + q);

                d->size = htole32(iovec[*i].iov_len);
                memcpy(d->payload, iovec[*i].iov_base, iovec[*i].iov_len);

                items[n_items++] = q | ENTRY_ITEM_INLINE;
                q += ALIGN64(sizeof(InlineData) + iovec[*i].iov_len);
        }

        assert(q == entry_size);

        typesafe_qsort(items, n_items, cmp_unsigned);

        next_seqnum = journal_file_next_seqnum(f, seqnum);

        Object *o = (Object*) (w->buffer + entry);

        o->object = (ObjectHeader) {
                .type = OBJECT_ENTRY,
                .aux = htole16(n_items),
                .size = htole64(entry_size),
        };
        o->entry.seqnum = htole64(next_seqnum);
        o->entry.realtime = htole64(ts->realtime);
        o->entry.monotonic = htole64(ts->monotonic);
        o->entry.boot_id = *boot_id;
        o->entry.xor_hash = htole64(xor_hash);

        for (size_t i = 0; i < n_items; i++)
                o->entry.items.compact[i].object_offset = htole32(items[i]);

        o->object.checksum = htole32(segmented_checksum(f, entry_offset, o, entry_size));

        r = batch_add_object(w, entry_offset, OBJECT_ENTRY);
        if (r < 0)
                return r;

        r = writer_check_space(f, p, /* use_reserve= */ false);
        if (r < 0)
                return r;

        /* The entry is part of the batch from now on, hence its sequence number is taken, even if what
         * follows fails and the file is rotated */
        saved.writer = NULL;
        if (seqnum)
                *seqnum = next_seqnum;
        segmented_header_add_entry(h, entry_offset, next_seqnum, ts->realtime, ts->monotonic, *boot_id);

        r = batch_commit(f);
        if (r < 0) {
                w->failed = true;
                return r;
        }

        if (context_offset != 0 && context->offset == 0) {
                context->offset = context_offset;
                object_done(f, OBJECT_CONTEXT, context_offset, entry_offset);
        }

        object_done(f, OBJECT_ENTRY, entry_offset, p);
        entry_reset(w);

        /* The entry is in the batch. Until the segment state has it too, a failure leaves the two out of
         * sync, hence the writer counts as failed until then. */
        w->failed = true;

        if (!GREEDY_REALLOC(a->tail_entries, a->n_tail_entries + 1))
                return -ENOMEM;

        uint64_t ordinal = a->n_tail_entries;
        a->tail_entries[a->n_tail_entries++] = entry_offset;

        FOREACH_ARRAY(i, direct, n_direct) {
                r = segment_data_reference(w, i->position, ordinal);
                if (r < 0)
                        return r;
        }

        /* Without a context, the shared data was copied to the direct references */
        if (context_offset != 0)
                FOREACH_ARRAY(i, shared, n_shared) {
                        r = segment_data_reference(w, i->position, ordinal);
                        if (r < 0)
                                return r;
                }

        if (context_offset == 0 && new_context) {
                r = context_add(w, shared, n_shared, context_hash);
                if (r < 0)
                        return r;
        }

        FOREACH_ARRAY(i, in_line, n_inline) {
                r = segment_inline_reference(f, iovec[*i].iov_base, iovec[*i].iov_len);
                if (r < 0)
                        return r;
        }

        w->failed = false;

        if (w->buffer_size >= BATCH_SIZE_MAX) {
                r = segmented_flush(f);
                if (r < 0)
                        return r;
        }

        uint64_t tail_size = a->scan_offset - a->tail_offset;
        if (tail_size >= tail_size_max(f) && tail_size >= w->checkpoint_retry_at) {
                r = segmented_checkpoint(f);
                if (r < 0) {
                        /* The entry is written, hence do not fail. Building an index is expensive, hence
                         * do not retry right away. */
                        log_debug_errno(r, "Failed to write index to %s, ignoring: %m", f->path);
                        w->checkpoint_retry_at = tail_size + tail_size_max(f) / 4;
                }
        }

        if (ret_object) {
                r = segmented_flush(f);
                if (r < 0)
                        return r;

                r = journal_file_move_to_object(f, OBJECT_ENTRY, entry_offset, ret_object);
                if (r < 0)
                        return r;
        }

        if (ret_offset)
                *ret_offset = entry_offset;

        return 0;
}

int segmented_append_tag(JournalFile *f, TagObject *tag) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        SegmentedWriter *w = a->writer;
        uint64_t offset;
        int r;

        assert(tag);

        if (!w)
                return -EPERM;
        if (w->archived) /* Checked first, the offline thread may set 'failed' */
                return -ESHUTDOWN;
        if (w->failed || w->tag_failed)
                return -EIO;

        offset = a->scan_offset;

        tag->object.checksum = htole32(segmented_checksum(f, offset, tag, sizeof(TagObject)));

        r = writer_append_object(f, OBJECT_TAG, tag, sizeof(TagObject));
        if (r < 0) {
                /* The caller consumed the HMAC, so a later tag could not cover what this one covers.
                 * Refuse further entries and tags, so that the file is rotated. Archiving still works,
                 * since indexes are not sealed. */
                log_debug_errno(r, "Failed to write tag to %s, giving up on the file: %m", f->path);
                w->tag_failed = true;
                return r;
        }

        return 0;
}

/* Opening and closing */

static int segment_data_load(JournalFile *f, uint64_t offset, size_t *ret) {
        SegmentedWriter *w = ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(f)->segmented)->writer);
        const void *payload;
        const char *eq;
        size_t size;
        uint32_t v, k;
        Object *o;
        int r;

        v = table_get(w->data_by_offset, offset);
        if (v > 0) {
                if (ret)
                        *ret = v - 1;
                return 0;
        }

        r = journal_file_move_to_object(f, OBJECT_DATA, offset, &o);
        if (r < 0)
                return r;

        SegmentData d = {
                .hash = le64toh(o->segmented_data.hash),
                .offset = offset,
        };

        /* Decompressors report damaged input with all kinds of errors, -ENOMEM among them */
        r = journal_file_data_payload(f, o, offset, /* field= */ NULL, 0, /* data_threshold= */ 0, &payload, &size);
        if (r < 0)
                return -EBADMSG;

        eq = memchr(payload, '=', size);
        if (!eq)
                return -EBADMSG;

        if (journal_file_hash_data(f, payload, size) != d.hash)
                return -EBADMSG;

        r = segment_field_acquire(f, payload, eq - (const char*) payload, &k);
        if (r == -EUCLEAN)
                return -EBADMSG; /* The file's fault after all */
        if (r < 0)
                return r;

        d.field = k;
        d.size = size;
        d.jenkins = jenkins_hash64(payload, size);
        d.hash2 = segmented_hash2(f, payload, size);

        if (!GREEDY_REALLOC(w->data, w->n_data + 1))
                return -ENOMEM;

        w->data[w->n_data] = d;

        r = segment_data_index(w, w->n_data);
        if (r < 0)
                return r;

        r = table_put(&w->data_by_offset, offset, w->n_data, /* ret_next= */ NULL);
        if (r < 0)
                return r;

        if (ret)
                *ret = w->n_data;

        w->n_data++;
        return 0;
}

static int segment_replay_entry(JournalFile *f, uint64_t offset, uint64_t ordinal) {
        SegmentedWriter *w = ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(f)->segmented)->writer);
        const SegmentedField *fields;
        size_t n;
        Object *o;
        int r;

        /* Contexts of the tail are not reused */

        r = journal_file_move_to_object(f, OBJECT_ENTRY, offset, &o);
        if (r < 0)
                return r;

        r = segmented_entry_fields(f, o, offset, &fields, &n);
        if (r < 0)
                return r;

        FOREACH_ARRAY(i, fields, n) {
                if (i->type == SEGMENTED_FIELD_INLINE) {
                        const void *payload;
                        size_t size;

                        r = segmented_inline_payload(f, i->offset, /* field= */ NULL, 0, &payload, &size);
                        if (r < 0)
                                return r;

                        r = segment_inline_reference(f, payload, size);
                        if (r == -EUCLEAN)
                                return -EBADMSG; /* The file's fault after all */
                } else {
                        size_t q;

                        r = segment_data_load(f, i->offset, &q);
                        if (r < 0)
                                return r;

                        r = segment_data_reference(w, q, ordinal);
                }
                if (r < 0)
                        return r;
        }

        return 0;
}

static int segment_replay(JournalFile *f, uint8_t *ret_last_type) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint64_t ordinal = 0;
        uint8_t last = 0;
        int r;

        for (uint64_t p = a->tail_offset; p < a->scan_offset;) {
                ObjectHeader *h, copy;

                r = journal_file_move_to(f, OBJECT_UNUSED, /* keep_always= */ false, p, sizeof(ObjectHeader), (void**) &h);
                if (r < 0)
                        return r;

                copy = *h;

                switch (copy.type) {

                case OBJECT_DATA:
                        r = segment_data_load(f, p, NULL);
                        if (r < 0)
                                return r;
                        break;

                case OBJECT_INDEX:
                        /* Only the newest index may be part of the tail. Another one was skipped as
                         * damaged, and the segments around it would get mixed up. */
                        if (p != a->tail_offset)
                                return -EBADMSG;
                        break;

                case OBJECT_ENTRY:
                        if (ordinal >= a->n_tail_entries || a->tail_entries[ordinal] != p)
                                return -EBADMSG;

                        r = segment_replay_entry(f, p, ordinal++);
                        if (r < 0)
                                return r;
                        break;

                default:
                        ;
                }

                last = copy.type;
                p += ALIGN64(le64toh(copy.size));
        }

        if (ordinal != a->n_tail_entries)
                return -EBADMSG;

        if (ret_last_type)
                *ret_last_type = last;

        return 0;
}

void segmented_writer_close(JournalFile *f) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        SegmentedWriter *w = a->writer;
        int r;

        if (!w)
                return;

        r = segmented_flush(f);
        if (r < 0)
                log_debug_errno(r, "Failed to write the last entries to %s, dropping them: %m", f->path);

        entry_reset(w);
        batch_clear(w);
        segment_clear(w);

        free(w->data);
        free(w->fields);
        free(w->contexts);
        free(w->buffer);
        free(w->objects);
        free(w->pending);

        a->writer = mfree(w);
}

int segmented_writer_open(JournalFile *f, bool newly_created) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint8_t last = 0;
        int r;

        assert(!a->writer);

        if (f->header->state == STATE_ARCHIVED)
                return -ESHUTDOWN; /* An archived file is never written again */

        /* Readers ignore the state in the header, but journalctl --verify reports anything else */
        if (a->disk_header->state != STATE_OFFLINE)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Journal file %s has a damaged header, not writing to it.", f->path);

        if (!newly_created && a->scan_offset != (uint64_t) f->last_stat.st_size)
                /* The end is not a valid object. Cutting it off might remove more than a torn write,
                 * hence leave the file alone and let the caller start a new one. */
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Journal file %s does not end with a valid object, not writing to it.", f->path);

        if (a->scan_offset - a->tail_offset > 2 * TAIL_SIZE_MAX)
                /* Probably an index is damaged. Replaying all it covered would take too long. */
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Journal file %s has too much that is not indexed, not writing to it.", f->path);

        a->writer = new(SegmentedWriter, 1);
        if (!a->writer)
                return -ENOMEM;

        *a->writer = (SegmentedWriter) {
                .checked = f->last_stat.st_size,
                .synced_index_offset = le64toh(a->disk_header->synced_index_offset),
                .flushed = a->scan_offset,
        };

        if (!newly_created) {
                r = segment_replay(f, &last);
                a->writer->data_by_offset = hashmap_free(a->writer->data_by_offset);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read tail of journal file %s: %m", f->path);

                if (JOURNAL_HEADER_SEALED(f->header) && last != OBJECT_TAG)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBUSY),
                                               "Sealed journal file %s does not end with a tag. Assuming unclean closing.", f->path);
        }

        f->header->state = STATE_ONLINE;
        return 0;
}

/* Sync and archival */

static void segmented_archive(JournalFile *f) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        SegmentedWriter *w = ASSERT_PTR(a->writer);
        int r;

        if (w->archived)
                return;

        r = segmented_checkpoint(f);
        if (r < 0)
                log_debug_errno(r, "Failed to write index to %s, ignoring: %m", f->path);

        /* From now on the file belongs to the offline thread */
        w->archived = true;
}

void segmented_offline_prepare(JournalFile *f) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        SegmentedWriter *w = ASSERT_PTR(a->writer);
        int r;

        /* The sync and the archival have to cover the batch */
        r = segmented_flush(f);
        if (r < 0)
                log_debug_errno(r, "Failed to write the last entries to %s: %m", f->path);

        if (f->archive) {
                /* The offline thread may already use what was recorded */
                if (__atomic_load_n(&w->offline_archive, __ATOMIC_SEQ_CST))
                        return;

                segmented_archive(f);

                __atomic_store_n(&w->offline_archive, true, __ATOMIC_SEQ_CST);
                return;
        }

        uint64_t newest = a->n_indexes > 0 ? a->indexes[a->n_indexes - 1].offset : 0;
        __atomic_store_n(&w->sync_index_offset, newest, __ATOMIC_SEQ_CST);
}

static int header_write_synced_index(JournalFile *f, uint64_t offset) {
        SegmentedWriter *w = ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(f)->segmented)->writer);
        le64_t v = htole64(offset);
        int r;

        /* Runs in the offline thread. Readers map the header, so they see the change right away. */
        r = pwrite_full(f->fd, &v, sizeof(v), offsetof(Header, synced_index_offset));
        if (r < 0)
                return r;

        w->synced_index_offset = offset;
        return 0;
}

static int offline_sync(JournalFile *f) {
        SegmentedWriter *w = ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(f)->segmented)->writer);
        uint64_t offset;

        /* The main thread writes an index before it records it, and may record a newer one while the sync
         * runs. Read the offset before the sync starts, so that the sync covers the index it names. */
        offset = __atomic_load_n(&w->sync_index_offset, __ATOMIC_SEQ_CST);

        if (fdatasync(f->fd) < 0) {
                w->sync_failed = true;
                return -errno;
        }

        /* After a failed sync, some data may never reach the disk, and no later sync can vouch for it */
        if (w->sync_failed || offset == 0 || offset == w->synced_index_offset)
                return 0;

        /* The sync covered the index, so the header may name it */
        return header_write_synced_index(f, offset);
}

static void offline_archive(JournalFile *f) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        SegmentedWriter *w = ASSERT_PTR(a->writer);
        uint8_t state = STATE_ARCHIVED;
        uint64_t newest;
        int r;

        /* The writer gave up on the file, which may end in a partial object that nothing can follow.
         * The header is left alone then, like the one of a file whose writer crashed. */
        if (w->failed) {
                (void) fsync(f->fd);
                return;
        }

        newest = a->n_indexes > 0 ? a->indexes[a->n_indexes - 1].offset : 0;

        /* The header may only name an index that is known to be on disk. After a failed sync, it keeps
         * naming the one it names. */
        if (fdatasync(f->fd) < 0) {
                log_debug_errno(errno, "Failed to sync %s before archiving it: %m", f->path);
                w->sync_failed = true;
        }

        r = 0;
        if (!w->sync_failed && newest != w->synced_index_offset)
                r = header_write_synced_index(f, newest);
        if (r >= 0)
                r = pwrite_full(f->fd, &state, sizeof(state), offsetof(Header, state));
        if (r < 0) {
                log_debug_errno(r, "Failed to write the header of %s: %m", f->path);
                w->failed = true;
        }

        (void) fsync(f->fd);
}

bool segmented_offline(JournalFile *f) {
        SegmentedWriter *w = ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(f)->segmented)->writer);
        int r;

        /* May run in a thread while the main thread appends. Only use what segmented_offline_prepare()
         * recorded, or what the main thread leaves alone once the file is archived. Access the file through
         * system calls, not the mmap cache. */

        if (!__atomic_load_n(&w->offline_archive, __ATOMIC_SEQ_CST)) {
                r = offline_sync(f);
                if (r < 0)
                        log_debug_errno(r, "Failed to sync %s: %m", f->path);
                return false;
        }

        if (w->archive_done)
                return false;

        offline_archive(f);
        w->archive_done = true;
        return !w->failed;
}

int segmented_offline_finish(JournalFile *f) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        SegmentedWriter *w = ASSERT_PTR(a->writer);

        if (!w->archive_done)
                return 0;

        /* A failed archival leaves the file unarchived, but it stays readable */
        if (w->failed)
                return -EIO;

        f->header->state = STATE_ARCHIVED;
        return 0;
}
