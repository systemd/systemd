/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <threads.h>
#include <unistd.h>

#include "alloc-util.h"
#include "env-util.h"
#include "io-util.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-segmented.h"
#include "journal-segmented-internal.h"
#include "log.h"
#include "random-util.h"
#include "set.h"
#include "siphash24.h"
#include "sort-util.h"
#include "time-util.h"

#ifdef __clang__
#  pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

#define ENTRY_ITEMS_OFFSET offsetof(Object, entry.items)

/* Readers check unsynced objects while scanning the log, so checksum computation has to be fast. x86-64
 * computes CRC32C with the SSE 4.2 crc32 instruction. Other CPUs use slicing-by-8 tables. */

#define CRC32C_POLY UINT32_C(0x82F63B78)

static uint32_t crc32c_table[8][256];
static pthread_once_t crc32c_once = PTHREAD_ONCE_INIT;

static void crc32c_table_init(void) {
        for (unsigned i = 0; i < 256; i++) {
                uint32_t c = i;

                for (unsigned k = 0; k < 8; k++)
                        c = c & 1 ? (c >> 1) ^ CRC32C_POLY : c >> 1;

                crc32c_table[0][i] = c;
        }

        for (unsigned i = 0; i < 256; i++)
                for (unsigned t = 1; t < 8; t++)
                        crc32c_table[t][i] = (crc32c_table[t - 1][i] >> 8) ^ crc32c_table[0][crc32c_table[t - 1][i] & 0xff];
}

static uint32_t crc32c_sw(uint32_t crc, const uint8_t *p, size_t n) {
        assert_se(pthread_once(&crc32c_once, crc32c_table_init) == 0);

        for (; n >= 8; n -= 8, p += 8) {
                uint64_t v;

                memcpy(&v, p, sizeof(v));
                v = le64toh(v) ^ crc;

                crc = crc32c_table[7][v & 0xff] ^
                      crc32c_table[6][(v >> 8) & 0xff] ^
                      crc32c_table[5][(v >> 16) & 0xff] ^
                      crc32c_table[4][(v >> 24) & 0xff] ^
                      crc32c_table[3][(v >> 32) & 0xff] ^
                      crc32c_table[2][(v >> 40) & 0xff] ^
                      crc32c_table[1][(v >> 48) & 0xff] ^
                      crc32c_table[0][v >> 56];
        }

        for (; n > 0; n--, p++)
                crc = (crc >> 8) ^ crc32c_table[0][(crc ^ *p) & 0xff];

        return crc;
}

#if defined(__x86_64__)
__attribute__((target("sse4.2")))
static uint32_t crc32c_hw(uint32_t crc, const uint8_t *p, size_t n) {
        uint64_t c = crc;

        for (; n >= 8; n -= 8, p += 8) {
                uint64_t v;

                memcpy(&v, p, sizeof(v));
                c = __builtin_ia32_crc32di(c, v);
        }

        for (; n > 0; n--, p++)
                c = __builtin_ia32_crc32qi((uint32_t) c, *p);

        return (uint32_t) c;
}

static bool crc32c_hw_supported(void) {
        static thread_local int cached = -1;

        if (cached < 0) {
                __builtin_cpu_init();
                cached = __builtin_cpu_supports("sse4.2");
        }

        return cached;
}
#endif

static uint32_t crc32c(uint32_t crc, const void *data, size_t size) {
        assert(data || size == 0);

#if defined(__x86_64__)
        if (crc32c_hw_supported())
                return crc32c_hw(crc, data, size);
#endif

        return crc32c_sw(crc, data, size);
}

bool segmented_requested(void) {
        int r;

        /* Tests switch between the formats within one process, hence the value is not cached, unlike the
         * other knobs. */

        r = secure_getenv_bool("SYSTEMD_JOURNAL_SEGMENTED");
        if (r < 0) {
                if (r != -ENXIO)
                        log_debug_errno(r, "Failed to parse $SYSTEMD_JOURNAL_SEGMENTED environment variable, ignoring: %m");
                return false;
        }

        return r;
}

size_t segmented_checked_size(const ObjectHeader *h) {
        assert(h);

        switch (h->type) {

        case OBJECT_DATA:
                return offsetof(SegmentedDataObject, payload);

        case OBJECT_INDEX:
                return sizeof(IndexObject);

        default:
                return le64toh(h->size);
        }
}

uint64_t segmented_process_hash(const void *data, size_t size) {
        static thread_local uint8_t key[16];
        static thread_local bool initialized = false;

        if (!initialized) {
                random_bytes(key, sizeof(key));
                initialized = true;
        }

        return siphash24(data, size, key);
}

uint64_t segmented_hash2(JournalFile *f, const void *data, size_t size) {
        static const uint8_t salt[16] = {
                0x6a, 0x6f, 0x75, 0x72, 0x6e, 0x61, 0x6c, 0x2d,
                0x61, 0x70, 0x70, 0x65, 0x6e, 0x64, 0x6f, 0x6e,
        };
        uint8_t key[16];

        assert(f);
        assert(f->header);

        for (size_t i = 0; i < sizeof(key); i++)
                key[i] = f->header->file_id.bytes[i] ^ salt[i];

        return siphash24(data, size, key);
}

uint32_t segmented_checksum_with_file_id(sd_id128_t file_id, uint64_t distance, const void *object, size_t size) {
        static const uint8_t zero[sizeof_field(ObjectHeader, checksum)] = {};
        le64_t o = htole64(distance);
        uint32_t crc;

        assert(object);
        assert(size >= sizeof(ObjectHeader));

        assert_cc(offsetof(ObjectHeader, checksum) + sizeof(zero) == offsetof(ObjectHeader, size));

        crc = crc32c(UINT32_MAX, file_id.bytes, sizeof(file_id.bytes));
        crc = crc32c(crc, &o, sizeof(o));
        crc = crc32c(crc, object, offsetof(ObjectHeader, checksum));
        crc = crc32c(crc, zero, sizeof(zero));
        crc = crc32c(crc, (const uint8_t*) object + offsetof(ObjectHeader, size), size - offsetof(ObjectHeader, size));

        return ~crc;
}

uint32_t segmented_payload_checksum(sd_id128_t file_id, const void *payload, size_t size) {
        uint32_t crc;

        assert(payload || size == 0);

        crc = crc32c(UINT32_MAX, file_id.bytes, sizeof(file_id.bytes));
        crc = crc32c(crc, payload, size);

        return ~crc;
}

uint32_t segmented_checksum(JournalFile *f, uint64_t distance, const void *object, size_t size) {
        assert(f);
        assert(f->header);

        return segmented_checksum_with_file_id(f->header->file_id, distance, object, size);
}

uint64_t segmented_object_size_min(uint8_t type) {
        switch (type) {

        case OBJECT_DATA:
                return offsetof(SegmentedDataObject, payload) + 1;

        case OBJECT_CONTEXT:
                return offsetof(ContextObject, items) + sizeof(le32_t);

        case OBJECT_ENTRY:
                return ENTRY_ITEMS_OFFSET + ALIGN64(sizeof(le32_t));

        case OBJECT_TAG:
                return sizeof(TagObject);

        case OBJECT_INDEX:
                return sizeof(IndexObject);

        default:
                return UINT64_MAX;
        }
}

static bool reference_is_valid(JournalFile *f, uint64_t reference, uint64_t referrer) {
        return VALID64(reference) &&
                reference >= le64toh(f->header->header_size) &&
                reference < referrer;
}

/* Items of entries and contexts are distances back from the object that contains them */
static bool item_is_valid(JournalFile *f, uint64_t distance, uint64_t referrer) {
        return distance > 0 && distance <= referrer && reference_is_valid(f, referrer - distance, referrer);
}

static bool section_is_valid(const SegmentedIndex *i, uint64_t offset, uint64_t n, uint64_t item_size) {
        uint64_t sz;

        if (n == 0)
                return true;
        if (!VALID64(offset) || offset < sizeof(IndexObject))
                return false;
        if (!MUL_SAFE(&sz, n, item_size))
                return false;

        return segmented_index_contains(i, offset, sz);
}

int segmented_index_parse(JournalFile *f, const IndexObject *o, uint64_t offset, SegmentedIndex *ret) {
        assert(f);
        assert(o);

        SegmentedIndex i = {
                .offset = offset,
                .size = le64toh(o->object.size),
                .head_offset = offset - MIN(le64toh(o->segment_size), offset),
                .n_entries = le64toh(o->n_entries),
                .tail_seqnum = le64toh(o->tail_entry_seqnum),
                .n_index_entries = le32toh(o->n_index_entries),
                .entry_array_offset = le32toh(o->entry_array_offset),
                .n_fields = le32toh(o->n_fields),
                .field_table_offset = le32toh(o->field_table_offset),
                .n_data_items = le32toh(o->n_data_items),
                .data_table_offset = le32toh(o->data_table_offset),
                .payload_checksum = le32toh(o->payload_checksum),
        };

        if (o->object.type != OBJECT_INDEX || i.size < sizeof(IndexObject))
                return -EBADMSG;

        /* A segment holds at least one object */
        if (le64toh(o->segment_size) > offset || !reference_is_valid(f, i.head_offset, i.offset))
                return -EBADMSG;

        if (le64toh(o->tail_entry_distance) > offset - le64toh(f->header->header_size) ||
            (o->n_entries != 0) != (o->tail_entry_distance != 0))
                return -EBADMSG;

        if (i.n_index_entries == 0 || i.n_index_entries > i.n_entries ||
            i.n_index_entries > (i.offset - i.head_offset) / segmented_object_size_min(OBJECT_ENTRY))
                return -EBADMSG;

        if (!section_is_valid(&i, i.entry_array_offset, i.n_index_entries, sizeof(le32_t)) ||
            !section_is_valid(&i, i.field_table_offset, i.n_fields, sizeof(IndexFieldItem)) ||
            !section_is_valid(&i, i.data_table_offset, i.n_data_items, sizeof(IndexDataItem)))
                return -EBADMSG;

        i.first_ordinal = i.n_entries - i.n_index_entries;

        if (ret)
                *ret = i;

        return 0;
}

int segmented_check_object(JournalFile *f, Object *o, uint64_t offset, size_t available) {
        uint64_t size;
        bool whole;
        int r;

        assert(f);
        assert(o);

        /* The caller checked the size against the minimum for the type, and made 'available' bytes
         * accessible. Items are only checked if that covers the whole object. */

        size = le64toh(o->object.size);
        whole = available >= size;

        if (o->object.type != OBJECT_DATA && (o->object.flags & _OBJECT_COMPRESSED_MASK))
                return -EBADMSG;

        switch (o->object.type) {

        case OBJECT_DATA:
                if (o->object.aux != 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Data object with items: %" PRIu64, offset);

                if (o->object.flags & ~_OBJECT_COMPRESSED_MASK)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Data object with unknown flags: %" PRIu64, offset);

                if (!ISPOWEROF2(o->object.flags & _OBJECT_COMPRESSED_MASK) && (o->object.flags & _OBJECT_COMPRESSED_MASK) != 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Data object with multiple compression flags: %" PRIu64, offset);
                break;

        case OBJECT_CONTEXT: {
                uint64_t n = le16toh(o->object.aux), previous = 0;

                /* The item count is limited, so that the cost of reading an entry stays bounded by its
                 * size */
                if (n == 0 || n > ENTRY_FIELD_COUNT_MAX || size != offsetof(Object, context.items) + n * sizeof(le32_t))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Bad context size %" PRIu64 " for %" PRIu64 " items: %" PRIu64,
                                               size, n, offset);

                for (uint64_t i = 0; whole && i < n; i++) {
                        uint64_t item = le32toh(o->context.items[i]);

                        if (!item_is_valid(f, item, offset) || item <= previous)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Bad context item %" PRIu64 ": %" PRIu64, i, offset);

                        previous = item;
                }

                break;
        }

        case OBJECT_ENTRY: {
                uint64_t n = le16toh(o->object.aux), inline_offset, previous = 0;
                bool context = false;

                inline_offset = ENTRY_ITEMS_OFFSET + ALIGN64(n * sizeof(le32_t));

                if (n == 0 || size < inline_offset)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Bad entry size %" PRIu64 " for %" PRIu64 " items: %" PRIu64,
                                               size, n, offset);

                r = journal_file_check_entry_header(o, offset);
                if (r < 0)
                        return r;

                if (!whole || offset == f->segmented->checked_entry_offset)
                        break;

                for (uint64_t i = 0; i < n; i++) {
                        uint64_t item = le32toh(o->entry.items.compact[i].object_offset),
                                 p = item & ~(uint64_t) _ENTRY_ITEM_TYPE_MASK;
                        bool good;

                        switch (item & _ENTRY_ITEM_TYPE_MASK) {

                        case ENTRY_ITEM_DATA:
                                good = item_is_valid(f, p, offset);
                                break;

                        case ENTRY_ITEM_CONTEXT:
                                /* An entry refers to one context at most, so that the cost of
                                 * reading it stays bounded by its size */
                                good = !context && item_is_valid(f, p, offset);
                                context = true;
                                break;

                        case ENTRY_ITEM_INLINE:
                                good = p >= inline_offset &&
                                        p <= size - sizeof(InlineData) &&
                                        le32toh(((const InlineData*) ((const uint8_t*) o + p))->size) > 0 &&
                                        le32toh(((const InlineData*) ((const uint8_t*) o + p))->size) <= size - p - sizeof(InlineData);
                                break;

                        default:
                                good = false;
                        }

                        if (!good || item <= previous)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Bad entry item %" PRIu64 ": %" PRIu64, i, offset);

                        previous = item;
                }

                f->segmented->checked_entry_offset = offset;
                break;
        }

        case OBJECT_TAG:
                if (size != sizeof(TagObject))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid object tag size: %" PRIu64, offset);

                if (!VALID_EPOCH(le64toh(o->tag.epoch)))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid object tag epoch: %" PRIu64, offset);
                break;

        case OBJECT_INDEX:

                return segmented_index_parse(f, &o->index, offset, NULL);

        default:
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Object of type %u in segmented file: %" PRIu64,
                                       o->object.type, offset);
        }

        return 0;
}

static int index_load(JournalFile *f, uint64_t offset, IndexObject *ret_object, SegmentedIndex *ret) {
        uint64_t file_size;
        IndexObject o;
        ssize_t n;
        int r;

        assert(f);
        assert(ret);

        file_size = (uint64_t) f->last_stat.st_size;

        if (!reference_is_valid(f, offset, file_size) || file_size - offset < sizeof(IndexObject))
                return -EBADMSG;

        /* A page fault in a mapping makes the kernel read the whole readahead window around the faulting
         * page, which is 4 MiB on btrfs. Opening a file loads the header of every index in the chain, and
         * most queries don't need the entries around them. pread() reads only the pages that hold the
         * index header. */
        n = pread(f->fd, &o, sizeof(o), offset);
        if (n < 0)
                return -errno;
        if ((size_t) n < sizeof(o))
                return -EIO;

        if (o.object.type != OBJECT_INDEX ||
            le64toh(o.object.size) < sizeof(IndexObject) ||
            le64toh(o.object.size) > file_size - offset)
                return -EBADMSG;

        if (segmented_checksum(f, le64toh(o.segment_size), &o, sizeof(IndexObject)) != le32toh(o.object.checksum))
                return -EBADMSG;

        r = segmented_index_parse(f, &o, offset, ret);
        if (r < 0)
                return r;

        if (ret_object)
                *ret_object = o;

        return 0;
}

bool segmented_index_follows(const SegmentedIndex *i, uint64_t head, uint64_t n_before) {
        assert(i);

        return i->head_offset == head && i->first_ordinal == n_before;
}

static void header_apply_index(Header *h, const SegmentedIndex *i, const IndexObject *o) {
        assert(h);
        assert(i);
        assert(o);

        h->n_objects = htole64(le64toh(o->n_objects) + 1);
        h->n_entries = o->n_entries;
        h->n_data = o->n_data;
        h->n_tags = o->n_tags;
        h->head_entry_seqnum = o->head_entry_seqnum;
        if (o->n_entries != 0)
                h->tail_entry_seqnum = o->tail_entry_seqnum;
        h->head_entry_realtime = o->head_entry_realtime;
        h->tail_entry_realtime = o->tail_entry_realtime;
        h->tail_entry_monotonic = o->tail_entry_monotonic;
        h->tail_entry_boot_id = o->tail_entry_boot_id;
        h->tail_entry_offset = htole64(o->tail_entry_distance != 0 ? i->offset - le64toh(o->tail_entry_distance) : 0);
        h->tail_object_offset = htole64(i->offset);
        h->arena_size = htole64(i->offset + ALIGN64(i->size) - le64toh(h->header_size));
}

void segmented_header_add_object(Header *h, uint8_t type, uint64_t offset, uint64_t end) {
        assert(h);

        h->n_objects = htole64(le64toh(h->n_objects) + 1);
        h->tail_object_offset = htole64(offset);
        h->arena_size = htole64(end - le64toh(h->header_size));

        if (type == OBJECT_DATA)
                h->n_data = htole64(le64toh(h->n_data) + 1);
        else if (type == OBJECT_TAG)
                h->n_tags = htole64(le64toh(h->n_tags) + 1);
}

void segmented_header_add_entry(
                Header *h,
                uint64_t offset,
                uint64_t seqnum,
                uint64_t realtime,
                uint64_t monotonic,
                sd_id128_t boot_id) {

        assert(h);

        if (h->n_entries == 0) {
                h->head_entry_seqnum = htole64(seqnum);
                h->head_entry_realtime = htole64(realtime);
        }

        h->n_entries = htole64(le64toh(h->n_entries) + 1);
        h->tail_entry_seqnum = htole64(seqnum);
        h->tail_entry_realtime = htole64(realtime);
        h->tail_entry_monotonic = htole64(monotonic);
        h->tail_entry_boot_id = boot_id;
        h->tail_entry_offset = htole64(offset);
}

static void header_reset(JournalFile *f) {
        Header *h = ASSERT_PTR(ASSERT_PTR(f)->header);

        h->n_objects = h->n_entries = h->n_data = h->n_tags = 0;
        h->head_entry_seqnum = 0;
        h->head_entry_realtime = h->tail_entry_realtime = h->tail_entry_monotonic = 0;
        h->tail_entry_boot_id = SD_ID128_NULL;
        h->tail_entry_offset = h->tail_object_offset = 0;
        h->arena_size = 0;
}

static void tail_reset(JournalFile *f, uint64_t tail_offset, uint64_t scan_offset, uint64_t n_indexed_entries) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);

        a->tail_offset = a->scan_base = tail_offset;
        a->scan_offset = scan_offset;
        a->n_indexed_entries = n_indexed_entries;
        a->n_tail_entries = 0;
}

static int index_chain_load(JournalFile *f, uint64_t offset) {
        _cleanup_free_ SegmentedIndex *chain = NULL;
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        size_t n = 0;
        int r;

        assert(a->n_indexes == 0);

        IndexObject newest_object;

        for (;;) {
                SegmentedIndex i;

                r = index_load(f, offset, n == 0 ? &newest_object : NULL, &i);
                if (r < 0)
                        return log_debug_errno(r, "Failed to load index at %" PRIu64 " of %s: %m", offset, f->path);

                if (n > 0 &&
                    !segmented_index_follows(chain + n - 1, i.offset, i.n_entries))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Index at %" PRIu64 " of %s does not fit the one that follows it.",
                                               offset, f->path);

                if (!GREEDY_REALLOC(chain, n + 1))
                        return -ENOMEM;

                chain[n++] = i;

                if (i.head_offset == le64toh(f->header->header_size)) {
                        if (i.first_ordinal != 0)
                                return -EBADMSG;
                        break;
                }

                offset = i.head_offset;
        }

        if (!GREEDY_REALLOC(a->indexes, n))
                return -ENOMEM;

        /* The chain is newest first */
        for (size_t k = 0; k < n; k++)
                a->indexes[k] = chain[n - 1 - k];
        a->n_indexes = n;
        a->indexes_generation++;

        const SegmentedIndex *newest = a->indexes + a->n_indexes - 1;

        header_apply_index(f->header, newest, &newest_object);
        tail_reset(f, newest->offset, newest->offset + ALIGN64(newest->size), newest->n_entries);

        return 0;
}

int segmented_index_payload_verify(JournalFile *f, const SegmentedIndex *i) {
        void *p;
        int r;

        assert(f);
        assert(i);

        r = journal_file_move_to(
                        f,
                        OBJECT_INDEX,
                        /* keep_always= */ false,
                        i->offset + sizeof(IndexObject),
                        i->size - sizeof(IndexObject),
                        &p);
        if (r < 0)
                return r;

        return i->payload_checksum == segmented_payload_checksum(f->header->file_id, p, i->size - sizeof(IndexObject));
}

static int index_adopt(JournalFile *f, const SegmentedIndex *i) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        int r;

        assert(i);

        if (i->n_entries != le64toh(f->header->n_entries) ||
            !segmented_index_follows(i, a->tail_offset, a->n_indexed_entries) ||
            i->n_index_entries != a->n_tail_entries)
                return 0;

        /* The index is newer than the one the header names, hence no sync vouches for it. Check that all
         * of it made it to disk. */
        r = segmented_index_payload_verify(f, i);
        if (r < 0)
                return r;
        if (r == 0)
                return 0;

        if (!GREEDY_REALLOC(a->indexes, a->n_indexes + 1))
                return -ENOMEM;

        a->indexes[a->n_indexes++] = *i;
        a->indexes_generation++;

        tail_reset(f, i->offset, i->offset + ALIGN64(i->size), i->n_entries);
        return 1;
}

static int scan_object(JournalFile *f, uint64_t file_size, uint64_t synced) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint64_t p = a->scan_offset, size, checked;
        Header *h = f->header;
        Object *o;
        int r;

        /* Objects are referenced by 32-bit offsets */
        /* The index of the tail refers to its entries with 32-bit offsets */
        if (p - a->tail_offset > UINT32_MAX || p > file_size || file_size - p < sizeof(ObjectHeader))
                return 0;

        r = journal_file_move_to(f, OBJECT_UNUSED, /* keep_always= */ false, p, sizeof(ObjectHeader), (void**) &o);
        if (r < 0)
                return r;

        size = le64toh(READ_NOW(o->object.size));
        if (size < segmented_object_size_min(o->object.type) || size > file_size - p)
                return 0;

        /* The payload of data objects and indexes may be large, only map the checked part. */
        checked = IN_SET(o->object.type, OBJECT_DATA, OBJECT_INDEX) ? segmented_checked_size(&o->object) : size;

        r = journal_file_move_to(f, OBJECT_UNUSED, /* keep_always= */ false, p, checked, (void**) &o);
        if (r < 0)
                return r;

        /* A partial write might have been cut off and replaced, hence check the object even if an entry at
         * this offset was checked before. */
        a->checked_entry_offset = 0;

        /* A sync wrote the objects before 'synced' to disk completely, so their checksums need no check.
         * Readers use an index without further checks, so the checksum of an index is always checked. */
        bool valid =
                le64toh(o->object.size) == size &&
                ((p + checked <= synced && o->object.type != OBJECT_INDEX) ||
                 segmented_checksum(f, p - a->scan_base, o, checked) == le32toh(o->object.checksum)) &&
                segmented_check_object(f, o, p, SIZE_MAX) >= 0;
        if (!valid) {
                /* Indexes are derived data, hence a bad one does not end the scan. */
                if (o->object.type != OBJECT_INDEX)
                        return 0;

                log_debug("Skipping over invalid index at %" PRIu64 " of %s.", p, f->path);
        }

        if (o->object.type == OBJECT_ENTRY && !GREEDY_REALLOC(a->tail_entries, a->n_tail_entries + 1))
                return -ENOMEM;

        if (o->object.type == OBJECT_INDEX) {
                SegmentedIndex i;

                if (valid && segmented_index_parse(f, &o->index, p, &i) >= 0) {
                        r = index_adopt(f, &i);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                segmented_header_add_object(h, OBJECT_INDEX, p, a->scan_offset);
                                return 1;
                        }
                }

                log_debug("Skipping over index at %" PRIu64 " of %s.", p, f->path);

                /* The writer started a new segment with the index, also if readers can't use it */
                a->scan_base = p;
        }

        a->scan_offset = p + ALIGN64(size);

        switch (o->object.type) {

        case OBJECT_ENTRY:
                a->tail_entries[a->n_tail_entries++] = (uint32_t) (p - a->tail_offset);
                segmented_header_add_entry(h, p, le64toh(o->entry.seqnum), le64toh(o->entry.realtime),
                                             le64toh(o->entry.monotonic), o->entry.boot_id);
                break;

        case OBJECT_DATA:
        case OBJECT_TAG:
        case OBJECT_CONTEXT:
        case OBJECT_INDEX:
                break;

        default:
                assert_not_reached();
        }

        segmented_header_add_object(h, o->object.type, p, a->scan_offset);
        return 1;
}

static int scan(JournalFile *f) {
        uint64_t file_size = (uint64_t) ASSERT_PTR(f)->last_stat.st_size;
        Segmented *a = ASSERT_PTR(f->segmented);
        uint64_t prefetched = a->scan_offset;
        int r;

        uint64_t synced = le64toh(READ_NOW(f->segmented->disk_header->synced_offset));

        for (;;) {
                if (a->scan_offset >= prefetched && a->scan_offset < file_size) {
                        uint64_t size = MIN(file_size - a->scan_offset, 128 * U64_KB);

                        segmented_prefetch(f, a->scan_offset, size);
                        prefetched = a->scan_offset + size;
                }

                r = scan_object(f, file_size, synced);
                if (r <= 0)
                        return r;
        }
}

void segmented_set_readahead(JournalFile *f, bool b) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);

        a->readahead = b;
        a->prefetch_n = 0;
        mmap_cache_fd_set_random(f->cache_fd, !b);
}

static void state_reset(JournalFile *f) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);

        a->n_indexes = 0;
        a->indexes_generation++;
        tail_reset(f, le64toh(f->header->header_size), le64toh(f->header->header_size), 0);

        a->current_offset = a->current_ordinal = 0;
        if (a->readahead)
                segmented_set_readahead(f, false);
        a->prefetch_n = 0;
        a->fields_offset = 0;
        a->checked_entry_offset = 0;
        a->tail_fields = set_free(a->tail_fields);
        a->tail_field_names = mfree(a->tail_field_names);
        a->n_tail_field_names = 0;
        a->tail_fields_base = a->tail_fields_end = 0;

        FOREACH_ELEMENT(result, a->results)
                segmented_result_done(result);

        /* Cached DATA hashes become invalid if the file is replaced. */
        a->data_hashes = mfree(a->data_hashes);

        header_reset(f);
}

int segmented_refresh(JournalFile *f, usec_t ts) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint64_t n_entries;
        bool archived;
        int r;

        if (journal_file_writable(f))
                return 0; /* The writer keeps the shadow header up to date itself */

        if (f->header->state == STATE_ARCHIVED)
                return 0;

        if (!a->refresh_pending) {
                if (ts == USEC_INFINITY)
                        ts = now(CLOCK_BOOTTIME);

                if (a->last_refresh_usec != 0 && ts < usec_add(a->last_refresh_usec, SEGMENTED_REFRESH_USEC))
                        return 0;

                a->last_refresh_usec = ts;
        }

        a->refresh_pending = false;

        /* The writer marks the file archived after it wrote everything, hence look at the state before
         * the file size */
        archived = READ_NOW(a->disk_header->state) == STATE_ARCHIVED;

        /* A file that was deleted can still be read, until inotify reports it gone */
        r = journal_file_fstat(f);
        if (r < 0 && r != -EIDRM)
                return r;

        /* A damaged file may end in the padding of its last object */
        if (ALIGN64((uint64_t) f->last_stat.st_size) < a->scan_offset) {
                /* The writer never shrinks a file, hence it was replaced or damaged. */
                log_debug("Journal file %s shrank, reading it anew.", f->path);

                state_reset(f);

                /* Positions are invalid even if the scan fails. A partial scan is consistent, the next
                 * refresh continues it. */
                r = scan(f);
                if (r < 0)
                        log_debug_errno(r, "Failed to read journal file %s anew, ignoring: %m", f->path);

                return -ESTALE;
        }

        n_entries = le64toh(f->header->n_entries);

        r = scan(f);
        if (r < 0)
                return r;

        if (archived)
                f->header->state = STATE_ARCHIVED;

        return le64toh(f->header->n_entries) != n_entries;
}

int segmented_verify_header(JournalFile *f) {
        Header *h;
        uint64_t header_size, synced;

        assert(f);
        assert(f->header);

        /* The caller did the checks that apply to all formats. */

        if (!JOURNAL_HEADER_COMPACT(f->header) || !JOURNAL_HEADER_KEYED_HASH(f->header))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Segmented journal file %s lacks the compact or keyed hash flag.", f->path);

        header_size = le64toh(f->header->header_size);
        if (!JOURNAL_HEADER_CONTAINS(f->header, tail_entry_offset) || !VALID64(header_size))
                return -EBADMSG;

        if (header_size > (uint64_t) f->last_stat.st_size)
                return -ENODATA;

        h = f->segmented ? f->segmented->disk_header : f->header;
        synced = le64toh(READ_NOW(h->synced_offset));
        if (synced != 0 && (!VALID64(synced) || synced < header_size))
                return -EBADMSG;

        if (synced > (uint64_t) f->last_stat.st_size) {
                int r;

                /* A writer can sync after the opener took its file-size snapshot. */
                r = journal_file_fstat(f);
                if (r < 0)
                        return r;
                if (synced > (uint64_t) f->last_stat.st_size)
                        return -EBADMSG;
        }

        return 0;
}

static void open_reset(JournalFile *f) {
        state_reset(f);

        /* The on-disk tail_entry_seqnum is the sequence number the file continues from. It is needed as long
         * as there are no entries. */
        f->header->tail_entry_seqnum = f->segmented->disk_header->tail_entry_seqnum;

        f->header->state = STATE_OFFLINE;
}

int segmented_open(JournalFile *f, bool newly_created) {
        _cleanup_free_ Segmented *a = NULL;
        uint64_t index_offset;
        Header *shadow;
        bool archived;
        int r;

        assert(f);
        assert(f->header);
        assert(!f->segmented);

        a = new0(Segmented, 1);
        if (!a)
                return -ENOMEM;

        shadow = new0(Header, 1);
        if (!shadow)
                return -ENOMEM;

        memcpy(shadow, f->header, MIN(sizeof(Header), le64toh(f->header->header_size)));

        a->disk_header = f->header;
        f->header = shadow;
        f->segmented = TAKE_PTR(a);

        open_reset(f);

        if (newly_created)
                return 0;

        /* Archival must precede the size snapshot before refreshes can stop permanently. */
        archived = READ_NOW(f->segmented->disk_header->state) == STATE_ARCHIVED;
        r = journal_file_fstat(f);
        if (r < 0 && r != -EIDRM)
                return r;

        /* The header names the newest index that a sync covered. The scan checks the indexes after it. */
        index_offset = le64toh(READ_NOW(f->segmented->disk_header->synced_index_offset));
        if (index_offset != 0) {
                r = index_chain_load(f, index_offset);
                if (r < 0) {
                        log_debug_errno(r, "Failed to load the index at %" PRIu64 " of %s that the header names, reading all of the file: %m",
                                        index_offset, f->path);
                        open_reset(f);
                }
        }

        r = scan(f);
        if (r < 0)
                return r;

        if (archived)
                f->header->state = STATE_ARCHIVED;
        return 0;
}

void segmented_close(JournalFile *f) {
        Segmented *a;

        assert(f);

        a = f->segmented;
        if (!a)
                return;

        FOREACH_ELEMENT(result, a->results)
                segmented_result_done(result);

        free(a->data_hashes);
        free(a->indexes);
        free(a->tail_entries);
        free(a->fields);
        free(a->inline_buffer);
        set_free(a->tail_fields);
        free(a->tail_field_names);

        free(f->header);
        f->header = a->disk_header;
        f->segmented = mfree(a);
}

static int index_ordinal_compare(const SegmentedIndex *key, const SegmentedIndex *i) {

        if (key->first_ordinal < i->first_ordinal)
                return -1;
        if (key->first_ordinal >= i->n_entries)
                return 1;
        return 0;
}

static SegmentedIndex* index_by_ordinal(Segmented *a, uint64_t ordinal) {
        assert(a);

        return typesafe_bsearch(&(SegmentedIndex) { .first_ordinal = ordinal }, a->indexes, a->n_indexes, index_ordinal_compare);
}

int segmented_index_entry_offset(JournalFile *f, const SegmentedIndex *i, uint64_t local, uint64_t *ret) {
        uint64_t p, q, first, last;
        le32_t *v;
        int r;

        assert(f);
        assert(i);
        assert(local < i->n_index_entries);
        assert(ret);

        first = local > 0 ? local - 1 : local;
        last = local + 1 < i->n_index_entries ? local + 1 : local;

        r = journal_file_move_to(
                        f,
                        OBJECT_ENTRY_ARRAY,
                        /* keep_always= */ false,
                        i->offset + i->entry_array_offset + first * sizeof(le32_t),
                        (last - first + 1) * sizeof(le32_t),
                        (void**) &v);
        if (r < 0)
                return r;

        q = le32toh(v[local - first]);
        p = i->head_offset + q;
        if (!VALID64(p) || p >= i->offset ||
            (first < local && le32toh(v[0]) >= q) ||
            (last > local && le32toh(v[last - first]) <= q))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Index at %" PRIu64 " of %s has invalid entry array.",
                                       i->offset, f->path);

        *ret = p;
        return 0;
}

static int segmented_entry_offset(JournalFile *f, uint64_t ordinal, uint64_t *ret) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        const SegmentedIndex *i;

        assert(ret);

        if (ordinal >= a->n_indexed_entries) {
                if (ordinal - a->n_indexed_entries >= a->n_tail_entries)
                        return -EADDRNOTAVAIL;

                *ret = a->tail_offset + a->tail_entries[ordinal - a->n_indexed_entries];
                return 0;
        }

        i = index_by_ordinal(a, ordinal);
        if (!i)
                return -EBADMSG;

        return segmented_index_entry_offset(f, i, ordinal - i->first_ordinal, ret);
}

static uint64_t n_entries_known(Segmented *a) {
        return a->n_indexed_entries + a->n_tail_entries;
}

uint64_t segmented_n_entries(JournalFile *f) {
        return n_entries_known(ASSERT_PTR(ASSERT_PTR(f)->segmented));
}

int segmented_entry_ordinal(JournalFile *f, uint64_t offset, direction_t direction, uint64_t *ret) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint64_t left, right, n;
        int r;

        assert(ret);

        if (offset == a->current_offset && offset != 0) {
                *ret = a->current_ordinal;
                return 1;
        }

        /* sd-journal looks for the entry after the current one by its offset plus or minus one */
        if (a->current_offset != 0 && direction == DIRECTION_DOWN && offset == a->current_offset + 1) {
                if (a->current_ordinal + 1 >= n_entries_known(a))
                        return 0;

                *ret = a->current_ordinal + 1;
                return 1;
        }
        if (a->current_offset != 0 && direction == DIRECTION_UP && offset == a->current_offset - 1) {
                if (a->current_ordinal == 0)
                        return 0;

                *ret = a->current_ordinal - 1;
                return 1;
        }

        n = n_entries_known(a);

        /* Without indexes, offsets before the tail are in the header */
        if (offset >= a->tail_offset || a->n_indexes == 0) {
                left = a->n_indexed_entries;
                right = n;
        } else {
                size_t l = 0, h = a->n_indexes;

                while (l < h) {
                        size_t m = (l + h) / 2;

                        if (a->indexes[m].offset <= offset)
                                l = m + 1;
                        else
                                h = m;
                }

                if (l >= a->n_indexes)
                        return -EBADMSG;

                left = a->indexes[l].first_ordinal;
                right = a->indexes[l].n_entries;
        }

        uint64_t limit = right;
        while (left < right) {
                uint64_t m = left + (right - left) / 2, p;

                r = segmented_entry_offset(f, m, &p);
                if (r < 0)
                        return r;

                if (p < offset)
                        left = m + 1;
                else
                        right = m;
        }

        if (direction == DIRECTION_DOWN) {
                if (left >= n)
                        return 0;

                *ret = left;
                return 1;
        }

        if (left < limit) {
                uint64_t p;

                r = segmented_entry_offset(f, left, &p);
                if (r < 0)
                        return r;

                if (p == offset) {
                        *ret = left;
                        return 1;
                }
        }

        if (left == 0)
                return 0;

        *ret = left - 1;
        return 1;
}

int segmented_entry_at(JournalFile *f, uint64_t ordinal, Object **ret_object, uint64_t *ret_offset) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint64_t p;
        int r;

        r = segmented_entry_offset(f, ordinal, &p);
        if (r < 0)
                return r;

        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, ret_object);
        if (ERRNO_IS_NEG_JOURNAL_CORRUPTION(r))
                return 0;
        if (r < 0)
                return r;

        a->current_offset = p;
        a->current_ordinal = ordinal;

        if (ret_offset)
                *ret_offset = p;

        return 1;
}

#define PREFETCH_ENTRIES_MIN 16U
#define PREFETCH_ENTRIES_MAX 1024U
/* Entries closer than this are prefetched with one read, including what lies between them */
#define PREFETCH_GAP_MAX (64U * 1024U)
/* A reader that loads at least one of every PREFETCH_DENSE_GAP entries, for this many entries in a row, gets
 * the readahead of the kernel */
#define PREFETCH_READAHEAD_ENTRIES 256U
#define PREFETCH_DENSE_GAP 4U

/* A prefetch reads the aligned windows of this size that contain the range. A window costs more bandwidth
 * than the range. An object that the reader loads later from the same window needs no read of its own. The
 * kernel reads at most the larger of the readahead window of the file and the largest I/O of the device for
 * each POSIX_FADV_WILLNEED, and ignores the rest of the range. On ext4, the readahead window is 128 KiB by
 * default, hence PREFETCH_WINDOW must not be larger. */
#define PREFETCH_WINDOW (128U * 1024U)

void segmented_prefetch_exact(JournalFile *f, uint64_t offset, uint64_t size) {
        assert(f);

        while (size > 0) {
                uint64_t n = MIN(size, (uint64_t) PREFETCH_WINDOW);

                if (posix_fadvise(f->fd, offset, n, POSIX_FADV_WILLNEED) != 0)
                        return;

                offset += n;
                size -= n;
        }
}

void segmented_prefetch(JournalFile *f, uint64_t offset, uint64_t size) {
        uint64_t end;

        assert(f);

        if (size == 0 || !ADD_SAFE(&end, offset, size))
                return;

        end = ALIGN_TO_U64(end, PREFETCH_WINDOW);
        for (offset = ALIGN_DOWN_U64(offset, PREFETCH_WINDOW); offset < end; offset += PREFETCH_WINDOW)
                if (posix_fadvise(f->fd, offset, PREFETCH_WINDOW, POSIX_FADV_WILLNEED) != 0)
                        return;
}

static uint64_t reading_position(uint64_t ordinal, direction_t direction) {

        return direction == DIRECTION_DOWN ? ordinal : UINT64_MAX - ordinal;
}

static void prefetch_entry_data(JournalFile *f, uint64_t offset) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint64_t n;
        Object *o;

        if (journal_file_move_to_category(f, MMAP_CACHE_CATEGORY_PREFETCH, offset, ENTRY_ITEMS_OFFSET, (void**) &o) < 0 ||
            o->object.type != OBJECT_ENTRY)
                return;

        n = le16toh(o->object.aux);
        if (le64toh(o->object.size) < ENTRY_ITEMS_OFFSET + n * sizeof(le32_t))
                return;

        if (journal_file_move_to_category(f, MMAP_CACHE_CATEGORY_PREFETCH, offset, ENTRY_ITEMS_OFFSET + n * sizeof(le32_t), (void**) &o) < 0)
                return;

        for (uint64_t i = 0; i < n; i++) {
                uint64_t item = le32toh(o->entry.items.compact[i].object_offset),
                         p = item & ~(uint64_t) _ENTRY_ITEM_TYPE_MASK, page;

                if (!IN_SET(item & _ENTRY_ITEM_TYPE_MASK, ENTRY_ITEM_DATA, ENTRY_ITEM_CONTEXT) || p == 0 || p > offset)
                        continue;

                p = offset - p;

                /* Consecutive entries refer to many of the same objects. Remember the pages prefetched
                 * last, so that each one needs only one system call. */
                page = p / page_size();
                uint64_t *slot = a->prefetch_pages + (page * UINT64_C(0x9E3779B97F4A7C15) >> 56) % SEGMENTED_PREFETCH_PAGES;
                if (*slot == page + 1)
                        continue;
                *slot = page + 1;

                segmented_prefetch(f, p, 1);
        }
}

static void prefetch_entry_offsets(JournalFile *f, uint64_t first, uint64_t last) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);

        FOREACH_ARRAY(i, a->indexes, a->n_indexes) {
                uint64_t from = MAX(first, i->first_ordinal),
                        to = MIN(last + 1, i->first_ordinal + i->n_index_entries);

                if (from < to)
                        segmented_prefetch(
                                        f,
                                        i->offset + i->entry_array_offset + (from - i->first_ordinal) * sizeof(le32_t),
                                        (to - from) * sizeof(le32_t));
        }
}

static bool prefetch_find(Segmented *a, uint64_t position, direction_t direction, const PostingBitmap *among, uint64_t *ret) {
        uint64_t o = reading_position(position, direction), limit = n_entries_known(a);

        if (direction == DIRECTION_DOWN) {
                if (among)
                        return posting_bitmap_find_first(among, o, limit, ret);
                if (o >= limit)
                        return false;
        } else {
                if (limit == 0)
                        return false;
                o = MIN(o, limit - 1);
                if (among)
                        return posting_bitmap_find_last(among, 0, o + 1, ret);
        }

        *ret = o;
        return true;
}

void segmented_prefetch_entries(JournalFile *f, uint64_t ordinal, direction_t direction, const PostingBitmap *among) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint64_t position = reading_position(ordinal, direction), n, next, start = 0, end = 0;
        size_t k = 0;

        if (a->readahead) {
                if (a->prefetch_direction == direction && position - a->prefetch_begin <= PREFETCH_DENSE_GAP) {
                        a->prefetch_begin = position;
                        return;
                }

                segmented_set_readahead(f, false);
        }

        bool sequential =
                a->prefetch_n > 0 &&
                a->prefetch_direction == direction &&
                position >= a->prefetch_begin &&
                position <= a->prefetch_end;

        if (sequential && position < a->prefetch_next)
                return;

        /* An entry refers to data objects anywhere before it, which the prefetching does not cover. When
         * the reader goes through most entries, the readahead of the kernel around those data objects
         * reads what the reader needs later. */
        if (sequential && a->prefetch_dense && a->prefetch_n >= PREFETCH_READAHEAD_ENTRIES) {
                segmented_set_readahead(f, true);
                a->prefetch_begin = position;
                return;
        }

        /* The entries up to the end of the last prefetch are in the page cache by now, or on their way. Their
         * data objects can lie anywhere before them, and the reader needs them after the entries. */
        if (sequential)
                for (uint64_t q = position, o, p; q < a->prefetch_end; q = reading_position(o, direction) + 1) {
                        if (!prefetch_find(a, q, direction, among, &o) ||
                            reading_position(o, direction) >= a->prefetch_end ||
                            segmented_entry_offset(f, o, &p) < 0)
                                break;

                        prefetch_entry_data(f, p);

                        if (reading_position(o, direction) == UINT64_MAX)
                                break;
                }

        n = sequential ? MIN(a->prefetch_n * 2, PREFETCH_ENTRIES_MAX) : PREFETCH_ENTRIES_MIN;
        next = sequential ? a->prefetch_end : position;

        a->prefetch_direction = direction;
        a->prefetch_begin = position;
        a->prefetch_n = n;
        a->prefetch_next = UINT64_MAX;

        /* The offsets of the entries are in the entry arrays of the indexes. Prefetch the part that the
         * loop below reads, too. */
        uint64_t first, last, q = next;
        if (!prefetch_find(a, q, direction, among, &first)) {
                a->prefetch_end = a->prefetch_next = next;
                return;
        }
        last = first;
        for (uint64_t j = 1; j < n; j++) {
                q = reading_position(last, direction) + 1;
                if (q == 0 || !prefetch_find(a, q, direction, among, &last))
                        break;
        }
        prefetch_entry_offsets(f, MIN(first, last), MAX(first, last));

        for (; k < n; k++) {
                uint64_t o, p;

                if (!prefetch_find(a, next, direction, among, &o))
                        break;

                if (segmented_entry_offset(f, o, &p) < 0)
                        break;

                if (end > start && p < end + PREFETCH_GAP_MAX && p + page_size() + PREFETCH_GAP_MAX > start) {
                        start = MIN(start, p);
                        end = MAX(end, p + page_size());
                } else {
                        if (end > start)
                                segmented_prefetch(f, start, end - start);
                        start = p;
                        end = p + page_size();
                }

                if (k == n / 2)
                        a->prefetch_next = reading_position(o, direction);

                next = reading_position(o, direction) + 1;
                if (next == 0)
                        break;
        }

        if (end > start)
                segmented_prefetch(f, start, end - start);

        a->prefetch_end = next;
        a->prefetch_next = MIN(a->prefetch_next, next);
        a->prefetch_dense = k > 0 && next - a->prefetch_begin <= k * PREFETCH_DENSE_GAP;
}

void segmented_prefetch_current_data(JournalFile *f) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);

        /* The caller reads the fields of the current entry next. segmented_prefetch_entries() prefetches the
         * data objects of only some of the entries it prefetches. Without readahead, each data object that
         * it missed is a read of its own. */

        if (!a->readahead)
                prefetch_entry_data(f, a->current_offset);
}

int segmented_entry_load(
                JournalFile *f,
                uint64_t ordinal,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        int r;

        /* If the entry cannot be read, the next readable one in 'direction' is loaded instead. Returns 0 if
         * there is none. */

        segmented_prefetch_entries(f, ordinal, direction, /* among= */ NULL);

        for (;;) {
                if (ordinal >= n_entries_known(a))
                        return 0;

                r = segmented_entry_at(f, ordinal, ret_object, ret_offset);
                if (r > 0) {
                        segmented_prefetch_current_data(f);
                        return 1;
                }
                if (r < 0)
                        return r;

                log_debug("Entry %" PRIu64 " of %s is bad, skipping over it.", ordinal, f->path);

                if (direction == DIRECTION_DOWN)
                        ordinal++;
                else {
                        if (ordinal == 0)
                                return 0;
                        ordinal--;
                }
        }
}

int segmented_next_entry(JournalFile *f, uint64_t p, direction_t direction, Object **ret_object, uint64_t *ret_offset) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint64_t ordinal, q;
        int r;

        if (p == 0) {
                if (n_entries_known(a) == 0)
                        return 0;

                ordinal = direction == DIRECTION_DOWN ? 0 : n_entries_known(a) - 1;
        } else {
                r = segmented_entry_ordinal(f, p, direction, &ordinal);
                if (r <= 0)
                        return r;

                r = segmented_entry_offset(f, ordinal, &q);
                if (r < 0)
                        return r;

                if (q == p) {
                        if (direction == DIRECTION_DOWN)
                                ordinal++;
                        else {
                                if (ordinal == 0)
                                        return 0;
                                ordinal--;
                        }
                }
        }

        return segmented_entry_load(f, ordinal, direction, ret_object, ret_offset);
}

static int entry_key(JournalFile *f, uint64_t ordinal, SegmentedKey key, uint64_t *ret) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint64_t p;
        Object *o;
        int r;

        assert(ret);

        if (ordinal == a->current_ordinal && a->current_offset != 0)
                p = a->current_offset;
        else {
                r = segmented_entry_offset(f, ordinal, &p);
                if (r < 0)
                        return r;
        }

        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, &o);
        if (ERRNO_IS_NEG_JOURNAL_CORRUPTION(r))
                return 0;
        if (r < 0)
                return r;

        switch (key) {

        case SEGMENTED_KEY_SEQNUM:
                *ret = le64toh(o->entry.seqnum);
                break;

        case SEGMENTED_KEY_REALTIME:
                *ret = le64toh(o->entry.realtime);
                break;

        case SEGMENTED_KEY_MONOTONIC:
                *ret = le64toh(o->entry.monotonic);
                break;

        default:
                assert_not_reached();
        }

        return 1;
}

static int entry_key_nearest(
                JournalFile *f,
                uint64_t ordinal,
                uint64_t limit,
                SegmentedKey key,
                const PostingBitmap *among,
                uint64_t *ret_ordinal,
                uint64_t *ret) {

        int r;

        assert(ret_ordinal);

        for (;;) {
                if (among) {
                        if (!posting_bitmap_find_first(among, ordinal, limit, &ordinal))
                                return 0;
                } else if (ordinal >= limit)
                        return 0;

                r = entry_key(f, ordinal, key, ret);
                if (r > 0) {
                        *ret_ordinal = ordinal;
                        return 1;
                }
                if (r < 0)
                        return r;

                ordinal++;
        }
}

static bool key_satisfies(uint64_t k, uint64_t needle, direction_t direction) {
        return direction == DIRECTION_DOWN ? k >= needle : k > needle;
}

static const SegmentedIndex* bisect_indexes(
                Segmented *a,
                uint64_t needle,
                direction_t direction,
                uint64_t *left,
                uint64_t *right) {

        size_t l = 0, r = a->n_indexes;

        assert(left);
        assert(right);

        /* Each index records the key of the last entry of its segment. The first segment whose last entry
         * satisfies the needle contains the result. The bisection hence only reads entries of that segment.
         * If no segment satisfies the needle, the result is in the tail. */

        while (l < r) {
                size_t m = l + (r - l) / 2;
                uint64_t k = a->indexes[m].tail_seqnum;

                if (key_satisfies(k, needle, direction))
                        r = m;
                else
                        l = m + 1;
        }

        if (l == a->n_indexes) {
                *left = a->n_indexed_entries;
                return NULL;
        }

        *left = a->indexes[l].first_ordinal;
        *right = a->indexes[l].first_ordinal + a->indexes[l].n_index_entries;
        return a->indexes + l;
}

/* If the entries that remain in a bisection lie within this many bytes, they are prefetched at once */
#define BISECT_PREFETCH_MAX (2U * PREFETCH_WINDOW)

static void bisect_prefetch(JournalFile *f, uint64_t left, uint64_t right, bool *done) {
        uint64_t p, q;

        assert(done);

        if (*done || left >= right)
                return;

        if (segmented_entry_offset(f, left, &p) < 0 || segmented_entry_offset(f, right - 1, &q) < 0 || q < p)
                return;

        if (q - p > BISECT_PREFETCH_MAX)
                return;

        /* The size of the last entry is not known before it is read. Its first bytes are in the windows. */
        segmented_prefetch(f, p, q - p + 1);
        *done = true;
}

int segmented_bisect(
                JournalFile *f,
                SegmentedKey key,
                uint64_t needle,
                const PostingBitmap *among,
                direction_t direction,
                uint64_t *ret) {

        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint64_t left = 0, right, n, first;
        bool found = false, prefetched = false;
        int r;

        assert(ret);

        /* Sequence numbers ascend even in files that combine entries from multiple sources. Realtime
         * timestamps can go backwards in files written without strict ordering. */
        if (key == SEGMENTED_KEY_SEQNUM && f->header->n_entries != 0) {
                uint64_t head = le64toh(f->header->head_entry_seqnum),
                         tail = le64toh(f->header->tail_entry_seqnum);

                if (direction == DIRECTION_DOWN ? tail < needle : head > needle)
                        return 0;
        }

        n = right = among ? MIN(n_entries_known(a), among->n_bits) : n_entries_known(a);

        if (!among && key == SEGMENTED_KEY_SEQNUM) {
                const SegmentedIndex *i;

                i = bisect_indexes(a, needle, direction, &left, &right);
                if (i)
                        segmented_prefetch(f, i->offset + i->entry_array_offset, (uint64_t) i->n_index_entries * sizeof(le32_t));
        }

        first = right;

        while (left < right) {
                uint64_t m = left + (right - left) / 2, o, k;

                bisect_prefetch(f, left, right, &prefetched);

                r = entry_key_nearest(f, m, right, key, among, &o, &k);
                if (r < 0)
                        return r;
                if (r == 0) {
                        right = m;
                        continue;
                }

                if (key_satisfies(k, needle, direction)) {
                        first = o;
                        found = true;
                        right = m;
                } else
                        left = o + 1;
        }

        if (direction == DIRECTION_DOWN) {
                /* If the indexes limited the bisection to one segment and no entry of the segment satisfies
                 * the needle, the first entry after the segment is the result */
                if (!found && first >= n)
                        return 0;

                *ret = first;
                return 1;
        }

        if (among)
                return posting_bitmap_find_last(among, 0, first, ret);

        if (first == 0)
                return 0;

        *ret = first - 1;
        return 1;
}

static int move_to_entry_by_key(
                JournalFile *f,
                SegmentedKey key,
                uint64_t needle,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        uint64_t ordinal;
        int r;

        r = segmented_bisect(f, key, needle, /* among= */ NULL, direction, &ordinal);
        if (r <= 0)
                return r;

        return segmented_entry_load(f, ordinal, direction, ret_object, ret_offset);
}

int segmented_move_to_entry_by_seqnum(JournalFile *f, uint64_t seqnum, direction_t direction, Object **ret_object, uint64_t *ret_offset) {
        return move_to_entry_by_key(f, SEGMENTED_KEY_SEQNUM, seqnum, direction, ret_object, ret_offset);
}

int segmented_move_to_entry_by_realtime(JournalFile *f, uint64_t realtime, direction_t direction, Object **ret_object, uint64_t *ret_offset) {
        return move_to_entry_by_key(f, SEGMENTED_KEY_REALTIME, realtime, direction, ret_object, ret_offset);
}

static int fields_load(JournalFile *f, Object *o, uint64_t offset) {
        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        uint64_t n;
        int r;

        assert(o);

        if (o->object.type != OBJECT_ENTRY)
                return -EBADMSG;

        if (a->fields_offset == offset && offset != 0)
                return 0;

        a->fields_offset = 0;
        a->n_fields = 0;

        n = le16toh(o->object.aux);
        if (!GREEDY_REALLOC(a->fields, n))
                return -ENOMEM;

        /* Items ascend, hence the distances to data objects descend. Go backwards, so that the data objects
         * come in file order. */
        for (uint64_t i = n; i > 0; i--) {
                uint64_t item = le32toh(o->entry.items.compact[i - 1].object_offset),
                         p = item & ~(uint64_t) _ENTRY_ITEM_TYPE_MASK;

                switch (item & _ENTRY_ITEM_TYPE_MASK) {

                case ENTRY_ITEM_DATA:
                        a->fields[a->n_fields++] = (SegmentedField) {
                                .type = SEGMENTED_FIELD_DATA,
                                .offset = offset - p,
                        };
                        break;

                case ENTRY_ITEM_INLINE:
                        a->fields[a->n_fields++] = (SegmentedField) {
                                .type = SEGMENTED_FIELD_INLINE,
                                .offset = offset + p,
                        };
                        break;

                case ENTRY_ITEM_CONTEXT: {
                        Object *c;
                        uint64_t m;

                        r = journal_file_move_to_object(f, OBJECT_CONTEXT, offset - p, &c);
                        if (ERRNO_IS_NEG_JOURNAL_CORRUPTION(r)) {
                                log_debug_errno(r, "Context %" PRIu64 " of entry %" PRIu64 " is bad, skipping over it: %m", offset - p, offset);
                                continue;
                        }
                        if (r < 0)
                                return r;

                        /* The array has room for one field per item. A context adds more fields, hence make
                         * room for its items and for the remaining items of the entry. */
                        m = le16toh(c->object.aux);
                        if (!GREEDY_REALLOC(a->fields, a->n_fields + m + (i - 1)))
                                return -ENOMEM;

                        for (uint64_t k = m; k > 0; k--)
                                a->fields[a->n_fields++] = (SegmentedField) {
                                        .type = SEGMENTED_FIELD_DATA,
                                        .offset = offset - p - le32toh(c->context.items[k - 1]),
                                };
                        break;
                }

                default:
                        return -EBADMSG;
                }
        }

        a->fields_offset = offset;
        return 0;
}

int segmented_entry_fields(JournalFile *f, Object *o, uint64_t offset, const SegmentedField **ret, size_t *ret_n) {
        int r;

        assert(f);

        r = fields_load(f, o, offset);
        if (r < 0)
                return r;

        if (ret)
                *ret = f->segmented->fields;
        if (ret_n)
                *ret_n = f->segmented->n_fields;

        return 0;
}

int segmented_inline_payload(
                JournalFile *f,
                uint64_t offset,
                const char *field,
                size_t field_length,
                const void **ret_data,
                size_t *ret_size) {

        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        InlineData *d;
        uint64_t size;
        int r;

        r = journal_file_move_to(f, OBJECT_ENTRY, /* keep_always= */ false, offset, sizeof(InlineData), (void**) &d);
        if (r < 0)
                return r;

        size = le32toh(READ_NOW(d->size));
        if (size == 0)
                return -EBADMSG;

        r = journal_file_move_to(f, OBJECT_ENTRY, /* keep_always= */ false, offset, sizeof(InlineData) + size, (void**) &d);
        if (r < 0)
                return r;

        if (field && (size < field_length + 1 ||
                      memcmp(d->payload, field, field_length) != 0 ||
                      d->payload[field_length] != '=')) {
                if (ret_data)
                        *ret_data = NULL;
                if (ret_size)
                        *ret_size = 0;
                return 0;
        }

        if (ret_data) {
                /* Callers expect the data to live longer than the mmap window of the entry does, hence
                 * return a copy. Decompressed payloads are followed by a NUL byte, and callers treat
                 * payloads as strings, hence add one here too. */
                if (!GREEDY_REALLOC(a->inline_buffer, size + 1))
                        return -ENOMEM;

                memcpy(a->inline_buffer, d->payload, size);
                a->inline_buffer[size] = 0;
                *ret_data = a->inline_buffer;
        }
        if (ret_size)
                *ret_size = size;

        return 1;
}

int segmented_entry_field_payload(
                JournalFile *f,
                Object *o,
                uint64_t offset,
                uint64_t i,
                const char *field,
                size_t field_length,
                sd_journal_data_flags_t flags,
                int fd,
                const void **ret_data,
                size_t *ret_size) {

        Segmented *a = ASSERT_PTR(ASSERT_PTR(f)->segmented);
        const void *d;
        size_t l;
        int r;

        assert(fd < 0 || !ret_data);

        r = fields_load(f, o, offset);
        if (r < 0)
                return r;

        if (i >= a->n_fields)
                return -EADDRNOTAVAIL;

        if (a->fields[i].type != SEGMENTED_FIELD_INLINE)
                return journal_file_data_payload_full(
                                f,
                                /* o= */ NULL,
                                a->fields[i].offset,
                                field, field_length,
                                flags, fd,
                                ret_data, ret_size);

        if (fd < 0 && !FLAGS_SET(flags, SD_JOURNAL_DATA_SKIP_FIELD))
                return segmented_inline_payload(f, a->fields[i].offset, field, field_length, ret_data, ret_size);

        r = segmented_inline_payload(f, a->fields[i].offset, field, field_length, &d, &l);
        if (r <= 0) {
                if (ret_data)
                        *ret_data = NULL;
                if (ret_size)
                        *ret_size = 0;
                return r;
        }

        size_t skip = FLAGS_SET(flags, SD_JOURNAL_DATA_SKIP_FIELD) && field_length > 0 ? field_length + 1 : 0;
        d = (const uint8_t*) d + skip;
        l -= skip;

        if (fd >= 0) {
                r = loop_write(fd, d, l);
                if (r < 0)
                        return r;
        }

        if (ret_data)
                *ret_data = d;
        if (ret_size)
                *ret_size = l;

        return 1;
}
