/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/mman.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "compress.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hash-funcs.h"
#include "journal-authenticate-internal.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-segmented-internal.h"
#include "journal-verify.h"
#include "log.h"
#include "memory-util.h"
#include "set.h"
#include "siphash24.h"
#include "terminal-util.h"
#include "time-util.h"
#include "tmpfile-util.h"

static void draw_progress(uint64_t p, usec_t *last_usec) {
        unsigned n, i, j, k;
        usec_t z, x;

        assert(last_usec);

        if (!on_tty())
                return;

        z = now(CLOCK_MONOTONIC);
        x = *last_usec;

        if (x != 0 && x + 40 * USEC_PER_MSEC > z)
                return;

        *last_usec = z;

        n = (3 * columns()) / 4;
        j = (n * (unsigned) p) / 65535ULL;
        k = n - j;

        fputs("\r", stdout);
        if (colors_enabled())
                fputs("\x1B[?25l", stdout);

        fputs(ansi_highlight_green(), stdout);

        for (i = 0; i < j; i++)
                fputs("\xe2\x96\x88", stdout);

        fputs(ansi_normal(), stdout);

        for (i = 0; i < k; i++)
                fputs("\xe2\x96\x91", stdout);

        printf(" %3"PRIu64"%%", 100U * p / 65535U);

        fputs("\r", stdout);
        if (colors_enabled())
                fputs("\x1B[?25h", stdout);

        fflush(stdout);
}

static uint64_t scale_progress(uint64_t scale, uint64_t p, uint64_t m) {
        /* Calculates scale * p / m, but handles m == 0 safely, and saturates.
         * Currently all callers use m >= 1, but we keep the check to be defensive.
         */

        if (p >= m || m == 0)
                return scale;

        return scale * p / m;
}

static void flush_progress(void) {
        unsigned n, i;

        if (!on_tty())
                return;

        n = (3 * columns()) / 4;

        putchar('\r');

        for (i = 0; i < n + 5; i++)
                putchar(' ');

        putchar('\r');
        fflush(stdout);
}

#define debug(_offset, _fmt, ...) do {                                  \
                flush_progress();                                       \
                log_debug(OFSfmt": " _fmt, _offset, ##__VA_ARGS__);     \
        } while (0)

#define warning(_offset, _fmt, ...) do {                                \
                flush_progress();                                       \
                log_warning(OFSfmt": " _fmt, _offset, ##__VA_ARGS__);   \
        } while (0)

#define error(_offset, _fmt, ...) do {                                  \
                flush_progress();                                       \
                log_error(OFSfmt": " _fmt, (uint64_t)_offset, ##__VA_ARGS__); \
        } while (0)

#define error_errno(_offset, error, _fmt, ...) do {               \
                flush_progress();                                       \
                log_error_errno(error, OFSfmt": " _fmt, (uint64_t)_offset, ##__VA_ARGS__); \
        } while (0)

static int hash_payload(JournalFile *f, Object *o, uint64_t offset, const uint8_t *src, uint64_t size, uint64_t *res_hash) {
        Compression c;
        int r;

        assert(o);
        assert(src);
        assert(res_hash);

        c = COMPRESSION_FROM_OBJECT(o);
        if (c < 0)
                return -EBADMSG;
        if (c != COMPRESSION_NONE) {
                _cleanup_free_ void *b = NULL;
                size_t b_size;

                r = decompress_blob_journal(c, src, size, &b, &b_size, DATA_SIZE_MAX);
                if (r < 0) {
                        error_errno(offset, r, "%s decompression failed: %m",
                                    compression_to_string(c));
                        return r;
                }

                *res_hash = journal_file_hash_data(f, b, b_size);
        } else
                *res_hash = journal_file_hash_data(f, src, size);

        return 0;
}

static int verify_compression(JournalFile *f, Object *o, uint64_t p) {
        Compression c;

        assert(f);
        assert(o);

        c = COMPRESSION_FROM_OBJECT(o);
        if (c < 0) {
                error(p, "Object has multiple compression flags set (flags: 0x%x)", o->object.flags);
                return -EBADMSG;
        }

        if (c != COMPRESSION_NONE && !(le32toh(f->header->incompatible_flags) & COMPRESSION_TO_HEADER_INCOMPATIBLE_FLAG(c))) {
                error(p, "%s compressed object in file without %s compression", compression_to_string(c), compression_to_string(c));
                return -EBADMSG;
        }

        return 0;
}

static int journal_file_object_verify(JournalFile *f, uint64_t offset, Object *o) {
        assert(f);
        assert(offset);
        assert(o);

        /* This does various superficial tests about the length an
         * possible field values. It does not follow any references to
         * other objects. */

        if ((o->object.flags & _OBJECT_COMPRESSED_MASK) != 0 &&
            o->object.type != OBJECT_DATA) {
                error(offset,
                      "Found compressed object of type %s that isn't of type data, which is not allowed.",
                      journal_object_type_to_string(o->object.type));
                return -EBADMSG;
        }

        switch (o->object.type) {

        case OBJECT_DATA: {
                uint64_t h1, h2;
                int r;

                if (le64toh(o->data.entry_offset) == 0)
                        debug(offset, "Unused data (entry_offset==0)");

                if ((le64toh(o->data.entry_offset) == 0) ^ (le64toh(o->data.n_entries) == 0)) {
                        error(offset, "Bad n_entries: %"PRIu64, le64toh(o->data.n_entries));
                        return -EBADMSG;
                }

                if (le64toh(o->object.size) - journal_file_data_payload_offset(f) <= 0) {
                        error(offset, "Bad object size (<= %zu): %"PRIu64,
                              journal_file_data_payload_offset(f),
                              le64toh(o->object.size));
                        return -EBADMSG;
                }

                h1 = le64toh(o->data.hash);
                r = hash_payload(f, o, offset, journal_file_data_payload_field(f, o),
                                 le64toh(o->object.size) - journal_file_data_payload_offset(f),
                                 &h2);
                if (r < 0)
                        return r;

                if (h1 != h2) {
                        error(offset, "Invalid hash (%08" PRIx64 " vs. %08" PRIx64 ")", h1, h2);
                        return -EBADMSG;
                }

                if (!VALID64(le64toh(o->data.next_hash_offset)) ||
                    !VALID64(le64toh(o->data.next_field_offset)) ||
                    !VALID64(le64toh(o->data.entry_offset)) ||
                    !VALID64(le64toh(o->data.entry_array_offset))) {
                        error(offset, "Invalid offset (next_hash_offset="OFSfmt", next_field_offset="OFSfmt", entry_offset="OFSfmt", entry_array_offset="OFSfmt,
                              le64toh(o->data.next_hash_offset),
                              le64toh(o->data.next_field_offset),
                              le64toh(o->data.entry_offset),
                              le64toh(o->data.entry_array_offset));
                        return -EBADMSG;
                }

                break;
        }

        case OBJECT_FIELD: {
                uint64_t h1, h2;
                int r;

                if (le64toh(o->object.size) - offsetof(Object, field.payload) <= 0) {
                        error(offset,
                              "Bad field size (<= %zu): %"PRIu64,
                              offsetof(Object, field.payload),
                              le64toh(o->object.size));
                        return -EBADMSG;
                }

                h1 = le64toh(o->field.hash);
                r = hash_payload(f, o, offset, o->field.payload,
                                 le64toh(o->object.size) - offsetof(Object, field.payload),
                                 &h2);
                if (r < 0)
                        return r;

                if (h1 != h2) {
                        error(offset, "Invalid hash (%08" PRIx64 " vs. %08" PRIx64 ")", h1, h2);
                        return -EBADMSG;
                }

                if (!VALID64(le64toh(o->field.next_hash_offset)) ||
                    !VALID64(le64toh(o->field.head_data_offset))) {
                        error(offset,
                              "Invalid offset (next_hash_offset="OFSfmt", head_data_offset="OFSfmt,
                              le64toh(o->field.next_hash_offset),
                              le64toh(o->field.head_data_offset));
                        return -EBADMSG;
                }
                break;
        }

        case OBJECT_ENTRY:
                if ((le64toh(o->object.size) - offsetof(Object, entry.items)) % journal_file_entry_item_size(f) != 0) {
                        error(offset,
                              "Bad entry size (<= %zu): %"PRIu64,
                              offsetof(Object, entry.items),
                              le64toh(o->object.size));
                        return -EBADMSG;
                }

                if ((le64toh(o->object.size) - offsetof(Object, entry.items)) / journal_file_entry_item_size(f) <= 0) {
                        error(offset,
                              "Invalid number items in entry: %"PRIu64,
                              (le64toh(o->object.size) - offsetof(Object, entry.items)) / journal_file_entry_item_size(f));
                        return -EBADMSG;
                }

                if (le64toh(o->entry.seqnum) <= 0) {
                        error(offset,
                              "Invalid entry seqnum: %"PRIx64,
                              le64toh(o->entry.seqnum));
                        return -EBADMSG;
                }

                if (!VALID_REALTIME(le64toh(o->entry.realtime))) {
                        error(offset,
                              "Invalid entry realtime timestamp: %"PRIu64,
                              le64toh(o->entry.realtime));
                        return -EBADMSG;
                }

                if (!VALID_MONOTONIC(le64toh(o->entry.monotonic))) {
                        error(offset,
                              "Invalid entry monotonic timestamp: %"PRIu64,
                              le64toh(o->entry.monotonic));
                        return -EBADMSG;
                }

                for (uint64_t i = 0; i < journal_file_entry_n_items(f, o); i++) {
                        if (journal_file_entry_item_object_offset(f, o, i) == 0 ||
                            !VALID64(journal_file_entry_item_object_offset(f, o, i))) {
                                error(offset,
                                      "Invalid entry item (%"PRIu64"/%"PRIu64") offset: "OFSfmt,
                                      i, journal_file_entry_n_items(f, o),
                                      journal_file_entry_item_object_offset(f, o, i));
                                return -EBADMSG;
                        }
                }

                break;

        case OBJECT_DATA_HASH_TABLE:
        case OBJECT_FIELD_HASH_TABLE:
                if ((le64toh(o->object.size) - offsetof(Object, hash_table.items)) % sizeof(HashItem) != 0 ||
                    (le64toh(o->object.size) - offsetof(Object, hash_table.items)) / sizeof(HashItem) <= 0) {
                        error(offset,
                              "Invalid %s size: %"PRIu64,
                              journal_object_type_to_string(o->object.type),
                              le64toh(o->object.size));
                        return -EBADMSG;
                }

                for (uint64_t i = 0; i < journal_file_hash_table_n_items(o); i++) {
                        if (o->hash_table.items[i].head_hash_offset != 0 &&
                            !VALID64(le64toh(o->hash_table.items[i].head_hash_offset))) {
                                error(offset,
                                      "Invalid %s hash table item (%"PRIu64"/%"PRIu64") head_hash_offset: "OFSfmt,
                                      journal_object_type_to_string(o->object.type),
                                      i, journal_file_hash_table_n_items(o),
                                      le64toh(o->hash_table.items[i].head_hash_offset));
                                return -EBADMSG;
                        }
                        if (o->hash_table.items[i].tail_hash_offset != 0 &&
                            !VALID64(le64toh(o->hash_table.items[i].tail_hash_offset))) {
                                error(offset,
                                      "Invalid %s hash table item (%"PRIu64"/%"PRIu64") tail_hash_offset: "OFSfmt,
                                      journal_object_type_to_string(o->object.type),
                                      i, journal_file_hash_table_n_items(o),
                                      le64toh(o->hash_table.items[i].tail_hash_offset));
                                return -EBADMSG;
                        }

                        if ((o->hash_table.items[i].head_hash_offset != 0) !=
                            (o->hash_table.items[i].tail_hash_offset != 0)) {
                                error(offset,
                                      "Invalid %s hash table item (%"PRIu64"/%"PRIu64"): head_hash_offset="OFSfmt" tail_hash_offset="OFSfmt,
                                      journal_object_type_to_string(o->object.type),
                                      i, journal_file_hash_table_n_items(o),
                                      le64toh(o->hash_table.items[i].head_hash_offset),
                                      le64toh(o->hash_table.items[i].tail_hash_offset));
                                return -EBADMSG;
                        }
                }

                break;

        case OBJECT_ENTRY_ARRAY:
                if ((le64toh(o->object.size) - offsetof(Object, entry_array.items)) % journal_file_entry_array_item_size(f) != 0 ||
                    (le64toh(o->object.size) - offsetof(Object, entry_array.items)) / journal_file_entry_array_item_size(f) <= 0) {
                        error(offset,
                              "Invalid object entry array size: %"PRIu64,
                              le64toh(o->object.size));
                        return -EBADMSG;
                }

                if (!VALID64(le64toh(o->entry_array.next_entry_array_offset))) {
                        error(offset,
                              "Invalid object entry array next_entry_array_offset: "OFSfmt,
                              le64toh(o->entry_array.next_entry_array_offset));
                        return -EBADMSG;
                }

                for (uint64_t i = 0; i < journal_file_entry_array_n_items(f, o); i++) {
                        uint64_t q = journal_file_entry_array_item(f, o, i);
                        if (q != 0 && !VALID64(q)) {
                                error(offset,
                                      "Invalid object entry array item (%"PRIu64"/%"PRIu64"): "OFSfmt,
                                      i, journal_file_entry_array_n_items(f, o), q);
                                return -EBADMSG;
                        }
                }

                break;

        case OBJECT_TAG:
                if (le64toh(o->object.size) != sizeof(TagObject)) {
                        error(offset,
                              "Invalid object tag size: %"PRIu64,
                              le64toh(o->object.size));
                        return -EBADMSG;
                }

                if (!VALID_EPOCH(le64toh(o->tag.epoch))) {
                        error(offset,
                              "Invalid object tag epoch: %"PRIu64,
                              le64toh(o->tag.epoch));
                        return -EBADMSG;
                }

                break;
        }

        return 0;
}

/* The offset lists take 8 bytes per data, entry and entry array object. For journal files up to this size
 * (journald's default maximum file size) they are kept in memory, which takes at most a quarter of the file
 * size, i.e. 32M, if the file consisted only of entry arrays with a single item, the smallest of these
 * objects, and a few percent in practice. For larger files they are written to temporary files in /var/tmp/
 * instead, so that the memory use does not grow with the file size. */
#define OFFSET_ARRAY_IN_MEMORY_MAX_FILE_SIZE (128 * U64_MB)

typedef struct OffsetArray {
        uint64_t *items;
        FILE *fp;
        MMapFileDescriptor *cache_fd;
        uint64_t n;
} OffsetArray;

static void offset_array_done(OffsetArray *a) {
        assert(a);

        a->items = mfree(a->items);
        a->cache_fd = mmap_cache_fd_free(a->cache_fd);
        a->fp = safe_fclose(a->fp);
        a->n = 0;
}

static int offset_array_open_tmpfile(OffsetArray *a, MMapCache *m, const char *tmp_dir) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(a);
        assert(!a->fp);
        assert(m);
        assert(tmp_dir);

        fd = open_tmpfile_unlinkable(tmp_dir, O_RDWR);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create temporary file: %m");

        r = mmap_cache_add_fd(m, fd, PROT_READ|PROT_WRITE, &a->cache_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to cache temporary file: %m");

        r = take_fdopen_unlocked(&fd, "w+", &a->fp);
        if (r < 0)
                return log_error_errno(r, "Failed to open temporary file stream: %m");

        return 0;
}

static int offset_array_append(OffsetArray *a, uint64_t p) {
        assert(a);

        /* Objects are added in the order in which they are found in the file, hence the array is sorted,
         * and looking an offset up is a bisection. */

        if (a->fp) {
                if (fwrite(&p, sizeof(p), 1, a->fp) != 1)
                        return -EIO;
        } else {
                if (!GREEDY_REALLOC(a->items, a->n + 1))
                        return log_oom();

                a->items[a->n] = p;
        }

        a->n++;
        return 0;
}

static int offset_array_flush(OffsetArray *a) {
        assert(a);

        if (a->fp && fflush(a->fp) != 0)
                return log_error_errno(errno, "Failed to flush temporary file stream: %m");

        return 0;
}

static int offset_array_get(const OffsetArray *a, uint64_t n, uint64_t *ret) {
        uint64_t *p;
        int r;

        assert(a);
        assert(n < a->n);
        assert(ret);

        if (!a->fp) {
                *ret = a->items[n];
                return 0;
        }

        /* Segmented verification looks up offsets while the object walk still appends them. */
        if (fflush(a->fp) != 0)
                return log_error_errno(errno, "Failed to flush temporary file stream: %m");

        r = mmap_cache_fd_get(a->cache_fd, 0, /* keep_always= */ false, n * sizeof(uint64_t), sizeof(uint64_t), /* st= */ NULL, (void**) &p, /* ret_size= */ NULL);
        if (r < 0)
                return r;

        *ret = *p;
        return 0;
}

static int offset_array_contains(const OffsetArray *a, uint64_t p) {
        int r;

        assert(a);

        uint64_t lo = 0, hi = a->n;
        while (lo < hi) {
                uint64_t c = lo + (hi - lo) / 2, offset;

                r = offset_array_get(a, c, &offset);
                if (r < 0)
                        return r;

                if (offset == p)
                        return true;
                if (offset < p)
                        lo = c + 1;
                else
                        hi = c;
        }

        return false;
}

static int verify_data(
                JournalFile *f,
                Object *o, uint64_t p,
                const OffsetArray *entries,
                const OffsetArray *entry_arrays) {

        uint64_t i, n, a, last, q;
        int r;

        assert(f);
        assert(o);
        assert(entries);
        assert(entry_arrays);

        n = le64toh(o->data.n_entries);
        a = le64toh(o->data.entry_array_offset);

        /* Entry array means at least two objects */
        if (a && n < 2) {
                error(p, "Entry array present (entry_array_offset="OFSfmt", but n_entries=%"PRIu64")", a, n);
                return -EBADMSG;
        }

        if (n == 0)
                return 0;

        /* We already checked that earlier */
        assert(o->data.entry_offset);

        last = q = le64toh(o->data.entry_offset);
        r = offset_array_contains(entries, q);
        if (r < 0)
                return r;
        if (r == 0) {
                error(p, "Data object references invalid entry at "OFSfmt, q);
                return -EBADMSG;
        }

        /* We don't check here that the entry is also linked from the main entry array, because that's
         * implied by the check above: verify_entry_array() ran before us, and checked that the main entry
         * array is strictly sorted, has exactly as many items as there are entry objects in the file, and
         * that each item is an entry object. Hence it contains every entry object. */

        i = 1;
        while (i < n) {
                uint64_t next, m, j;

                if (a == 0) {
                        error(p, "Array chain too short");
                        return -EBADMSG;
                }

                r = offset_array_contains(entry_arrays, a);
                if (r < 0)
                        return r;
                if (r == 0) {
                        error(p, "Invalid array offset "OFSfmt, a);
                        return -EBADMSG;
                }

                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o);
                if (r < 0)
                        return r;

                next = le64toh(o->entry_array.next_entry_array_offset);
                if (next != 0 && next <= a) {
                        error(p, "Array chain has cycle (jumps back from "OFSfmt" to "OFSfmt")", a, next);
                        return -EBADMSG;
                }

                m = journal_file_entry_array_n_items(f, o);
                for (j = 0; i < n && j < m; i++, j++) {

                        q = journal_file_entry_array_item(f, o, j);
                        if (q <= last) {
                                error(p, "Data object's entry array not sorted (%"PRIu64" <= %"PRIu64")", q, last);
                                return -EBADMSG;
                        }
                        last = q;

                        r = offset_array_contains(entries, q);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                error(p, "Data object references invalid entry at "OFSfmt, q);
                                return -EBADMSG;
                        }

                        /* No need to look the entry up in the main entry array either, see above. */
                }

                a = next;
        }

        return 0;
}

static int verify_data_hash_table(
                JournalFile *f,
                const OffsetArray *data,
                const OffsetArray *entries,
                const OffsetArray *entry_arrays,
                usec_t *last_usec,
                bool show_progress) {

        uint64_t i, n;
        int r;

        assert(f);
        assert(data);
        assert(entries);
        assert(entry_arrays);
        assert(last_usec);

        n = le64toh(f->header->data_hash_table_size) / sizeof(HashItem);
        if (n <= 0)
                return 0;

        r = journal_file_map_data_hash_table(f);
        if (r < 0)
                return log_error_errno(r, "Failed to map data hash table: %m");

        for (i = 0; i < n; i++) {
                uint64_t last = 0, p;

                if (show_progress)
                        draw_progress(0xC000 + scale_progress(0x3FFF, i, n), last_usec);

                p = le64toh(f->data_hash_table[i].head_hash_offset);
                while (p != 0) {
                        Object *o;
                        uint64_t next;

                        r = offset_array_contains(data, p);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                error(p, "Invalid data object at hash entry %"PRIu64" of %"PRIu64, i, n);
                                return -EBADMSG;
                        }

                        r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
                        if (r < 0)
                                return r;

                        next = le64toh(o->data.next_hash_offset);
                        if (next != 0 && next <= p) {
                                error(p, "Hash chain has a cycle in hash entry %"PRIu64" of %"PRIu64, i, n);
                                return -EBADMSG;
                        }

                        if (le64toh(o->data.hash) % n != i) {
                                error(p, "Hash value mismatch in hash entry %"PRIu64" of %"PRIu64, i, n);
                                return -EBADMSG;
                        }

                        r = verify_data(f, o, p, entries, entry_arrays);
                        if (r < 0)
                                return r;

                        last = p;
                        p = next;
                }

                if (last != le64toh(f->data_hash_table[i].tail_hash_offset)) {
                        error(last,
                              "Tail hash pointer mismatch in hash table (%"PRIu64" != %"PRIu64")",
                              last,
                              le64toh(f->data_hash_table[i].tail_hash_offset));
                        return -EBADMSG;
                }
        }

        return 0;
}

static int data_object_in_hash_table(JournalFile *f, uint64_t hash, uint64_t p) {
        uint64_t n, h, q;
        int r;
        assert(f);

        n = le64toh(f->header->data_hash_table_size) / sizeof(HashItem);
        if (n <= 0)
                return 0;

        r = journal_file_map_data_hash_table(f);
        if (r < 0)
                return log_error_errno(r, "Failed to map data hash table: %m");

        h = hash % n;

        q = le64toh(f->data_hash_table[h].head_hash_offset);
        while (q != 0) {
                Object *o;

                if (p == q)
                        return 1;

                r = journal_file_move_to_object(f, OBJECT_DATA, q, &o);
                if (r < 0)
                        return r;

                q = le64toh(o->data.next_hash_offset);
        }

        return 0;
}

static int verify_entry(
                JournalFile *f,
                Object *o, uint64_t p,
                const OffsetArray *data,
                bool last) {

        uint64_t i, n;
        int r;

        assert(f);
        assert(o);
        assert(data);

        n = journal_file_entry_n_items(f, o);
        for (i = 0; i < n; i++) {
                uint64_t q;
                Object *u;

                q = journal_file_entry_item_object_offset(f, o, i);

                r = offset_array_contains(data, q);
                if (r < 0)
                        return r;
                if (r == 0) {
                        error(p, "Invalid data object of entry");
                        return -EBADMSG;
                }

                r = journal_file_move_to_object(f, OBJECT_DATA, q, &u);
                if (r < 0)
                        return r;

                r = data_object_in_hash_table(f, le64toh(u->data.hash), q);
                if (r < 0)
                        return r;
                if (r == 0) {
                        error(p, "Data object missing from hash table");
                        return -EBADMSG;
                }

                /* Pointer might have moved, reposition */
                r = journal_file_move_to_object(f, OBJECT_DATA, q, &u);
                if (r < 0)
                        return r;

                r = journal_file_move_to_entry_by_offset_for_data(f, u, p, DIRECTION_DOWN, /* ret_object= */ NULL, /* ret_offset= */ NULL);
                if (r < 0)
                        return r;

                /* The last entry object has a very high chance of not being referenced as journal files
                 * almost always run out of space during linking of entry items when trying to add a new
                 * entry array so let's not error in that scenario. */
                if (r == 0 && !last) {
                        error(p, "Entry object not referenced by linked data object at "OFSfmt, q);
                        return -EBADMSG;
                }
        }

        return 0;
}

static int verify_entry_array(
                JournalFile *f,
                const OffsetArray *data,
                const OffsetArray *entries,
                const OffsetArray *entry_arrays,
                usec_t *last_usec,
                bool show_progress) {

        uint64_t i = 0, a, n, last = 0;
        int r;

        assert(f);
        assert(data);
        assert(entries);
        assert(entry_arrays);
        assert(last_usec);

        n = le64toh(f->header->n_entries);
        a = le64toh(f->header->entry_array_offset);
        while (i < n) {
                uint64_t next, m, j;
                Object *o;

                if (show_progress)
                        draw_progress(0x8000 + scale_progress(0x3FFF, i, n), last_usec);

                if (a == 0) {
                        error(a, "Array chain too short at %"PRIu64" of %"PRIu64, i, n);
                        return -EBADMSG;
                }

                r = offset_array_contains(entry_arrays, a);
                if (r < 0)
                        return r;
                if (r == 0) {
                        error(a, "Invalid array %"PRIu64" of %"PRIu64, i, n);
                        return -EBADMSG;
                }

                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o);
                if (r < 0)
                        return r;

                next = le64toh(o->entry_array.next_entry_array_offset);
                if (next != 0 && next <= a) {
                        error(a, "Array chain has cycle at %"PRIu64" of %"PRIu64" (jumps back from to "OFSfmt")", i, n, next);
                        return -EBADMSG;
                }

                m = journal_file_entry_array_n_items(f, o);
                for (j = 0; i < n && j < m; i++, j++) {
                        uint64_t p;

                        p = journal_file_entry_array_item(f, o, j);
                        if (p <= last) {
                                error(a, "Entry array not sorted at %"PRIu64" of %"PRIu64, i, n);
                                return -EBADMSG;
                        }
                        last = p;

                        r = offset_array_contains(entries, p);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                error(a, "Invalid array entry at %"PRIu64" of %"PRIu64, i, n);
                                return -EBADMSG;
                        }

                        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, &o);
                        if (r < 0)
                                return r;

                        r = verify_entry(f, o, p, data, /* last= */ i + 1 == n);
                        if (r < 0)
                                return r;

                        /* Pointer might have moved, reposition */
                        r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o);
                        if (r < 0)
                                return r;
                }

                a = next;
        }

        return 0;
}

static int verify_hash_table(
                Object *o, uint64_t p, uint64_t *n_hash_tables, uint64_t header_offset, uint64_t header_size) {

        assert(o);
        assert(n_hash_tables);

        if (*n_hash_tables > 1) {
                error(p,
                      "More than one %s: %" PRIu64,
                      journal_object_type_to_string(o->object.type),
                      *n_hash_tables);
                return -EBADMSG;
        }

        if (header_offset != p + offsetof(Object, hash_table.items)) {
                error(p,
                      "Header offset for %s invalid (%" PRIu64 " != %" PRIu64 ")",
                      journal_object_type_to_string(o->object.type),
                      header_offset,
                      p + offsetof(Object, hash_table.items));
                return -EBADMSG;
        }

        if (header_size != le64toh(o->object.size) - offsetof(Object, hash_table.items)) {
                error(p,
                      "Header size for %s invalid (%" PRIu64 " != %" PRIu64 ")",
                      journal_object_type_to_string(o->object.type),
                      header_size,
                      le64toh(o->object.size) - offsetof(Object, hash_table.items));
                return -EBADMSG;
        }

        (*n_hash_tables)++;

        return 0;
}

typedef struct VerifyTagState {
        uint64_t n_tags;
        uint64_t last_tag_end;
        uint64_t last_epoch;
        usec_t last_tag_realtime, last_tag_realtime_end;
        usec_t min_entry_realtime, max_entry_realtime, last_entry_realtime;
} VerifyTagState;

static int verify_tag_add_entry(VerifyTagState *s, bool sealed, uint64_t p, usec_t realtime) {
        assert(s);

        if (sealed && s->n_tags <= 0) {
                error(p, "First entry before first tag");
                return -EBADMSG;
        }

        if (realtime < s->last_tag_realtime) {
                error(p,
                      "Older entry after newer tag (%"PRIu64" < %"PRIu64")",
                      realtime,
                      s->last_tag_realtime);
                return -EBADMSG;
        }

        s->min_entry_realtime = MIN(s->min_entry_realtime, realtime);
        s->max_entry_realtime = MAX(s->max_entry_realtime, realtime);
        s->last_entry_realtime = realtime;
        return 0;
}

static int verify_tag(JournalFile *f, VerifyTagState *s, uint64_t p, Object **o) {
        uint64_t seqnum, epoch;
        int r;

        assert(f);
        assert(s);
        assert(o);

        if (!JOURNAL_HEADER_SEALED(f->header)) {
                error(p, "Tag object in file without sealing");
                return -EBADMSG;
        }

        seqnum = le64toh((*o)->tag.seqnum);
        epoch = le64toh((*o)->tag.epoch);

        if (seqnum != s->n_tags + 1) {
                error(p,
                      "Tag sequence number out of synchronization (%"PRIu64" != %"PRIu64")",
                      seqnum,
                      s->n_tags + 1);
                return -EBADMSG;
        }

        if (JOURNAL_HEADER_SEALED_CONTINUOUS(f->header)) {
                if (!(s->n_tags == 0 || (s->n_tags == 1 && epoch == s->last_epoch) || epoch == s->last_epoch + 1)) {
                        error(p,
                              "Epoch sequence not continuous (%"PRIu64" vs %"PRIu64")",
                              epoch,
                              s->last_epoch);
                        return -EBADMSG;
                }
        } else if (epoch < s->last_epoch) {
                error(p,
                      "Epoch sequence out of synchronization (%"PRIu64" < %"PRIu64")",
                      epoch,
                      s->last_epoch);
                return -EBADMSG;
        }

        if (journal_auth_supported()) {
                uint8_t tag[TAG_LENGTH];
                usec_t rt, rt_end;

                CLEANUP_ERASE(tag);

                debug(p, "Checking tag %"PRIu64"...", seqnum);

                r = journal_file_auth_epoch_to_realtime_usec(f, epoch, &rt, &rt_end);
                if (r < 0)
                        return r;

                /* rt_end is never 0, so this never triggers before the first entry. */
                if (s->last_entry_realtime >= rt_end) {
                        error(p,
                              "tag/entry realtime timestamp out of synchronization (%"PRIu64" >= %"PRIu64")",
                              s->last_entry_realtime,
                              rt_end);
                        return -EBADMSG;
                }
                if (s->max_entry_realtime >= rt_end) {
                        error(p,
                              "Entry realtime (%"PRIu64", %s) is too late with respect to tag (%"PRIu64", %s)",
                              s->max_entry_realtime, FORMAT_TIMESTAMP(s->max_entry_realtime),
                              rt_end, FORMAT_TIMESTAMP(rt_end));
                        return -EBADMSG;
                }
                if (s->min_entry_realtime < rt) {
                        error(p,
                              "Entry realtime (%"PRIu64", %s) is too early with respect to tag (%"PRIu64", %s)",
                              s->min_entry_realtime, FORMAT_TIMESTAMP(s->min_entry_realtime),
                              rt, FORMAT_TIMESTAMP(rt));
                        return -EBADMSG;
                }
                s->min_entry_realtime = USEC_INFINITY;

                r = journal_file_auth_seek(f, epoch);
                if (r < 0)
                        return r;

                r = journal_file_auth_start(f);
                if (r < 0)
                        return r;

                if (s->n_tags == 0) {
                        r = journal_file_auth_put_header(f);
                        if (r < 0)
                                return r;
                }

                for (uint64_t q = s->last_tag_end; q <= p;) {
                        Object *object;

                        r = journal_file_move_to_object(f, OBJECT_UNUSED, q, &object);
                        if (r < 0)
                                return r;

                        r = journal_file_auth_put_object(f, OBJECT_UNUSED, object, q);
                        if (r < 0)
                                return r;

                        q += ALIGN64(le64toh(object->object.size));
                }

                /* The traversal may have unmapped the tag. */
                r = journal_file_move_to_object(f, OBJECT_TAG, p, o);
                if (r < 0)
                        return r;

                r = journal_file_auth_end(f, tag);
                if (r < 0)
                        return r;

                if (memcmp((*o)->tag.tag, tag, TAG_LENGTH) != 0) {
                        error(p, "Tag failed verification");
                        return -EBADMSG;
                }

                s->last_tag_realtime = rt;
                s->last_tag_realtime_end = rt_end;
        }

        s->last_tag_end = p + ALIGN64(le64toh((*o)->object.size));
        s->last_epoch = epoch;
        s->n_tags++;
        return 0;
}

typedef struct VerifyData {
        uint64_t offset;
        uint64_t hash;
        uint64_t hash2;
        uint64_t field_hash;
} VerifyData;

typedef struct VerifyValue {
        uint64_t hash;
        uint64_t hash2;
        uint64_t data_offset;
        PostingEncoder postings;
} VerifyValue;

static VerifyValue* verify_value_free(VerifyValue *value) {
        if (!value)
                return NULL;

        posting_encoder_done(&value->postings);
        return mfree(value);
}

static void verify_value_hash_func(const VerifyValue *value, struct siphash *state) {
        siphash24_compress_typesafe(value->hash, state);
        siphash24_compress_typesafe(value->hash2, state);
}

static int verify_value_compare_func(const VerifyValue *a, const VerifyValue *b) {
        int r;

        r = CMP(a->hash, b->hash);
        if (r != 0)
                return r;

        return CMP(a->hash2, b->hash2);
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                verify_value_hash_ops,
                VerifyValue,
                verify_value_hash_func,
                verify_value_compare_func,
                verify_value_free);

typedef struct VerifyField {
        uint64_t hash;
        uint32_t flags;
        uint32_t n_values;
        bool seen;              /* in the field table of the index */
        char name[];
} VerifyField;

typedef struct VerifyDataCache {
        VerifyField *field;
        VerifyValue *value;
        uint64_t offset;
} VerifyDataCache;

#define VERIFY_DATA_CACHE_MAX 1024U

typedef struct VerifyState {
        JournalFile *f;
        uint64_t file_size;

        OffsetArray data;
        OffsetArray contexts;
        OffsetArray entries;

        OffsetArray live;
        SegmentedIndex newest;

        Header state;           /* what the log says about the file up to the current position */

        VerifyTagState tag;

        VerifyDataCache *cache;
} VerifyState;

static void verify_state_done(VerifyState *v) {
        offset_array_done(&v->data);
        offset_array_done(&v->contexts);
        offset_array_done(&v->entries);
        offset_array_done(&v->live);
        free(v->cache);
}

/* Items of entries and contexts are distances back from the object that contains them */
static bool item_target(uint64_t referrer, uint64_t distance, uint64_t *ret) {
        assert(ret);

        if (distance == 0 || distance > referrer)
                return false;

        *ret = referrer - distance;
        return true;
}

static int verify_segmented_data(VerifyState *v, Object *o, uint64_t p) {
        JournalFile *f = v->f;
        const void *payload;
        size_t size;
        const char *eq;
        Compression c;
        int r;

        r = verify_compression(f, o, p);
        if (r < 0)
                return r;

        c = COMPRESSION_FROM_OBJECT(o);

        r = journal_file_data_payload(f, o, p, /* field= */ NULL, /* field_length= */ 0, &payload, &size);
        if (r < 0) {
                error_errno(p, r, "%s decompression failed: %m", compression_to_string(c));
                return r;
        }

        if (journal_file_hash_data(f, payload, size) != le64toh(o->segmented_data.hash)) {
                error(p, "Data object has wrong hash");
                return -EBADMSG;
        }

        eq = memchr(payload, '=', size);
        if (!eq || !journal_field_valid(payload, eq - (const char*) payload, /* allow_protected= */ true)) {
                error(p, "Data object has invalid field name");
                return -EBADMSG;
        }

        return offset_array_append(&v->data, p);
}

static int verify_segmented_entry(VerifyState *v, Object *o, uint64_t p) {
        uint64_t n = le16toh(o->object.aux);
        int r;

        r = verify_tag_add_entry(&v->tag, JOURNAL_HEADER_SEALED(v->f->header), p, le64toh(o->entry.realtime));
        if (r < 0)
                return r;

        if (v->entries.n > 0) {
                if (le64toh(o->entry.seqnum) <= le64toh(v->state.tail_entry_seqnum)) {
                        error(p, "Entry seqnum out of sequence");
                        return -EBADMSG;
                }

                if (sd_id128_equal(o->entry.boot_id, v->state.tail_entry_boot_id) &&
                    le64toh(o->entry.monotonic) < le64toh(v->state.tail_entry_monotonic)) {
                        error(p, "Entry monotonic timestamp out of sequence");
                        return -EBADMSG;
                }
        }

        for (uint64_t i = 0; i < n; i++) {
                uint64_t item = le32toh(o->entry.items.compact[i].object_offset),
                         q = item & ~(uint64_t) _ENTRY_ITEM_TYPE_MASK;
                bool good;

                switch (item & _ENTRY_ITEM_TYPE_MASK) {

                case ENTRY_ITEM_DATA:
                case ENTRY_ITEM_CONTEXT:
                        r = item_target(p, q, &q) ? offset_array_contains(
                                        (item & _ENTRY_ITEM_TYPE_MASK) == ENTRY_ITEM_DATA ? &v->data : &v->contexts, q) : 0;
                        if (r < 0)
                                return r;
                        good = r > 0;
                        break;

                case ENTRY_ITEM_INLINE: {
                        const InlineData *d = (const InlineData*) ((const uint8_t*) o + q);
                        const char *eq = memchr(d->payload, '=', le32toh(d->size));

                        good = eq && journal_field_valid((const char*) d->payload, eq - (const char*) d->payload, /* allow_protected= */ true);
                        break;
                }

                default:
                        good = false;
                }

                if (!good) {
                        error(p, "Entry item %" PRIu64 " does not refer to a valid object", i);
                        return -EBADMSG;
                }
        }

        r = offset_array_append(&v->entries, p);
        if (r < 0)
                return r;

        segmented_header_add_entry(&v->state, p, le64toh(o->entry.seqnum), le64toh(o->entry.realtime),
                                     le64toh(o->entry.monotonic), o->entry.boot_id);
        return 0;
}

static bool verify_segmented_index_fits(VerifyState *v, const SegmentedIndex *i) {
        const SegmentedIndex *newest = v->live.n > 0 ? &v->newest : NULL;
        uint64_t header_size = le64toh(v->f->header->header_size);

        if (i->n_entries != v->entries.n)
                return false;

        return segmented_index_follows(i,
                                       newest ? newest->offset : header_size,
                                       newest ? newest->n_entries : 0);
}

static int verify_field_get(
                Hashmap **fields,
                uint64_t hash,
                const void *payload,
                size_t size,
                VerifyField **ret) {

        VerifyField *field;
        const char *eq;
        int r;

        assert(fields);
        assert(ret);

        eq = memchr(payload, '=', size);
        assert(eq);

        size_t name_size = eq - (const char*) payload;
        char name[name_size + 1];

        memcpy(name, payload, name_size);
        name[name_size] = 0;
        field = hashmap_get(*fields, name);
        if (field) {
                *ret = field;
                return 0;
        }

        field = malloc(sizeof(VerifyField) + name_size + 1);
        if (!field)
                return -ENOMEM;

        *field = (VerifyField) {
                .hash = hash,
        };
        memcpy(field->name, name, name_size + 1);

        r = hashmap_ensure_put(fields, &string_hash_ops_value_free, field->name, field);
        if (r < 0) {
                free(field);
                return r;
        }

        *ret = field;
        return 0;
}

static int verify_value_get(Set **values, const VerifyData *d, VerifyField *field, VerifyValue **ret) {
        VerifyValue *value;
        int r;

        assert(values);
        assert(ret);

        value = set_get(*values, &(VerifyValue) { .hash = d->hash, .hash2 = d->hash2 });
        if (value) {
                *ret = value;
                return 0;
        }

        value = new(VerifyValue, 1);
        if (!value)
                return -ENOMEM;

        *value = (VerifyValue) {
                .hash = d->hash,
                .hash2 = d->hash2,
                .data_offset = d->offset,
        };

        r = set_ensure_consume(values, &verify_value_hash_ops, value);
        if (r < 0)
                return r;

        field->n_values++;
        *ret = value;
        return 0;
}

static bool verify_segmented_index_state(const VerifyState *v, const IndexObject *o, uint64_t offset) {
        IndexObject expected = {};

        index_object_set_state(&expected, &v->state, offset);
        return memcmp((const uint8_t*) o + offsetof(IndexObject, n_objects),
                      (const uint8_t*) &expected + offsetof(IndexObject, n_objects),
                      offsetof(IndexObject, n_index_entries) - offsetof(IndexObject, n_objects)) == 0;
}

static int verify_segmented_rebuild(VerifyState *v, const SegmentedIndex *i, uint64_t base) {
        JournalFile *f = v->f;
        _cleanup_set_free_ Set *values = NULL;
        _cleanup_hashmap_free_ Hashmap *fields = NULL;
        int r;

        if (!v->cache) {
                v->cache = new0(VerifyDataCache, VERIFY_DATA_CACHE_MAX);
                if (!v->cache)
                        return -ENOMEM;
        }
        memzero(v->cache, sizeof(VerifyDataCache) * VERIFY_DATA_CACHE_MAX);

        for (uint64_t k = base; k < v->entries.n; k++) {
                const SegmentedField *entry_fields;
                size_t n_entry_fields;
                uint64_t ordinal = k - base, entry_offset;
                Object *o;

                r = offset_array_get(&v->entries, k, &entry_offset);
                if (r < 0)
                        return r;
                if (entry_offset >= i->offset)
                        break;

                r = journal_file_move_to_object(f, OBJECT_ENTRY, entry_offset, &o);
                if (r < 0)
                        return r;

                r = segmented_entry_fields(f, o, entry_offset, &entry_fields, &n_entry_fields);
                if (r < 0)
                        return r;

                for (size_t m = 0; m < n_entry_fields; m++) {
                        VerifyField *field;

                        if (entry_fields[m].type == SEGMENTED_FIELD_INLINE) {
                                const void *payload;
                                const char *eq;
                                size_t size;

                                r = segmented_inline_payload(f, entry_fields[m].offset, /* field= */ NULL, /* field_length= */ 0, &payload, &size);
                                if (r < 0)
                                        return r;

                                eq = memchr(payload, '=', size);
                                assert(eq);

                                r = verify_field_get(&fields, journal_file_hash_data(f, payload, eq - (const char*) payload),
                                                     payload, size, &field);
                                if (r < 0)
                                        return r;

                                field->flags |= INDEX_FIELD_INLINE;
                                continue;
                        }

                        uint64_t offset = entry_fields[m].offset;
                        VerifyDataCache *c = v->cache + (offset / 8) % VERIFY_DATA_CACHE_MAX;

                        if (c->offset != offset) {
                                const void *payload;
                                const char *eq;
                                size_t size;

                                r = journal_file_data_payload(f, NULL, offset, /* field= */ NULL, /* field_length= */ 0, &payload, &size);
                                if (r < 0)
                                        return r;

                                eq = memchr(payload, '=', size);
                                assert(eq);

                                VerifyData d = {
                                        .offset = offset,
                                        .hash = journal_file_hash_data(f, payload, size),
                                        .hash2 = segmented_hash2(f, payload, size),
                                        .field_hash = journal_file_hash_data(f, payload, eq - (const char*) payload),
                                };
                                *c = (VerifyDataCache) { .offset = offset };

                                r = verify_field_get(&fields, d.field_hash, payload, size, &c->field);
                                if (r < 0)
                                        return r;

                                r = verify_value_get(&values, &d, c->field, &c->value);
                                if (r < 0)
                                        return r;
                        }

                        r = posting_encoder_add(&c->value->postings, ordinal);
                        if (r < 0)
                                return r;
                }
        }

        if (i->n_fields != hashmap_size(fields)) {
                error(i->offset, "Index has %" PRIu32 " fields, expected %u", i->n_fields, hashmap_size(fields));
                return -EBADMSG;
        }

        uint32_t next_data = 0;
        uint64_t postings_end = 0;
        const VerifyField *previous_field = NULL;
        for (uint32_t k = 0; k < i->n_fields; k++) {
                IndexFieldItem item;
                const void *name;

                r = segmented_index_field(f, i, k, &item);
                if (r < 0)
                        return r;

                r = segmented_index_field_name(f, i, &item, &name);
                if (r < 0)
                        return r;

                size_t name_size = le32toh(item.name_size);
                char key[name_size + 1];

                memcpy(key, name, name_size);
                key[name_size] = 0;
                VerifyField *field = hashmap_get(fields, key);
                if (!field || field->seen || le64toh(item.hash) != field->hash || le32toh(item.flags) != field->flags) {
                        error(i->offset, "Index field %" PRIu32 " does not match the log", k);
                        return -EBADMSG;
                }
                field->seen = true;

                if (previous_field &&
                    (field->hash < previous_field->hash ||
                     (field->hash == previous_field->hash && strcmp(field->name, previous_field->name) <= 0))) {
                        error(i->offset, "Index field %" PRIu32 " is out of order", k);
                        return -EBADMSG;
                }
                previous_field = field;

                /* The values of each field are contiguous in the data table, in field order. */
                if (le32toh(item.n_data) != field->n_values || le32toh(item.first_data) != next_data) {
                        error(i->offset, "Index field %" PRIu32 " has %" PRIu32 " values at %" PRIu32 ", expected %" PRIu32 " at %" PRIu32,
                              k, le32toh(item.n_data), le32toh(item.first_data), field->n_values, next_data);
                        return -EBADMSG;
                }

                IndexDataItem previous;
                for (uint32_t m = 0; m < le32toh(item.n_data); m++) {
                        IndexDataItem d;

                        r = segmented_index_data(f, i, next_data + m, &d);
                        if (r < 0)
                                return r;

                        if (m > 0 &&
                            (le64toh(previous.hash) > le64toh(d.hash) ||
                             (le64toh(previous.hash) == le64toh(d.hash) && le64toh(previous.hash2) >= le64toh(d.hash2)))) {
                                error(i->offset, "Index value %" PRIu32 " is out of order", next_data + m);
                                return -EBADMSG;
                        }
                        previous = d;

                        if (le32toh(d.postings_offset) < postings_end) {
                                error(i->offset, "Index value %" PRIu32 " has a posting list that overlaps the previous one", next_data + m);
                                return -EBADMSG;
                        }
                        postings_end = le32toh(d.postings_offset) + le32toh(d.postings_size);
                }

                next_data += le32toh(item.n_data);
        }

        if (next_data != i->n_data_items) {
                error(i->offset, "Index has %" PRIu32 " values that belong to no field", i->n_data_items - next_data);
                return -EBADMSG;
        }

        if (i->n_data_items != set_size(values)) {
                error(i->offset, "Index has %" PRIu32 " values, expected %u", i->n_data_items, set_size(values));
                return -EBADMSG;
        }

        VerifyValue *value;
        SET_FOREACH(value, values) {
                _cleanup_free_ void *payload = NULL;
                PostingDecoder found;
                IndexFieldItem field;
                IndexDataItem item;
                const void *p;
                size_t size;

                r = journal_file_data_payload(f, NULL, value->data_offset, /* field= */ NULL, /* field_length= */ 0, &p, &size);
                if (r < 0)
                        return r;

                /* The lookup decompresses other payloads into the same buffer */
                payload = memdup(p, size);
                if (!payload)
                        return -ENOMEM;

                r = segmented_index_find_field(f, i, payload, (const char*) memchr(payload, '=', size) - (const char*) payload, &field);
                if (r < 0)
                        return r;
                if (r > 0)
                        r = segmented_index_find_data(f, i, &field, payload, size, value->hash, &item);
                if (r < 0)
                        return r;
                if (r == 0) {
                        error(i->offset, "Index lacks value that is in the log");
                        return -EBADMSG;
                }

                r = posting_encoder_finish(&value->postings);
                if (r < 0)
                        return r;

                r = segmented_index_postings(f, i, &item, &found);
                if (r < 0) {
                        error_errno(i->offset, r, "Index has invalid posting list: %m");
                        return r;
                }

                /* The encoder writes each integer in its shortest form and merges runs that touch. A posting
                 * list that matches the log hence has the same bytes as the expected one. */
                if (le32toh(item.n_entries) != value->postings.n_postings ||
                    memcmp_nn(found.p, found.size, value->postings.buffer, value->postings.size) != 0) {
                        error(i->offset, "Index has posting list that does not match the log");
                        return -EBADMSG;
                }
        }

        return 0;
}

static int verify_segmented(
                JournalFile *f,
                usec_t *ret_first_contained,
                usec_t *ret_last_validated,
                usec_t *ret_last_contained,
                bool show_progress) {

        _cleanup_(mmap_cache_unrefp) MMapCache *offsets_cache = NULL;
        _cleanup_(verify_state_done) VerifyState v = {
                .f = f,
                .tag.min_entry_realtime = USEC_INFINITY,
        };
        uint64_t p, padding_end;
        usec_t last_usec = 0;
        int r;

        v.file_size = f->last_stat.st_size;
        if (v.file_size > OFFSET_ARRAY_IN_MEMORY_MAX_FILE_SIZE) {
                const char *tmp_dir;
                OffsetArray *a;

                r = var_tmp_dir(&tmp_dir);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine temporary directory: %m");

                offsets_cache = mmap_cache_new();
                if (!offsets_cache)
                        return -ENOMEM;

                FOREACH_ARGUMENT(a, &v.data, &v.contexts, &v.entries, &v.live) {
                        r = offset_array_open_tmpfile(a, offsets_cache, tmp_dir);
                        if (r < 0)
                                return r;
                }
        }
        v.tag.last_tag_end = le64toh(f->header->header_size);
        v.state = (Header) {
                .header_size = f->header->header_size,
                .tail_entry_seqnum = f->segmented->disk_header->tail_entry_seqnum,
        };

        /* Checksums are keyed with the offset relative to the start of the segment: the newest index
         * object, or the end of the header */
        uint64_t segment = le64toh(f->header->header_size);

        for (p = le64toh(f->header->header_size); p < v.file_size; p = padding_end) {
                uint64_t size = 0, checked;
                uint8_t type;
                Object *o;

                if (show_progress)
                        draw_progress(scale_progress(0x7FFF, p, v.file_size), &last_usec);

                /* Objects of a segment refer to each other with 32-bit offsets, and readers stop scanning
                 * beyond them */
                if (p - (v.live.n > 0 ? v.newest.offset : le64toh(f->header->header_size)) > UINT32_MAX) {
                        error(p, "Object more than 4 GiB after the start of its segment");
                        return -EBADMSG;
                }

                if (v.file_size - p >= sizeof(ObjectHeader)) {
                        ObjectHeader *h;

                        r = journal_file_move_to(f, OBJECT_UNUSED, /* keep_always= */ false, p, sizeof(ObjectHeader), (void**) &h);
                        if (r < 0)
                                return r;

                        size = le64toh(h->size);
                }

                if (v.file_size - p < sizeof(ObjectHeader) || size > v.file_size - p) {
                        if (f->segmented->disk_header->state == STATE_ARCHIVED) {
                                error(p, "Object extends beyond the end of the file");
                                return -EBADMSG;
                        }

                        /* A crash or a failed write leaves a partial object at the end of a file that is
                         * not archived. Readers stop scanning there, hence stop here too. */
                        warning(p, "File ends with a partial object");
                        break;
                }

                r = journal_file_move_to_object(f, OBJECT_UNUSED, p, &o);
                if (r < 0) {
                        error_errno(p, r, "Invalid object: %m");
                        return r;
                }

                checked = segmented_checked_size(&o->object);
                if (segmented_checksum(f, p - segment, o, checked) != le32toh(o->object.checksum)) {
                        error(p, "Object has wrong checksum");
                        return -EBADMSG;
                }

                type = o->object.type;

                switch (type) {

                case OBJECT_DATA:
                        r = verify_segmented_data(&v, o, p);
                        break;

                case OBJECT_CONTEXT:
                        for (uint64_t i = 0; i < le16toh(o->object.aux); i++) {
                                uint64_t q;

                                r = item_target(p, le32toh(o->context.items[i]), &q) ? offset_array_contains(&v.data, q) : 0;
                                if (r < 0)
                                        return r;
                                if (r == 0) {
                                        error(p, "Context item %" PRIu64 " does not refer to a data object", i);
                                        return -EBADMSG;
                                }
                        }

                        r = offset_array_append(&v.contexts, p);
                        break;

                case OBJECT_ENTRY:
                        r = verify_segmented_entry(&v, o, p);
                        break;

                case OBJECT_TAG:
                        r = verify_tag(f, &v.tag, p, &o);
                        break;

                case OBJECT_INDEX: {
                        SegmentedIndex i;

                        r = segmented_index_parse(f, &o->index, p, &i);
                        if (r < 0) {
                                error_errno(p, r, "Invalid index: %m");
                                return r;
                        }

                        if (verify_segmented_index_fits(&v, &i)) {
                                r = segmented_index_payload_verify(f, &i);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        /* Readers drop it, and with it the indexes that build on it. */
                                        warning(p, "Index has wrong payload checksum, not in use");
                                else {
                                        r = journal_file_move_to_object(f, OBJECT_INDEX, p, &o);
                                        if (r < 0)
                                                return r;

                                        if (!verify_segmented_index_state(&v, &o->index, p)) {
                                                error(p, "Index does not match the log before it");
                                                return -EBADMSG;
                                        }

                                        r = offset_array_append(&v.live, p);
                                        if (r < 0)
                                                return r;
                                        v.newest = i;
                                }
                        } else
                                warning(p, "Index is not in use");

                        segment = p;
                        break;
                }

                default:
                        error(p, "Object of unknown type %u", o->object.type);
                        return -EBADMSG;
                }
                if (r < 0)
                        return r;

                segmented_header_add_object(&v.state, type, p, p + ALIGN64(size));

                padding_end = p + ALIGN64(size);
                if (padding_end > v.file_size) {
                        if (f->segmented->disk_header->state == STATE_ARCHIVED) {
                                error(p, "Padding extends beyond the end of the file");
                                return -EBADMSG;
                        }

                        /* Readers accept the object, and the next one would start beyond the end */
                        warning(p, "File ends within the padding of the last object");
                        break;
                }

                if (padding_end > p + size) {
                        uint8_t *q;

                        r = journal_file_move_to(f, OBJECT_UNUSED, /* keep_always= */ false, p + size, padding_end - p - size, (void**) &q);
                        if (r < 0)
                                return r;

                        if (!memeqzero(q, padding_end - p - size)) {
                                error(p, "Padding is not zero");
                                return -EBADMSG;
                        }
                }
        }

        if (show_progress)
                flush_progress();

        if (!IN_SET(f->segmented->disk_header->state, STATE_OFFLINE, STATE_ARCHIVED)) {
                error(0, "Header has state %u, expected STATE_OFFLINE or STATE_ARCHIVED", (unsigned) f->segmented->disk_header->state);
                return -EBADMSG;
        }

        /* Readers load the index that the header names without checking its payload. The header must
         * name a live index. v.live is sorted by offset. */
        uint64_t synced = le64toh(f->segmented->disk_header->synced_index_offset);
        r = synced != 0 ? offset_array_contains(&v.live, synced) : 1;
        if (r < 0)
                return r;
        if (r == 0) {
                error(offsetof(Header, synced_index_offset), "Header does not refer to a usable index");
                return -EBADMSG;
        }

        for (uint64_t index_number = 0; index_number < v.live.n; index_number++) {
                SegmentedIndex index, *i = &index;
                uint64_t offset;
                Object *o;

                r = offset_array_get(&v.live, index_number, &offset);
                if (r < 0)
                        return r;

                r = journal_file_move_to_object(f, OBJECT_INDEX, offset, &o);
                if (r < 0)
                        return r;

                r = segmented_index_parse(f, &o->index, offset, i);
                if (r < 0)
                        return r;

                uint64_t base = i->first_ordinal;

                if (show_progress)
                        draw_progress(scale_progress(0x7FFF, i->offset, v.file_size), &last_usec);

                for (uint32_t k = 0; k < i->n_index_entries; k++) {
                        uint64_t q;

                        r = segmented_index_entry_offset(f, i, k, &q);
                        if (r < 0) {
                                error_errno(i->offset, r, "Invalid entry array: %m");
                                return r;
                        }

                        uint64_t expected;
                        if (base + k >= v.entries.n)
                                return -EBADMSG;

                        r = offset_array_get(&v.entries, base + k, &expected);
                        if (r < 0)
                                return r;

                        if (expected != q) {
                                error(i->offset, "Entry array does not match the log");
                                return -EBADMSG;
                        }
                }

                r = verify_segmented_rebuild(&v, i, base);
                if (r < 0)
                        return r;
        }

        if (show_progress)
                flush_progress();

        if (ret_first_contained)
                *ret_first_contained = le64toh(v.state.head_entry_realtime);
        if (ret_last_validated)
                *ret_last_validated = v.tag.last_tag_realtime_end;
        if (ret_last_contained)
                *ret_last_contained = v.tag.last_entry_realtime;

        return 0;
}

int journal_file_verify(
                JournalFile *f,
                const char *key,
                usec_t *ret_first_contained,
                usec_t *ret_last_validated,
                usec_t *ret_last_contained,
                bool show_progress) {

        int r;
        Object *o;
        uint64_t p = 0;
        uint64_t entry_seqnum = 0, entry_monotonic = 0;
        VerifyTagState tag = {
                .min_entry_realtime = USEC_INFINITY,
        };
        sd_id128_t entry_boot_id = {};  /* Unnecessary initialization to appease gcc */
        bool entry_seqnum_set = false, entry_monotonic_set = false, entry_realtime_set = false, found_main_entry_array = false;
        uint64_t n_objects = 0, n_entries = 0, n_data = 0, n_fields = 0, n_data_hash_tables = 0, n_field_hash_tables = 0, n_entry_arrays = 0;
        usec_t last_usec = 0;
        _cleanup_(offset_array_done) OffsetArray data = {}, entries = {}, entry_arrays = {};
        OffsetArray *a;
        unsigned i;
        bool found_last = false;

        assert(f);

        /* Header verification done on open is typically relaxed; verify it strictly here.
         * The header verification requires the latest stat, let's first update the stat. */
        r = journal_file_fstat(f);
        if (r < 0)
                return log_error_errno(r, "Failed to stat journal file: %m");

        f->verifying = true;
        r = journal_file_verify_header(f);
        if (r < 0)
                return log_error_errno(r, "Journal file header is broken: %m");

        if (key) {
                r = journal_file_auth_load_key(f, key);
                if (r < 0)
                        return log_error_errno(r, "Failed to load verification key: %m");
        } else if (JOURNAL_HEADER_SEALED(f->header)) {
                /* For a sealed journal file, request the verification key when journal sealing is supported.
                 * Otherwise, log that seal verification is skipped. */
                if (journal_auth_supported())
                        return -ENOKEY;
                else
                        log_notice("Journal file is sealed, but journal sealing support is disabled. Skipping seal verification.");
        }

        if (le32toh(f->header->compatible_flags) & ~HEADER_COMPATIBLE_SUPPORTED) {
                r = log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Cannot verify file with unknown extensions.");
                goto fail;
        }

        for (i = 0; i < sizeof(f->header->reserved); i++)
                if (f->header->reserved[i] != 0) {
                        error(offsetof(Header, reserved[i]), "Reserved field is non-zero");
                        r = -EBADMSG;
                        goto fail;
                }

        if (f->segmented)
                return verify_segmented(f, ret_first_contained, ret_last_validated, ret_last_contained, show_progress);

        if ((uint64_t) f->last_stat.st_size > OFFSET_ARRAY_IN_MEMORY_MAX_FILE_SIZE) {
                const char *tmp_dir;
                MMapCache *m;

                r = var_tmp_dir(&tmp_dir);
                if (r < 0) {
                        log_error_errno(r, "Failed to determine temporary directory: %m");
                        goto fail;
                }

                m = mmap_cache_fd_cache(f->cache_fd);
                FOREACH_ARGUMENT(a, &data, &entries, &entry_arrays) {
                        r = offset_array_open_tmpfile(a, m, tmp_dir);
                        if (r < 0)
                                goto fail;
                }
        }

        if (JOURNAL_HEADER_SEALED(f->header) && !JOURNAL_HEADER_SEALED_CONTINUOUS(f->header))
                warning(p,
                        "This log file was sealed with an old journald version where the sequence of seals might not be continuous. We cannot guarantee completeness.");

        /* First iteration: we go through all objects, verify the
         * superficial structure, headers, hashes. */

        p = tag.last_tag_end = le64toh(f->header->header_size);
        for (;;) {
                /* Early exit if there are no objects in the file, at all */
                if (le64toh(f->header->tail_object_offset) == 0)
                        break;

                if (show_progress)
                        draw_progress(scale_progress(0x7FFF, p, le64toh(f->header->tail_object_offset)), &last_usec);

                r = journal_file_move_to_object(f, OBJECT_UNUSED, p, &o);
                if (r < 0) {
                        error_errno(p, r, "Invalid object: %m");
                        goto fail;
                }

                if (p > le64toh(f->header->tail_object_offset)) {
                        error(offsetof(Header, tail_object_offset),
                              "Invalid tail object pointer (%"PRIu64" > %"PRIu64")",
                              p,
                              le64toh(f->header->tail_object_offset));
                        r = -EBADMSG;
                        goto fail;
                }

                n_objects++;

                r = journal_file_object_verify(f, p, o);
                if (r < 0) {
                        error_errno(p, r, "Invalid object contents: %m");
                        goto fail;
                }

                r = verify_compression(f, o, p);
                if (r < 0)
                        goto fail;

                switch (o->object.type) {

                case OBJECT_DATA:
                        r = offset_array_append(&data, p);
                        if (r < 0)
                                goto fail;

                        n_data++;
                        break;

                case OBJECT_FIELD:
                        n_fields++;
                        break;

                case OBJECT_ENTRY:
                        r = offset_array_append(&entries, p);
                        if (r < 0)
                                goto fail;

                        r = verify_tag_add_entry(&tag, JOURNAL_HEADER_SEALED(f->header), p, le64toh(o->entry.realtime));
                        if (r < 0)
                                goto fail;

                        if (!entry_seqnum_set &&
                            le64toh(o->entry.seqnum) != le64toh(f->header->head_entry_seqnum)) {
                                error(p,
                                      "Head entry sequence number incorrect (%"PRIu64" != %"PRIu64")",
                                      le64toh(o->entry.seqnum),
                                      le64toh(f->header->head_entry_seqnum));
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (entry_seqnum_set &&
                            entry_seqnum >= le64toh(o->entry.seqnum)) {
                                error(p,
                                      "Entry sequence number out of synchronization (%"PRIu64" >= %"PRIu64")",
                                      entry_seqnum,
                                      le64toh(o->entry.seqnum));
                                r = -EBADMSG;
                                goto fail;
                        }

                        entry_seqnum = le64toh(o->entry.seqnum);
                        entry_seqnum_set = true;

                        if (entry_monotonic_set &&
                            sd_id128_equal(entry_boot_id, o->entry.boot_id) &&
                            entry_monotonic > le64toh(o->entry.monotonic)) {
                                error(p,
                                      "Entry timestamp out of synchronization (%"PRIu64" > %"PRIu64")",
                                      entry_monotonic,
                                      le64toh(o->entry.monotonic));
                                r = -EBADMSG;
                                goto fail;
                        }

                        entry_monotonic = le64toh(o->entry.monotonic);
                        entry_boot_id = o->entry.boot_id;
                        entry_monotonic_set = true;

                        if (!entry_realtime_set &&
                            le64toh(o->entry.realtime) != le64toh(f->header->head_entry_realtime)) {
                                error(p,
                                      "Head entry realtime timestamp incorrect (%"PRIu64" != %"PRIu64")",
                                      le64toh(o->entry.realtime),
                                      le64toh(f->header->head_entry_realtime));
                                r = -EBADMSG;
                                goto fail;
                        }

                        entry_realtime_set = true;

                        n_entries++;
                        break;

                case OBJECT_DATA_HASH_TABLE:
                        r = verify_hash_table(o, p, &n_data_hash_tables,
                                              le64toh(f->header->data_hash_table_offset),
                                              le64toh(f->header->data_hash_table_size));
                        if (r < 0)
                                goto fail;
                        break;

                case OBJECT_FIELD_HASH_TABLE:
                        r = verify_hash_table(o, p, &n_field_hash_tables,
                                              le64toh(f->header->field_hash_table_offset),
                                              le64toh(f->header->field_hash_table_size));
                        if (r < 0)
                                goto fail;

                        break;

                case OBJECT_ENTRY_ARRAY:
                        r = offset_array_append(&entry_arrays, p);
                        if (r < 0)
                                goto fail;

                        if (p == le64toh(f->header->entry_array_offset)) {
                                if (found_main_entry_array) {
                                        error(p, "More than one main entry array");
                                        r = -EBADMSG;
                                        goto fail;
                                }

                                found_main_entry_array = true;
                        }

                        n_entry_arrays++;
                        break;

                case OBJECT_TAG:
                        r = verify_tag(f, &tag, p, &o);
                        if (r < 0)
                                goto fail;

                        break;
                }

                if (p == le64toh(f->header->tail_object_offset)) {
                        found_last = true;
                        break;
                }

                p = p + ALIGN64(le64toh(o->object.size));
        };

        if (!found_last && le64toh(f->header->tail_object_offset) != 0) {
                error(le64toh(f->header->tail_object_offset),
                      "Tail object pointer dead (%"PRIu64" != 0)",
                      le64toh(f->header->tail_object_offset));
                r = -EBADMSG;
                goto fail;
        }

        if (n_objects != le64toh(f->header->n_objects)) {
                error(offsetof(Header, n_objects),
                      "Object number mismatch (%"PRIu64" != %"PRIu64")",
                      n_objects,
                      le64toh(f->header->n_objects));
                r = -EBADMSG;
                goto fail;
        }

        if (n_entries != le64toh(f->header->n_entries)) {
                error(offsetof(Header, n_entries),
                      "Entry number mismatch (%"PRIu64" != %"PRIu64")",
                      n_entries,
                      le64toh(f->header->n_entries));
                r = -EBADMSG;
                goto fail;
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_data) &&
            n_data != le64toh(f->header->n_data)) {
                error(offsetof(Header, n_data),
                      "Data number mismatch (%"PRIu64" != %"PRIu64")",
                      n_data,
                      le64toh(f->header->n_data));
                r = -EBADMSG;
                goto fail;
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_fields) &&
            n_fields != le64toh(f->header->n_fields)) {
                error(offsetof(Header, n_fields),
                      "Field number mismatch (%"PRIu64" != %"PRIu64")",
                      n_fields,
                      le64toh(f->header->n_fields));
                r = -EBADMSG;
                goto fail;
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_tags) &&
            tag.n_tags != le64toh(f->header->n_tags)) {
                error(offsetof(Header, n_tags),
                      "Tag number mismatch (%"PRIu64" != %"PRIu64")",
                      tag.n_tags,
                      le64toh(f->header->n_tags));
                r = -EBADMSG;
                goto fail;
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_entry_arrays) &&
            n_entry_arrays != le64toh(f->header->n_entry_arrays)) {
                error(offsetof(Header, n_entry_arrays),
                      "Entry array number mismatch (%"PRIu64" != %"PRIu64")",
                      n_entry_arrays,
                      le64toh(f->header->n_entry_arrays));
                r = -EBADMSG;
                goto fail;
        }

        if (!found_main_entry_array && le64toh(f->header->entry_array_offset) != 0) {
                error(0, "Missing main entry array");
                r = -EBADMSG;
                goto fail;
        }

        if (entry_seqnum_set &&
            entry_seqnum != le64toh(f->header->tail_entry_seqnum)) {
                error(offsetof(Header, tail_entry_seqnum),
                      "Tail entry sequence number incorrect (%"PRIu64" != %"PRIu64")",
                      entry_seqnum,
                      le64toh(f->header->tail_entry_seqnum));
                r = -EBADMSG;
                goto fail;
        }

        if (entry_monotonic_set &&
            (sd_id128_equal(entry_boot_id, f->header->tail_entry_boot_id) &&
             JOURNAL_HEADER_TAIL_ENTRY_BOOT_ID(f->header) &&
             entry_monotonic != le64toh(f->header->tail_entry_monotonic))) {
                error(0,
                      "Invalid tail monotonic timestamp (%"PRIu64" != %"PRIu64")",
                      entry_monotonic,
                      le64toh(f->header->tail_entry_monotonic));
                r = -EBADMSG;
                goto fail;
        }

        if (entry_realtime_set && tag.last_entry_realtime != le64toh(f->header->tail_entry_realtime)) {
                error(0,
                      "Invalid tail realtime timestamp (%"PRIu64" != %"PRIu64")",
                      tag.last_entry_realtime,
                      le64toh(f->header->tail_entry_realtime));
                r = -EBADMSG;
                goto fail;
        }

        FOREACH_ARGUMENT(a, &data, &entries, &entry_arrays) {
                r = offset_array_flush(a);
                if (r < 0)
                        goto fail;
        }

        /* Second iteration: we follow all objects referenced from the
         * two entry points: the object hash table and the entry
         * array. We also check that everything referenced (directly
         * or indirectly) in the data hash table also exists in the
         * entry array, and vice versa. Note that we do not care for
         * unreferenced objects. We only care that everything that is
         * referenced is consistent. */

        r = verify_entry_array(f,
                               &data,
                               &entries,
                               &entry_arrays,
                               &last_usec,
                               show_progress);
        if (r < 0)
                goto fail;

        r = verify_data_hash_table(f,
                                   &data,
                                   &entries,
                                   &entry_arrays,
                                   &last_usec,
                                   show_progress);
        if (r < 0)
                goto fail;

        if (show_progress)
                flush_progress();

        if (ret_first_contained)
                *ret_first_contained = le64toh(f->header->head_entry_realtime);
        if (ret_last_validated)
                *ret_last_validated = tag.last_tag_realtime_end;
        if (ret_last_contained)
                *ret_last_contained = le64toh(f->header->tail_entry_realtime);

        return 0;

fail:
        if (show_progress)
                flush_progress();

        log_error("File corruption detected at %s:%"PRIu64" (of %"PRIu64" bytes, %"PRIu64"%%).",
                  f->path,
                  p,
                  (uint64_t) f->last_stat.st_size,
                  100U * p / (uint64_t) f->last_stat.st_size);

        return r;
}
