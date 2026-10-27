/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/mman.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "compress.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "journal-authenticate-internal.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-verify.h"
#include "log.h"
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

        fd = open_tmpfile_unlinkable(tmp_dir, O_RDWR | O_CLOEXEC);
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

static int offset_array_contains(const OffsetArray *a, uint64_t p) {
        int r;

        assert(a);

        /* Bisection ... */

        uint64_t lo = 0, hi = a->n;

        if (!a->fp) {
                while (lo < hi) {
                        uint64_t c = lo + (hi - lo) / 2;

                        if (a->items[c] == p)
                                return true;
                        if (a->items[c] < p)
                                lo = c + 1;
                        else
                                hi = c;
                }

                return false;
        }

        while (lo < hi) {
                uint64_t c = lo + (hi - lo) / 2, *z;

                r = mmap_cache_fd_get(a->cache_fd, 0, false, c * sizeof(uint64_t), sizeof(uint64_t), NULL, (void **) &z, /* ret_size= */ NULL);
                if (r < 0)
                        return r;

                if (*z == p)
                        return true;
                if (*z < p)
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

                r = journal_file_move_to_entry_by_offset_for_data(f, u, p, DIRECTION_DOWN, NULL, NULL);
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
