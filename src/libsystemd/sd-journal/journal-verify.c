/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

#include "alloc-util.h"
#include "compress.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "journal-authenticate.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-verify.h"
#include "lookup3.h"
#include "macro.h"
#include "terminal-util.h"
#include "tmpfile-util.h"

static void draw_progress(uint64_t p, usec_t *last_usec) {
        unsigned n, i, j, k;
        usec_t z, x;

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

                r = decompress_blob(c, src, size, &b, &b_size, 0);
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
                        warning(offset, "Unused data (entry_offset==0)");

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

static int write_uint64(FILE *fp, uint64_t p) {
        if (fwrite(&p, sizeof(p), 1, fp) != 1)
                return -EIO;

        return 0;
}

static int contains_uint64(MMapFileDescriptor *f, uint64_t n, uint64_t p) {
        uint64_t a, b;
        int r;

        assert(f);

        /* Bisection ... */

        a = 0; b = n;
        while (a < b) {
                uint64_t c, *z;

                c = (a + b) / 2;

                r = mmap_cache_fd_get(f, 0, false, c * sizeof(uint64_t), sizeof(uint64_t), NULL, (void **) &z);
                if (r < 0)
                        return r;

                if (*z == p)
                        return 1;

                if (a + 1 >= b)
                        return 0;

                if (p < *z)
                        b = c;
                else
                        a = c;
        }

        return 0;
}

static int verify_data(
                JournalFile *f,
                Object *o, uint64_t p,
                MMapFileDescriptor *cache_entry_fd, uint64_t n_entries,
                MMapFileDescriptor *cache_entry_array_fd, uint64_t n_entry_arrays) {

        uint64_t i, n, a, last, q;
        int r;

        assert(f);
        assert(o);
        assert(cache_entry_fd);
        assert(cache_entry_array_fd);

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
        if (!contains_uint64(cache_entry_fd, n_entries, q)) {
                error(p, "Data object references invalid entry at "OFSfmt, q);
                return -EBADMSG;
        }

        r = journal_file_move_to_entry_by_offset(f, q, DIRECTION_DOWN, NULL, NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                error(q, "Entry object doesn't exist in the main entry array");
                return -EBADMSG;
        }

        i = 1;
        while (i < n) {
                uint64_t next, m, j;

                if (a == 0) {
                        error(p, "Array chain too short");
                        return -EBADMSG;
                }

                if (!contains_uint64(cache_entry_array_fd, n_entry_arrays, a)) {
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

                        if (!contains_uint64(cache_entry_fd, n_entries, q)) {
                                error(p, "Data object references invalid entry at "OFSfmt, q);
                                return -EBADMSG;
                        }

                        r = journal_file_move_to_entry_by_offset(f, q, DIRECTION_DOWN, NULL, NULL);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                error(q, "Entry object doesn't exist in the main entry array");
                                return -EBADMSG;
                        }

                        /* Pointer might have moved, reposition */
                        r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o);
                        if (r < 0)
                                return r;
                }

                a = next;
        }

        return 0;
}

static int verify_data_hash_table(
                JournalFile *f,
                MMapFileDescriptor *cache_data_fd, uint64_t n_data,
                MMapFileDescriptor *cache_entry_fd, uint64_t n_entries,
                MMapFileDescriptor *cache_entry_array_fd, uint64_t n_entry_arrays,
                usec_t *last_usec,
                bool show_progress) {

        uint64_t i, n;
        int r;

        assert(f);
        assert(cache_data_fd);
        assert(cache_entry_fd);
        assert(cache_entry_array_fd);
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

                        if (!contains_uint64(cache_data_fd, n_data, p)) {
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

                        r = verify_data(f, o, p, cache_entry_fd, n_entries, cache_entry_array_fd, n_entry_arrays);
                        if (r < 0)
                                return r;

                        last = p;
                        p = next;
                }

                if (last != le64toh(f->data_hash_table[i].tail_hash_offset)) {
                        error(p,
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
                MMapFileDescriptor *cache_data_fd, uint64_t n_data,
                bool last) {

        uint64_t i, n;
        int r;

        assert(f);
        assert(o);
        assert(cache_data_fd);

        n = journal_file_entry_n_items(f, o);
        for (i = 0; i < n; i++) {
                uint64_t q;
                Object *u;

                q = journal_file_entry_item_object_offset(f, o, i);

                if (!contains_uint64(cache_data_fd, n_data, q)) {
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
                MMapFileDescriptor *cache_data_fd, uint64_t n_data,
                MMapFileDescriptor *cache_entry_fd, uint64_t n_entries,
                MMapFileDescriptor *cache_entry_array_fd, uint64_t n_entry_arrays,
                usec_t *last_usec,
                bool show_progress) {

        uint64_t i = 0, a, n, last = 0;
        int r;

        assert(f);
        assert(cache_data_fd);
        assert(cache_entry_fd);
        assert(cache_entry_array_fd);
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

                if (!contains_uint64(cache_entry_array_fd, n_entry_arrays, a)) {
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

                        if (!contains_uint64(cache_entry_fd, n_entries, p)) {
                                error(a, "Invalid array entry at %"PRIu64" of %"PRIu64, i, n);
                                return -EBADMSG;
                        }

                        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, &o);
                        if (r < 0)
                                return r;

                        r = verify_entry(f, o, p, cache_data_fd, n_data, /*last=*/ i + 1 == n);
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

int journal_file_verify(
                JournalFile *f,
                const char *key,
                usec_t *first_contained, usec_t *last_validated, usec_t *last_contained,
                bool show_progress) {
        int r;
        Object *o;
        uint64_t p = 0, last_epoch = 0, last_tag_realtime = 0;

        uint64_t entry_seqnum = 0, entry_monotonic = 0, entry_realtime = 0;
        usec_t min_entry_realtime = USEC_INFINITY, max_entry_realtime = 0;
        sd_id128_t entry_boot_id = {};  /* Unnecessary initialization to appease gcc */
        bool entry_seqnum_set = false, entry_monotonic_set = false, entry_realtime_set = false, found_main_entry_array = false;
        uint64_t n_objects = 0, n_entries = 0, n_data = 0, n_fields = 0, n_data_hash_tables = 0, n_field_hash_tables = 0, n_entry_arrays = 0, n_tags = 0;
        usec_t last_usec = 0;
        _cleanup_close_ int data_fd = -EBADF, entry_fd = -EBADF, entry_array_fd = -EBADF;
        _cleanup_fclose_ FILE *data_fp = NULL, *entry_fp = NULL, *entry_array_fp = NULL;
        MMapFileDescriptor *cache_data_fd = NULL, *cache_entry_fd = NULL, *cache_entry_array_fd = NULL;
        unsigned i;
        bool found_last = false;
        const char *tmp_dir = NULL;
        MMapCache *m;

#if HAVE_GCRYPT
        uint64_t last_tag = 0;
#endif
        assert(f);

        if (key) {
#if HAVE_GCRYPT
                r = journal_file_parse_verification_key(f, key);
                if (r < 0) {
                        log_error("Failed to parse seed.");
                        return r;
                }
#else
                return -EOPNOTSUPP;
#endif
        } else if (JOURNAL_HEADER_SEALED(f->header))
                return -ENOKEY;

        r = var_tmp_dir(&tmp_dir);
        if (r < 0) {
                log_error_errno(r, "Failed to determine temporary directory: %m");
                goto fail;
        }

        data_fd = open_tmpfile_unlinkable(tmp_dir, O_RDWR | O_CLOEXEC);
        if (data_fd < 0) {
                r = log_error_errno(data_fd, "Failed to create data file: %m");
                goto fail;
        }

        entry_fd = open_tmpfile_unlinkable(tmp_dir, O_RDWR | O_CLOEXEC);
        if (entry_fd < 0) {
                r = log_error_errno(entry_fd, "Failed to create entry file: %m");
                goto fail;
        }

        entry_array_fd = open_tmpfile_unlinkable(tmp_dir, O_RDWR | O_CLOEXEC);
        if (entry_array_fd < 0) {
                r = log_error_errno(entry_array_fd,
                                    "Failed to create entry array file: %m");
                goto fail;
        }

        m = mmap_cache_fd_cache(f->cache_fd);
        r = mmap_cache_add_fd(m, data_fd, PROT_READ|PROT_WRITE, &cache_data_fd);
        if (r < 0) {
                log_error_errno(r, "Failed to cache data file: %m");
                goto fail;
        }

        r = mmap_cache_add_fd(m, entry_fd, PROT_READ|PROT_WRITE, &cache_entry_fd);
        if (r < 0) {
                log_error_errno(r, "Failed to cache entry file: %m");
                goto fail;
        }

        r = mmap_cache_add_fd(m, entry_array_fd, PROT_READ|PROT_WRITE, &cache_entry_array_fd);
        if (r < 0) {
                log_error_errno(r, "Failed to cache entry array file: %m");
                goto fail;
        }

        r = take_fdopen_unlocked(&data_fd, "w+", &data_fp);
        if (r < 0) {
                log_error_errno(r, "Failed to open data file stream: %m");
                goto fail;
        }

        r = take_fdopen_unlocked(&entry_fd, "w+", &entry_fp);
        if (r < 0) {
                log_error_errno(r, "Failed to open entry file stream: %m");
                goto fail;
        }

        r = take_fdopen_unlocked(&entry_array_fd, "w+", &entry_array_fp);
        if (r < 0) {
                log_error_errno(r, "Failed to open entry array file stream: %m");
                goto fail;
        }

        if (le32toh(f->header->compatible_flags) & ~HEADER_COMPATIBLE_SUPPORTED) {
                log_error("Cannot verify file with unknown extensions.");
                r = -EOPNOTSUPP;
                goto fail;
        }

        for (i = 0; i < sizeof(f->header->reserved); i++)
                if (f->header->reserved[i] != 0) {
                        error(offsetof(Header, reserved[i]), "Reserved field is non-zero");
                        r = -EBADMSG;
                        goto fail;
                }

        if (JOURNAL_HEADER_SEALED(f->header) && !JOURNAL_HEADER_SEALED_CONTINUOUS(f->header))
                warning(p,
                        "This log file was sealed with an old journald version where the sequence of seals might not be continuous. We cannot guarantee completeness.");

        /* First iteration: we go through all objects, verify the
         * superficial structure, headers, hashes. */

        p = le64toh(f->header->header_size);
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

                if (!!(o->object.flags & OBJECT_COMPRESSED_XZ) +
                    !!(o->object.flags & OBJECT_COMPRESSED_LZ4) +
                    !!(o->object.flags & OBJECT_COMPRESSED_ZSTD) > 1) {
                        error(p, "Object has multiple compression flags set (flags: 0x%x)", o->object.flags);
                        r = -EINVAL;
                        goto fail;
                }

                if ((o->object.flags & OBJECT_COMPRESSED_XZ) && !JOURNAL_HEADER_COMPRESSED_XZ(f->header)) {
                        error(p, "XZ compressed object in file without XZ compression");
                        r = -EBADMSG;
                        goto fail;
                }

                if ((o->object.flags & OBJECT_COMPRESSED_LZ4) && !JOURNAL_HEADER_COMPRESSED_LZ4(f->header)) {
                        error(p, "LZ4 compressed object in file without LZ4 compression");
                        r = -EBADMSG;
                        goto fail;
                }

                if ((o->object.flags & OBJECT_COMPRESSED_ZSTD) && !JOURNAL_HEADER_COMPRESSED_ZSTD(f->header)) {
                        error(p, "ZSTD compressed object in file without ZSTD compression");
                        r = -EBADMSG;
                        goto fail;
                }

                switch (o->object.type) {

                case OBJECT_DATA:
                        r = write_uint64(data_fp, p);
                        if (r < 0)
                                goto fail;

                        n_data++;
                        break;

                case OBJECT_FIELD:
                        n_fields++;
                        break;

                case OBJECT_ENTRY:
                        if (JOURNAL_HEADER_SEALED(f->header) && n_tags <= 0) {
                                error(p, "First entry before first tag");
                                r = -EBADMSG;
                                goto fail;
                        }

                        r = write_uint64(entry_fp, p);
                        if (r < 0)
                                goto fail;

                        if (le64toh(o->entry.realtime) < last_tag_realtime) {
                                error(p,
                                      "Older entry after newer tag (%"PRIu64" < %"PRIu64")",
                                      le64toh(o->entry.realtime),
                                      last_tag_realtime);
                                r = -EBADMSG;
                                goto fail;
                        }

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

                        entry_realtime = le64toh(o->entry.realtime);
                        entry_realtime_set = true;

                        max_entry_realtime = MAX(max_entry_realtime, le64toh(o->entry.realtime));
                        min_entry_realtime = MIN(min_entry_realtime, le64toh(o->entry.realtime));

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
                        r = write_uint64(entry_array_fp, p);
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
                        if (!JOURNAL_HEADER_SEALED(f->header)) {
                                error(p, "Tag object in file without sealing");
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (le64toh(o->tag.seqnum) != n_tags + 1) {
                                error(p,
                                      "Tag sequence number out of synchronization (%"PRIu64" != %"PRIu64")",
                                      le64toh(o->tag.seqnum),
                                      n_tags + 1);
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (JOURNAL_HEADER_SEALED_CONTINUOUS(f->header)) {
                                if (!(n_tags == 0 || (n_tags == 1 && le64toh(o->tag.epoch) == last_epoch)
                                      || le64toh(o->tag.epoch) == last_epoch + 1)) {
                                        error(p,
                                              "Epoch sequence not continuous (%"PRIu64" vs %"PRIu64")",
                                              le64toh(o->tag.epoch),
                                              last_epoch);
                                        r = -EBADMSG;
                                        goto fail;
                                }
                        } else {
                                if (le64toh(o->tag.epoch) < last_epoch) {
                                        error(p,
                                              "Epoch sequence out of synchronization (%"PRIu64" < %"PRIu64")",
                                              le64toh(o->tag.epoch),
                                              last_epoch);
                                        r = -EBADMSG;
                                        goto fail;
                                }
                        }

#if HAVE_GCRYPT
                        if (JOURNAL_HEADER_SEALED(f->header)) {
                                uint64_t q, rt, rt_end;

                                debug(p, "Checking tag %"PRIu64"...", le64toh(o->tag.seqnum));

                                rt = f->fss_start_usec + le64toh(o->tag.epoch) * f->fss_interval_usec;
                                rt_end = usec_add(rt, f->fss_interval_usec);
                                if (entry_realtime_set && entry_realtime >= rt_end) {
                                        error(p,
                                              "tag/entry realtime timestamp out of synchronization (%"PRIu64" >= %"PRIu64")",
                                              entry_realtime,
                                              rt + f->fss_interval_usec);
                                        r = -EBADMSG;
                                        goto fail;
                                }
                                if (max_entry_realtime >= rt_end) {
                                        error(p,
                                              "Entry realtime (%"PRIu64", %s) is too late with respect to tag (%"PRIu64", %s)",
                                              max_entry_realtime, FORMAT_TIMESTAMP(max_entry_realtime),
                                              rt_end, FORMAT_TIMESTAMP(rt_end));
                                        r = -EBADMSG;
                                        goto fail;
                                }
                                if (min_entry_realtime < rt) {
                                        error(p,
                                              "Entry realtime (%"PRIu64", %s) is too early with respect to tag (%"PRIu64", %s)",
                                              min_entry_realtime, FORMAT_TIMESTAMP(min_entry_realtime),
                                              rt, FORMAT_TIMESTAMP(rt));
                                        r = -EBADMSG;
                                        goto fail;
                                }
                                min_entry_realtime = USEC_INFINITY;

                                /* OK, now we know the epoch. So let's now set
                                 * it, and calculate the HMAC for everything
                                 * since the last tag. */
                                r = journal_file_fsprg_seek(f, le64toh(o->tag.epoch));
                                if (r < 0)
                                        goto fail;

                                r = journal_file_hmac_start(f);
                                if (r < 0)
                                        goto fail;

                                if (last_tag == 0) {
                                        r = journal_file_hmac_put_header(f);
                                        if (r < 0)
                                                goto fail;

                                        q = le64toh(f->header->header_size);
                                } else
                                        q = last_tag;

                                while (q <= p) {
                                        r = journal_file_move_to_object(f, OBJECT_UNUSED, q, &o);
                                        if (r < 0)
                                                goto fail;

                                        r = journal_file_hmac_put_object(f, OBJECT_UNUSED, o, q);
                                        if (r < 0)
                                                goto fail;

                                        q = q + ALIGN64(le64toh(o->object.size));
                                }

                                /* Position might have changed, let's reposition things */
                                r = journal_file_move_to_object(f, OBJECT_UNUSED, p, &o);
                                if (r < 0)
                                        goto fail;

                                if (memcmp(o->tag.tag, gcry_md_read(f->hmac, 0), TAG_LENGTH) != 0) {
                                        error(p, "Tag failed verification");
                                        r = -EBADMSG;
                                        goto fail;
                                }

                                f->hmac_running = false;
                                last_tag_realtime = rt;
                        }

                        last_tag = p + ALIGN64(le64toh(o->object.size));
#endif

                        last_epoch = le64toh(o->tag.epoch);

                        n_tags++;
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
            n_tags != le64toh(f->header->n_tags)) {
                error(offsetof(Header, n_tags),
                      "Tag number mismatch (%"PRIu64" != %"PRIu64")",
                      n_tags,
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

        if (entry_realtime_set && entry_realtime != le64toh(f->header->tail_entry_realtime)) {
                error(0,
                      "Invalid tail realtime timestamp (%"PRIu64" != %"PRIu64")",
                      entry_realtime,
                      le64toh(f->header->tail_entry_realtime));
                r = -EBADMSG;
                goto fail;
        }

        if (fflush(data_fp) != 0) {
                r = log_error_errno(errno, "Failed to flush data file stream: %m");
                goto fail;
        }

        if (fflush(entry_fp) != 0) {
                r = log_error_errno(errno, "Failed to flush entry file stream: %m");
                goto fail;
        }

        if (fflush(entry_array_fp) != 0) {
                r = log_error_errno(errno, "Failed to flush entry array file stream: %m");
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
                               cache_data_fd, n_data,
                               cache_entry_fd, n_entries,
                               cache_entry_array_fd, n_entry_arrays,
                               &last_usec,
                               show_progress);
        if (r < 0)
                goto fail;

        r = verify_data_hash_table(f,
                                   cache_data_fd, n_data,
                                   cache_entry_fd, n_entries,
                                   cache_entry_array_fd, n_entry_arrays,
                                   &last_usec,
                                   show_progress);
        if (r < 0)
                goto fail;

        if (show_progress)
                flush_progress();

        mmap_cache_fd_free(cache_data_fd);
        mmap_cache_fd_free(cache_entry_fd);
        mmap_cache_fd_free(cache_entry_array_fd);

        if (first_contained)
                *first_contained = le64toh(f->header->head_entry_realtime);
#if HAVE_GCRYPT
        if (last_validated)
                *last_validated = last_tag_realtime + f->fss_interval_usec;
#endif
        if (last_contained)
                *last_contained = le64toh(f->header->tail_entry_realtime);

        return 0;

fail:
        if (show_progress)
                flush_progress();

        log_error("File corruption detected at %s:%"PRIu64" (of %"PRIu64" bytes, %"PRIu64"%%).",
                  f->path,
                  p,
                  (uint64_t) f->last_stat.st_size,
                  100U * p / (uint64_t) f->last_stat.st_size);

        if (cache_data_fd)
                mmap_cache_fd_free(cache_data_fd);

        if (cache_entry_fd)
                mmap_cache_fd_free(cache_entry_fd);

        if (cache_entry_array_fd)
                mmap_cache_fd_free(cache_entry_array_fd);

        return r;
}
