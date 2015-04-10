/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stddef.h>

#include "util.h"
#include "macro.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-authenticate.h"
#include "journal-verify.h"
#include "lookup3.h"
#include "compress.h"
#include "terminal-util.h"

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

        fputs("\r\x1B[?25l" ANSI_HIGHLIGHT_GREEN_ON, stdout);

        for (i = 0; i < j; i++)
                fputs("\xe2\x96\x88", stdout);

        fputs(ANSI_HIGHLIGHT_OFF, stdout);

        for (i = 0; i < k; i++)
                fputs("\xe2\x96\x91", stdout);

        printf(" %3"PRIu64"%%", 100U * p / 65535U);

        fputs("\r\x1B[?25h", stdout);
        fflush(stdout);
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

#define debug(_offset, _fmt, ...) do{                                   \
                flush_progress();                                       \
                log_debug(OFSfmt": " _fmt, _offset, ##__VA_ARGS__);     \
        } while(0)

#define warning(_offset, _fmt, ...) do{                                 \
                flush_progress();                                       \
                log_warning(OFSfmt": " _fmt, _offset, ##__VA_ARGS__);   \
        } while(0)

#define error(_offset, _fmt, ...) do{                                   \
                flush_progress();                                       \
                log_error(OFSfmt": " _fmt, (uint64_t)_offset, ##__VA_ARGS__); \
        } while(0)

static int journal_file_object_verify(JournalFile *f, uint64_t offset, Object *o) {
        uint64_t i;

        assert(f);
        assert(offset);
        assert(o);

        /* This does various superficial tests about the length an
         * possible field values. It does not follow any references to
         * other objects. */

        if ((o->object.flags & OBJECT_COMPRESSED_XZ) &&
            o->object.type != OBJECT_DATA)
                return -EBADMSG;

        switch (o->object.type) {

        case OBJECT_DATA: {
                uint64_t h1, h2;
                int compression, r;

                if (le64toh(o->data.entry_offset) == 0)
                        warning(offset, "unused data (entry_offset==0)");

                if ((le64toh(o->data.entry_offset) == 0) ^ (le64toh(o->data.n_entries) == 0)) {
                        error(offset, "bad n_entries: %"PRIu64, o->data.n_entries);
                        return -EBADMSG;
                }

                if (le64toh(o->object.size) - offsetof(DataObject, payload) <= 0) {
                        error(offset, "bad object size (<= %zu): %"PRIu64,
                              offsetof(DataObject, payload),
                              le64toh(o->object.size));
                        return -EBADMSG;
                }

                h1 = le64toh(o->data.hash);

                compression = o->object.flags & OBJECT_COMPRESSION_MASK;
                if (compression) {
                        _cleanup_free_ void *b = NULL;
                        size_t alloc = 0, b_size;

                        r = decompress_blob(compression,
                                            o->data.payload,
                                            le64toh(o->object.size) - offsetof(Object, data.payload),
                                            &b, &alloc, &b_size, 0);
                        if (r < 0) {
                                error(offset, "%s decompression failed: %s",
                                      object_compressed_to_string(compression), strerror(-r));
                                return r;
                        }

                        h2 = hash64(b, b_size);
                } else
                        h2 = hash64(o->data.payload, le64toh(o->object.size) - offsetof(Object, data.payload));

                if (h1 != h2) {
                        error(offset, "invalid hash (%08"PRIx64" vs. %08"PRIx64, h1, h2);
                        return -EBADMSG;
                }

                if (!VALID64(o->data.next_hash_offset) ||
                    !VALID64(o->data.next_field_offset) ||
                    !VALID64(o->data.entry_offset) ||
                    !VALID64(o->data.entry_array_offset)) {
                        error(offset, "invalid offset (next_hash_offset="OFSfmt", next_field_offset="OFSfmt", entry_offset="OFSfmt", entry_array_offset="OFSfmt,
                              o->data.next_hash_offset,
                              o->data.next_field_offset,
                              o->data.entry_offset,
                              o->data.entry_array_offset);
                        return -EBADMSG;
                }

                break;
        }

        case OBJECT_FIELD:
                if (le64toh(o->object.size) - offsetof(FieldObject, payload) <= 0) {
                        error(offset,
                              "bad field size (<= %zu): %"PRIu64,
                              offsetof(FieldObject, payload),
                              le64toh(o->object.size));
                        return -EBADMSG;
                }

                if (!VALID64(o->field.next_hash_offset) ||
                    !VALID64(o->field.head_data_offset)) {
                        error(offset,
                              "invalid offset (next_hash_offset="OFSfmt", head_data_offset="OFSfmt,
                              o->field.next_hash_offset,
                              o->field.head_data_offset);
                        return -EBADMSG;
                }
                break;

        case OBJECT_ENTRY:
                if ((le64toh(o->object.size) - offsetof(EntryObject, items)) % sizeof(EntryItem) != 0) {
                        error(offset,
                              "bad entry size (<= %zu): %"PRIu64,
                              offsetof(EntryObject, items),
                              le64toh(o->object.size));
                        return -EBADMSG;
                }

                if ((le64toh(o->object.size) - offsetof(EntryObject, items)) / sizeof(EntryItem) <= 0) {
                        error(offset,
                              "invalid number items in entry: %"PRIu64,
                              (le64toh(o->object.size) - offsetof(EntryObject, items)) / sizeof(EntryItem));
                        return -EBADMSG;
                }

                if (le64toh(o->entry.seqnum) <= 0) {
                        error(offset,
                              "invalid entry seqnum: %"PRIx64,
                              le64toh(o->entry.seqnum));
                        return -EBADMSG;
                }

                if (!VALID_REALTIME(le64toh(o->entry.realtime))) {
                        error(offset,
                              "invalid entry realtime timestamp: %"PRIu64,
                              le64toh(o->entry.realtime));
                        return -EBADMSG;
                }

                if (!VALID_MONOTONIC(le64toh(o->entry.monotonic))) {
                        error(offset,
                              "invalid entry monotonic timestamp: %"PRIu64,
                              le64toh(o->entry.monotonic));
                        return -EBADMSG;
                }

                for (i = 0; i < journal_file_entry_n_items(o); i++) {
                        if (o->entry.items[i].object_offset == 0 ||
                            !VALID64(o->entry.items[i].object_offset)) {
                                error(offset,
                                      "invalid entry item (%"PRIu64"/%"PRIu64" offset: "OFSfmt,
                                      i, journal_file_entry_n_items(o),
                                      o->entry.items[i].object_offset);
                                return -EBADMSG;
                        }
                }

                break;

        case OBJECT_DATA_HASH_TABLE:
        case OBJECT_FIELD_HASH_TABLE:
                if ((le64toh(o->object.size) - offsetof(HashTableObject, items)) % sizeof(HashItem) != 0 ||
                    (le64toh(o->object.size) - offsetof(HashTableObject, items)) / sizeof(HashItem) <= 0) {
                        error(offset,
                              "invalid %s hash table size: %"PRIu64,
                              o->object.type == OBJECT_DATA_HASH_TABLE ? "data" : "field",
                              le64toh(o->object.size));
                        return -EBADMSG;
                }

                for (i = 0; i < journal_file_hash_table_n_items(o); i++) {
                        if (o->hash_table.items[i].head_hash_offset != 0 &&
                            !VALID64(le64toh(o->hash_table.items[i].head_hash_offset))) {
                                error(offset,
                                      "invalid %s hash table item (%"PRIu64"/%"PRIu64") head_hash_offset: "OFSfmt,
                                      o->object.type == OBJECT_DATA_HASH_TABLE ? "data" : "field",
                                      i, journal_file_hash_table_n_items(o),
                                      le64toh(o->hash_table.items[i].head_hash_offset));
                                return -EBADMSG;
                        }
                        if (o->hash_table.items[i].tail_hash_offset != 0 &&
                            !VALID64(le64toh(o->hash_table.items[i].tail_hash_offset))) {
                                error(offset,
                                      "invalid %s hash table item (%"PRIu64"/%"PRIu64") tail_hash_offset: "OFSfmt,
                                      o->object.type == OBJECT_DATA_HASH_TABLE ? "data" : "field",
                                      i, journal_file_hash_table_n_items(o),
                                      le64toh(o->hash_table.items[i].tail_hash_offset));
                                return -EBADMSG;
                        }

                        if ((o->hash_table.items[i].head_hash_offset != 0) !=
                            (o->hash_table.items[i].tail_hash_offset != 0)) {
                                error(offset,
                                      "invalid %s hash table item (%"PRIu64"/%"PRIu64"): head_hash_offset="OFSfmt" tail_hash_offset="OFSfmt,
                                      o->object.type == OBJECT_DATA_HASH_TABLE ? "data" : "field",
                                      i, journal_file_hash_table_n_items(o),
                                      le64toh(o->hash_table.items[i].head_hash_offset),
                                      le64toh(o->hash_table.items[i].tail_hash_offset));
                                return -EBADMSG;
                        }
                }

                break;

        case OBJECT_ENTRY_ARRAY:
                if ((le64toh(o->object.size) - offsetof(EntryArrayObject, items)) % sizeof(le64_t) != 0 ||
                    (le64toh(o->object.size) - offsetof(EntryArrayObject, items)) / sizeof(le64_t) <= 0) {
                        error(offset,
                              "invalid object entry array size: %"PRIu64,
                              le64toh(o->object.size));
                        return -EBADMSG;
                }

                if (!VALID64(o->entry_array.next_entry_array_offset)) {
                        error(offset,
                              "invalid object entry array next_entry_array_offset: "OFSfmt,
                              o->entry_array.next_entry_array_offset);
                        return -EBADMSG;
                }

                for (i = 0; i < journal_file_entry_array_n_items(o); i++)
                        if (le64toh(o->entry_array.items[i]) != 0 &&
                            !VALID64(le64toh(o->entry_array.items[i]))) {
                                error(offset,
                                      "invalid object entry array item (%"PRIu64"/%"PRIu64"): "OFSfmt,
                                      i, journal_file_entry_array_n_items(o),
                                      le64toh(o->entry_array.items[i]));
                                return -EBADMSG;
                        }

                break;

        case OBJECT_TAG:
                if (le64toh(o->object.size) != sizeof(TagObject)) {
                        error(offset,
                              "invalid object tag size: %"PRIu64,
                              le64toh(o->object.size));
                        return -EBADMSG;
                }

                if (!VALID_EPOCH(o->tag.epoch)) {
                        error(offset,
                              "invalid object tag epoch: %"PRIu64,
                              o->tag.epoch);
                        return -EBADMSG;
                }

                break;
        }

        return 0;
}

static int write_uint64(int fd, uint64_t p) {
        ssize_t k;

        k = write(fd, &p, sizeof(p));
        if (k < 0)
                return -errno;
        if (k != sizeof(p))
                return -EIO;

        return 0;
}

static int contains_uint64(MMapCache *m, int fd, uint64_t n, uint64_t p) {
        uint64_t a, b;
        int r;

        assert(m);
        assert(fd >= 0);

        /* Bisection ... */

        a = 0; b = n;
        while (a < b) {
                uint64_t c, *z;

                c = (a + b) / 2;

                r = mmap_cache_get(m, fd, PROT_READ|PROT_WRITE, 0, false, c * sizeof(uint64_t), sizeof(uint64_t), NULL, (void **) &z);
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

static int entry_points_to_data(
                JournalFile *f,
                int entry_fd,
                uint64_t n_entries,
                uint64_t entry_p,
                uint64_t data_p) {

        int r;
        uint64_t i, n, a;
        Object *o;
        bool found = false;

        assert(f);
        assert(entry_fd >= 0);

        if (!contains_uint64(f->mmap, entry_fd, n_entries, entry_p)) {
                error(data_p,
                      "data object references invalid entry at "OFSfmt, entry_p);
                return -EBADMSG;
        }

        r = journal_file_move_to_object(f, OBJECT_ENTRY, entry_p, &o);
        if (r < 0)
                return r;

        n = journal_file_entry_n_items(o);
        for (i = 0; i < n; i++)
                if (le64toh(o->entry.items[i].object_offset) == data_p) {
                        found = true;
                        break;
                }

        if (!found) {
                error(entry_p,
                      "data object at "OFSfmt" not referenced by linked entry", data_p);
                return -EBADMSG;
        }

        /* Check if this entry is also in main entry array. Since the
         * main entry array has already been verified we can rely on
         * its consistency. */

        i = 0;
        n = le64toh(f->header->n_entries);
        a = le64toh(f->header->entry_array_offset);

        while (i < n) {
                uint64_t m, u;

                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o);
                if (r < 0)
                        return r;

                m = journal_file_entry_array_n_items(o);
                u = MIN(n - i, m);

                if (entry_p <= le64toh(o->entry_array.items[u-1])) {
                        uint64_t x, y, z;

                        x = 0;
                        y = u;

                        while (x < y) {
                                z = (x + y) / 2;

                                if (le64toh(o->entry_array.items[z]) == entry_p)
                                        return 0;

                                if (x + 1 >= y)
                                        break;

                                if (entry_p < le64toh(o->entry_array.items[z]))
                                        y = z;
                                else
                                        x = z;
                        }

                        error(entry_p, "entry object doesn't exist in main entry array");
                        return -EBADMSG;
                }

                i += u;
                a = le64toh(o->entry_array.next_entry_array_offset);
        }

        return 0;
}

static int verify_data(
                JournalFile *f,
                Object *o, uint64_t p,
                int entry_fd, uint64_t n_entries,
                int entry_array_fd, uint64_t n_entry_arrays) {

        uint64_t i, n, a, last, q;
        int r;

        assert(f);
        assert(o);
        assert(entry_fd >= 0);
        assert(entry_array_fd >= 0);

        n = le64toh(o->data.n_entries);
        a = le64toh(o->data.entry_array_offset);

        /* Entry array means at least two objects */
        if (a && n < 2) {
                error(p,
                      "entry array present (entry_array_offset="OFSfmt", but n_entries=%"PRIu64")",
                      a, n);
                return -EBADMSG;
        }

        if (n == 0)
                return 0;

        /* We already checked that earlier */
        assert(o->data.entry_offset);

        last = q = le64toh(o->data.entry_offset);
        r = entry_points_to_data(f, entry_fd, n_entries, q, p);
        if (r < 0)
                return r;

        i = 1;
        while (i < n) {
                uint64_t next, m, j;

                if (a == 0) {
                        error(p, "array chain too short");
                        return -EBADMSG;
                }

                if (!contains_uint64(f->mmap, entry_array_fd, n_entry_arrays, a)) {
                        error(p, "invalid array offset "OFSfmt, a);
                        return -EBADMSG;
                }

                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o);
                if (r < 0)
                        return r;

                next = le64toh(o->entry_array.next_entry_array_offset);
                if (next != 0 && next <= a) {
                        error(p, "array chain has cycle (jumps back from "OFSfmt" to "OFSfmt")",
                              a, next);
                        return -EBADMSG;
                }

                m = journal_file_entry_array_n_items(o);
                for (j = 0; i < n && j < m; i++, j++) {

                        q = le64toh(o->entry_array.items[j]);
                        if (q <= last) {
                                error(p, "data object's entry array not sorted");
                                return -EBADMSG;
                        }
                        last = q;

                        r = entry_points_to_data(f, entry_fd, n_entries, q, p);
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
                JournalFile *f,
                int data_fd, uint64_t n_data,
                int entry_fd, uint64_t n_entries,
                int entry_array_fd, uint64_t n_entry_arrays,
                usec_t *last_usec,
                bool show_progress) {

        uint64_t i, n;
        int r;

        assert(f);
        assert(data_fd >= 0);
        assert(entry_fd >= 0);
        assert(entry_array_fd >= 0);
        assert(last_usec);

        n = le64toh(f->header->data_hash_table_size) / sizeof(HashItem);
        for (i = 0; i < n; i++) {
                uint64_t last = 0, p;

                if (show_progress)
                        draw_progress(0xC000 + (0x3FFF * i / n), last_usec);

                p = le64toh(f->data_hash_table[i].head_hash_offset);
                while (p != 0) {
                        Object *o;
                        uint64_t next;

                        if (!contains_uint64(f->mmap, data_fd, n_data, p)) {
                                error(p, "invalid data object at hash entry %"PRIu64" of %"PRIu64,
                                      i, n);
                                return -EBADMSG;
                        }

                        r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
                        if (r < 0)
                                return r;

                        next = le64toh(o->data.next_hash_offset);
                        if (next != 0 && next <= p) {
                                error(p, "hash chain has a cycle in hash entry %"PRIu64" of %"PRIu64,
                                      i, n);
                                return -EBADMSG;
                        }

                        if (le64toh(o->data.hash) % n != i) {
                                error(p, "hash value mismatch in hash entry %"PRIu64" of %"PRIu64,
                                      i, n);
                                return -EBADMSG;
                        }

                        r = verify_data(f, o, p, entry_fd, n_entries, entry_array_fd, n_entry_arrays);
                        if (r < 0)
                                return r;

                        last = p;
                        p = next;
                }

                if (last != le64toh(f->data_hash_table[i].tail_hash_offset)) {
                        error(p, "tail hash pointer mismatch in hash table");
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
                int data_fd, uint64_t n_data) {

        uint64_t i, n;
        int r;

        assert(f);
        assert(o);
        assert(data_fd >= 0);

        n = journal_file_entry_n_items(o);
        for (i = 0; i < n; i++) {
                uint64_t q, h;
                Object *u;

                q = le64toh(o->entry.items[i].object_offset);
                h = le64toh(o->entry.items[i].hash);

                if (!contains_uint64(f->mmap, data_fd, n_data, q)) {
                        error(p, "invalid data object of entry");
                                return -EBADMSG;
                        }

                r = journal_file_move_to_object(f, OBJECT_DATA, q, &u);
                if (r < 0)
                        return r;

                if (le64toh(u->data.hash) != h) {
                        error(p, "hash mismatch for data object of entry");
                        return -EBADMSG;
                }

                r = data_object_in_hash_table(f, h, q);
                if (r < 0)
                        return r;
                if (r == 0) {
                        error(p, "data object missing from hash table");
                        return -EBADMSG;
                }
        }

        return 0;
}

static int verify_entry_array(
                JournalFile *f,
                int data_fd, uint64_t n_data,
                int entry_fd, uint64_t n_entries,
                int entry_array_fd, uint64_t n_entry_arrays,
                usec_t *last_usec,
                bool show_progress) {

        uint64_t i = 0, a, n, last = 0;
        int r;

        assert(f);
        assert(data_fd >= 0);
        assert(entry_fd >= 0);
        assert(entry_array_fd >= 0);
        assert(last_usec);

        n = le64toh(f->header->n_entries);
        a = le64toh(f->header->entry_array_offset);
        while (i < n) {
                uint64_t next, m, j;
                Object *o;

                if (show_progress)
                        draw_progress(0x8000 + (0x3FFF * i / n), last_usec);

                if (a == 0) {
                        error(a, "array chain too short at %"PRIu64" of %"PRIu64, i, n);
                        return -EBADMSG;
                }

                if (!contains_uint64(f->mmap, entry_array_fd, n_entry_arrays, a)) {
                        error(a, "invalid array %"PRIu64" of %"PRIu64, i, n);
                        return -EBADMSG;
                }

                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o);
                if (r < 0)
                        return r;

                next = le64toh(o->entry_array.next_entry_array_offset);
                if (next != 0 && next <= a) {
                        error(a,
                              "array chain has cycle at %"PRIu64" of %"PRIu64" (jumps back from to "OFSfmt")",
                              i, n, next);
                        return -EBADMSG;
                }

                m = journal_file_entry_array_n_items(o);
                for (j = 0; i < n && j < m; i++, j++) {
                        uint64_t p;

                        p = le64toh(o->entry_array.items[j]);
                        if (p <= last) {
                                error(a, "entry array not sorted at %"PRIu64" of %"PRIu64,
                                      i, n);
                                return -EBADMSG;
                        }
                        last = p;

                        if (!contains_uint64(f->mmap, entry_fd, n_entries, p)) {
                                error(a, "invalid array entry at %"PRIu64" of %"PRIu64,
                                      i, n);
                                return -EBADMSG;
                        }

                        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, &o);
                        if (r < 0)
                                return r;

                        r = verify_entry(f, o, p, data_fd, n_data);
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

int journal_file_verify(
                JournalFile *f,
                const char *key,
                usec_t *first_contained, usec_t *last_validated, usec_t *last_contained,
                bool show_progress) {
        int r;
        Object *o;
        uint64_t p = 0, last_epoch = 0, last_tag_realtime = 0, last_sealed_realtime = 0;

        uint64_t entry_seqnum = 0, entry_monotonic = 0, entry_realtime = 0;
        sd_id128_t entry_boot_id;
        bool entry_seqnum_set = false, entry_monotonic_set = false, entry_realtime_set = false, found_main_entry_array = false;
        uint64_t n_weird = 0, n_objects = 0, n_entries = 0, n_data = 0, n_fields = 0, n_data_hash_tables = 0, n_field_hash_tables = 0, n_entry_arrays = 0, n_tags = 0;
        usec_t last_usec = 0;
        int data_fd = -1, entry_fd = -1, entry_array_fd = -1;
        unsigned i;
        bool found_last = false;
#ifdef HAVE_GCRYPT
        uint64_t last_tag = 0;
#endif
        assert(f);

        if (key) {
#ifdef HAVE_GCRYPT
                r = journal_file_parse_verification_key(f, key);
                if (r < 0) {
                        log_error("Failed to parse seed.");
                        return r;
                }
#else
                return -EOPNOTSUPP;
#endif
        } else if (f->seal)
                return -ENOKEY;

        data_fd = open_tmpfile("/var/tmp", O_RDWR | O_CLOEXEC);
        if (data_fd < 0) {
                log_error_errno(errno, "Failed to create data file: %m");
                r = -errno;
                goto fail;
        }

        entry_fd = open_tmpfile("/var/tmp", O_RDWR | O_CLOEXEC);
        if (entry_fd < 0) {
                log_error_errno(errno, "Failed to create entry file: %m");
                r = -errno;
                goto fail;
        }

        entry_array_fd = open_tmpfile("/var/tmp", O_RDWR | O_CLOEXEC);
        if (entry_array_fd < 0) {
                log_error_errno(errno, "Failed to create entry array file: %m");
                r = -errno;
                goto fail;
        }

        if (le32toh(f->header->compatible_flags) & ~HEADER_COMPATIBLE_SUPPORTED) {
                log_error("Cannot verify file with unknown extensions.");
                r = -EOPNOTSUPP;
                goto fail;
        }

        for (i = 0; i < sizeof(f->header->reserved); i++)
                if (f->header->reserved[i] != 0) {
                        error(offsetof(Header, reserved[i]), "reserved field is non-zero");
                        r = -EBADMSG;
                        goto fail;
                }

        /* First iteration: we go through all objects, verify the
         * superficial structure, headers, hashes. */

        p = le64toh(f->header->header_size);
        while (p != 0) {
                if (show_progress)
                        draw_progress(0x7FFF * p / le64toh(f->header->tail_object_offset), &last_usec);

                r = journal_file_move_to_object(f, OBJECT_UNUSED, p, &o);
                if (r < 0) {
                        error(p, "invalid object");
                        goto fail;
                }

                if (p > le64toh(f->header->tail_object_offset)) {
                        error(offsetof(Header, tail_object_offset), "invalid tail object pointer");
                        r = -EBADMSG;
                        goto fail;
                }

                if (p == le64toh(f->header->tail_object_offset))
                        found_last = true;

                n_objects ++;

                r = journal_file_object_verify(f, p, o);
                if (r < 0) {
                        error(p, "invalid object contents: %s", strerror(-r));
                        goto fail;
                }

                if ((o->object.flags & OBJECT_COMPRESSED_XZ) &&
                    (o->object.flags & OBJECT_COMPRESSED_LZ4)) {
                        error(p, "objected with double compression");
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

                switch (o->object.type) {

                case OBJECT_DATA:
                        r = write_uint64(data_fd, p);
                        if (r < 0)
                                goto fail;

                        n_data++;
                        break;

                case OBJECT_FIELD:
                        n_fields++;
                        break;

                case OBJECT_ENTRY:
                        if (JOURNAL_HEADER_SEALED(f->header) && n_tags <= 0) {
                                error(p, "first entry before first tag");
                                r = -EBADMSG;
                                goto fail;
                        }

                        r = write_uint64(entry_fd, p);
                        if (r < 0)
                                goto fail;

                        if (le64toh(o->entry.realtime) < last_tag_realtime) {
                                error(p, "older entry after newer tag");
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (!entry_seqnum_set &&
                            le64toh(o->entry.seqnum) != le64toh(f->header->head_entry_seqnum)) {
                                error(p, "head entry sequence number incorrect");
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (entry_seqnum_set &&
                            entry_seqnum >= le64toh(o->entry.seqnum)) {
                                error(p, "entry sequence number out of synchronization");
                                r = -EBADMSG;
                                goto fail;
                        }

                        entry_seqnum = le64toh(o->entry.seqnum);
                        entry_seqnum_set = true;

                        if (entry_monotonic_set &&
                            sd_id128_equal(entry_boot_id, o->entry.boot_id) &&
                            entry_monotonic > le64toh(o->entry.monotonic)) {
                                error(p, "entry timestamp out of synchronization");
                                r = -EBADMSG;
                                goto fail;
                        }

                        entry_monotonic = le64toh(o->entry.monotonic);
                        entry_boot_id = o->entry.boot_id;
                        entry_monotonic_set = true;

                        if (!entry_realtime_set &&
                            le64toh(o->entry.realtime) != le64toh(f->header->head_entry_realtime)) {
                                error(p, "head entry realtime timestamp incorrect");
                                r = -EBADMSG;
                                goto fail;
                        }

                        entry_realtime = le64toh(o->entry.realtime);
                        entry_realtime_set = true;

                        n_entries ++;
                        break;

                case OBJECT_DATA_HASH_TABLE:
                        if (n_data_hash_tables > 1) {
                                error(p, "more than one data hash table");
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (le64toh(f->header->data_hash_table_offset) != p + offsetof(HashTableObject, items) ||
                            le64toh(f->header->data_hash_table_size) != le64toh(o->object.size) - offsetof(HashTableObject, items)) {
                                error(p, "header fields for data hash table invalid");
                                r = -EBADMSG;
                                goto fail;
                        }

                        n_data_hash_tables++;
                        break;

                case OBJECT_FIELD_HASH_TABLE:
                        if (n_field_hash_tables > 1) {
                                error(p, "more than one field hash table");
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (le64toh(f->header->field_hash_table_offset) != p + offsetof(HashTableObject, items) ||
                            le64toh(f->header->field_hash_table_size) != le64toh(o->object.size) - offsetof(HashTableObject, items)) {
                                error(p, "header fields for field hash table invalid");
                                r = -EBADMSG;
                                goto fail;
                        }

                        n_field_hash_tables++;
                        break;

                case OBJECT_ENTRY_ARRAY:
                        r = write_uint64(entry_array_fd, p);
                        if (r < 0)
                                goto fail;

                        if (p == le64toh(f->header->entry_array_offset)) {
                                if (found_main_entry_array) {
                                        error(p, "more than one main entry array");
                                        r = -EBADMSG;
                                        goto fail;
                                }

                                found_main_entry_array = true;
                        }

                        n_entry_arrays++;
                        break;

                case OBJECT_TAG:
                        if (!JOURNAL_HEADER_SEALED(f->header)) {
                                error(p, "tag object in file without sealing");
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (le64toh(o->tag.seqnum) != n_tags + 1) {
                                error(p, "tag sequence number out of synchronization");
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (le64toh(o->tag.epoch) < last_epoch) {
                                error(p, "epoch sequence out of synchronization");
                                r = -EBADMSG;
                                goto fail;
                        }

#ifdef HAVE_GCRYPT
                        if (f->seal) {
                                uint64_t q, rt;

                                debug(p, "checking tag %"PRIu64"...", le64toh(o->tag.seqnum));

                                rt = f->fss_start_usec + o->tag.epoch * f->fss_interval_usec;
                                if (entry_realtime_set && entry_realtime >= rt + f->fss_interval_usec) {
                                        error(p, "tag/entry realtime timestamp out of synchronization");
                                        r = -EBADMSG;
                                        goto fail;
                                }

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
                                        error(p, "tag failed verification");
                                        r = -EBADMSG;
                                        goto fail;
                                }

                                f->hmac_running = false;
                                last_tag_realtime = rt;
                                last_sealed_realtime = entry_realtime;
                        }

                        last_tag = p + ALIGN64(le64toh(o->object.size));
#endif

                        last_epoch = le64toh(o->tag.epoch);

                        n_tags ++;
                        break;

                default:
                        n_weird ++;
                }

                if (p == le64toh(f->header->tail_object_offset))
                        p = 0;
                else
                        p = p + ALIGN64(le64toh(o->object.size));
        }

        if (!found_last) {
                error(le64toh(f->header->tail_object_offset), "tail object pointer dead");
                r = -EBADMSG;
                goto fail;
        }

        if (n_objects != le64toh(f->header->n_objects)) {
                error(offsetof(Header, n_objects), "object number mismatch");
                r = -EBADMSG;
                goto fail;
        }

        if (n_entries != le64toh(f->header->n_entries)) {
                error(offsetof(Header, n_entries), "entry number mismatch");
                r = -EBADMSG;
                goto fail;
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_data) &&
            n_data != le64toh(f->header->n_data)) {
                error(offsetof(Header, n_data), "data number mismatch");
                r = -EBADMSG;
                goto fail;
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_fields) &&
            n_fields != le64toh(f->header->n_fields)) {
                error(offsetof(Header, n_fields), "field number mismatch");
                r = -EBADMSG;
                goto fail;
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_tags) &&
            n_tags != le64toh(f->header->n_tags)) {
                error(offsetof(Header, n_tags), "tag number mismatch");
                r = -EBADMSG;
                goto fail;
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_entry_arrays) &&
            n_entry_arrays != le64toh(f->header->n_entry_arrays)) {
                error(offsetof(Header, n_entry_arrays), "entry array number mismatch");
                r = -EBADMSG;
                goto fail;
        }

        if (n_data_hash_tables != 1) {
                error(0, "missing data hash table");
                r = -EBADMSG;
                goto fail;
        }

        if (n_field_hash_tables != 1) {
                error(0, "missing field hash table");
                r = -EBADMSG;
                goto fail;
        }

        if (!found_main_entry_array) {
                error(0, "missing entry array");
                r = -EBADMSG;
                goto fail;
        }

        if (entry_seqnum_set &&
            entry_seqnum != le64toh(f->header->tail_entry_seqnum)) {
                error(offsetof(Header, tail_entry_seqnum), "invalid tail seqnum");
                r = -EBADMSG;
                goto fail;
        }

        if (entry_monotonic_set &&
            (!sd_id128_equal(entry_boot_id, f->header->boot_id) ||
             entry_monotonic != le64toh(f->header->tail_entry_monotonic))) {
                error(0, "invalid tail monotonic timestamp");
                r = -EBADMSG;
                goto fail;
        }

        if (entry_realtime_set && entry_realtime != le64toh(f->header->tail_entry_realtime)) {
                error(0, "invalid tail realtime timestamp");
                r = -EBADMSG;
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
                               data_fd, n_data,
                               entry_fd, n_entries,
                               entry_array_fd, n_entry_arrays,
                               &last_usec,
                               show_progress);
        if (r < 0)
                goto fail;

        r = verify_hash_table(f,
                              data_fd, n_data,
                              entry_fd, n_entries,
                              entry_array_fd, n_entry_arrays,
                              &last_usec,
                              show_progress);
        if (r < 0)
                goto fail;

        if (show_progress)
                flush_progress();

        mmap_cache_close_fd(f->mmap, data_fd);
        mmap_cache_close_fd(f->mmap, entry_fd);
        mmap_cache_close_fd(f->mmap, entry_array_fd);

        safe_close(data_fd);
        safe_close(entry_fd);
        safe_close(entry_array_fd);

        if (first_contained)
                *first_contained = le64toh(f->header->head_entry_realtime);
        if (last_validated)
                *last_validated = last_sealed_realtime;
        if (last_contained)
                *last_contained = le64toh(f->header->tail_entry_realtime);

        return 0;

fail:
        if (show_progress)
                flush_progress();

        log_error("File corruption detected at %s:"OFSfmt" (of %llu bytes, %"PRIu64"%%).",
                  f->path,
                  p,
                  (unsigned long long) f->last_stat.st_size,
                  100 * p / f->last_stat.st_size);

        if (data_fd >= 0) {
                mmap_cache_close_fd(f->mmap, data_fd);
                safe_close(data_fd);
        }

        if (entry_fd >= 0) {
                mmap_cache_close_fd(f->mmap, entry_fd);
                safe_close(entry_fd);
        }

        if (entry_array_fd >= 0) {
                mmap_cache_close_fd(f->mmap, entry_array_fd);
                safe_close(entry_array_fd);
        }

        return r;
}
