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

#include "util.h"
#include "macro.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-authenticate.h"
#include "journal-verify.h"
#include "lookup3.h"

/* FIXME:
 *
 * - verify hashes of compressed objects
 * - follow all chains
 * - check for unreferenced objects
 * - verify FSPRG
 *
 * */

static int journal_file_object_verify(JournalFile *f, Object *o) {
        assert(f);
        assert(o);

        /* This does various superficial tests about the length an
         * possible field values. It does not follow any references to
         * other objects. */

        if ((o->object.flags & OBJECT_COMPRESSED) &&
            o->object.type != OBJECT_DATA)
                return -EBADMSG;

        switch (o->object.type) {

        case OBJECT_DATA:
                if (le64toh(o->data.entry_offset) <= 0 ||
                    le64toh(o->data.n_entries) <= 0)
                        return -EBADMSG;

                if (le64toh(o->object.size) - offsetof(DataObject, payload) <= 0)
                        return -EBADMSG;

                if (!(o->object.flags & OBJECT_COMPRESSED)) {
                        uint64_t h1, h2;

                        h1 = le64toh(o->data.hash);
                        h2 = hash64(o->data.payload, le64toh(o->object.size) - offsetof(Object, data.payload));

                        if (h1 != h2)
                                return -EBADMSG;
                }

                break;

        case OBJECT_FIELD:
                if (le64toh(o->object.size) - offsetof(FieldObject, payload) <= 0)
                        return -EBADMSG;
                break;

        case OBJECT_ENTRY:
                if ((le64toh(o->object.size) - offsetof(EntryObject, items)) % sizeof(EntryItem) != 0)
                        return -EBADMSG;

                if ((le64toh(o->object.size) - offsetof(EntryObject, items)) / sizeof(EntryItem) <= 0)
                        return -EBADMSG;

                if (le64toh(o->entry.seqnum) <= 0 ||
                    le64toh(o->entry.realtime) <= 0)
                        return -EBADMSG;

                break;

        case OBJECT_DATA_HASH_TABLE:
        case OBJECT_FIELD_HASH_TABLE:
                if ((le64toh(o->object.size) - offsetof(HashTableObject, items)) % sizeof(HashItem) != 0)
                        return -EBADMSG;

                break;

        case OBJECT_ENTRY_ARRAY:
                if ((le64toh(o->object.size) - offsetof(EntryArrayObject, items)) % sizeof(le64_t) != 0)
                        return -EBADMSG;

                break;

        case OBJECT_TAG:
                if (le64toh(o->object.size) != sizeof(TagObject))
                        return -EBADMSG;
                break;
        }

        return 0;
}

static void draw_progress(uint64_t p, usec_t *last_usec) {
        unsigned n, i, j, k;
        usec_t z, x;

        if (!isatty(STDOUT_FILENO))
                return;

        z = now(CLOCK_MONOTONIC);
        x = *last_usec;

        if (x != 0 && x + 40 * USEC_PER_MSEC > z)
                return;

        *last_usec = z;

        n = (3 * columns()) / 4;
        j = (n * (unsigned) p) / 65535ULL;
        k = n - j;

        fputs("\r\x1B[?25l", stdout);

        for (i = 0; i < j; i++)
                fputs("\xe2\x96\x88", stdout);

        for (i = 0; i < k; i++)
                fputs("\xe2\x96\x91", stdout);

        printf(" %3lu%%", 100LU * (unsigned long) p / 65535LU);

        fputs("\r\x1B[?25h", stdout);
        fflush(stdout);
}

static void flush_progress(void) {
        unsigned n, i;

        if (!isatty(STDOUT_FILENO))
                return;

        n = (3 * columns()) / 4;

        putchar('\r');

        for (i = 0; i < n + 5; i++)
                putchar(' ');

        putchar('\r');
        fflush(stdout);
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

                r = mmap_cache_get(m, fd, PROT_READ, 0, c * sizeof(uint64_t), sizeof(uint64_t), (void **) &z);
                if (r < 0)
                        return r;

                if (*z == p)
                        return 1;

                if (p < *z)
                        b = c;
                else
                        a = c;
        }

        return 0;
}

int journal_file_verify(JournalFile *f, const char *key) {
        int r;
        Object *o;
        uint64_t p = 0;
        uint64_t tag_seqnum = 0, entry_seqnum = 0, entry_monotonic = 0, entry_realtime = 0;
        sd_id128_t entry_boot_id;
        bool entry_seqnum_set = false, entry_monotonic_set = false, entry_realtime_set = false, found_main_entry_array = false;
        uint64_t n_weird = 0, n_objects = 0, n_entries = 0, n_data = 0, n_fields = 0, n_data_hash_tables = 0, n_field_hash_tables = 0, n_entry_arrays = 0;
        usec_t last_usec = 0;
        int data_fd = -1, entry_fd = -1, entry_array_fd = -1;
        char data_path[] = "/var/tmp/journal-data-XXXXXX",
                entry_path[] = "/var/tmp/journal-entry-XXXXXX",
                entry_array_path[] = "/var/tmp/journal-entry-array-XXXXXX";

        assert(f);

        data_fd = mkostemp(data_path, O_CLOEXEC);
        if (data_fd < 0) {
                log_error("Failed to create data file: %m");
                goto fail;
        }
        unlink(data_path);

        entry_fd = mkostemp(entry_path, O_CLOEXEC);
        if (entry_fd < 0) {
                log_error("Failed to create entry file: %m");
                goto fail;
        }
        unlink(entry_path);

        entry_array_fd = mkostemp(entry_array_path, O_CLOEXEC);
        if (entry_array_fd < 0) {
                log_error("Failed to create entry array file: %m");
                goto fail;
        }
        unlink(entry_array_path);

        /* First iteration: we go through all objects, verify the
         * superficial structure, headers, hashes. */

        r = journal_file_hmac_put_header(f);
        if (r < 0) {
                log_error("Failed to calculate HMAC of header.");
                goto fail;
        }

        p = le64toh(f->header->header_size);
        while (p != 0) {
                draw_progress((0x7FFF * p) / le64toh(f->header->tail_object_offset), &last_usec);

                r = journal_file_move_to_object(f, -1, p, &o);
                if (r < 0) {
                        log_error("Invalid object at %llu", (unsigned long long) p);
                        goto fail;
                }

                if (le64toh(f->header->tail_object_offset) < p) {
                        log_error("Invalid tail object pointer.");
                        r = -EBADMSG;
                        goto fail;
                }

                n_objects ++;

                r = journal_file_object_verify(f, o);
                if (r < 0) {
                        log_error("Invalid object contents at %llu", (unsigned long long) p);
                        goto fail;
                }

                if (o->object.flags & OBJECT_COMPRESSED &&
                    !(le32toh(f->header->incompatible_flags) & HEADER_INCOMPATIBLE_COMPRESSED)) {
                        log_error("Compressed object without compression at %llu", (unsigned long long) p);
                        r = -EBADMSG;
                        goto fail;
                }

                r = journal_file_hmac_put_object(f, -1, p);
                if (r < 0) {
                        log_error("Failed to calculate HMAC at %llu", (unsigned long long) p);
                        goto fail;
                }

                if (o->object.type == OBJECT_TAG) {

                        if (!(le32toh(f->header->compatible_flags) & HEADER_COMPATIBLE_AUTHENTICATED)) {
                                log_error("Tag object without authentication at %llu", (unsigned long long) p);
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (le64toh(o->tag.seqnum) != tag_seqnum) {
                                log_error("Tag sequence number out of synchronization at %llu", (unsigned long long) p);
                                r = -EBADMSG;
                                goto fail;
                        }

                } else if (o->object.type == OBJECT_ENTRY) {

                        r = write_uint64(entry_fd, p);
                        if (r < 0)
                                goto fail;

                        if (!entry_seqnum_set &&
                            le64toh(o->entry.seqnum) != le64toh(f->header->head_entry_seqnum)) {
                                log_error("Head entry sequence number incorrect");
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (entry_seqnum_set &&
                            entry_seqnum >= le64toh(o->entry.seqnum)) {
                                log_error("Entry sequence number out of synchronization at %llu", (unsigned long long) p);
                                r = -EBADMSG;
                                goto fail;
                        }

                        entry_seqnum = le64toh(o->entry.seqnum);
                        entry_seqnum_set = true;

                        if (entry_monotonic_set &&
                            sd_id128_equal(entry_boot_id, o->entry.boot_id) &&
                            entry_monotonic > le64toh(o->entry.monotonic)) {
                                log_error("Entry timestamp out of synchronization at %llu", (unsigned long long) p);
                                r = -EBADMSG;
                                goto fail;
                        }

                        entry_monotonic = le64toh(o->entry.monotonic);
                        entry_boot_id = o->entry.boot_id;
                        entry_monotonic_set = true;

                        if (!entry_realtime_set &&
                            le64toh(o->entry.realtime) != le64toh(f->header->head_entry_realtime)) {
                                log_error("Head entry realtime timestamp incorrect");
                                r = -EBADMSG;
                                goto fail;
                        }

                        entry_realtime = le64toh(o->entry.realtime);
                        entry_realtime_set = true;

                        n_entries ++;
                } else if (o->object.type == OBJECT_ENTRY_ARRAY) {

                        r = write_uint64(entry_array_fd, p);
                        if (r < 0)
                                goto fail;

                        if (p == le64toh(f->header->entry_array_offset)) {
                                if (found_main_entry_array) {
                                        log_error("More than one main entry array at %llu", (unsigned long long) p);
                                        r = -EBADMSG;
                                        goto fail;
                                }

                                found_main_entry_array = true;
                        }

                        n_entry_arrays++;

                } else if (o->object.type == OBJECT_DATA) {

                        r = write_uint64(data_fd, p);
                        if (r < 0)
                                goto fail;

                        n_data++;

                } else if (o->object.type == OBJECT_FIELD)
                        n_fields++;
                else if (o->object.type == OBJECT_DATA_HASH_TABLE) {
                        n_data_hash_tables++;

                        if (n_data_hash_tables > 1) {
                                log_error("More than one data hash table at %llu", (unsigned long long) p);
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (le64toh(f->header->data_hash_table_offset) != p + offsetof(HashTableObject, items) ||
                            le64toh(f->header->data_hash_table_size) != le64toh(o->object.size) - offsetof(HashTableObject, items)) {
                                log_error("Header fields for data hash table invalid.");
                                r = -EBADMSG;
                                goto fail;
                        }
                } else if (o->object.type == OBJECT_FIELD_HASH_TABLE) {
                        n_field_hash_tables++;

                        if (n_field_hash_tables > 1) {
                                log_error("More than one field hash table at %llu", (unsigned long long) p);
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (le64toh(f->header->field_hash_table_offset) != p + offsetof(HashTableObject, items) ||
                            le64toh(f->header->field_hash_table_size) != le64toh(o->object.size) - offsetof(HashTableObject, items)) {
                                log_error("Header fields for field hash table invalid.");
                                r = -EBADMSG;
                                goto fail;
                        }
                } else if (o->object.type >= _OBJECT_TYPE_MAX)
                        n_weird ++;

                if (p == le64toh(f->header->tail_object_offset))
                        p = 0;
                else
                        p = p + ALIGN64(le64toh(o->object.size));
        }

        if (n_objects != le64toh(f->header->n_objects)) {
                log_error("Object number mismatch");
                r = -EBADMSG;
                goto fail;
        }

        if (n_entries != le64toh(f->header->n_entries)) {
                log_error("Entry number mismatch");
                r = -EBADMSG;
                goto fail;
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_data) &&
            n_data != le64toh(f->header->n_data)) {
                log_error("Data number mismatch");
                r = -EBADMSG;
                goto fail;
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_fields) &&
            n_fields != le64toh(f->header->n_fields)) {
                log_error("Field number mismatch");
                r = -EBADMSG;
                goto fail;
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_tags) &&
            tag_seqnum != le64toh(f->header->n_tags)) {
                log_error("Tag number mismatch");
                r = -EBADMSG;
                goto fail;
        }

        if (n_data_hash_tables != 1) {
                log_error("Missing data hash table");
                r = -EBADMSG;
                goto fail;
        }

        if (n_field_hash_tables != 1) {
                log_error("Missing field hash table");
                r = -EBADMSG;
                goto fail;
        }

        if (!found_main_entry_array) {
                log_error("Missing entry array");
                r = -EBADMSG;
                goto fail;
        }

        if (entry_seqnum_set &&
            entry_seqnum != le64toh(f->header->tail_entry_seqnum)) {
                log_error("Invalid tail seqnum");
                r = -EBADMSG;
                goto fail;
        }

        if (entry_monotonic_set &&
            (!sd_id128_equal(entry_boot_id, f->header->boot_id) ||
             entry_monotonic != le64toh(f->header->tail_entry_monotonic))) {
                log_error("Invalid tail monotonic timestamp");
                r = -EBADMSG;
                goto fail;
        }

        if (entry_realtime_set && entry_realtime != le64toh(f->header->tail_entry_realtime)) {
                log_error("Invalid tail realtime timestamp");
                r = -EBADMSG;
                goto fail;
        }

        /* Second iteration: we go through all objects again, this
         * time verify all pointers. */

        p = le64toh(f->header->header_size);
        while (p != 0) {
                draw_progress(0x8000 + (0x7FFF * p) / le64toh(f->header->tail_object_offset), &last_usec);

                r = journal_file_move_to_object(f, -1, p, &o);
                if (r < 0) {
                        log_error("Invalid object at %llu", (unsigned long long) p);
                        goto fail;
                }

                if (o->object.type == OBJECT_ENTRY_ARRAY) {
                        uint64_t i = 0, n;

                        if (le64toh(o->entry_array.next_entry_array_offset) != 0 &&
                            !contains_uint64(f->mmap, entry_array_fd, n_entry_arrays, le64toh(o->entry_array.next_entry_array_offset))) {
                                log_error("Entry array chains up to invalid next array at %llu", (unsigned long long) p);
                                r = -EBADMSG;
                                goto fail;
                        }

                        n = journal_file_entry_array_n_items(o);
                        for (i = 0; i < n; i++) {
                                if (le64toh(o->entry_array.items[i]) != 0 &&
                                    !contains_uint64(f->mmap, entry_fd, n_entries, le64toh(o->entry_array.items[i]))) {

                                        log_error("Entry array points to invalid next array at %llu", (unsigned long long) p);
                                        r = -EBADMSG;
                                        goto fail;
                                }
                        }

                }

                r = journal_file_move_to_object(f, -1, p, &o);
                if (r < 0) {
                        log_error("Invalid object at %llu", (unsigned long long) p);
                        goto fail;
                }

                if (p == le64toh(f->header->tail_object_offset))
                        p = 0;
                else
                        p = p + ALIGN64(le64toh(o->object.size));
        }

        flush_progress();

        mmap_cache_close_fd(f->mmap, data_fd);
        mmap_cache_close_fd(f->mmap, entry_fd);
        mmap_cache_close_fd(f->mmap, entry_array_fd);

        close_nointr_nofail(data_fd);
        close_nointr_nofail(entry_fd);
        close_nointr_nofail(entry_array_fd);

        return 0;

fail:
        flush_progress();

        log_error("File corruption detected at %s:%llu (of %llu, %llu%%).",
                  f->path,
                  (unsigned long long) p,
                  (unsigned long long) f->last_stat.st_size,
                  (unsigned long long) (100 * p / f->last_stat.st_size));

        if (data_fd >= 0) {
                mmap_cache_close_fd(f->mmap, data_fd);
                close_nointr_nofail(data_fd);
        }

        if (entry_fd >= 0) {
                mmap_cache_close_fd(f->mmap, entry_fd);
                close_nointr_nofail(entry_fd);
        }

        if (entry_array_fd >= 0) {
                mmap_cache_close_fd(f->mmap, entry_array_fd);
                close_nointr_nofail(entry_array_fd);
        }

        return r;
}
