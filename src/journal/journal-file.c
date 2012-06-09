/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <sys/mman.h>
#include <errno.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <stddef.h>

#include "journal-def.h"
#include "journal-file.h"
#include "lookup3.h"
#include "compress.h"

#define DEFAULT_DATA_HASH_TABLE_SIZE (2047ULL*16ULL)
#define DEFAULT_FIELD_HASH_TABLE_SIZE (2047ULL*16ULL)

#define DEFAULT_WINDOW_SIZE (8ULL*1024ULL*1024ULL)

#define COMPRESSION_SIZE_THRESHOLD (512ULL)

/* This is the minimum journal file size */
#define JOURNAL_FILE_SIZE_MIN (64ULL*1024ULL)                  /* 64 KiB */

/* These are the lower and upper bounds if we deduce the max_use value
 * from the file system size */
#define DEFAULT_MAX_USE_LOWER (1ULL*1024ULL*1024ULL)           /* 1 MiB */
#define DEFAULT_MAX_USE_UPPER (4ULL*1024ULL*1024ULL*1024ULL)   /* 4 GiB */

/* This is the upper bound if we deduce max_size from max_use */
#define DEFAULT_MAX_SIZE_UPPER (128ULL*1024ULL*1024ULL)        /* 128 MiB */

/* This is the upper bound if we deduce the keep_free value from the
 * file system size */
#define DEFAULT_KEEP_FREE_UPPER (4ULL*1024ULL*1024ULL*1024ULL) /* 4 GiB */

/* This is the keep_free value when we can't determine the system
 * size */
#define DEFAULT_KEEP_FREE (1024ULL*1024ULL)                    /* 1 MB */

static const char signature[] = { 'L', 'P', 'K', 'S', 'H', 'H', 'R', 'H' };

#define ALIGN64(x) (((x) + 7ULL) & ~7ULL)

void journal_file_close(JournalFile *f) {
        int t;

        assert(f);

        if (f->header) {
                if (f->writable)
                        f->header->state = STATE_OFFLINE;

                munmap(f->header, PAGE_ALIGN(sizeof(Header)));
        }

        for (t = 0; t < _WINDOW_MAX; t++)
                if (f->windows[t].ptr)
                        munmap(f->windows[t].ptr, f->windows[t].size);

        if (f->fd >= 0)
                close_nointr_nofail(f->fd);

        free(f->path);

#ifdef HAVE_XZ
        free(f->compress_buffer);
#endif

        free(f);
}

static int journal_file_init_header(JournalFile *f, JournalFile *template) {
        Header h;
        ssize_t k;
        int r;

        assert(f);

        zero(h);
        memcpy(h.signature, signature, 8);
        h.header_size = htole64(ALIGN64(sizeof(h)));

        r = sd_id128_randomize(&h.file_id);
        if (r < 0)
                return r;

        if (template) {
                h.seqnum_id = template->header->seqnum_id;
                h.seqnum = template->header->seqnum;
        } else
                h.seqnum_id = h.file_id;

        k = pwrite(f->fd, &h, sizeof(h), 0);
        if (k < 0)
                return -errno;

        if (k != sizeof(h))
                return -EIO;

        return 0;
}

static int journal_file_refresh_header(JournalFile *f) {
        int r;
        sd_id128_t boot_id;

        assert(f);

        r = sd_id128_get_machine(&f->header->machine_id);
        if (r < 0)
                return r;

        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return r;

        if (sd_id128_equal(boot_id, f->header->boot_id))
                f->tail_entry_monotonic_valid = true;

        f->header->boot_id = boot_id;

        f->header->state = STATE_ONLINE;

        __sync_synchronize();

        return 0;
}

static int journal_file_verify_header(JournalFile *f) {
        assert(f);

        if (memcmp(f->header, signature, 8))
                return -EBADMSG;

#ifdef HAVE_XZ
        if ((le64toh(f->header->incompatible_flags) & ~HEADER_INCOMPATIBLE_COMPRESSED) != 0)
                return -EPROTONOSUPPORT;
#else
        if (f->header->incompatible_flags != 0)
                return -EPROTONOSUPPORT;
#endif

        if (f->header->header_size != htole64(ALIGN64(sizeof(*(f->header)))))
                return -EBADMSG;

        if ((uint64_t) f->last_stat.st_size < (le64toh(f->header->header_size) + le64toh(f->header->arena_size)))
                return -ENODATA;

        if (f->writable) {
                uint8_t state;
                sd_id128_t machine_id;
                int r;

                r = sd_id128_get_machine(&machine_id);
                if (r < 0)
                        return r;

                if (!sd_id128_equal(machine_id, f->header->machine_id))
                        return -EHOSTDOWN;

                state = f->header->state;

                if (state == STATE_ONLINE)
                        log_debug("Journal file %s is already online. Assuming unclean closing. Ignoring.", f->path);
                        /* FIXME: immediately rotate */
                else if (state == STATE_ARCHIVED)
                        return -ESHUTDOWN;
                else if (state != STATE_OFFLINE)
                        log_debug("Journal file %s has unknown state %u. Ignoring.", f->path, state);
        }

        return 0;
}

static int journal_file_allocate(JournalFile *f, uint64_t offset, uint64_t size) {
        uint64_t old_size, new_size;
        int r;

        assert(f);

        /* We assume that this file is not sparse, and we know that
         * for sure, since we always call posix_fallocate()
         * ourselves */

        old_size =
                le64toh(f->header->header_size) +
                le64toh(f->header->arena_size);

        new_size = PAGE_ALIGN(offset + size);
        if (new_size < le64toh(f->header->header_size))
                new_size = le64toh(f->header->header_size);

        if (new_size <= old_size)
                return 0;

        if (f->metrics.max_size > 0 &&
            new_size > f->metrics.max_size)
                return -E2BIG;

        if (new_size > f->metrics.min_size &&
            f->metrics.keep_free > 0) {
                struct statvfs svfs;

                if (fstatvfs(f->fd, &svfs) >= 0) {
                        uint64_t available;

                        available = svfs.f_bfree * svfs.f_bsize;

                        if (available >= f->metrics.keep_free)
                                available -= f->metrics.keep_free;
                        else
                                available = 0;

                        if (new_size - old_size > available)
                                return -E2BIG;
                }
        }

        /* Note that the glibc fallocate() fallback is very
           inefficient, hence we try to minimize the allocation area
           as we can. */
        r = posix_fallocate(f->fd, old_size, new_size - old_size);
        if (r != 0)
                return -r;

        if (fstat(f->fd, &f->last_stat) < 0)
                return -errno;

        f->header->arena_size = htole64(new_size - le64toh(f->header->header_size));

        return 0;
}

static int journal_file_map(
                JournalFile *f,
                uint64_t offset,
                uint64_t size,
                void **_window,
                uint64_t *_woffset,
                uint64_t *_wsize,
                void **ret) {

        uint64_t woffset, wsize;
        void *window;

        assert(f);
        assert(size > 0);
        assert(ret);

        woffset = offset & ~((uint64_t) page_size() - 1ULL);
        wsize = size + (offset - woffset);
        wsize = PAGE_ALIGN(wsize);

        /* Avoid SIGBUS on invalid accesses */
        if (woffset + wsize > (uint64_t) PAGE_ALIGN(f->last_stat.st_size))
                return -EADDRNOTAVAIL;

        window = mmap(NULL, wsize, f->prot, MAP_SHARED, f->fd, woffset);
        if (window == MAP_FAILED)
                return -errno;

        if (_window)
                *_window = window;

        if (_woffset)
                *_woffset = woffset;

        if (_wsize)
                *_wsize = wsize;

        *ret = (uint8_t*) window + (offset - woffset);

        return 0;
}

static int journal_file_move_to(JournalFile *f, int wt, uint64_t offset, uint64_t size, void **ret) {
        void *p = NULL;
        uint64_t delta;
        int r;
        Window *w;

        assert(f);
        assert(ret);
        assert(wt >= 0);
        assert(wt < _WINDOW_MAX);

        if (offset + size > (uint64_t) f->last_stat.st_size) {
                /* Hmm, out of range? Let's refresh the fstat() data
                 * first, before we trust that check. */

                if (fstat(f->fd, &f->last_stat) < 0 ||
                    offset + size > (uint64_t) f->last_stat.st_size)
                        return -EADDRNOTAVAIL;
        }

        w = f->windows + wt;

        if (_likely_(w->ptr &&
                     w->offset <= offset &&
                     w->offset + w->size >= offset + size)) {

                *ret = (uint8_t*) w->ptr + (offset - w->offset);
                return 0;
        }

        if (w->ptr) {
                if (munmap(w->ptr, w->size) < 0)
                        return -errno;

                w->ptr = NULL;
                w->size = w->offset = 0;
        }

        if (size < DEFAULT_WINDOW_SIZE) {
                /* If the default window size is larger then what was
                 * asked for extend the mapping a bit in the hope to
                 * minimize needed remappings later on. We add half
                 * the window space before and half behind the
                 * requested mapping */

                delta = (DEFAULT_WINDOW_SIZE - size) / 2;

                if (delta > offset)
                        delta = offset;

                offset -= delta;
                size = DEFAULT_WINDOW_SIZE;
        } else
                delta = 0;

        if (offset + size > (uint64_t) f->last_stat.st_size)
                size = (uint64_t) f->last_stat.st_size - offset;

        if (size <= 0)
                return -EADDRNOTAVAIL;

        r = journal_file_map(f,
                             offset, size,
                             &w->ptr, &w->offset, &w->size,
                             &p);

        if (r < 0)
                return r;

        *ret = (uint8_t*) p + delta;
        return 0;
}

static bool verify_hash(Object *o) {
        uint64_t h1, h2;

        assert(o);

        if (o->object.type == OBJECT_DATA && !(o->object.flags & OBJECT_COMPRESSED)) {
                h1 = le64toh(o->data.hash);
                h2 = hash64(o->data.payload, le64toh(o->object.size) - offsetof(Object, data.payload));
        } else if (o->object.type == OBJECT_FIELD) {
                h1 = le64toh(o->field.hash);
                h2 = hash64(o->field.payload, le64toh(o->object.size) - offsetof(Object, field.payload));
        } else
                return true;

        return h1 == h2;
}

int journal_file_move_to_object(JournalFile *f, int type, uint64_t offset, Object **ret) {
        int r;
        void *t;
        Object *o;
        uint64_t s;

        assert(f);
        assert(ret);
        assert(type < _OBJECT_TYPE_MAX);

        r = journal_file_move_to(f, type >= 0 ? type : WINDOW_UNKNOWN, offset, sizeof(ObjectHeader), &t);
        if (r < 0)
                return r;

        o = (Object*) t;
        s = le64toh(o->object.size);

        if (s < sizeof(ObjectHeader))
                return -EBADMSG;

        if (type >= 0 && o->object.type != type)
                return -EBADMSG;

        if (s > sizeof(ObjectHeader)) {
                r = journal_file_move_to(f, o->object.type, offset, s, &t);
                if (r < 0)
                        return r;

                o = (Object*) t;
        }

        if (!verify_hash(o))
                return -EBADMSG;

        *ret = o;
        return 0;
}

static uint64_t journal_file_seqnum(JournalFile *f, uint64_t *seqnum) {
        uint64_t r;

        assert(f);

        r = le64toh(f->header->seqnum) + 1;

        if (seqnum) {
                /* If an external seqnum counter was passed, we update
                 * both the local and the external one, and set it to
                 * the maximum of both */

                if (*seqnum + 1 > r)
                        r = *seqnum + 1;

                *seqnum = r;
        }

        f->header->seqnum = htole64(r);

        if (f->header->first_seqnum == 0)
                f->header->first_seqnum = htole64(r);

        return r;
}

static int journal_file_append_object(JournalFile *f, int type, uint64_t size, Object **ret, uint64_t *offset) {
        int r;
        uint64_t p;
        Object *tail, *o;
        void *t;

        assert(f);
        assert(size >= sizeof(ObjectHeader));
        assert(offset);
        assert(ret);

        p = le64toh(f->header->tail_object_offset);
        if (p == 0)
                p = le64toh(f->header->header_size);
        else {
                r = journal_file_move_to_object(f, -1, p, &tail);
                if (r < 0)
                        return r;

                p += ALIGN64(le64toh(tail->object.size));
        }

        r = journal_file_allocate(f, p, size);
        if (r < 0)
                return r;

        r = journal_file_move_to(f, type, p, size, &t);
        if (r < 0)
                return r;

        o = (Object*) t;

        zero(o->object);
        o->object.type = type;
        o->object.size = htole64(size);

        f->header->tail_object_offset = htole64(p);
        f->header->n_objects = htole64(le64toh(f->header->n_objects) + 1);

        *ret = o;
        *offset = p;

        return 0;
}

static int journal_file_setup_data_hash_table(JournalFile *f) {
        uint64_t s, p;
        Object *o;
        int r;

        assert(f);

        s = DEFAULT_DATA_HASH_TABLE_SIZE;
        r = journal_file_append_object(f,
                                       OBJECT_DATA_HASH_TABLE,
                                       offsetof(Object, hash_table.items) + s,
                                       &o, &p);
        if (r < 0)
                return r;

        memset(o->hash_table.items, 0, s);

        f->header->data_hash_table_offset = htole64(p + offsetof(Object, hash_table.items));
        f->header->data_hash_table_size = htole64(s);

        return 0;
}

static int journal_file_setup_field_hash_table(JournalFile *f) {
        uint64_t s, p;
        Object *o;
        int r;

        assert(f);

        s = DEFAULT_FIELD_HASH_TABLE_SIZE;
        r = journal_file_append_object(f,
                                       OBJECT_FIELD_HASH_TABLE,
                                       offsetof(Object, hash_table.items) + s,
                                       &o, &p);
        if (r < 0)
                return r;

        memset(o->hash_table.items, 0, s);

        f->header->field_hash_table_offset = htole64(p + offsetof(Object, hash_table.items));
        f->header->field_hash_table_size = htole64(s);

        return 0;
}

static int journal_file_map_data_hash_table(JournalFile *f) {
        uint64_t s, p;
        void *t;
        int r;

        assert(f);

        p = le64toh(f->header->data_hash_table_offset);
        s = le64toh(f->header->data_hash_table_size);

        r = journal_file_move_to(f,
                                 WINDOW_DATA_HASH_TABLE,
                                 p, s,
                                 &t);
        if (r < 0)
                return r;

        f->data_hash_table = t;
        return 0;
}

static int journal_file_map_field_hash_table(JournalFile *f) {
        uint64_t s, p;
        void *t;
        int r;

        assert(f);

        p = le64toh(f->header->field_hash_table_offset);
        s = le64toh(f->header->field_hash_table_size);

        r = journal_file_move_to(f,
                                 WINDOW_FIELD_HASH_TABLE,
                                 p, s,
                                 &t);
        if (r < 0)
                return r;

        f->field_hash_table = t;
        return 0;
}

static int journal_file_link_data(JournalFile *f, Object *o, uint64_t offset, uint64_t hash) {
        uint64_t p, h;
        int r;

        assert(f);
        assert(o);
        assert(offset > 0);
        assert(o->object.type == OBJECT_DATA);

        /* This might alter the window we are looking at */

        o->data.next_hash_offset = o->data.next_field_offset = 0;
        o->data.entry_offset = o->data.entry_array_offset = 0;
        o->data.n_entries = 0;

        h = hash % (le64toh(f->header->data_hash_table_size) / sizeof(HashItem));
        p = le64toh(f->data_hash_table[h].tail_hash_offset);
        if (p == 0) {
                /* Only entry in the hash table is easy */
                f->data_hash_table[h].head_hash_offset = htole64(offset);
        } else {
                /* Move back to the previous data object, to patch in
                 * pointer */

                r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
                if (r < 0)
                        return r;

                o->data.next_hash_offset = htole64(offset);
        }

        f->data_hash_table[h].tail_hash_offset = htole64(offset);

        return 0;
}

int journal_file_find_data_object_with_hash(
                JournalFile *f,
                const void *data, uint64_t size, uint64_t hash,
                Object **ret, uint64_t *offset) {

        uint64_t p, osize, h;
        int r;

        assert(f);
        assert(data || size == 0);

        osize = offsetof(Object, data.payload) + size;

        if (f->header->data_hash_table_size == 0)
                return -EBADMSG;

        h = hash % (le64toh(f->header->data_hash_table_size) / sizeof(HashItem));
        p = le64toh(f->data_hash_table[h].head_hash_offset);

        while (p > 0) {
                Object *o;

                r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
                if (r < 0)
                        return r;

                if (le64toh(o->data.hash) != hash)
                        goto next;

                if (o->object.flags & OBJECT_COMPRESSED) {
#ifdef HAVE_XZ
                        uint64_t l, rsize;

                        l = le64toh(o->object.size);
                        if (l <= offsetof(Object, data.payload))
                                return -EBADMSG;

                        l -= offsetof(Object, data.payload);

                        if (!uncompress_blob(o->data.payload, l, &f->compress_buffer, &f->compress_buffer_size, &rsize))
                                return -EBADMSG;

                        if (rsize == size &&
                            memcmp(f->compress_buffer, data, size) == 0) {

                                if (ret)
                                        *ret = o;

                                if (offset)
                                        *offset = p;

                                return 1;
                        }
#else
                        return -EPROTONOSUPPORT;
#endif

                } else if (le64toh(o->object.size) == osize &&
                           memcmp(o->data.payload, data, size) == 0) {

                        if (ret)
                                *ret = o;

                        if (offset)
                                *offset = p;

                        return 1;
                }

        next:
                p = le64toh(o->data.next_hash_offset);
        }

        return 0;
}

int journal_file_find_data_object(
                JournalFile *f,
                const void *data, uint64_t size,
                Object **ret, uint64_t *offset) {

        uint64_t hash;

        assert(f);
        assert(data || size == 0);

        hash = hash64(data, size);

        return journal_file_find_data_object_with_hash(f,
                                                       data, size, hash,
                                                       ret, offset);
}

static int journal_file_append_data(
                JournalFile *f,
                const void *data, uint64_t size,
                Object **ret, uint64_t *offset) {

        uint64_t hash, p;
        uint64_t osize;
        Object *o;
        int r;
        bool compressed = false;

        assert(f);
        assert(data || size == 0);

        hash = hash64(data, size);

        r = journal_file_find_data_object_with_hash(f, data, size, hash, &o, &p);
        if (r < 0)
                return r;
        else if (r > 0) {

                if (ret)
                        *ret = o;

                if (offset)
                        *offset = p;

                return 0;
        }

        osize = offsetof(Object, data.payload) + size;
        r = journal_file_append_object(f, OBJECT_DATA, osize, &o, &p);
        if (r < 0)
                return r;

        o->data.hash = htole64(hash);

#ifdef HAVE_XZ
        if (f->compress &&
            size >= COMPRESSION_SIZE_THRESHOLD) {
                uint64_t rsize;

                compressed = compress_blob(data, size, o->data.payload, &rsize);

                if (compressed) {
                        o->object.size = htole64(offsetof(Object, data.payload) + rsize);
                        o->object.flags |= OBJECT_COMPRESSED;

                        f->header->incompatible_flags = htole32(le32toh(f->header->incompatible_flags) | HEADER_INCOMPATIBLE_COMPRESSED);

                        log_debug("Compressed data object %lu -> %lu", (unsigned long) size, (unsigned long) rsize);
                }
        }
#endif

        if (!compressed)
                memcpy(o->data.payload, data, size);

        r = journal_file_link_data(f, o, p, hash);
        if (r < 0)
                return r;

        /* The linking might have altered the window, so let's
         * refresh our pointer */
        r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
        if (r < 0)
                return r;

        if (ret)
                *ret = o;

        if (offset)
                *offset = p;

        return 0;
}

uint64_t journal_file_entry_n_items(Object *o) {
        assert(o);
        assert(o->object.type == OBJECT_ENTRY);

        return (le64toh(o->object.size) - offsetof(Object, entry.items)) / sizeof(EntryItem);
}

static uint64_t journal_file_entry_array_n_items(Object *o) {
        assert(o);
        assert(o->object.type == OBJECT_ENTRY_ARRAY);

        return (le64toh(o->object.size) - offsetof(Object, entry_array.items)) / sizeof(uint64_t);
}

static int link_entry_into_array(JournalFile *f,
                                 le64_t *first,
                                 le64_t *idx,
                                 uint64_t p) {
        int r;
        uint64_t n = 0, ap = 0, q, i, a, hidx;
        Object *o;

        assert(f);
        assert(first);
        assert(idx);
        assert(p > 0);

        a = le64toh(*first);
        i = hidx = le64toh(*idx);
        while (a > 0) {

                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o);
                if (r < 0)
                        return r;

                n = journal_file_entry_array_n_items(o);
                if (i < n) {
                        o->entry_array.items[i] = htole64(p);
                        *idx = htole64(hidx + 1);
                        return 0;
                }

                i -= n;
                ap = a;
                a = le64toh(o->entry_array.next_entry_array_offset);
        }

        if (hidx > n)
                n = (hidx+1) * 2;
        else
                n = n * 2;

        if (n < 4)
                n = 4;

        r = journal_file_append_object(f, OBJECT_ENTRY_ARRAY,
                                       offsetof(Object, entry_array.items) + n * sizeof(uint64_t),
                                       &o, &q);
        if (r < 0)
                return r;

        o->entry_array.items[i] = htole64(p);

        if (ap == 0)
                *first = htole64(q);
        else {
                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, ap, &o);
                if (r < 0)
                        return r;

                o->entry_array.next_entry_array_offset = htole64(q);
        }

        *idx = htole64(hidx + 1);

        return 0;
}

static int link_entry_into_array_plus_one(JournalFile *f,
                                          le64_t *extra,
                                          le64_t *first,
                                          le64_t *idx,
                                          uint64_t p) {

        int r;

        assert(f);
        assert(extra);
        assert(first);
        assert(idx);
        assert(p > 0);

        if (*idx == 0)
                *extra = htole64(p);
        else {
                le64_t i;

                i = htole64(le64toh(*idx) - 1);
                r = link_entry_into_array(f, first, &i, p);
                if (r < 0)
                        return r;
        }

        *idx = htole64(le64toh(*idx) + 1);
        return 0;
}

static int journal_file_link_entry_item(JournalFile *f, Object *o, uint64_t offset, uint64_t i) {
        uint64_t p;
        int r;
        assert(f);
        assert(o);
        assert(offset > 0);

        p = le64toh(o->entry.items[i].object_offset);
        if (p == 0)
                return -EINVAL;

        r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
        if (r < 0)
                return r;

        return link_entry_into_array_plus_one(f,
                                              &o->data.entry_offset,
                                              &o->data.entry_array_offset,
                                              &o->data.n_entries,
                                              offset);
}

static int journal_file_link_entry(JournalFile *f, Object *o, uint64_t offset) {
        uint64_t n, i;
        int r;

        assert(f);
        assert(o);
        assert(offset > 0);
        assert(o->object.type == OBJECT_ENTRY);

        __sync_synchronize();

        /* Link up the entry itself */
        r = link_entry_into_array(f,
                                  &f->header->entry_array_offset,
                                  &f->header->n_entries,
                                  offset);
        if (r < 0)
                return r;

        /* log_debug("=> %s seqnr=%lu n_entries=%lu", f->path, (unsigned long) o->entry.seqnum, (unsigned long) f->header->n_entries); */

        if (f->header->head_entry_realtime == 0)
                f->header->head_entry_realtime = o->entry.realtime;

        f->header->tail_entry_realtime = o->entry.realtime;
        f->header->tail_entry_monotonic = o->entry.monotonic;

        f->tail_entry_monotonic_valid = true;

        /* Link up the items */
        n = journal_file_entry_n_items(o);
        for (i = 0; i < n; i++) {
                r = journal_file_link_entry_item(f, o, offset, i);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int journal_file_append_entry_internal(
                JournalFile *f,
                const dual_timestamp *ts,
                uint64_t xor_hash,
                const EntryItem items[], unsigned n_items,
                uint64_t *seqnum,
                Object **ret, uint64_t *offset) {
        uint64_t np;
        uint64_t osize;
        Object *o;
        int r;

        assert(f);
        assert(items || n_items == 0);
        assert(ts);

        osize = offsetof(Object, entry.items) + (n_items * sizeof(EntryItem));

        r = journal_file_append_object(f, OBJECT_ENTRY, osize, &o, &np);
        if (r < 0)
                return r;

        o->entry.seqnum = htole64(journal_file_seqnum(f, seqnum));
        memcpy(o->entry.items, items, n_items * sizeof(EntryItem));
        o->entry.realtime = htole64(ts->realtime);
        o->entry.monotonic = htole64(ts->monotonic);
        o->entry.xor_hash = htole64(xor_hash);
        o->entry.boot_id = f->header->boot_id;

        r = journal_file_link_entry(f, o, np);
        if (r < 0)
                return r;

        if (ret)
                *ret = o;

        if (offset)
                *offset = np;

        return 0;
}

void journal_file_post_change(JournalFile *f) {
        assert(f);

        /* inotify() does not receive IN_MODIFY events from file
         * accesses done via mmap(). After each access we hence
         * trigger IN_MODIFY by truncating the journal file to its
         * current size which triggers IN_MODIFY. */

        __sync_synchronize();

        if (ftruncate(f->fd, f->last_stat.st_size) < 0)
                log_error("Failed to to truncate file to its own size: %m");
}

int journal_file_append_entry(JournalFile *f, const dual_timestamp *ts, const struct iovec iovec[], unsigned n_iovec, uint64_t *seqnum, Object **ret, uint64_t *offset) {
        unsigned i;
        EntryItem *items;
        int r;
        uint64_t xor_hash = 0;
        struct dual_timestamp _ts;

        assert(f);
        assert(iovec || n_iovec == 0);

        if (!f->writable)
                return -EPERM;

        if (!ts) {
                dual_timestamp_get(&_ts);
                ts = &_ts;
        }

        if (f->tail_entry_monotonic_valid &&
            ts->monotonic < le64toh(f->header->tail_entry_monotonic))
                return -EINVAL;

        items = alloca(sizeof(EntryItem) * n_iovec);

        for (i = 0; i < n_iovec; i++) {
                uint64_t p;
                Object *o;

                r = journal_file_append_data(f, iovec[i].iov_base, iovec[i].iov_len, &o, &p);
                if (r < 0)
                        return r;

                xor_hash ^= le64toh(o->data.hash);
                items[i].object_offset = htole64(p);
                items[i].hash = o->data.hash;
        }

        r = journal_file_append_entry_internal(f, ts, xor_hash, items, n_iovec, seqnum, ret, offset);

        journal_file_post_change(f);

        return r;
}

static int generic_array_get(JournalFile *f,
                             uint64_t first,
                             uint64_t i,
                             Object **ret, uint64_t *offset) {

        Object *o;
        uint64_t p = 0, a;
        int r;

        assert(f);

        a = first;
        while (a > 0) {
                uint64_t n;

                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o);
                if (r < 0)
                        return r;

                n = journal_file_entry_array_n_items(o);
                if (i < n) {
                        p = le64toh(o->entry_array.items[i]);
                        break;
                }

                i -= n;
                a = le64toh(o->entry_array.next_entry_array_offset);
        }

        if (a <= 0 || p <= 0)
                return 0;

        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, &o);
        if (r < 0)
                return r;

        if (ret)
                *ret = o;

        if (offset)
                *offset = p;

        return 1;
}

static int generic_array_get_plus_one(JournalFile *f,
                                      uint64_t extra,
                                      uint64_t first,
                                      uint64_t i,
                                      Object **ret, uint64_t *offset) {

        Object *o;

        assert(f);

        if (i == 0) {
                int r;

                r = journal_file_move_to_object(f, OBJECT_ENTRY, extra, &o);
                if (r < 0)
                        return r;

                if (ret)
                        *ret = o;

                if (offset)
                        *offset = extra;

                return 1;
        }

        return generic_array_get(f, first, i-1, ret, offset);
}

enum {
        TEST_FOUND,
        TEST_LEFT,
        TEST_RIGHT
};

static int generic_array_bisect(JournalFile *f,
                                uint64_t first,
                                uint64_t n,
                                uint64_t needle,
                                int (*test_object)(JournalFile *f, uint64_t p, uint64_t needle),
                                direction_t direction,
                                Object **ret,
                                uint64_t *offset,
                                uint64_t *idx) {

        uint64_t a, p, t = 0, i = 0, last_p = 0;
        bool subtract_one = false;
        Object *o, *array = NULL;
        int r;

        assert(f);
        assert(test_object);

        a = first;
        while (a > 0) {
                uint64_t left, right, k, lp;

                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &array);
                if (r < 0)
                        return r;

                k = journal_file_entry_array_n_items(array);
                right = MIN(k, n);
                if (right <= 0)
                        return 0;

                i = right - 1;
                lp = p = le64toh(array->entry_array.items[i]);
                if (p <= 0)
                        return -EBADMSG;

                r = test_object(f, p, needle);
                if (r < 0)
                        return r;

                if (r == TEST_FOUND)
                        r = direction == DIRECTION_DOWN ? TEST_RIGHT : TEST_LEFT;

                if (r == TEST_RIGHT) {
                        left = 0;
                        right -= 1;
                        for (;;) {
                                if (left == right) {
                                        if (direction == DIRECTION_UP)
                                                subtract_one = true;

                                        i = left;
                                        goto found;
                                }

                                assert(left < right);

                                i = (left + right) / 2;
                                p = le64toh(array->entry_array.items[i]);
                                if (p <= 0)
                                        return -EBADMSG;

                                r = test_object(f, p, needle);
                                if (r < 0)
                                        return r;

                                if (r == TEST_FOUND)
                                        r = direction == DIRECTION_DOWN ? TEST_RIGHT : TEST_LEFT;

                                if (r == TEST_RIGHT)
                                        right = i;
                                else
                                        left = i + 1;
                        }
                }

                if (k > n)
                        return 0;

                last_p = lp;

                n -= k;
                t += k;
                a = le64toh(array->entry_array.next_entry_array_offset);
        }

        return 0;

found:
        if (subtract_one && t == 0 && i == 0)
                return 0;

        if (subtract_one && i == 0)
                p = last_p;
        else if (subtract_one)
                p = le64toh(array->entry_array.items[i-1]);
        else
                p = le64toh(array->entry_array.items[i]);

        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, &o);
        if (r < 0)
                return r;

        if (ret)
                *ret = o;

        if (offset)
                *offset = p;

        if (idx)
                *idx = t + i - (subtract_one ? 1 : 0);

        return 1;
}

static int generic_array_bisect_plus_one(JournalFile *f,
                                         uint64_t extra,
                                         uint64_t first,
                                         uint64_t n,
                                         uint64_t needle,
                                         int (*test_object)(JournalFile *f, uint64_t p, uint64_t needle),
                                         direction_t direction,
                                         Object **ret,
                                         uint64_t *offset,
                                         uint64_t *idx) {

        int r;

        assert(f);
        assert(test_object);

        if (n <= 0)
                return 0;

        /* This bisects the array in object 'first', but first checks
         * an extra  */
        r = test_object(f, extra, needle);
        if (r < 0)
                return r;
        else if (r == TEST_FOUND) {
                Object *o;

                r = journal_file_move_to_object(f, OBJECT_ENTRY, extra, &o);
                if (r < 0)
                        return r;

                if (ret)
                        *ret = o;

                if (offset)
                        *offset = extra;

                if (idx)
                        *idx = 0;

                return 1;
        } else if (r == TEST_RIGHT)
                return 0;

        r = generic_array_bisect(f, first, n-1, needle, test_object, direction, ret, offset, idx);

        if (r > 0)
                (*idx) ++;

        return r;
}

static int test_object_seqnum(JournalFile *f, uint64_t p, uint64_t needle) {
        Object *o;
        int r;

        assert(f);
        assert(p > 0);

        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, &o);
        if (r < 0)
                return r;

        if (le64toh(o->entry.seqnum) == needle)
                return TEST_FOUND;
        else if (le64toh(o->entry.seqnum) < needle)
                return TEST_LEFT;
        else
                return TEST_RIGHT;
}

int journal_file_move_to_entry_by_seqnum(
                JournalFile *f,
                uint64_t seqnum,
                direction_t direction,
                Object **ret,
                uint64_t *offset) {

        return generic_array_bisect(f,
                                    le64toh(f->header->entry_array_offset),
                                    le64toh(f->header->n_entries),
                                    seqnum,
                                    test_object_seqnum,
                                    direction,
                                    ret, offset, NULL);
}

static int test_object_realtime(JournalFile *f, uint64_t p, uint64_t needle) {
        Object *o;
        int r;

        assert(f);
        assert(p > 0);

        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, &o);
        if (r < 0)
                return r;

        if (le64toh(o->entry.realtime) == needle)
                return TEST_FOUND;
        else if (le64toh(o->entry.realtime) < needle)
                return TEST_LEFT;
        else
                return TEST_RIGHT;
}

int journal_file_move_to_entry_by_realtime(
                JournalFile *f,
                uint64_t realtime,
                direction_t direction,
                Object **ret,
                uint64_t *offset) {

        return generic_array_bisect(f,
                                    le64toh(f->header->entry_array_offset),
                                    le64toh(f->header->n_entries),
                                    realtime,
                                    test_object_realtime,
                                    direction,
                                    ret, offset, NULL);
}

static int test_object_monotonic(JournalFile *f, uint64_t p, uint64_t needle) {
        Object *o;
        int r;

        assert(f);
        assert(p > 0);

        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, &o);
        if (r < 0)
                return r;

        if (le64toh(o->entry.monotonic) == needle)
                return TEST_FOUND;
        else if (le64toh(o->entry.monotonic) < needle)
                return TEST_LEFT;
        else
                return TEST_RIGHT;
}

int journal_file_move_to_entry_by_monotonic(
                JournalFile *f,
                sd_id128_t boot_id,
                uint64_t monotonic,
                direction_t direction,
                Object **ret,
                uint64_t *offset) {

        char t[8+32+1] = "_BOOT_ID=";
        Object *o;
        int r;

        sd_id128_to_string(boot_id, t + 8);

        r = journal_file_find_data_object(f, t, strlen(t), &o, NULL);
        if (r < 0)
                return r;
        else if (r == 0)
                return -ENOENT;

        return generic_array_bisect_plus_one(f,
                                             le64toh(o->data.entry_offset),
                                             le64toh(o->data.entry_array_offset),
                                             le64toh(o->data.n_entries),
                                             monotonic,
                                             test_object_monotonic,
                                             direction,
                                             ret, offset, NULL);
}

static int test_object_offset(JournalFile *f, uint64_t p, uint64_t needle) {
        assert(f);
        assert(p > 0);

        if (p == needle)
                return TEST_FOUND;
        else if (p < needle)
                return TEST_LEFT;
        else
                return TEST_RIGHT;
}

int journal_file_next_entry(
                JournalFile *f,
                Object *o, uint64_t p,
                direction_t direction,
                Object **ret, uint64_t *offset) {

        uint64_t i, n;
        int r;

        assert(f);
        assert(p > 0 || !o);

        n = le64toh(f->header->n_entries);
        if (n <= 0)
                return 0;

        if (!o)
                i = direction == DIRECTION_DOWN ? 0 : n - 1;
        else {
                if (o->object.type != OBJECT_ENTRY)
                        return -EINVAL;

                r = generic_array_bisect(f,
                                         le64toh(f->header->entry_array_offset),
                                         le64toh(f->header->n_entries),
                                         p,
                                         test_object_offset,
                                         DIRECTION_DOWN,
                                         NULL, NULL,
                                         &i);
                if (r <= 0)
                        return r;

                if (direction == DIRECTION_DOWN) {
                        if (i >= n - 1)
                                return 0;

                        i++;
                } else {
                        if (i <= 0)
                                return 0;

                        i--;
                }
        }

        /* And jump to it */
        return generic_array_get(f,
                                 le64toh(f->header->entry_array_offset),
                                 i,
                                 ret, offset);
}

int journal_file_skip_entry(
                JournalFile *f,
                Object *o, uint64_t p,
                int64_t skip,
                Object **ret, uint64_t *offset) {

        uint64_t i, n;
        int r;

        assert(f);
        assert(o);
        assert(p > 0);

        if (o->object.type != OBJECT_ENTRY)
                return -EINVAL;

        r = generic_array_bisect(f,
                                 le64toh(f->header->entry_array_offset),
                                 le64toh(f->header->n_entries),
                                 p,
                                 test_object_offset,
                                 DIRECTION_DOWN,
                                 NULL, NULL,
                                 &i);
        if (r <= 0)
                return r;

        /* Calculate new index */
        if (skip < 0) {
                if ((uint64_t) -skip >= i)
                        i = 0;
                else
                        i = i - (uint64_t) -skip;
        } else
                i  += (uint64_t) skip;

        n = le64toh(f->header->n_entries);
        if (n <= 0)
                return -EBADMSG;

        if (i >= n)
                i = n-1;

        return generic_array_get(f,
                                 le64toh(f->header->entry_array_offset),
                                 i,
                                 ret, offset);
}

int journal_file_next_entry_for_data(
                JournalFile *f,
                Object *o, uint64_t p,
                uint64_t data_offset,
                direction_t direction,
                Object **ret, uint64_t *offset) {

        uint64_t n, i;
        int r;
        Object *d;

        assert(f);
        assert(p > 0 || !o);

        r = journal_file_move_to_object(f, OBJECT_DATA, data_offset, &d);
        if (r < 0)
                return r;

        n = le64toh(d->data.n_entries);
        if (n <= 0)
                return n;

        if (!o)
                i = direction == DIRECTION_DOWN ? 0 : n - 1;
        else {
                if (o->object.type != OBJECT_ENTRY)
                        return -EINVAL;

                r = generic_array_bisect_plus_one(f,
                                                  le64toh(d->data.entry_offset),
                                                  le64toh(d->data.entry_array_offset),
                                                  le64toh(d->data.n_entries),
                                                  p,
                                                  test_object_offset,
                                                  DIRECTION_DOWN,
                                                  NULL, NULL,
                                                  &i);

                if (r <= 0)
                        return r;

                if (direction == DIRECTION_DOWN) {
                        if (i >= n - 1)
                                return 0;

                        i++;
                } else {
                        if (i <= 0)
                                return 0;

                        i--;
                }

        }

        return generic_array_get_plus_one(f,
                                          le64toh(d->data.entry_offset),
                                          le64toh(d->data.entry_array_offset),
                                          i,
                                          ret, offset);
}

int journal_file_move_to_entry_by_seqnum_for_data(
                JournalFile *f,
                uint64_t data_offset,
                uint64_t seqnum,
                direction_t direction,
                Object **ret, uint64_t *offset) {

        Object *d;
        int r;

        r = journal_file_move_to_object(f, OBJECT_DATA, data_offset, &d);
        if (r <= 0)
                return r;

        return generic_array_bisect_plus_one(f,
                                             le64toh(d->data.entry_offset),
                                             le64toh(d->data.entry_array_offset),
                                             le64toh(d->data.n_entries),
                                             seqnum,
                                             test_object_seqnum,
                                             direction,
                                             ret, offset, NULL);
}

int journal_file_move_to_entry_by_realtime_for_data(
                JournalFile *f,
                uint64_t data_offset,
                uint64_t realtime,
                direction_t direction,
                Object **ret, uint64_t *offset) {

        Object *d;
        int r;

        r = journal_file_move_to_object(f, OBJECT_DATA, data_offset, &d);
        if (r <= 0)
                return r;

        return generic_array_bisect_plus_one(f,
                                             le64toh(d->data.entry_offset),
                                             le64toh(d->data.entry_array_offset),
                                             le64toh(d->data.n_entries),
                                             realtime,
                                             test_object_realtime,
                                             direction,
                                             ret, offset, NULL);
}

void journal_file_dump(JournalFile *f) {
        char a[33], b[33], c[33];
        Object *o;
        int r;
        uint64_t p;

        assert(f);

        printf("File Path: %s\n"
               "File ID: %s\n"
               "Machine ID: %s\n"
               "Boot ID: %s\n"
               "Arena size: %llu\n"
               "Objects: %lu\n"
               "Entries: %lu\n",
               f->path,
               sd_id128_to_string(f->header->file_id, a),
               sd_id128_to_string(f->header->machine_id, b),
               sd_id128_to_string(f->header->boot_id, c),
               (unsigned long long) le64toh(f->header->arena_size),
               (unsigned long) le64toh(f->header->n_objects),
               (unsigned long) le64toh(f->header->n_entries));

        p = le64toh(f->header->header_size);
        while (p != 0) {
                r = journal_file_move_to_object(f, -1, p, &o);
                if (r < 0)
                        goto fail;

                switch (o->object.type) {

                case OBJECT_UNUSED:
                        printf("Type: OBJECT_UNUSED\n");
                        break;

                case OBJECT_DATA:
                        printf("Type: OBJECT_DATA\n");
                        break;

                case OBJECT_ENTRY:
                        printf("Type: OBJECT_ENTRY %llu %llu %llu\n",
                               (unsigned long long) le64toh(o->entry.seqnum),
                               (unsigned long long) le64toh(o->entry.monotonic),
                               (unsigned long long) le64toh(o->entry.realtime));
                        break;

                case OBJECT_FIELD_HASH_TABLE:
                        printf("Type: OBJECT_FIELD_HASH_TABLE\n");
                        break;

                case OBJECT_DATA_HASH_TABLE:
                        printf("Type: OBJECT_DATA_HASH_TABLE\n");
                        break;

                case OBJECT_ENTRY_ARRAY:
                        printf("Type: OBJECT_ENTRY_ARRAY\n");
                        break;

                case OBJECT_SIGNATURE:
                        printf("Type: OBJECT_SIGNATURE\n");
                        break;
                }

                if (o->object.flags & OBJECT_COMPRESSED)
                        printf("Flags: COMPRESSED\n");

                if (p == le64toh(f->header->tail_object_offset))
                        p = 0;
                else
                        p = p + ALIGN64(le64toh(o->object.size));
        }

        return;
fail:
        log_error("File corrupt");
}

int journal_file_open(
                const char *fname,
                int flags,
                mode_t mode,
                JournalFile *template,
                JournalFile **ret) {

        JournalFile *f;
        int r;
        bool newly_created = false;

        assert(fname);

        if ((flags & O_ACCMODE) != O_RDONLY &&
            (flags & O_ACCMODE) != O_RDWR)
                return -EINVAL;

        if (!endswith(fname, ".journal"))
                return -EINVAL;

        f = new0(JournalFile, 1);
        if (!f)
                return -ENOMEM;

        f->fd = -1;
        f->flags = flags;
        f->mode = mode;
        f->writable = (flags & O_ACCMODE) != O_RDONLY;
        f->prot = prot_from_flags(flags);

        if (template) {
                f->metrics = template->metrics;
                f->compress = template->compress;
        }

        f->path = strdup(fname);
        if (!f->path) {
                r = -ENOMEM;
                goto fail;
        }

        f->fd = open(f->path, f->flags|O_CLOEXEC, f->mode);
        if (f->fd < 0) {
                r = -errno;
                goto fail;
        }

        if (fstat(f->fd, &f->last_stat) < 0) {
                r = -errno;
                goto fail;
        }

        if (f->last_stat.st_size == 0 && f->writable) {
                newly_created = true;

                r = journal_file_init_header(f, template);
                if (r < 0)
                        goto fail;

                if (fstat(f->fd, &f->last_stat) < 0) {
                        r = -errno;
                        goto fail;
                }
        }

        if (f->last_stat.st_size < (off_t) sizeof(Header)) {
                r = -EIO;
                goto fail;
        }

        f->header = mmap(NULL, PAGE_ALIGN(sizeof(Header)), prot_from_flags(flags), MAP_SHARED, f->fd, 0);
        if (f->header == MAP_FAILED) {
                f->header = NULL;
                r = -errno;
                goto fail;
        }

        if (!newly_created) {
                r = journal_file_verify_header(f);
                if (r < 0)
                        goto fail;
        }

        if (f->writable) {
                r = journal_file_refresh_header(f);
                if (r < 0)
                        goto fail;
        }

        if (newly_created) {

                r = journal_file_setup_field_hash_table(f);
                if (r < 0)
                        goto fail;

                r = journal_file_setup_data_hash_table(f);
                if (r < 0)
                        goto fail;
        }

        r = journal_file_map_field_hash_table(f);
        if (r < 0)
                goto fail;

        r = journal_file_map_data_hash_table(f);
        if (r < 0)
                goto fail;

        if (ret)
                *ret = f;

        return 0;

fail:
        journal_file_close(f);

        return r;
}

int journal_file_rotate(JournalFile **f) {
        char *p;
        size_t l;
        JournalFile *old_file, *new_file = NULL;
        int r;

        assert(f);
        assert(*f);

        old_file = *f;

        if (!old_file->writable)
                return -EINVAL;

        if (!endswith(old_file->path, ".journal"))
                return -EINVAL;

        l = strlen(old_file->path);

        p = new(char, l + 1 + 32 + 1 + 16 + 1 + 16 + 1);
        if (!p)
                return -ENOMEM;

        memcpy(p, old_file->path, l - 8);
        p[l-8] = '@';
        sd_id128_to_string(old_file->header->seqnum_id, p + l - 8 + 1);
        snprintf(p + l - 8 + 1 + 32, 1 + 16 + 1 + 16 + 8 + 1,
                 "-%016llx-%016llx.journal",
                 (unsigned long long) le64toh((*f)->header->seqnum),
                 (unsigned long long) le64toh((*f)->header->tail_entry_realtime));

        r = rename(old_file->path, p);
        free(p);

        if (r < 0)
                return -errno;

        old_file->header->state = STATE_ARCHIVED;

        r = journal_file_open(old_file->path, old_file->flags, old_file->mode, old_file, &new_file);
        journal_file_close(old_file);

        *f = new_file;
        return r;
}

int journal_file_open_reliably(
                const char *fname,
                int flags,
                mode_t mode,
                JournalFile *template,
                JournalFile **ret) {

        int r;
        size_t l;
        char *p;

        r = journal_file_open(fname, flags, mode, template, ret);
        if (r != -EBADMSG && /* corrupted */
            r != -ENODATA && /* truncated */
            r != -EHOSTDOWN && /* other machine */
            r != -EPROTONOSUPPORT) /* incompatible feature */
                return r;

        if ((flags & O_ACCMODE) == O_RDONLY)
                return r;

        if (!(flags & O_CREAT))
                return r;

        /* The file is corrupted. Rotate it away and try it again (but only once) */

        l = strlen(fname);
        if (asprintf(&p, "%.*s@%016llx-%016llx.journal~",
                     (int) (l-8), fname,
                     (unsigned long long) now(CLOCK_REALTIME),
                     random_ull()) < 0)
                return -ENOMEM;

        r = rename(fname, p);
        free(p);
        if (r < 0)
                return -errno;

        log_warning("File %s corrupted, renaming and replacing.", fname);

        return journal_file_open(fname, flags, mode, template, ret);
}

struct vacuum_info {
        off_t usage;
        char *filename;

        uint64_t realtime;
        sd_id128_t seqnum_id;
        uint64_t seqnum;

        bool have_seqnum;
};

static int vacuum_compare(const void *_a, const void *_b) {
        const struct vacuum_info *a, *b;

        a = _a;
        b = _b;

        if (a->have_seqnum && b->have_seqnum &&
            sd_id128_equal(a->seqnum_id, b->seqnum_id)) {
                if (a->seqnum < b->seqnum)
                        return -1;
                else if (a->seqnum > b->seqnum)
                        return 1;
                else
                        return 0;
        }

        if (a->realtime < b->realtime)
                return -1;
        else if (a->realtime > b->realtime)
                return 1;
        else if (a->have_seqnum && b->have_seqnum)
                return memcmp(&a->seqnum_id, &b->seqnum_id, 16);
        else
                return strcmp(a->filename, b->filename);
}

int journal_directory_vacuum(const char *directory, uint64_t max_use, uint64_t min_free) {
        DIR *d;
        int r = 0;
        struct vacuum_info *list = NULL;
        unsigned n_list = 0, n_allocated = 0, i;
        uint64_t sum = 0;

        assert(directory);

        if (max_use <= 0)
                return 0;

        d = opendir(directory);
        if (!d)
                return -errno;

        for (;;) {
                int k;
                struct dirent buf, *de;
                size_t q;
                struct stat st;
                char *p;
                unsigned long long seqnum = 0, realtime;
                sd_id128_t seqnum_id;
                bool have_seqnum;

                k = readdir_r(d, &buf, &de);
                if (k != 0) {
                        r = -k;
                        goto finish;
                }

                if (!de)
                        break;

                if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                        continue;

                if (!S_ISREG(st.st_mode))
                        continue;

                q = strlen(de->d_name);

                if (endswith(de->d_name, ".journal")) {

                        /* Vacuum archived files */

                        if (q < 1 + 32 + 1 + 16 + 1 + 16 + 8)
                                continue;

                        if (de->d_name[q-8-16-1] != '-' ||
                            de->d_name[q-8-16-1-16-1] != '-' ||
                            de->d_name[q-8-16-1-16-1-32-1] != '@')
                                continue;

                        p = strdup(de->d_name);
                        if (!p) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        de->d_name[q-8-16-1-16-1] = 0;
                        if (sd_id128_from_string(de->d_name + q-8-16-1-16-1-32, &seqnum_id) < 0) {
                                free(p);
                                continue;
                        }

                        if (sscanf(de->d_name + q-8-16-1-16, "%16llx-%16llx.journal", &seqnum, &realtime) != 2) {
                                free(p);
                                continue;
                        }

                        have_seqnum = true;

                } else if (endswith(de->d_name, ".journal~")) {
                        unsigned long long tmp;

                        /* Vacuum corrupted files */

                        if (q < 1 + 16 + 1 + 16 + 8 + 1)
                                continue;

                        if (de->d_name[q-1-8-16-1] != '-' ||
                            de->d_name[q-1-8-16-1-16-1] != '@')
                                continue;

                        p = strdup(de->d_name);
                        if (!p) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        if (sscanf(de->d_name + q-1-8-16-1-16, "%16llx-%16llx.journal~", &realtime, &tmp) != 2) {
                                free(p);
                                continue;
                        }

                        have_seqnum = false;
                } else
                        continue;

                if (n_list >= n_allocated) {
                        struct vacuum_info *j;

                        n_allocated = MAX(n_allocated * 2U, 8U);
                        j = realloc(list, n_allocated * sizeof(struct vacuum_info));
                        if (!j) {
                                free(p);
                                r = -ENOMEM;
                                goto finish;
                        }

                        list = j;
                }

                list[n_list].filename = p;
                list[n_list].usage = 512UL * (uint64_t) st.st_blocks;
                list[n_list].seqnum = seqnum;
                list[n_list].realtime = realtime;
                list[n_list].seqnum_id = seqnum_id;
                list[n_list].have_seqnum = have_seqnum;

                sum += list[n_list].usage;

                n_list ++;
        }

        qsort(list, n_list, sizeof(struct vacuum_info), vacuum_compare);

        for(i = 0; i < n_list; i++) {
                struct statvfs ss;

                if (fstatvfs(dirfd(d), &ss) < 0) {
                        r = -errno;
                        goto finish;
                }

                if (sum <= max_use &&
                    (uint64_t) ss.f_bavail * (uint64_t) ss.f_bsize >= min_free)
                        break;

                if (unlinkat(dirfd(d), list[i].filename, 0) >= 0) {
                        log_info("Deleted archived journal %s/%s.", directory, list[i].filename);
                        sum -= list[i].usage;
                } else if (errno != ENOENT)
                        log_warning("Failed to delete %s/%s: %m", directory, list[i].filename);
        }

finish:
        for (i = 0; i < n_list; i++)
                free(list[i].filename);

        free(list);

        if (d)
                closedir(d);

        return r;
}

int journal_file_copy_entry(JournalFile *from, JournalFile *to, Object *o, uint64_t p, uint64_t *seqnum, Object **ret, uint64_t *offset) {
        uint64_t i, n;
        uint64_t q, xor_hash = 0;
        int r;
        EntryItem *items;
        dual_timestamp ts;

        assert(from);
        assert(to);
        assert(o);
        assert(p);

        if (!to->writable)
                return -EPERM;

        ts.monotonic = le64toh(o->entry.monotonic);
        ts.realtime = le64toh(o->entry.realtime);

        if (to->tail_entry_monotonic_valid &&
            ts.monotonic < le64toh(to->header->tail_entry_monotonic))
                return -EINVAL;

        if (ts.realtime < le64toh(to->header->tail_entry_realtime))
                return -EINVAL;

        n = journal_file_entry_n_items(o);
        items = alloca(sizeof(EntryItem) * n);

        for (i = 0; i < n; i++) {
                uint64_t l, h;
                le64_t le_hash;
                size_t t;
                void *data;
                Object *u;

                q = le64toh(o->entry.items[i].object_offset);
                le_hash = o->entry.items[i].hash;

                r = journal_file_move_to_object(from, OBJECT_DATA, q, &o);
                if (r < 0)
                        return r;

                if (le_hash != o->data.hash)
                        return -EBADMSG;

                l = le64toh(o->object.size) - offsetof(Object, data.payload);
                t = (size_t) l;

                /* We hit the limit on 32bit machines */
                if ((uint64_t) t != l)
                        return -E2BIG;

                if (o->object.flags & OBJECT_COMPRESSED) {
#ifdef HAVE_XZ
                        uint64_t rsize;

                        if (!uncompress_blob(o->data.payload, l, &from->compress_buffer, &from->compress_buffer_size, &rsize))
                                return -EBADMSG;

                        data = from->compress_buffer;
                        l = rsize;
#else
                        return -EPROTONOSUPPORT;
#endif
                } else
                        data = o->data.payload;

                r = journal_file_append_data(to, data, l, &u, &h);
                if (r < 0)
                        return r;

                xor_hash ^= le64toh(u->data.hash);
                items[i].object_offset = htole64(h);
                items[i].hash = u->data.hash;

                r = journal_file_move_to_object(from, OBJECT_ENTRY, p, &o);
                if (r < 0)
                        return r;
        }

        return journal_file_append_entry_internal(to, &ts, xor_hash, items, n, seqnum, ret, offset);
}

void journal_default_metrics(JournalMetrics *m, int fd) {
        uint64_t fs_size = 0;
        struct statvfs ss;
        char a[FORMAT_BYTES_MAX], b[FORMAT_BYTES_MAX], c[FORMAT_BYTES_MAX], d[FORMAT_BYTES_MAX];

        assert(m);
        assert(fd >= 0);

        if (fstatvfs(fd, &ss) >= 0)
                fs_size = ss.f_frsize * ss.f_blocks;

        if (m->max_use == (uint64_t) -1) {

                if (fs_size > 0) {
                        m->max_use = PAGE_ALIGN(fs_size / 10); /* 10% of file system size */

                        if (m->max_use > DEFAULT_MAX_USE_UPPER)
                                m->max_use = DEFAULT_MAX_USE_UPPER;

                        if (m->max_use < DEFAULT_MAX_USE_LOWER)
                                m->max_use = DEFAULT_MAX_USE_LOWER;
                } else
                        m->max_use = DEFAULT_MAX_USE_LOWER;
        } else {
                m->max_use = PAGE_ALIGN(m->max_use);

                if (m->max_use < JOURNAL_FILE_SIZE_MIN*2)
                        m->max_use = JOURNAL_FILE_SIZE_MIN*2;
        }

        if (m->max_size == (uint64_t) -1) {
                m->max_size = PAGE_ALIGN(m->max_use / 8); /* 8 chunks */

                if (m->max_size > DEFAULT_MAX_SIZE_UPPER)
                        m->max_size = DEFAULT_MAX_SIZE_UPPER;
        } else
                m->max_size = PAGE_ALIGN(m->max_size);

        if (m->max_size < JOURNAL_FILE_SIZE_MIN)
                m->max_size = JOURNAL_FILE_SIZE_MIN;

        if (m->max_size*2 > m->max_use)
                m->max_use = m->max_size*2;

        if (m->min_size == (uint64_t) -1)
                m->min_size = JOURNAL_FILE_SIZE_MIN;
        else {
                m->min_size = PAGE_ALIGN(m->min_size);

                if (m->min_size < JOURNAL_FILE_SIZE_MIN)
                        m->min_size = JOURNAL_FILE_SIZE_MIN;

                if (m->min_size > m->max_size)
                        m->max_size = m->min_size;
        }

        if (m->keep_free == (uint64_t) -1) {

                if (fs_size > 0) {
                        m->keep_free = PAGE_ALIGN(fs_size / 20); /* 5% of file system size */

                        if (m->keep_free > DEFAULT_KEEP_FREE_UPPER)
                                m->keep_free = DEFAULT_KEEP_FREE_UPPER;

                } else
                        m->keep_free = DEFAULT_KEEP_FREE;
        }

        log_info("Fixed max_use=%s max_size=%s min_size=%s keep_free=%s",
                 format_bytes(a, sizeof(a), m->max_use),
                 format_bytes(b, sizeof(b), m->max_size),
                 format_bytes(c, sizeof(c), m->min_size),
                 format_bytes(d, sizeof(d), m->keep_free));
}

int journal_file_get_cutoff_realtime_usec(JournalFile *f, usec_t *from, usec_t *to) {
        Object *o;
        int r;

        assert(f);
        assert(from || to);

        if (from) {
                r = journal_file_next_entry(f, NULL, 0, DIRECTION_DOWN, &o, NULL);
                if (r <= 0)
                        return r;

                *from = le64toh(o->entry.realtime);
        }

        if (to) {
                r = journal_file_next_entry(f, NULL, 0, DIRECTION_UP, &o, NULL);
                if (r <= 0)
                        return r;

                *to = le64toh(o->entry.realtime);
        }

        return 1;
}

int journal_file_get_cutoff_monotonic_usec(JournalFile *f, sd_id128_t boot_id, usec_t *from, usec_t *to) {
        char t[9+32+1] = "_BOOT_ID=";
        Object *o;
        uint64_t p;
        int r;

        assert(f);
        assert(from || to);

        sd_id128_to_string(boot_id, t + 9);

        r = journal_file_find_data_object(f, t, strlen(t), &o, &p);
        if (r <= 0)
                return r;

        if (le64toh(o->data.n_entries) <= 0)
                return 0;

        if (from) {
                r = journal_file_move_to_object(f, OBJECT_ENTRY, le64toh(o->data.entry_offset), &o);
                if (r < 0)
                        return r;

                *from = le64toh(o->entry.monotonic);
        }

        if (to) {
                r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
                if (r < 0)
                        return r;

                r = generic_array_get_plus_one(f,
                                               le64toh(o->data.entry_offset),
                                               le64toh(o->data.entry_array_offset),
                                               le64toh(o->data.n_entries)-1,
                                               &o, NULL);
                if (r <= 0)
                        return r;

                *to = le64toh(o->entry.monotonic);
        }

        return 1;
}
