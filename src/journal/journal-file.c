/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
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

#define DEFAULT_ARENA_MAX_SIZE (16ULL*1024ULL*1024ULL*1024ULL)
#define DEFAULT_ARENA_MIN_SIZE (256ULL*1024ULL)
#define DEFAULT_ARENA_KEEP_FREE (1ULL*1024ULL*1024ULL)

#define DEFAULT_MAX_USE (16ULL*1024ULL*1024ULL*16ULL)

#define DEFAULT_HASH_TABLE_SIZE (2047ULL*16ULL)
#define DEFAULT_BISECT_TABLE_SIZE ((DEFAULT_ARENA_MAX_SIZE/(64ULL*1024ULL))*8ULL)

#define DEFAULT_WINDOW_SIZE (128ULL*1024ULL*1024ULL)

static const char signature[] = { 'L', 'P', 'K', 'S', 'H', 'H', 'R', 'H' };

#define ALIGN64(x) (((x) + 7ULL) & ~7ULL)

void journal_file_close(JournalFile *f) {
        assert(f);

        if (f->header) {
                if (f->writable && f->header->state == htole32(STATE_ONLINE))
                        f->header->state = htole32(STATE_OFFLINE);

                munmap(f->header, PAGE_ALIGN(sizeof(Header)));
        }

        if (f->hash_table_window)
                munmap(f->hash_table_window, f->hash_table_window_size);

        if (f->bisect_table_window)
                munmap(f->bisect_table_window, f->bisect_table_window_size);

        if (f->window)
                munmap(f->window, f->window_size);

        if (f->fd >= 0)
                close_nointr_nofail(f->fd);

        free(f->path);
        free(f);
}

static int journal_file_init_header(JournalFile *f, JournalFile *template) {
        Header h;
        ssize_t k;
        int r;

        assert(f);

        zero(h);
        memcpy(h.signature, signature, 8);
        h.arena_offset = htole64(ALIGN64(sizeof(h)));
        h.arena_max_size = htole64(DEFAULT_ARENA_MAX_SIZE);
        h.arena_min_size = htole64(DEFAULT_ARENA_MIN_SIZE);
        h.arena_keep_free = htole64(DEFAULT_ARENA_KEEP_FREE);

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

        assert(f);

        r = sd_id128_get_machine(&f->header->machine_id);
        if (r < 0)
                return r;

        r = sd_id128_get_boot(&f->header->boot_id);
        if (r < 0)
                return r;

        f->header->state = htole32(STATE_ONLINE);
        return 0;
}

static int journal_file_verify_header(JournalFile *f) {
        assert(f);

        if (memcmp(f->header, signature, 8))
                return -EBADMSG;

        if (f->header->incompatible_flags != 0)
                return -EPROTONOSUPPORT;

        if ((uint64_t) f->last_stat.st_size < (le64toh(f->header->arena_offset) + le64toh(f->header->arena_size)))
                return -ENODATA;

        if (f->writable) {
                uint32_t state;
                sd_id128_t machine_id;
                int r;

                r = sd_id128_get_machine(&machine_id);
                if (r < 0)
                        return r;

                if (!sd_id128_equal(machine_id, f->header->machine_id))
                        return -EHOSTDOWN;

                state = le32toh(f->header->state);

                if (state == STATE_ONLINE)
                        log_debug("Journal file %s is already online. Assuming unclean closing. Ignoring.", f->path);
                else if (state == STATE_ARCHIVED)
                        return -ESHUTDOWN;
                else if (state != STATE_OFFLINE)
                        log_debug("Journal file %s has unknown state %u. Ignoring.", f->path, state);
        }

        return 0;
}

static int journal_file_allocate(JournalFile *f, uint64_t offset, uint64_t size) {
        uint64_t asize;
        uint64_t old_size, new_size;

        assert(f);

        if (offset < le64toh(f->header->arena_offset))
                return -EINVAL;

        new_size = PAGE_ALIGN(offset + size);

        /* We assume that this file is not sparse, and we know that
         * for sure, since we always call posix_fallocate()
         * ourselves */

        old_size =
                le64toh(f->header->arena_offset) +
                le64toh(f->header->arena_size);

        if (old_size >= new_size)
                return 0;

        asize = new_size - le64toh(f->header->arena_offset);

        if (asize > le64toh(f->header->arena_min_size)) {
                struct statvfs svfs;

                if (fstatvfs(f->fd, &svfs) >= 0) {
                        uint64_t available;

                        available = svfs.f_bfree * svfs.f_bsize;

                        if (available >= f->header->arena_keep_free)
                                available -= f->header->arena_keep_free;
                        else
                                available = 0;

                        if (new_size - old_size > available)
                                return -E2BIG;
                }
        }

        if (asize > le64toh(f->header->arena_max_size))
                return -E2BIG;

        if (posix_fallocate(f->fd, old_size, new_size - old_size) < 0)
                return -errno;

        if (fstat(f->fd, &f->last_stat) < 0)
                return -errno;

        f->header->arena_size = htole64(asize);

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

static int journal_file_move_to(JournalFile *f, uint64_t offset, uint64_t size, void **ret) {
        void *p;
        uint64_t delta;
        int r;

        assert(f);
        assert(ret);

        if (_likely_(f->window &&
                     f->window_offset <= offset &&
                     f->window_offset+f->window_size >= offset + size)) {

                *ret = (uint8_t*) f->window + (offset - f->window_offset);
                return 0;
        }

        if (f->window) {
                if (munmap(f->window, f->window_size) < 0)
                        return -errno;

                f->window = NULL;
                f->window_size = f->window_offset = 0;
        }

        if (size < DEFAULT_WINDOW_SIZE) {
                /* If the default window size is larger then what was
                 * asked for extend the mapping a bit in the hope to
                 * minimize needed remappings later on. We add half
                 * the window space before and half behind the
                 * requested mapping */

                delta = PAGE_ALIGN((DEFAULT_WINDOW_SIZE - size) / 2);

                if (offset < delta)
                        delta = offset;

                offset -= delta;
                size += (DEFAULT_WINDOW_SIZE - delta);
        } else
                delta = 0;

        r = journal_file_map(f,
                             offset, size,
                             &f->window, &f->window_offset, &f->window_size,
                             & p);

        if (r < 0)
                return r;

        *ret = (uint8_t*) p + delta;
        return 0;
}

static bool verify_hash(Object *o) {
        uint64_t t;

        assert(o);

        t = le64toh(o->object.type);
        if (t == OBJECT_DATA) {
                uint64_t s, h1, h2;

                s = le64toh(o->object.size);

                h1 = le64toh(o->data.hash);
                h2 = hash64(o->data.payload, s - offsetof(Object, data.payload));

                return h1 == h2;
        }

        return true;
}

int journal_file_move_to_object(JournalFile *f, uint64_t offset, int type, Object **ret) {
        int r;
        void *t;
        Object *o;
        uint64_t s;

        assert(f);
        assert(ret);

        r = journal_file_move_to(f, offset, sizeof(ObjectHeader), &t);
        if (r < 0)
                return r;

        o = (Object*) t;
        s = le64toh(o->object.size);

        if (s < sizeof(ObjectHeader))
                return -EBADMSG;

        if (type >= 0 && le64toh(o->object.type) != type)
                return -EBADMSG;

        if (s > sizeof(ObjectHeader)) {
                r = journal_file_move_to(f, offset, s, &t);
                if (r < 0)
                        return r;

                o = (Object*) t;
        }

        if (!verify_hash(o))
                return -EBADMSG;

        *ret = o;
        return 0;
}

static uint64_t journal_file_seqnum(JournalFile *f) {
        uint64_t r;

        assert(f);

        r = le64toh(f->header->seqnum) + 1;
        f->header->seqnum = htole64(r);

        return r;
}

static int journal_file_append_object(JournalFile *f, uint64_t size, Object **ret, uint64_t *offset) {
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
                p = le64toh(f->header->arena_offset);
        else {
                r = journal_file_move_to_object(f, p, -1, &tail);
                if (r < 0)
                        return r;

                p += ALIGN64(le64toh(tail->object.size));
        }

        r = journal_file_allocate(f, p, size);
        if (r < 0)
                return r;

        r = journal_file_move_to(f, p, size, &t);
        if (r < 0)
                return r;

        o = (Object*) t;

        zero(o->object);
        o->object.type = htole64(OBJECT_UNUSED);
        zero(o->object.reserved);
        o->object.size = htole64(size);

        f->header->tail_object_offset = htole64(p);
        if (f->header->head_object_offset == 0)
                f->header->head_object_offset = htole64(p);

        f->header->n_objects = htole64(le64toh(f->header->n_objects) + 1);

        *ret = o;
        *offset = p;

        return 0;
}

static int journal_file_setup_hash_table(JournalFile *f) {
        uint64_t s, p;
        Object *o;
        int r;

        assert(f);

        s = DEFAULT_HASH_TABLE_SIZE;
        r = journal_file_append_object(f, offsetof(Object, hash_table.table) + s, &o, &p);
        if (r < 0)
                return r;

        o->object.type = htole64(OBJECT_HASH_TABLE);
        memset(o->hash_table.table, 0, s);

        f->header->hash_table_offset = htole64(p + offsetof(Object, hash_table.table));
        f->header->hash_table_size = htole64(s);

        return 0;
}

static int journal_file_setup_bisect_table(JournalFile *f) {
        uint64_t s, p;
        Object *o;
        int r;

        assert(f);

        s = DEFAULT_BISECT_TABLE_SIZE;
        r = journal_file_append_object(f, offsetof(Object, bisect_table.table) + s, &o, &p);
        if (r < 0)
                return r;

        o->object.type = htole64(OBJECT_BISECT_TABLE);
        memset(o->bisect_table.table, 0, s);

        f->header->bisect_table_offset = htole64(p + offsetof(Object, bisect_table.table));
        f->header->bisect_table_size = htole64(s);

        return 0;
}

static int journal_file_map_hash_table(JournalFile *f) {
        uint64_t s, p;
        void *t;
        int r;

        assert(f);

        p = le64toh(f->header->hash_table_offset);
        s = le64toh(f->header->hash_table_size);

        r = journal_file_map(f,
                             p, s,
                             &f->hash_table_window, NULL, &f->hash_table_window_size,
                             &t);
        if (r < 0)
                return r;

        f->hash_table = t;
        return 0;
}

static int journal_file_map_bisect_table(JournalFile *f) {
        uint64_t s, p;
        void *t;
        int r;

        assert(f);

        p = le64toh(f->header->bisect_table_offset);
        s = le64toh(f->header->bisect_table_size);

        r = journal_file_map(f,
                             p, s,
                             &f->bisect_table_window, NULL, &f->bisect_table_window_size,
                             &t);

        if (r < 0)
                return r;

        f->bisect_table = t;
        return 0;
}

static int journal_file_link_data(JournalFile *f, Object *o, uint64_t offset, uint64_t hash_index) {
        uint64_t p;
        int r;

        assert(f);
        assert(o);
        assert(offset > 0);
        assert(o->object.type == htole64(OBJECT_DATA));

        o->data.head_entry_offset = o->data.tail_entry_offset = 0;
        o->data.next_hash_offset = 0;

        p = le64toh(f->hash_table[hash_index].tail_hash_offset);
        if (p == 0) {
                /* Only entry in the hash table is easy */

                o->data.prev_hash_offset = 0;
                f->hash_table[hash_index].head_hash_offset = htole64(offset);
        } else {
                o->data.prev_hash_offset = htole64(p);

                /* Temporarily move back to the previous data object,
                 * to patch in pointer */

                r = journal_file_move_to_object(f, p, OBJECT_DATA, &o);
                if (r < 0)
                        return r;

                o->data.next_hash_offset = offset;

                r = journal_file_move_to_object(f, offset, OBJECT_DATA, &o);
                if (r < 0)
                        return r;
        }

        f->hash_table[hash_index].tail_hash_offset = htole64(offset);

        return 0;
}

static int journal_file_append_data(JournalFile *f, const void *data, uint64_t size, Object **ret, uint64_t *offset) {
        uint64_t hash, h, p, np;
        uint64_t osize;
        Object *o;
        int r;

        assert(f);
        assert(data || size == 0);

        osize = offsetof(Object, data.payload) + size;

        hash = hash64(data, size);
        h = hash % (le64toh(f->header->hash_table_size) / sizeof(HashItem));
        p = le64toh(f->hash_table[h].head_hash_offset);

        while (p != 0) {
                /* Look for this data object in the hash table */

                r = journal_file_move_to_object(f, p, OBJECT_DATA, &o);
                if (r < 0)
                        return r;

                if (le64toh(o->object.size) == osize &&
                    memcmp(o->data.payload, data, size) == 0) {

                        if (le64toh(o->data.hash) != hash)
                                return -EBADMSG;

                        if (ret)
                                *ret = o;

                        if (offset)
                                *offset = p;

                        return 0;
                }

                p = le64toh(o->data.next_hash_offset);
        }

        r = journal_file_append_object(f, osize, &o, &np);
        if (r < 0)
                return r;

        o->object.type = htole64(OBJECT_DATA);
        o->data.hash = htole64(hash);
        memcpy(o->data.payload, data, size);

        r = journal_file_link_data(f, o, np, h);
        if (r < 0)
                return r;

        if (ret)
                *ret = o;

        if (offset)
                *offset = np;

        return 0;
}

uint64_t journal_file_entry_n_items(Object *o) {
        assert(o);
        assert(o->object.type == htole64(OBJECT_ENTRY));

        return (le64toh(o->object.size) - offsetof(Object, entry.items)) / sizeof(EntryItem);
}

static int journal_file_link_entry_item(JournalFile *f, Object *o, uint64_t offset, uint64_t i) {
        uint64_t p, q;
        int r;
        assert(f);
        assert(o);
        assert(offset > 0);

        p = le64toh(o->entry.items[i].object_offset);
        if (p == 0)
                return -EINVAL;

        o->entry.items[i].next_entry_offset = 0;

        /* Move to the data object */
        r = journal_file_move_to_object(f, p, OBJECT_DATA, &o);
        if (r < 0)
                return r;

        q = le64toh(o->data.tail_entry_offset);
        o->data.tail_entry_offset = htole64(offset);

        if (q == 0)
                o->data.head_entry_offset = htole64(offset);
        else {
                uint64_t n, j;

                /* Move to previous entry */
                r = journal_file_move_to_object(f, q, OBJECT_ENTRY, &o);
                if (r < 0)
                        return r;

                n = journal_file_entry_n_items(o);
                for (j = 0; j < n; j++)
                        if (le64toh(o->entry.items[j].object_offset) == p)
                                break;

                if (j >= n)
                        return -EBADMSG;

                o->entry.items[j].next_entry_offset = offset;
        }

        /* Move back to original entry */
        r = journal_file_move_to_object(f, offset, OBJECT_ENTRY, &o);
        if (r < 0)
                return r;

        o->entry.items[i].prev_entry_offset = q;
        return 0;
}

static int journal_file_link_entry(JournalFile *f, Object *o, uint64_t offset) {
        uint64_t p, i, n, k, a, b;
        int r;

        assert(f);
        assert(o);
        assert(offset > 0);
        assert(o->object.type == htole64(OBJECT_ENTRY));

        /* Link up the entry itself */
        p = le64toh(f->header->tail_entry_offset);

        o->entry.prev_entry_offset = f->header->tail_entry_offset;
        o->entry.next_entry_offset = 0;

        if (p == 0) {
                f->header->head_entry_offset = htole64(offset);
                f->header->head_entry_realtime = o->entry.realtime;
        } else {
                /* Temporarily move back to the previous entry, to
                 * patch in pointer */

                r = journal_file_move_to_object(f, p, OBJECT_ENTRY, &o);
                if (r < 0)
                        return r;

                o->entry.next_entry_offset = htole64(offset);

                r = journal_file_move_to_object(f, offset, OBJECT_ENTRY, &o);
                if (r < 0)
                        return r;
        }

        f->header->tail_entry_offset = htole64(offset);
        f->header->tail_entry_realtime = o->entry.realtime;

        /* Link up the items */
        n = journal_file_entry_n_items(o);
        for (i = 0; i < n; i++) {
                r = journal_file_link_entry_item(f, o, offset, i);
                if (r < 0)
                        return r;
        }

        /* Link up the entry in the bisect table */
        n = le64toh(f->header->bisect_table_size) / sizeof(uint64_t);
        k = le64toh(f->header->arena_max_size) / n;

        a = (le64toh(f->header->last_bisect_offset) + k - 1) / k;
        b = offset / k;

        for (; a <= b; a++)
                f->bisect_table[a] = htole64(offset);

        f->header->last_bisect_offset = htole64(offset + le64toh(o->object.size));

        return 0;
}

static int journal_file_append_entry_internal(
                JournalFile *f,
                const dual_timestamp *ts,
                uint64_t xor_hash,
                const EntryItem items[], unsigned n_items,
                Object **ret, uint64_t *offset) {
        uint64_t np;
        uint64_t osize;
        Object *o;
        int r;

        assert(f);
        assert(items || n_items == 0);

        osize = offsetof(Object, entry.items) + (n_items * sizeof(EntryItem));

        r = journal_file_append_object(f, osize, &o, &np);
        if (r < 0)
                return r;

        o->object.type = htole64(OBJECT_ENTRY);
        o->entry.seqnum = htole64(journal_file_seqnum(f));
        memcpy(o->entry.items, items, n_items * sizeof(EntryItem));
        o->entry.realtime = htole64(ts ? ts->realtime : now(CLOCK_REALTIME));
        o->entry.monotonic = htole64(ts ? ts->monotonic : now(CLOCK_MONOTONIC));
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

int journal_file_append_entry(JournalFile *f, const dual_timestamp *ts, const struct iovec iovec[], unsigned n_iovec, Object **ret, uint64_t *offset) {
        unsigned i;
        EntryItem *items;
        int r;
        uint64_t xor_hash = 0;

        assert(f);
        assert(iovec || n_iovec == 0);

        items = new(EntryItem, n_iovec);
        if (!items)
                return -ENOMEM;

        for (i = 0; i < n_iovec; i++) {
                uint64_t p;
                Object *o;

                r = journal_file_append_data(f, iovec[i].iov_base, iovec[i].iov_len, &o, &p);
                if (r < 0)
                        goto finish;

                xor_hash ^= le64toh(o->data.hash);
                items[i].object_offset = htole64(p);
        }

        r = journal_file_append_entry_internal(f, ts, xor_hash, items, n_iovec, ret, offset);

finish:
        free(items);

        return r;
}

int journal_file_move_to_entry(JournalFile *f, uint64_t seqnum, Object **ret, uint64_t *offset) {
        Object *o;
        uint64_t lower, upper, p, n, k;
        int r;

        assert(f);

        n = le64toh(f->header->bisect_table_size) / sizeof(uint64_t);
        k = le64toh(f->header->arena_max_size) / n;

        lower = 0;
        upper = le64toh(f->header->last_bisect_offset)/k+1;

        while (lower < upper) {
                k = (upper + lower) / 2;
                p = le64toh(f->bisect_table[k]);

                if (p == 0) {
                        upper = k;
                        continue;
                }

                r = journal_file_move_to_object(f, p, OBJECT_ENTRY, &o);
                if (r < 0)
                        return r;

                if (o->entry.seqnum == seqnum) {
                        if (ret)
                                *ret = o;

                        if (offset)
                                *offset = p;

                        return 1;
                } else if (seqnum < o->entry.seqnum)
                        upper = k;
                else if (seqnum > o->entry.seqnum)
                        lower = k+1;
        }

        assert(lower == upper);

        if (lower <= 0)
                return 0;

        /* The object we are looking for is between
         * bisect_table[lower-1] and bisect_table[lower] */

        p = le64toh(f->bisect_table[lower-1]);

        for (;;) {
                r = journal_file_move_to_object(f, p, OBJECT_ENTRY, &o);
                if (r < 0)
                        return r;

                if (o->entry.seqnum == seqnum) {
                        if (ret)
                                *ret = o;

                        if (offset)
                                *offset = p;

                        return 1;

                } if (seqnum < o->entry.seqnum)
                        return 0;

                if (o->entry.next_entry_offset == 0)
                        return 0;

                p = le64toh(o->entry.next_entry_offset);
        }

        return 0;
}

int journal_file_next_entry(JournalFile *f, Object *o, Object **ret, uint64_t *offset) {
        uint64_t np;
        int r;

        assert(f);

        if (!o)
                np = le64toh(f->header->head_entry_offset);
        else {
                if (le64toh(o->object.type) != OBJECT_ENTRY)
                        return -EINVAL;

                np = le64toh(o->entry.next_entry_offset);
        }

        if (np == 0)
                return 0;

        r = journal_file_move_to_object(f, np, OBJECT_ENTRY, &o);
        if (r < 0)
                return r;

        if (ret)
                *ret = o;

        if (offset)
                *offset = np;

        return 1;
}

int journal_file_prev_entry(JournalFile *f, Object *o, Object **ret, uint64_t *offset) {
        uint64_t np;
        int r;

        assert(f);

        if (!o)
                np = le64toh(f->header->tail_entry_offset);
        else {
                if (le64toh(o->object.type) != OBJECT_ENTRY)
                        return -EINVAL;

                np = le64toh(o->entry.prev_entry_offset);
        }

        if (np == 0)
                return 0;

        r = journal_file_move_to_object(f, np, OBJECT_ENTRY, &o);
        if (r < 0)
                return r;

        if (ret)
                *ret = o;

        if (offset)
                *offset = np;

        return 1;
}

int journal_file_find_first_entry(JournalFile *f, const void *data, uint64_t size, Object **ret, uint64_t *offset) {
        uint64_t p, osize, hash, h;
        int r;

        assert(f);
        assert(data || size == 0);

        osize = offsetof(Object, data.payload) + size;

        hash = hash64(data, size);
        h = hash % (le64toh(f->header->hash_table_size) / sizeof(HashItem));
        p = le64toh(f->hash_table[h].head_hash_offset);

        while (p != 0) {
                Object *o;

                r = journal_file_move_to_object(f, p, OBJECT_DATA, &o);
                if (r < 0)
                        return r;

                if (le64toh(o->object.size) == osize &&
                    memcmp(o->data.payload, data, size) == 0) {

                        if (le64toh(o->data.hash) != hash)
                                return -EBADMSG;

                        if (o->data.head_entry_offset == 0)
                                return 0;

                        p = le64toh(o->data.head_entry_offset);
                        r = journal_file_move_to_object(f, p, OBJECT_ENTRY, &o);
                        if (r < 0)
                                return r;

                        if (ret)
                                *ret = o;

                        if (offset)
                                *offset = p;

                        return 1;
                }

                p = le64toh(o->data.next_hash_offset);
        }

        return 0;
}

int journal_file_find_last_entry(JournalFile *f, const void *data, uint64_t size, Object **ret, uint64_t *offset) {
        uint64_t p, osize, hash, h;
        int r;

        assert(f);
        assert(data || size == 0);

        osize = offsetof(Object, data.payload) + size;

        hash = hash64(data, size);
        h = hash % (le64toh(f->header->hash_table_size) / sizeof(HashItem));
        p = le64toh(f->hash_table[h].tail_hash_offset);

        while (p != 0) {
                Object *o;

                r = journal_file_move_to_object(f, p, OBJECT_DATA, &o);
                if (r < 0)
                        return r;

                if (le64toh(o->object.size) == osize &&
                    memcmp(o->data.payload, data, size) == 0) {

                        if (le64toh(o->data.hash) != hash)
                                return -EBADMSG;

                        if (o->data.tail_entry_offset == 0)
                                return 0;

                        p = le64toh(o->data.tail_entry_offset);
                        r = journal_file_move_to_object(f, p, OBJECT_ENTRY, &o);
                        if (r < 0)
                                return r;

                        if (ret)
                                *ret = o;

                        if (offset)
                                *offset = p;

                        return 1;
                }

                p = le64toh(o->data.prev_hash_offset);
        }

        return 0;
}

void journal_file_dump(JournalFile *f) {
        char a[33], b[33], c[33];
        Object *o;
        int r;
        uint64_t p;

        assert(f);

        printf("File ID: %s\n"
               "Machine ID: %s\n"
               "Boot ID: %s\n"
               "Arena size: %llu\n",
               sd_id128_to_string(f->header->file_id, a),
               sd_id128_to_string(f->header->machine_id, b),
               sd_id128_to_string(f->header->boot_id, c),
               (unsigned long long) le64toh(f->header->arena_size));

        p = le64toh(f->header->head_object_offset);
        while (p != 0) {
                r = journal_file_move_to_object(f, p, -1, &o);
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

                case OBJECT_HASH_TABLE:
                        printf("Type: OBJECT_HASH_TABLE\n");
                        break;

                case OBJECT_BISECT_TABLE:
                        printf("Type: OBJECT_BISECT_TABLE\n");
                        break;
                }

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

        f = new0(JournalFile, 1);
        if (!f)
                return -ENOMEM;

        f->fd = -1;
        f->flags = flags;
        f->mode = mode;
        f->writable = (flags & O_ACCMODE) != O_RDONLY;
        f->prot = prot_from_flags(flags);

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

                r = journal_file_setup_hash_table(f);
                if (r < 0)
                        goto fail;

                r = journal_file_setup_bisect_table(f);
                if (r < 0)
                        goto fail;
        }

        r = journal_file_map_hash_table(f);
        if (r < 0)
                goto fail;

        r = journal_file_map_bisect_table(f);
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

        p = new(char, l + 1 + 16 + 1 + 32 + 1 + 16 + 1);
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

        old_file->header->state = le32toh(STATE_ARCHIVED);

        r = journal_file_open(old_file->path, old_file->flags, old_file->mode, old_file, &new_file);
        journal_file_close(old_file);

        *f = new_file;
        return r;
}

struct vacuum_info {
        off_t usage;
        char *filename;

        uint64_t realtime;
        sd_id128_t seqnum_id;
        uint64_t seqnum;
};

static int vacuum_compare(const void *_a, const void *_b) {
        const struct vacuum_info *a, *b;

        a = _a;
        b = _b;

        if (sd_id128_equal(a->seqnum_id, b->seqnum_id)) {
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
        else
                return memcmp(&a->seqnum_id, &b->seqnum_id, 16);
}

int journal_directory_vacuum(const char *directory, uint64_t max_use, uint64_t min_free) {
        DIR *d;
        int r = 0;
        struct vacuum_info *list = NULL;
        unsigned n_list = 0, n_allocated = 0, i;
        uint64_t sum = 0;

        assert(directory);

        if (max_use <= 0)
                max_use = DEFAULT_MAX_USE;

        d = opendir(directory);
        if (!d)
                return -errno;

        for (;;) {
                int k;
                struct dirent buf, *de;
                size_t q;
                struct stat st;
                char *p;
                unsigned long long seqnum, realtime;
                sd_id128_t seqnum_id;

                k = readdir_r(d, &buf, &de);
                if (k != 0) {
                        r = -k;
                        goto finish;
                }

                if (!de)
                        break;

                if (!dirent_is_file_with_suffix(de, ".journal"))
                        continue;

                q = strlen(de->d_name);

                if (q < 1 + 32 + 1 + 16 + 1 + 16 + 8)
                        continue;

                if (de->d_name[q-8-16-1] != '-' ||
                    de->d_name[q-8-16-1-16-1] != '-' ||
                    de->d_name[q-8-16-1-16-1-32-1] != '@')
                        continue;

                if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                        continue;

                if (!S_ISREG(st.st_mode))
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
                list[n_list].usage = (uint64_t) st.st_blksize * (uint64_t) st.st_blocks;
                list[n_list].seqnum = seqnum;
                list[n_list].realtime = realtime;
                list[n_list].seqnum_id = seqnum_id;

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
                        log_debug("Deleted archived journal %s/%s.", directory, list[i].filename);
                        sum -= list[i].usage;
                } else if (errno != ENOENT)
                        log_warning("Failed to delete %s/%s: %m", directory, list[i].filename);
        }

finish:
        for (i = 0; i < n_list; i++)
                free(list[i].filename);

        free(list);

        return r;
}
