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
#include <sys/xattr.h>

#include "journal-def.h"
#include "journal-file.h"
#include "journal-authenticate.h"
#include "lookup3.h"
#include "compress.h"
#include "fsprg.h"

#define DEFAULT_DATA_HASH_TABLE_SIZE (2047ULL*sizeof(HashItem))
#define DEFAULT_FIELD_HASH_TABLE_SIZE (333ULL*sizeof(HashItem))

#define COMPRESSION_SIZE_THRESHOLD (512ULL)

/* This is the minimum journal file size */
#define JOURNAL_FILE_SIZE_MIN (4ULL*1024ULL*1024ULL)           /* 4 MiB */

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

/* n_data was the first entry we added after the initial file format design */
#define HEADER_SIZE_MIN ALIGN64(offsetof(Header, n_data))

/* How many entries to keep in the entry array chain cache at max */
#define CHAIN_CACHE_MAX 20

/* How much to increase the journal file size at once each time we allocate something new. */
#define FILE_SIZE_INCREASE (8ULL*1024ULL*1024ULL)              /* 8MB */

static int journal_file_set_online(JournalFile *f) {
        assert(f);

        if (!f->writable)
                return -EPERM;

        if (!(f->fd >= 0 && f->header))
                return -EINVAL;

        switch(f->header->state) {
                case STATE_ONLINE:
                        return 0;

                case STATE_OFFLINE:
                        f->header->state = STATE_ONLINE;
                        fsync(f->fd);
                        return 0;

                default:
                        return -EINVAL;
        }
}

int journal_file_set_offline(JournalFile *f) {
        assert(f);

        if (!f->writable)
                return -EPERM;

        if (!(f->fd >= 0 && f->header))
                return -EINVAL;

        if (f->header->state != STATE_ONLINE)
                return 0;

        fsync(f->fd);

        f->header->state = STATE_OFFLINE;

        fsync(f->fd);

        return 0;
}

void journal_file_close(JournalFile *f) {
        assert(f);

#ifdef HAVE_GCRYPT
        /* Write the final tag */
        if (f->seal && f->writable)
                journal_file_append_tag(f);
#endif

        /* Sync everything to disk, before we mark the file offline */
        if (f->mmap && f->fd >= 0)
                mmap_cache_close_fd(f->mmap, f->fd);

        journal_file_set_offline(f);

        if (f->header)
                munmap(f->header, PAGE_ALIGN(sizeof(Header)));

        safe_close(f->fd);
        free(f->path);

        if (f->mmap)
                mmap_cache_unref(f->mmap);

        hashmap_free_free(f->chain_cache);

#ifdef HAVE_XZ
        free(f->compress_buffer);
#endif

#ifdef HAVE_GCRYPT
        if (f->fss_file)
                munmap(f->fss_file, PAGE_ALIGN(f->fss_file_size));
        else if (f->fsprg_state)
                free(f->fsprg_state);

        free(f->fsprg_seed);

        if (f->hmac)
                gcry_md_close(f->hmac);
#endif

        free(f);
}

static int journal_file_init_header(JournalFile *f, JournalFile *template) {
        Header h;
        ssize_t k;
        int r;

        assert(f);

        zero(h);
        memcpy(h.signature, HEADER_SIGNATURE, 8);
        h.header_size = htole64(ALIGN64(sizeof(h)));

        h.incompatible_flags =
                htole32(f->compress ? HEADER_INCOMPATIBLE_COMPRESSED : 0);

        h.compatible_flags =
                htole32(f->seal ? HEADER_COMPATIBLE_SEALED : 0);

        r = sd_id128_randomize(&h.file_id);
        if (r < 0)
                return r;

        if (template) {
                h.seqnum_id = template->header->seqnum_id;
                h.tail_entry_seqnum = template->header->tail_entry_seqnum;
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

        journal_file_set_online(f);

        /* Sync the online state to disk */
        fsync(f->fd);

        return 0;
}

static int journal_file_verify_header(JournalFile *f) {
        assert(f);

        if (memcmp(f->header->signature, HEADER_SIGNATURE, 8))
                return -EBADMSG;

        /* In both read and write mode we refuse to open files with
         * incompatible flags we don't know */
#ifdef HAVE_XZ
        if ((le32toh(f->header->incompatible_flags) & ~HEADER_INCOMPATIBLE_COMPRESSED) != 0)
                return -EPROTONOSUPPORT;
#else
        if (f->header->incompatible_flags != 0)
                return -EPROTONOSUPPORT;
#endif

        /* When open for writing we refuse to open files with
         * compatible flags, too */
        if (f->writable) {
#ifdef HAVE_GCRYPT
                if ((le32toh(f->header->compatible_flags) & ~HEADER_COMPATIBLE_SEALED) != 0)
                        return -EPROTONOSUPPORT;
#else
                if (f->header->compatible_flags != 0)
                        return -EPROTONOSUPPORT;
#endif
        }

        if (f->header->state >= _STATE_MAX)
                return -EBADMSG;

        /* The first addition was n_data, so check that we are at least this large */
        if (le64toh(f->header->header_size) < HEADER_SIZE_MIN)
                return -EBADMSG;

        if (JOURNAL_HEADER_SEALED(f->header) && !JOURNAL_HEADER_CONTAINS(f->header, n_entry_arrays))
                return -EBADMSG;

        if ((le64toh(f->header->header_size) + le64toh(f->header->arena_size)) > (uint64_t) f->last_stat.st_size)
                return -ENODATA;

        if (le64toh(f->header->tail_object_offset) > (le64toh(f->header->header_size) + le64toh(f->header->arena_size)))
                return -ENODATA;

        if (!VALID64(le64toh(f->header->data_hash_table_offset)) ||
            !VALID64(le64toh(f->header->field_hash_table_offset)) ||
            !VALID64(le64toh(f->header->tail_object_offset)) ||
            !VALID64(le64toh(f->header->entry_array_offset)))
                return -ENODATA;

        if (le64toh(f->header->data_hash_table_offset) < le64toh(f->header->header_size) ||
            le64toh(f->header->field_hash_table_offset) < le64toh(f->header->header_size) ||
            le64toh(f->header->tail_object_offset) < le64toh(f->header->header_size) ||
            le64toh(f->header->entry_array_offset) < le64toh(f->header->header_size))
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

                if (state == STATE_ONLINE) {
                        log_debug("Journal file %s is already online. Assuming unclean closing.", f->path);
                        return -EBUSY;
                } else if (state == STATE_ARCHIVED)
                        return -ESHUTDOWN;
                else if (state != STATE_OFFLINE) {
                        log_debug("Journal file %s has unknown state %u.", f->path, state);
                        return -EBUSY;
                }
        }

        f->compress = JOURNAL_HEADER_COMPRESSED(f->header);

        f->seal = JOURNAL_HEADER_SEALED(f->header);

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

        if (f->metrics.max_size > 0 && new_size > f->metrics.max_size)
                return -E2BIG;

        if (new_size > f->metrics.min_size && f->metrics.keep_free > 0) {
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

        /* Increase by larger blocks at once */
        new_size = ((new_size+FILE_SIZE_INCREASE-1) / FILE_SIZE_INCREASE) * FILE_SIZE_INCREASE;
        if (f->metrics.max_size > 0 && new_size > f->metrics.max_size)
                new_size = f->metrics.max_size;

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

static int journal_file_move_to(JournalFile *f, int context, bool keep_always, uint64_t offset, uint64_t size, void **ret) {
        assert(f);
        assert(ret);

        if (size <= 0)
                return -EINVAL;

        /* Avoid SIGBUS on invalid accesses */
        if (offset + size > (uint64_t) f->last_stat.st_size) {
                /* Hmm, out of range? Let's refresh the fstat() data
                 * first, before we trust that check. */

                if (fstat(f->fd, &f->last_stat) < 0 ||
                    offset + size > (uint64_t) f->last_stat.st_size)
                        return -EADDRNOTAVAIL;
        }

        return mmap_cache_get(f->mmap, f->fd, f->prot, context, keep_always, offset, size, &f->last_stat, ret);
}

static uint64_t minimum_header_size(Object *o) {

        static const uint64_t table[] = {
                [OBJECT_DATA] = sizeof(DataObject),
                [OBJECT_FIELD] = sizeof(FieldObject),
                [OBJECT_ENTRY] = sizeof(EntryObject),
                [OBJECT_DATA_HASH_TABLE] = sizeof(HashTableObject),
                [OBJECT_FIELD_HASH_TABLE] = sizeof(HashTableObject),
                [OBJECT_ENTRY_ARRAY] = sizeof(EntryArrayObject),
                [OBJECT_TAG] = sizeof(TagObject),
        };

        if (o->object.type >= ELEMENTSOF(table) || table[o->object.type] <= 0)
                return sizeof(ObjectHeader);

        return table[o->object.type];
}

int journal_file_move_to_object(JournalFile *f, int type, uint64_t offset, Object **ret) {
        int r;
        void *t;
        Object *o;
        uint64_t s;

        assert(f);
        assert(ret);

        /* Objects may only be located at multiple of 64 bit */
        if (!VALID64(offset))
                return -EFAULT;


        r = journal_file_move_to(f, type_to_context(type), false, offset, sizeof(ObjectHeader), &t);
        if (r < 0)
                return r;

        o = (Object*) t;
        s = le64toh(o->object.size);

        if (s < sizeof(ObjectHeader))
                return -EBADMSG;

        if (o->object.type <= OBJECT_UNUSED)
                return -EBADMSG;

        if (s < minimum_header_size(o))
                return -EBADMSG;

        if (type > 0 && o->object.type != type)
                return -EBADMSG;

        if (s > sizeof(ObjectHeader)) {
                r = journal_file_move_to(f, o->object.type, false, offset, s, &t);
                if (r < 0)
                        return r;

                o = (Object*) t;
        }

        *ret = o;
        return 0;
}

static uint64_t journal_file_entry_seqnum(JournalFile *f, uint64_t *seqnum) {
        uint64_t r;

        assert(f);

        r = le64toh(f->header->tail_entry_seqnum) + 1;

        if (seqnum) {
                /* If an external seqnum counter was passed, we update
                 * both the local and the external one, and set it to
                 * the maximum of both */

                if (*seqnum + 1 > r)
                        r = *seqnum + 1;

                *seqnum = r;
        }

        f->header->tail_entry_seqnum = htole64(r);

        if (f->header->head_entry_seqnum == 0)
                f->header->head_entry_seqnum = htole64(r);

        return r;
}

int journal_file_append_object(JournalFile *f, int type, uint64_t size, Object **ret, uint64_t *offset) {
        int r;
        uint64_t p;
        Object *tail, *o;
        void *t;

        assert(f);
        assert(type > 0 && type < _OBJECT_TYPE_MAX);
        assert(size >= sizeof(ObjectHeader));
        assert(offset);
        assert(ret);

        r = journal_file_set_online(f);
        if (r < 0)
                return r;

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

        r = journal_file_move_to(f, type, false, p, size, &t);
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

        /* We estimate that we need 1 hash table entry per 768 of
           journal file and we want to make sure we never get beyond
           75% fill level. Calculate the hash table size for the
           maximum file size based on these metrics. */

        s = (f->metrics.max_size * 4 / 768 / 3) * sizeof(HashItem);
        if (s < DEFAULT_DATA_HASH_TABLE_SIZE)
                s = DEFAULT_DATA_HASH_TABLE_SIZE;

        log_debug("Reserving %"PRIu64" entries in hash table.", s / sizeof(HashItem));

        r = journal_file_append_object(f,
                                       OBJECT_DATA_HASH_TABLE,
                                       offsetof(Object, hash_table.items) + s,
                                       &o, &p);
        if (r < 0)
                return r;

        memzero(o->hash_table.items, s);

        f->header->data_hash_table_offset = htole64(p + offsetof(Object, hash_table.items));
        f->header->data_hash_table_size = htole64(s);

        return 0;
}

static int journal_file_setup_field_hash_table(JournalFile *f) {
        uint64_t s, p;
        Object *o;
        int r;

        assert(f);

        /* We use a fixed size hash table for the fields as this
         * number should grow very slowly only */

        s = DEFAULT_FIELD_HASH_TABLE_SIZE;
        r = journal_file_append_object(f,
                                       OBJECT_FIELD_HASH_TABLE,
                                       offsetof(Object, hash_table.items) + s,
                                       &o, &p);
        if (r < 0)
                return r;

        memzero(o->hash_table.items, s);

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
                                 OBJECT_DATA_HASH_TABLE,
                                 true,
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
                                 OBJECT_FIELD_HASH_TABLE,
                                 true,
                                 p, s,
                                 &t);
        if (r < 0)
                return r;

        f->field_hash_table = t;
        return 0;
}

static int journal_file_link_field(
                JournalFile *f,
                Object *o,
                uint64_t offset,
                uint64_t hash) {

        uint64_t p, h;
        int r;

        assert(f);
        assert(o);
        assert(offset > 0);

        if (o->object.type != OBJECT_FIELD)
                return -EINVAL;

        /* This might alter the window we are looking at */

        o->field.next_hash_offset = o->field.head_data_offset = 0;

        h = hash % (le64toh(f->header->field_hash_table_size) / sizeof(HashItem));
        p = le64toh(f->field_hash_table[h].tail_hash_offset);
        if (p == 0)
                f->field_hash_table[h].head_hash_offset = htole64(offset);
        else {
                r = journal_file_move_to_object(f, OBJECT_FIELD, p, &o);
                if (r < 0)
                        return r;

                o->field.next_hash_offset = htole64(offset);
        }

        f->field_hash_table[h].tail_hash_offset = htole64(offset);

        if (JOURNAL_HEADER_CONTAINS(f->header, n_fields))
                f->header->n_fields = htole64(le64toh(f->header->n_fields) + 1);

        return 0;
}

static int journal_file_link_data(
                JournalFile *f,
                Object *o,
                uint64_t offset,
                uint64_t hash) {

        uint64_t p, h;
        int r;

        assert(f);
        assert(o);
        assert(offset > 0);

        if (o->object.type != OBJECT_DATA)
                return -EINVAL;

        /* This might alter the window we are looking at */

        o->data.next_hash_offset = o->data.next_field_offset = 0;
        o->data.entry_offset = o->data.entry_array_offset = 0;
        o->data.n_entries = 0;

        h = hash % (le64toh(f->header->data_hash_table_size) / sizeof(HashItem));
        p = le64toh(f->data_hash_table[h].tail_hash_offset);
        if (p == 0)
                /* Only entry in the hash table is easy */
                f->data_hash_table[h].head_hash_offset = htole64(offset);
        else {
                /* Move back to the previous data object, to patch in
                 * pointer */

                r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
                if (r < 0)
                        return r;

                o->data.next_hash_offset = htole64(offset);
        }

        f->data_hash_table[h].tail_hash_offset = htole64(offset);

        if (JOURNAL_HEADER_CONTAINS(f->header, n_data))
                f->header->n_data = htole64(le64toh(f->header->n_data) + 1);

        return 0;
}

int journal_file_find_field_object_with_hash(
                JournalFile *f,
                const void *field, uint64_t size, uint64_t hash,
                Object **ret, uint64_t *offset) {

        uint64_t p, osize, h;
        int r;

        assert(f);
        assert(field && size > 0);

        osize = offsetof(Object, field.payload) + size;

        if (f->header->field_hash_table_size == 0)
                return -EBADMSG;

        h = hash % (le64toh(f->header->field_hash_table_size) / sizeof(HashItem));
        p = le64toh(f->field_hash_table[h].head_hash_offset);

        while (p > 0) {
                Object *o;

                r = journal_file_move_to_object(f, OBJECT_FIELD, p, &o);
                if (r < 0)
                        return r;

                if (le64toh(o->field.hash) == hash &&
                    le64toh(o->object.size) == osize &&
                    memcmp(o->field.payload, field, size) == 0) {

                        if (ret)
                                *ret = o;
                        if (offset)
                                *offset = p;

                        return 1;
                }

                p = le64toh(o->field.next_hash_offset);
        }

        return 0;
}

int journal_file_find_field_object(
                JournalFile *f,
                const void *field, uint64_t size,
                Object **ret, uint64_t *offset) {

        uint64_t hash;

        assert(f);
        assert(field && size > 0);

        hash = hash64(field, size);

        return journal_file_find_field_object_with_hash(f,
                                                        field, size, hash,
                                                        ret, offset);
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

                        if (!uncompress_blob(o->data.payload, l, &f->compress_buffer, &f->compress_buffer_size, &rsize, 0))
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

static int journal_file_append_field(
                JournalFile *f,
                const void *field, uint64_t size,
                Object **ret, uint64_t *offset) {

        uint64_t hash, p;
        uint64_t osize;
        Object *o;
        int r;

        assert(f);
        assert(field && size > 0);

        hash = hash64(field, size);

        r = journal_file_find_field_object_with_hash(f, field, size, hash, &o, &p);
        if (r < 0)
                return r;
        else if (r > 0) {

                if (ret)
                        *ret = o;

                if (offset)
                        *offset = p;

                return 0;
        }

        osize = offsetof(Object, field.payload) + size;
        r = journal_file_append_object(f, OBJECT_FIELD, osize, &o, &p);
        if (r < 0)
                return r;

        o->field.hash = htole64(hash);
        memcpy(o->field.payload, field, size);

        r = journal_file_link_field(f, o, p, hash);
        if (r < 0)
                return r;

        /* The linking might have altered the window, so let's
         * refresh our pointer */
        r = journal_file_move_to_object(f, OBJECT_FIELD, p, &o);
        if (r < 0)
                return r;

#ifdef HAVE_GCRYPT
        r = journal_file_hmac_put_object(f, OBJECT_FIELD, o, p);
        if (r < 0)
                return r;
#endif

        if (ret)
                *ret = o;

        if (offset)
                *offset = p;

        return 0;
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
        const void *eq;

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

                        log_debug("Compressed data object %"PRIu64" -> %"PRIu64, size, rsize);
                }
        }
#endif

        if (!compressed && size > 0)
                memcpy(o->data.payload, data, size);

        r = journal_file_link_data(f, o, p, hash);
        if (r < 0)
                return r;

        /* The linking might have altered the window, so let's
         * refresh our pointer */
        r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
        if (r < 0)
                return r;

        if (!data)
                eq = NULL;
        else
                eq = memchr(data, '=', size);
        if (eq && eq > data) {
                Object *fo = NULL;
                uint64_t fp;

                /* Create field object ... */
                r = journal_file_append_field(f, data, (uint8_t*) eq - (uint8_t*) data, &fo, &fp);
                if (r < 0)
                        return r;

                /* ... and link it in. */
                o->data.next_field_offset = fo->field.head_data_offset;
                fo->field.head_data_offset = le64toh(p);
        }

#ifdef HAVE_GCRYPT
        r = journal_file_hmac_put_object(f, OBJECT_DATA, o, p);
        if (r < 0)
                return r;
#endif

        if (ret)
                *ret = o;

        if (offset)
                *offset = p;

        return 0;
}

uint64_t journal_file_entry_n_items(Object *o) {
        assert(o);

        if (o->object.type != OBJECT_ENTRY)
                return 0;

        return (le64toh(o->object.size) - offsetof(Object, entry.items)) / sizeof(EntryItem);
}

uint64_t journal_file_entry_array_n_items(Object *o) {
        assert(o);

        if (o->object.type != OBJECT_ENTRY_ARRAY)
                return 0;

        return (le64toh(o->object.size) - offsetof(Object, entry_array.items)) / sizeof(uint64_t);
}

uint64_t journal_file_hash_table_n_items(Object *o) {
        assert(o);

        if (o->object.type != OBJECT_DATA_HASH_TABLE &&
            o->object.type != OBJECT_FIELD_HASH_TABLE)
                return 0;

        return (le64toh(o->object.size) - offsetof(Object, hash_table.items)) / sizeof(HashItem);
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

#ifdef HAVE_GCRYPT
        r = journal_file_hmac_put_object(f, OBJECT_ENTRY_ARRAY, o, q);
        if (r < 0)
                return r;
#endif

        o->entry_array.items[i] = htole64(p);

        if (ap == 0)
                *first = htole64(q);
        else {
                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, ap, &o);
                if (r < 0)
                        return r;

                o->entry_array.next_entry_array_offset = htole64(q);
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_entry_arrays))
                f->header->n_entry_arrays = htole64(le64toh(f->header->n_entry_arrays) + 1);

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

        if (o->object.type != OBJECT_ENTRY)
                return -EINVAL;

        __sync_synchronize();

        /* Link up the entry itself */
        r = link_entry_into_array(f,
                                  &f->header->entry_array_offset,
                                  &f->header->n_entries,
                                  offset);
        if (r < 0)
                return r;

        /* log_debug("=> %s seqnr=%"PRIu64" n_entries=%"PRIu64, f->path, o->entry.seqnum, f->header->n_entries); */

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

        o->entry.seqnum = htole64(journal_file_entry_seqnum(f, seqnum));
        memcpy(o->entry.items, items, n_items * sizeof(EntryItem));
        o->entry.realtime = htole64(ts->realtime);
        o->entry.monotonic = htole64(ts->monotonic);
        o->entry.xor_hash = htole64(xor_hash);
        o->entry.boot_id = f->header->boot_id;

#ifdef HAVE_GCRYPT
        r = journal_file_hmac_put_object(f, OBJECT_ENTRY, o, np);
        if (r < 0)
                return r;
#endif

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
                log_error("Failed to truncate file to its own size: %m");
}

static int entry_item_cmp(const void *_a, const void *_b) {
        const EntryItem *a = _a, *b = _b;

        if (le64toh(a->object_offset) < le64toh(b->object_offset))
                return -1;
        if (le64toh(a->object_offset) > le64toh(b->object_offset))
                return 1;
        return 0;
}

int journal_file_append_entry(JournalFile *f, const dual_timestamp *ts, const struct iovec iovec[], unsigned n_iovec, uint64_t *seqnum, Object **ret, uint64_t *offset) {
        unsigned i;
        EntryItem *items;
        int r;
        uint64_t xor_hash = 0;
        struct dual_timestamp _ts;

        assert(f);
        assert(iovec || n_iovec == 0);

        if (!ts) {
                dual_timestamp_get(&_ts);
                ts = &_ts;
        }

        if (f->tail_entry_monotonic_valid &&
            ts->monotonic < le64toh(f->header->tail_entry_monotonic))
                return -EINVAL;

#ifdef HAVE_GCRYPT
        r = journal_file_maybe_append_tag(f, ts->realtime);
        if (r < 0)
                return r;
#endif

        /* alloca() can't take 0, hence let's allocate at least one */
        items = alloca(sizeof(EntryItem) * MAX(1u, n_iovec));

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

        /* Order by the position on disk, in order to improve seek
         * times for rotating media. */
        qsort_safe(items, n_iovec, sizeof(EntryItem), entry_item_cmp);

        r = journal_file_append_entry_internal(f, ts, xor_hash, items, n_iovec, seqnum, ret, offset);

        journal_file_post_change(f);

        return r;
}

typedef struct ChainCacheItem {
        uint64_t first; /* the array at the beginning of the chain */
        uint64_t array; /* the cached array */
        uint64_t begin; /* the first item in the cached array */
        uint64_t total; /* the total number of items in all arrays before this one in the chain */
        uint64_t last_index; /* the last index we looked at, to optimize locality when bisecting */
} ChainCacheItem;

static void chain_cache_put(
                Hashmap *h,
                ChainCacheItem *ci,
                uint64_t first,
                uint64_t array,
                uint64_t begin,
                uint64_t total,
                uint64_t last_index) {

        if (!ci) {
                /* If the chain item to cache for this chain is the
                 * first one it's not worth caching anything */
                if (array == first)
                        return;

                if (hashmap_size(h) >= CHAIN_CACHE_MAX)
                        ci = hashmap_steal_first(h);
                else {
                        ci = new(ChainCacheItem, 1);
                        if (!ci)
                                return;
                }

                ci->first = first;

                if (hashmap_put(h, &ci->first, ci) < 0) {
                        free(ci);
                        return;
                }
        } else
                assert(ci->first == first);

        ci->array = array;
        ci->begin = begin;
        ci->total = total;
        ci->last_index = last_index;
}

static int generic_array_get(
                JournalFile *f,
                uint64_t first,
                uint64_t i,
                Object **ret, uint64_t *offset) {

        Object *o;
        uint64_t p = 0, a, t = 0;
        int r;
        ChainCacheItem *ci;

        assert(f);

        a = first;

        /* Try the chain cache first */
        ci = hashmap_get(f->chain_cache, &first);
        if (ci && i > ci->total) {
                a = ci->array;
                i -= ci->total;
                t = ci->total;
        }

        while (a > 0) {
                uint64_t k;

                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o);
                if (r < 0)
                        return r;

                k = journal_file_entry_array_n_items(o);
                if (i < k) {
                        p = le64toh(o->entry_array.items[i]);
                        goto found;
                }

                i -= k;
                t += k;
                a = le64toh(o->entry_array.next_entry_array_offset);
        }

        return 0;

found:
        /* Let's cache this item for the next invocation */
        chain_cache_put(f->chain_cache, ci, first, a, le64toh(o->entry_array.items[0]), t, i);

        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, &o);
        if (r < 0)
                return r;

        if (ret)
                *ret = o;

        if (offset)
                *offset = p;

        return 1;
}

static int generic_array_get_plus_one(
                JournalFile *f,
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

static int generic_array_bisect(
                JournalFile *f,
                uint64_t first,
                uint64_t n,
                uint64_t needle,
                int (*test_object)(JournalFile *f, uint64_t p, uint64_t needle),
                direction_t direction,
                Object **ret,
                uint64_t *offset,
                uint64_t *idx) {

        uint64_t a, p, t = 0, i = 0, last_p = 0, last_index = (uint64_t) -1;
        bool subtract_one = false;
        Object *o, *array = NULL;
        int r;
        ChainCacheItem *ci;

        assert(f);
        assert(test_object);

        /* Start with the first array in the chain */
        a = first;

        ci = hashmap_get(f->chain_cache, &first);
        if (ci && n > ci->total) {
                /* Ah, we have iterated this bisection array chain
                 * previously! Let's see if we can skip ahead in the
                 * chain, as far as the last time. But we can't jump
                 * backwards in the chain, so let's check that
                 * first. */

                r = test_object(f, ci->begin, needle);
                if (r < 0)
                        return r;

                if (r == TEST_LEFT) {
                        /* OK, what we are looking for is right of the
                         * begin of this EntryArray, so let's jump
                         * straight to previously cached array in the
                         * chain */

                        a = ci->array;
                        n -= ci->total;
                        t = ci->total;
                        last_index = ci->last_index;
                }
        }

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

                        if (last_index != (uint64_t) -1) {
                                assert(last_index <= right);

                                /* If we cached the last index we
                                 * looked at, let's try to not to jump
                                 * too wildly around and see if we can
                                 * limit the range to look at early to
                                 * the immediate neighbors of the last
                                 * index we looked at. */

                                if (last_index > 0) {
                                        uint64_t x = last_index - 1;

                                        p = le64toh(array->entry_array.items[x]);
                                        if (p <= 0)
                                                return -EBADMSG;

                                        r = test_object(f, p, needle);
                                        if (r < 0)
                                                return r;

                                        if (r == TEST_FOUND)
                                                r = direction == DIRECTION_DOWN ? TEST_RIGHT : TEST_LEFT;

                                        if (r == TEST_RIGHT)
                                                right = x;
                                        else
                                                left = x + 1;
                                }

                                if (last_index < right) {
                                        uint64_t y = last_index + 1;

                                        p = le64toh(array->entry_array.items[y]);
                                        if (p <= 0)
                                                return -EBADMSG;

                                        r = test_object(f, p, needle);
                                        if (r < 0)
                                                return r;

                                        if (r == TEST_FOUND)
                                                r = direction == DIRECTION_DOWN ? TEST_RIGHT : TEST_LEFT;

                                        if (r == TEST_RIGHT)
                                                right = y;
                                        else
                                                left = y + 1;
                                }
                        }

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

                if (k > n) {
                        if (direction == DIRECTION_UP) {
                                i = n;
                                subtract_one = true;
                                goto found;
                        }

                        return 0;
                }

                last_p = lp;

                n -= k;
                t += k;
                last_index = (uint64_t) -1;
                a = le64toh(array->entry_array.next_entry_array_offset);
        }

        return 0;

found:
        if (subtract_one && t == 0 && i == 0)
                return 0;

        /* Let's cache this item for the next invocation */
        chain_cache_put(f->chain_cache, ci, first, a, le64toh(array->entry_array.items[0]), t, subtract_one ? (i > 0 ? i-1 : (uint64_t) -1) : i);

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
                *idx = t + i + (subtract_one ? -1 : 0);

        return 1;
}


static int generic_array_bisect_plus_one(
                JournalFile *f,
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
        bool step_back = false;
        Object *o;

        assert(f);
        assert(test_object);

        if (n <= 0)
                return 0;

        /* This bisects the array in object 'first', but first checks
         * an extra  */
        r = test_object(f, extra, needle);
        if (r < 0)
                return r;

        if (r == TEST_FOUND)
                r = direction == DIRECTION_DOWN ? TEST_RIGHT : TEST_LEFT;

        /* if we are looking with DIRECTION_UP then we need to first
           see if in the actual array there is a matching entry, and
           return the last one of that. But if there isn't any we need
           to return this one. Hence remember this, and return it
           below. */
        if (r == TEST_LEFT)
                step_back = direction == DIRECTION_UP;

        if (r == TEST_RIGHT) {
                if (direction == DIRECTION_DOWN)
                        goto found;
                else
                        return 0;
        }

        r = generic_array_bisect(f, first, n-1, needle, test_object, direction, ret, offset, idx);

        if (r == 0 && step_back)
                goto found;

        if (r > 0 && idx)
                (*idx) ++;

        return r;

found:
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
}

_pure_ static int test_object_offset(JournalFile *f, uint64_t p, uint64_t needle) {
        assert(f);
        assert(p > 0);

        if (p == needle)
                return TEST_FOUND;
        else if (p < needle)
                return TEST_LEFT;
        else
                return TEST_RIGHT;
}

int journal_file_move_to_entry_by_offset(
                JournalFile *f,
                uint64_t p,
                direction_t direction,
                Object **ret,
                uint64_t *offset) {

        return generic_array_bisect(f,
                                    le64toh(f->header->entry_array_offset),
                                    le64toh(f->header->n_entries),
                                    p,
                                    test_object_offset,
                                    direction,
                                    ret, offset, NULL);
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

static inline int find_data_object_by_boot_id(
                JournalFile *f,
                sd_id128_t boot_id,
                Object **o,
                uint64_t *b) {
        char t[sizeof("_BOOT_ID=")-1 + 32 + 1] = "_BOOT_ID=";

        sd_id128_to_string(boot_id, t + 9);
        return journal_file_find_data_object(f, t, sizeof(t) - 1, o, b);
}

int journal_file_move_to_entry_by_monotonic(
                JournalFile *f,
                sd_id128_t boot_id,
                uint64_t monotonic,
                direction_t direction,
                Object **ret,
                uint64_t *offset) {

        Object *o;
        int r;

        assert(f);

        r = find_data_object_by_boot_id(f, boot_id, &o, NULL);
        if (r < 0)
                return r;
        if (r == 0)
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

int journal_file_next_entry(
                JournalFile *f,
                Object *o, uint64_t p,
                direction_t direction,
                Object **ret, uint64_t *offset) {

        uint64_t i, n, ofs;
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
        r = generic_array_get(f,
                              le64toh(f->header->entry_array_offset),
                              i,
                              ret, &ofs);
        if (r <= 0)
                return r;

        if (p > 0 &&
            (direction == DIRECTION_DOWN ? ofs <= p : ofs >= p)) {
                log_debug("%s: entry array corrupted at entry %"PRIu64,
                          f->path, i);
                return -EBADMSG;
        }

        if (offset)
                *offset = ofs;

        return 1;
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

int journal_file_move_to_entry_by_offset_for_data(
                JournalFile *f,
                uint64_t data_offset,
                uint64_t p,
                direction_t direction,
                Object **ret, uint64_t *offset) {

        int r;
        Object *d;

        assert(f);

        r = journal_file_move_to_object(f, OBJECT_DATA, data_offset, &d);
        if (r < 0)
                return r;

        return generic_array_bisect_plus_one(f,
                                             le64toh(d->data.entry_offset),
                                             le64toh(d->data.entry_array_offset),
                                             le64toh(d->data.n_entries),
                                             p,
                                             test_object_offset,
                                             direction,
                                             ret, offset, NULL);
}

int journal_file_move_to_entry_by_monotonic_for_data(
                JournalFile *f,
                uint64_t data_offset,
                sd_id128_t boot_id,
                uint64_t monotonic,
                direction_t direction,
                Object **ret, uint64_t *offset) {

        Object *o, *d;
        int r;
        uint64_t b, z;

        assert(f);

        /* First, seek by time */
        r = find_data_object_by_boot_id(f, boot_id, &o, &b);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOENT;

        r = generic_array_bisect_plus_one(f,
                                          le64toh(o->data.entry_offset),
                                          le64toh(o->data.entry_array_offset),
                                          le64toh(o->data.n_entries),
                                          monotonic,
                                          test_object_monotonic,
                                          direction,
                                          NULL, &z, NULL);
        if (r <= 0)
                return r;

        /* And now, continue seeking until we find an entry that
         * exists in both bisection arrays */

        for (;;) {
                Object *qo;
                uint64_t p, q;

                r = journal_file_move_to_object(f, OBJECT_DATA, data_offset, &d);
                if (r < 0)
                        return r;

                r = generic_array_bisect_plus_one(f,
                                                  le64toh(d->data.entry_offset),
                                                  le64toh(d->data.entry_array_offset),
                                                  le64toh(d->data.n_entries),
                                                  z,
                                                  test_object_offset,
                                                  direction,
                                                  NULL, &p, NULL);
                if (r <= 0)
                        return r;

                r = journal_file_move_to_object(f, OBJECT_DATA, b, &o);
                if (r < 0)
                        return r;

                r = generic_array_bisect_plus_one(f,
                                                  le64toh(o->data.entry_offset),
                                                  le64toh(o->data.entry_array_offset),
                                                  le64toh(o->data.n_entries),
                                                  p,
                                                  test_object_offset,
                                                  direction,
                                                  &qo, &q, NULL);

                if (r <= 0)
                        return r;

                if (p == q) {
                        if (ret)
                                *ret = qo;
                        if (offset)
                                *offset = q;

                        return 1;
                }

                z = q;
        }
}

int journal_file_move_to_entry_by_seqnum_for_data(
                JournalFile *f,
                uint64_t data_offset,
                uint64_t seqnum,
                direction_t direction,
                Object **ret, uint64_t *offset) {

        Object *d;
        int r;

        assert(f);

        r = journal_file_move_to_object(f, OBJECT_DATA, data_offset, &d);
        if (r < 0)
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

        assert(f);

        r = journal_file_move_to_object(f, OBJECT_DATA, data_offset, &d);
        if (r < 0)
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
        Object *o;
        int r;
        uint64_t p;

        assert(f);

        journal_file_print_header(f);

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

                case OBJECT_FIELD:
                        printf("Type: OBJECT_FIELD\n");
                        break;

                case OBJECT_ENTRY:
                        printf("Type: OBJECT_ENTRY seqnum=%"PRIu64" monotonic=%"PRIu64" realtime=%"PRIu64"\n",
                               le64toh(o->entry.seqnum),
                               le64toh(o->entry.monotonic),
                               le64toh(o->entry.realtime));
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

                case OBJECT_TAG:
                        printf("Type: OBJECT_TAG seqnum=%"PRIu64" epoch=%"PRIu64"\n",
                               le64toh(o->tag.seqnum),
                               le64toh(o->tag.epoch));
                        break;

                default:
                        printf("Type: unknown (%u)\n", o->object.type);
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

static const char* format_timestamp_safe(char *buf, size_t l, usec_t t) {
        const char *x;

        x = format_timestamp(buf, l, t);
        if (x)
                return x;
        return " --- ";
}

void journal_file_print_header(JournalFile *f) {
        char a[33], b[33], c[33], d[33];
        char x[FORMAT_TIMESTAMP_MAX], y[FORMAT_TIMESTAMP_MAX], z[FORMAT_TIMESTAMP_MAX];
        struct stat st;
        char bytes[FORMAT_BYTES_MAX];

        assert(f);

        printf("File Path: %s\n"
               "File ID: %s\n"
               "Machine ID: %s\n"
               "Boot ID: %s\n"
               "Sequential Number ID: %s\n"
               "State: %s\n"
               "Compatible Flags:%s%s\n"
               "Incompatible Flags:%s%s\n"
               "Header size: %"PRIu64"\n"
               "Arena size: %"PRIu64"\n"
               "Data Hash Table Size: %"PRIu64"\n"
               "Field Hash Table Size: %"PRIu64"\n"
               "Rotate Suggested: %s\n"
               "Head Sequential Number: %"PRIu64"\n"
               "Tail Sequential Number: %"PRIu64"\n"
               "Head Realtime Timestamp: %s\n"
               "Tail Realtime Timestamp: %s\n"
               "Tail Monotonic Timestamp: %s\n"
               "Objects: %"PRIu64"\n"
               "Entry Objects: %"PRIu64"\n",
               f->path,
               sd_id128_to_string(f->header->file_id, a),
               sd_id128_to_string(f->header->machine_id, b),
               sd_id128_to_string(f->header->boot_id, c),
               sd_id128_to_string(f->header->seqnum_id, d),
               f->header->state == STATE_OFFLINE ? "OFFLINE" :
               f->header->state == STATE_ONLINE ? "ONLINE" :
               f->header->state == STATE_ARCHIVED ? "ARCHIVED" : "UNKNOWN",
               JOURNAL_HEADER_SEALED(f->header) ? " SEALED" : "",
               (le32toh(f->header->compatible_flags) & ~HEADER_COMPATIBLE_SEALED) ? " ???" : "",
               JOURNAL_HEADER_COMPRESSED(f->header) ? " COMPRESSED" : "",
               (le32toh(f->header->incompatible_flags) & ~HEADER_INCOMPATIBLE_COMPRESSED) ? " ???" : "",
               le64toh(f->header->header_size),
               le64toh(f->header->arena_size),
               le64toh(f->header->data_hash_table_size) / sizeof(HashItem),
               le64toh(f->header->field_hash_table_size) / sizeof(HashItem),
               yes_no(journal_file_rotate_suggested(f, 0)),
               le64toh(f->header->head_entry_seqnum),
               le64toh(f->header->tail_entry_seqnum),
               format_timestamp_safe(x, sizeof(x), le64toh(f->header->head_entry_realtime)),
               format_timestamp_safe(y, sizeof(y), le64toh(f->header->tail_entry_realtime)),
               format_timespan(z, sizeof(z), le64toh(f->header->tail_entry_monotonic), USEC_PER_MSEC),
               le64toh(f->header->n_objects),
               le64toh(f->header->n_entries));

        if (JOURNAL_HEADER_CONTAINS(f->header, n_data))
                printf("Data Objects: %"PRIu64"\n"
                       "Data Hash Table Fill: %.1f%%\n",
                       le64toh(f->header->n_data),
                       100.0 * (double) le64toh(f->header->n_data) / ((double) (le64toh(f->header->data_hash_table_size) / sizeof(HashItem))));

        if (JOURNAL_HEADER_CONTAINS(f->header, n_fields))
                printf("Field Objects: %"PRIu64"\n"
                       "Field Hash Table Fill: %.1f%%\n",
                       le64toh(f->header->n_fields),
                       100.0 * (double) le64toh(f->header->n_fields) / ((double) (le64toh(f->header->field_hash_table_size) / sizeof(HashItem))));

        if (JOURNAL_HEADER_CONTAINS(f->header, n_tags))
                printf("Tag Objects: %"PRIu64"\n",
                       le64toh(f->header->n_tags));
        if (JOURNAL_HEADER_CONTAINS(f->header, n_entry_arrays))
                printf("Entry Array Objects: %"PRIu64"\n",
                       le64toh(f->header->n_entry_arrays));

        if (fstat(f->fd, &st) >= 0)
                printf("Disk usage: %s\n", format_bytes(bytes, sizeof(bytes), (off_t) st.st_blocks * 512ULL));
}

int journal_file_open(
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                bool seal,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                JournalFile *template,
                JournalFile **ret) {

        JournalFile *f;
        int r;
        bool newly_created = false;

        assert(fname);
        assert(ret);

        if ((flags & O_ACCMODE) != O_RDONLY &&
            (flags & O_ACCMODE) != O_RDWR)
                return -EINVAL;

        if (!endswith(fname, ".journal") &&
            !endswith(fname, ".journal~"))
                return -EINVAL;

        f = new0(JournalFile, 1);
        if (!f)
                return -ENOMEM;

        f->fd = -1;
        f->mode = mode;

        f->flags = flags;
        f->prot = prot_from_flags(flags);
        f->writable = (flags & O_ACCMODE) != O_RDONLY;
#ifdef HAVE_XZ
        f->compress = compress;
#endif
#ifdef HAVE_GCRYPT
        f->seal = seal;
#endif

        if (mmap_cache)
                f->mmap = mmap_cache_ref(mmap_cache);
        else {
                f->mmap = mmap_cache_new();
                if (!f->mmap) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        f->path = strdup(fname);
        if (!f->path) {
                r = -ENOMEM;
                goto fail;
        }

        f->chain_cache = hashmap_new(uint64_hash_func, uint64_compare_func);
        if (!f->chain_cache) {
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
                uint64_t crtime;

                /* Let's attach the creation time to the journal file,
                 * so that the vacuuming code knows the age of this
                 * file even if the file might end up corrupted one
                 * day... Ideally we'd just use the creation time many
                 * file systems maintain for each file, but there is
                 * currently no usable API to query this, hence let's
                 * emulate this via extended attributes. If extended
                 * attributes are not supported we'll just skip this,
                 * and rely solely on mtime/atime/ctime of the file.*/

                crtime = htole64((uint64_t) now(CLOCK_REALTIME));
                fsetxattr(f->fd, "user.crtime_usec", &crtime, sizeof(crtime), XATTR_CREATE);

#ifdef HAVE_GCRYPT
                /* Try to load the FSPRG state, and if we can't, then
                 * just don't do sealing */
                if (f->seal) {
                        r = journal_file_fss_load(f);
                        if (r < 0)
                                f->seal = false;
                }
#endif

                r = journal_file_init_header(f, template);
                if (r < 0)
                        goto fail;

                if (fstat(f->fd, &f->last_stat) < 0) {
                        r = -errno;
                        goto fail;
                }

                newly_created = true;
        }

        if (f->last_stat.st_size < (off_t) HEADER_SIZE_MIN) {
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

#ifdef HAVE_GCRYPT
        if (!newly_created && f->writable) {
                r = journal_file_fss_load(f);
                if (r < 0)
                        goto fail;
        }
#endif

        if (f->writable) {
                if (metrics) {
                        journal_default_metrics(metrics, f->fd);
                        f->metrics = *metrics;
                } else if (template)
                        f->metrics = template->metrics;

                r = journal_file_refresh_header(f);
                if (r < 0)
                        goto fail;
        }

#ifdef HAVE_GCRYPT
        r = journal_file_hmac_setup(f);
        if (r < 0)
                goto fail;
#endif

        if (newly_created) {
                r = journal_file_setup_field_hash_table(f);
                if (r < 0)
                        goto fail;

                r = journal_file_setup_data_hash_table(f);
                if (r < 0)
                        goto fail;

#ifdef HAVE_GCRYPT
                r = journal_file_append_first_tag(f);
                if (r < 0)
                        goto fail;
#endif
        }

        r = journal_file_map_field_hash_table(f);
        if (r < 0)
                goto fail;

        r = journal_file_map_data_hash_table(f);
        if (r < 0)
                goto fail;

        *ret = f;
        return 0;

fail:
        journal_file_close(f);

        return r;
}

int journal_file_rotate(JournalFile **f, bool compress, bool seal) {
        _cleanup_free_ char *p = NULL;
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
        r = asprintf(&p, "%.*s@" SD_ID128_FORMAT_STR "-%016"PRIx64"-%016"PRIx64".journal",
                     (int) l - 8, old_file->path,
                     SD_ID128_FORMAT_VAL(old_file->header->seqnum_id),
                     le64toh((*f)->header->head_entry_seqnum),
                     le64toh((*f)->header->head_entry_realtime));
        if (r < 0)
                return -ENOMEM;

        r = rename(old_file->path, p);
        if (r < 0)
                return -errno;

        old_file->header->state = STATE_ARCHIVED;

        r = journal_file_open(old_file->path, old_file->flags, old_file->mode, compress, seal, NULL, old_file->mmap, old_file, &new_file);
        journal_file_close(old_file);

        *f = new_file;
        return r;
}

int journal_file_open_reliably(
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                bool seal,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                JournalFile *template,
                JournalFile **ret) {

        int r;
        size_t l;
        _cleanup_free_ char *p = NULL;

        r = journal_file_open(fname, flags, mode, compress, seal,
                              metrics, mmap_cache, template, ret);
        if (r != -EBADMSG && /* corrupted */
            r != -ENODATA && /* truncated */
            r != -EHOSTDOWN && /* other machine */
            r != -EPROTONOSUPPORT && /* incompatible feature */
            r != -EBUSY && /* unclean shutdown */
            r != -ESHUTDOWN /* already archived */)
                return r;

        if ((flags & O_ACCMODE) == O_RDONLY)
                return r;

        if (!(flags & O_CREAT))
                return r;

        if (!endswith(fname, ".journal"))
                return r;

        /* The file is corrupted. Rotate it away and try it again (but only once) */

        l = strlen(fname);
        if (asprintf(&p, "%.*s@%016llx-%016" PRIx64 ".journal~",
                     (int) l - 8, fname,
                     (unsigned long long) now(CLOCK_REALTIME),
                     random_u64()) < 0)
                return -ENOMEM;

        r = rename(fname, p);
        if (r < 0)
                return -errno;

        log_warning("File %s corrupted or uncleanly shut down, renaming and replacing.", fname);

        return journal_file_open(fname, flags, mode, compress, seal,
                                 metrics, mmap_cache, template, ret);
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

        n = journal_file_entry_n_items(o);
        /* alloca() can't take 0, hence let's allocate at least one */
        items = alloca(sizeof(EntryItem) * MAX(1u, n));

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

                        if (!uncompress_blob(o->data.payload, l, &from->compress_buffer, &from->compress_buffer_size, &rsize, 0))
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
                        m->keep_free = PAGE_ALIGN(fs_size * 3 / 20); /* 15% of file system size */

                        if (m->keep_free > DEFAULT_KEEP_FREE_UPPER)
                                m->keep_free = DEFAULT_KEEP_FREE_UPPER;

                } else
                        m->keep_free = DEFAULT_KEEP_FREE;
        }

        log_debug("Fixed max_use=%s max_size=%s min_size=%s keep_free=%s",
                  format_bytes(a, sizeof(a), m->max_use),
                  format_bytes(b, sizeof(b), m->max_size),
                  format_bytes(c, sizeof(c), m->min_size),
                  format_bytes(d, sizeof(d), m->keep_free));
}

int journal_file_get_cutoff_realtime_usec(JournalFile *f, usec_t *from, usec_t *to) {
        assert(f);
        assert(from || to);

        if (from) {
                if (f->header->head_entry_realtime == 0)
                        return -ENOENT;

                *from = le64toh(f->header->head_entry_realtime);
        }

        if (to) {
                if (f->header->tail_entry_realtime == 0)
                        return -ENOENT;

                *to = le64toh(f->header->tail_entry_realtime);
        }

        return 1;
}

int journal_file_get_cutoff_monotonic_usec(JournalFile *f, sd_id128_t boot_id, usec_t *from, usec_t *to) {
        Object *o;
        uint64_t p;
        int r;

        assert(f);
        assert(from || to);

        r = find_data_object_by_boot_id(f, boot_id, &o, &p);
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

bool journal_file_rotate_suggested(JournalFile *f, usec_t max_file_usec) {
        assert(f);

        /* If we gained new header fields we gained new features,
         * hence suggest a rotation */
        if (le64toh(f->header->header_size) < sizeof(Header)) {
                log_debug("%s uses an outdated header, suggesting rotation.", f->path);
                return true;
        }

        /* Let's check if the hash tables grew over a certain fill
         * level (75%, borrowing this value from Java's hash table
         * implementation), and if so suggest a rotation. To calculate
         * the fill level we need the n_data field, which only exists
         * in newer versions. */

        if (JOURNAL_HEADER_CONTAINS(f->header, n_data))
                if (le64toh(f->header->n_data) * 4ULL > (le64toh(f->header->data_hash_table_size) / sizeof(HashItem)) * 3ULL) {
                        log_debug("Data hash table of %s has a fill level at %.1f (%"PRIu64" of %"PRIu64" items, %llu file size, %"PRIu64" bytes per hash table item), suggesting rotation.",
                                  f->path,
                                  100.0 * (double) le64toh(f->header->n_data) / ((double) (le64toh(f->header->data_hash_table_size) / sizeof(HashItem))),
                                  le64toh(f->header->n_data),
                                  le64toh(f->header->data_hash_table_size) / sizeof(HashItem),
                                  (unsigned long long) f->last_stat.st_size,
                                  f->last_stat.st_size / le64toh(f->header->n_data));
                        return true;
                }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_fields))
                if (le64toh(f->header->n_fields) * 4ULL > (le64toh(f->header->field_hash_table_size) / sizeof(HashItem)) * 3ULL) {
                        log_debug("Field hash table of %s has a fill level at %.1f (%"PRIu64" of %"PRIu64" items), suggesting rotation.",
                                  f->path,
                                  100.0 * (double) le64toh(f->header->n_fields) / ((double) (le64toh(f->header->field_hash_table_size) / sizeof(HashItem))),
                                  le64toh(f->header->n_fields),
                                  le64toh(f->header->field_hash_table_size) / sizeof(HashItem));
                        return true;
                }

        /* Are the data objects properly indexed by field objects? */
        if (JOURNAL_HEADER_CONTAINS(f->header, n_data) &&
            JOURNAL_HEADER_CONTAINS(f->header, n_fields) &&
            le64toh(f->header->n_data) > 0 &&
            le64toh(f->header->n_fields) == 0)
                return true;

        if (max_file_usec > 0) {
                usec_t t, h;

                h = le64toh(f->header->head_entry_realtime);
                t = now(CLOCK_REALTIME);

                if (h > 0 && t > h + max_file_usec)
                        return true;
        }

        return false;
}
