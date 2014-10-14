/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "hashmap.h"
#include "macro.h"
#include "siphash24.h"
#include "mempool.h"

#define INITIAL_N_BUCKETS 31

struct hashmap_entry {
        const void *key;
        void *value;
        struct hashmap_entry *bucket_next, *bucket_previous;
        struct hashmap_entry *iterate_next, *iterate_previous;
};

struct Hashmap {
        const struct hash_ops *hash_ops;

        struct hashmap_entry *iterate_list_head, *iterate_list_tail;

        struct hashmap_entry ** buckets;
        unsigned n_buckets, n_entries;

        uint8_t hash_key[HASH_KEY_SIZE];
        bool from_pool:1;
};

struct hashmap_tile {
        Hashmap h;
        struct hashmap_entry *initial_buckets[INITIAL_N_BUCKETS];
};

static DEFINE_MEMPOOL(hashmap_pool, struct hashmap_tile, 8);
static DEFINE_MEMPOOL(hashmap_entry_pool, struct hashmap_entry, 64);

#ifdef VALGRIND

__attribute__((destructor)) static void cleanup_pools(void) {
        /* Be nice to valgrind */

        mempool_drop(&hashmap_entry_pool);
        mempool_drop(&hashmap_pool);
}

#endif

unsigned long string_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]) {
        uint64_t u;
        siphash24((uint8_t*) &u, p, strlen(p), hash_key);
        return (unsigned long) u;
}

int string_compare_func(const void *a, const void *b) {
        return strcmp(a, b);
}

const struct hash_ops string_hash_ops = {
        .hash = string_hash_func,
        .compare = string_compare_func
};

unsigned long trivial_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]) {
        uint64_t u;
        siphash24((uint8_t*) &u, &p, sizeof(p), hash_key);
        return (unsigned long) u;
}

int trivial_compare_func(const void *a, const void *b) {
        return a < b ? -1 : (a > b ? 1 : 0);
}

const struct hash_ops trivial_hash_ops = {
        .hash = trivial_hash_func,
        .compare = trivial_compare_func
};

unsigned long uint64_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]) {
        uint64_t u;
        siphash24((uint8_t*) &u, p, sizeof(uint64_t), hash_key);
        return (unsigned long) u;
}

int uint64_compare_func(const void *_a, const void *_b) {
        uint64_t a, b;
        a = *(const uint64_t*) _a;
        b = *(const uint64_t*) _b;
        return a < b ? -1 : (a > b ? 1 : 0);
}

const struct hash_ops uint64_hash_ops = {
        .hash = uint64_hash_func,
        .compare = uint64_compare_func
};

#if SIZEOF_DEV_T != 8
unsigned long devt_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]) {
        uint64_t u;
        siphash24((uint8_t*) &u, p, sizeof(dev_t), hash_key);
        return (unsigned long) u;
}

int devt_compare_func(const void *_a, const void *_b) {
        dev_t a, b;
        a = *(const dev_t*) _a;
        b = *(const dev_t*) _b;
        return a < b ? -1 : (a > b ? 1 : 0);
}

const struct hash_ops devt_hash_ops = {
        .hash = devt_hash_func,
        .compare = devt_compare_func
};
#endif

static unsigned bucket_hash(Hashmap *h, const void *p) {
        return (unsigned) (h->hash_ops->hash(p, h->hash_key) % h->n_buckets);
}

static void get_hash_key(uint8_t hash_key[HASH_KEY_SIZE], bool reuse_is_ok) {
        static uint8_t current[HASH_KEY_SIZE];
        static bool current_initialized = false;

        /* Returns a hash function key to use. In order to keep things
         * fast we will not generate a new key each time we allocate a
         * new hash table. Instead, we'll just reuse the most recently
         * generated one, except if we never generated one or when we
         * are rehashing an entire hash table because we reached a
         * fill level */

        if (!current_initialized || !reuse_is_ok) {
                random_bytes(current, sizeof(current));
                current_initialized = true;
        }

        memcpy(hash_key, current, sizeof(current));
}

Hashmap *hashmap_new(const struct hash_ops *hash_ops) {
        bool b;
        struct hashmap_tile *ht;
        Hashmap *h;

        b = is_main_thread();

        if (b) {
                ht = mempool_alloc_tile(&hashmap_pool);
                if (!ht)
                        return NULL;

                memzero(ht, sizeof(struct hashmap_tile));
        } else {
                ht = malloc0(sizeof(struct hashmap_tile));

                if (!ht)
                        return NULL;
        }

        h = &ht->h;
        h->hash_ops = hash_ops ? hash_ops : &trivial_hash_ops;

        h->n_buckets = INITIAL_N_BUCKETS;
        h->n_entries = 0;
        h->iterate_list_head = h->iterate_list_tail = NULL;

        h->buckets = ht->initial_buckets;

        h->from_pool = b;

        get_hash_key(h->hash_key, true);

        return h;
}

int hashmap_ensure_allocated(Hashmap **h, const struct hash_ops *hash_ops) {
        Hashmap *q;

        assert(h);

        if (*h)
                return 0;

        q = hashmap_new(hash_ops);
        if (!q)
                return -ENOMEM;

        *h = q;
        return 0;
}

static void link_entry(Hashmap *h, struct hashmap_entry *e, unsigned hash) {
        assert(h);
        assert(e);

        /* Insert into hash table */
        e->bucket_next = h->buckets[hash];
        e->bucket_previous = NULL;
        if (h->buckets[hash])
                h->buckets[hash]->bucket_previous = e;
        h->buckets[hash] = e;

        /* Insert into iteration list */
        e->iterate_previous = h->iterate_list_tail;
        e->iterate_next = NULL;
        if (h->iterate_list_tail) {
                assert(h->iterate_list_head);
                h->iterate_list_tail->iterate_next = e;
        } else {
                assert(!h->iterate_list_head);
                h->iterate_list_head = e;
        }
        h->iterate_list_tail = e;

        h->n_entries++;
        assert(h->n_entries >= 1);
}

static void unlink_entry(Hashmap *h, struct hashmap_entry *e, unsigned hash) {
        assert(h);
        assert(e);

        /* Remove from iteration list */
        if (e->iterate_next)
                e->iterate_next->iterate_previous = e->iterate_previous;
        else
                h->iterate_list_tail = e->iterate_previous;

        if (e->iterate_previous)
                e->iterate_previous->iterate_next = e->iterate_next;
        else
                h->iterate_list_head = e->iterate_next;

        /* Remove from hash table bucket list */
        if (e->bucket_next)
                e->bucket_next->bucket_previous = e->bucket_previous;

        if (e->bucket_previous)
                e->bucket_previous->bucket_next = e->bucket_next;
        else
                h->buckets[hash] = e->bucket_next;

        assert(h->n_entries >= 1);
        h->n_entries--;
}

static void remove_entry(Hashmap *h, struct hashmap_entry *e) {
        unsigned hash;

        assert(h);
        assert(e);

        hash = bucket_hash(h, e->key);
        unlink_entry(h, e, hash);

        if (h->from_pool)
                mempool_free_tile(&hashmap_entry_pool, e);
        else
                free(e);
}

void hashmap_free(Hashmap*h) {

        /* Free the hashmap, but nothing in it */

        if (!h)
                return;

        hashmap_clear(h);

        if (h->buckets != (struct hashmap_entry**) ((uint8_t*) h + ALIGN(sizeof(Hashmap))))
                free(h->buckets);

        if (h->from_pool)
                mempool_free_tile(&hashmap_pool, container_of(h, struct hashmap_tile, h));
        else
                free(h);
}

void hashmap_free_free(Hashmap *h) {

        /* Free the hashmap and all data objects in it, but not the
         * keys */

        if (!h)
                return;

        hashmap_clear_free(h);
        hashmap_free(h);
}

void hashmap_free_free_free(Hashmap *h) {

        /* Free the hashmap and all data and key objects in it */

        if (!h)
                return;

        hashmap_clear_free_free(h);
        hashmap_free(h);
}

void hashmap_clear(Hashmap *h) {
        if (!h)
                return;

        while (h->iterate_list_head)
                remove_entry(h, h->iterate_list_head);
}

void hashmap_clear_free(Hashmap *h) {
        void *p;

        if (!h)
                return;

        while ((p = hashmap_steal_first(h)))
                free(p);
}

void hashmap_clear_free_free(Hashmap *h) {
        if (!h)
                return;

        while (h->iterate_list_head) {
                void *a, *b;

                a = h->iterate_list_head->value;
                b = (void*) h->iterate_list_head->key;
                remove_entry(h, h->iterate_list_head);
                free(a);
                free(b);
        }
}

static struct hashmap_entry *hash_scan(Hashmap *h, unsigned hash, const void *key) {
        struct hashmap_entry *e;
        assert(h);
        assert(hash < h->n_buckets);

        for (e = h->buckets[hash]; e; e = e->bucket_next)
                if (h->hash_ops->compare(e->key, key) == 0)
                        return e;

        return NULL;
}

static int resize_buckets(Hashmap *h, unsigned entries_add) {
        struct hashmap_entry **n, *i;
        unsigned m, new_n_entries, new_n_buckets;
        uint8_t nkey[HASH_KEY_SIZE];

        assert(h);

        new_n_entries = h->n_entries + entries_add;

        /* overflow? */
        if (_unlikely_(new_n_entries < entries_add || new_n_entries > UINT_MAX / 4))
                return -ENOMEM;

        new_n_buckets = new_n_entries * 4 / 3;

        if (_likely_(new_n_buckets <= h->n_buckets))
                return 0;

        /* Increase by four at least */
        m = MAX((h->n_entries+1)*4-1, new_n_buckets);

        /* If we hit OOM we simply risk packed hashmaps... */
        n = new0(struct hashmap_entry*, m);
        if (!n)
                return -ENOMEM;

        /* Let's use a different randomized hash key for the
         * extension, so that people cannot guess what we are using
         * here forever */
        get_hash_key(nkey, false);

        for (i = h->iterate_list_head; i; i = i->iterate_next) {
                unsigned long old_bucket, new_bucket;

                old_bucket = h->hash_ops->hash(i->key, h->hash_key) % h->n_buckets;

                /* First, drop from old bucket table */
                if (i->bucket_next)
                        i->bucket_next->bucket_previous = i->bucket_previous;

                if (i->bucket_previous)
                        i->bucket_previous->bucket_next = i->bucket_next;
                else
                        h->buckets[old_bucket] = i->bucket_next;

                /* Then, add to new backet table */
                new_bucket = h->hash_ops->hash(i->key, nkey) % m;

                i->bucket_next = n[new_bucket];
                i->bucket_previous = NULL;
                if (n[new_bucket])
                        n[new_bucket]->bucket_previous = i;
                n[new_bucket] = i;
        }

        if (h->buckets != (struct hashmap_entry**) ((uint8_t*) h + ALIGN(sizeof(Hashmap))))
                free(h->buckets);

        h->buckets = n;
        h->n_buckets = m;

        memcpy(h->hash_key, nkey, HASH_KEY_SIZE);

        return 1;
}

static int __hashmap_put(Hashmap *h, const void *key, void *value, unsigned hash) {
        /* For when we know no such entry exists yet */

        struct hashmap_entry *e;

        if (resize_buckets(h, 1) > 0)
                hash = bucket_hash(h, key);

        if (h->from_pool)
                e = mempool_alloc_tile(&hashmap_entry_pool);
        else
                e = new(struct hashmap_entry, 1);

        if (!e)
                return -ENOMEM;

        e->key = key;
        e->value = value;

        link_entry(h, e, hash);

        return 1;
}

int hashmap_put(Hashmap *h, const void *key, void *value) {
        struct hashmap_entry *e;
        unsigned hash;

        assert(h);

        hash = bucket_hash(h, key);
        e = hash_scan(h, hash, key);
        if (e) {
                if (e->value == value)
                        return 0;
                return -EEXIST;
        }

        return __hashmap_put(h, key, value, hash);
}

int hashmap_replace(Hashmap *h, const void *key, void *value) {
        struct hashmap_entry *e;
        unsigned hash;

        assert(h);

        hash = bucket_hash(h, key);
        e = hash_scan(h, hash, key);
        if (e) {
                e->key = key;
                e->value = value;
                return 0;
        }

        return __hashmap_put(h, key, value, hash);
}

int hashmap_update(Hashmap *h, const void *key, void *value) {
        struct hashmap_entry *e;
        unsigned hash;

        assert(h);

        hash = bucket_hash(h, key);
        e = hash_scan(h, hash, key);
        if (!e)
                return -ENOENT;

        e->value = value;
        return 0;
}

void* hashmap_get(Hashmap *h, const void *key) {
        unsigned hash;
        struct hashmap_entry *e;

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);
        e = hash_scan(h, hash, key);
        if (!e)
                return NULL;

        return e->value;
}

void* hashmap_get2(Hashmap *h, const void *key, void **key2) {
        unsigned hash;
        struct hashmap_entry *e;

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);
        e = hash_scan(h, hash, key);
        if (!e)
                return NULL;

        if (key2)
                *key2 = (void*) e->key;

        return e->value;
}

bool hashmap_contains(Hashmap *h, const void *key) {
        unsigned hash;

        if (!h)
                return false;

        hash = bucket_hash(h, key);
        return !!hash_scan(h, hash, key);
}

void* hashmap_remove(Hashmap *h, const void *key) {
        struct hashmap_entry *e;
        unsigned hash;
        void *data;

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);
        e = hash_scan(h, hash, key);
        if (!e)
                return NULL;

        data = e->value;
        remove_entry(h, e);

        return data;
}

void* hashmap_remove2(Hashmap *h, const void *key, void **rkey) {
        struct hashmap_entry *e;
        unsigned hash;
        void *data;

        if (!h) {
                if (rkey)
                        *rkey = NULL;
                return NULL;
        }

        hash = bucket_hash(h, key);
        e = hash_scan(h, hash, key);
        if (!e) {
                if (rkey)
                        *rkey = NULL;
                return NULL;
        }

        data = e->value;
        if (rkey)
                *rkey = (void*) e->key;

        remove_entry(h, e);

        return data;
}

int hashmap_remove_and_put(Hashmap *h, const void *old_key, const void *new_key, void *value) {
        struct hashmap_entry *e;
        unsigned old_hash, new_hash;

        if (!h)
                return -ENOENT;

        old_hash = bucket_hash(h, old_key);
        e = hash_scan(h, old_hash, old_key);
        if (!e)
                return -ENOENT;

        new_hash = bucket_hash(h, new_key);
        if (hash_scan(h, new_hash, new_key))
                return -EEXIST;

        unlink_entry(h, e, old_hash);

        e->key = new_key;
        e->value = value;

        link_entry(h, e, new_hash);

        return 0;
}

int hashmap_remove_and_replace(Hashmap *h, const void *old_key, const void *new_key, void *value) {
        struct hashmap_entry *e, *k;
        unsigned old_hash, new_hash;

        if (!h)
                return -ENOENT;

        old_hash = bucket_hash(h, old_key);
        e = hash_scan(h, old_hash, old_key);
        if (!e)
                return -ENOENT;

        new_hash = bucket_hash(h, new_key);
        k = hash_scan(h, new_hash, new_key);
        if (k)
                if (e != k)
                        remove_entry(h, k);

        unlink_entry(h, e, old_hash);

        e->key = new_key;
        e->value = value;

        link_entry(h, e, new_hash);

        return 0;
}

void* hashmap_remove_value(Hashmap *h, const void *key, void *value) {
        struct hashmap_entry *e;
        unsigned hash;

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);

        e = hash_scan(h, hash, key);
        if (!e)
                return NULL;

        if (e->value != value)
                return NULL;

        remove_entry(h, e);

        return value;
}

void *hashmap_iterate(Hashmap *h, Iterator *i, const void **key) {
        struct hashmap_entry *e;

        assert(i);

        if (!h)
                goto at_end;

        if (*i == ITERATOR_LAST)
                goto at_end;

        if (*i == ITERATOR_FIRST && !h->iterate_list_head)
                goto at_end;

        e = *i == ITERATOR_FIRST ? h->iterate_list_head : (struct hashmap_entry*) *i;

        if (e->iterate_next)
                *i = (Iterator) e->iterate_next;
        else
                *i = ITERATOR_LAST;

        if (key)
                *key = e->key;

        return e->value;

at_end:
        *i = ITERATOR_LAST;

        if (key)
                *key = NULL;

        return NULL;
}

void* hashmap_first(Hashmap *h) {

        if (!h)
                return NULL;

        if (!h->iterate_list_head)
                return NULL;

        return h->iterate_list_head->value;
}

void* hashmap_first_key(Hashmap *h) {

        if (!h)
                return NULL;

        if (!h->iterate_list_head)
                return NULL;

        return (void*) h->iterate_list_head->key;
}

void* hashmap_steal_first(Hashmap *h) {
        void *data;

        if (!h)
                return NULL;

        if (!h->iterate_list_head)
                return NULL;

        data = h->iterate_list_head->value;
        remove_entry(h, h->iterate_list_head);

        return data;
}

void* hashmap_steal_first_key(Hashmap *h) {
        void *key;

        if (!h)
                return NULL;

        if (!h->iterate_list_head)
                return NULL;

        key = (void*) h->iterate_list_head->key;
        remove_entry(h, h->iterate_list_head);

        return key;
}

unsigned hashmap_size(Hashmap *h) {

        if (!h)
                return 0;

        return h->n_entries;
}

unsigned hashmap_buckets(Hashmap *h) {

        if (!h)
                return 0;

        return h->n_buckets;
}

bool hashmap_isempty(Hashmap *h) {

        if (!h)
                return true;

        return h->n_entries == 0;
}

int hashmap_merge(Hashmap *h, Hashmap *other) {
        struct hashmap_entry *e;

        assert(h);

        if (!other)
                return 0;

        for (e = other->iterate_list_head; e; e = e->iterate_next) {
                int r;

                r = hashmap_put(h, e->key, e->value);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        return 0;
}

int hashmap_reserve(Hashmap *h, unsigned entries_add) {
        int r;

        assert(h);

        r = resize_buckets(h, entries_add);
        if (r < 0)
                return r;

        return 0;
}

int hashmap_move(Hashmap *h, Hashmap *other) {
        struct hashmap_entry *e, *n;

        assert(h);

        /* The same as hashmap_merge(), but every new item from other
         * is moved to h. */

        if (!other)
                return 0;

        for (e = other->iterate_list_head; e; e = n) {
                unsigned h_hash, other_hash;

                n = e->iterate_next;

                h_hash = bucket_hash(h, e->key);
                if (hash_scan(h, h_hash, e->key))
                        continue;

                other_hash = bucket_hash(other, e->key);
                unlink_entry(other, e, other_hash);
                link_entry(h, e, h_hash);
        }

        return 0;
}

int hashmap_move_one(Hashmap *h, Hashmap *other, const void *key) {
        unsigned h_hash, other_hash;
        struct hashmap_entry *e;

        assert(h);

        h_hash = bucket_hash(h, key);
        if (hash_scan(h, h_hash, key))
                return -EEXIST;

        if (!other)
                return -ENOENT;

        other_hash = bucket_hash(other, key);
        e = hash_scan(other, other_hash, key);
        if (!e)
                return -ENOENT;

        unlink_entry(other, e, other_hash);
        link_entry(h, e, h_hash);

        return 0;
}

Hashmap *hashmap_copy(Hashmap *h) {
        Hashmap *copy;

        assert(h);

        copy = hashmap_new(h->hash_ops);
        if (!copy)
                return NULL;

        if (hashmap_merge(copy, h) < 0) {
                hashmap_free(copy);
                return NULL;
        }

        return copy;
}

char **hashmap_get_strv(Hashmap *h) {
        char **sv;
        Iterator it;
        char *item;
        int n;

        sv = new(char*, h->n_entries+1);
        if (!sv)
                return NULL;

        n = 0;
        HASHMAP_FOREACH(item, h, it)
                sv[n++] = item;
        sv[n] = NULL;

        return sv;
}

void *hashmap_next(Hashmap *h, const void *key) {
        unsigned hash;
        struct hashmap_entry *e;

        assert(key);

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);
        e = hash_scan(h, hash, key);
        if (!e)
                return NULL;

        e = e->iterate_next;
        if (!e)
                return NULL;

        return e->value;
}
