/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "hashmap.h"
#include "macro.h"

#define NBUCKETS 127

struct hashmap_entry {
        const void *key;
        void *value;
        struct hashmap_entry *bucket_next, *bucket_previous;
        struct hashmap_entry *iterate_next, *iterate_previous;
};

struct Hashmap {
        hash_func_t hash_func;
        compare_func_t compare_func;

        struct hashmap_entry *iterate_list_head, *iterate_list_tail;
        unsigned n_entries;
};

#define BY_HASH(h) ((struct hashmap_entry**) ((uint8_t*) (h) + ALIGN(sizeof(Hashmap))))

unsigned string_hash_func(const void *p) {
        unsigned hash = 0;
        const char *c;

        for (c = p; *c; c++)
                hash = 31 * hash + (unsigned) *c;

        return hash;
}

int string_compare_func(const void *a, const void *b) {
        return strcmp(a, b);
}

unsigned trivial_hash_func(const void *p) {
        return PTR_TO_UINT(p);
}

int trivial_compare_func(const void *a, const void *b) {
        return a < b ? -1 : (a > b ? 1 : 0);
}

Hashmap *hashmap_new(hash_func_t hash_func, compare_func_t compare_func) {
        Hashmap *h;

        if (!(h = malloc0(ALIGN(sizeof(Hashmap)) + NBUCKETS * ALIGN(sizeof(struct hashmap_entry*)))))
                return NULL;

        h->hash_func = hash_func ? hash_func : trivial_hash_func;
        h->compare_func = compare_func ? compare_func : trivial_compare_func;

        h->n_entries = 0;
        h->iterate_list_head = h->iterate_list_tail = NULL;

        return h;
}

int hashmap_ensure_allocated(Hashmap **h, hash_func_t hash_func, compare_func_t compare_func) {
        assert(h);

        if (*h)
                return 0;

        if (!(*h = hashmap_new(hash_func, compare_func)))
                return -ENOMEM;

        return 0;
}

static void link_entry(Hashmap *h, struct hashmap_entry *e, unsigned hash) {
        assert(h);
        assert(e);

        /* Insert into hash table */
        e->bucket_next = BY_HASH(h)[hash];
        e->bucket_previous = NULL;
        if (BY_HASH(h)[hash])
                BY_HASH(h)[hash]->bucket_previous = e;
        BY_HASH(h)[hash] = e;

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
                BY_HASH(h)[hash] = e->bucket_next;

        assert(h->n_entries >= 1);
        h->n_entries--;
}

static void remove_entry(Hashmap *h, struct hashmap_entry *e) {
        unsigned hash;

        assert(h);
        assert(e);

        hash = h->hash_func(e->key) % NBUCKETS;

        unlink_entry(h, e, hash);
        free(e);
}

void hashmap_free(Hashmap*h) {

        if (!h)
                return;

        hashmap_clear(h);

        free(h);
}

void hashmap_free_free(Hashmap *h) {
        void *p;

        while ((p = hashmap_steal_first(h)))
                free(p);

        hashmap_free(h);
}

void hashmap_clear(Hashmap *h) {
        if (!h)
                return;

        while (h->iterate_list_head)
                remove_entry(h, h->iterate_list_head);
}

static struct hashmap_entry *hash_scan(Hashmap *h, unsigned hash, const void *key) {
        struct hashmap_entry *e;
        assert(h);
        assert(hash < NBUCKETS);

        for (e = BY_HASH(h)[hash]; e; e = e->bucket_next)
                if (h->compare_func(e->key, key) == 0)
                        return e;

        return NULL;
}

int hashmap_put(Hashmap *h, const void *key, void *value) {
        struct hashmap_entry *e;
        unsigned hash;

        assert(h);

        hash = h->hash_func(key) % NBUCKETS;

        if ((e = hash_scan(h, hash, key))) {

                if (e->value == value)
                        return 0;

                return -EEXIST;
        }

        if (!(e = new(struct hashmap_entry, 1)))
                return -ENOMEM;

        e->key = key;
        e->value = value;

        link_entry(h, e, hash);

        return 1;
}

int hashmap_replace(Hashmap *h, const void *key, void *value) {
        struct hashmap_entry *e;
        unsigned hash;

        assert(h);

        hash = h->hash_func(key) % NBUCKETS;

        if ((e = hash_scan(h, hash, key))) {
                e->key = key;
                e->value = value;
                return 0;
        }

        return hashmap_put(h, key, value);
}

void* hashmap_get(Hashmap *h, const void *key) {
        unsigned hash;
        struct hashmap_entry *e;

        if (!h)
                return NULL;

        hash = h->hash_func(key) % NBUCKETS;

        if (!(e = hash_scan(h, hash, key)))
                return NULL;

        return e->value;
}

void* hashmap_remove(Hashmap *h, const void *key) {
        struct hashmap_entry *e;
        unsigned hash;
        void *data;

        if (!h)
                return NULL;

        hash = h->hash_func(key) % NBUCKETS;

        if (!(e = hash_scan(h, hash, key)))
                return NULL;

        data = e->value;
        remove_entry(h, e);

        return data;
}

int hashmap_remove_and_put(Hashmap *h, const void *old_key, const void *new_key, void *value) {
        struct hashmap_entry *e;
        unsigned old_hash, new_hash;

        if (!h)
                return -ENOENT;

        old_hash = h->hash_func(old_key) % NBUCKETS;
        if (!(e = hash_scan(h, old_hash, old_key)))
                return -ENOENT;

        new_hash = h->hash_func(new_key) % NBUCKETS;
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

        old_hash = h->hash_func(old_key) % NBUCKETS;
        if (!(e = hash_scan(h, old_hash, old_key)))
                return -ENOENT;

        new_hash = h->hash_func(new_key) % NBUCKETS;

        if ((k = hash_scan(h, new_hash, new_key)))
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

        hash = h->hash_func(key) % NBUCKETS;

        if (!(e = hash_scan(h, hash, key)))
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

void *hashmap_iterate_backwards(Hashmap *h, Iterator *i, const void **key) {
        struct hashmap_entry *e;

        assert(i);

        if (!h)
                goto at_beginning;

        if (*i == ITERATOR_FIRST)
                goto at_beginning;

        if (*i == ITERATOR_LAST && !h->iterate_list_tail)
                goto at_beginning;

        e = *i == ITERATOR_LAST ? h->iterate_list_tail : (struct hashmap_entry*) *i;

        if (e->iterate_previous)
                *i = (Iterator) e->iterate_previous;
        else
                *i = ITERATOR_FIRST;

        if (key)
                *key = e->key;

        return e->value;

at_beginning:
        *i = ITERATOR_FIRST;

        if (key)
                *key = NULL;

        return NULL;
}

void *hashmap_iterate_skip(Hashmap *h, const void *key, Iterator *i) {
        unsigned hash;
        struct hashmap_entry *e;

        if (!h)
                return NULL;

        hash = h->hash_func(key) % NBUCKETS;

        if (!(e = hash_scan(h, hash, key)))
                return NULL;

        *i = (Iterator) e;

        return e->value;
}

void* hashmap_first(Hashmap *h) {

        if (!h)
                return NULL;

        if (!h->iterate_list_head)
                return NULL;

        return h->iterate_list_head->value;
}

void* hashmap_last(Hashmap *h) {

        if (!h)
                return NULL;

        if (!h->iterate_list_tail)
                return NULL;

        return h->iterate_list_tail->value;
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

unsigned hashmap_size(Hashmap *h) {

        if (!h)
                return 0;

        return h->n_entries;
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

                if ((r = hashmap_put(h, e->key, e->value)) < 0)
                        if (r != -EEXIST)
                                return r;
        }

        return 0;
}

void hashmap_move(Hashmap *h, Hashmap *other) {
        struct hashmap_entry *e, *n;

        assert(h);

        /* The same as hashmap_merge(), but every new item from other
         * is moved to h. This function is guaranteed to succeed. */

        if (!other)
                return;

        for (e = other->iterate_list_head; e; e = n) {
                unsigned h_hash, other_hash;

                n = e->iterate_next;

                h_hash = h->hash_func(e->key) % NBUCKETS;

                if (hash_scan(h, h_hash, e->key))
                        continue;

                other_hash = other->hash_func(e->key) % NBUCKETS;

                unlink_entry(other, e, other_hash);
                link_entry(h, e, h_hash);
        }
}

int hashmap_move_one(Hashmap *h, Hashmap *other, const void *key) {
        unsigned h_hash, other_hash;
        struct hashmap_entry *e;

        if (!other)
                return 0;

        assert(h);

        h_hash = h->hash_func(key) % NBUCKETS;
        if (hash_scan(h, h_hash, key))
                return -EEXIST;

        other_hash = other->hash_func(key) % NBUCKETS;
        if (!(e = hash_scan(other, other_hash, key)))
                return -ENOENT;

        unlink_entry(other, e, other_hash);
        link_entry(h, e, h_hash);

        return 0;
}

Hashmap *hashmap_copy(Hashmap *h) {
        Hashmap *copy;

        assert(h);

        if (!(copy = hashmap_new(h->hash_func, h->compare_func)))
                return NULL;

        if (hashmap_merge(copy, h) < 0) {
                hashmap_free(copy);
                return NULL;
        }

        return copy;
}
