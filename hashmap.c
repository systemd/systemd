/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

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

static void remove_entry(Hashmap *h, struct hashmap_entry *e) {
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
        else {
                unsigned hash = h->hash_func(e->key) % NBUCKETS;
                BY_HASH(h)[hash] = e->bucket_next;
        }

        free(e);

        assert(h->n_entries >= 1);
        h->n_entries--;
}

void hashmap_free(Hashmap*h) {

        if (!h)
                return;

        while (h->iterate_list_head)
                remove_entry(h, h->iterate_list_head);

        free(h);
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

        if (hash_scan(h, hash, key))
                return -EEXIST;

        if (!(e = new(struct hashmap_entry, 1)))
                return -ENOMEM;

        e->key = key;
        e->value = value;

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

        return 0;
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

void *hashmap_iterate(Hashmap *h, void **state, const void **key) {
        struct hashmap_entry *e;

        assert(state);

        if (!h)
                goto at_end;

        if (*state == (void*) -1)
                goto at_end;

        if (!*state && !h->iterate_list_head)
                goto at_end;

        e = *state ? *state : h->iterate_list_head;

        if (e->iterate_next)
                *state = e->iterate_next;
        else
                *state = (void*) -1;

        if (key)
                *key = e->key;

        return e->value;

at_end:
        *state = (void *) -1;

        if (key)
                *key = NULL;

        return NULL;
}

void *hashmap_iterate_backwards(Hashmap *h, void **state, const void **key) {
        struct hashmap_entry *e;

        assert(state);

        if (!h)
                goto at_beginning;

        if (*state == (void*) -1)
                goto at_beginning;

        if (!*state && !h->iterate_list_tail)
                goto at_beginning;

        e = *state ? *state : h->iterate_list_tail;

        if (e->iterate_previous)
                *state = e->iterate_previous;
        else
                *state = (void*) -1;

        if (key)
                *key = e->key;

        return e->value;

at_beginning:
        *state = (void *) -1;

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
