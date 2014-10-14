/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include <stdbool.h>

#include "macro.h"
#include "util.h"

/* Pretty straightforward hash table implementation. As a minor
 * optimization a NULL hashmap object will be treated as empty hashmap
 * for all read operations. That way it is not necessary to
 * instantiate an object for each Hashmap use. */

#define HASH_KEY_SIZE 16

typedef struct Hashmap Hashmap;
typedef struct OrderedHashmap OrderedHashmap;
typedef struct _IteratorStruct _IteratorStruct;
typedef _IteratorStruct* Iterator;

#define ITERATOR_FIRST ((Iterator) 0)
#define ITERATOR_LAST ((Iterator) -1)

typedef unsigned long (*hash_func_t)(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]);
typedef int (*compare_func_t)(const void *a, const void *b);

struct hash_ops {
        hash_func_t hash;
        compare_func_t compare;
};

unsigned long string_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]) _pure_;
int string_compare_func(const void *a, const void *b) _pure_;
extern const struct hash_ops string_hash_ops;

/* This will compare the passed pointers directly, and will not
 * dereference them. This is hence not useful for strings or
 * suchlike. */
unsigned long trivial_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]) _pure_;
int trivial_compare_func(const void *a, const void *b) _const_;
extern const struct hash_ops trivial_hash_ops;

/* 32bit values we can always just embedd in the pointer itself, but
 * in order to support 32bit archs we need store 64bit values
 * indirectly, since they don't fit in a pointer. */
unsigned long uint64_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]) _pure_;
int uint64_compare_func(const void *a, const void *b) _pure_;
extern const struct hash_ops uint64_hash_ops;

/* On some archs dev_t is 32bit, and on others 64bit. And sometimes
 * it's 64bit on 32bit archs, and sometimes 32bit on 64bit archs. Yuck! */
#if SIZEOF_DEV_T != 8
unsigned long devt_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]) _pure_;
int devt_compare_func(const void *a, const void *b) _pure_;
extern const struct hash_ops devt_hash_ops = {
        .hash = devt_hash_func,
        .compare = devt_compare_func
};
#else
#define devt_hash_func uint64_hash_func
#define devt_compare_func uint64_compare_func
#define devt_hash_ops uint64_hash_ops
#endif

Hashmap *hashmap_new(const struct hash_ops *hash_ops);
static inline OrderedHashmap *ordered_hashmap_new(const struct hash_ops *hash_ops) {
        return (OrderedHashmap*) hashmap_new(hash_ops);
}
void hashmap_free(Hashmap *h);
static inline void ordered_hashmap_free(OrderedHashmap *h) {
        hashmap_free((Hashmap*) h);
}
void hashmap_free_free(Hashmap *h);
static inline void ordered_hashmap_free_free(OrderedHashmap *h) {
        hashmap_free_free((Hashmap*) h);
}
void hashmap_free_free_free(Hashmap *h);
static inline void ordered_hashmap_free_free_free(OrderedHashmap *h) {
        hashmap_free_free_free((Hashmap*) h);
}
Hashmap *hashmap_copy(Hashmap *h);
static inline OrderedHashmap *ordered_hashmap_copy(OrderedHashmap *h) {
        return (OrderedHashmap*) hashmap_copy((Hashmap*) h);
}
int hashmap_ensure_allocated(Hashmap **h, const struct hash_ops *hash_ops);
static inline int ordered_hashmap_ensure_allocated(OrderedHashmap **h, const struct hash_ops *hash_ops) {
        return hashmap_ensure_allocated((Hashmap**) h, hash_ops);
}

int hashmap_put(Hashmap *h, const void *key, void *value);
static inline int ordered_hashmap_put(OrderedHashmap *h, const void *key, void *value) {
        return hashmap_put((Hashmap*) h, key, value);
}
int hashmap_update(Hashmap *h, const void *key, void *value);
static inline int ordered_hashmap_update(OrderedHashmap *h, const void *key, void *value) {
        return hashmap_update((Hashmap*) h, key, value);
}
int hashmap_replace(Hashmap *h, const void *key, void *value);
static inline int ordered_hashmap_replace(OrderedHashmap *h, const void *key, void *value) {
        return hashmap_replace((Hashmap*) h, key, value);
}
void *hashmap_get(Hashmap *h, const void *key);
static inline void *ordered_hashmap_get(OrderedHashmap *h, const void *key) {
        return hashmap_get((Hashmap*) h, key);
}
void *hashmap_get2(Hashmap *h, const void *key, void **rkey);
static inline void *ordered_hashmap_get2(OrderedHashmap *h, const void *key, void **rkey) {
        return hashmap_get2((Hashmap*) h, key, rkey);
}
bool hashmap_contains(Hashmap *h, const void *key);
static inline bool ordered_hashmap_contains(OrderedHashmap *h, const void *key) {
        return hashmap_contains((Hashmap*) h, key);
}
void *hashmap_remove(Hashmap *h, const void *key);
static inline void *ordered_hashmap_remove(OrderedHashmap *h, const void *key) {
        return hashmap_remove((Hashmap*) h, key);
}
void *hashmap_remove2(Hashmap *h, const void *key, void **rkey);
static inline void *ordered_hashmap_remove2(OrderedHashmap *h, const void *key, void **rkey) {
        return hashmap_remove2((Hashmap*) h, key, rkey);
}
void *hashmap_remove_value(Hashmap *h, const void *key, void *value);
static inline void *ordered_hashmap_remove_value(OrderedHashmap *h, const void *key, void *value) {
        return hashmap_remove_value((Hashmap*) h, key, value);
}
int hashmap_remove_and_put(Hashmap *h, const void *old_key, const void *new_key, void *value);
static inline int ordered_hashmap_remove_and_put(OrderedHashmap *h, const void *old_key, const void *new_key, void *value) {
        return hashmap_remove_and_put((Hashmap*) h, old_key, new_key, value);
}
int hashmap_remove_and_replace(Hashmap *h, const void *old_key, const void *new_key, void *value);
static inline int ordered_hashmap_remove_and_replace(OrderedHashmap *h, const void *old_key, const void *new_key, void *value) {
        return hashmap_remove_and_replace((Hashmap*) h, old_key, new_key, value);
}

int hashmap_merge(Hashmap *h, Hashmap *other);
static inline int ordered_hashmap_merge(OrderedHashmap *h, OrderedHashmap *other) {
        return hashmap_merge((Hashmap*) h, (Hashmap*) other);
}
int hashmap_reserve(Hashmap *h, unsigned entries_add);
static inline int ordered_hashmap_reserve(OrderedHashmap *h, unsigned entries_add) {
        return hashmap_reserve((Hashmap*) h, entries_add);
}
int hashmap_move(Hashmap *h, Hashmap *other);
static inline int ordered_hashmap_move(OrderedHashmap *h, OrderedHashmap *other) {
        return hashmap_move((Hashmap*) h, (Hashmap*) other);
}
int hashmap_move_one(Hashmap *h, Hashmap *other, const void *key);
static inline int ordered_hashmap_move_one(OrderedHashmap *h, OrderedHashmap *other, const void *key) {
        return hashmap_move_one((Hashmap*) h, (Hashmap*) other, key);
}

unsigned hashmap_size(Hashmap *h) _pure_;
static inline unsigned ordered_hashmap_size(OrderedHashmap *h) {
        return hashmap_size((Hashmap*) h);
}
bool hashmap_isempty(Hashmap *h) _pure_;
static inline bool ordered_hashmap_isempty(OrderedHashmap *h) {
        return hashmap_isempty((Hashmap*) h);
}
unsigned hashmap_buckets(Hashmap *h) _pure_;
static inline unsigned ordered_hashmap_buckets(OrderedHashmap *h) {
        return hashmap_buckets((Hashmap*) h);
}

void *hashmap_iterate(Hashmap *h, Iterator *i, const void **key);
static inline void *ordered_hashmap_iterate(OrderedHashmap *h, Iterator *i, const void **key) {
        return hashmap_iterate((Hashmap*) h, i, key);
}

void hashmap_clear(Hashmap *h);
static inline void ordered_hashmap_clear(OrderedHashmap *h) {
        hashmap_clear((Hashmap*) h);
}
void hashmap_clear_free(Hashmap *h);
static inline void ordered_hashmap_clear_free(OrderedHashmap *h) {
        hashmap_clear_free((Hashmap*) h);
}
void hashmap_clear_free_free(Hashmap *h);
static inline void ordered_hashmap_clear_free_free(OrderedHashmap *h) {
        hashmap_clear_free_free((Hashmap*) h);
}

void *hashmap_steal_first(Hashmap *h);
static inline void *ordered_hashmap_steal_first(OrderedHashmap *h) {
        return hashmap_steal_first((Hashmap*) h);
}
void *hashmap_steal_first_key(Hashmap *h);
static inline void *ordered_hashmap_steal_first_key(OrderedHashmap *h) {
        return hashmap_steal_first_key((Hashmap*) h);
}
void *hashmap_first(Hashmap *h) _pure_;
static inline void *ordered_hashmap_first(OrderedHashmap *h) {
        return hashmap_first((Hashmap*) h);
}
void *hashmap_first_key(Hashmap *h) _pure_;
static inline void *ordered_hashmap_first_key(OrderedHashmap *h) {
        return hashmap_first_key((Hashmap*) h);
}

void *hashmap_next(Hashmap *h, const void *key);
static inline void *ordered_hashmap_next(OrderedHashmap *h, const void *key) {
        return hashmap_next((Hashmap*) h, key);
}

char **hashmap_get_strv(Hashmap *h);
static inline char **ordered_hashmap_get_strv(OrderedHashmap *h) {
        return hashmap_get_strv((Hashmap*) h);
}

#define HASHMAP_FOREACH(e, h, i) \
        for ((i) = ITERATOR_FIRST, (e) = hashmap_iterate((h), &(i), NULL); (e); (e) = hashmap_iterate((h), &(i), NULL))

#define ORDERED_HASHMAP_FOREACH(e, h, i) \
        for ((i) = ITERATOR_FIRST, (e) = ordered_hashmap_iterate((h), &(i), NULL); \
             (e); \
             (e) = ordered_hashmap_iterate((h), &(i), NULL))

#define HASHMAP_FOREACH_KEY(e, k, h, i) \
        for ((i) = ITERATOR_FIRST, (e) = hashmap_iterate((h), &(i), (const void**) &(k)); (e); (e) = hashmap_iterate((h), &(i), (const void**) &(k)))

#define ORDERED_HASHMAP_FOREACH_KEY(e, k, h, i) \
        for ((i) = ITERATOR_FIRST, (e) = ordered_hashmap_iterate((h), &(i), (const void**) &(k)); \
             (e); \
             (e) = ordered_hashmap_iterate((h), &(i), (const void**) &(k)))

DEFINE_TRIVIAL_CLEANUP_FUNC(Hashmap*, hashmap_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(Hashmap*, hashmap_free_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(Hashmap*, hashmap_free_free_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(OrderedHashmap*, ordered_hashmap_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(OrderedHashmap*, ordered_hashmap_free_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(OrderedHashmap*, ordered_hashmap_free_free_free);
#define _cleanup_hashmap_free_ _cleanup_(hashmap_freep)
#define _cleanup_hashmap_free_free_ _cleanup_(hashmap_free_freep)
#define _cleanup_hashmap_free_free_free_ _cleanup_(hashmap_free_free_freep)
#define _cleanup_ordered_hashmap_free_ _cleanup_(ordered_hashmap_freep)
#define _cleanup_ordered_hashmap_free_free_ _cleanup_(ordered_hashmap_free_freep)
#define _cleanup_ordered_hashmap_free_free_free_ _cleanup_(ordered_hashmap_free_free_freep)
