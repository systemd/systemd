/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2014 Michal Schmidt

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

/*
 * A hash table implementation. As a minor optimization a NULL hashmap object
 * will be treated as empty hashmap for all read operations. That way it is not
 * necessary to instantiate an object for each Hashmap use.
 *
 * If ENABLE_DEBUG_HASHMAP is defined (by configuring with --enable-debug=hashmap),
 * the implemention will:
 * - store extra data for debugging and statistics (see tools/gdb-sd_dump_hashmaps.py)
 * - perform extra checks for invalid use of iterators
 */

#define HASH_KEY_SIZE 16

/* The base type for all hashmap and set types. Many functions in the
 * implementation take (HashmapBase*) parameters and are run-time polymorphic,
 * though the API is not meant to be polymorphic (do not call functions
 * internal_*() directly). */
typedef struct HashmapBase HashmapBase;

/* Specific hashmap/set types */
typedef struct Hashmap Hashmap;               /* Maps keys to values */
typedef struct OrderedHashmap OrderedHashmap; /* Like Hashmap, but also remembers entry insertion order */
typedef struct Set Set;                       /* Stores just keys */

/* Ideally the Iterator would be an opaque struct, but it is instantiated
 * by hashmap users, so the definition has to be here. Do not use its fields
 * directly. */
typedef struct {
        unsigned idx;         /* index of an entry to be iterated next */
        const void *next_key; /* expected value of that entry's key pointer */
#ifdef ENABLE_DEBUG_HASHMAP
        unsigned put_count;   /* hashmap's put_count recorded at start of iteration */
        unsigned rem_count;   /* hashmap's rem_count in previous iteration */
        unsigned prev_idx;    /* idx in previous iteration */
#endif
} Iterator;

#define _IDX_ITERATOR_FIRST (UINT_MAX - 1)
#define ITERATOR_FIRST ((Iterator) { .idx = _IDX_ITERATOR_FIRST, .next_key = NULL })

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

/* Macros for type checking */
#define PTR_COMPATIBLE_WITH_HASHMAP_BASE(h) \
        (__builtin_types_compatible_p(typeof(h), HashmapBase*) || \
         __builtin_types_compatible_p(typeof(h), Hashmap*) || \
         __builtin_types_compatible_p(typeof(h), OrderedHashmap*) || \
         __builtin_types_compatible_p(typeof(h), Set*))

#define PTR_COMPATIBLE_WITH_PLAIN_HASHMAP(h) \
        (__builtin_types_compatible_p(typeof(h), Hashmap*) || \
         __builtin_types_compatible_p(typeof(h), OrderedHashmap*)) \

#define HASHMAP_BASE(h) \
        __builtin_choose_expr(PTR_COMPATIBLE_WITH_HASHMAP_BASE(h), \
                (HashmapBase*)(h), \
                (void)0)

#define PLAIN_HASHMAP(h) \
        __builtin_choose_expr(PTR_COMPATIBLE_WITH_PLAIN_HASHMAP(h), \
                (Hashmap*)(h), \
                (void)0)

#ifdef ENABLE_DEBUG_HASHMAP
# define HASHMAP_DEBUG_PARAMS , const char *func, const char *file, int line
# define HASHMAP_DEBUG_SRC_ARGS   , __func__, __FILE__, __LINE__
# define HASHMAP_DEBUG_PASS_ARGS   , func, file, line
#else
# define HASHMAP_DEBUG_PARAMS
# define HASHMAP_DEBUG_SRC_ARGS
# define HASHMAP_DEBUG_PASS_ARGS
#endif

Hashmap *internal_hashmap_new(const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS);
OrderedHashmap *internal_ordered_hashmap_new(const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS);
#define hashmap_new(ops) internal_hashmap_new(ops  HASHMAP_DEBUG_SRC_ARGS)
#define ordered_hashmap_new(ops) internal_ordered_hashmap_new(ops  HASHMAP_DEBUG_SRC_ARGS)

void internal_hashmap_free(HashmapBase *h);
static inline void hashmap_free(Hashmap *h) {
        internal_hashmap_free(HASHMAP_BASE(h));
}
static inline void ordered_hashmap_free(OrderedHashmap *h) {
        internal_hashmap_free(HASHMAP_BASE(h));
}

void internal_hashmap_free_free(HashmapBase *h);
static inline void hashmap_free_free(Hashmap *h) {
        internal_hashmap_free_free(HASHMAP_BASE(h));
}
static inline void ordered_hashmap_free_free(OrderedHashmap *h) {
        internal_hashmap_free_free(HASHMAP_BASE(h));
}

void hashmap_free_free_free(Hashmap *h);
static inline void ordered_hashmap_free_free_free(OrderedHashmap *h) {
        hashmap_free_free_free(PLAIN_HASHMAP(h));
}

HashmapBase *internal_hashmap_copy(HashmapBase *h);
static inline Hashmap *hashmap_copy(Hashmap *h) {
        return (Hashmap*) internal_hashmap_copy(HASHMAP_BASE(h));
}
static inline OrderedHashmap *ordered_hashmap_copy(OrderedHashmap *h) {
        return (OrderedHashmap*) internal_hashmap_copy(HASHMAP_BASE(h));
}

int internal_hashmap_ensure_allocated(Hashmap **h, const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS);
int internal_ordered_hashmap_ensure_allocated(OrderedHashmap **h, const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS);
#define hashmap_ensure_allocated(h, ops) internal_hashmap_ensure_allocated(h, ops  HASHMAP_DEBUG_SRC_ARGS)
#define ordered_hashmap_ensure_allocated(h, ops) internal_ordered_hashmap_ensure_allocated(h, ops  HASHMAP_DEBUG_SRC_ARGS)

int hashmap_put(Hashmap *h, const void *key, void *value);
static inline int ordered_hashmap_put(OrderedHashmap *h, const void *key, void *value) {
        return hashmap_put(PLAIN_HASHMAP(h), key, value);
}

int hashmap_update(Hashmap *h, const void *key, void *value);
static inline int ordered_hashmap_update(OrderedHashmap *h, const void *key, void *value) {
        return hashmap_update(PLAIN_HASHMAP(h), key, value);
}

int hashmap_replace(Hashmap *h, const void *key, void *value);
static inline int ordered_hashmap_replace(OrderedHashmap *h, const void *key, void *value) {
        return hashmap_replace(PLAIN_HASHMAP(h), key, value);
}

void *internal_hashmap_get(HashmapBase *h, const void *key);
static inline void *hashmap_get(Hashmap *h, const void *key) {
        return internal_hashmap_get(HASHMAP_BASE(h), key);
}
static inline void *ordered_hashmap_get(OrderedHashmap *h, const void *key) {
        return internal_hashmap_get(HASHMAP_BASE(h), key);
}

void *hashmap_get2(Hashmap *h, const void *key, void **rkey);
static inline void *ordered_hashmap_get2(OrderedHashmap *h, const void *key, void **rkey) {
        return hashmap_get2(PLAIN_HASHMAP(h), key, rkey);
}

bool internal_hashmap_contains(HashmapBase *h, const void *key);
static inline bool hashmap_contains(Hashmap *h, const void *key) {
        return internal_hashmap_contains(HASHMAP_BASE(h), key);
}
static inline bool ordered_hashmap_contains(OrderedHashmap *h, const void *key) {
        return internal_hashmap_contains(HASHMAP_BASE(h), key);
}

void *internal_hashmap_remove(HashmapBase *h, const void *key);
static inline void *hashmap_remove(Hashmap *h, const void *key) {
        return internal_hashmap_remove(HASHMAP_BASE(h), key);
}
static inline void *ordered_hashmap_remove(OrderedHashmap *h, const void *key) {
        return internal_hashmap_remove(HASHMAP_BASE(h), key);
}

void *hashmap_remove2(Hashmap *h, const void *key, void **rkey);
static inline void *ordered_hashmap_remove2(OrderedHashmap *h, const void *key, void **rkey) {
        return hashmap_remove2(PLAIN_HASHMAP(h), key, rkey);
}

void *hashmap_remove_value(Hashmap *h, const void *key, void *value);
static inline void *ordered_hashmap_remove_value(OrderedHashmap *h, const void *key, void *value) {
        return hashmap_remove_value(PLAIN_HASHMAP(h), key, value);
}

int hashmap_remove_and_put(Hashmap *h, const void *old_key, const void *new_key, void *value);
static inline int ordered_hashmap_remove_and_put(OrderedHashmap *h, const void *old_key, const void *new_key, void *value) {
        return hashmap_remove_and_put(PLAIN_HASHMAP(h), old_key, new_key, value);
}

int hashmap_remove_and_replace(Hashmap *h, const void *old_key, const void *new_key, void *value);
static inline int ordered_hashmap_remove_and_replace(OrderedHashmap *h, const void *old_key, const void *new_key, void *value) {
        return hashmap_remove_and_replace(PLAIN_HASHMAP(h), old_key, new_key, value);
}

/* Since merging data from a OrderedHashmap into a Hashmap or vice-versa
 * should just work, allow this by having looser type-checking here. */
int internal_hashmap_merge(Hashmap *h, Hashmap *other);
#define hashmap_merge(h, other) internal_hashmap_merge(PLAIN_HASHMAP(h), PLAIN_HASHMAP(other))
#define ordered_hashmap_merge(h, other) hashmap_merge(h, other)

int internal_hashmap_reserve(HashmapBase *h, unsigned entries_add);
static inline int hashmap_reserve(Hashmap *h, unsigned entries_add) {
        return internal_hashmap_reserve(HASHMAP_BASE(h), entries_add);
}
static inline int ordered_hashmap_reserve(OrderedHashmap *h, unsigned entries_add) {
        return internal_hashmap_reserve(HASHMAP_BASE(h), entries_add);
}

int internal_hashmap_move(HashmapBase *h, HashmapBase *other);
/* Unlike hashmap_merge, hashmap_move does not allow mixing the types. */
static inline int hashmap_move(Hashmap *h, Hashmap *other) {
        return internal_hashmap_move(HASHMAP_BASE(h), HASHMAP_BASE(other));
}
static inline int ordered_hashmap_move(OrderedHashmap *h, OrderedHashmap *other) {
        return internal_hashmap_move(HASHMAP_BASE(h), HASHMAP_BASE(other));
}

int internal_hashmap_move_one(HashmapBase *h, HashmapBase *other, const void *key);
static inline int hashmap_move_one(Hashmap *h, Hashmap *other, const void *key) {
        return internal_hashmap_move_one(HASHMAP_BASE(h), HASHMAP_BASE(other), key);
}
static inline int ordered_hashmap_move_one(OrderedHashmap *h, OrderedHashmap *other, const void *key) {
        return internal_hashmap_move_one(HASHMAP_BASE(h), HASHMAP_BASE(other), key);
}

unsigned internal_hashmap_size(HashmapBase *h) _pure_;
static inline unsigned hashmap_size(Hashmap *h) {
        return internal_hashmap_size(HASHMAP_BASE(h));
}
static inline unsigned ordered_hashmap_size(OrderedHashmap *h) {
        return internal_hashmap_size(HASHMAP_BASE(h));
}

static inline bool hashmap_isempty(Hashmap *h) {
        return hashmap_size(h) == 0;
}
static inline bool ordered_hashmap_isempty(OrderedHashmap *h) {
        return ordered_hashmap_size(h) == 0;
}

unsigned internal_hashmap_buckets(HashmapBase *h) _pure_;
static inline unsigned hashmap_buckets(Hashmap *h) {
        return internal_hashmap_buckets(HASHMAP_BASE(h));
}
static inline unsigned ordered_hashmap_buckets(OrderedHashmap *h) {
        return internal_hashmap_buckets(HASHMAP_BASE(h));
}

void *internal_hashmap_iterate(HashmapBase *h, Iterator *i, const void **key);
static inline void *hashmap_iterate(Hashmap *h, Iterator *i, const void **key) {
        return internal_hashmap_iterate(HASHMAP_BASE(h), i, key);
}
static inline void *ordered_hashmap_iterate(OrderedHashmap *h, Iterator *i, const void **key) {
        return internal_hashmap_iterate(HASHMAP_BASE(h), i, key);
}

void internal_hashmap_clear(HashmapBase *h);
static inline void hashmap_clear(Hashmap *h) {
        internal_hashmap_clear(HASHMAP_BASE(h));
}
static inline void ordered_hashmap_clear(OrderedHashmap *h) {
        internal_hashmap_clear(HASHMAP_BASE(h));
}

void internal_hashmap_clear_free(HashmapBase *h);
static inline void hashmap_clear_free(Hashmap *h) {
        internal_hashmap_clear_free(HASHMAP_BASE(h));
}
static inline void ordered_hashmap_clear_free(OrderedHashmap *h) {
        internal_hashmap_clear_free(HASHMAP_BASE(h));
}

void hashmap_clear_free_free(Hashmap *h);
static inline void ordered_hashmap_clear_free_free(OrderedHashmap *h) {
        hashmap_clear_free_free(PLAIN_HASHMAP(h));
}

/*
 * Note about all *_first*() functions
 *
 * For plain Hashmaps and Sets the order of entries is undefined.
 * The functions find whatever entry is first in the implementation
 * internal order.
 *
 * Only for OrderedHashmaps the order is well defined and finding
 * the first entry is O(1).
 */

void *internal_hashmap_steal_first(HashmapBase *h);
static inline void *hashmap_steal_first(Hashmap *h) {
        return internal_hashmap_steal_first(HASHMAP_BASE(h));
}
static inline void *ordered_hashmap_steal_first(OrderedHashmap *h) {
        return internal_hashmap_steal_first(HASHMAP_BASE(h));
}

void *internal_hashmap_steal_first_key(HashmapBase *h);
static inline void *hashmap_steal_first_key(Hashmap *h) {
        return internal_hashmap_steal_first_key(HASHMAP_BASE(h));
}
static inline void *ordered_hashmap_steal_first_key(OrderedHashmap *h) {
        return internal_hashmap_steal_first_key(HASHMAP_BASE(h));
}

void *internal_hashmap_first_key(HashmapBase *h) _pure_;
static inline void *hashmap_first_key(Hashmap *h) {
        return internal_hashmap_first_key(HASHMAP_BASE(h));
}
static inline void *ordered_hashmap_first_key(OrderedHashmap *h) {
        return internal_hashmap_first_key(HASHMAP_BASE(h));
}

void *internal_hashmap_first(HashmapBase *h) _pure_;
static inline void *hashmap_first(Hashmap *h) {
        return internal_hashmap_first(HASHMAP_BASE(h));
}
static inline void *ordered_hashmap_first(OrderedHashmap *h) {
        return internal_hashmap_first(HASHMAP_BASE(h));
}

/* no hashmap_next */
void *ordered_hashmap_next(OrderedHashmap *h, const void *key);

char **internal_hashmap_get_strv(HashmapBase *h);
static inline char **hashmap_get_strv(Hashmap *h) {
        return internal_hashmap_get_strv(HASHMAP_BASE(h));
}
static inline char **ordered_hashmap_get_strv(OrderedHashmap *h) {
        return internal_hashmap_get_strv(HASHMAP_BASE(h));
}

/*
 * Hashmaps are iterated in unpredictable order.
 * OrderedHashmaps are an exception to this. They are iterated in the order
 * the entries were inserted.
 * It is safe to remove the current entry.
 */
#define HASHMAP_FOREACH(e, h, i) \
        for ((i) = ITERATOR_FIRST, (e) = hashmap_iterate((h), &(i), NULL); \
             (e); \
             (e) = hashmap_iterate((h), &(i), NULL))

#define ORDERED_HASHMAP_FOREACH(e, h, i) \
        for ((i) = ITERATOR_FIRST, (e) = ordered_hashmap_iterate((h), &(i), NULL); \
             (e); \
             (e) = ordered_hashmap_iterate((h), &(i), NULL))

#define HASHMAP_FOREACH_KEY(e, k, h, i) \
        for ((i) = ITERATOR_FIRST, (e) = hashmap_iterate((h), &(i), (const void**) &(k)); \
             (e); \
             (e) = hashmap_iterate((h), &(i), (const void**) &(k)))

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
