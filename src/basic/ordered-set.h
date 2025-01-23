/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "hashmap.h"

typedef struct OrderedSet OrderedSet;

static inline OrderedSet* _ordered_set_new(const struct hash_ops *ops  HASHMAP_DEBUG_PARAMS) {
        return (OrderedSet*) _ordered_hashmap_new(ops  HASHMAP_DEBUG_PASS_ARGS);
}
#define ordered_set_new(ops) _ordered_set_new(ops  HASHMAP_DEBUG_SRC_ARGS)

int _ordered_set_ensure_allocated(OrderedSet **s, const struct hash_ops *ops  HASHMAP_DEBUG_PARAMS);
#define ordered_set_ensure_allocated(s, ops) _ordered_set_ensure_allocated(s, ops  HASHMAP_DEBUG_SRC_ARGS)

int _ordered_set_ensure_put(OrderedSet **s, const struct hash_ops *ops, void *p  HASHMAP_DEBUG_PARAMS);
#define ordered_set_ensure_put(s, hash_ops, key) _ordered_set_ensure_put(s, hash_ops, key  HASHMAP_DEBUG_SRC_ARGS)

static inline void ordered_set_clear(OrderedSet *s) {
        return ordered_hashmap_clear((OrderedHashmap*) s);
}

static inline OrderedSet* ordered_set_free(OrderedSet *s) {
        return (OrderedSet*) ordered_hashmap_free((OrderedHashmap*) s);
}

static inline int ordered_set_contains(OrderedSet *s, const void *p) {
        return ordered_hashmap_contains((OrderedHashmap*) s, p);
}

static inline int ordered_set_put(OrderedSet *s, void *p) {
        return ordered_hashmap_put((OrderedHashmap*) s, p, p);
}

static inline void *ordered_set_get(OrderedSet *s, const void *p) {
        return ordered_hashmap_get((OrderedHashmap*) s, p);
}

static inline unsigned ordered_set_size(OrderedSet *s) {
        return ordered_hashmap_size((OrderedHashmap*) s);
}

static inline bool ordered_set_isempty(OrderedSet *s) {
        return ordered_hashmap_isempty((OrderedHashmap*) s);
}

static inline bool ordered_set_iterate(OrderedSet *s, Iterator *i, void **value) {
        return ordered_hashmap_iterate((OrderedHashmap*) s, i, value, NULL);
}

static inline void* ordered_set_remove(OrderedSet *s, void *p) {
        return ordered_hashmap_remove((OrderedHashmap*) s, p);
}

static inline void* ordered_set_first(OrderedSet *s) {
        return ordered_hashmap_first((OrderedHashmap*) s);
}

static inline void* ordered_set_steal_first(OrderedSet *s) {
        return ordered_hashmap_steal_first((OrderedHashmap*) s);
}

static inline char** ordered_set_get_strv(OrderedSet *s) {
        return _hashmap_get_strv(HASHMAP_BASE((OrderedHashmap*) s));
}

static inline int ordered_set_reserve(OrderedSet *s, unsigned entries_add) {
        return ordered_hashmap_reserve((OrderedHashmap*) s, entries_add);
}

int ordered_set_consume(OrderedSet *s, void *p);
int _ordered_set_put_strdup(OrderedSet **s, const char *p  HASHMAP_DEBUG_PARAMS);
#define ordered_set_put_strdup(s, p) _ordered_set_put_strdup(s, p  HASHMAP_DEBUG_SRC_ARGS)
int _ordered_set_put_strdupv(OrderedSet **s, char **l  HASHMAP_DEBUG_PARAMS);
#define ordered_set_put_strdupv(s, l) _ordered_set_put_strdupv(s, l  HASHMAP_DEBUG_SRC_ARGS)
int ordered_set_put_string_set(OrderedSet **s, OrderedSet *l);
void ordered_set_print(FILE *f, const char *field, OrderedSet *s);

#define _ORDERED_SET_FOREACH(e, s, i) \
        for (Iterator i = ITERATOR_FIRST; ordered_set_iterate((s), &i, (void**)&(e)); )
#define ORDERED_SET_FOREACH(e, s) \
        _ORDERED_SET_FOREACH(e, s, UNIQ_T(i, UNIQ))

#define ordered_set_clear_with_destructor(s, f)                 \
        ({                                                      \
                OrderedSet *_s = (s);                           \
                void *_item;                                    \
                while ((_item = ordered_set_steal_first(_s)))   \
                        f(_item);                               \
                _s;                                             \
        })
#define ordered_set_free_with_destructor(s, f)                  \
        ordered_set_free(ordered_set_clear_with_destructor(s, f))

DEFINE_TRIVIAL_CLEANUP_FUNC(OrderedSet*, ordered_set_free);

#define _cleanup_ordered_set_free_ _cleanup_(ordered_set_freep)
