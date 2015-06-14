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

#include "hashmap.h"
#include "macro.h"

Set *internal_set_new(const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS);
#define set_new(ops) internal_set_new(ops  HASHMAP_DEBUG_SRC_ARGS)


static inline void set_free(Set *s) {
        internal_hashmap_free(HASHMAP_BASE(s));
}

static inline void set_free_free(Set *s) {
        internal_hashmap_free_free(HASHMAP_BASE(s));
}

/* no set_free_free_free */

static inline Set *set_copy(Set *s) {
        return (Set*) internal_hashmap_copy(HASHMAP_BASE(s));
}

int internal_set_ensure_allocated(Set **s, const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS);
#define set_ensure_allocated(h, ops) internal_set_ensure_allocated(h, ops  HASHMAP_DEBUG_SRC_ARGS)

int set_put(Set *s, const void *key);
/* no set_update */
/* no set_replace */
static inline void *set_get(Set *s, void *key) {
        return internal_hashmap_get(HASHMAP_BASE(s), key);
}
/* no set_get2 */

static inline bool set_contains(Set *s, const void *key) {
        return internal_hashmap_contains(HASHMAP_BASE(s), key);
}

static inline void *set_remove(Set *s, const void *key) {
        return internal_hashmap_remove(HASHMAP_BASE(s), key);
}

/* no set_remove2 */
/* no set_remove_value */
int set_remove_and_put(Set *s, const void *old_key, const void *new_key);
/* no set_remove_and_replace */
int set_merge(Set *s, Set *other);

static inline int set_reserve(Set *h, unsigned entries_add) {
        return internal_hashmap_reserve(HASHMAP_BASE(h), entries_add);
}

static inline int set_move(Set *s, Set *other) {
        return internal_hashmap_move(HASHMAP_BASE(s), HASHMAP_BASE(other));
}

static inline int set_move_one(Set *s, Set *other, const void *key) {
        return internal_hashmap_move_one(HASHMAP_BASE(s), HASHMAP_BASE(other), key);
}

static inline unsigned set_size(Set *s) {
        return internal_hashmap_size(HASHMAP_BASE(s));
}

static inline bool set_isempty(Set *s) {
        return set_size(s) == 0;
}

static inline unsigned set_buckets(Set *s) {
        return internal_hashmap_buckets(HASHMAP_BASE(s));
}

bool set_iterate(Set *s, Iterator *i, void **value);

static inline void set_clear(Set *s) {
        internal_hashmap_clear(HASHMAP_BASE(s));
}

static inline void set_clear_free(Set *s) {
        internal_hashmap_clear_free(HASHMAP_BASE(s));
}

/* no set_clear_free_free */

static inline void *set_steal_first(Set *s) {
        return internal_hashmap_steal_first(HASHMAP_BASE(s));
}

/* no set_steal_first_key */
/* no set_first_key */

static inline void *set_first(Set *s) {
        return internal_hashmap_first(HASHMAP_BASE(s));
}

/* no set_next */

static inline char **set_get_strv(Set *s) {
        return internal_hashmap_get_strv(HASHMAP_BASE(s));
}

int set_consume(Set *s, void *value);
int set_put_strdup(Set *s, const char *p);
int set_put_strdupv(Set *s, char **l);

#define SET_FOREACH(e, s, i) \
        for ((i) = ITERATOR_FIRST; set_iterate((s), &(i), (void**)&(e)); )

DEFINE_TRIVIAL_CLEANUP_FUNC(Set*, set_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(Set*, set_free_free);

#define _cleanup_set_free_ _cleanup_(set_freep)
#define _cleanup_set_free_free_ _cleanup_(set_free_freep)
