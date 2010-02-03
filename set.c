/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include "set.h"
#include "hashmap.h"

#define MAKE_SET(h) ((Set*) (h))
#define MAKE_HASHMAP(s) ((Hashmap*) (s))

/* For now this is not much more than a wrapper around a hashmap */

Set *set_new(hash_func_t hash_func, compare_func_t compare_func) {
        return MAKE_SET(hashmap_new(hash_func, compare_func));
}

void set_free(Set* s) {
        hashmap_free(MAKE_HASHMAP(s));
}

int set_ensure_allocated(Set **s, hash_func_t hash_func, compare_func_t compare_func) {
        return hashmap_ensure_allocated((Hashmap**) s, hash_func, compare_func);
}

int set_put(Set *s, void *value) {
        return hashmap_put(MAKE_HASHMAP(s), value, value);
}

int set_replace(Set *s, void *value) {
        return hashmap_replace(MAKE_HASHMAP(s), value, value);
}

void *set_get(Set *s, void *value) {
        return hashmap_get(MAKE_HASHMAP(s), value);
}

void *set_remove(Set *s, void *value) {
        return hashmap_remove(MAKE_HASHMAP(s), value);
}

unsigned set_size(Set *s) {
        return hashmap_size(MAKE_HASHMAP(s));
}

bool set_isempty(Set *s) {
        return hashmap_isempty(MAKE_HASHMAP(s));
}

void *set_iterate(Set *s, Iterator *i) {
        return hashmap_iterate(MAKE_HASHMAP(s), i, NULL);
}

void *set_iterate_backwards(Set *s, Iterator *i) {
        return hashmap_iterate_backwards(MAKE_HASHMAP(s), i, NULL);
}

void *set_iterate_skip(Set *s, void *value, Iterator *i) {
        return hashmap_iterate_skip(MAKE_HASHMAP(s), value, i);
}

void *set_steal_first(Set *s) {
        return hashmap_steal_first(MAKE_HASHMAP(s));
}

void* set_first(Set *s) {
        return hashmap_first(MAKE_HASHMAP(s));
}

void* set_last(Set *s) {
        return hashmap_last(MAKE_HASHMAP(s));
}

int set_merge(Set *s, Set *other) {
        return hashmap_merge(MAKE_HASHMAP(s), MAKE_HASHMAP(other));
}

Set* set_copy(Set *s) {
        return MAKE_SET(hashmap_copy(MAKE_HASHMAP(s)));
}

void set_clear(Set *s) {
        hashmap_clear(MAKE_HASHMAP(s));
}
