/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foohashmaphfoo
#define foohashmaphfoo

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

#include <stdbool.h>

/* Pretty straightforward hash table implementation. As a minor
 * optimization a NULL hashmap object will be treated as empty hashmap
 * for all read operations. That way it is not necessary to
 * instantiate an object for each Hashmap use. */

typedef struct Hashmap Hashmap;
typedef struct _IteratorStruct _IteratorStruct;
typedef _IteratorStruct* Iterator;

#define ITERATOR_FIRST ((Iterator) 0)
#define ITERATOR_LAST ((Iterator) -1)

typedef unsigned (*hash_func_t)(const void *p);
typedef int (*compare_func_t)(const void *a, const void *b);

unsigned string_hash_func(const void *p);
int string_compare_func(const void *a, const void *b);

unsigned trivial_hash_func(const void *p);
int trivial_compare_func(const void *a, const void *b);

Hashmap *hashmap_new(hash_func_t hash_func, compare_func_t compare_func);
void hashmap_free(Hashmap *h);
void hashmap_free_free(Hashmap *h);
Hashmap *hashmap_copy(Hashmap *h);
int hashmap_ensure_allocated(Hashmap **h, hash_func_t hash_func, compare_func_t compare_func);

int hashmap_put(Hashmap *h, const void *key, void *value);
int hashmap_replace(Hashmap *h, const void *key, void *value);
void* hashmap_get(Hashmap *h, const void *key);
void* hashmap_remove(Hashmap *h, const void *key);
void* hashmap_remove_value(Hashmap *h, const void *key, void *value);
int hashmap_remove_and_put(Hashmap *h, const void *old_key, const void *new_key, void *value);
int hashmap_remove_and_replace(Hashmap *h, const void *old_key, const void *new_key, void *value);

int hashmap_merge(Hashmap *h, Hashmap *other);
void hashmap_move(Hashmap *h, Hashmap *other);
int hashmap_move_one(Hashmap *h, Hashmap *other, const void *key);

unsigned hashmap_size(Hashmap *h);
bool hashmap_isempty(Hashmap *h);

void *hashmap_iterate(Hashmap *h, Iterator *i, const void **key);
void *hashmap_iterate_backwards(Hashmap *h, Iterator *i, const void **key);
void *hashmap_iterate_skip(Hashmap *h, const void *key, Iterator *i);

void hashmap_clear(Hashmap *h);
void *hashmap_steal_first(Hashmap *h);
void* hashmap_first(Hashmap *h);
void* hashmap_last(Hashmap *h);

#define HASHMAP_FOREACH(e, h, i) \
        for ((i) = ITERATOR_FIRST, (e) = hashmap_iterate((h), &(i), NULL); (e); (e) = hashmap_iterate((h), &(i), NULL))

#define HASHMAP_FOREACH_KEY(e, k, h, i) \
        for ((i) = ITERATOR_FIRST, (e) = hashmap_iterate((h), &(i), (const void**) &(k)); (e); (e) = hashmap_iterate((h), &(i), (const void**) &(k)))

#define HASHMAP_FOREACH_BACKWARDS(e, h, i) \
        for ((i) = ITERATOR_LAST, (e) = hashmap_iterate_backwards((h), &(i), NULL); (e); (e) = hashmap_iterate_backwards((h), &(i), NULL))

#endif
