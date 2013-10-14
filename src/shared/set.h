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

/* Pretty straightforward set implementation. Internally based on the
 * hashmap. That means that as a minor optimization a NULL set
 * object will be treated as empty set for all read
 * operations. That way it is not necessary to instantiate an object
 * for each set use. */

#include "hashmap.h"
#include "util.h"

typedef struct Set Set;

Set *set_new(hash_func_t hash_func, compare_func_t compare_func);
void set_free(Set* s);
void set_free_free(Set *s);

Set* set_copy(Set *s);
int set_ensure_allocated(Set **s, hash_func_t hash_func, compare_func_t compare_func);

int set_put(Set *s, void *value);
int set_consume(Set *s, void *value);
int set_replace(Set *s, void *value);
void *set_get(Set *s, void *value);
bool set_contains(Set *s, void *value);
void *set_remove(Set *s, void *value);
int set_remove_and_put(Set *s, void *old_value, void *new_value);

int set_merge(Set *s, Set *other);
void set_move(Set *s, Set *other);
int set_move_one(Set *s, Set *other, void *value);

unsigned set_size(Set *s);
bool set_isempty(Set *s);

void *set_iterate(Set *s, Iterator *i);
void *set_iterate_backwards(Set *s, Iterator *i);
void *set_iterate_skip(Set *s, void *value, Iterator *i);

void set_clear(Set *s);
void set_clear_free(Set *s);

void *set_steal_first(Set *s);
void* set_first(Set *s);
void* set_last(Set *s);

char **set_get_strv(Set *s);

#define SET_FOREACH(e, s, i) \
        for ((i) = ITERATOR_FIRST, (e) = set_iterate((s), &(i)); (e); (e) = set_iterate((s), &(i)))

#define SET_FOREACH_BACKWARDS(e, s, i) \
        for ((i) = ITERATOR_LAST, (e) = set_iterate_backwards((s), &(i)); (e); (e) = set_iterate_backwards((s), &(i)))

DEFINE_TRIVIAL_CLEANUP_FUNC(Set*, set_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(Set*, set_free_free);
#define _cleanup_set_free_ _cleanup_(set_freep)
#define _cleanup_set_free_free_ _cleanup_(set_free_freep)
