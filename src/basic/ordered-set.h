/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

typedef struct OrderedSet OrderedSet;

static inline OrderedSet* ordered_set_new(const struct hash_ops *ops) {
        return (OrderedSet*) ordered_hashmap_new(ops);
}

static inline OrderedSet* ordered_set_free(OrderedSet *s) {
        ordered_hashmap_free((OrderedHashmap*) s);
        return NULL;
}

static inline OrderedSet* ordered_set_free_free(OrderedSet *s) {
        ordered_hashmap_free_free((OrderedHashmap*) s);
        return NULL;
}

static inline int ordered_set_put(OrderedSet *s, void *p) {
        return ordered_hashmap_put((OrderedHashmap*) s, p, p);
}

static inline bool ordered_set_isempty(OrderedSet *s) {
        return ordered_hashmap_isempty((OrderedHashmap*) s);
}

static inline bool ordered_set_iterate(OrderedSet *s, Iterator *i, void **value) {
        return ordered_hashmap_iterate((OrderedHashmap*) s, i, value, NULL);
}

#define ORDERED_SET_FOREACH(e, s, i)                                    \
        for ((i) = ITERATOR_FIRST; ordered_set_iterate((s), &(i), (void**)&(e)); )

DEFINE_TRIVIAL_CLEANUP_FUNC(OrderedSet*, ordered_set_free);

#define _cleanup_ordered_set_free_ _cleanup_(ordered_set_freep)
