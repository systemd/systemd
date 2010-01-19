/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

int set_put(Set *s, void *value) {
        return hashmap_put(MAKE_HASHMAP(s), value, value);
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

void *set_iterate(Set *s, void **state) {
        return hashmap_iterate(MAKE_HASHMAP(s), state, NULL);
}

void *set_iterate_backwards(Set *s, void **state) {
        return hashmap_iterate_backwards(MAKE_HASHMAP(s), state, NULL);
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
