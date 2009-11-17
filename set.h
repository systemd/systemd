/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foosethfoo
#define foosethfoo

/* Pretty straightforward set implementation. Internally based on the
 * hashmap. That means that as a minor optimization a NULL set
 * object will be treated as empty set for all read
 * operations. That way it is not necessary to instantiate an object
 * for each set use. */

#include "hashmap.h"

typedef struct Set Set;

Set *set_new(hash_func_t hash_func, compare_func_t compare_func);
void set_free(Set* set);

int set_put(Set *s, void *value);
void *set_get(Set *s, void *value);
void *set_remove(Set *s, void *value);

unsigned set_size(Set *s);
bool set_isempty(Set *s);

void *set_iterate(Set *h, void **state);
void *set_iterate_backwards(Set *h, void **state);

void *set_steal_first(Set *h);
void* set_first(Set *h);
void* set_last(Set *h);

#define SET_FOREACH(e, s, state) \
        for ((state) = NULL, (e) = set_iterate((s), &(state)); (e); (e) = set_iterate((s), &(state)))

#define SET_FOREACH_BACKWARDS(e, s, state) \
        for ((state) = NULL, (e) = set_iterate_backwards((s), &(state)); (e); (e) = set_iterate_backwards((s), &(state)))

#endif
