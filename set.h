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
Set* set_copy(Set *s);
void set_free(Set* s);

int set_put(Set *s, void *value);
void *set_get(Set *s, void *value);
void *set_remove(Set *s, void *value);

int set_merge(Set *s, Set *other);

unsigned set_size(Set *s);
bool set_isempty(Set *s);

void *set_iterate(Set *s, void **state);
void *set_iterate_backwards(Set *s, void **state);

void set_clear(Set *s);
void *set_steal_first(Set *s);
void* set_first(Set *s);
void* set_last(Set *s);

#define SET_FOREACH(e, s, state) \
        for ((state) = NULL, (e) = set_iterate((s), &(state)); (e); (e) = set_iterate((s), &(state)))

#define SET_FOREACH_BACKWARDS(e, s, state) \
        for ((state) = NULL, (e) = set_iterate_backwards((s), &(state)); (e); (e) = set_iterate_backwards((s), &(state)))

#endif
