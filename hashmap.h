/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foohashmaphfoo
#define foohashmaphfoo

#include <stdbool.h>

/* Pretty straightforward hash table implementation. As a minor
 * optimization a NULL hashmap object will be treated as empty hashmap
 * for all read operations. That way it is not necessary to
 * instantiate an object for each Hashmap use. */

typedef struct Hashmap Hashmap;

typedef unsigned (*hash_func_t)(const void *p);
typedef int (*compare_func_t)(const void *a, const void *b);

unsigned string_hash_func(const void *p);
int string_compare_func(const void *a, const void *b);

unsigned trivial_hash_func(const void *p);
int trivial_compare_func(const void *a, const void *b);

Hashmap *hashmap_new(hash_func_t hash_func, compare_func_t compare_func);
void hashmap_free(Hashmap *h);
Hashmap *hashmap_copy(Hashmap *h);

int hashmap_put(Hashmap *h, const void *key, void *value);
int hashmap_replace(Hashmap *h, const void *key, void *value);
void* hashmap_get(Hashmap *h, const void *key);
void* hashmap_remove(Hashmap *h, const void *key);
void* hashmap_remove_value(Hashmap *h, const void *key, void *value);

int hashmap_merge(Hashmap *h, Hashmap *other);

unsigned hashmap_size(Hashmap *h);
bool hashmap_isempty(Hashmap *h);

void *hashmap_iterate(Hashmap *h, void **state, const void **key);
void *hashmap_iterate_backwards(Hashmap *h, void **state, const void **key);

void hashmap_clear(Hashmap *h);
void *hashmap_steal_first(Hashmap *h);
void* hashmap_first(Hashmap *h);
void* hashmap_last(Hashmap *h);

#define HASHMAP_FOREACH(e, h, state) \
        for ((state) = NULL, (e) = hashmap_iterate((h), &(state), NULL); (e); (e) = hashmap_iterate((h), &(state), NULL))

#define HASHMAP_FOREACH_KEY(e, k, h, state) \
        for ((state) = NULL, (e) = hashmap_iterate((h), &(state), (const void**) &(k)); (e); (e) = hashmap_iterate((h), &(state), (const void**) &(k)))

#define HASHMAP_FOREACH_BACKWARDS(e, h, state) \
        for ((state) = NULL, (e) = hashmap_iterate_backwards((h), &(state), NULL); (e); (e) = hashmap_iterate_backwards((h), &(state), NULL))

#endif
