/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foohashmaphfoo
#define foohashmaphfoo

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
Hashmap *hashmap_copy(Hashmap *h);
int hashmap_ensure_allocated(Hashmap **h, hash_func_t hash_func, compare_func_t compare_func);

int hashmap_put(Hashmap *h, const void *key, void *value);
int hashmap_replace(Hashmap *h, const void *key, void *value);
void* hashmap_get(Hashmap *h, const void *key);
void* hashmap_remove(Hashmap *h, const void *key);
void* hashmap_remove_value(Hashmap *h, const void *key, void *value);

int hashmap_merge(Hashmap *h, Hashmap *other);

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
        for ((i) = ITERATE_LAST, (e) = hashmap_iterate_backwards((h), &(i), NULL); (e); (e) = hashmap_iterate_backwards((h), &(i), NULL))

#endif
