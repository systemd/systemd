/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fnmatch.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "macro.h"
#include "memory-util.h"
#include "mempool.h"
#include "missing_syscall.h"
#include "process-util.h"
#include "random-util.h"
#include "set.h"
#include "siphash24.h"
#include "string-util.h"
#include "strv.h"

#if ENABLE_DEBUG_HASHMAP
#include "list.h"
#endif

/*
 * Implementation of hashmaps.
 * Addressing: open
 *   - uses less RAM compared to closed addressing (chaining), because
 *     our entries are small (especially in Sets, which tend to contain
 *     the majority of entries in systemd).
 * Collision resolution: Robin Hood
 *   - tends to equalize displacement of entries from their optimal buckets.
 * Probe sequence: linear
 *   - though theoretically worse than random probing/uniform hashing/double
 *     hashing, it is good for cache locality.
 *
 * References:
 * Celis, P. 1986. Robin Hood Hashing.
 * Ph.D. Dissertation. University of Waterloo, Waterloo, Ont., Canada, Canada.
 * https://cs.uwaterloo.ca/research/tr/1986/CS-86-14.pdf
 * - The results are derived for random probing. Suggests deletion with
 *   tombstones and two mean-centered search methods. None of that works
 *   well for linear probing.
 *
 * Janson, S. 2005. Individual displacements for linear probing hashing with different insertion policies.
 * ACM Trans. Algorithms 1, 2 (October 2005), 177-213.
 * DOI=10.1145/1103963.1103964 http://doi.acm.org/10.1145/1103963.1103964
 * http://www.math.uu.se/~svante/papers/sj157.pdf
 * - Applies to Robin Hood with linear probing. Contains remarks on
 *   the unsuitability of mean-centered search with linear probing.
 *
 * Viola, A. 2005. Exact distribution of individual displacements in linear probing hashing.
 * ACM Trans. Algorithms 1, 2 (October 2005), 214-242.
 * DOI=10.1145/1103963.1103965 http://doi.acm.org/10.1145/1103963.1103965
 * - Similar to Janson. Note that Viola writes about C_{m,n} (number of probes
 *   in a successful search), and Janson writes about displacement. C = d + 1.
 *
 * Goossaert, E. 2013. Robin Hood hashing: backward shift deletion.
 * http://codecapsule.com/2013/11/17/robin-hood-hashing-backward-shift-deletion/
 * - Explanation of backward shift deletion with pictures.
 *
 * Khuong, P. 2013. The Other Robin Hood Hashing.
 * http://www.pvk.ca/Blog/2013/11/26/the-other-robin-hood-hashing/
 * - Short summary of random vs. linear probing, and tombstones vs. backward shift.
 */

/*
 * XXX Ideas for improvement:
 * For unordered hashmaps, randomize iteration order, similarly to Perl:
 * http://blog.booking.com/hardening-perls-hash-function.html
 */

/* INV_KEEP_FREE = 1 / (1 - max_load_factor)
 * e.g. 1 / (1 - 0.8) = 5 ... keep one fifth of the buckets free. */
#define INV_KEEP_FREE            5U

/* Fields common to entries of all hashmap/set types */
struct hashmap_base_entry {
        const void *key;
};

/* Entry types for specific hashmap/set types
 * hashmap_base_entry must be at the beginning of each entry struct. */

struct plain_hashmap_entry {
        struct hashmap_base_entry b;
        void *value;
};

struct ordered_hashmap_entry {
        struct plain_hashmap_entry p;
        unsigned iterate_next, iterate_previous;
};

struct set_entry {
        struct hashmap_base_entry b;
};

/* In several functions it is advantageous to have the hash table extended
 * virtually by a couple of additional buckets. We reserve special index values
 * for these "swap" buckets. */
#define _IDX_SWAP_BEGIN     (UINT_MAX - 3)
#define IDX_PUT             (_IDX_SWAP_BEGIN + 0)
#define IDX_TMP             (_IDX_SWAP_BEGIN + 1)
#define _IDX_SWAP_END       (_IDX_SWAP_BEGIN + 2)

#define IDX_FIRST           (UINT_MAX - 1) /* special index for freshly initialized iterators */
#define IDX_NIL             UINT_MAX       /* special index value meaning "none" or "end" */

assert_cc(IDX_FIRST == _IDX_SWAP_END);
assert_cc(IDX_FIRST == _IDX_ITERATOR_FIRST);

/* Storage space for the "swap" buckets.
 * All entry types can fit into an ordered_hashmap_entry. */
struct swap_entries {
        struct ordered_hashmap_entry e[_IDX_SWAP_END - _IDX_SWAP_BEGIN];
};

/* Distance from Initial Bucket */
typedef uint8_t dib_raw_t;
#define DIB_RAW_OVERFLOW ((dib_raw_t)0xfdU)   /* indicates DIB value is greater than representable */
#define DIB_RAW_REHASH   ((dib_raw_t)0xfeU)   /* entry yet to be rehashed during in-place resize */
#define DIB_RAW_FREE     ((dib_raw_t)0xffU)   /* a free bucket */
#define DIB_RAW_INIT     ((char)DIB_RAW_FREE) /* a byte to memset a DIB store with when initializing */

#define DIB_FREE UINT_MAX

#if ENABLE_DEBUG_HASHMAP
struct hashmap_debug_info {
        LIST_FIELDS(struct hashmap_debug_info, debug_list);
        unsigned max_entries;  /* high watermark of n_entries */

        /* who allocated this hashmap */
        int line;
        const char *file;
        const char *func;

        /* fields to detect modification while iterating */
        unsigned put_count;    /* counts puts into the hashmap */
        unsigned rem_count;    /* counts removals from hashmap */
        unsigned last_rem_idx; /* remembers last removal index */
};

/* Tracks all existing hashmaps. Get at it from gdb. See sd_dump_hashmaps.py */
static LIST_HEAD(struct hashmap_debug_info, hashmap_debug_list);
static pthread_mutex_t hashmap_debug_list_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

enum HashmapType {
        HASHMAP_TYPE_PLAIN,
        HASHMAP_TYPE_ORDERED,
        HASHMAP_TYPE_SET,
        _HASHMAP_TYPE_MAX
};

struct _packed_ indirect_storage {
        void *storage;                     /* where buckets and DIBs are stored */
        uint8_t  hash_key[HASH_KEY_SIZE];  /* hash key; changes during resize */

        unsigned n_entries;                /* number of stored entries */
        unsigned n_buckets;                /* number of buckets */

        unsigned idx_lowest_entry;         /* Index below which all buckets are free.
                                              Makes "while (hashmap_steal_first())" loops
                                              O(n) instead of O(n^2) for unordered hashmaps. */
        uint8_t  _pad[3];                  /* padding for the whole HashmapBase */
        /* The bitfields in HashmapBase complete the alignment of the whole thing. */
};

struct direct_storage {
        /* This gives us 39 bytes on 64bit, or 35 bytes on 32bit.
         * That's room for 4 set_entries + 4 DIB bytes + 3 unused bytes on 64bit,
         *              or 7 set_entries + 7 DIB bytes + 0 unused bytes on 32bit. */
        uint8_t storage[sizeof(struct indirect_storage)];
};

#define DIRECT_BUCKETS(entry_t) \
        (sizeof(struct direct_storage) / (sizeof(entry_t) + sizeof(dib_raw_t)))

/* We should be able to store at least one entry directly. */
assert_cc(DIRECT_BUCKETS(struct ordered_hashmap_entry) >= 1);

/* We have 3 bits for n_direct_entries. */
assert_cc(DIRECT_BUCKETS(struct set_entry) < (1 << 3));

/* Hashmaps with directly stored entries all use this shared hash key.
 * It's no big deal if the key is guessed, because there can be only
 * a handful of directly stored entries in a hashmap. When a hashmap
 * outgrows direct storage, it gets its own key for indirect storage. */
static uint8_t shared_hash_key[HASH_KEY_SIZE];

/* Fields that all hashmap/set types must have */
struct HashmapBase {
        const struct hash_ops *hash_ops;  /* hash and compare ops to use */

        union _packed_ {
                struct indirect_storage indirect; /* if  has_indirect */
                struct direct_storage direct;     /* if !has_indirect */
        };

        enum HashmapType type:2;     /* HASHMAP_TYPE_* */
        bool has_indirect:1;         /* whether indirect storage is used */
        unsigned n_direct_entries:3; /* Number of entries in direct storage.
                                      * Only valid if !has_indirect. */
        bool from_pool:1;            /* whether was allocated from mempool */
        bool dirty:1;                /* whether dirtied since last iterated_cache_get() */
        bool cached:1;               /* whether this hashmap is being cached */

#if ENABLE_DEBUG_HASHMAP
        struct hashmap_debug_info debug;
#endif
};

/* Specific hash types
 * HashmapBase must be at the beginning of each hashmap struct. */

struct Hashmap {
        struct HashmapBase b;
};

struct OrderedHashmap {
        struct HashmapBase b;
        unsigned iterate_list_head, iterate_list_tail;
};

struct Set {
        struct HashmapBase b;
};

typedef struct CacheMem {
        const void **ptr;
        size_t n_populated;
        bool active:1;
} CacheMem;

struct IteratedCache {
        HashmapBase *hashmap;
        CacheMem keys, values;
};

DEFINE_MEMPOOL(hashmap_pool,         Hashmap,        8);
DEFINE_MEMPOOL(ordered_hashmap_pool, OrderedHashmap, 8);
/* No need for a separate Set pool */
assert_cc(sizeof(Hashmap) == sizeof(Set));

struct hashmap_type_info {
        size_t head_size;
        size_t entry_size;
        struct mempool *mempool;
        unsigned n_direct_buckets;
};

static _used_ const struct hashmap_type_info hashmap_type_info[_HASHMAP_TYPE_MAX] = {
        [HASHMAP_TYPE_PLAIN] = {
                .head_size        = sizeof(Hashmap),
                .entry_size       = sizeof(struct plain_hashmap_entry),
                .mempool          = &hashmap_pool,
                .n_direct_buckets = DIRECT_BUCKETS(struct plain_hashmap_entry),
        },
        [HASHMAP_TYPE_ORDERED] = {
                .head_size        = sizeof(OrderedHashmap),
                .entry_size       = sizeof(struct ordered_hashmap_entry),
                .mempool          = &ordered_hashmap_pool,
                .n_direct_buckets = DIRECT_BUCKETS(struct ordered_hashmap_entry),
        },
        [HASHMAP_TYPE_SET] = {
                .head_size        = sizeof(Set),
                .entry_size       = sizeof(struct set_entry),
                .mempool          = &hashmap_pool,
                .n_direct_buckets = DIRECT_BUCKETS(struct set_entry),
        },
};

#if VALGRIND
_destructor_ static void cleanup_pools(void) {
        _cleanup_free_ char *t = NULL;
        int r;

        /* Be nice to valgrind */

        /* The pool is only allocated by the main thread, but the memory can
         * be passed to other threads. Let's clean up if we are the main thread
         * and no other threads are live. */
        /* We build our own is_main_thread() here, which doesn't use C11
         * TLS based caching of the result. That's because valgrind apparently
         * doesn't like malloc() (which C11 TLS internally uses) to be called
         * from a GCC destructors. */
        if (getpid() != gettid())
                return;

        r = get_proc_field("/proc/self/status", "Threads", WHITESPACE, &t);
        if (r < 0 || !streq(t, "1"))
                return;

        mempool_drop(&hashmap_pool);
        mempool_drop(&ordered_hashmap_pool);
}
#endif

static unsigned n_buckets(HashmapBase *h) {
        return h->has_indirect ? h->indirect.n_buckets
                               : hashmap_type_info[h->type].n_direct_buckets;
}

static unsigned n_entries(HashmapBase *h) {
        return h->has_indirect ? h->indirect.n_entries
                               : h->n_direct_entries;
}

static void n_entries_inc(HashmapBase *h) {
        if (h->has_indirect)
                h->indirect.n_entries++;
        else
                h->n_direct_entries++;
}

static void n_entries_dec(HashmapBase *h) {
        if (h->has_indirect)
                h->indirect.n_entries--;
        else
                h->n_direct_entries--;
}

static void* storage_ptr(HashmapBase *h) {
        return h->has_indirect ? h->indirect.storage
                               : h->direct.storage;
}

static uint8_t* hash_key(HashmapBase *h) {
        return h->has_indirect ? h->indirect.hash_key
                               : shared_hash_key;
}

static unsigned base_bucket_hash(HashmapBase *h, const void *p) {
        struct siphash state;
        uint64_t hash;

        siphash24_init(&state, hash_key(h));

        h->hash_ops->hash(p, &state);

        hash = siphash24_finalize(&state);

        return (unsigned) (hash % n_buckets(h));
}
#define bucket_hash(h, p) base_bucket_hash(HASHMAP_BASE(h), p)

static void base_set_dirty(HashmapBase *h) {
        h->dirty = true;
}
#define hashmap_set_dirty(h) base_set_dirty(HASHMAP_BASE(h))

static void get_hash_key(uint8_t hash_key[HASH_KEY_SIZE], bool reuse_is_ok) {
        static uint8_t current[HASH_KEY_SIZE];
        static bool current_initialized = false;

        /* Returns a hash function key to use. In order to keep things
         * fast we will not generate a new key each time we allocate a
         * new hash table. Instead, we'll just reuse the most recently
         * generated one, except if we never generated one or when we
         * are rehashing an entire hash table because we reached a
         * fill level */

        if (!current_initialized || !reuse_is_ok) {
                random_bytes(current, sizeof(current));
                current_initialized = true;
        }

        memcpy(hash_key, current, sizeof(current));
}

static struct hashmap_base_entry* bucket_at(HashmapBase *h, unsigned idx) {
        return (struct hashmap_base_entry*)
                ((uint8_t*) storage_ptr(h) + idx * hashmap_type_info[h->type].entry_size);
}

static struct plain_hashmap_entry* plain_bucket_at(Hashmap *h, unsigned idx) {
        return (struct plain_hashmap_entry*) bucket_at(HASHMAP_BASE(h), idx);
}

static struct ordered_hashmap_entry* ordered_bucket_at(OrderedHashmap *h, unsigned idx) {
        return (struct ordered_hashmap_entry*) bucket_at(HASHMAP_BASE(h), idx);
}

static struct set_entry *set_bucket_at(Set *h, unsigned idx) {
        return (struct set_entry*) bucket_at(HASHMAP_BASE(h), idx);
}

static struct ordered_hashmap_entry* bucket_at_swap(struct swap_entries *swap, unsigned idx) {
        return &swap->e[idx - _IDX_SWAP_BEGIN];
}

/* Returns a pointer to the bucket at index idx.
 * Understands real indexes and swap indexes, hence "_virtual". */
static struct hashmap_base_entry* bucket_at_virtual(HashmapBase *h, struct swap_entries *swap,
                                                    unsigned idx) {
        if (idx < _IDX_SWAP_BEGIN)
                return bucket_at(h, idx);

        if (idx < _IDX_SWAP_END)
                return &bucket_at_swap(swap, idx)->p.b;

        assert_not_reached();
}

static dib_raw_t* dib_raw_ptr(HashmapBase *h) {
        return (dib_raw_t*)
                ((uint8_t*) storage_ptr(h) + hashmap_type_info[h->type].entry_size * n_buckets(h));
}

static unsigned bucket_distance(HashmapBase *h, unsigned idx, unsigned from) {
        return idx >= from ? idx - from
                           : n_buckets(h) + idx - from;
}

static unsigned bucket_calculate_dib(HashmapBase *h, unsigned idx, dib_raw_t raw_dib) {
        unsigned initial_bucket;

        if (raw_dib == DIB_RAW_FREE)
                return DIB_FREE;

        if (_likely_(raw_dib < DIB_RAW_OVERFLOW))
                return raw_dib;

        /*
         * Having an overflow DIB value is very unlikely. The hash function
         * would have to be bad. For example, in a table of size 2^24 filled
         * to load factor 0.9 the maximum observed DIB is only about 60.
         * In theory (assuming I used Maxima correctly), for an infinite size
         * hash table with load factor 0.8 the probability of a given entry
         * having DIB > 40 is 1.9e-8.
         * This returns the correct DIB value by recomputing the hash value in
         * the unlikely case. XXX Hitting this case could be a hint to rehash.
         */
        initial_bucket = bucket_hash(h, bucket_at(h, idx)->key);
        return bucket_distance(h, idx, initial_bucket);
}

static void bucket_set_dib(HashmapBase *h, unsigned idx, unsigned dib) {
        dib_raw_ptr(h)[idx] = dib != DIB_FREE ? MIN(dib, DIB_RAW_OVERFLOW) : DIB_RAW_FREE;
}

static unsigned skip_free_buckets(HashmapBase *h, unsigned idx) {
        dib_raw_t *dibs;

        dibs = dib_raw_ptr(h);

        for ( ; idx < n_buckets(h); idx++)
                if (dibs[idx] != DIB_RAW_FREE)
                        return idx;

        return IDX_NIL;
}

static void bucket_mark_free(HashmapBase *h, unsigned idx) {
        memzero(bucket_at(h, idx), hashmap_type_info[h->type].entry_size);
        bucket_set_dib(h, idx, DIB_FREE);
}

static void bucket_move_entry(HashmapBase *h, struct swap_entries *swap,
                              unsigned from, unsigned to) {
        struct hashmap_base_entry *e_from, *e_to;

        assert(from != to);

        e_from = bucket_at_virtual(h, swap, from);
        e_to   = bucket_at_virtual(h, swap, to);

        memcpy(e_to, e_from, hashmap_type_info[h->type].entry_size);

        if (h->type == HASHMAP_TYPE_ORDERED) {
                OrderedHashmap *lh = (OrderedHashmap*) h;
                struct ordered_hashmap_entry *le, *le_to;

                le_to = (struct ordered_hashmap_entry*) e_to;

                if (le_to->iterate_next != IDX_NIL) {
                        le = (struct ordered_hashmap_entry*)
                             bucket_at_virtual(h, swap, le_to->iterate_next);
                        le->iterate_previous = to;
                }

                if (le_to->iterate_previous != IDX_NIL) {
                        le = (struct ordered_hashmap_entry*)
                             bucket_at_virtual(h, swap, le_to->iterate_previous);
                        le->iterate_next = to;
                }

                if (lh->iterate_list_head == from)
                        lh->iterate_list_head = to;
                if (lh->iterate_list_tail == from)
                        lh->iterate_list_tail = to;
        }
}

static unsigned next_idx(HashmapBase *h, unsigned idx) {
        return (idx + 1U) % n_buckets(h);
}

static unsigned prev_idx(HashmapBase *h, unsigned idx) {
        return (n_buckets(h) + idx - 1U) % n_buckets(h);
}

static void* entry_value(HashmapBase *h, struct hashmap_base_entry *e) {
        switch (h->type) {

        case HASHMAP_TYPE_PLAIN:
        case HASHMAP_TYPE_ORDERED:
                return ((struct plain_hashmap_entry*)e)->value;

        case HASHMAP_TYPE_SET:
                return (void*) e->key;

        default:
                assert_not_reached();
        }
}

static void base_remove_entry(HashmapBase *h, unsigned idx) {
        unsigned left, right, prev, dib;
        dib_raw_t raw_dib, *dibs;

        dibs = dib_raw_ptr(h);
        assert(dibs[idx] != DIB_RAW_FREE);

#if ENABLE_DEBUG_HASHMAP
        h->debug.rem_count++;
        h->debug.last_rem_idx = idx;
#endif

        left = idx;
        /* Find the stop bucket ("right"). It is either free or has DIB == 0. */
        for (right = next_idx(h, left); ; right = next_idx(h, right)) {
                raw_dib = dibs[right];
                if (IN_SET(raw_dib, 0, DIB_RAW_FREE))
                        break;

                /* The buckets are not supposed to be all occupied and with DIB > 0.
                 * That would mean we could make everyone better off by shifting them
                 * backward. This scenario is impossible. */
                assert(left != right);
        }

        if (h->type == HASHMAP_TYPE_ORDERED) {
                OrderedHashmap *lh = (OrderedHashmap*) h;
                struct ordered_hashmap_entry *le = ordered_bucket_at(lh, idx);

                if (le->iterate_next != IDX_NIL)
                        ordered_bucket_at(lh, le->iterate_next)->iterate_previous = le->iterate_previous;
                else
                        lh->iterate_list_tail = le->iterate_previous;

                if (le->iterate_previous != IDX_NIL)
                        ordered_bucket_at(lh, le->iterate_previous)->iterate_next = le->iterate_next;
                else
                        lh->iterate_list_head = le->iterate_next;
        }

        /* Now shift all buckets in the interval (left, right) one step backwards */
        for (prev = left, left = next_idx(h, left); left != right;
             prev = left, left = next_idx(h, left)) {
                dib = bucket_calculate_dib(h, left, dibs[left]);
                assert(dib != 0);
                bucket_move_entry(h, NULL, left, prev);
                bucket_set_dib(h, prev, dib - 1);
        }

        bucket_mark_free(h, prev);
        n_entries_dec(h);
        base_set_dirty(h);
}
#define remove_entry(h, idx) base_remove_entry(HASHMAP_BASE(h), idx)

static unsigned hashmap_iterate_in_insertion_order(OrderedHashmap *h, Iterator *i) {
        struct ordered_hashmap_entry *e;
        unsigned idx;

        assert(h);
        assert(i);

        if (i->idx == IDX_NIL)
                goto at_end;

        if (i->idx == IDX_FIRST && h->iterate_list_head == IDX_NIL)
                goto at_end;

        if (i->idx == IDX_FIRST) {
                idx = h->iterate_list_head;
                e = ordered_bucket_at(h, idx);
        } else {
                idx = i->idx;
                e = ordered_bucket_at(h, idx);
                /*
                 * We allow removing the current entry while iterating, but removal may cause
                 * a backward shift. The next entry may thus move one bucket to the left.
                 * To detect when it happens, we remember the key pointer of the entry we were
                 * going to iterate next. If it does not match, there was a backward shift.
                 */
                if (e->p.b.key != i->next_key) {
                        idx = prev_idx(HASHMAP_BASE(h), idx);
                        e = ordered_bucket_at(h, idx);
                }
                assert(e->p.b.key == i->next_key);
        }

#if ENABLE_DEBUG_HASHMAP
        i->prev_idx = idx;
#endif

        if (e->iterate_next != IDX_NIL) {
                struct ordered_hashmap_entry *n;
                i->idx = e->iterate_next;
                n = ordered_bucket_at(h, i->idx);
                i->next_key = n->p.b.key;
        } else
                i->idx = IDX_NIL;

        return idx;

at_end:
        i->idx = IDX_NIL;
        return IDX_NIL;
}

static unsigned hashmap_iterate_in_internal_order(HashmapBase *h, Iterator *i) {
        unsigned idx;

        assert(h);
        assert(i);

        if (i->idx == IDX_NIL)
                goto at_end;

        if (i->idx == IDX_FIRST) {
                /* fast forward to the first occupied bucket */
                if (h->has_indirect) {
                        i->idx = skip_free_buckets(h, h->indirect.idx_lowest_entry);
                        h->indirect.idx_lowest_entry = i->idx;
                } else
                        i->idx = skip_free_buckets(h, 0);

                if (i->idx == IDX_NIL)
                        goto at_end;
        } else {
                struct hashmap_base_entry *e;

                assert(i->idx > 0);

                e = bucket_at(h, i->idx);
                /*
                 * We allow removing the current entry while iterating, but removal may cause
                 * a backward shift. The next entry may thus move one bucket to the left.
                 * To detect when it happens, we remember the key pointer of the entry we were
                 * going to iterate next. If it does not match, there was a backward shift.
                 */
                if (e->key != i->next_key)
                        e = bucket_at(h, --i->idx);

                assert(e->key == i->next_key);
        }

        idx = i->idx;
#if ENABLE_DEBUG_HASHMAP
        i->prev_idx = idx;
#endif

        i->idx = skip_free_buckets(h, i->idx + 1);
        if (i->idx != IDX_NIL)
                i->next_key = bucket_at(h, i->idx)->key;
        else
                i->idx = IDX_NIL;

        return idx;

at_end:
        i->idx = IDX_NIL;
        return IDX_NIL;
}

static unsigned hashmap_iterate_entry(HashmapBase *h, Iterator *i) {
        if (!h) {
                i->idx = IDX_NIL;
                return IDX_NIL;
        }

#if ENABLE_DEBUG_HASHMAP
        if (i->idx == IDX_FIRST) {
                i->put_count = h->debug.put_count;
                i->rem_count = h->debug.rem_count;
        } else {
                /* While iterating, must not add any new entries */
                assert(i->put_count == h->debug.put_count);
                /* ... or remove entries other than the current one */
                assert(i->rem_count == h->debug.rem_count ||
                       (i->rem_count == h->debug.rem_count - 1 &&
                        i->prev_idx == h->debug.last_rem_idx));
                /* Reset our removals counter */
                i->rem_count = h->debug.rem_count;
        }
#endif

        return h->type == HASHMAP_TYPE_ORDERED ? hashmap_iterate_in_insertion_order((OrderedHashmap*) h, i)
                                               : hashmap_iterate_in_internal_order(h, i);
}

bool _hashmap_iterate(HashmapBase *h, Iterator *i, void **value, const void **key) {
        struct hashmap_base_entry *e;
        void *data;
        unsigned idx;

        idx = hashmap_iterate_entry(h, i);
        if (idx == IDX_NIL) {
                if (value)
                        *value = NULL;
                if (key)
                        *key = NULL;

                return false;
        }

        e = bucket_at(h, idx);
        data = entry_value(h, e);
        if (value)
                *value = data;
        if (key)
                *key = e->key;

        return true;
}

#define HASHMAP_FOREACH_IDX(idx, h, i) \
        for ((i) = ITERATOR_FIRST, (idx) = hashmap_iterate_entry((h), &(i)); \
             (idx != IDX_NIL); \
             (idx) = hashmap_iterate_entry((h), &(i)))

IteratedCache* _hashmap_iterated_cache_new(HashmapBase *h) {
        IteratedCache *cache;

        assert(h);
        assert(!h->cached);

        if (h->cached)
                return NULL;

        cache = new0(IteratedCache, 1);
        if (!cache)
                return NULL;

        cache->hashmap = h;
        h->cached = true;

        return cache;
}

static void reset_direct_storage(HashmapBase *h) {
        const struct hashmap_type_info *hi = &hashmap_type_info[h->type];
        void *p;

        assert(!h->has_indirect);

        p = mempset(h->direct.storage, 0, hi->entry_size * hi->n_direct_buckets);
        memset(p, DIB_RAW_INIT, sizeof(dib_raw_t) * hi->n_direct_buckets);
}

static void shared_hash_key_initialize(void) {
        random_bytes(shared_hash_key, sizeof(shared_hash_key));
}

static struct HashmapBase* hashmap_base_new(const struct hash_ops *hash_ops, enum HashmapType type  HASHMAP_DEBUG_PARAMS) {
        HashmapBase *h;
        const struct hashmap_type_info *hi = &hashmap_type_info[type];
        bool up;

        up = mempool_enabled();

        h = up ? mempool_alloc0_tile(hi->mempool) : malloc0(hi->head_size);
        if (!h)
                return NULL;

        h->type = type;
        h->from_pool = up;
        h->hash_ops = hash_ops ?: &trivial_hash_ops;

        if (type == HASHMAP_TYPE_ORDERED) {
                OrderedHashmap *lh = (OrderedHashmap*)h;
                lh->iterate_list_head = lh->iterate_list_tail = IDX_NIL;
        }

        reset_direct_storage(h);

        static pthread_once_t once = PTHREAD_ONCE_INIT;
        assert_se(pthread_once(&once, shared_hash_key_initialize) == 0);

#if ENABLE_DEBUG_HASHMAP
        h->debug.func = func;
        h->debug.file = file;
        h->debug.line = line;
        assert_se(pthread_mutex_lock(&hashmap_debug_list_mutex) == 0);
        LIST_PREPEND(debug_list, hashmap_debug_list, &h->debug);
        assert_se(pthread_mutex_unlock(&hashmap_debug_list_mutex) == 0);
#endif

        return h;
}

Hashmap *_hashmap_new(const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS) {
        return (Hashmap*)        hashmap_base_new(hash_ops, HASHMAP_TYPE_PLAIN  HASHMAP_DEBUG_PASS_ARGS);
}

OrderedHashmap *_ordered_hashmap_new(const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS) {
        return (OrderedHashmap*) hashmap_base_new(hash_ops, HASHMAP_TYPE_ORDERED  HASHMAP_DEBUG_PASS_ARGS);
}

Set *_set_new(const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS) {
        return (Set*)            hashmap_base_new(hash_ops, HASHMAP_TYPE_SET  HASHMAP_DEBUG_PASS_ARGS);
}

static int hashmap_base_ensure_allocated(HashmapBase **h, const struct hash_ops *hash_ops,
                                         enum HashmapType type  HASHMAP_DEBUG_PARAMS) {
        HashmapBase *q;

        assert(h);

        if (*h)
                return 0;

        q = hashmap_base_new(hash_ops, type  HASHMAP_DEBUG_PASS_ARGS);
        if (!q)
                return -ENOMEM;

        *h = q;
        return 1;
}

int _hashmap_ensure_allocated(Hashmap **h, const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS) {
        return hashmap_base_ensure_allocated((HashmapBase**)h, hash_ops, HASHMAP_TYPE_PLAIN  HASHMAP_DEBUG_PASS_ARGS);
}

int _ordered_hashmap_ensure_allocated(OrderedHashmap **h, const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS) {
        return hashmap_base_ensure_allocated((HashmapBase**)h, hash_ops, HASHMAP_TYPE_ORDERED  HASHMAP_DEBUG_PASS_ARGS);
}

int _set_ensure_allocated(Set **s, const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS) {
        return hashmap_base_ensure_allocated((HashmapBase**)s, hash_ops, HASHMAP_TYPE_SET  HASHMAP_DEBUG_PASS_ARGS);
}

int _hashmap_ensure_put(Hashmap **h, const struct hash_ops *hash_ops, const void *key, void *value  HASHMAP_DEBUG_PARAMS) {
        int r;

        r = _hashmap_ensure_allocated(h, hash_ops  HASHMAP_DEBUG_PASS_ARGS);
        if (r < 0)
                return r;

        return hashmap_put(*h, key, value);
}

int _ordered_hashmap_ensure_put(OrderedHashmap **h, const struct hash_ops *hash_ops, const void *key, void *value  HASHMAP_DEBUG_PARAMS) {
        int r;

        r = _ordered_hashmap_ensure_allocated(h, hash_ops  HASHMAP_DEBUG_PASS_ARGS);
        if (r < 0)
                return r;

        return ordered_hashmap_put(*h, key, value);
}

static void hashmap_free_no_clear(HashmapBase *h) {
        assert(!h->has_indirect);
        assert(h->n_direct_entries == 0);

#if ENABLE_DEBUG_HASHMAP
        assert_se(pthread_mutex_lock(&hashmap_debug_list_mutex) == 0);
        LIST_REMOVE(debug_list, hashmap_debug_list, &h->debug);
        assert_se(pthread_mutex_unlock(&hashmap_debug_list_mutex) == 0);
#endif

        if (h->from_pool) {
                /* Ensure that the object didn't get migrated between threads. */
                assert_se(is_main_thread());
                mempool_free_tile(hashmap_type_info[h->type].mempool, h);
        } else
                free(h);
}

HashmapBase* _hashmap_free(HashmapBase *h, free_func_t default_free_key, free_func_t default_free_value) {
        if (h) {
                _hashmap_clear(h, default_free_key, default_free_value);
                hashmap_free_no_clear(h);
        }

        return NULL;
}

void _hashmap_clear(HashmapBase *h, free_func_t default_free_key, free_func_t default_free_value) {
        free_func_t free_key, free_value;
        if (!h)
                return;

        free_key = h->hash_ops->free_key ?: default_free_key;
        free_value = h->hash_ops->free_value ?: default_free_value;

        if (free_key || free_value) {

                /* If destructor calls are defined, let's destroy things defensively: let's take the item out of the
                 * hash table, and only then call the destructor functions. If these destructors then try to unregister
                 * themselves from our hash table a second time, the entry is already gone. */

                while (_hashmap_size(h) > 0) {
                        void *k = NULL;
                        void *v;

                        v = _hashmap_first_key_and_value(h, true, &k);

                        if (free_key)
                                free_key(k);

                        if (free_value)
                                free_value(v);
                }
        }

        if (h->has_indirect) {
                free(h->indirect.storage);
                h->has_indirect = false;
        }

        h->n_direct_entries = 0;
        reset_direct_storage(h);

        if (h->type == HASHMAP_TYPE_ORDERED) {
                OrderedHashmap *lh = (OrderedHashmap*) h;
                lh->iterate_list_head = lh->iterate_list_tail = IDX_NIL;
        }

        base_set_dirty(h);
}

static int resize_buckets(HashmapBase *h, unsigned entries_add);

/*
 * Finds an empty bucket to put an entry into, starting the scan at 'idx'.
 * Performs Robin Hood swaps as it goes. The entry to put must be placed
 * by the caller into swap slot IDX_PUT.
 * If used for in-place resizing, may leave a displaced entry in swap slot
 * IDX_PUT. Caller must rehash it next.
 * Returns: true if it left a displaced entry to rehash next in IDX_PUT,
 *          false otherwise.
 */
static bool hashmap_put_robin_hood(HashmapBase *h, unsigned idx,
                                   struct swap_entries *swap) {
        dib_raw_t raw_dib, *dibs;
        unsigned dib, distance;

#if ENABLE_DEBUG_HASHMAP
        h->debug.put_count++;
#endif

        dibs = dib_raw_ptr(h);

        for (distance = 0; ; distance++) {
                raw_dib = dibs[idx];
                if (IN_SET(raw_dib, DIB_RAW_FREE, DIB_RAW_REHASH)) {
                        if (raw_dib == DIB_RAW_REHASH)
                                bucket_move_entry(h, swap, idx, IDX_TMP);

                        if (h->has_indirect && h->indirect.idx_lowest_entry > idx)
                                h->indirect.idx_lowest_entry = idx;

                        bucket_set_dib(h, idx, distance);
                        bucket_move_entry(h, swap, IDX_PUT, idx);
                        if (raw_dib == DIB_RAW_REHASH) {
                                bucket_move_entry(h, swap, IDX_TMP, IDX_PUT);
                                return true;
                        }

                        return false;
                }

                dib = bucket_calculate_dib(h, idx, raw_dib);

                if (dib < distance) {
                        /* Found a wealthier entry. Go Robin Hood! */
                        bucket_set_dib(h, idx, distance);

                        /* swap the entries */
                        bucket_move_entry(h, swap, idx, IDX_TMP);
                        bucket_move_entry(h, swap, IDX_PUT, idx);
                        bucket_move_entry(h, swap, IDX_TMP, IDX_PUT);

                        distance = dib;
                }

                idx = next_idx(h, idx);
        }
}

/*
 * Puts an entry into a hashmap, boldly - no check whether key already exists.
 * The caller must place the entry (only its key and value, not link indexes)
 * in swap slot IDX_PUT.
 * Caller must ensure: the key does not exist yet in the hashmap.
 *                     that resize is not needed if !may_resize.
 * Returns: 1 if entry was put successfully.
 *          -ENOMEM if may_resize==true and resize failed with -ENOMEM.
 *          Cannot return -ENOMEM if !may_resize.
 */
static int hashmap_base_put_boldly(HashmapBase *h, unsigned idx,
                                   struct swap_entries *swap, bool may_resize) {
        struct ordered_hashmap_entry *new_entry;
        int r;

        assert(idx < n_buckets(h));

        new_entry = bucket_at_swap(swap, IDX_PUT);

        if (may_resize) {
                r = resize_buckets(h, 1);
                if (r < 0)
                        return r;
                if (r > 0)
                        idx = bucket_hash(h, new_entry->p.b.key);
        }
        assert(n_entries(h) < n_buckets(h));

        if (h->type == HASHMAP_TYPE_ORDERED) {
                OrderedHashmap *lh = (OrderedHashmap*) h;

                new_entry->iterate_next = IDX_NIL;
                new_entry->iterate_previous = lh->iterate_list_tail;

                if (lh->iterate_list_tail != IDX_NIL) {
                        struct ordered_hashmap_entry *old_tail;

                        old_tail = ordered_bucket_at(lh, lh->iterate_list_tail);
                        assert(old_tail->iterate_next == IDX_NIL);
                        old_tail->iterate_next = IDX_PUT;
                }

                lh->iterate_list_tail = IDX_PUT;
                if (lh->iterate_list_head == IDX_NIL)
                        lh->iterate_list_head = IDX_PUT;
        }

        assert_se(hashmap_put_robin_hood(h, idx, swap) == false);

        n_entries_inc(h);
#if ENABLE_DEBUG_HASHMAP
        h->debug.max_entries = MAX(h->debug.max_entries, n_entries(h));
#endif

        base_set_dirty(h);

        return 1;
}
#define hashmap_put_boldly(h, idx, swap, may_resize) \
        hashmap_base_put_boldly(HASHMAP_BASE(h), idx, swap, may_resize)

/*
 * Returns 0 if resize is not needed.
 *         1 if successfully resized.
 *         -ENOMEM on allocation failure.
 */
static int resize_buckets(HashmapBase *h, unsigned entries_add) {
        struct swap_entries swap;
        void *new_storage;
        dib_raw_t *old_dibs, *new_dibs;
        const struct hashmap_type_info *hi;
        unsigned idx, optimal_idx;
        unsigned old_n_buckets, new_n_buckets, n_rehashed, new_n_entries;
        uint8_t new_shift;
        bool rehash_next;

        assert(h);

        hi = &hashmap_type_info[h->type];
        new_n_entries = n_entries(h) + entries_add;

        /* overflow? */
        if (_unlikely_(new_n_entries < entries_add))
                return -ENOMEM;

        /* For direct storage we allow 100% load, because it's tiny. */
        if (!h->has_indirect && new_n_entries <= hi->n_direct_buckets)
                return 0;

        /*
         * Load factor = n/m = 1 - (1/INV_KEEP_FREE).
         * From it follows: m = n + n/(INV_KEEP_FREE - 1)
         */
        new_n_buckets = new_n_entries + new_n_entries / (INV_KEEP_FREE - 1);
        /* overflow? */
        if (_unlikely_(new_n_buckets < new_n_entries))
                return -ENOMEM;

        if (_unlikely_(new_n_buckets > UINT_MAX / (hi->entry_size + sizeof(dib_raw_t))))
                return -ENOMEM;

        old_n_buckets = n_buckets(h);

        if (_likely_(new_n_buckets <= old_n_buckets))
                return 0;

        new_shift = log2u_round_up(MAX(
                        new_n_buckets * (hi->entry_size + sizeof(dib_raw_t)),
                        2 * sizeof(struct direct_storage)));

        /* Realloc storage (buckets and DIB array). */
        new_storage = realloc(h->has_indirect ? h->indirect.storage : NULL,
                              1U << new_shift);
        if (!new_storage)
                return -ENOMEM;

        /* Must upgrade direct to indirect storage. */
        if (!h->has_indirect) {
                memcpy(new_storage, h->direct.storage,
                       old_n_buckets * (hi->entry_size + sizeof(dib_raw_t)));
                h->indirect.n_entries = h->n_direct_entries;
                h->indirect.idx_lowest_entry = 0;
                h->n_direct_entries = 0;
        }

        /* Get a new hash key. If we've just upgraded to indirect storage,
         * allow reusing a previously generated key. It's still a different key
         * from the shared one that we used for direct storage. */
        get_hash_key(h->indirect.hash_key, !h->has_indirect);

        h->has_indirect = true;
        h->indirect.storage = new_storage;
        h->indirect.n_buckets = (1U << new_shift) /
                                (hi->entry_size + sizeof(dib_raw_t));

        old_dibs = (dib_raw_t*)((uint8_t*) new_storage + hi->entry_size * old_n_buckets);
        new_dibs = dib_raw_ptr(h);

        /*
         * Move the DIB array to the new place, replacing valid DIB values with
         * DIB_RAW_REHASH to indicate all of the used buckets need rehashing.
         * Note: Overlap is not possible, because we have at least doubled the
         * number of buckets and dib_raw_t is smaller than any entry type.
         */
        for (idx = 0; idx < old_n_buckets; idx++) {
                assert(old_dibs[idx] != DIB_RAW_REHASH);
                new_dibs[idx] = old_dibs[idx] == DIB_RAW_FREE ? DIB_RAW_FREE
                                                              : DIB_RAW_REHASH;
        }

        /* Zero the area of newly added entries (including the old DIB area) */
        memzero(bucket_at(h, old_n_buckets),
               (n_buckets(h) - old_n_buckets) * hi->entry_size);

        /* The upper half of the new DIB array needs initialization */
        memset(&new_dibs[old_n_buckets], DIB_RAW_INIT,
               (n_buckets(h) - old_n_buckets) * sizeof(dib_raw_t));

        /* Rehash entries that need it */
        n_rehashed = 0;
        for (idx = 0; idx < old_n_buckets; idx++) {
                if (new_dibs[idx] != DIB_RAW_REHASH)
                        continue;

                optimal_idx = bucket_hash(h, bucket_at(h, idx)->key);

                /*
                 * Not much to do if by luck the entry hashes to its current
                 * location. Just set its DIB.
                 */
                if (optimal_idx == idx) {
                        new_dibs[idx] = 0;
                        n_rehashed++;
                        continue;
                }

                new_dibs[idx] = DIB_RAW_FREE;
                bucket_move_entry(h, &swap, idx, IDX_PUT);
                /* bucket_move_entry does not clear the source */
                memzero(bucket_at(h, idx), hi->entry_size);

                do {
                        /*
                         * Find the new bucket for the current entry. This may make
                         * another entry homeless and load it into IDX_PUT.
                         */
                        rehash_next = hashmap_put_robin_hood(h, optimal_idx, &swap);
                        n_rehashed++;

                        /* Did the current entry displace another one? */
                        if (rehash_next)
                                optimal_idx = bucket_hash(h, bucket_at_swap(&swap, IDX_PUT)->p.b.key);
                } while (rehash_next);
        }

        assert(n_rehashed == n_entries(h));

        return 1;
}

/*
 * Finds an entry with a matching key
 * Returns: index of the found entry, or IDX_NIL if not found.
 */
static unsigned base_bucket_scan(HashmapBase *h, unsigned idx, const void *key) {
        struct hashmap_base_entry *e;
        unsigned dib, distance;
        dib_raw_t *dibs = dib_raw_ptr(h);

        assert(idx < n_buckets(h));

        for (distance = 0; ; distance++) {
                if (dibs[idx] == DIB_RAW_FREE)
                        return IDX_NIL;

                dib = bucket_calculate_dib(h, idx, dibs[idx]);

                if (dib < distance)
                        return IDX_NIL;
                if (dib == distance) {
                        e = bucket_at(h, idx);
                        if (h->hash_ops->compare(e->key, key) == 0)
                                return idx;
                }

                idx = next_idx(h, idx);
        }
}
#define bucket_scan(h, idx, key) base_bucket_scan(HASHMAP_BASE(h), idx, key)

int hashmap_put(Hashmap *h, const void *key, void *value) {
        struct swap_entries swap;
        struct plain_hashmap_entry *e;
        unsigned hash, idx;

        assert(h);

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx != IDX_NIL) {
                e = plain_bucket_at(h, idx);
                if (e->value == value)
                        return 0;
                return -EEXIST;
        }

        e = &bucket_at_swap(&swap, IDX_PUT)->p;
        e->b.key = key;
        e->value = value;
        return hashmap_put_boldly(h, hash, &swap, true);
}

int set_put(Set *s, const void *key) {
        struct swap_entries swap;
        struct hashmap_base_entry *e;
        unsigned hash, idx;

        assert(s);

        hash = bucket_hash(s, key);
        idx = bucket_scan(s, hash, key);
        if (idx != IDX_NIL)
                return 0;

        e = &bucket_at_swap(&swap, IDX_PUT)->p.b;
        e->key = key;
        return hashmap_put_boldly(s, hash, &swap, true);
}

int _set_ensure_put(Set **s, const struct hash_ops *hash_ops, const void *key  HASHMAP_DEBUG_PARAMS) {
        int r;

        r = _set_ensure_allocated(s, hash_ops  HASHMAP_DEBUG_PASS_ARGS);
        if (r < 0)
                return r;

        return set_put(*s, key);
}

int _set_ensure_consume(Set **s, const struct hash_ops *hash_ops, void *key  HASHMAP_DEBUG_PARAMS) {
        int r;

        r = _set_ensure_put(s, hash_ops, key  HASHMAP_DEBUG_PASS_ARGS);
        if (r <= 0) {
                if (hash_ops && hash_ops->free_key)
                        hash_ops->free_key(key);
                else
                        free(key);
        }

        return r;
}

int hashmap_replace(Hashmap *h, const void *key, void *value) {
        struct swap_entries swap;
        struct plain_hashmap_entry *e;
        unsigned hash, idx;

        assert(h);

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx != IDX_NIL) {
                e = plain_bucket_at(h, idx);
#if ENABLE_DEBUG_HASHMAP
                /* Although the key is equal, the key pointer may have changed,
                 * and this would break our assumption for iterating. So count
                 * this operation as incompatible with iteration. */
                if (e->b.key != key) {
                        h->b.debug.put_count++;
                        h->b.debug.rem_count++;
                        h->b.debug.last_rem_idx = idx;
                }
#endif
                e->b.key = key;
                e->value = value;
                hashmap_set_dirty(h);

                return 0;
        }

        e = &bucket_at_swap(&swap, IDX_PUT)->p;
        e->b.key = key;
        e->value = value;
        return hashmap_put_boldly(h, hash, &swap, true);
}

int hashmap_update(Hashmap *h, const void *key, void *value) {
        struct plain_hashmap_entry *e;
        unsigned hash, idx;

        assert(h);

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx == IDX_NIL)
                return -ENOENT;

        e = plain_bucket_at(h, idx);
        e->value = value;
        hashmap_set_dirty(h);

        return 0;
}

void* _hashmap_get(HashmapBase *h, const void *key) {
        struct hashmap_base_entry *e;
        unsigned hash, idx;

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx == IDX_NIL)
                return NULL;

        e = bucket_at(h, idx);
        return entry_value(h, e);
}

void* hashmap_get2(Hashmap *h, const void *key, void **key2) {
        struct plain_hashmap_entry *e;
        unsigned hash, idx;

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx == IDX_NIL)
                return NULL;

        e = plain_bucket_at(h, idx);
        if (key2)
                *key2 = (void*) e->b.key;

        return e->value;
}

bool _hashmap_contains(HashmapBase *h, const void *key) {
        unsigned hash;

        if (!h)
                return false;

        hash = bucket_hash(h, key);
        return bucket_scan(h, hash, key) != IDX_NIL;
}

void* _hashmap_remove(HashmapBase *h, const void *key) {
        struct hashmap_base_entry *e;
        unsigned hash, idx;
        void *data;

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx == IDX_NIL)
                return NULL;

        e = bucket_at(h, idx);
        data = entry_value(h, e);
        remove_entry(h, idx);

        return data;
}

void* hashmap_remove2(Hashmap *h, const void *key, void **rkey) {
        struct plain_hashmap_entry *e;
        unsigned hash, idx;
        void *data;

        if (!h) {
                if (rkey)
                        *rkey = NULL;
                return NULL;
        }

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx == IDX_NIL) {
                if (rkey)
                        *rkey = NULL;
                return NULL;
        }

        e = plain_bucket_at(h, idx);
        data = e->value;
        if (rkey)
                *rkey = (void*) e->b.key;

        remove_entry(h, idx);

        return data;
}

int hashmap_remove_and_put(Hashmap *h, const void *old_key, const void *new_key, void *value) {
        struct swap_entries swap;
        struct plain_hashmap_entry *e;
        unsigned old_hash, new_hash, idx;

        if (!h)
                return -ENOENT;

        old_hash = bucket_hash(h, old_key);
        idx = bucket_scan(h, old_hash, old_key);
        if (idx == IDX_NIL)
                return -ENOENT;

        new_hash = bucket_hash(h, new_key);
        if (bucket_scan(h, new_hash, new_key) != IDX_NIL)
                return -EEXIST;

        remove_entry(h, idx);

        e = &bucket_at_swap(&swap, IDX_PUT)->p;
        e->b.key = new_key;
        e->value = value;
        assert_se(hashmap_put_boldly(h, new_hash, &swap, false) == 1);

        return 0;
}

int set_remove_and_put(Set *s, const void *old_key, const void *new_key) {
        struct swap_entries swap;
        struct hashmap_base_entry *e;
        unsigned old_hash, new_hash, idx;

        if (!s)
                return -ENOENT;

        old_hash = bucket_hash(s, old_key);
        idx = bucket_scan(s, old_hash, old_key);
        if (idx == IDX_NIL)
                return -ENOENT;

        new_hash = bucket_hash(s, new_key);
        if (bucket_scan(s, new_hash, new_key) != IDX_NIL)
                return -EEXIST;

        remove_entry(s, idx);

        e = &bucket_at_swap(&swap, IDX_PUT)->p.b;
        e->key = new_key;
        assert_se(hashmap_put_boldly(s, new_hash, &swap, false) == 1);

        return 0;
}

int hashmap_remove_and_replace(Hashmap *h, const void *old_key, const void *new_key, void *value) {
        struct swap_entries swap;
        struct plain_hashmap_entry *e;
        unsigned old_hash, new_hash, idx_old, idx_new;

        if (!h)
                return -ENOENT;

        old_hash = bucket_hash(h, old_key);
        idx_old = bucket_scan(h, old_hash, old_key);
        if (idx_old == IDX_NIL)
                return -ENOENT;

        old_key = bucket_at(HASHMAP_BASE(h), idx_old)->key;

        new_hash = bucket_hash(h, new_key);
        idx_new = bucket_scan(h, new_hash, new_key);
        if (idx_new != IDX_NIL)
                if (idx_old != idx_new) {
                        remove_entry(h, idx_new);
                        /* Compensate for a possible backward shift. */
                        if (old_key != bucket_at(HASHMAP_BASE(h), idx_old)->key)
                                idx_old = prev_idx(HASHMAP_BASE(h), idx_old);
                        assert(old_key == bucket_at(HASHMAP_BASE(h), idx_old)->key);
                }

        remove_entry(h, idx_old);

        e = &bucket_at_swap(&swap, IDX_PUT)->p;
        e->b.key = new_key;
        e->value = value;
        assert_se(hashmap_put_boldly(h, new_hash, &swap, false) == 1);

        return 0;
}

void* _hashmap_remove_value(HashmapBase *h, const void *key, void *value) {
        struct hashmap_base_entry *e;
        unsigned hash, idx;

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx == IDX_NIL)
                return NULL;

        e = bucket_at(h, idx);
        if (entry_value(h, e) != value)
                return NULL;

        remove_entry(h, idx);

        return value;
}

static unsigned find_first_entry(HashmapBase *h) {
        Iterator i = ITERATOR_FIRST;

        if (!h || !n_entries(h))
                return IDX_NIL;

        return hashmap_iterate_entry(h, &i);
}

void* _hashmap_first_key_and_value(HashmapBase *h, bool remove, void **ret_key) {
        struct hashmap_base_entry *e;
        void *key, *data;
        unsigned idx;

        idx = find_first_entry(h);
        if (idx == IDX_NIL) {
                if (ret_key)
                        *ret_key = NULL;
                return NULL;
        }

        e = bucket_at(h, idx);
        key = (void*) e->key;
        data = entry_value(h, e);

        if (remove)
                remove_entry(h, idx);

        if (ret_key)
                *ret_key = key;

        return data;
}

unsigned _hashmap_size(HashmapBase *h) {
        if (!h)
                return 0;

        return n_entries(h);
}

unsigned _hashmap_buckets(HashmapBase *h) {
        if (!h)
                return 0;

        return n_buckets(h);
}

int _hashmap_merge(Hashmap *h, Hashmap *other) {
        Iterator i;
        unsigned idx;

        assert(h);

        HASHMAP_FOREACH_IDX(idx, HASHMAP_BASE(other), i) {
                struct plain_hashmap_entry *pe = plain_bucket_at(other, idx);
                int r;

                r = hashmap_put(h, pe->b.key, pe->value);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        return 0;
}

int set_merge(Set *s, Set *other) {
        Iterator i;
        unsigned idx;

        assert(s);

        HASHMAP_FOREACH_IDX(idx, HASHMAP_BASE(other), i) {
                struct set_entry *se = set_bucket_at(other, idx);
                int r;

                r = set_put(s, se->b.key);
                if (r < 0)
                        return r;
        }

        return 0;
}

int _hashmap_reserve(HashmapBase *h, unsigned entries_add) {
        int r;

        assert(h);

        r = resize_buckets(h, entries_add);
        if (r < 0)
                return r;

        return 0;
}

/*
 * The same as hashmap_merge(), but every new item from other is moved to h.
 * Keys already in h are skipped and stay in other.
 * Returns: 0 on success.
 *          -ENOMEM on alloc failure, in which case no move has been done.
 */
int _hashmap_move(HashmapBase *h, HashmapBase *other) {
        struct swap_entries swap;
        struct hashmap_base_entry *e, *n;
        Iterator i;
        unsigned idx;
        int r;

        assert(h);

        if (!other)
                return 0;

        assert(other->type == h->type);

        /*
         * This reserves buckets for the worst case, where none of other's
         * entries are yet present in h. This is preferable to risking
         * an allocation failure in the middle of the moving and having to
         * rollback or return a partial result.
         */
        r = resize_buckets(h, n_entries(other));
        if (r < 0)
                return r;

        HASHMAP_FOREACH_IDX(idx, other, i) {
                unsigned h_hash;

                e = bucket_at(other, idx);
                h_hash = bucket_hash(h, e->key);
                if (bucket_scan(h, h_hash, e->key) != IDX_NIL)
                        continue;

                n = &bucket_at_swap(&swap, IDX_PUT)->p.b;
                n->key = e->key;
                if (h->type != HASHMAP_TYPE_SET)
                        ((struct plain_hashmap_entry*) n)->value =
                                ((struct plain_hashmap_entry*) e)->value;
                assert_se(hashmap_put_boldly(h, h_hash, &swap, false) == 1);

                remove_entry(other, idx);
        }

        return 0;
}

int _hashmap_move_one(HashmapBase *h, HashmapBase *other, const void *key) {
        struct swap_entries swap;
        unsigned h_hash, other_hash, idx;
        struct hashmap_base_entry *e, *n;
        int r;

        assert(h);

        h_hash = bucket_hash(h, key);
        if (bucket_scan(h, h_hash, key) != IDX_NIL)
                return -EEXIST;

        if (!other)
                return -ENOENT;

        assert(other->type == h->type);

        other_hash = bucket_hash(other, key);
        idx = bucket_scan(other, other_hash, key);
        if (idx == IDX_NIL)
                return -ENOENT;

        e = bucket_at(other, idx);

        n = &bucket_at_swap(&swap, IDX_PUT)->p.b;
        n->key = e->key;
        if (h->type != HASHMAP_TYPE_SET)
                ((struct plain_hashmap_entry*) n)->value =
                        ((struct plain_hashmap_entry*) e)->value;
        r = hashmap_put_boldly(h, h_hash, &swap, true);
        if (r < 0)
                return r;

        remove_entry(other, idx);
        return 0;
}

HashmapBase* _hashmap_copy(HashmapBase *h  HASHMAP_DEBUG_PARAMS) {
        HashmapBase *copy;
        int r;

        assert(h);

        copy = hashmap_base_new(h->hash_ops, h->type  HASHMAP_DEBUG_PASS_ARGS);
        if (!copy)
                return NULL;

        switch (h->type) {
        case HASHMAP_TYPE_PLAIN:
        case HASHMAP_TYPE_ORDERED:
                r = hashmap_merge((Hashmap*)copy, (Hashmap*)h);
                break;
        case HASHMAP_TYPE_SET:
                r = set_merge((Set*)copy, (Set*)h);
                break;
        default:
                assert_not_reached();
        }

        if (r < 0)
                return _hashmap_free(copy, false, false);

        return copy;
}

char** _hashmap_get_strv(HashmapBase *h) {
        char **sv;
        Iterator i;
        unsigned idx, n;

        if (!h)
                return new0(char*, 1);

        sv = new(char*, n_entries(h)+1);
        if (!sv)
                return NULL;

        n = 0;
        HASHMAP_FOREACH_IDX(idx, h, i)
                sv[n++] = entry_value(h, bucket_at(h, idx));
        sv[n] = NULL;

        return sv;
}

void* ordered_hashmap_next(OrderedHashmap *h, const void *key) {
        struct ordered_hashmap_entry *e;
        unsigned hash, idx;

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx == IDX_NIL)
                return NULL;

        e = ordered_bucket_at(h, idx);
        if (e->iterate_next == IDX_NIL)
                return NULL;
        return ordered_bucket_at(h, e->iterate_next)->p.value;
}

int set_consume(Set *s, void *value) {
        int r;

        assert(s);
        assert(value);

        r = set_put(s, value);
        if (r <= 0)
                free(value);

        return r;
}

int _hashmap_put_strdup_full(Hashmap **h, const struct hash_ops *hash_ops, const char *k, const char *v  HASHMAP_DEBUG_PARAMS) {
        int r;

        r = _hashmap_ensure_allocated(h, hash_ops  HASHMAP_DEBUG_PASS_ARGS);
        if (r < 0)
                return r;

        _cleanup_free_ char *kdup = NULL, *vdup = NULL;

        kdup = strdup(k);
        if (!kdup)
                return -ENOMEM;

        if (v) {
                vdup = strdup(v);
                if (!vdup)
                        return -ENOMEM;
        }

        r = hashmap_put(*h, kdup, vdup);
        if (r < 0) {
                if (r == -EEXIST && streq_ptr(v, hashmap_get(*h, kdup)))
                        return 0;
                return r;
        }

        /* 0 with non-null vdup would mean vdup is already in the hashmap, which cannot be */
        assert(vdup == NULL || r > 0);
        if (r > 0)
                kdup = vdup = NULL;

        return r;
}

int _set_put_strndup_full(Set **s, const struct hash_ops *hash_ops, const char *p, size_t n  HASHMAP_DEBUG_PARAMS) {
        char *c;
        int r;

        assert(s);
        assert(p);

        r = _set_ensure_allocated(s, hash_ops  HASHMAP_DEBUG_PASS_ARGS);
        if (r < 0)
                return r;

        if (n == SIZE_MAX) {
                if (set_contains(*s, (char*) p))
                        return 0;

                c = strdup(p);
        } else
                c = strndup(p, n);
        if (!c)
                return -ENOMEM;

        return set_consume(*s, c);
}

int _set_put_strdupv_full(Set **s, const struct hash_ops *hash_ops, char **l  HASHMAP_DEBUG_PARAMS) {
        int n = 0, r;

        assert(s);

        STRV_FOREACH(i, l) {
                r = _set_put_strndup_full(s, hash_ops, *i, SIZE_MAX  HASHMAP_DEBUG_PASS_ARGS);
                if (r < 0)
                        return r;

                n += r;
        }

        return n;
}

int set_put_strsplit(Set *s, const char *v, const char *separators, ExtractFlags flags) {
        const char *p = v;
        int r;

        assert(s);
        assert(v);

        for (;;) {
                char *word;

                r = extract_first_word(&p, &word, separators, flags);
                if (r <= 0)
                        return r;

                r = set_consume(s, word);
                if (r < 0)
                        return r;
        }
}

/* expand the cachemem if needed, return true if newly (re)activated. */
static int cachemem_maintain(CacheMem *mem, size_t size) {
        assert(mem);

        if (!GREEDY_REALLOC(mem->ptr, size)) {
                if (size > 0)
                        return -ENOMEM;
        }

        if (!mem->active) {
                mem->active = true;
                return true;
        }

        return false;
}

int iterated_cache_get(IteratedCache *cache, const void ***res_keys, const void ***res_values, unsigned *res_n_entries) {
        bool sync_keys = false, sync_values = false;
        size_t size;
        int r;

        assert(cache);
        assert(cache->hashmap);

        size = n_entries(cache->hashmap);

        if (res_keys) {
                r = cachemem_maintain(&cache->keys, size);
                if (r < 0)
                        return r;

                sync_keys = r;
        } else
                cache->keys.active = false;

        if (res_values) {
                r = cachemem_maintain(&cache->values, size);
                if (r < 0)
                        return r;

                sync_values = r;
        } else
                cache->values.active = false;

        if (cache->hashmap->dirty) {
                if (cache->keys.active)
                        sync_keys = true;
                if (cache->values.active)
                        sync_values = true;

                cache->hashmap->dirty = false;
        }

        if (sync_keys || sync_values) {
                unsigned i, idx;
                Iterator iter;

                i = 0;
                HASHMAP_FOREACH_IDX(idx, cache->hashmap, iter) {
                        struct hashmap_base_entry *e;

                        e = bucket_at(cache->hashmap, idx);

                        if (sync_keys)
                                cache->keys.ptr[i] = e->key;
                        if (sync_values)
                                cache->values.ptr[i] = entry_value(cache->hashmap, e);
                        i++;
                }
        }

        if (res_keys)
                *res_keys = cache->keys.ptr;
        if (res_values)
                *res_values = cache->values.ptr;
        if (res_n_entries)
                *res_n_entries = size;

        return 0;
}

IteratedCache* iterated_cache_free(IteratedCache *cache) {
        if (cache) {
                free(cache->keys.ptr);
                free(cache->values.ptr);
        }

        return mfree(cache);
}

int set_strjoin(Set *s, const char *separator, bool wrap_with_separator, char **ret) {
        _cleanup_free_ char *str = NULL;
        size_t separator_len, len = 0;
        const char *value;
        bool first;

        assert(ret);

        if (set_isempty(s)) {
                *ret = NULL;
                return 0;
        }

        separator_len = strlen_ptr(separator);

        if (separator_len == 0)
                wrap_with_separator = false;

        first = !wrap_with_separator;

        SET_FOREACH(value, s) {
                size_t l = strlen_ptr(value);

                if (l == 0)
                        continue;

                if (!GREEDY_REALLOC(str, len + l + (first ? 0 : separator_len) + (wrap_with_separator ? separator_len : 0) + 1))
                        return -ENOMEM;

                if (separator_len > 0 && !first) {
                        memcpy(str + len, separator, separator_len);
                        len += separator_len;
                }

                memcpy(str + len, value, l);
                len += l;
                first = false;
        }

        if (wrap_with_separator) {
                memcpy(str + len, separator, separator_len);
                len += separator_len;
        }

        str[len] = '\0';

        *ret = TAKE_PTR(str);
        return 0;
}

bool set_equal(Set *a, Set *b) {
        void *p;

        /* Checks whether each entry of 'a' is also in 'b' and vice versa, i.e. the two sets contain the same
         * entries */

        if (a == b)
                return true;

        if (set_isempty(a) && set_isempty(b))
                return true;

        if (set_size(a) != set_size(b)) /* Cheap check that hopefully catches a lot of inequality cases
                                         * already */
                return false;

        SET_FOREACH(p, a)
                if (!set_contains(b, p))
                        return false;

        /* If we have the same hashops, then we don't need to check things backwards given we compared the
         * size and that all of a is in b. */
        if (a->b.hash_ops == b->b.hash_ops)
                return true;

        SET_FOREACH(p, b)
                if (!set_contains(a, p))
                        return false;

        return true;
}

static bool set_fnmatch_one(Set *patterns, const char *needle) {
        const char *p;

        assert(needle);

        SET_FOREACH(p, patterns)
                if (fnmatch(p, needle, 0) == 0)
                        return true;

        return false;
}

bool set_fnmatch(Set *include_patterns, Set *exclude_patterns, const char *needle) {
        assert(needle);

        if (set_fnmatch_one(exclude_patterns, needle))
                return false;

        if (set_isempty(include_patterns))
                return true;

        return set_fnmatch_one(include_patterns, needle);
}
