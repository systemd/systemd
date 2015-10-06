/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2014 Michal Schmidt

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

#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#include "util.h"
#include "hashmap.h"
#include "set.h"
#include "macro.h"
#include "siphash24.h"
#include "strv.h"
#include "mempool.h"
#include "random-util.h"

#ifdef ENABLE_DEBUG_HASHMAP
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
 * All entry types can fit into a ordered_hashmap_entry. */
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

#ifdef ENABLE_DEBUG_HASHMAP
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

#define HASHMAP_DEBUG_FIELDS struct hashmap_debug_info debug;

#else /* !ENABLE_DEBUG_HASHMAP */
#define HASHMAP_DEBUG_FIELDS
#endif /* ENABLE_DEBUG_HASHMAP */

enum HashmapType {
        HASHMAP_TYPE_PLAIN,
        HASHMAP_TYPE_ORDERED,
        HASHMAP_TYPE_SET,
        _HASHMAP_TYPE_MAX
};

struct _packed_ indirect_storage {
        char    *storage;                  /* where buckets and DIBs are stored */
        uint8_t  hash_key[HASH_KEY_SIZE];  /* hash key; changes during resize */

        unsigned n_entries;                /* number of stored entries */
        unsigned n_buckets;                /* number of buckets */

        unsigned idx_lowest_entry;         /* Index below which all buckets are free.
                                              Makes "while(hashmap_steal_first())" loops
                                              O(n) instead of O(n^2) for unordered hashmaps. */
        uint8_t  _pad[3];                  /* padding for the whole HashmapBase */
        /* The bitfields in HashmapBase complete the alignment of the whole thing. */
};

struct direct_storage {
        /* This gives us 39 bytes on 64bit, or 35 bytes on 32bit.
         * That's room for 4 set_entries + 4 DIB bytes + 3 unused bytes on 64bit,
         *              or 7 set_entries + 7 DIB bytes + 0 unused bytes on 32bit. */
        char storage[sizeof(struct indirect_storage)];
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
static bool shared_hash_key_initialized;

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
        HASHMAP_DEBUG_FIELDS         /* optional hashmap_debug_info */
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

static const struct hashmap_type_info hashmap_type_info[_HASHMAP_TYPE_MAX] = {
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

void string_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(p, strlen(p) + 1, state);
}

int string_compare_func(const void *a, const void *b) {
        return strcmp(a, b);
}

const struct hash_ops string_hash_ops = {
        .hash = string_hash_func,
        .compare = string_compare_func
};

void trivial_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(&p, sizeof(p), state);
}

int trivial_compare_func(const void *a, const void *b) {
        return a < b ? -1 : (a > b ? 1 : 0);
}

const struct hash_ops trivial_hash_ops = {
        .hash = trivial_hash_func,
        .compare = trivial_compare_func
};

void uint64_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(p, sizeof(uint64_t), state);
}

int uint64_compare_func(const void *_a, const void *_b) {
        uint64_t a, b;
        a = *(const uint64_t*) _a;
        b = *(const uint64_t*) _b;
        return a < b ? -1 : (a > b ? 1 : 0);
}

const struct hash_ops uint64_hash_ops = {
        .hash = uint64_hash_func,
        .compare = uint64_compare_func
};

#if SIZEOF_DEV_T != 8
void devt_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(p, sizeof(dev_t), state);
}

int devt_compare_func(const void *_a, const void *_b) {
        dev_t a, b;
        a = *(const dev_t*) _a;
        b = *(const dev_t*) _b;
        return a < b ? -1 : (a > b ? 1 : 0);
}

const struct hash_ops devt_hash_ops = {
        .hash = devt_hash_func,
        .compare = devt_compare_func
};
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

static char *storage_ptr(HashmapBase *h) {
        return h->has_indirect ? h->indirect.storage
                               : h->direct.storage;
}

static uint8_t *hash_key(HashmapBase *h) {
        return h->has_indirect ? h->indirect.hash_key
                               : shared_hash_key;
}

static unsigned base_bucket_hash(HashmapBase *h, const void *p) {
        struct siphash state;
        uint64_t hash;

        siphash24_init(&state, hash_key(h));

        h->hash_ops->hash(p, &state);

        siphash24_finalize((uint8_t*)&hash, &state);

        return (unsigned) (hash % n_buckets(h));
}
#define bucket_hash(h, p) base_bucket_hash(HASHMAP_BASE(h), p)

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

static struct hashmap_base_entry *bucket_at(HashmapBase *h, unsigned idx) {
        return (struct hashmap_base_entry*)
                (storage_ptr(h) + idx * hashmap_type_info[h->type].entry_size);
}

static struct plain_hashmap_entry *plain_bucket_at(Hashmap *h, unsigned idx) {
        return (struct plain_hashmap_entry*) bucket_at(HASHMAP_BASE(h), idx);
}

static struct ordered_hashmap_entry *ordered_bucket_at(OrderedHashmap *h, unsigned idx) {
        return (struct ordered_hashmap_entry*) bucket_at(HASHMAP_BASE(h), idx);
}

static struct set_entry *set_bucket_at(Set *h, unsigned idx) {
        return (struct set_entry*) bucket_at(HASHMAP_BASE(h), idx);
}

static struct ordered_hashmap_entry *bucket_at_swap(struct swap_entries *swap, unsigned idx) {
        return &swap->e[idx - _IDX_SWAP_BEGIN];
}

/* Returns a pointer to the bucket at index idx.
 * Understands real indexes and swap indexes, hence "_virtual". */
static struct hashmap_base_entry *bucket_at_virtual(HashmapBase *h, struct swap_entries *swap,
                                                    unsigned idx) {
        if (idx < _IDX_SWAP_BEGIN)
                return bucket_at(h, idx);

        if (idx < _IDX_SWAP_END)
                return &bucket_at_swap(swap, idx)->p.b;

        assert_not_reached("Invalid index");
}

static dib_raw_t *dib_raw_ptr(HashmapBase *h) {
        return (dib_raw_t*)
                (storage_ptr(h) + hashmap_type_info[h->type].entry_size * n_buckets(h));
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

static void *entry_value(HashmapBase *h, struct hashmap_base_entry *e) {
        switch (h->type) {

        case HASHMAP_TYPE_PLAIN:
        case HASHMAP_TYPE_ORDERED:
                return ((struct plain_hashmap_entry*)e)->value;

        case HASHMAP_TYPE_SET:
                return (void*) e->key;

        default:
                assert_not_reached("Unknown hashmap type");
        }
}

static void base_remove_entry(HashmapBase *h, unsigned idx) {
        unsigned left, right, prev, dib;
        dib_raw_t raw_dib, *dibs;

        dibs = dib_raw_ptr(h);
        assert(dibs[idx] != DIB_RAW_FREE);

#ifdef ENABLE_DEBUG_HASHMAP
        h->debug.rem_count++;
        h->debug.last_rem_idx = idx;
#endif

        left = idx;
        /* Find the stop bucket ("right"). It is either free or has DIB == 0. */
        for (right = next_idx(h, left); ; right = next_idx(h, right)) {
                raw_dib = dibs[right];
                if (raw_dib == 0 || raw_dib == DIB_RAW_FREE)
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

#ifdef ENABLE_DEBUG_HASHMAP
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
#ifdef ENABLE_DEBUG_HASHMAP
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

#ifdef ENABLE_DEBUG_HASHMAP
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

bool internal_hashmap_iterate(HashmapBase *h, Iterator *i, void **value, const void **key) {
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

bool set_iterate(Set *s, Iterator *i, void **value) {
        return internal_hashmap_iterate(HASHMAP_BASE(s), i, value, NULL);
}

#define HASHMAP_FOREACH_IDX(idx, h, i) \
        for ((i) = ITERATOR_FIRST, (idx) = hashmap_iterate_entry((h), &(i)); \
             (idx != IDX_NIL); \
             (idx) = hashmap_iterate_entry((h), &(i)))

static void reset_direct_storage(HashmapBase *h) {
        const struct hashmap_type_info *hi = &hashmap_type_info[h->type];
        void *p;

        assert(!h->has_indirect);

        p = mempset(h->direct.storage, 0, hi->entry_size * hi->n_direct_buckets);
        memset(p, DIB_RAW_INIT, sizeof(dib_raw_t) * hi->n_direct_buckets);
}

static struct HashmapBase *hashmap_base_new(const struct hash_ops *hash_ops, enum HashmapType type HASHMAP_DEBUG_PARAMS) {
        HashmapBase *h;
        const struct hashmap_type_info *hi = &hashmap_type_info[type];
        bool use_pool;

        use_pool = is_main_thread();

        h = use_pool ? mempool_alloc0_tile(hi->mempool) : malloc0(hi->head_size);

        if (!h)
                return NULL;

        h->type = type;
        h->from_pool = use_pool;
        h->hash_ops = hash_ops ? hash_ops : &trivial_hash_ops;

        if (type == HASHMAP_TYPE_ORDERED) {
                OrderedHashmap *lh = (OrderedHashmap*)h;
                lh->iterate_list_head = lh->iterate_list_tail = IDX_NIL;
        }

        reset_direct_storage(h);

        if (!shared_hash_key_initialized) {
                random_bytes(shared_hash_key, sizeof(shared_hash_key));
                shared_hash_key_initialized= true;
        }

#ifdef ENABLE_DEBUG_HASHMAP
        h->debug.func = func;
        h->debug.file = file;
        h->debug.line = line;
        assert_se(pthread_mutex_lock(&hashmap_debug_list_mutex) == 0);
        LIST_PREPEND(debug_list, hashmap_debug_list, &h->debug);
        assert_se(pthread_mutex_unlock(&hashmap_debug_list_mutex) == 0);
#endif

        return h;
}

Hashmap *internal_hashmap_new(const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS) {
        return (Hashmap*)        hashmap_base_new(hash_ops, HASHMAP_TYPE_PLAIN HASHMAP_DEBUG_PASS_ARGS);
}

OrderedHashmap *internal_ordered_hashmap_new(const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS) {
        return (OrderedHashmap*) hashmap_base_new(hash_ops, HASHMAP_TYPE_ORDERED HASHMAP_DEBUG_PASS_ARGS);
}

Set *internal_set_new(const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS) {
        return (Set*)            hashmap_base_new(hash_ops, HASHMAP_TYPE_SET HASHMAP_DEBUG_PASS_ARGS);
}

static int hashmap_base_ensure_allocated(HashmapBase **h, const struct hash_ops *hash_ops,
                                         enum HashmapType type HASHMAP_DEBUG_PARAMS) {
        HashmapBase *q;

        assert(h);

        if (*h)
                return 0;

        q = hashmap_base_new(hash_ops, type HASHMAP_DEBUG_PASS_ARGS);
        if (!q)
                return -ENOMEM;

        *h = q;
        return 0;
}

int internal_hashmap_ensure_allocated(Hashmap **h, const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS) {
        return hashmap_base_ensure_allocated((HashmapBase**)h, hash_ops, HASHMAP_TYPE_PLAIN HASHMAP_DEBUG_PASS_ARGS);
}

int internal_ordered_hashmap_ensure_allocated(OrderedHashmap **h, const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS) {
        return hashmap_base_ensure_allocated((HashmapBase**)h, hash_ops, HASHMAP_TYPE_ORDERED HASHMAP_DEBUG_PASS_ARGS);
}

int internal_set_ensure_allocated(Set **s, const struct hash_ops *hash_ops  HASHMAP_DEBUG_PARAMS) {
        return hashmap_base_ensure_allocated((HashmapBase**)s, hash_ops, HASHMAP_TYPE_SET HASHMAP_DEBUG_PASS_ARGS);
}

static void hashmap_free_no_clear(HashmapBase *h) {
        assert(!h->has_indirect);
        assert(!h->n_direct_entries);

#ifdef ENABLE_DEBUG_HASHMAP
        assert_se(pthread_mutex_lock(&hashmap_debug_list_mutex) == 0);
        LIST_REMOVE(debug_list, hashmap_debug_list, &h->debug);
        assert_se(pthread_mutex_unlock(&hashmap_debug_list_mutex) == 0);
#endif

        if (h->from_pool)
                mempool_free_tile(hashmap_type_info[h->type].mempool, h);
        else
                free(h);
}

HashmapBase *internal_hashmap_free(HashmapBase *h) {

        /* Free the hashmap, but nothing in it */

        if (h) {
                internal_hashmap_clear(h);
                hashmap_free_no_clear(h);
        }

        return NULL;
}

HashmapBase *internal_hashmap_free_free(HashmapBase *h) {

        /* Free the hashmap and all data objects in it, but not the
         * keys */

        if (h) {
                internal_hashmap_clear_free(h);
                hashmap_free_no_clear(h);
        }

        return NULL;
}

Hashmap *hashmap_free_free_free(Hashmap *h) {

        /* Free the hashmap and all data and key objects in it */

        if (h) {
                hashmap_clear_free_free(h);
                hashmap_free_no_clear(HASHMAP_BASE(h));
        }

        return NULL;
}

void internal_hashmap_clear(HashmapBase *h) {
        if (!h)
                return;

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
}

void internal_hashmap_clear_free(HashmapBase *h) {
        unsigned idx;

        if (!h)
                return;

        for (idx = skip_free_buckets(h, 0); idx != IDX_NIL;
             idx = skip_free_buckets(h, idx + 1))
                free(entry_value(h, bucket_at(h, idx)));

        internal_hashmap_clear(h);
}

void hashmap_clear_free_free(Hashmap *h) {
        unsigned idx;

        if (!h)
                return;

        for (idx = skip_free_buckets(HASHMAP_BASE(h), 0); idx != IDX_NIL;
             idx = skip_free_buckets(HASHMAP_BASE(h), idx + 1)) {
                struct plain_hashmap_entry *e = plain_bucket_at(h, idx);
                free((void*)e->b.key);
                free(e->value);
        }

        internal_hashmap_clear(HASHMAP_BASE(h));
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

#ifdef ENABLE_DEBUG_HASHMAP
        h->debug.put_count++;
#endif

        dibs = dib_raw_ptr(h);

        for (distance = 0; ; distance++) {
                raw_dib = dibs[idx];
                if (raw_dib == DIB_RAW_FREE || raw_dib == DIB_RAW_REHASH) {
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
#ifdef ENABLE_DEBUG_HASHMAP
        h->debug.max_entries = MAX(h->debug.max_entries, n_entries(h));
#endif

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
        char *new_storage;
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

        old_dibs = (dib_raw_t*)(new_storage + hi->entry_size * old_n_buckets);
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

int hashmap_replace(Hashmap *h, const void *key, void *value) {
        struct swap_entries swap;
        struct plain_hashmap_entry *e;
        unsigned hash, idx;

        assert(h);

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx != IDX_NIL) {
                e = plain_bucket_at(h, idx);
#ifdef ENABLE_DEBUG_HASHMAP
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
        return 0;
}

void *internal_hashmap_get(HashmapBase *h, const void *key) {
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

void *hashmap_get2(Hashmap *h, const void *key, void **key2) {
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

bool internal_hashmap_contains(HashmapBase *h, const void *key) {
        unsigned hash;

        if (!h)
                return false;

        hash = bucket_hash(h, key);
        return bucket_scan(h, hash, key) != IDX_NIL;
}

void *internal_hashmap_remove(HashmapBase *h, const void *key) {
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

void *hashmap_remove2(Hashmap *h, const void *key, void **rkey) {
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

void *hashmap_remove_value(Hashmap *h, const void *key, void *value) {
        struct plain_hashmap_entry *e;
        unsigned hash, idx;

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx == IDX_NIL)
                return NULL;

        e = plain_bucket_at(h, idx);
        if (e->value != value)
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

void *internal_hashmap_first(HashmapBase *h) {
        unsigned idx;

        idx = find_first_entry(h);
        if (idx == IDX_NIL)
                return NULL;

        return entry_value(h, bucket_at(h, idx));
}

void *internal_hashmap_first_key(HashmapBase *h) {
        struct hashmap_base_entry *e;
        unsigned idx;

        idx = find_first_entry(h);
        if (idx == IDX_NIL)
                return NULL;

        e = bucket_at(h, idx);
        return (void*) e->key;
}

void *internal_hashmap_steal_first(HashmapBase *h) {
        struct hashmap_base_entry *e;
        void *data;
        unsigned idx;

        idx = find_first_entry(h);
        if (idx == IDX_NIL)
                return NULL;

        e = bucket_at(h, idx);
        data = entry_value(h, e);
        remove_entry(h, idx);

        return data;
}

void *internal_hashmap_steal_first_key(HashmapBase *h) {
        struct hashmap_base_entry *e;
        void *key;
        unsigned idx;

        idx = find_first_entry(h);
        if (idx == IDX_NIL)
                return NULL;

        e = bucket_at(h, idx);
        key = (void*) e->key;
        remove_entry(h, idx);

        return key;
}

unsigned internal_hashmap_size(HashmapBase *h) {

        if (!h)
                return 0;

        return n_entries(h);
}

unsigned internal_hashmap_buckets(HashmapBase *h) {

        if (!h)
                return 0;

        return n_buckets(h);
}

int internal_hashmap_merge(Hashmap *h, Hashmap *other) {
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

int internal_hashmap_reserve(HashmapBase *h, unsigned entries_add) {
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
int internal_hashmap_move(HashmapBase *h, HashmapBase *other) {
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

int internal_hashmap_move_one(HashmapBase *h, HashmapBase *other, const void *key) {
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

HashmapBase *internal_hashmap_copy(HashmapBase *h) {
        HashmapBase *copy;
        int r;

        assert(h);

        copy = hashmap_base_new(h->hash_ops, h->type  HASHMAP_DEBUG_SRC_ARGS);
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
                assert_not_reached("Unknown hashmap type");
        }

        if (r < 0) {
                internal_hashmap_free(copy);
                return NULL;
        }

        return copy;
}

char **internal_hashmap_get_strv(HashmapBase *h) {
        char **sv;
        Iterator i;
        unsigned idx, n;

        sv = new(char*, n_entries(h)+1);
        if (!sv)
                return NULL;

        n = 0;
        HASHMAP_FOREACH_IDX(idx, h, i)
                sv[n++] = entry_value(h, bucket_at(h, idx));
        sv[n] = NULL;

        return sv;
}

void *ordered_hashmap_next(OrderedHashmap *h, const void *key) {
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

        r = set_put(s, value);
        if (r <= 0)
                free(value);

        return r;
}

int set_put_strdup(Set *s, const char *p) {
        char *c;
        int r;

        assert(s);
        assert(p);

        c = strdup(p);
        if (!c)
                return -ENOMEM;

        r = set_consume(s, c);
        if (r == -EEXIST)
                return 0;

        return r;
}

int set_put_strdupv(Set *s, char **l) {
        int n = 0, r;
        char **i;

        STRV_FOREACH(i, l) {
                r = set_put_strdup(s, *i);
                if (r < 0)
                        return r;

                n += r;
        }

        return n;
}
