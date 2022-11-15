/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct DnsAnswer DnsAnswer;
typedef struct DnsAnswerItem DnsAnswerItem;

#include "macro.h"
#include "ordered-set.h"
#include "resolved-dns-rr.h"

/* A simple array of resource records. We keep track of the originating ifindex for each RR where that makes
 * sense, so that we can qualify A and AAAA RRs referring to a local link with the right ifindex.
 *
 * Note that we usually encode the empty DnsAnswer object as a simple NULL. */

typedef enum DnsAnswerFlags {
        DNS_ANSWER_AUTHENTICATED      = 1 << 0, /* Item has been authenticated */
        DNS_ANSWER_CACHEABLE          = 1 << 1, /* Item is subject to caching */
        DNS_ANSWER_SHARED_OWNER       = 1 << 2, /* For mDNS: RRset may be owner by multiple peers */
        DNS_ANSWER_CACHE_FLUSH        = 1 << 3, /* For mDNS: sets cache-flush bit in the rrclass of response records */
        DNS_ANSWER_GOODBYE            = 1 << 4, /* For mDNS: item is subject to disappear */
        DNS_ANSWER_SECTION_ANSWER     = 1 << 5, /* When parsing: RR originates from answer section */
        DNS_ANSWER_SECTION_AUTHORITY  = 1 << 6, /* When parsing: RR originates from authority section */
        DNS_ANSWER_SECTION_ADDITIONAL = 1 << 7, /* When parsing: RR originates from additional section */

        DNS_ANSWER_MASK_SECTIONS      = DNS_ANSWER_SECTION_ANSWER|
                                        DNS_ANSWER_SECTION_AUTHORITY|
                                        DNS_ANSWER_SECTION_ADDITIONAL,
} DnsAnswerFlags;

struct DnsAnswerItem {
        unsigned n_ref;
        DnsResourceRecord *rr;
        DnsResourceRecord *rrsig; /* Optionally, also store RRSIG RR that successfully validates this item */
        int ifindex;
        DnsAnswerFlags flags;
};

struct DnsAnswer {
        unsigned n_ref;
        OrderedSet *items;
};

DnsAnswer *dns_answer_new(size_t n);
DnsAnswer *dns_answer_ref(DnsAnswer *a);
DnsAnswer *dns_answer_unref(DnsAnswer *a);

#define DNS_ANSWER_REPLACE(a, b)                \
        do {                                    \
                typeof(a)* _a = &(a);           \
                typeof(b) _b = (b);             \
                dns_answer_unref(*_a);          \
                *_a = _b;                       \
        } while(0)

int dns_answer_add(DnsAnswer *a, DnsResourceRecord *rr, int ifindex, DnsAnswerFlags flags, DnsResourceRecord *rrsig);
int dns_answer_add_extend(DnsAnswer **a, DnsResourceRecord *rr, int ifindex, DnsAnswerFlags flags, DnsResourceRecord *rrsig);
int dns_answer_add_soa(DnsAnswer *a, const char *name, uint32_t ttl, int ifindex);

int dns_answer_match_key(DnsAnswer *a, const DnsResourceKey *key, DnsAnswerFlags *ret_flags);
bool dns_answer_contains_nsec_or_nsec3(DnsAnswer *a);
int dns_answer_contains_zone_nsec3(DnsAnswer *answer, const char *zone);
bool dns_answer_contains(DnsAnswer *answer, DnsResourceRecord *rr);

int dns_answer_find_soa(DnsAnswer *a, const DnsResourceKey *key, DnsResourceRecord **ret, DnsAnswerFlags *ret_flags);
int dns_answer_find_cname_or_dname(DnsAnswer *a, const DnsResourceKey *key, DnsResourceRecord **ret, DnsAnswerFlags *ret_flags);

int dns_answer_merge(DnsAnswer *a, DnsAnswer *b, DnsAnswer **ret);
int dns_answer_extend(DnsAnswer **a, DnsAnswer *b);

void dns_answer_order_by_scope(DnsAnswer *a, bool prefer_link_local);

int dns_answer_reserve(DnsAnswer **a, size_t n_free);
int dns_answer_reserve_or_clone(DnsAnswer **a, size_t n_free);

int dns_answer_remove_by_key(DnsAnswer **a, const DnsResourceKey *key);
int dns_answer_remove_by_rr(DnsAnswer **a, DnsResourceRecord *rr);
int dns_answer_remove_by_answer_keys(DnsAnswer **a, DnsAnswer *b);

int dns_answer_copy_by_key(DnsAnswer **a, DnsAnswer *source, const DnsResourceKey *key, DnsAnswerFlags or_flags, DnsResourceRecord *rrsig);
int dns_answer_move_by_key(DnsAnswer **to, DnsAnswer **from, const DnsResourceKey *key, DnsAnswerFlags or_flags, DnsResourceRecord *rrsig);

int dns_answer_has_dname_for_cname(DnsAnswer *a, DnsResourceRecord *cname);

static inline size_t dns_answer_size(DnsAnswer *a) {
        return a ? ordered_set_size(a->items) : 0;
}

static inline bool dns_answer_isempty(DnsAnswer *a) {
        return dns_answer_size(a) <= 0;
}

void dns_answer_dump(DnsAnswer *answer, FILE *f);

void dns_answer_randomize(DnsAnswer *a);

uint32_t dns_answer_min_ttl(DnsAnswer *a);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsAnswer*, dns_answer_unref);

typedef struct DnsAnswerIterator {
        Iterator iterator;
        DnsAnswer *answer;
        DnsAnswerItem *item;
} DnsAnswerIterator;

#define _DNS_ANSWER_FOREACH(kk, a, i)                                   \
        for (DnsAnswerIterator i = { .iterator = ITERATOR_FIRST, .answer = (a) };  \
             i.answer &&                                                \
             ordered_set_iterate(i.answer->items, &i.iterator, (void**) &(i.item)) && \
             (kk = i.item->rr, true); )

#define DNS_ANSWER_FOREACH(rr, a) _DNS_ANSWER_FOREACH(rr, a, UNIQ_T(i, UNIQ))

#define _DNS_ANSWER_FOREACH_IFINDEX(kk, ifi, a, i)                      \
        for (DnsAnswerIterator i = { .iterator = ITERATOR_FIRST, .answer = (a) };  \
             i.answer &&                                                \
             ordered_set_iterate(i.answer->items, &i.iterator, (void**) &(i.item)) && \
             (kk = i.item->rr, ifi = i.item->ifindex, true); )

#define DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, a) _DNS_ANSWER_FOREACH_IFINDEX(rr, ifindex, a, UNIQ_T(i, UNIQ))

#define _DNS_ANSWER_FOREACH_FLAGS(kk, fl, a, i)                         \
        for (DnsAnswerIterator i = { .iterator = ITERATOR_FIRST, .answer = (a) };  \
             i.answer &&                                                \
             ordered_set_iterate(i.answer->items, &i.iterator, (void**) &(i.item)) && \
             (kk = i.item->rr, fl = i.item->flags, true); )

#define DNS_ANSWER_FOREACH_FLAGS(rr, flags, a) _DNS_ANSWER_FOREACH_FLAGS(rr, flags, a, UNIQ_T(i, UNIQ))

#define _DNS_ANSWER_FOREACH_ITEM(it, a, i)                            \
        for (DnsAnswerIterator i = { .iterator = ITERATOR_FIRST, .answer = (a) };  \
             i.answer &&                                                \
             ordered_set_iterate(i.answer->items, &i.iterator, (void**) &(i.item)) && \
             (it = i.item, true); )

#define DNS_ANSWER_FOREACH_ITEM(item, a) _DNS_ANSWER_FOREACH_ITEM(item, a, UNIQ_T(i, UNIQ))
