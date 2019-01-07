/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct DnsAnswer DnsAnswer;
typedef struct DnsAnswerItem DnsAnswerItem;

#include "macro.h"
#include "resolved-dns-rr.h"

/* A simple array of resource records. We keep track of the
 * originating ifindex for each RR where that makes sense, so that we
 * can qualify A and AAAA RRs referring to a local link with the
 * right ifindex.
 *
 * Note that we usually encode the empty DnsAnswer object as a simple NULL. */

typedef enum DnsAnswerFlags {
        DNS_ANSWER_AUTHENTICATED = 1 << 0, /* Item has been authenticated */
        DNS_ANSWER_CACHEABLE     = 1 << 1, /* Item is subject to caching */
        DNS_ANSWER_SHARED_OWNER  = 1 << 2, /* For mDNS: RRset may be owner by multiple peers */
        DNS_ANSWER_CACHE_FLUSH   = 1 << 3, /* For mDNS: sets cache-flush bit in the rrclass of response records */
        DNS_ANSWER_GOODBYE       = 1 << 4, /* For mDNS: item is subject to disappear */
} DnsAnswerFlags;

struct DnsAnswerItem {
        DnsResourceRecord *rr;
        int ifindex;
        DnsAnswerFlags flags;
};

struct DnsAnswer {
        unsigned n_ref;
        size_t n_rrs, n_allocated;
        DnsAnswerItem items[0];
};

DnsAnswer *dns_answer_new(size_t n);
DnsAnswer *dns_answer_ref(DnsAnswer *a);
DnsAnswer *dns_answer_unref(DnsAnswer *a);

int dns_answer_add(DnsAnswer *a, DnsResourceRecord *rr, int ifindex, DnsAnswerFlags flags);
int dns_answer_add_extend(DnsAnswer **a, DnsResourceRecord *rr, int ifindex, DnsAnswerFlags flags);
int dns_answer_add_soa(DnsAnswer *a, const char *name, uint32_t ttl, int ifindex);

int dns_answer_match_key(DnsAnswer *a, const DnsResourceKey *key, DnsAnswerFlags *combined_flags);
int dns_answer_contains_nsec_or_nsec3(DnsAnswer *a);
int dns_answer_contains_zone_nsec3(DnsAnswer *answer, const char *zone);

int dns_answer_find_soa(DnsAnswer *a, const DnsResourceKey *key, DnsResourceRecord **ret, DnsAnswerFlags *flags);
int dns_answer_find_cname_or_dname(DnsAnswer *a, const DnsResourceKey *key, DnsResourceRecord **ret, DnsAnswerFlags *flags);

int dns_answer_merge(DnsAnswer *a, DnsAnswer *b, DnsAnswer **ret);
int dns_answer_extend(DnsAnswer **a, DnsAnswer *b);

void dns_answer_order_by_scope(DnsAnswer *a, bool prefer_link_local);

int dns_answer_reserve(DnsAnswer **a, size_t n_free);
int dns_answer_reserve_or_clone(DnsAnswer **a, size_t n_free);

int dns_answer_remove_by_key(DnsAnswer **a, const DnsResourceKey *key);
int dns_answer_remove_by_rr(DnsAnswer **a, DnsResourceRecord *rr);

int dns_answer_copy_by_key(DnsAnswer **a, DnsAnswer *source, const DnsResourceKey *key, DnsAnswerFlags or_flags);
int dns_answer_move_by_key(DnsAnswer **to, DnsAnswer **from, const DnsResourceKey *key, DnsAnswerFlags or_flags);

int dns_answer_has_dname_for_cname(DnsAnswer *a, DnsResourceRecord *cname);

static inline size_t dns_answer_size(DnsAnswer *a) {
        return a ? a->n_rrs : 0;
}

static inline bool dns_answer_isempty(DnsAnswer *a) {
        return dns_answer_size(a) <= 0;
}

void dns_answer_dump(DnsAnswer *answer, FILE *f);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsAnswer*, dns_answer_unref);

#define _DNS_ANSWER_FOREACH(q, kk, a)                                   \
        for (size_t UNIQ_T(i, q) = ({                                   \
                                (kk) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].rr : NULL; \
                                0;                                      \
                        });                                             \
             (a) && (UNIQ_T(i, q) < (a)->n_rrs);                        \
             UNIQ_T(i, q)++, (kk) = (UNIQ_T(i, q) < (a)->n_rrs ? (a)->items[UNIQ_T(i, q)].rr : NULL))

#define DNS_ANSWER_FOREACH(kk, a) _DNS_ANSWER_FOREACH(UNIQ, kk, a)

#define _DNS_ANSWER_FOREACH_IFINDEX(q, kk, ifi, a)                      \
        for (size_t UNIQ_T(i, q) = ({                                   \
                                (kk) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].rr : NULL; \
                                (ifi) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].ifindex : 0; \
                                0;                                      \
                        });                                             \
             (a) && (UNIQ_T(i, q) < (a)->n_rrs);                        \
             UNIQ_T(i, q)++,                                            \
                     (kk) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].rr : NULL), \
                     (ifi) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].ifindex : 0))

#define DNS_ANSWER_FOREACH_IFINDEX(kk, ifindex, a) _DNS_ANSWER_FOREACH_IFINDEX(UNIQ, kk, ifindex, a)

#define _DNS_ANSWER_FOREACH_FLAGS(q, kk, fl, a)                         \
        for (size_t UNIQ_T(i, q) = ({                                   \
                                (kk) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].rr : NULL; \
                                (fl) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].flags : 0; \
                                0;                                      \
                        });                                             \
             (a) && (UNIQ_T(i, q) < (a)->n_rrs);                        \
             UNIQ_T(i, q)++,                                            \
                     (kk) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].rr : NULL), \
                     (fl) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].flags : 0))

#define DNS_ANSWER_FOREACH_FLAGS(kk, flags, a) _DNS_ANSWER_FOREACH_FLAGS(UNIQ, kk, flags, a)

#define _DNS_ANSWER_FOREACH_FULL(q, kk, ifi, fl, a)                     \
        for (size_t UNIQ_T(i, q) = ({                                   \
                                (kk) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].rr : NULL; \
                                (ifi) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].ifindex : 0; \
                                (fl) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].flags : 0; \
                                0;                                      \
                        });                                             \
             (a) && (UNIQ_T(i, q) < (a)->n_rrs);                        \
             UNIQ_T(i, q)++,                                            \
                     (kk) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].rr : NULL), \
                     (ifi) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].ifindex : 0), \
                     (fl) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].flags : 0))

#define DNS_ANSWER_FOREACH_FULL(kk, ifindex, flags, a) _DNS_ANSWER_FOREACH_FULL(UNIQ, kk, ifindex, flags, a)
