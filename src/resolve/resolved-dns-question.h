/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct DnsQuestion DnsQuestion;
typedef struct DnsQuestionItem DnsQuestionItem;

#include "macro.h"
#include "resolved-dns-rr.h"

/* A simple array of resource keys */

typedef enum DnsQuestionFlags {
        DNS_QUESTION_WANTS_UNICAST_REPLY = 1 << 0, /* For mDNS: sender is willing to accept unicast replies */
} DnsQuestionFlags;

struct DnsQuestionItem {
        DnsResourceKey *key;
        DnsQuestionFlags flags;
};

struct DnsQuestion {
        unsigned n_ref;
        size_t n_keys, n_allocated;
        DnsQuestionItem items[];
};

DnsQuestion *dns_question_new(size_t n);
DnsQuestion *dns_question_ref(DnsQuestion *q);
DnsQuestion *dns_question_unref(DnsQuestion *q);

int dns_question_new_address(DnsQuestion **ret, int family, const char *name, bool convert_idna);
int dns_question_new_reverse(DnsQuestion **ret, int family, const union in_addr_union *a);
int dns_question_new_service(DnsQuestion **ret, const char *service, const char *type, const char *domain, bool with_txt, bool convert_idna);
int dns_question_new_service_type(DnsQuestion **ret, const char *service, const char *type, const char *domain, bool convert_idna, uint16_t record_type);

int dns_question_add_raw(DnsQuestion *q, DnsResourceKey *key, DnsQuestionFlags flags);
int dns_question_add(DnsQuestion *q, DnsResourceKey *key, DnsQuestionFlags flags);

int dns_question_matches_rr(DnsQuestion *q, DnsResourceRecord *rr, const char *search_domain);
int dns_question_matches_cname_or_dname(DnsQuestion *q, DnsResourceRecord *rr, const char* search_domain);
int dns_question_is_valid_for_query(DnsQuestion *q);
int dns_question_contains_key(DnsQuestion *q, const DnsResourceKey *k);
int dns_question_is_equal(DnsQuestion *a, DnsQuestion *b);

int dns_question_cname_redirect(DnsQuestion *q, const DnsResourceRecord *cname, DnsQuestion **ret);

void dns_question_dump(DnsQuestion *q, FILE *f);

const char *dns_question_first_name(DnsQuestion *q);

static inline DnsResourceKey *dns_question_first_key(DnsQuestion *q) {
        return (q && q->n_keys > 0) ? q->items[0].key : NULL;
}

static inline size_t dns_question_size(DnsQuestion *q) {
        return q ? q->n_keys : 0;
}

static inline bool dns_question_isempty(DnsQuestion *q) {
        return dns_question_size(q) <= 0;
}

int dns_question_merge(DnsQuestion *a, DnsQuestion *b, DnsQuestion **ret);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsQuestion*, dns_question_unref);

#define _DNS_QUESTION_FOREACH(u, k, q)                                     \
        for (size_t UNIQ_T(i, u) = ({                                      \
                                (k) = ((q) && (q)->n_keys > 0) ? (q)->items[0].key : NULL; \
                                0;                                         \
                        });                                                \
             (q) && (UNIQ_T(i, u) < (q)->n_keys);                          \
             UNIQ_T(i, u)++, (k) = (UNIQ_T(i, u) < (q)->n_keys ? (q)->items[UNIQ_T(i, u)].key : NULL))

#define DNS_QUESTION_FOREACH(key, q) _DNS_QUESTION_FOREACH(UNIQ, key, q)

#define _DNS_QUESTION_FOREACH_ITEM(u, item, q)                             \
        for (size_t UNIQ_T(i, u) = ({                                      \
                     (item) = dns_question_isempty(q) ? NULL : (q)->items; \
                     0;                                                    \
             });                                                           \
             UNIQ_T(i, u) < dns_question_size(q);                          \
             UNIQ_T(i, u)++, (item) = (UNIQ_T(i, u) < dns_question_size(q) ? (q)->items + UNIQ_T(i, u) : NULL))

#define DNS_QUESTION_FOREACH_ITEM(item, q) _DNS_QUESTION_FOREACH_ITEM(UNIQ, item, q)
