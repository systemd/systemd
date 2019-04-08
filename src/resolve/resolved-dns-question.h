/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct DnsQuestion DnsQuestion;

#include "macro.h"
#include "resolved-dns-rr.h"

/* A simple array of resource keys */

struct DnsQuestion {
        unsigned n_ref;
        size_t n_keys, n_allocated;
        DnsResourceKey* keys[0];
};

DnsQuestion *dns_question_new(size_t n);
DnsQuestion *dns_question_ref(DnsQuestion *q);
DnsQuestion *dns_question_unref(DnsQuestion *q);

int dns_question_new_address(DnsQuestion **ret, int family, const char *name, bool convert_idna);
int dns_question_new_reverse(DnsQuestion **ret, int family, const union in_addr_union *a);
int dns_question_new_service(DnsQuestion **ret, const char *service, const char *type, const char *domain, bool with_txt, bool convert_idna);

int dns_question_add_raw(DnsQuestion *q, DnsResourceKey *key);
int dns_question_add(DnsQuestion *q, DnsResourceKey *key);

int dns_question_matches_rr(DnsQuestion *q, DnsResourceRecord *rr, const char *search_domain);
int dns_question_matches_cname_or_dname(DnsQuestion *q, DnsResourceRecord *rr, const char* search_domain);
int dns_question_is_valid_for_query(DnsQuestion *q);
int dns_question_contains(DnsQuestion *a, const DnsResourceKey *k);
int dns_question_is_equal(DnsQuestion *a, DnsQuestion *b);

int dns_question_cname_redirect(DnsQuestion *q, const DnsResourceRecord *cname, DnsQuestion **ret);

const char *dns_question_first_name(DnsQuestion *q);

static inline size_t dns_question_size(DnsQuestion *q) {
        return q ? q->n_keys : 0;
}

static inline bool dns_question_isempty(DnsQuestion *q) {
        return dns_question_size(q) <= 0;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsQuestion*, dns_question_unref);

#define _DNS_QUESTION_FOREACH(u, key, q)                                \
        for (size_t UNIQ_T(i, u) = ({                                 \
                                (key) = ((q) && (q)->n_keys > 0) ? (q)->keys[0] : NULL; \
                                0;                                      \
                        });                                             \
             (q) && (UNIQ_T(i, u) < (q)->n_keys);                       \
             UNIQ_T(i, u)++, (key) = (UNIQ_T(i, u) < (q)->n_keys ? (q)->keys[UNIQ_T(i, u)] : NULL))

#define DNS_QUESTION_FOREACH(key, q) _DNS_QUESTION_FOREACH(UNIQ, key, q)
