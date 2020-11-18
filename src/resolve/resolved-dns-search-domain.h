/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "macro.h"

typedef struct DnsSearchDomain DnsSearchDomain;
typedef struct Link Link;
typedef struct Manager Manager;

typedef enum DnsSearchDomainType {
        DNS_SEARCH_DOMAIN_SYSTEM,
        DNS_SEARCH_DOMAIN_LINK,
} DnsSearchDomainType;

struct DnsSearchDomain {
        Manager *manager;

        unsigned n_ref;

        DnsSearchDomainType type;
        Link *link;

        char *name;

        bool marked:1;
        bool route_only:1;

        bool linked:1;
        LIST_FIELDS(DnsSearchDomain, domains);
};

int dns_search_domain_new(
                Manager *m,
                DnsSearchDomain **ret,
                DnsSearchDomainType type,
                Link *link,
                const char *name);

DnsSearchDomain* dns_search_domain_ref(DnsSearchDomain *d);
DnsSearchDomain* dns_search_domain_unref(DnsSearchDomain *d);

void dns_search_domain_unlink(DnsSearchDomain *d);
void dns_search_domain_move_back_and_unmark(DnsSearchDomain *d);

void dns_search_domain_unlink_all(DnsSearchDomain *first);
bool dns_search_domain_unlink_marked(DnsSearchDomain *first);
void dns_search_domain_mark_all(DnsSearchDomain *first);

int dns_search_domain_find(DnsSearchDomain *first, const char *name, DnsSearchDomain **ret);

static inline const char* DNS_SEARCH_DOMAIN_NAME(DnsSearchDomain *d) {
        return d ? d->name : NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsSearchDomain*, dns_search_domain_unref);
