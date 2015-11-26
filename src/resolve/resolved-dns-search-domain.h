/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include "macro.h"

typedef struct DnsSearchDomain DnsSearchDomain;

typedef enum DnsSearchDomainType {
        DNS_SEARCH_DOMAIN_SYSTEM,
        DNS_SEARCH_DOMAIN_LINK,
} DnsSearchDomainType;

#include "resolved-link.h"
#include "resolved-manager.h"

struct DnsSearchDomain {
        Manager *manager;

        unsigned n_ref;

        DnsSearchDomainType type;
        Link *link;

        char *name;

        bool marked:1;

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
void dns_search_domain_unlink_marked(DnsSearchDomain *first);
void dns_search_domain_mark_all(DnsSearchDomain *first);

int dns_search_domain_find(DnsSearchDomain *first, const char *name, DnsSearchDomain **ret);

static inline const char* DNS_SEARCH_DOMAIN_NAME(DnsSearchDomain *d) {
        return d ? d->name : NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsSearchDomain*, dns_search_domain_unref);
