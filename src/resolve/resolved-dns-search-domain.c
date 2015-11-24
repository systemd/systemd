/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "alloc-util.h"
#include "dns-domain.h"
#include "resolved-dns-search-domain.h"

int dns_search_domain_new(
                Manager *m,
                DnsSearchDomain **ret,
                DnsSearchDomainType type,
                Link *l,
                const char *name) {

        _cleanup_free_ char *normalized = NULL;
        DnsSearchDomain *d;
        int r;

        assert(m);
        assert((type == DNS_SEARCH_DOMAIN_LINK) == !!l);
        assert(name);

        r = dns_name_normalize(name, &normalized);
        if (r < 0)
                return r;

        r = dns_name_root(normalized);
        if (r < 0)
                return r;
        if (r > 0)
                return -EINVAL;

        if (l) {
                if (l->n_search_domains >= LINK_SEARCH_DOMAINS_MAX)
                        return -E2BIG;
        } else {
                if (m->n_search_domains >= MANAGER_SEARCH_DOMAINS_MAX)
                        return -E2BIG;
        }

        d = new0(DnsSearchDomain, 1);
        if (!d)
                return -ENOMEM;

        d->n_ref = 1;
        d->manager = m;
        d->type = type;
        d->name = normalized;
        normalized = NULL;

        switch (type) {

        case DNS_SEARCH_DOMAIN_LINK:
                d->link = l;
                LIST_APPEND(domains, l->search_domains, d);
                l->n_search_domains++;
                break;

        case DNS_SERVER_SYSTEM:
                LIST_APPEND(domains, m->search_domains, d);
                m->n_search_domains++;
                break;

        default:
                assert_not_reached("Unknown search domain type");
        }

        d->linked = true;

        if (ret)
                *ret = d;

        return 0;
}

DnsSearchDomain* dns_search_domain_ref(DnsSearchDomain *d) {
        if (!d)
                return NULL;

        assert(d->n_ref > 0);
        d->n_ref++;

        return d;
}

DnsSearchDomain* dns_search_domain_unref(DnsSearchDomain *d) {
        if (!d)
                return NULL;

        assert(d->n_ref > 0);
        d->n_ref--;

        if (d->n_ref > 0)
                return NULL;

        free(d->name);
        free(d);

        return NULL;
}

void dns_search_domain_unlink(DnsSearchDomain *d) {
        assert(d);
        assert(d->manager);

        if (!d->linked)
                return;

        switch (d->type) {

        case DNS_SEARCH_DOMAIN_LINK:
                assert(d->link);
                assert(d->link->n_search_domains > 0);
                LIST_REMOVE(domains, d->link->search_domains, d);
                d->link->n_search_domains--;
                break;

        case DNS_SEARCH_DOMAIN_SYSTEM:
                assert(d->manager->n_search_domains > 0);
                LIST_REMOVE(domains, d->manager->search_domains, d);
                d->manager->n_search_domains--;
                break;
        }

        d->linked = false;

        dns_search_domain_unref(d);
}

void dns_search_domain_move_back_and_unmark(DnsSearchDomain *d) {
        DnsSearchDomain *tail;

        assert(d);

        if (!d->marked)
                return;

        d->marked = false;

        if (!d->linked || !d->domains_next)
                return;

        switch (d->type) {

        case DNS_SEARCH_DOMAIN_LINK:
                assert(d->link);
                LIST_FIND_TAIL(domains, d, tail);
                LIST_REMOVE(domains, d->link->search_domains, d);
                LIST_INSERT_AFTER(domains, d->link->search_domains, tail, d);
                break;

        case DNS_SEARCH_DOMAIN_SYSTEM:
                LIST_FIND_TAIL(domains, d, tail);
                LIST_REMOVE(domains, d->manager->search_domains, d);
                LIST_INSERT_AFTER(domains, d->manager->search_domains, tail, d);
                break;

        default:
                assert_not_reached("Unknown search domain type");
        }
}

void dns_search_domain_unlink_all(DnsSearchDomain *first) {
        DnsSearchDomain *next;

        if (!first)
                return;

        next = first->domains_next;
        dns_search_domain_unlink(first);

        dns_search_domain_unlink_all(next);
}

void dns_search_domain_unlink_marked(DnsSearchDomain *first) {
        DnsSearchDomain *next;

        if (!first)
                return;

        next = first->domains_next;

        if (first->marked)
                dns_search_domain_unlink(first);

        dns_search_domain_unlink_marked(next);
}

void dns_search_domain_mark_all(DnsSearchDomain *first) {
        if (!first)
                return;

        first->marked = true;
        dns_search_domain_mark_all(first->domains_next);
}

int dns_search_domain_find(DnsSearchDomain *first, const char *name, DnsSearchDomain **ret) {
        DnsSearchDomain *d;
        int r;

        assert(name);
        assert(ret);

        LIST_FOREACH(domains, d, first) {

                r = dns_name_equal(name, d->name);
                if (r < 0)
                        return r;
                if (r > 0) {
                        *ret = d;
                        return 1;
                }
        }

        *ret = NULL;
        return 0;
}
