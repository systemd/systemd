/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "dns-domain.h"
#include "resolved-dns-search-domain.h"
#include "resolved-link.h"
#include "resolved-manager.h"

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

        r = dns_name_normalize(name, 0, &normalized);
        if (r < 0)
                return r;

        if (l) {
                if (l->n_search_domains >= LINK_SEARCH_DOMAINS_MAX)
                        return -E2BIG;
        } else {
                if (m->n_search_domains >= MANAGER_SEARCH_DOMAINS_MAX)
                        return -E2BIG;
        }

        d = new(DnsSearchDomain, 1);
        if (!d)
                return -ENOMEM;

        *d = (DnsSearchDomain) {
                .n_ref = 1,
                .manager = m,
                .type = type,
                .name = TAKE_PTR(normalized),
        };

        switch (type) {

        case DNS_SEARCH_DOMAIN_LINK:
                d->link = l;
                LIST_APPEND(domains, l->search_domains, d);
                l->n_search_domains++;
                break;

        case DNS_SEARCH_DOMAIN_SYSTEM:
                LIST_APPEND(domains, m->search_domains, d);
                m->n_search_domains++;
                break;

        default:
                assert_not_reached();
        }

        d->linked = true;

        if (ret)
                *ret = d;

        return 0;
}

static DnsSearchDomain* dns_search_domain_free(DnsSearchDomain *d) {
        assert(d);

        free(d->name);
        return mfree(d);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DnsSearchDomain, dns_search_domain, dns_search_domain_free);

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
                tail = LIST_FIND_TAIL(domains, d);
                LIST_REMOVE(domains, d->link->search_domains, d);
                LIST_INSERT_AFTER(domains, d->link->search_domains, tail, d);
                break;

        case DNS_SEARCH_DOMAIN_SYSTEM:
                tail = LIST_FIND_TAIL(domains, d);
                LIST_REMOVE(domains, d->manager->search_domains, d);
                LIST_INSERT_AFTER(domains, d->manager->search_domains, tail, d);
                break;

        default:
                assert_not_reached();
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

bool dns_search_domain_unlink_marked(DnsSearchDomain *first) {
        DnsSearchDomain *next;
        bool changed;

        if (!first)
                return false;

        next = first->domains_next;

        if (first->marked) {
                dns_search_domain_unlink(first);
                changed = true;
        } else
                changed = false;

        return dns_search_domain_unlink_marked(next) || changed;
}

void dns_search_domain_mark_all(DnsSearchDomain *first) {
        if (!first)
                return;

        first->marked = true;
        dns_search_domain_mark_all(first->domains_next);
}

int dns_search_domain_find(DnsSearchDomain *first, const char *name, DnsSearchDomain **ret) {
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

int dns_search_domain_dump_to_json(DnsSearchDomain *domain, sd_json_variant **ret) {
        int ifindex = 0;

        assert(domain);
        assert(ret);

        if (domain->type == DNS_SEARCH_DOMAIN_LINK) {
                assert(domain->link);
                ifindex = domain->link->ifindex;
        }

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("name", domain->name),
                        SD_JSON_BUILD_PAIR_BOOLEAN("routeOnly", domain->route_only),
                        SD_JSON_BUILD_PAIR_CONDITION(ifindex > 0, "ifindex", SD_JSON_BUILD_UNSIGNED(ifindex)));
}
