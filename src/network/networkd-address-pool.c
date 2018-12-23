/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "networkd-address-pool.h"
#include "networkd-manager.h"
#include "set.h"
#include "string-util.h"

int address_pool_new(Manager *m, AddressPool **ret, int family, const union in_addr_union *u, unsigned prefixlen) {

        AddressPool *p;

        assert(m);
        assert(ret);
        assert(u);

        p = new (AddressPool, 1);
        if (!p)
                return -ENOMEM;

        *p = (AddressPool){
                .manager = m,
                .family = family,
                .prefixlen = prefixlen,
                .in_addr = *u,
        };

        LIST_PREPEND(address_pools, m->address_pools, p);

        *ret = p;
        return 0;
}

int address_pool_new_from_string(Manager *m, AddressPool **ret, int family, const char *p, unsigned prefixlen) {

        union in_addr_union u;
        int r;

        assert(m);
        assert(ret);
        assert(p);

        r = in_addr_from_string(family, p, &u);
        if (r < 0)
                return r;

        return address_pool_new(m, ret, family, &u, prefixlen);
}

void address_pool_free(AddressPool *p) {

        if (!p)
                return;

        if (p->manager)
                LIST_REMOVE(address_pools, p->manager->address_pools, p);

        free(p);
}

static bool address_pool_prefix_is_taken(AddressPool *p, const union in_addr_union *u, unsigned prefixlen) {

        Iterator i;
        Link *l;
        Network *n;

        assert(p);
        assert(u);

        HASHMAP_FOREACH(l, p->manager->links, i) {
                Address *a;
                Iterator j;

                /* Don't clash with assigned addresses */
                SET_FOREACH(a, l->addresses, j) {
                        if (a->family != p->family)
                                continue;

                        if (in_addr_prefix_intersect(p->family, u, prefixlen, &a->in_addr, a->prefixlen))
                                return true;
                }

                /* Don't clash with addresses already pulled from the pool, but not assigned yet */
                LIST_FOREACH(addresses, a, l->pool_addresses) {
                        if (a->family != p->family)
                                continue;

                        if (in_addr_prefix_intersect(p->family, u, prefixlen, &a->in_addr, a->prefixlen))
                                return true;
                }
        }

        /* And don't clash with configured but un-assigned addresses either */
        LIST_FOREACH(networks, n, p->manager->networks) {
                Address *a;

                LIST_FOREACH(addresses, a, n->static_addresses) {
                        if (a->family != p->family)
                                continue;

                        if (in_addr_prefix_intersect(p->family, u, prefixlen, &a->in_addr, a->prefixlen))
                                return true;
                }
        }

        return false;
}

int address_pool_acquire(AddressPool *p, unsigned prefixlen, union in_addr_union *found) {
        union in_addr_union u;

        assert(p);
        assert(prefixlen > 0);
        assert(found);

        if (p->prefixlen > prefixlen)
                return 0;

        u = p->in_addr;
        for (;;) {
                if (!address_pool_prefix_is_taken(p, &u, prefixlen)) {
                        _cleanup_free_ char *s = NULL;
                        int r;

                        r = in_addr_to_string(p->family, &u, &s);
                        if (r < 0)
                                return r;

                        log_debug("Found range %s/%u", strna(s), prefixlen);

                        *found = u;
                        return 1;
                }

                if (!in_addr_prefix_next(p->family, &u, prefixlen))
                        return 0;

                if (!in_addr_prefix_intersect(p->family, &p->in_addr, p->prefixlen, &u, prefixlen))
                        return 0;
        }

        return 0;
}
