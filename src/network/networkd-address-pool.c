/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "networkd-address-pool.h"
#include "networkd-address.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "string-util.h"

#define RANDOM_PREFIX_TRIAL_MAX  1024

static int address_pool_new(
                Manager *m,
                int family,
                const union in_addr_union *u,
                unsigned prefixlen) {

        _cleanup_free_ AddressPool *p = NULL;
        int r;

        assert(m);
        assert(u);

        p = new(AddressPool, 1);
        if (!p)
                return -ENOMEM;

        *p = (AddressPool) {
                .manager = m,
                .family = family,
                .prefixlen = prefixlen,
                .in_addr = *u,
        };

        r = ordered_set_ensure_put(&m->address_pools, &trivial_hash_ops_free, p);
        if (r < 0)
                return r;

        TAKE_PTR(p);
        return 0;
}

static int address_pool_new_from_string(
                Manager *m,
                int family,
                const char *p,
                unsigned prefixlen) {

        union in_addr_union u;
        int r;

        assert(m);
        assert(p);

        r = in_addr_from_string(family, p, &u);
        if (r < 0)
                return r;

        return address_pool_new(m, family, &u, prefixlen);
}

int address_pool_setup_default(Manager *m) {
        int r;

        assert(m);

        /* Add in the well-known private address ranges. */
        r = address_pool_new_from_string(m, AF_INET6, "fd00::", 8);
        if (r < 0)
                return r;

        r = address_pool_new_from_string(m, AF_INET, "192.168.0.0", 16);
        if (r < 0)
                return r;

        r = address_pool_new_from_string(m, AF_INET, "172.16.0.0", 12);
        if (r < 0)
                return r;

        r = address_pool_new_from_string(m, AF_INET, "10.0.0.0", 8);
        if (r < 0)
                return r;

        return 0;
}

static bool address_intersect(
                const Address *a,
                int family,
                const union in_addr_union *u,
                unsigned prefixlen) {

        assert(a);
        assert(u);

        if (a->family != family)
                return false;

        return in_addr_prefix_intersect(family, u, prefixlen, &a->in_addr, a->prefixlen);
}

static bool address_pool_prefix_is_taken(
                AddressPool *p,
                const union in_addr_union *u,
                unsigned prefixlen) {

        Address *a;
        Link *l;
        Network *n;
        Request *req;

        assert(p);
        assert(u);

        /* Don't clash with assigned addresses. */
        HASHMAP_FOREACH(l, p->manager->links_by_index)
                SET_FOREACH(a, l->addresses)
                        if (address_intersect(a, p->family, u, prefixlen))
                                return true;

        /* And don't clash with configured but un-assigned addresses either. */
        ORDERED_HASHMAP_FOREACH(n, p->manager->networks)
                ORDERED_HASHMAP_FOREACH(a, n->addresses_by_section)
                        if (address_intersect(a, p->family, u, prefixlen))
                                return true;

        /* Also check queued addresses. */
        ORDERED_SET_FOREACH(req, p->manager->request_queue) {
                if (req->type != REQUEST_TYPE_ADDRESS)
                        continue;

                if (address_intersect(req->userdata, p->family, u, prefixlen))
                        return true;
        }

        return false;
}

static int address_pool_acquire_one(AddressPool *p, int family, unsigned prefixlen, union in_addr_union *found) {
        union in_addr_union u;
        int r;

        assert(p);
        assert(prefixlen > 0);
        assert(found);

        if (p->family != family)
                return 0;

        if (p->prefixlen >= prefixlen)
                return 0;

        u = p->in_addr;

        for (unsigned i = 0; i < RANDOM_PREFIX_TRIAL_MAX; i++) {
                r = in_addr_random_prefix(p->family, &u, p->prefixlen, prefixlen);
                if (r <= 0)
                        return r;

                if (!address_pool_prefix_is_taken(p, &u, prefixlen)) {
                        log_debug("Found range %s", IN_ADDR_PREFIX_TO_STRING(p->family, &u, prefixlen));

                        *found = u;
                        return 1;
                }
        }

        return 0;
}

int address_pool_acquire(Manager *m, int family, unsigned prefixlen, union in_addr_union *found) {
        AddressPool *p;
        int r;

        assert(m);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(prefixlen > 0);
        assert(found);

        ORDERED_SET_FOREACH(p, m->address_pools) {
                r = address_pool_acquire_one(p, family, prefixlen, found);
                if (r != 0)
                        return r;
        }

        return 0;
}
