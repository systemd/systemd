/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "siphash24.h"

#include "resolved-dns-server.h"

int dns_server_new(
                Manager *m,
                DnsServer **ret,
                DnsServerType type,
                Link *l,
                int family,
                const union in_addr_union *in_addr) {

        DnsServer *s, *tail;

        assert(m);
        assert((type == DNS_SERVER_LINK) == !!l);
        assert(in_addr);

        s = new0(DnsServer, 1);
        if (!s)
                return -ENOMEM;

        s->type = type;
        s->family = family;
        s->address = *in_addr;

        if (type == DNS_SERVER_LINK) {
                LIST_FIND_TAIL(servers, l->dns_servers, tail);
                LIST_INSERT_AFTER(servers, l->dns_servers, tail, s);
                s->link = l;
        } else if (type == DNS_SERVER_SYSTEM) {
                LIST_FIND_TAIL(servers, m->dns_servers, tail);
                LIST_INSERT_AFTER(servers, m->dns_servers, tail, s);
        } else if (type == DNS_SERVER_FALLBACK) {
                LIST_FIND_TAIL(servers, m->fallback_dns_servers, tail);
                LIST_INSERT_AFTER(servers, m->fallback_dns_servers, tail, s);
        } else
                assert_not_reached("Unknown server type");

        s->manager = m;

        /* A new DNS server that isn't fallback is added and the one
         * we used so far was a fallback one? Then let's try to pick
         * the new one */
        if (type != DNS_SERVER_FALLBACK &&
            m->current_dns_server &&
            m->current_dns_server->type == DNS_SERVER_FALLBACK)
                manager_set_dns_server(m, NULL);

        if (ret)
                *ret = s;

        return 0;
}

DnsServer* dns_server_free(DnsServer *s)  {
        if (!s)
                return NULL;

        if (s->link) {
                if (s->type == DNS_SERVER_LINK)
                        LIST_REMOVE(servers, s->link->dns_servers, s);

                if (s->link->current_dns_server == s)
                        link_set_dns_server(s->link, NULL);
        }

        if (s->manager) {
                if (s->type == DNS_SERVER_SYSTEM)
                        LIST_REMOVE(servers, s->manager->dns_servers, s);
                else if (s->type == DNS_SERVER_FALLBACK)
                        LIST_REMOVE(servers, s->manager->fallback_dns_servers, s);

                if (s->manager->current_dns_server == s)
                        manager_set_dns_server(s->manager, NULL);
        }

        free(s);

        return NULL;
}

static unsigned long dns_server_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]) {
        const DnsServer *s = p;
        uint64_t u;

        siphash24((uint8_t*) &u, &s->address, FAMILY_ADDRESS_SIZE(s->family), hash_key);
        u = u * hash_key[0] + u + s->family;

        return u;
}

static int dns_server_compare_func(const void *a, const void *b) {
        const DnsServer *x = a, *y = b;

        if (x->family < y->family)
                return -1;
        if (x->family > y->family)
                return 1;

        return memcmp(&x->address, &y->address, FAMILY_ADDRESS_SIZE(x->family));
}

const struct hash_ops dns_server_hash_ops = {
        .hash = dns_server_hash_func,
        .compare = dns_server_compare_func
};
