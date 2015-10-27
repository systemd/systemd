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

#include "alloc-util.h"
#include "resolved-dns-server.h"
#include "siphash24.h"

/* After how much time to repeat classic DNS requests */
#define DNS_TIMEOUT_MIN_USEC (500 * USEC_PER_MSEC)
#define DNS_TIMEOUT_MAX_USEC (5 * USEC_PER_SEC)

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

        s->n_ref = 1;
        s->type = type;
        s->family = family;
        s->address = *in_addr;
        s->resend_timeout = DNS_TIMEOUT_MIN_USEC;

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

DnsServer* dns_server_ref(DnsServer *s)  {
        if (!s)
                return NULL;

        assert(s->n_ref > 0);

        s->n_ref ++;

        return s;
}

static DnsServer* dns_server_free(DnsServer *s)  {
        if (!s)
                return NULL;

        if (s->link && s->link->current_dns_server == s)
                link_set_dns_server(s->link, NULL);

        if (s->manager && s->manager->current_dns_server == s)
                manager_set_dns_server(s->manager, NULL);

        free(s);

        return NULL;
}

DnsServer* dns_server_unref(DnsServer *s)  {
        if (!s)
                return NULL;

        assert(s->n_ref > 0);

        if (s->n_ref == 1)
                dns_server_free(s);
        else
                s->n_ref --;

        return NULL;
}

void dns_server_packet_received(DnsServer *s, usec_t rtt) {
        assert(s);

        if (rtt > s->max_rtt) {
                s->max_rtt = rtt;
                s->resend_timeout = MIN(MAX(DNS_TIMEOUT_MIN_USEC, s->max_rtt * 2),
                                        DNS_TIMEOUT_MAX_USEC);
        }
}

void dns_server_packet_lost(DnsServer *s, usec_t usec) {
        assert(s);

        if (s->resend_timeout <= usec)
                s->resend_timeout = MIN(s->resend_timeout * 2, DNS_TIMEOUT_MAX_USEC);
}

static void dns_server_hash_func(const void *p, struct siphash *state) {
        const DnsServer *s = p;

        assert(s);

        siphash24_compress(&s->family, sizeof(s->family), state);
        siphash24_compress(&s->address, FAMILY_ADDRESS_SIZE(s->family), state);
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
