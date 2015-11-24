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
#include "resolved-resolv-conf.h"
#include "siphash24.h"
#include "string-util.h"

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
        s->manager = m;
        s->type = type;
        s->family = family;
        s->address = *in_addr;
        s->resend_timeout = DNS_TIMEOUT_MIN_USEC;

        switch (type) {

        case DNS_SERVER_LINK:
                s->link = l;
                LIST_FIND_TAIL(servers, l->dns_servers, tail);
                LIST_INSERT_AFTER(servers, l->dns_servers, tail, s);
                break;

        case DNS_SERVER_SYSTEM:
                LIST_FIND_TAIL(servers, m->dns_servers, tail);
                LIST_INSERT_AFTER(servers, m->dns_servers, tail, s);
                break;

        case DNS_SERVER_FALLBACK:
                LIST_FIND_TAIL(servers, m->fallback_dns_servers, tail);
                LIST_INSERT_AFTER(servers, m->fallback_dns_servers, tail, s);
                break;

        default:
                assert_not_reached("Unknown server type");
        }

        s->linked = true;

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

DnsServer* dns_server_unref(DnsServer *s)  {
        if (!s)
                return NULL;

        assert(s->n_ref > 0);
        s->n_ref --;

        if (s->n_ref > 0)
                return NULL;

        free(s);
        return NULL;
}

void dns_server_unlink(DnsServer *s) {
        assert(s);
        assert(s->manager);

        /* This removes the specified server from the linked list of
         * servers, but any server might still stay around if it has
         * refs, for example from an ongoing transaction. */

        if (!s->linked)
                return;

        switch (s->type) {

        case DNS_SERVER_LINK:
                assert(s->link);
                LIST_REMOVE(servers, s->link->dns_servers, s);
                break;

        case DNS_SERVER_SYSTEM:
                LIST_REMOVE(servers, s->manager->dns_servers, s);
                break;

        case DNS_SERVER_FALLBACK:
                LIST_REMOVE(servers, s->manager->fallback_dns_servers, s);
                break;
        }

        s->linked = false;

        if (s->link && s->link->current_dns_server == s)
                link_set_dns_server(s->link, NULL);

        if (s->manager->current_dns_server == s)
                manager_set_dns_server(s->manager, NULL);

        dns_server_unref(s);
}

void dns_server_move_back_and_unmark(DnsServer *s) {
        DnsServer *tail;

        assert(s);

        if (!s->marked)
                return;

        s->marked = false;

        if (!s->linked || !s->servers_next)
                return;

        /* Move us to the end of the list, so that the order is
         * strictly kept, if we are not at the end anyway. */

        switch (s->type) {

        case DNS_SERVER_LINK:
                assert(s->link);
                LIST_FIND_TAIL(servers, s, tail);
                LIST_REMOVE(servers, s->link->dns_servers, s);
                LIST_INSERT_AFTER(servers, s->link->dns_servers, tail, s);
                break;

        case DNS_SERVER_SYSTEM:
                LIST_FIND_TAIL(servers, s, tail);
                LIST_REMOVE(servers, s->manager->dns_servers, s);
                LIST_INSERT_AFTER(servers, s->manager->dns_servers, tail, s);
                break;

        case DNS_SERVER_FALLBACK:
                LIST_FIND_TAIL(servers, s, tail);
                LIST_REMOVE(servers, s->manager->fallback_dns_servers, s);
                LIST_INSERT_AFTER(servers, s->manager->fallback_dns_servers, tail, s);
                break;

        default:
                assert_not_reached("Unknown server type");
        }
}

void dns_server_packet_received(DnsServer *s, usec_t rtt) {
        assert(s);

        if (rtt <= s->max_rtt)
                return;

        s->max_rtt = rtt;
        s->resend_timeout = MIN(MAX(DNS_TIMEOUT_MIN_USEC, s->max_rtt * 2), DNS_TIMEOUT_MAX_USEC);
}

void dns_server_packet_lost(DnsServer *s, usec_t usec) {
        assert(s);

        if (s->resend_timeout > usec)
                return;

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

DnsServer *manager_get_first_dns_server(Manager *m, DnsServerType t) {
        assert(m);

        switch (t) {

        case DNS_SERVER_SYSTEM:
                return m->dns_servers;

        case DNS_SERVER_FALLBACK:
                return m->fallback_dns_servers;

        default:
                return NULL;
        }
}

void manager_flush_dns_servers(Manager *m, DnsServerType type) {
        assert(m);

        for (;;) {
                DnsServer *first;

                first = manager_get_first_dns_server(m, type);
                if (!first)
                        break;

                dns_server_unlink(first);
        }
}

void manager_flush_marked_dns_servers(Manager *m, DnsServerType type) {
        DnsServer *first, *s, *next;

        assert(m);

        first = manager_get_first_dns_server(m, type);

        LIST_FOREACH_SAFE(servers, s, next, first) {
                if (!s->marked)
                        continue;

                dns_server_unlink(s);
        }
}

void manager_mark_dns_servers(Manager *m, DnsServerType type) {
        DnsServer *first, *s;

        assert(m);

        first = manager_get_first_dns_server(m, type);
        LIST_FOREACH(servers, s, first)
                s->marked = true;
}

DnsServer* manager_find_dns_server(Manager *m, DnsServerType type, int family, const union in_addr_union *in_addr) {
        DnsServer *first, *s;

        assert(m);
        assert(in_addr);

        first = manager_get_first_dns_server(m, type);

        LIST_FOREACH(servers, s, first)
                if (s->family == family && in_addr_equal(family, &s->address, in_addr) > 0)
                        return s;

        return NULL;
}

DnsServer *manager_set_dns_server(Manager *m, DnsServer *s) {
        assert(m);

        if (m->current_dns_server == s)
                return s;

        if (s) {
                _cleanup_free_ char *ip = NULL;

                in_addr_to_string(s->family, &s->address, &ip);
                log_info("Switching to system DNS server %s.", strna(ip));
        }

        dns_server_unref(m->current_dns_server);
        m->current_dns_server = dns_server_ref(s);

        if (m->unicast_scope)
                dns_cache_flush(&m->unicast_scope->cache);

        return s;
}

DnsServer *manager_get_dns_server(Manager *m) {
        Link *l;
        assert(m);

        /* Try to read updates resolv.conf */
        manager_read_resolv_conf(m);

        /* If no DNS server was chose so far, pick the first one */
        if (!m->current_dns_server)
                manager_set_dns_server(m, m->dns_servers);

        if (!m->current_dns_server) {
                bool found = false;
                Iterator i;

                /* No DNS servers configured, let's see if there are
                 * any on any links. If not, we use the fallback
                 * servers */

                HASHMAP_FOREACH(l, m->links, i)
                        if (l->dns_servers) {
                                found = true;
                                break;
                        }

                if (!found)
                        manager_set_dns_server(m, m->fallback_dns_servers);
        }

        return m->current_dns_server;
}

void manager_next_dns_server(Manager *m) {
        assert(m);

        /* If there's currently no DNS server set, then the next
         * manager_get_dns_server() will find one */
        if (!m->current_dns_server)
                return;

        /* Change to the next one, but make sure to follow the linked
         * list only if the server is still linked. */
        if (m->current_dns_server->linked && m->current_dns_server->servers_next) {
                manager_set_dns_server(m, m->current_dns_server->servers_next);
                return;
        }

        /* If there was no next one, then start from the beginning of
         * the list */
        if (m->current_dns_server->type == DNS_SERVER_FALLBACK)
                manager_set_dns_server(m, m->fallback_dns_servers);
        else
                manager_set_dns_server(m, m->dns_servers);
}
