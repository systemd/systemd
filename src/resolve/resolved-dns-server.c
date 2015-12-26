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
#include "string-table.h"
#include "string-util.h"

/* After how much time to repeat classic DNS requests */
#define DNS_TIMEOUT_MIN_USEC (500 * USEC_PER_MSEC)
#define DNS_TIMEOUT_MAX_USEC (5 * USEC_PER_SEC)

/* The amount of time to wait before retrying with a full feature set */
#define DNS_SERVER_FEATURE_GRACE_PERIOD_MAX_USEC (6 * USEC_PER_HOUR)
#define DNS_SERVER_FEATURE_GRACE_PERIOD_MIN_USEC (5 * USEC_PER_MINUTE)

/* The number of times we will attempt a certain feature set before degrading */
#define DNS_SERVER_FEATURE_RETRY_ATTEMPTS 3

int dns_server_new(
                Manager *m,
                DnsServer **ret,
                DnsServerType type,
                Link *l,
                int family,
                const union in_addr_union *in_addr) {

        DnsServer *s;

        assert(m);
        assert((type == DNS_SERVER_LINK) == !!l);
        assert(in_addr);

        if (!IN_SET(family, AF_INET, AF_INET6))
                return -EAFNOSUPPORT;

        if (l) {
                if (l->n_dns_servers >= LINK_DNS_SERVERS_MAX)
                        return -E2BIG;
        } else {
                if (m->n_dns_servers >= MANAGER_DNS_SERVERS_MAX)
                        return -E2BIG;
        }

        s = new0(DnsServer, 1);
        if (!s)
                return -ENOMEM;

        s->n_ref = 1;
        s->manager = m;
        s->verified_features = _DNS_SERVER_FEATURE_LEVEL_INVALID;
        s->possible_features = DNS_SERVER_FEATURE_LEVEL_BEST;
        s->features_grace_period_usec = DNS_SERVER_FEATURE_GRACE_PERIOD_MIN_USEC;
        s->received_udp_packet_max = DNS_PACKET_UNICAST_SIZE_MAX;
        s->type = type;
        s->family = family;
        s->address = *in_addr;
        s->resend_timeout = DNS_TIMEOUT_MIN_USEC;

        switch (type) {

        case DNS_SERVER_LINK:
                s->link = l;
                LIST_APPEND(servers, l->dns_servers, s);
                l->n_dns_servers++;
                break;

        case DNS_SERVER_SYSTEM:
                LIST_APPEND(servers, m->dns_servers, s);
                m->n_dns_servers++;
                break;

        case DNS_SERVER_FALLBACK:
                LIST_APPEND(servers, m->fallback_dns_servers, s);
                m->n_dns_servers++;
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
                assert(s->link->n_dns_servers > 0);
                LIST_REMOVE(servers, s->link->dns_servers, s);
                break;

        case DNS_SERVER_SYSTEM:
                assert(s->manager->n_dns_servers > 0);
                LIST_REMOVE(servers, s->manager->dns_servers, s);
                s->manager->n_dns_servers--;
                break;

        case DNS_SERVER_FALLBACK:
                assert(s->manager->n_dns_servers > 0);
                LIST_REMOVE(servers, s->manager->fallback_dns_servers, s);
                s->manager->n_dns_servers--;
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

void dns_server_packet_received(DnsServer *s, DnsServerFeatureLevel features, usec_t rtt, size_t size) {
        assert(s);

        if (features == DNS_SERVER_FEATURE_LEVEL_LARGE) {
                /* Even if we successfully receive a reply to a
                   request announcing support for large packets, that
                   does not mean we can necessarily receive large
                   packets. */

                if (s->verified_features < DNS_SERVER_FEATURE_LEVEL_LARGE - 1) {
                        s->verified_features = DNS_SERVER_FEATURE_LEVEL_LARGE - 1;
                        assert_se(sd_event_now(s->manager->event, clock_boottime_or_monotonic(), &s->verified_usec) >= 0);
                }
        } else if (s->verified_features < features) {
                s->verified_features = features;
                assert_se(sd_event_now(s->manager->event, clock_boottime_or_monotonic(), &s->verified_usec) >= 0);
        }

        if (s->possible_features == features)
                s->n_failed_attempts = 0;

        /* Remember the size of the largest UDP packet we received from a server,
           we know that we can always announce support for packets with at least
           this size. */
        if (s->received_udp_packet_max < size)
                s->received_udp_packet_max = size;

        if (s->max_rtt < rtt) {
                s->max_rtt = rtt;
                s->resend_timeout = MIN(MAX(DNS_TIMEOUT_MIN_USEC, s->max_rtt * 2), DNS_TIMEOUT_MAX_USEC);
        }
}

void dns_server_packet_lost(DnsServer *s, DnsServerFeatureLevel features, usec_t usec) {
        assert(s);
        assert(s->manager);

        if (s->possible_features == features)
                s->n_failed_attempts ++;

        if (s->resend_timeout > usec)
                return;

        s->resend_timeout = MIN(s->resend_timeout * 2, DNS_TIMEOUT_MAX_USEC);
}

void dns_server_packet_failed(DnsServer *s, DnsServerFeatureLevel features) {
        assert(s);
        assert(s->manager);

        if (s->possible_features != features)
                return;

        s->n_failed_attempts  = (unsigned) -1;
}

void dns_server_packet_rrsig_missing(DnsServer *s) {
        _cleanup_free_ char *ip = NULL;
        assert(s);
        assert(s->manager);

        in_addr_to_string(s->family, &s->address, &ip);
        log_warning("DNS server %s does not augment replies with RRSIG records, DNSSEC not available.", strna(ip));

        s->rrsig_missing = true;
}

static bool dns_server_grace_period_expired(DnsServer *s) {
        usec_t ts;

        assert(s);
        assert(s->manager);

        if (s->verified_usec == 0)
                return false;

        assert_se(sd_event_now(s->manager->event, clock_boottime_or_monotonic(), &ts) >= 0);

        if (s->verified_usec + s->features_grace_period_usec > ts)
                return false;

        s->features_grace_period_usec = MIN(s->features_grace_period_usec * 2, DNS_SERVER_FEATURE_GRACE_PERIOD_MAX_USEC);

        return true;
}

DnsServerFeatureLevel dns_server_possible_features(DnsServer *s) {
        assert(s);

        if (s->possible_features != DNS_SERVER_FEATURE_LEVEL_BEST &&
            dns_server_grace_period_expired(s)) {
                _cleanup_free_ char *ip = NULL;

                s->possible_features = DNS_SERVER_FEATURE_LEVEL_BEST;
                s->n_failed_attempts = 0;
                s->verified_usec = 0;
                s->rrsig_missing = false;

                in_addr_to_string(s->family, &s->address, &ip);
                log_info("Grace period over, resuming full feature set for DNS server %s", strna(ip));
        } else if (s->possible_features <= s->verified_features)
                s->possible_features = s->verified_features;
        else if (s->n_failed_attempts >= DNS_SERVER_FEATURE_RETRY_ATTEMPTS &&
                 s->possible_features > DNS_SERVER_FEATURE_LEVEL_WORST) {
                _cleanup_free_ char *ip = NULL;

                s->possible_features --;
                s->n_failed_attempts = 0;
                s->verified_usec = 0;

                in_addr_to_string(s->family, &s->address, &ip);
                log_warning("Using degraded feature set (%s) for DNS server %s",
                            dns_server_feature_level_to_string(s->possible_features), strna(ip));
        }

        return s->possible_features;
}

int dns_server_adjust_opt(DnsServer *server, DnsPacket *packet, DnsServerFeatureLevel level) {
        size_t packet_size;
        bool edns_do;
        int r;

        assert(server);
        assert(packet);
        assert(packet->protocol == DNS_PROTOCOL_DNS);

        /* Fix the OPT field in the packet to match our current feature level. */

        r = dns_packet_truncate_opt(packet);
        if (r < 0)
                return r;

        if (level < DNS_SERVER_FEATURE_LEVEL_EDNS0)
                return 0;

        edns_do = level >= DNS_SERVER_FEATURE_LEVEL_DO;

        if (level >= DNS_SERVER_FEATURE_LEVEL_LARGE)
                packet_size = DNS_PACKET_UNICAST_SIZE_LARGE_MAX;
        else
                packet_size = server->received_udp_packet_max;

        return dns_packet_append_opt(packet, packet_size, edns_do, NULL);
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

void dns_server_unlink_all(DnsServer *first) {
        DnsServer *next;

        if (!first)
                return;

        next = first->servers_next;
        dns_server_unlink(first);

        dns_server_unlink_all(next);
}

void dns_server_unlink_marked(DnsServer *first) {
        DnsServer *next;

        if (!first)
                return;

        next = first->servers_next;

        if (first->marked)
                dns_server_unlink(first);

        dns_server_unlink_marked(next);
}

void dns_server_mark_all(DnsServer *first) {
        if (!first)
                return;

        first->marked = true;
        dns_server_mark_all(first->servers_next);
}

DnsServer *dns_server_find(DnsServer *first, int family, const union in_addr_union *in_addr) {
        DnsServer *s;

        LIST_FOREACH(servers, s, first)
                if (s->family == family && in_addr_equal(family, &s->address, in_addr) > 0)
                        return s;

        return NULL;
}

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

static const char* const dns_server_feature_level_table[_DNS_SERVER_FEATURE_LEVEL_MAX] = {
        [DNS_SERVER_FEATURE_LEVEL_TCP] = "TCP",
        [DNS_SERVER_FEATURE_LEVEL_UDP] = "UDP",
        [DNS_SERVER_FEATURE_LEVEL_EDNS0] = "UDP+EDNS0",
        [DNS_SERVER_FEATURE_LEVEL_DO] = "UDP+EDNS0+DO",
        [DNS_SERVER_FEATURE_LEVEL_LARGE] = "UDP+EDNS0+DO+LARGE",
};
DEFINE_STRING_TABLE_LOOKUP(dns_server_feature_level, DnsServerFeatureLevel);
