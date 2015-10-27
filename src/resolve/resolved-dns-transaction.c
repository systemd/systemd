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

#include "af-list.h"
#include "alloc-util.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "random-util.h"
#include "resolved-dns-transaction.h"
#include "resolved-llmnr.h"
#include "string-table.h"

DnsTransaction* dns_transaction_free(DnsTransaction *t) {
        DnsQuery *q;
        DnsZoneItem *i;

        if (!t)
                return NULL;

        sd_event_source_unref(t->timeout_event_source);

        dns_packet_unref(t->sent);
        dns_packet_unref(t->received);
        dns_answer_unref(t->cached);

        sd_event_source_unref(t->dns_udp_event_source);
        safe_close(t->dns_udp_fd);

        dns_server_unref(t->server);
        dns_stream_free(t->stream);

        if (t->scope) {
                hashmap_remove(t->scope->transactions, t->key);

                if (t->id != 0)
                        hashmap_remove(t->scope->manager->dns_transactions, UINT_TO_PTR(t->id));
        }

        dns_resource_key_unref(t->key);

        while ((q = set_steal_first(t->queries)))
                set_remove(q->transactions, t);
        set_free(t->queries);

        while ((i = set_steal_first(t->zone_items)))
                i->probe_transaction = NULL;
        set_free(t->zone_items);

        free(t);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsTransaction*, dns_transaction_free);

void dns_transaction_gc(DnsTransaction *t) {
        assert(t);

        if (t->block_gc > 0)
                return;

        if (set_isempty(t->queries) && set_isempty(t->zone_items))
                dns_transaction_free(t);
}

int dns_transaction_new(DnsTransaction **ret, DnsScope *s, DnsResourceKey *key) {
        _cleanup_(dns_transaction_freep) DnsTransaction *t = NULL;
        int r;

        assert(ret);
        assert(s);
        assert(key);

        r = hashmap_ensure_allocated(&s->manager->dns_transactions, NULL);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&s->transactions, &dns_resource_key_hash_ops);
        if (r < 0)
                return r;

        t = new0(DnsTransaction, 1);
        if (!t)
                return -ENOMEM;

        t->dns_udp_fd = -1;
        t->key = dns_resource_key_ref(key);

        /* Find a fresh, unused transaction id */
        do
                random_bytes(&t->id, sizeof(t->id));
        while (t->id == 0 ||
               hashmap_get(s->manager->dns_transactions, UINT_TO_PTR(t->id)));

        r = hashmap_put(s->manager->dns_transactions, UINT_TO_PTR(t->id), t);
        if (r < 0) {
                t->id = 0;
                return r;
        }

        r = hashmap_put(s->transactions, t->key, t);
        if (r < 0) {
                hashmap_remove(s->manager->dns_transactions, UINT_TO_PTR(t->id));
                return r;
        }

        t->scope = s;

        if (ret)
                *ret = t;

        t = NULL;

        return 0;
}

static void dns_transaction_stop(DnsTransaction *t) {
        assert(t);

        t->timeout_event_source = sd_event_source_unref(t->timeout_event_source);
        t->stream = dns_stream_free(t->stream);
}

static void dns_transaction_tentative(DnsTransaction *t, DnsPacket *p) {
        _cleanup_free_ char *pretty = NULL;
        DnsZoneItem *z;

        assert(t);
        assert(p);

        if (manager_our_packet(t->scope->manager, p) != 0)
                return;

        in_addr_to_string(p->family, &p->sender, &pretty);

        log_debug("Transaction on scope %s on %s/%s got tentative packet from %s",
                  dns_protocol_to_string(t->scope->protocol),
                  t->scope->link ? t->scope->link->name : "*",
                  t->scope->family == AF_UNSPEC ? "*" : af_to_name(t->scope->family),
                  pretty);

        /* RFC 4795, Section 4.1 says that the peer with the
         * lexicographically smaller IP address loses */
        if (memcmp(&p->sender, &p->destination, FAMILY_ADDRESS_SIZE(p->family)) >= 0) {
                log_debug("Peer has lexicographically larger IP address and thus lost in the conflict.");
                return;
        }

        log_debug("We have the lexicographically larger IP address and thus lost in the conflict.");

        t->block_gc++;
        while ((z = set_first(t->zone_items))) {
                /* First, make sure the zone item drops the reference
                 * to us */
                dns_zone_item_probe_stop(z);

                /* Secondly, report this as conflict, so that we might
                 * look for a different hostname */
                dns_zone_item_conflict(z);
        }
        t->block_gc--;

        dns_transaction_gc(t);
}

void dns_transaction_complete(DnsTransaction *t, DnsTransactionState state) {
        DnsQuery *q;
        DnsZoneItem *z;
        Iterator i;

        assert(t);
        assert(!IN_SET(state, DNS_TRANSACTION_NULL, DNS_TRANSACTION_PENDING));

        /* Note that this call might invalidate the query. Callers
         * should hence not attempt to access the query or transaction
         * after calling this function. */

        log_debug("Transaction on scope %s on %s/%s now complete with <%s>",
                  dns_protocol_to_string(t->scope->protocol),
                  t->scope->link ? t->scope->link->name : "*",
                  t->scope->family == AF_UNSPEC ? "*" : af_to_name(t->scope->family),
                  dns_transaction_state_to_string(state));

        t->state = state;

        dns_transaction_stop(t);

        /* Notify all queries that are interested, but make sure the
         * transaction isn't freed while we are still looking at it */
        t->block_gc++;
        SET_FOREACH(q, t->queries, i)
                dns_query_ready(q);
        SET_FOREACH(z, t->zone_items, i)
                dns_zone_item_ready(z);
        t->block_gc--;

        dns_transaction_gc(t);
}

static int on_stream_complete(DnsStream *s, int error) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        DnsTransaction *t;

        assert(s);
        assert(s->transaction);

        /* Copy the data we care about out of the stream before we
         * destroy it. */
        t = s->transaction;
        p = dns_packet_ref(s->read_packet);

        t->stream = dns_stream_free(t->stream);

        if (error != 0) {
                dns_transaction_complete(t, DNS_TRANSACTION_RESOURCES);
                return 0;
        }

        if (dns_packet_validate_reply(p) <= 0) {
                log_debug("Invalid LLMNR TCP packet.");
                dns_transaction_complete(t, DNS_TRANSACTION_INVALID_REPLY);
                return 0;
        }

        dns_scope_check_conflicts(t->scope, p);

        t->block_gc++;
        dns_transaction_process_reply(t, p);
        t->block_gc--;

        /* If the response wasn't useful, then complete the transition now */
        if (t->state == DNS_TRANSACTION_PENDING)
                dns_transaction_complete(t, DNS_TRANSACTION_INVALID_REPLY);

        return 0;
}

static int dns_transaction_open_tcp(DnsTransaction *t) {
        DnsServer *server = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        assert(t);

        if (t->stream)
                return 0;

        switch (t->scope->protocol) {
        case DNS_PROTOCOL_DNS:
                fd = dns_scope_tcp_socket(t->scope, AF_UNSPEC, NULL, 53, &server);
                break;

        case DNS_PROTOCOL_LLMNR:
                /* When we already received a reply to this (but it was truncated), send to its sender address */
                if (t->received)
                        fd = dns_scope_tcp_socket(t->scope, t->received->family, &t->received->sender, t->received->sender_port, NULL);
                else {
                        union in_addr_union address;
                        int family = AF_UNSPEC;

                        /* Otherwise, try to talk to the owner of a
                         * the IP address, in case this is a reverse
                         * PTR lookup */

                        r = dns_name_address(DNS_RESOURCE_KEY_NAME(t->key), &family, &address);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EINVAL;
                        if (family != t->scope->family)
                                return -ESRCH;

                        fd = dns_scope_tcp_socket(t->scope, family, &address, LLMNR_PORT, NULL);
                }

                break;

        default:
                return -EAFNOSUPPORT;
        }

        if (fd < 0)
                return fd;

        r = dns_stream_new(t->scope->manager, &t->stream, t->scope->protocol, fd);
        if (r < 0)
                return r;

        fd = -1;

        r = dns_stream_write_packet(t->stream, t->sent);
        if (r < 0) {
                t->stream = dns_stream_free(t->stream);
                return r;
        }

        dns_server_unref(t->server);
        t->server = dns_server_ref(server);
        t->received = dns_packet_unref(t->received);
        t->stream->complete = on_stream_complete;
        t->stream->transaction = t;

        /* The interface index is difficult to determine if we are
         * connecting to the local host, hence fill this in right away
         * instead of determining it from the socket */
        if (t->scope->link)
                t->stream->ifindex = t->scope->link->ifindex;

        return 0;
}

static void dns_transaction_next_dns_server(DnsTransaction *t) {
        assert(t);

        t->server = dns_server_unref(t->server);
        t->dns_udp_event_source = sd_event_source_unref(t->dns_udp_event_source);
        t->dns_udp_fd = safe_close(t->dns_udp_fd);

        dns_scope_next_dns_server(t->scope);
}

void dns_transaction_process_reply(DnsTransaction *t, DnsPacket *p) {
        usec_t ts;
        int r;

        assert(t);
        assert(p);
        assert(t->state == DNS_TRANSACTION_PENDING);
        assert(t->scope);
        assert(t->scope->manager);

        /* Note that this call might invalidate the query. Callers
         * should hence not attempt to access the query or transaction
         * after calling this function. */

        switch (t->scope->protocol) {
        case DNS_PROTOCOL_LLMNR:
                assert(t->scope->link);

                /* For LLMNR we will not accept any packets from other
                 * interfaces */

                if (p->ifindex != t->scope->link->ifindex)
                        return;

                if (p->family != t->scope->family)
                        return;

                /* Tentative packets are not full responses but still
                 * useful for identifying uniqueness conflicts during
                 * probing. */
                if (DNS_PACKET_LLMNR_T(p)) {
                        dns_transaction_tentative(t, p);
                        return;
                }

                break;

        case DNS_PROTOCOL_DNS:
                break;

        default:
                assert_not_reached("Invalid DNS protocol.");
        }

        if (t->received != p) {
                dns_packet_unref(t->received);
                t->received = dns_packet_ref(p);
        }

        if (p->ipproto == IPPROTO_TCP) {
                if (DNS_PACKET_TC(p)) {
                        /* Truncated via TCP? Somebody must be fucking with us */
                        dns_transaction_complete(t, DNS_TRANSACTION_INVALID_REPLY);
                        return;
                }

                if (DNS_PACKET_ID(p) != t->id) {
                        /* Not the reply to our query? Somebody must be fucking with us */
                        dns_transaction_complete(t, DNS_TRANSACTION_INVALID_REPLY);
                        return;
                }
        }

        assert_se(sd_event_now(t->scope->manager->event, clock_boottime_or_monotonic(), &ts) >= 0);

        switch (t->scope->protocol) {
        case DNS_PROTOCOL_DNS:
                assert(t->server);

                dns_server_packet_received(t->server, ts - t->start_usec);

                break;
        case DNS_PROTOCOL_LLMNR:
        case DNS_PROTOCOL_MDNS:
                dns_scope_packet_received(t->scope, ts - t->start_usec);

                break;
        default:
                break;
        }

        if (DNS_PACKET_TC(p)) {
                /* Response was truncated, let's try again with good old TCP */
                r = dns_transaction_open_tcp(t);
                if (r == -ESRCH) {
                        /* No servers found? Damn! */
                        dns_transaction_complete(t, DNS_TRANSACTION_NO_SERVERS);
                        return;
                }
                if (r < 0) {
                        /* On LLMNR, if we cannot connect to the host,
                         * we immediately give up */
                        if (t->scope->protocol == DNS_PROTOCOL_LLMNR) {
                                dns_transaction_complete(t, DNS_TRANSACTION_RESOURCES);
                                return;
                        }

                        /* On DNS, couldn't send? Try immediately again, with a new server */
                        dns_transaction_next_dns_server(t);

                        r = dns_transaction_go(t);
                        if (r < 0) {
                                dns_transaction_complete(t, DNS_TRANSACTION_RESOURCES);
                                return;
                        }

                        return;
                }
        }

        /* Parse and update the cache */
        r = dns_packet_extract(p);
        if (r < 0) {
                dns_transaction_complete(t, DNS_TRANSACTION_INVALID_REPLY);
                return;
        }

        /* Only consider responses with equivalent query section to the request */
        if (p->question->n_keys != 1 || dns_resource_key_equal(p->question->keys[0], t->key) <= 0) {
                dns_transaction_complete(t, DNS_TRANSACTION_INVALID_REPLY);
                return;
        }

        /* According to RFC 4795, section 2.9. only the RRs from the answer section shall be cached */
        dns_cache_put(&t->scope->cache, t->key, DNS_PACKET_RCODE(p), p->answer, DNS_PACKET_ANCOUNT(p), 0, p->family, &p->sender);

        if (DNS_PACKET_RCODE(p) == DNS_RCODE_SUCCESS)
                dns_transaction_complete(t, DNS_TRANSACTION_SUCCESS);
        else
                dns_transaction_complete(t, DNS_TRANSACTION_FAILURE);
}

static int on_dns_packet(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        DnsTransaction *t = userdata;
        int r;

        assert(t);
        assert(t->scope);

        r = manager_recv(t->scope->manager, fd, DNS_PROTOCOL_DNS, &p);
        if (r <= 0)
                return r;

        if (dns_packet_validate_reply(p) > 0 &&
            DNS_PACKET_ID(p) == t->id)
                dns_transaction_process_reply(t, p);
        else
                log_debug("Invalid DNS packet.");

        return 0;
}

static int dns_transaction_emit(DnsTransaction *t) {
        int r;

        assert(t);

        if (t->scope->protocol == DNS_PROTOCOL_DNS && !t->server) {
                DnsServer *server = NULL;
                _cleanup_close_ int fd = -1;

                fd = dns_scope_udp_dns_socket(t->scope, &server);
                if (fd < 0)
                        return fd;

                r = sd_event_add_io(t->scope->manager->event, &t->dns_udp_event_source, fd, EPOLLIN, on_dns_packet, t);
                if (r < 0)
                        return r;

                t->dns_udp_fd = fd;
                fd = -1;
                t->server = dns_server_ref(server);
        }

        r = dns_scope_emit(t->scope, t->dns_udp_fd, t->sent);
        if (r < 0)
                return r;

        return 0;
}

static int on_transaction_timeout(sd_event_source *s, usec_t usec, void *userdata) {
        DnsTransaction *t = userdata;
        int r;

        assert(s);
        assert(t);

        /* Timeout reached? Try again, with a new server */
        dns_transaction_next_dns_server(t);

        /* ... and possibly increased timeout */
        if (t->server)
                dns_server_packet_lost(t->server, usec - t->start_usec);
        else
                dns_scope_packet_lost(t->scope, usec - t->start_usec);

        r = dns_transaction_go(t);
        if (r < 0)
                dns_transaction_complete(t, DNS_TRANSACTION_RESOURCES);

        return 0;
}

static int dns_transaction_make_packet(DnsTransaction *t) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        int r;

        assert(t);

        if (t->sent)
                return 0;

        r = dns_packet_new_query(&p, t->scope->protocol, 0);
        if (r < 0)
                return r;

        r = dns_scope_good_key(t->scope, t->key);
        if (r < 0)
                return r;
        if (r == 0)
                return -EDOM;

        r = dns_packet_append_key(p, t->key, NULL);
        if (r < 0)
                return r;

        DNS_PACKET_HEADER(p)->qdcount = htobe16(1);
        DNS_PACKET_HEADER(p)->id = t->id;

        t->sent = p;
        p = NULL;

        return 0;
}

static usec_t transaction_get_resend_timeout(DnsTransaction *t) {
        assert(t);
        assert(t->scope);

        switch (t->scope->protocol) {
        case DNS_PROTOCOL_DNS:
                assert(t->server);

                return t->server->resend_timeout;
        case DNS_PROTOCOL_LLMNR:
        case DNS_PROTOCOL_MDNS:
                return t->scope->resend_timeout;
        default:
                assert_not_reached("Invalid DNS protocol.");
        }
}

int dns_transaction_go(DnsTransaction *t) {
        bool had_stream;
        usec_t ts;
        int r;

        assert(t);

        had_stream = !!t->stream;

        dns_transaction_stop(t);

        log_debug("Excercising transaction on scope %s on %s/%s",
                  dns_protocol_to_string(t->scope->protocol),
                  t->scope->link ? t->scope->link->name : "*",
                  t->scope->family == AF_UNSPEC ? "*" : af_to_name(t->scope->family));

        if (t->n_attempts >= TRANSACTION_ATTEMPTS_MAX(t->scope->protocol)) {
                dns_transaction_complete(t, DNS_TRANSACTION_ATTEMPTS_MAX_REACHED);
                return 0;
        }

        if (t->scope->protocol == DNS_PROTOCOL_LLMNR && had_stream) {
                /* If we already tried via a stream, then we don't
                 * retry on LLMNR. See RFC 4795, Section 2.7. */
                dns_transaction_complete(t, DNS_TRANSACTION_ATTEMPTS_MAX_REACHED);
                return 0;
        }

        assert_se(sd_event_now(t->scope->manager->event, clock_boottime_or_monotonic(), &ts) >= 0);

        t->n_attempts++;
        t->start_usec = ts;
        t->received = dns_packet_unref(t->received);
        t->cached = dns_answer_unref(t->cached);
        t->cached_rcode = 0;

        /* Check the cache, but only if this transaction is not used
         * for probing or verifying a zone item. */
        if (set_isempty(t->zone_items)) {

                /* Before trying the cache, let's make sure we figured out a
                 * server to use. Should this cause a change of server this
                 * might flush the cache. */
                dns_scope_get_dns_server(t->scope);

                /* Let's then prune all outdated entries */
                dns_cache_prune(&t->scope->cache);

                r = dns_cache_lookup(&t->scope->cache, t->key, &t->cached_rcode, &t->cached);
                if (r < 0)
                        return r;
                if (r > 0) {
                        if (t->cached_rcode == DNS_RCODE_SUCCESS)
                                dns_transaction_complete(t, DNS_TRANSACTION_SUCCESS);
                        else
                                dns_transaction_complete(t, DNS_TRANSACTION_FAILURE);
                        return 0;
                }
        }

        if (t->scope->protocol == DNS_PROTOCOL_LLMNR && !t->initial_jitter) {
                usec_t jitter;

                /* RFC 4795 Section 2.7 suggests all queries should be
                 * delayed by a random time from 0 to JITTER_INTERVAL. */

                t->initial_jitter = true;

                random_bytes(&jitter, sizeof(jitter));
                jitter %= LLMNR_JITTER_INTERVAL_USEC;

                r = sd_event_add_time(
                                t->scope->manager->event,
                                &t->timeout_event_source,
                                clock_boottime_or_monotonic(),
                                ts + jitter,
                                LLMNR_JITTER_INTERVAL_USEC,
                                on_transaction_timeout, t);
                if (r < 0)
                        return r;

                t->n_attempts = 0;
                t->state = DNS_TRANSACTION_PENDING;

                log_debug("Delaying LLMNR transaction for " USEC_FMT "us.", jitter);
                return 0;
        }

        /* Otherwise, we need to ask the network */
        r = dns_transaction_make_packet(t);
        if (r == -EDOM) {
                /* Not the right request to make on this network?
                 * (i.e. an A request made on IPv6 or an AAAA request
                 * made on IPv4, on LLMNR or mDNS.) */
                dns_transaction_complete(t, DNS_TRANSACTION_NO_SERVERS);
                return 0;
        }
        if (r < 0)
                return r;

        if (t->scope->protocol == DNS_PROTOCOL_LLMNR &&
            (dns_name_endswith(DNS_RESOURCE_KEY_NAME(t->key), "in-addr.arpa") > 0 ||
             dns_name_endswith(DNS_RESOURCE_KEY_NAME(t->key), "ip6.arpa") > 0)) {

                /* RFC 4795, Section 2.4. says reverse lookups shall
                 * always be made via TCP on LLMNR */
                r = dns_transaction_open_tcp(t);
        } else {
                /* Try via UDP, and if that fails due to large size try via TCP */
                r = dns_transaction_emit(t);
                if (r == -EMSGSIZE)
                        r = dns_transaction_open_tcp(t);
        }
        if (r == -ESRCH) {
                /* No servers to send this to? */
                dns_transaction_complete(t, DNS_TRANSACTION_NO_SERVERS);
                return 0;
        } else if (r < 0) {
                if (t->scope->protocol != DNS_PROTOCOL_DNS) {
                        dns_transaction_complete(t, DNS_TRANSACTION_RESOURCES);
                        return 0;
                }

                /* Couldn't send? Try immediately again, with a new server */
                dns_transaction_next_dns_server(t);

                return dns_transaction_go(t);
        }

        r = sd_event_add_time(
                        t->scope->manager->event,
                        &t->timeout_event_source,
                        clock_boottime_or_monotonic(),
                        ts + transaction_get_resend_timeout(t), 0,
                        on_transaction_timeout, t);
        if (r < 0)
                return r;

        t->state = DNS_TRANSACTION_PENDING;
        return 1;
}

static const char* const dns_transaction_state_table[_DNS_TRANSACTION_STATE_MAX] = {
        [DNS_TRANSACTION_NULL] = "null",
        [DNS_TRANSACTION_PENDING] = "pending",
        [DNS_TRANSACTION_FAILURE] = "failure",
        [DNS_TRANSACTION_SUCCESS] = "success",
        [DNS_TRANSACTION_NO_SERVERS] = "no-servers",
        [DNS_TRANSACTION_TIMEOUT] = "timeout",
        [DNS_TRANSACTION_ATTEMPTS_MAX_REACHED] = "attempts-max-reached",
        [DNS_TRANSACTION_INVALID_REPLY] = "invalid-reply",
        [DNS_TRANSACTION_RESOURCES] = "resources",
        [DNS_TRANSACTION_ABORTED] = "aborted",
};
DEFINE_STRING_TABLE_LOOKUP(dns_transaction_state, DnsTransactionState);
