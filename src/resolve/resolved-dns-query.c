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

#include "resolved-dns-query.h"
#include "resolved-dns-domain.h"

#define TRANSACTION_TIMEOUT_USEC (5 * USEC_PER_SEC)
#define QUERY_TIMEOUT_USEC (30 * USEC_PER_SEC)
#define ATTEMPTS_MAX 8
#define CNAME_MAX 8
#define QUERIES_MAX 2048

static int dns_query_transaction_go(DnsQueryTransaction *t);

DnsQueryTransaction* dns_query_transaction_free(DnsQueryTransaction *t) {
        DnsQuery *q;

        if (!t)
                return NULL;

        sd_event_source_unref(t->timeout_event_source);

        dns_question_unref(t->question);
        dns_packet_unref(t->sent);
        dns_packet_unref(t->received);
        dns_answer_unref(t->cached);

        dns_stream_free(t->stream);

        if (t->scope) {
                LIST_REMOVE(transactions_by_scope, t->scope->transactions, t);

                if (t->id != 0)
                        hashmap_remove(t->scope->manager->dns_query_transactions, UINT_TO_PTR(t->id));
        }

        while ((q = set_steal_first(t->queries)))
                set_remove(q->transactions, t);

        set_free(t->queries);

        free(t);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsQueryTransaction*, dns_query_transaction_free);

static void dns_query_transaction_gc(DnsQueryTransaction *t) {
        assert(t);

        if (t->block_gc > 0)
                return;

        if (set_isempty(t->queries))
                dns_query_transaction_free(t);
}

static int dns_query_transaction_new(DnsQueryTransaction **ret, DnsScope *s, DnsQuestion *q) {
        _cleanup_(dns_query_transaction_freep) DnsQueryTransaction *t = NULL;
        int r;

        assert(ret);
        assert(s);
        assert(q);

        r = hashmap_ensure_allocated(&s->manager->dns_query_transactions, NULL, NULL);
        if (r < 0)
                return r;

        t = new0(DnsQueryTransaction, 1);
        if (!t)
                return -ENOMEM;

        t->question = dns_question_ref(q);

        do
                random_bytes(&t->id, sizeof(t->id));
        while (t->id == 0 ||
               hashmap_get(s->manager->dns_query_transactions, UINT_TO_PTR(t->id)));

        r = hashmap_put(s->manager->dns_query_transactions, UINT_TO_PTR(t->id), t);
        if (r < 0) {
                t->id = 0;
                return r;
        }

        LIST_PREPEND(transactions_by_scope, s->transactions, t);
        t->scope = s;

        if (ret)
                *ret = t;

        t = NULL;

        return 0;
}

static void dns_query_transaction_stop(DnsQueryTransaction *t) {
        assert(t);

        t->timeout_event_source = sd_event_source_unref(t->timeout_event_source);
        t->stream = dns_stream_free(t->stream);
}

void dns_query_transaction_complete(DnsQueryTransaction *t, DnsQueryState state) {
        DnsQuery *q;
        Iterator i;

        assert(t);
        assert(!IN_SET(state, DNS_QUERY_NULL, DNS_QUERY_PENDING));
        assert(IN_SET(t->state, DNS_QUERY_NULL, DNS_QUERY_PENDING));

        /* Note that this call might invalidate the query. Callers
         * should hence not attempt to access the query or transaction
         * after calling this function. */

        t->state = state;

        dns_query_transaction_stop(t);

        /* Notify all queries that are interested, but make sure the
         * transaction isn't freed while we are still looking at it */
        t->block_gc++;
        SET_FOREACH(q, t->queries, i)
                dns_query_ready(q);
        t->block_gc--;

        dns_query_transaction_gc(t);
}

static int on_stream_complete(DnsStream *s, int error) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        DnsQueryTransaction *t;

        assert(s);
        assert(s->transaction);

        /* Copy the data we care about out of the stream before we
         * destroy it. */
        t = s->transaction;
        p = dns_packet_ref(s->read_packet);

        t->stream = dns_stream_free(t->stream);

        if (error != 0) {
                dns_query_transaction_complete(t, DNS_QUERY_RESOURCES);
                return 0;
        }

        t->block_gc++;
        dns_query_transaction_process_reply(t, p);
        t->block_gc--;

        /* If the response wasn't useful, then complete the transition now */
        if (t->state == DNS_QUERY_PENDING)
                dns_query_transaction_complete(t, DNS_QUERY_INVALID_REPLY);

        return 0;
}

static int dns_query_transaction_open_tcp(DnsQueryTransaction *t) {
        _cleanup_close_ int fd = -1;
        int r;

        assert(t);

        if (t->stream)
                return 0;

        if (t->scope->protocol == DNS_PROTOCOL_DNS)
                fd = dns_scope_tcp_socket(t->scope, AF_UNSPEC, NULL, 53);
        else if (t->scope->protocol == DNS_PROTOCOL_LLMNR) {

                /* When we already received a query to this (but it was truncated), send to its sender address */
                if (t->received)
                        fd = dns_scope_tcp_socket(t->scope, t->received->family, &t->received->sender, t->received->sender_port);
                else {
                        union in_addr_union address;
                        int family;

                        /* Otherwise, try to talk to the owner of a
                         * the IP address, in case this is a reverse
                         * PTR lookup */
                        r = dns_question_extract_reverse_address(t->question, &family, &address);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EINVAL;

                        fd = dns_scope_tcp_socket(t->scope, family, &address, 5355);
                }
        } else
                return -EAFNOSUPPORT;

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

void dns_query_transaction_process_reply(DnsQueryTransaction *t, DnsPacket *p) {
        int r;

        assert(t);
        assert(p);
        assert(t->state == DNS_QUERY_PENDING);

        /* Note that this call might invalidate the query. Callers
         * should hence not attempt to access the query or transaction
         * after calling this function. */

        if (t->scope->protocol == DNS_PROTOCOL_LLMNR) {
                assert(t->scope->link);

                /* For LLMNR we will not accept any packets from other
                 * interfaces */

                if (p->ifindex != t->scope->link->ifindex)
                        return;

                if (p->family != t->scope->family)
                        return;

                if (p->ipproto == IPPROTO_UDP) {
                        if (p->family == AF_INET && !in_addr_equal(AF_INET, &p->destination, (union in_addr_union*) &LLMNR_MULTICAST_IPV4_ADDRESS))
                                return;

                        if (p->family == AF_INET6 && !in_addr_equal(AF_INET6, &p->destination, (union in_addr_union*) &LLMNR_MULTICAST_IPV6_ADDRESS))
                                return;
                }
        }

        if (t->scope->protocol == DNS_PROTOCOL_DNS) {

                /* For DNS we are fine with accepting packets on any
                 * interface, but the source IP address must be one of
                 * a valid DNS server */

                if (!dns_scope_good_dns_server(t->scope, p->family, &p->sender))
                        return;

                if (p->sender_port != 53)
                        return;
        }

        if (t->received != p) {
                dns_packet_unref(t->received);
                t->received = dns_packet_ref(p);
        }

        if (p->ipproto == IPPROTO_TCP) {
                if (DNS_PACKET_TC(p)) {
                        /* Truncated via TCP? Somebody must be fucking with us */
                        dns_query_transaction_complete(t, DNS_QUERY_INVALID_REPLY);
                        return;
                }

                if (DNS_PACKET_ID(p) != t->id) {
                        /* Not the reply to our query? Somebody must be fucking with us */
                        dns_query_transaction_complete(t, DNS_QUERY_INVALID_REPLY);
                        return;
                }
        }

        if (DNS_PACKET_TC(p)) {
                /* Response was truncated, let's try again with good old TCP */
                r = dns_query_transaction_open_tcp(t);
                if (r == -ESRCH) {
                        /* No servers found? Damn! */
                        dns_query_transaction_complete(t, DNS_QUERY_NO_SERVERS);
                        return;
                }
                if (r < 0) {
                        /* On LLMNR, if we cannot connect to the host,
                         * we immediately give up */
                        if (t->scope->protocol == DNS_PROTOCOL_LLMNR) {
                                dns_query_transaction_complete(t, DNS_QUERY_RESOURCES);
                                return;
                        }

                        /* On DNS, couldn't send? Try immediately again, with a new server */
                        dns_scope_next_dns_server(t->scope);

                        r = dns_query_transaction_go(t);
                        if (r < 0) {
                                dns_query_transaction_complete(t, DNS_QUERY_RESOURCES);
                                return;
                        }

                        return;
                }
        }

        /* Parse and update the cache */
        r = dns_packet_extract(p);
        if (r < 0) {
                dns_query_transaction_complete(t, DNS_QUERY_INVALID_REPLY);
                return;
        }

        dns_cache_put(&t->scope->cache, p->question, DNS_PACKET_RCODE(p), p->answer, 0);

        if (DNS_PACKET_RCODE(p) == DNS_RCODE_SUCCESS)
                dns_query_transaction_complete(t, DNS_QUERY_SUCCESS);
        else
                dns_query_transaction_complete(t, DNS_QUERY_FAILURE);
}

static int on_transaction_timeout(sd_event_source *s, usec_t usec, void *userdata) {
        DnsQueryTransaction *t = userdata;
        int r;

        assert(s);
        assert(t);

        /* Timeout reached? Try again, with a new server */
        dns_scope_next_dns_server(t->scope);

        r = dns_query_transaction_go(t);
        if (r < 0)
                dns_query_transaction_complete(t, DNS_QUERY_RESOURCES);

        return 0;
}

static int dns_query_make_packet(DnsQueryTransaction *t) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        unsigned n, added = 0;
        int r;

        assert(t);

        if (t->sent)
                return 0;

        r = dns_packet_new_query(&p, t->scope->protocol, 0);
        if (r < 0)
                return r;

        for (n = 0; n < t->question->n_keys; n++) {
                r = dns_scope_good_key(t->scope, t->question->keys[n]);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = dns_packet_append_key(p, t->question->keys[n], NULL);
                if (r < 0)
                        return r;

                added++;
        }

        if (added <= 0)
                return -EDOM;

        DNS_PACKET_HEADER(p)->qdcount = htobe16(added);
        DNS_PACKET_HEADER(p)->id = t->id;

        t->sent = p;
        p = NULL;

        return 0;
}

static int dns_query_transaction_go(DnsQueryTransaction *t) {
        int r;

        assert(t);

        dns_query_transaction_stop(t);

        if (t->n_attempts >= ATTEMPTS_MAX) {
                dns_query_transaction_complete(t, DNS_QUERY_ATTEMPTS_MAX);
                return 0;
        }

        t->n_attempts++;
        t->received = dns_packet_unref(t->received);
        t->cached = dns_answer_unref(t->cached);
        t->cached_rcode = 0;

        /* First, let's try the cache */
        dns_cache_prune(&t->scope->cache);
        r = dns_cache_lookup(&t->scope->cache, t->question, &t->cached_rcode, &t->cached);
        if (r < 0)
                return r;
        if (r > 0) {
                if (t->cached_rcode == DNS_RCODE_SUCCESS)
                        dns_query_transaction_complete(t, DNS_QUERY_SUCCESS);
                else
                        dns_query_transaction_complete(t, DNS_QUERY_FAILURE);
                return 0;
        }

        /* Otherwise, we need to ask the network */
        r = dns_query_make_packet(t);
        if (r == -EDOM) {
                /* Not the right request to make on this network?
                 * (i.e. an A request made on IPv6 or an AAAA request
                 * made on IPv4, on LLMNR or mDNS.) */
                dns_query_transaction_complete(t, DNS_QUERY_NO_SERVERS);
                return 0;
        }
        if (r < 0)
                return r;

        if (t->scope->protocol == DNS_PROTOCOL_LLMNR &&
            (dns_question_endswith(t->question, "in-addr.arpa") > 0 ||
             dns_question_endswith(t->question, "ip6.arpa") > 0)) {

                /* RFC 4795, Section 2.4. says reverse lookups shall
                 * always be made via TCP on LLMNR */
                r = dns_query_transaction_open_tcp(t);
        } else {
                /* Try via UDP, and if that fails due to large size try via TCP */
                r = dns_scope_send(t->scope, t->sent);
                if (r == -EMSGSIZE)
                        r = dns_query_transaction_open_tcp(t);
        }
        if (r == -ESRCH) {
                /* No servers to send this to? */
                dns_query_transaction_complete(t, DNS_QUERY_NO_SERVERS);
                return 0;
        }
        if (r < 0) {
                /* Couldn't send? Try immediately again, with a new server */
                dns_scope_next_dns_server(t->scope);

                return dns_query_transaction_go(t);
        }

        r = sd_event_add_time(t->scope->manager->event, &t->timeout_event_source, CLOCK_MONOTONIC, now(CLOCK_MONOTONIC) + TRANSACTION_TIMEOUT_USEC, 0, on_transaction_timeout, t);
        if (r < 0)
                return r;

        t->state = DNS_QUERY_PENDING;
        return 1;
}

DnsQuery *dns_query_free(DnsQuery *q) {
        DnsQueryTransaction *t;

        if (!q)
                return NULL;

        sd_bus_message_unref(q->request);

        dns_question_unref(q->question);
        dns_answer_unref(q->answer);

        sd_event_source_unref(q->timeout_event_source);

        while ((t = set_steal_first(q->transactions))) {
                set_remove(t->queries, q);
                dns_query_transaction_gc(t);
        }

        set_free(q->transactions);

        if (q->manager) {
                LIST_REMOVE(queries, q->manager->dns_queries, q);
                q->manager->n_dns_queries--;
        }

        free(q);

        return NULL;
}

int dns_query_new(Manager *m, DnsQuery **ret, DnsQuestion *question) {
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        unsigned i;
        int r;

        assert(m);
        assert(question);

        r = dns_question_is_valid(question);
        if (r < 0)
                return r;

        if (m->n_dns_queries >= QUERIES_MAX)
                return -EBUSY;

        q = new0(DnsQuery, 1);
        if (!q)
                return -ENOMEM;

        q->question = dns_question_ref(question);

        for (i = 0; i < question->n_keys; i++) {
                log_debug("Looking up RR for %s %s %s",
                          strna(dns_class_to_string(question->keys[i]->class)),
                          strna(dns_type_to_string(question->keys[i]->type)),
                          DNS_RESOURCE_KEY_NAME(question->keys[i]));
        }

        LIST_PREPEND(queries, m->dns_queries, q);
        m->n_dns_queries++;
        q->manager = m;

        if (ret)
                *ret = q;
        q = NULL;

        return 0;
}

static void dns_query_stop(DnsQuery *q) {
        DnsQueryTransaction *t;

        assert(q);

        q->timeout_event_source = sd_event_source_unref(q->timeout_event_source);

        while ((t = set_steal_first(q->transactions))) {
                set_remove(t->queries, q);
                dns_query_transaction_gc(t);
        }
}

static void dns_query_complete(DnsQuery *q, DnsQueryState state) {
        assert(q);
        assert(!IN_SET(state, DNS_QUERY_NULL, DNS_QUERY_PENDING));
        assert(IN_SET(q->state, DNS_QUERY_NULL, DNS_QUERY_PENDING));

        /* Note that this call might invalidate the query. Callers
         * should hence not attempt to access the query or transaction
         * after calling this function. */

        q->state = state;

        dns_query_stop(q);
        if (q->complete)
                q->complete(q);
}

static int on_query_timeout(sd_event_source *s, usec_t usec, void *userdata) {
        DnsQuery *q = userdata;

        assert(s);
        assert(q);

        dns_query_complete(q, DNS_QUERY_TIMEOUT);
        return 0;
}

static int dns_query_add_transaction(DnsQuery *q, DnsScope *s, DnsResourceKey *key) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        DnsQueryTransaction *t;
        int r;

        assert(q);

        r = set_ensure_allocated(&q->transactions, NULL, NULL);
        if (r < 0)
                return r;

        if (key) {
                question = dns_question_new(1);
                if (!question)
                        return -ENOMEM;

                r = dns_question_add(question, key);
                if (r < 0)
                        return r;
        } else
                question = dns_question_ref(q->question);

        LIST_FOREACH(transactions_by_scope, t, s->transactions)
                if (dns_question_is_superset(t->question, question))
                        break;

        if (!t) {
                r = dns_query_transaction_new(&t, s, question);
                if (r < 0)
                        return r;
        }

        r = set_ensure_allocated(&t->queries, NULL, NULL);
        if (r < 0)
                goto fail;

        r = set_put(t->queries, q);
        if (r < 0)
                goto fail;

        r = set_put(q->transactions, t);
        if (r < 0) {
                set_remove(t->queries, q);
                goto fail;
        }

        return 0;

fail:
        dns_query_transaction_gc(t);
        return r;
}

static int dns_query_add_transaction_split(DnsQuery *q, DnsScope *s) {
        int r;

        assert(q);
        assert(s);

        if (s->protocol == DNS_PROTOCOL_MDNS) {
                r = dns_query_add_transaction(q, s, NULL);
                if (r < 0)
                        return r;
        } else {
                unsigned i;

                /* On DNS and LLMNR we can only send a single
                 * question per datagram, hence issue multiple
                 * transactions. */

                for (i = 0; i < q->question->n_keys; i++) {
                        r = dns_query_add_transaction(q, s, q->question->keys[i]);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

int dns_query_go(DnsQuery *q) {
        DnsScopeMatch found = DNS_SCOPE_NO;
        DnsScope *s, *first = NULL;
        DnsQueryTransaction *t;
        const char *name;
        Iterator i;
        int r;

        assert(q);

        if (q->state != DNS_QUERY_NULL)
                return 0;

        assert(q->question);
        assert(q->question->n_keys > 0);

        name = DNS_RESOURCE_KEY_NAME(q->question->keys[0]);

        LIST_FOREACH(scopes, s, q->manager->dns_scopes) {
                DnsScopeMatch match;

                match = dns_scope_good_domain(s, name);
                if (match < 0)
                        return match;

                if (match == DNS_SCOPE_NO)
                        continue;

                found = match;

                if (match == DNS_SCOPE_YES) {
                        first = s;
                        break;
                } else {
                        assert(match == DNS_SCOPE_MAYBE);

                        if (!first)
                                first = s;
                }
        }

        if (found == DNS_SCOPE_NO)
                return -ESRCH;

        r = dns_query_add_transaction_split(q, first);
        if (r < 0)
                return r;

        LIST_FOREACH(scopes, s, first->scopes_next) {
                DnsScopeMatch match;

                match = dns_scope_good_domain(s, name);
                if (match < 0)
                        return match;

                if (match != found)
                        continue;

                r = dns_query_add_transaction_split(q, s);
                if (r < 0)
                        return r;
        }

        q->answer = dns_answer_unref(q->answer);
        q->answer_ifindex = 0;
        q->answer_rcode = 0;

        r = sd_event_add_time(q->manager->event, &q->timeout_event_source, CLOCK_MONOTONIC, now(CLOCK_MONOTONIC) + QUERY_TIMEOUT_USEC, 0, on_query_timeout, q);
        if (r < 0)
                goto fail;

        q->state = DNS_QUERY_PENDING;
        q->block_ready++;

        SET_FOREACH(t, q->transactions, i) {
                if (t->state == DNS_QUERY_NULL) {
                        r = dns_query_transaction_go(t);
                        if (r < 0)
                                goto fail;
                }
        }

        q->block_ready--;
        dns_query_ready(q);

        return 1;

fail:
        dns_query_stop(q);
        return r;
}

void dns_query_ready(DnsQuery *q) {
        DnsQueryTransaction *t;
        DnsQueryState state = DNS_QUERY_NO_SERVERS;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        int rcode = 0;
        DnsScope *scope = NULL;
        Iterator i;

        assert(q);
        assert(IN_SET(q->state, DNS_QUERY_NULL, DNS_QUERY_PENDING));

        /* Note that this call might invalidate the query. Callers
         * should hence not attempt to access the query or transaction
         * after calling this function, unless the block_ready
         * counter was explicitly bumped before doing so. */

        if (q->block_ready > 0)
                return;

        SET_FOREACH(t, q->transactions, i) {

                /* If we found a successful answer, ignore all answers from other scopes */
                if (state == DNS_QUERY_SUCCESS && t->scope != scope)
                        continue;

                /* One of the transactions is still going on, let's wait for it */
                if (t->state == DNS_QUERY_PENDING || t->state == DNS_QUERY_NULL)
                        return;

                /* One of the transactions is successful, let's use
                 * it, and copy its data out */
                if (t->state == DNS_QUERY_SUCCESS) {
                        DnsAnswer *a;

                        if (t->received) {
                                rcode = DNS_PACKET_RCODE(t->received);
                                a = t->received->answer;
                        } else {
                                rcode = t->cached_rcode;
                                a = t->cached;
                        }

                        if (state == DNS_QUERY_SUCCESS) {
                                DnsAnswer *merged;

                                merged = dns_answer_merge(answer, a);
                                if (!merged) {
                                        dns_query_complete(q, DNS_QUERY_RESOURCES);
                                        return;
                                }

                                dns_answer_unref(answer);
                                answer = merged;
                        } else {
                                dns_answer_unref(answer);
                                answer = dns_answer_ref(a);
                        }

                        scope = t->scope;
                        state = DNS_QUERY_SUCCESS;
                        continue;
                }

                /* One of the transactions has failed, let's see
                 * whether we find anything better, but if not, return
                 * its response data */
                if (state != DNS_QUERY_SUCCESS && t->state == DNS_QUERY_FAILURE) {
                        DnsAnswer *a;

                        if (t->received) {
                                rcode = DNS_PACKET_RCODE(t->received);
                                a = t->received->answer;
                        } else {
                                rcode = t->cached_rcode;
                                a = t->cached;
                        }

                        dns_answer_unref(answer);
                        answer = dns_answer_ref(a);

                        scope = t->scope;
                        state = DNS_QUERY_FAILURE;
                        continue;
                }

                if (state == DNS_QUERY_NO_SERVERS && t->state != DNS_QUERY_NO_SERVERS)
                        state = t->state;
        }

        if (IN_SET(state, DNS_QUERY_SUCCESS, DNS_QUERY_FAILURE)) {
                q->answer = dns_answer_ref(answer);
                q->answer_rcode = rcode;
                q->answer_ifindex = (scope && scope->link) ? scope->link->ifindex : 0;
        }

        dns_query_complete(q, state);
}

int dns_query_cname_redirect(DnsQuery *q, const char *name) {
        _cleanup_(dns_question_unrefp) DnsQuestion *nq = NULL;
        int r;

        assert(q);

        if (q->n_cname_redirects > CNAME_MAX)
                return -ELOOP;

        r = dns_question_cname_redirect(q->question, name, &nq);
        if (r < 0)
                return r;

        dns_question_unref(q->question);
        q->question = nq;
        nq = NULL;

        q->n_cname_redirects++;

        dns_query_stop(q);
        q->state = DNS_QUERY_NULL;

        return 0;
}
