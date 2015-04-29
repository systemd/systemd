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

/* How long to wait for the query in total */
#define QUERY_TIMEOUT_USEC (30 * USEC_PER_SEC)

#define CNAME_MAX 8
#define QUERIES_MAX 2048

static void dns_query_stop(DnsQuery *q) {
        DnsTransaction *t;

        assert(q);

        q->timeout_event_source = sd_event_source_unref(q->timeout_event_source);

        while ((t = set_steal_first(q->transactions))) {
                set_remove(t->queries, q);
                dns_transaction_gc(t);
        }
}

DnsQuery *dns_query_free(DnsQuery *q) {
        if (!q)
                return NULL;

        dns_query_stop(q);
        set_free(q->transactions);

        dns_question_unref(q->question);
        dns_answer_unref(q->answer);

        sd_bus_message_unref(q->request);
        sd_bus_track_unref(q->bus_track);

        if (q->manager) {
                LIST_REMOVE(queries, q->manager->dns_queries, q);
                q->manager->n_dns_queries--;
        }

        free(q);

        return NULL;
}

int dns_query_new(Manager *m, DnsQuery **ret, DnsQuestion *question, int ifindex, uint64_t flags) {
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
        q->ifindex = ifindex;
        q->flags = flags;

        for (i = 0; i < question->n_keys; i++) {
                _cleanup_free_ char *p;

                r = dns_resource_key_to_string(question->keys[i], &p);
                if (r < 0)
                        return r;

                log_debug("Looking up RR for %s", p);
        }

        LIST_PREPEND(queries, m->dns_queries, q);
        m->n_dns_queries++;
        q->manager = m;

        if (ret)
                *ret = q;
        q = NULL;

        return 0;
}

static void dns_query_complete(DnsQuery *q, DnsTransactionState state) {
        assert(q);
        assert(!IN_SET(state, DNS_TRANSACTION_NULL, DNS_TRANSACTION_PENDING));
        assert(IN_SET(q->state, DNS_TRANSACTION_NULL, DNS_TRANSACTION_PENDING));

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

        dns_query_complete(q, DNS_TRANSACTION_TIMEOUT);
        return 0;
}

static int dns_query_add_transaction(DnsQuery *q, DnsScope *s, DnsResourceKey *key) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        DnsTransaction *t;
        int r;

        assert(q);
        assert(s);

        r = set_ensure_allocated(&q->transactions, NULL);
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

        t = dns_scope_find_transaction(s, question, true);
        if (!t) {
                r = dns_transaction_new(&t, s, question);
                if (r < 0)
                        return r;
        }

        r = set_ensure_allocated(&t->queries, NULL);
        if (r < 0)
                goto gc;

        r = set_put(t->queries, q);
        if (r < 0)
                goto gc;

        r = set_put(q->transactions, t);
        if (r < 0) {
                set_remove(t->queries, q);
                goto gc;
        }

        return 0;

gc:
        dns_transaction_gc(t);
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
        DnsTransaction *t;
        const char *name;
        Iterator i;
        int r;

        assert(q);

        if (q->state != DNS_TRANSACTION_NULL)
                return 0;

        assert(q->question);
        assert(q->question->n_keys > 0);

        name = DNS_RESOURCE_KEY_NAME(q->question->keys[0]);

        LIST_FOREACH(scopes, s, q->manager->dns_scopes) {
                DnsScopeMatch match;

                match = dns_scope_good_domain(s, q->ifindex, q->flags, name);
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
                goto fail;

        LIST_FOREACH(scopes, s, first->scopes_next) {
                DnsScopeMatch match;

                match = dns_scope_good_domain(s, q->ifindex, q->flags, name);
                if (match < 0)
                        goto fail;

                if (match != found)
                        continue;

                r = dns_query_add_transaction_split(q, s);
                if (r < 0)
                        goto fail;
        }

        q->answer = dns_answer_unref(q->answer);
        q->answer_ifindex = 0;
        q->answer_rcode = 0;
        q->answer_family = AF_UNSPEC;
        q->answer_protocol = _DNS_PROTOCOL_INVALID;

        r = sd_event_add_time(
                        q->manager->event,
                        &q->timeout_event_source,
                        clock_boottime_or_monotonic(),
                        now(clock_boottime_or_monotonic()) + QUERY_TIMEOUT_USEC, 0,
                        on_query_timeout, q);
        if (r < 0)
                goto fail;

        q->state = DNS_TRANSACTION_PENDING;
        q->block_ready++;

        /* Start the transactions that are not started yet */
        SET_FOREACH(t, q->transactions, i) {
                if (t->state != DNS_TRANSACTION_NULL)
                        continue;

                r = dns_transaction_go(t);
                if (r < 0)
                        goto fail;
        }

        q->block_ready--;
        dns_query_ready(q);

        return 1;

fail:
        dns_query_stop(q);
        return r;
}

void dns_query_ready(DnsQuery *q) {
        DnsTransaction *t;
        DnsTransactionState state = DNS_TRANSACTION_NO_SERVERS;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        int rcode = 0;
        DnsScope *scope = NULL;
        bool pending = false;
        Iterator i;

        assert(q);
        assert(IN_SET(q->state, DNS_TRANSACTION_NULL, DNS_TRANSACTION_PENDING));

        /* Note that this call might invalidate the query. Callers
         * should hence not attempt to access the query or transaction
         * after calling this function, unless the block_ready
         * counter was explicitly bumped before doing so. */

        if (q->block_ready > 0)
                return;

        SET_FOREACH(t, q->transactions, i) {

                /* If we found a successful answer, ignore all answers from other scopes */
                if (state == DNS_TRANSACTION_SUCCESS && t->scope != scope)
                        continue;

                /* One of the transactions is still going on, let's maybe wait for it */
                if (IN_SET(t->state, DNS_TRANSACTION_PENDING, DNS_TRANSACTION_NULL)) {
                        pending = true;
                        continue;
                }

                /* One of the transactions is successful, let's use
                 * it, and copy its data out */
                if (t->state == DNS_TRANSACTION_SUCCESS) {
                        DnsAnswer *a;

                        if (t->received) {
                                rcode = DNS_PACKET_RCODE(t->received);
                                a = t->received->answer;
                        } else {
                                rcode = t->cached_rcode;
                                a = t->cached;
                        }

                        if (state == DNS_TRANSACTION_SUCCESS) {
                                DnsAnswer *merged;

                                merged = dns_answer_merge(answer, a);
                                if (!merged) {
                                        dns_query_complete(q, DNS_TRANSACTION_RESOURCES);
                                        return;
                                }

                                dns_answer_unref(answer);
                                answer = merged;
                        } else {
                                dns_answer_unref(answer);
                                answer = dns_answer_ref(a);
                        }

                        scope = t->scope;
                        state = DNS_TRANSACTION_SUCCESS;
                        continue;
                }

                /* One of the transactions has failed, let's see
                 * whether we find anything better, but if not, return
                 * its response data */
                if (state != DNS_TRANSACTION_SUCCESS && t->state == DNS_TRANSACTION_FAILURE) {
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
                        state = DNS_TRANSACTION_FAILURE;
                        continue;
                }

                if (state == DNS_TRANSACTION_NO_SERVERS && t->state != DNS_TRANSACTION_NO_SERVERS)
                        state = t->state;
        }

        if (pending) {

                /* If so far we weren't successful, and there's
                 * something still pending, then wait for it */
                if (state != DNS_TRANSACTION_SUCCESS)
                        return;

                /* If we already were successful, then only wait for
                 * other transactions on the same scope to finish. */
                SET_FOREACH(t, q->transactions, i) {
                        if (t->scope == scope && IN_SET(t->state, DNS_TRANSACTION_PENDING, DNS_TRANSACTION_NULL))
                                return;
                }
        }

        if (IN_SET(state, DNS_TRANSACTION_SUCCESS, DNS_TRANSACTION_FAILURE)) {
                q->answer = dns_answer_ref(answer);
                q->answer_rcode = rcode;
                q->answer_ifindex = (scope && scope->link) ? scope->link->ifindex : 0;
                q->answer_protocol = scope ? scope->protocol : _DNS_PROTOCOL_INVALID;
                q->answer_family = scope ? scope->family : AF_UNSPEC;
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
        q->state = DNS_TRANSACTION_NULL;

        return 0;
}

static int on_bus_track(sd_bus_track *t, void *userdata) {
        DnsQuery *q = userdata;

        assert(t);
        assert(q);

        log_debug("Client of active query vanished, aborting query.");
        dns_query_complete(q, DNS_TRANSACTION_ABORTED);
        return 0;
}

int dns_query_bus_track(DnsQuery *q, sd_bus_message *m) {
        int r;

        assert(q);
        assert(m);

        if (!q->bus_track) {
                r = sd_bus_track_new(sd_bus_message_get_bus(m), &q->bus_track, on_bus_track, q);
                if (r < 0)
                        return r;
        }

        r = sd_bus_track_add_sender(q->bus_track, m);
        if (r < 0)
                return r;

        return 0;
}
