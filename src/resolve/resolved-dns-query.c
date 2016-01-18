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
#include "dns-domain.h"
#include "hostname-util.h"
#include "local-addresses.h"
#include "resolved-dns-query.h"

/* How long to wait for the query in total */
#define QUERY_TIMEOUT_USEC (30 * USEC_PER_SEC)

#define CNAME_MAX 8
#define QUERIES_MAX 2048
#define AUXILIARY_QUERIES_MAX 64

static int dns_query_candidate_new(DnsQueryCandidate **ret, DnsQuery *q, DnsScope *s) {
        DnsQueryCandidate *c;

        assert(ret);
        assert(q);
        assert(s);

        c = new0(DnsQueryCandidate, 1);
        if (!c)
                return -ENOMEM;

        c->query = q;
        c->scope = s;

        LIST_PREPEND(candidates_by_query, q->candidates, c);
        LIST_PREPEND(candidates_by_scope, s->query_candidates, c);

        *ret = c;
        return 0;
}

static void dns_query_candidate_stop(DnsQueryCandidate *c) {
        DnsTransaction *t;

        assert(c);

        while ((t = set_steal_first(c->transactions))) {
                set_remove(t->notify_query_candidates, c);
                dns_transaction_gc(t);
        }
}

DnsQueryCandidate* dns_query_candidate_free(DnsQueryCandidate *c) {

        if (!c)
                return NULL;

        dns_query_candidate_stop(c);

        set_free(c->transactions);
        dns_search_domain_unref(c->search_domain);

        if (c->query)
                LIST_REMOVE(candidates_by_query, c->query->candidates, c);

        if (c->scope)
                LIST_REMOVE(candidates_by_scope, c->scope->query_candidates, c);

        free(c);

        return NULL;
}

static int dns_query_candidate_next_search_domain(DnsQueryCandidate *c) {
        DnsSearchDomain *next = NULL;

        assert(c);

        if (c->search_domain && c->search_domain->linked) {
                next = c->search_domain->domains_next;

                if (!next) /* We hit the end of the list */
                        return 0;

        } else {
                next = dns_scope_get_search_domains(c->scope);

                if (!next) /* OK, there's nothing. */
                        return 0;
        }

        dns_search_domain_unref(c->search_domain);
        c->search_domain = dns_search_domain_ref(next);

        return 1;
}

static int dns_query_candidate_add_transaction(DnsQueryCandidate *c, DnsResourceKey *key) {
        DnsTransaction *t;
        int r;

        assert(c);
        assert(key);

        t = dns_scope_find_transaction(c->scope, key, true);
        if (!t) {
                r = dns_transaction_new(&t, c->scope, key);
                if (r < 0)
                        return r;
        } else {
                if (set_contains(c->transactions, t))
                        return 0;
        }

        r = set_ensure_allocated(&c->transactions, NULL);
        if (r < 0)
                goto gc;

        r = set_ensure_allocated(&t->notify_query_candidates, NULL);
        if (r < 0)
                goto gc;

        r = set_put(t->notify_query_candidates, c);
        if (r < 0)
                goto gc;

        r = set_put(c->transactions, t);
        if (r < 0) {
                (void) set_remove(t->notify_query_candidates, c);
                goto gc;
        }

        return 1;

gc:
        dns_transaction_gc(t);
        return r;
}

static int dns_query_candidate_go(DnsQueryCandidate *c) {
        DnsTransaction *t;
        Iterator i;
        int r;

        assert(c);

        /* Start the transactions that are not started yet */
        SET_FOREACH(t, c->transactions, i) {
                if (t->state != DNS_TRANSACTION_NULL)
                        continue;

                r = dns_transaction_go(t);
                if (r < 0)
                        return r;
        }

        return 0;
}

static DnsTransactionState dns_query_candidate_state(DnsQueryCandidate *c) {
        DnsTransactionState state = DNS_TRANSACTION_NO_SERVERS;
        DnsTransaction *t;
        Iterator i;

        assert(c);

        if (c->error_code != 0)
                return DNS_TRANSACTION_RESOURCES;

        SET_FOREACH(t, c->transactions, i) {

                switch (t->state) {

                case DNS_TRANSACTION_NULL:
                        /* If there's a NULL transaction pending, then
                         * this means not all transactions where
                         * started yet, and we were called from within
                         * the stackframe that is supposed to start
                         * remaining transactions. In this case,
                         * simply claim the candidate is pending. */

                case DNS_TRANSACTION_PENDING:
                case DNS_TRANSACTION_VALIDATING:
                        /* If there's one transaction currently in
                         * VALIDATING state, then this means there's
                         * also one in PENDING state, hence we can
                         * return PENDING immediately. */
                        return DNS_TRANSACTION_PENDING;

                case DNS_TRANSACTION_SUCCESS:
                        state = t->state;
                        break;

                default:
                        if (state != DNS_TRANSACTION_SUCCESS)
                                state = t->state;

                        break;
                }
        }

        return state;
}

static int dns_query_candidate_setup_transactions(DnsQueryCandidate *c) {
        DnsResourceKey *key;
        int n = 0, r;

        assert(c);

        dns_query_candidate_stop(c);

        /* Create one transaction per question key */
        DNS_QUESTION_FOREACH(key, c->query->question) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *new_key = NULL;

                if (c->search_domain) {
                        r = dns_resource_key_new_append_suffix(&new_key, key, c->search_domain->name);
                        if (r < 0)
                                goto fail;
                }

                r = dns_query_candidate_add_transaction(c, new_key ?: key);
                if (r < 0)
                        goto fail;

                n++;
        }

        return n;

fail:
        dns_query_candidate_stop(c);
        return r;
}

void dns_query_candidate_notify(DnsQueryCandidate *c) {
        DnsTransactionState state;
        int r;

        assert(c);

        state = dns_query_candidate_state(c);

        if (DNS_TRANSACTION_IS_LIVE(state))
                return;

        if (state != DNS_TRANSACTION_SUCCESS && c->search_domain) {

                r = dns_query_candidate_next_search_domain(c);
                if (r < 0)
                        goto fail;

                if (r > 0) {
                        /* OK, there's another search domain to try, let's do so. */

                        r = dns_query_candidate_setup_transactions(c);
                        if (r < 0)
                                goto fail;

                        if (r > 0) {
                                /* New transactions where queued. Start them and wait */

                                r = dns_query_candidate_go(c);
                                if (r < 0)
                                        goto fail;

                                return;
                        }
                }

        }

        dns_query_ready(c->query);
        return;

fail:
        log_warning_errno(r, "Failed to follow search domains: %m");
        c->error_code = r;
        dns_query_ready(c->query);
}

static void dns_query_stop(DnsQuery *q) {
        DnsQueryCandidate *c;

        assert(q);

        q->timeout_event_source = sd_event_source_unref(q->timeout_event_source);

        LIST_FOREACH(candidates_by_query, c, q->candidates)
                dns_query_candidate_stop(c);
}

DnsQuery *dns_query_free(DnsQuery *q) {
        if (!q)
                return NULL;

        while (q->auxiliary_queries)
                dns_query_free(q->auxiliary_queries);

        if (q->auxiliary_for) {
                assert(q->auxiliary_for->n_auxiliary_queries > 0);
                q->auxiliary_for->n_auxiliary_queries--;
                LIST_REMOVE(auxiliary_queries, q->auxiliary_for->auxiliary_queries, q);
        }

        while (q->candidates)
                dns_query_candidate_free(q->candidates);

        dns_question_unref(q->question);
        dns_answer_unref(q->answer);
        dns_search_domain_unref(q->answer_search_domain);

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

        r = dns_question_is_valid_for_query(question);
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
        q->answer_family = AF_UNSPEC;
        q->answer_protocol = _DNS_PROTOCOL_INVALID;

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

int dns_query_make_auxiliary(DnsQuery *q, DnsQuery *auxiliary_for) {
        assert(q);
        assert(auxiliary_for);

        /* Ensure that that the query is not auxiliary yet, and
         * nothing else is auxiliary to it either */
        assert(!q->auxiliary_for);
        assert(!q->auxiliary_queries);

        /* Ensure that the unit we shall be made auxiliary for isn't
         * auxiliary itself */
        assert(!auxiliary_for->auxiliary_for);

        if (auxiliary_for->n_auxiliary_queries >= AUXILIARY_QUERIES_MAX)
                return -EAGAIN;

        LIST_PREPEND(auxiliary_queries, auxiliary_for->auxiliary_queries, q);
        q->auxiliary_for = auxiliary_for;

        auxiliary_for->n_auxiliary_queries++;
        return 0;
}

static void dns_query_complete(DnsQuery *q, DnsTransactionState state) {
        assert(q);
        assert(!DNS_TRANSACTION_IS_LIVE(state));
        assert(DNS_TRANSACTION_IS_LIVE(q->state));

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

static int dns_query_add_candidate(DnsQuery *q, DnsScope *s) {
        DnsQueryCandidate *c;
        int r;

        assert(q);
        assert(s);

        r = dns_query_candidate_new(&c, q, s);
        if (r < 0)
                return r;

        /* If this a single-label domain on DNS, we might append a suitable search domain first. */
        if ((q->flags & SD_RESOLVED_NO_SEARCH) == 0)  {
                r = dns_scope_name_needs_search_domain(s, dns_question_first_name(q->question));
                if (r < 0)
                        goto fail;
                if (r > 0) {
                        /* OK, we need a search domain now. Let's find one for this scope */

                        r = dns_query_candidate_next_search_domain(c);
                        if (r <= 0) /* if there's no search domain, then we won't add any transaction. */
                                goto fail;
                }
        }

        r = dns_query_candidate_setup_transactions(c);
        if (r < 0)
                goto fail;

        return 0;

fail:
        dns_query_candidate_free(c);
        return r;
}

static int SYNTHESIZE_IFINDEX(int ifindex) {

        /* When the caller asked for resolving on a specific
         * interface, we synthesize the answer for that
         * interface. However, if nothing specific was claimed and we
         * only return localhost RRs, we synthesize the answer for
         * localhost. */

        if (ifindex > 0)
                return ifindex;

        return LOOPBACK_IFINDEX;
}

static int SYNTHESIZE_FAMILY(uint64_t flags) {

        /* Picks an address family depending on set flags. This is
         * purely for synthesized answers, where the family we return
         * for the reply should match what was requested in the
         * question, even though we are synthesizing the answer
         * here. */

        if (!(flags & SD_RESOLVED_DNS)) {
                if (flags & SD_RESOLVED_LLMNR_IPV4)
                        return AF_INET;
                if (flags & SD_RESOLVED_LLMNR_IPV6)
                        return AF_INET6;
        }

        return AF_UNSPEC;
}

static DnsProtocol SYNTHESIZE_PROTOCOL(uint64_t flags) {

        /* Similar as SYNTHESIZE_FAMILY() but does this for the
         * protocol. If resolving via DNS was requested, we claim it
         * was DNS. Similar, if nothing specific was
         * requested. However, if only resolving via LLMNR was
         * requested we return that. */

        if (flags & SD_RESOLVED_DNS)
                return DNS_PROTOCOL_DNS;
        if (flags & SD_RESOLVED_LLMNR)
                return DNS_PROTOCOL_LLMNR;

        return DNS_PROTOCOL_DNS;
}

static int dns_type_to_af(uint16_t t) {
        switch (t) {

        case DNS_TYPE_A:
                return AF_INET;

        case DNS_TYPE_AAAA:
                return AF_INET6;

        case DNS_TYPE_ANY:
                return AF_UNSPEC;

        default:
                return -EINVAL;
        }
}

static int synthesize_localhost_rr(DnsQuery *q, DnsResourceKey *key, DnsAnswer **answer) {
        int r;

        assert(q);
        assert(key);
        assert(answer);

        r = dns_answer_reserve(answer, 2);
        if (r < 0)
                return r;

        if (IN_SET(key->type, DNS_TYPE_A, DNS_TYPE_ANY)) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, DNS_RESOURCE_KEY_NAME(key));
                if (!rr)
                        return -ENOMEM;

                rr->a.in_addr.s_addr = htobe32(INADDR_LOOPBACK);

                r = dns_answer_add(*answer, rr, SYNTHESIZE_IFINDEX(q->ifindex), DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;
        }

        if (IN_SET(key->type, DNS_TYPE_AAAA, DNS_TYPE_ANY)) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, DNS_RESOURCE_KEY_NAME(key));
                if (!rr)
                        return -ENOMEM;

                rr->aaaa.in6_addr = in6addr_loopback;

                r = dns_answer_add(*answer, rr, SYNTHESIZE_IFINDEX(q->ifindex), DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int answer_add_ptr(DnsAnswer **answer, const char *from, const char *to, int ifindex, DnsAnswerFlags flags) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, from);
        if (!rr)
                return -ENOMEM;

        rr->ptr.name = strdup(to);
        if (!rr->ptr.name)
                return -ENOMEM;

        return dns_answer_add(*answer, rr, ifindex, flags);
}

static int synthesize_localhost_ptr(DnsQuery *q, DnsResourceKey *key, DnsAnswer **answer) {
        int r;

        assert(q);
        assert(key);
        assert(answer);

        if (IN_SET(key->type, DNS_TYPE_PTR, DNS_TYPE_ANY)) {
                r = dns_answer_reserve(answer, 1);
                if (r < 0)
                        return r;

                r = answer_add_ptr(answer, DNS_RESOURCE_KEY_NAME(key), "localhost", SYNTHESIZE_IFINDEX(q->ifindex), DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int answer_add_addresses_rr(
                DnsAnswer **answer,
                const char *name,
                struct local_address *addresses,
                unsigned n_addresses) {

        unsigned j;
        int r;

        assert(answer);
        assert(name);

        r = dns_answer_reserve(answer, n_addresses);
        if (r < 0)
                return r;

        for (j = 0; j < n_addresses; j++) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                r = dns_resource_record_new_address(&rr, addresses[j].family, &addresses[j].address, name);
                if (r < 0)
                        return r;

                r = dns_answer_add(*answer, rr, addresses[j].ifindex, DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int answer_add_addresses_ptr(
                DnsAnswer **answer,
                const char *name,
                struct local_address *addresses,
                unsigned n_addresses,
                int af, const union in_addr_union *match) {

        unsigned j;
        int r;

        assert(answer);
        assert(name);

        for (j = 0; j < n_addresses; j++) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                if (af != AF_UNSPEC) {

                        if (addresses[j].family != af)
                                continue;

                        if (match && !in_addr_equal(af, match, &addresses[j].address))
                                continue;
                }

                r = dns_answer_reserve(answer, 1);
                if (r < 0)
                        return r;

                r = dns_resource_record_new_reverse(&rr, addresses[j].family, &addresses[j].address, name);
                if (r < 0)
                        return r;

                r = dns_answer_add(*answer, rr, addresses[j].ifindex, DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int synthesize_system_hostname_rr(DnsQuery *q, DnsResourceKey *key, DnsAnswer **answer) {
        _cleanup_free_ struct local_address *addresses = NULL;
        int n = 0, af;

        assert(q);
        assert(key);
        assert(answer);

        af = dns_type_to_af(key->type);
        if (af >= 0) {
                n = local_addresses(q->manager->rtnl, q->ifindex, af, &addresses);
                if (n < 0)
                        return n;

                if (n == 0) {
                        struct local_address buffer[2];

                        /* If we have no local addresses then use ::1
                         * and 127.0.0.2 as local ones. */

                        if (af == AF_INET || af == AF_UNSPEC)
                                buffer[n++] = (struct local_address) {
                                        .family = AF_INET,
                                        .ifindex = SYNTHESIZE_IFINDEX(q->ifindex),
                                        .address.in.s_addr = htobe32(0x7F000002),
                                };

                        if (af == AF_INET6 || af == AF_UNSPEC)
                                buffer[n++] = (struct local_address) {
                                        .family = AF_INET6,
                                        .ifindex = SYNTHESIZE_IFINDEX(q->ifindex),
                                        .address.in6 = in6addr_loopback,
                                };

                        return answer_add_addresses_rr(answer, DNS_RESOURCE_KEY_NAME(key), buffer, n);
                }
        }

        return answer_add_addresses_rr(answer, DNS_RESOURCE_KEY_NAME(key), addresses, n);
}

static int synthesize_system_hostname_ptr(DnsQuery *q, int af, const union in_addr_union *address, DnsAnswer **answer) {
        _cleanup_free_ struct local_address *addresses = NULL;
        int n, r;

        assert(q);
        assert(address);
        assert(answer);

        if (af == AF_INET && address->in.s_addr == htobe32(0x7F000002)) {

                /* Always map the IPv4 address 127.0.0.2 to the local
                 * hostname, in addition to "localhost": */

                r = dns_answer_reserve(answer, 3);
                if (r < 0)
                        return r;

                r = answer_add_ptr(answer, "2.0.0.127.in-addr.arpa", q->manager->llmnr_hostname, SYNTHESIZE_IFINDEX(q->ifindex), DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;

                r = answer_add_ptr(answer, "2.0.0.127.in-addr.arpa", q->manager->mdns_hostname, SYNTHESIZE_IFINDEX(q->ifindex), DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;

                r = answer_add_ptr(answer, "2.0.0.127.in-addr.arpa", "localhost", SYNTHESIZE_IFINDEX(q->ifindex), DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;

                return 0;
        }

        n = local_addresses(q->manager->rtnl, q->ifindex, af, &addresses);
        if (n < 0)
                return n;

        r = answer_add_addresses_ptr(answer, q->manager->llmnr_hostname, addresses, n, af, address);
        if (r < 0)
                return r;

        return answer_add_addresses_ptr(answer, q->manager->mdns_hostname, addresses, n, af, address);
}

static int synthesize_gateway_rr(DnsQuery *q, DnsResourceKey *key, DnsAnswer **answer) {
        _cleanup_free_ struct local_address *addresses = NULL;
        int n = 0, af;

        assert(q);
        assert(key);
        assert(answer);

        af = dns_type_to_af(key->type);
        if (af >= 0) {
                n = local_gateways(q->manager->rtnl, q->ifindex, af, &addresses);
                if (n < 0)
                        return n;
        }

        return answer_add_addresses_rr(answer, DNS_RESOURCE_KEY_NAME(key), addresses, n);
}

static int synthesize_gateway_ptr(DnsQuery *q, int af, const union in_addr_union *address, DnsAnswer **answer) {
        _cleanup_free_ struct local_address *addresses = NULL;
        int n;

        assert(q);
        assert(address);
        assert(answer);

        n = local_gateways(q->manager->rtnl, q->ifindex, af, &addresses);
        if (n < 0)
                return n;

        return answer_add_addresses_ptr(answer, "gateway", addresses, n, af, address);
}

static int dns_query_synthesize_reply(DnsQuery *q, DnsTransactionState *state) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        unsigned i;
        int r;

        assert(q);
        assert(state);

        /* Tries to synthesize localhost RR replies where appropriate */

        if (!IN_SET(*state,
                    DNS_TRANSACTION_RCODE_FAILURE,
                    DNS_TRANSACTION_NO_SERVERS,
                    DNS_TRANSACTION_TIMEOUT,
                    DNS_TRANSACTION_ATTEMPTS_MAX_REACHED))
                return 0;

        for (i = 0; i < q->question->n_keys; i++) {
                union in_addr_union address;
                const char *name;
                int af;

                if (q->question->keys[i]->class != DNS_CLASS_IN &&
                    q->question->keys[i]->class != DNS_CLASS_ANY)
                        continue;

                name = DNS_RESOURCE_KEY_NAME(q->question->keys[i]);

                if (is_localhost(name)) {

                        r = synthesize_localhost_rr(q, q->question->keys[i], &answer);
                        if (r < 0)
                                return log_error_errno(r, "Failed to synthesize localhost RRs: %m");

                } else if (manager_is_own_hostname(q->manager, name)) {

                        r = synthesize_system_hostname_rr(q, q->question->keys[i], &answer);
                        if (r < 0)
                                return log_error_errno(r, "Failed to synthesize system hostname RRs: %m");

                } else if (is_gateway_hostname(name)) {

                        r = synthesize_gateway_rr(q, q->question->keys[i], &answer);
                        if (r < 0)
                                return log_error_errno(r, "Failed to synthesize gateway RRs: %m");

                } else if ((dns_name_endswith(name, "127.in-addr.arpa") > 0 && dns_name_equal(name, "2.0.0.127.in-addr.arpa") == 0) ||
                           dns_name_equal(name, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa") > 0) {

                        r = synthesize_localhost_ptr(q, q->question->keys[i], &answer);
                        if (r < 0)
                                return log_error_errno(r, "Failed to synthesize localhost PTR RRs: %m");

                } else if (dns_name_address(name, &af, &address) > 0) {

                        r = synthesize_system_hostname_ptr(q, af, &address, &answer);
                        if (r < 0)
                                return log_error_errno(r, "Failed to synthesize system hostname PTR RR: %m");

                        r = synthesize_gateway_ptr(q, af, &address, &answer);
                        if (r < 0)
                                return log_error_errno(r, "Failed to synthesize gateway hostname PTR RR: %m");
                }
        }

        if (!answer)
                return 0;

        dns_answer_unref(q->answer);
        q->answer = answer;
        answer = NULL;

        q->answer_rcode = DNS_RCODE_SUCCESS;
        q->answer_protocol = SYNTHESIZE_PROTOCOL(q->flags);
        q->answer_family = SYNTHESIZE_FAMILY(q->flags);

        *state = DNS_TRANSACTION_SUCCESS;

        return 1;
}

int dns_query_go(DnsQuery *q) {
        DnsScopeMatch found = DNS_SCOPE_NO;
        DnsScope *s, *first = NULL;
        DnsQueryCandidate *c;
        const char *name;
        int r;

        assert(q);

        if (q->state != DNS_TRANSACTION_NULL)
                return 0;

        assert(q->question);
        assert(q->question->n_keys > 0);

        name = dns_question_first_name(q->question);

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

        if (found == DNS_SCOPE_NO) {
                DnsTransactionState state = DNS_TRANSACTION_NO_SERVERS;

                dns_query_synthesize_reply(q, &state);
                dns_query_complete(q, state);
                return 1;
        }

        r = dns_query_add_candidate(q, first);
        if (r < 0)
                goto fail;

        LIST_FOREACH(scopes, s, first->scopes_next) {
                DnsScopeMatch match;

                match = dns_scope_good_domain(s, q->ifindex, q->flags, name);
                if (match < 0)
                        goto fail;

                if (match != found)
                        continue;

                r = dns_query_add_candidate(q, s);
                if (r < 0)
                        goto fail;
        }

        q->answer = dns_answer_unref(q->answer);
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

        (void) sd_event_source_set_description(q->timeout_event_source, "query-timeout");

        q->state = DNS_TRANSACTION_PENDING;
        q->block_ready++;

        /* Start the transactions */
        LIST_FOREACH(candidates_by_query, c, q->candidates) {
                r = dns_query_candidate_go(c);
                if (r < 0) {
                        q->block_ready--;
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

static void dns_query_accept(DnsQuery *q, DnsQueryCandidate *c) {
        DnsTransactionState state = DNS_TRANSACTION_NO_SERVERS;
        bool has_authenticated = false, has_non_authenticated = false;
        DnssecResult dnssec_result_authenticated = _DNSSEC_RESULT_INVALID, dnssec_result_non_authenticated = _DNSSEC_RESULT_INVALID;
        DnsTransaction *t;
        Iterator i;
        int r;

        assert(q);

        if (!c) {
                dns_query_synthesize_reply(q, &state);
                dns_query_complete(q, state);
                return;
        }

        SET_FOREACH(t, c->transactions, i) {

                switch (t->state) {

                case DNS_TRANSACTION_SUCCESS: {
                        /* We found a successfuly reply, merge it into the answer */
                        r = dns_answer_extend(&q->answer, t->answer);
                        if (r < 0) {
                                dns_query_complete(q, DNS_TRANSACTION_RESOURCES);
                                return;
                        }

                        q->answer_rcode = t->answer_rcode;

                        if (t->answer_authenticated) {
                                has_authenticated = true;
                                dnssec_result_authenticated = t->answer_dnssec_result;
                        } else {
                                has_non_authenticated = true;
                                dnssec_result_non_authenticated = t->answer_dnssec_result;
                        }

                        state = DNS_TRANSACTION_SUCCESS;
                        break;
                }

                case DNS_TRANSACTION_NULL:
                case DNS_TRANSACTION_PENDING:
                case DNS_TRANSACTION_VALIDATING:
                case DNS_TRANSACTION_ABORTED:
                        /* Ignore transactions that didn't complete */
                        continue;

                default:
                        /* Any kind of failure? Store the data away,
                         * if there's nothing stored yet. */

                        if (state == DNS_TRANSACTION_SUCCESS)
                                continue;

                        q->answer = dns_answer_unref(q->answer);
                        q->answer_rcode = t->answer_rcode;
                        q->answer_dnssec_result = t->answer_dnssec_result;

                        state = t->state;
                        break;
                }
        }

        if (state == DNS_TRANSACTION_SUCCESS) {
                q->answer_authenticated = has_authenticated && !has_non_authenticated;
                q->answer_dnssec_result = q->answer_authenticated ? dnssec_result_authenticated : dnssec_result_non_authenticated;
        }

        q->answer_protocol = c->scope->protocol;
        q->answer_family = c->scope->family;

        dns_search_domain_unref(q->answer_search_domain);
        q->answer_search_domain = dns_search_domain_ref(c->search_domain);

        dns_query_synthesize_reply(q, &state);
        dns_query_complete(q, state);
}

void dns_query_ready(DnsQuery *q) {

        DnsQueryCandidate *bad = NULL, *c;
        bool pending = false;

        assert(q);
        assert(DNS_TRANSACTION_IS_LIVE(q->state));

        /* Note that this call might invalidate the query. Callers
         * should hence not attempt to access the query or transaction
         * after calling this function, unless the block_ready
         * counter was explicitly bumped before doing so. */

        if (q->block_ready > 0)
                return;

        LIST_FOREACH(candidates_by_query, c, q->candidates) {
                DnsTransactionState state;

                state = dns_query_candidate_state(c);
                switch (state) {

                case DNS_TRANSACTION_SUCCESS:
                        /* One of the candidates is successful,
                         * let's use it, and copy its data out */
                        dns_query_accept(q, c);
                        return;

                case DNS_TRANSACTION_NULL:
                case DNS_TRANSACTION_PENDING:
                case DNS_TRANSACTION_VALIDATING:
                        /* One of the candidates is still going on,
                         * let's maybe wait for it */
                        pending = true;
                        break;

                default:
                        /* Any kind of failure */
                        bad = c;
                        break;
                }
        }

        if (pending)
                return;

        dns_query_accept(q, bad);
}

static int dns_query_cname_redirect(DnsQuery *q, const DnsResourceRecord *cname) {
        _cleanup_(dns_question_unrefp) DnsQuestion *nq = NULL;
        int r;

        assert(q);

        q->n_cname_redirects ++;
        if (q->n_cname_redirects > CNAME_MAX)
                return -ELOOP;

        r = dns_question_cname_redirect(q->question, cname, &nq);
        if (r < 0)
                return r;

        log_debug("Following CNAME/DNAME %s → %s", dns_question_first_name(q->question), dns_question_first_name(nq));

        dns_question_unref(q->question);
        q->question = nq;
        nq = NULL;

        dns_query_stop(q);
        q->state = DNS_TRANSACTION_NULL;

        return 0;
}

int dns_query_process_cname(DnsQuery *q) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL;
        DnsResourceRecord *rr;
        int r;

        assert(q);

        if (!IN_SET(q->state, DNS_TRANSACTION_SUCCESS, DNS_TRANSACTION_NULL))
                return DNS_QUERY_NOMATCH;

        DNS_ANSWER_FOREACH(rr, q->answer) {

                r = dns_question_matches_rr(q->question, rr, DNS_SEARCH_DOMAIN_NAME(q->answer_search_domain));
                if (r < 0)
                        return r;
                if (r > 0)
                        return DNS_QUERY_MATCH; /* The answer matches directly, no need to follow cnames */

                r = dns_question_matches_cname(q->question, rr, DNS_SEARCH_DOMAIN_NAME(q->answer_search_domain));
                if (r < 0)
                        return r;
                if (r > 0 && !cname)
                        cname = dns_resource_record_ref(rr);
        }

        if (!cname)
                return DNS_QUERY_NOMATCH; /* No match and no cname to follow */

        if (q->flags & SD_RESOLVED_NO_CNAME)
                return -ELOOP;

        /* OK, let's actually follow the CNAME */
        r = dns_query_cname_redirect(q, cname);
        if (r < 0)
                return r;

        /* Let's see if the answer can already answer the new
         * redirected question */
        r = dns_query_process_cname(q);
        if (r != DNS_QUERY_NOMATCH)
                return r;

        /* OK, it cannot, let's begin with the new query */
        r = dns_query_go(q);
        if (r < 0)
                return r;

        return DNS_QUERY_RESTARTED; /* We restarted the query for a new cname */
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
