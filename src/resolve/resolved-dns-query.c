/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dns-domain.h"
#include "dns-type.h"
#include "event-util.h"
#include "glyph-util.h"
#include "hostname-util.h"
#include "local-addresses.h"
#include "resolved-dns-query.h"
#include "resolved-dns-synthesize.h"
#include "resolved-etc-hosts.h"
#include "string-util.h"

#define QUERIES_MAX 2048
#define AUXILIARY_QUERIES_MAX 64
#define CNAME_REDIRECTS_MAX 16

assert_cc(AUXILIARY_QUERIES_MAX < UINT8_MAX);
assert_cc(CNAME_REDIRECTS_MAX < UINT8_MAX);

static int dns_query_candidate_new(DnsQueryCandidate **ret, DnsQuery *q, DnsScope *s) {
        DnsQueryCandidate *c;

        assert(ret);
        assert(q);
        assert(s);

        c = new(DnsQueryCandidate, 1);
        if (!c)
                return -ENOMEM;

        *c = (DnsQueryCandidate) {
                .n_ref = 1,
                .query = q,
                .scope = s,
        };

        LIST_PREPEND(candidates_by_query, q->candidates, c);
        LIST_PREPEND(candidates_by_scope, s->query_candidates, c);

        *ret = c;
        return 0;
}

static void dns_query_candidate_stop(DnsQueryCandidate *c) {
        DnsTransaction *t;

        assert(c);

        /* Detach all the DnsTransactions attached to this query */

        while ((t = set_steal_first(c->transactions))) {
                set_remove(t->notify_query_candidates, c);
                set_remove(t->notify_query_candidates_done, c);
                dns_transaction_gc(t);
        }
}

static DnsQueryCandidate* dns_query_candidate_unlink(DnsQueryCandidate *c) {
        assert(c);

        /* Detach this DnsQueryCandidate from the Query and Scope objects */

        if (c->query) {
                LIST_REMOVE(candidates_by_query, c->query->candidates, c);
                c->query = NULL;
        }

        if (c->scope) {
                LIST_REMOVE(candidates_by_scope, c->scope->query_candidates, c);
                c->scope = NULL;
        }

        return c;
}

static DnsQueryCandidate* dns_query_candidate_free(DnsQueryCandidate *c) {
        if (!c)
                return NULL;

        dns_query_candidate_stop(c);
        dns_query_candidate_unlink(c);

        set_free(c->transactions);
        dns_search_domain_unref(c->search_domain);

        return mfree(c);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(DnsQueryCandidate, dns_query_candidate, dns_query_candidate_free);

static int dns_query_candidate_next_search_domain(DnsQueryCandidate *c) {
        DnsSearchDomain *next;

        assert(c);

        if (c->search_domain && c->search_domain->linked)
                next = c->search_domain->domains_next;
        else
                next = dns_scope_get_search_domains(c->scope);

        for (;;) {
                if (!next) /* We hit the end of the list */
                        return 0;

                if (!next->route_only)
                        break;

                /* Skip over route-only domains */
                next = next->domains_next;
        }

        dns_search_domain_unref(c->search_domain);
        c->search_domain = dns_search_domain_ref(next);

        return 1;
}

static int dns_query_candidate_add_transaction(
                DnsQueryCandidate *c,
                DnsResourceKey *key,
                DnsPacket *bypass) {

        _cleanup_(dns_transaction_gcp) DnsTransaction *t = NULL;
        int r;

        assert(c);
        assert(c->query); /* We shan't add transactions to a candidate that has been detached already */

        if (key) {
                /* Regular lookup with a resource key */
                assert(!bypass);

                t = dns_scope_find_transaction(c->scope, key, c->query->flags);
                if (!t) {
                        r = dns_transaction_new(&t, c->scope, key, NULL, c->query->flags);
                        if (r < 0)
                                return r;
                } else if (set_contains(c->transactions, t))
                        return 0;
        } else {
                /* "Bypass" lookup with a query packet */
                assert(bypass);

                r = dns_transaction_new(&t, c->scope, NULL, bypass, c->query->flags);
                if (r < 0)
                        return r;
        }

        r = set_ensure_allocated(&t->notify_query_candidates_done, NULL);
        if (r < 0)
                return r;

        r = set_ensure_put(&t->notify_query_candidates, NULL, c);
        if (r < 0)
                return r;

        r = set_ensure_put(&c->transactions, NULL, t);
        if (r < 0) {
                (void) set_remove(t->notify_query_candidates, c);
                return r;
        }

        TAKE_PTR(t);
        return 1;
}

static int dns_query_candidate_go(DnsQueryCandidate *c) {
        _unused_ _cleanup_(dns_query_candidate_unrefp) DnsQueryCandidate *keep_c = NULL;
        DnsTransaction *t;
        int r;
        unsigned n = 0;

        assert(c);

        /* Let's keep a reference to the query while we're operating */
        keep_c = dns_query_candidate_ref(c);

        /* Start the transactions that are not started yet */
        SET_FOREACH(t, c->transactions) {
                if (t->state != DNS_TRANSACTION_NULL)
                        continue;

                r = dns_transaction_go(t);
                if (r < 0)
                        return r;

                n++;
        }

        /* If there was nothing to start, then let's proceed immediately */
        if (n == 0)
                dns_query_candidate_notify(c);

        return 0;
}

static DnsTransactionState dns_query_candidate_state(DnsQueryCandidate *c) {
        DnsTransactionState state = DNS_TRANSACTION_NO_SERVERS;
        DnsTransaction *t;

        assert(c);

        if (c->error_code != 0)
                return DNS_TRANSACTION_ERRNO;

        SET_FOREACH(t, c->transactions)

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

        return state;
}

static int dns_query_candidate_setup_transactions(DnsQueryCandidate *c) {
        DnsQuestion *question;
        DnsResourceKey *key;
        int n = 0, r;

        assert(c);
        assert(c->query); /* We shan't add transactions to a candidate that has been detached already */

        dns_query_candidate_stop(c);

        if (c->query->question_bypass) {
                /* If this is a bypass query, then pass the original query packet along to the transaction */

                assert(dns_question_size(c->query->question_bypass->question) == 1);

                if (!dns_scope_good_key(c->scope, dns_question_first_key(c->query->question_bypass->question)))
                        return 0;

                r = dns_query_candidate_add_transaction(c, NULL, c->query->question_bypass);
                if (r < 0)
                        goto fail;

                return 1;
        }

        question = dns_query_question_for_protocol(c->query, c->scope->protocol);

        /* Create one transaction per question key */
        DNS_QUESTION_FOREACH(key, question) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *new_key = NULL;
                DnsResourceKey *qkey;

                if (c->search_domain) {
                        r = dns_resource_key_new_append_suffix(&new_key, key, c->search_domain->name);
                        if (r < 0)
                                goto fail;

                        qkey = new_key;
                } else
                        qkey = key;

                if (!dns_scope_good_key(c->scope, qkey))
                        continue;

                r = dns_query_candidate_add_transaction(c, qkey, NULL);
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

        if (!c->query) /* This candidate has been abandoned, do nothing. */
                return;

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
        c->error_code = log_warning_errno(r, "Failed to follow search domains: %m");
        dns_query_ready(c->query);
}

static void dns_query_stop(DnsQuery *q) {
        assert(q);

        event_source_disable(q->timeout_event_source);

        LIST_FOREACH(candidates_by_query, c, q->candidates)
                dns_query_candidate_stop(c);
}

static void dns_query_unlink_candidates(DnsQuery *q) {
        assert(q);

        while (q->candidates)
                /* Here we drop *our* references to each of the candidates. If we had the only reference, the
                 * DnsQueryCandidate object will be freed. */
                dns_query_candidate_unref(dns_query_candidate_unlink(q->candidates));
}

static void dns_query_reset_answer(DnsQuery *q) {
        assert(q);

        q->answer = dns_answer_unref(q->answer);
        q->answer_rcode = 0;
        q->answer_dnssec_result = _DNSSEC_RESULT_INVALID;
        q->answer_errno = 0;
        q->answer_query_flags = 0;
        q->answer_protocol = _DNS_PROTOCOL_INVALID;
        q->answer_family = AF_UNSPEC;
        q->answer_search_domain = dns_search_domain_unref(q->answer_search_domain);
        q->answer_full_packet = dns_packet_unref(q->answer_full_packet);
}

DnsQuery *dns_query_free(DnsQuery *q) {
        if (!q)
                return NULL;

        q->timeout_event_source = sd_event_source_disable_unref(q->timeout_event_source);

        while (q->auxiliary_queries)
                dns_query_free(q->auxiliary_queries);

        if (q->auxiliary_for) {
                assert(q->auxiliary_for->n_auxiliary_queries > 0);
                q->auxiliary_for->n_auxiliary_queries--;
                LIST_REMOVE(auxiliary_queries, q->auxiliary_for->auxiliary_queries, q);
        }

        dns_query_unlink_candidates(q);

        dns_question_unref(q->question_idna);
        dns_question_unref(q->question_utf8);
        dns_packet_unref(q->question_bypass);
        dns_question_unref(q->collected_questions);

        dns_query_reset_answer(q);

        sd_bus_message_unref(q->bus_request);
        sd_bus_track_unref(q->bus_track);

        if (q->varlink_request) {
                varlink_set_userdata(q->varlink_request, NULL);
                varlink_unref(q->varlink_request);
        }

        if (q->request_packet)
                hashmap_remove_value(q->stub_listener_extra ?
                                     q->stub_listener_extra->queries_by_packet :
                                     q->manager->stub_queries_by_packet,
                                     q->request_packet,
                                     q);

        dns_packet_unref(q->request_packet);
        dns_answer_unref(q->reply_answer);
        dns_answer_unref(q->reply_authoritative);
        dns_answer_unref(q->reply_additional);

        free(q->answer_ede_msg);

        if (q->request_stream) {
                /* Detach the stream from our query, in case something else keeps a reference to it. */
                (void) set_remove(q->request_stream->queries, q);
                q->request_stream = dns_stream_unref(q->request_stream);
        }

        free(q->request_address_string);

        if (q->manager) {
                LIST_REMOVE(queries, q->manager->dns_queries, q);
                q->manager->n_dns_queries--;
        }

        return mfree(q);
}

int dns_query_new(
                Manager *m,
                DnsQuery **ret,
                DnsQuestion *question_utf8,
                DnsQuestion *question_idna,
                DnsPacket *question_bypass,
                int ifindex,
                uint64_t flags) {

        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        char key_str[DNS_RESOURCE_KEY_STRING_MAX];
        DnsResourceKey *key;
        int r;

        assert(m);

        if (question_bypass) {
                /* It's either a "bypass" query, or a regular one, but can't be both. */
                if (question_utf8 || question_idna)
                        return -EINVAL;

        } else {
                bool good = false;

                /* This (primarily) checks two things:
                 *
                 * 1. That the question is not empty
                 * 2. That all RR keys in the question objects are for the same domain
                 *
                 * Or in other words, a single DnsQuery object may be used to look up A+AAAA combination for
                 * the same domain name, or SRV+TXT (for DNS-SD services), but not for unrelated lookups. */

                if (dns_question_size(question_utf8) > 0) {
                        r = dns_question_is_valid_for_query(question_utf8);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EINVAL;

                        good = true;
                }

                /* If the IDNA and UTF8 questions are the same, merge their references */
                r = dns_question_is_equal(question_idna, question_utf8);
                if (r < 0)
                        return r;
                if (r > 0)
                        question_idna = question_utf8;
                else {
                        if (dns_question_size(question_idna) > 0) {
                                r = dns_question_is_valid_for_query(question_idna);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        return -EINVAL;

                                good = true;
                        }
                }

                if (!good) /* don't allow empty queries */
                        return -EINVAL;
        }

        if (m->n_dns_queries >= QUERIES_MAX)
                return -EBUSY;

        q = new(DnsQuery, 1);
        if (!q)
                return -ENOMEM;

        *q = (DnsQuery) {
                .question_utf8 = dns_question_ref(question_utf8),
                .question_idna = dns_question_ref(question_idna),
                .question_bypass = dns_packet_ref(question_bypass),
                .ifindex = ifindex,
                .flags = flags,
                .answer_dnssec_result = _DNSSEC_RESULT_INVALID,
                .answer_protocol = _DNS_PROTOCOL_INVALID,
                .answer_family = AF_UNSPEC,
        };

        if (question_bypass) {
                DNS_QUESTION_FOREACH(key, question_bypass->question)
                        log_debug("Looking up bypass packet for %s.",
                                  dns_resource_key_to_string(key, key_str, sizeof key_str));
        } else {
                /* First dump UTF8 question */
                DNS_QUESTION_FOREACH(key, question_utf8)
                        log_debug("Looking up RR for %s.",
                                  dns_resource_key_to_string(key, key_str, sizeof key_str));

                /* And then dump the IDNA question, but only what hasn't been dumped already through the UTF8 question. */
                DNS_QUESTION_FOREACH(key, question_idna) {
                        r = dns_question_contains_key(question_utf8, key);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                continue;

                        log_debug("Looking up IDNA RR for %s.",
                                  dns_resource_key_to_string(key, key_str, sizeof key_str));
                }
        }

        LIST_PREPEND(queries, m->dns_queries, q);
        m->n_dns_queries++;
        q->manager = m;

        if (ret)
                *ret = q;

        TAKE_PTR(q);
        return 0;
}

int dns_query_make_auxiliary(DnsQuery *q, DnsQuery *auxiliary_for) {
        assert(q);
        assert(auxiliary_for);

        /* Ensure that the query is not auxiliary yet, and
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

void dns_query_complete(DnsQuery *q, DnsTransactionState state) {
        assert(q);
        assert(!DNS_TRANSACTION_IS_LIVE(state));
        assert(DNS_TRANSACTION_IS_LIVE(q->state));

        /* Note that this call might invalidate the query. Callers should hence not attempt to access the
         * query or transaction after calling this function. */

        q->state = state;

        (void) manager_monitor_send(q->manager, q->state, q->answer_rcode, q->answer_errno, q->question_idna, q->question_utf8, q->question_bypass, q->collected_questions, q->answer);

        dns_query_stop(q);
        if (q->complete)
                q->complete(q);
}

static int on_query_timeout(sd_event_source *s, usec_t usec, void *userdata) {
        DnsQuery *q = ASSERT_PTR(userdata);

        assert(s);

        dns_query_complete(q, DNS_TRANSACTION_TIMEOUT);
        return 0;
}

static int dns_query_add_candidate(DnsQuery *q, DnsScope *s) {
        _cleanup_(dns_query_candidate_unrefp) DnsQueryCandidate *c = NULL;
        int r;

        assert(q);
        assert(s);

        r = dns_query_candidate_new(&c, q, s);
        if (r < 0)
                return r;

        /* If this a single-label domain on DNS, we might append a suitable search domain first. */
        if (!FLAGS_SET(q->flags, SD_RESOLVED_NO_SEARCH) &&
            dns_scope_name_wants_search_domain(s, dns_question_first_name(q->question_idna))) {
                /* OK, we want a search domain now. Let's find one for this scope */

                r = dns_query_candidate_next_search_domain(c);
                if (r < 0)
                        return r;
        }

        r = dns_query_candidate_setup_transactions(c);
        if (r < 0)
                return r;

        TAKE_PTR(c);
        return 0;
}

static int dns_query_synthesize_reply(DnsQuery *q, DnsTransactionState *state) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        int r;

        assert(q);
        assert(state);

        /* Tries to synthesize localhost RR replies (and others) where appropriate. Note that this is done *after* the
         * the normal lookup finished. The data from the network hence takes precedence over the data we
         * synthesize. (But note that many scopes refuse to resolve certain domain names) */

        if (!IN_SET(*state,
                    DNS_TRANSACTION_RCODE_FAILURE,
                    DNS_TRANSACTION_NO_SERVERS,
                    DNS_TRANSACTION_TIMEOUT,
                    DNS_TRANSACTION_ATTEMPTS_MAX_REACHED,
                    DNS_TRANSACTION_NETWORK_DOWN,
                    DNS_TRANSACTION_NOT_FOUND))
                return 0;

        if (FLAGS_SET(q->flags, SD_RESOLVED_NO_SYNTHESIZE))
                return 0;

        r = dns_synthesize_answer(
                        q->manager,
                        q->question_bypass ? q->question_bypass->question : q->question_utf8,
                        q->ifindex,
                        &answer);
        if (r == -ENXIO) {
                /* If we get ENXIO this tells us to generate NXDOMAIN unconditionally. */

                dns_query_reset_answer(q);
                q->answer_rcode = DNS_RCODE_NXDOMAIN;
                q->answer_protocol = dns_synthesize_protocol(q->flags);
                q->answer_family = dns_synthesize_family(q->flags);
                q->answer_query_flags = SD_RESOLVED_AUTHENTICATED|SD_RESOLVED_CONFIDENTIAL|SD_RESOLVED_SYNTHETIC;
                *state = DNS_TRANSACTION_RCODE_FAILURE;

                return 0;
        }
        if (r <= 0)
                return r;

        dns_query_reset_answer(q);

        q->answer = TAKE_PTR(answer);
        q->answer_rcode = DNS_RCODE_SUCCESS;
        q->answer_protocol = dns_synthesize_protocol(q->flags);
        q->answer_family = dns_synthesize_family(q->flags);
        q->answer_query_flags = SD_RESOLVED_AUTHENTICATED|SD_RESOLVED_CONFIDENTIAL|SD_RESOLVED_SYNTHETIC;

        *state = DNS_TRANSACTION_SUCCESS;

        return 1;
}

static int dns_query_try_etc_hosts(DnsQuery *q) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        int r;

        assert(q);

        /* Looks in /etc/hosts for matching entries. Note that this is done *before* the normal lookup is
         * done. The data from /etc/hosts hence takes precedence over the network. */

        if (FLAGS_SET(q->flags, SD_RESOLVED_NO_SYNTHESIZE))
                return 0;

        r = manager_etc_hosts_lookup(
                        q->manager,
                        q->question_bypass ? q->question_bypass->question : q->question_utf8,
                        &answer);
        if (r <= 0)
                return r;

        dns_query_reset_answer(q);

        q->answer = TAKE_PTR(answer);
        q->answer_rcode = DNS_RCODE_SUCCESS;
        q->answer_protocol = dns_synthesize_protocol(q->flags);
        q->answer_family = dns_synthesize_family(q->flags);
        q->answer_query_flags = SD_RESOLVED_AUTHENTICATED|SD_RESOLVED_CONFIDENTIAL|SD_RESOLVED_SYNTHETIC;

        return 1;
}

int dns_query_go(DnsQuery *q) {
        DnsScopeMatch found = DNS_SCOPE_NO;
        DnsScope *first = NULL;
        int r;

        assert(q);

        if (q->state != DNS_TRANSACTION_NULL)
                return 0;

        r = dns_query_try_etc_hosts(q);
        if (r < 0)
                return r;
        if (r > 0) {
                dns_query_complete(q, DNS_TRANSACTION_SUCCESS);
                return 1;
        }

        LIST_FOREACH(scopes, s, q->manager->dns_scopes) {
                DnsScopeMatch match;

                match = dns_scope_good_domain(s, q);
                assert(match >= 0);
                if (match > found) { /* Does this match better? If so, remember how well it matched, and the first one
                                      * that matches this well */
                        found = match;
                        first = s;
                }
        }

        if (found == DNS_SCOPE_NO) {
                DnsTransactionState state = DNS_TRANSACTION_NO_SERVERS;

                r = dns_query_synthesize_reply(q, &state);
                if (r < 0)
                        return r;

                dns_query_complete(q, state);
                return 1;
        }

        r = dns_query_add_candidate(q, first);
        if (r < 0)
                goto fail;

        LIST_FOREACH(scopes, s, first->scopes_next) {
                DnsScopeMatch match;

                match = dns_scope_good_domain(s, q);
                assert(match >= 0);
                if (match < found)
                        continue;

                r = dns_query_add_candidate(q, s);
                if (r < 0)
                        goto fail;
        }

        dns_query_reset_answer(q);

        r = event_reset_time_relative(
                        q->manager->event,
                        &q->timeout_event_source,
                        CLOCK_BOOTTIME,
                        SD_RESOLVED_QUERY_TIMEOUT_USEC,
                        0, on_query_timeout, q,
                        0, "query-timeout", true);
        if (r < 0)
                goto fail;

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
        bool has_authenticated = false, has_non_authenticated = false, has_confidential = false, has_non_confidential = false;
        DnssecResult dnssec_result_authenticated = _DNSSEC_RESULT_INVALID, dnssec_result_non_authenticated = _DNSSEC_RESULT_INVALID;
        DnsTransaction *t;
        int r;

        assert(q);

        if (!c) {
                r = dns_query_synthesize_reply(q, &state);
                if (r < 0)
                        goto fail;

                dns_query_complete(q, state);
                return;
        }

        if (c->error_code != 0) {
                /* If the candidate had an error condition of its own, start with that. */
                state = DNS_TRANSACTION_ERRNO;
                q->answer = dns_answer_unref(q->answer);
                q->answer_rcode = 0;
                q->answer_dnssec_result = _DNSSEC_RESULT_INVALID;
                q->answer_query_flags = 0;
                q->answer_errno = c->error_code;
                q->answer_full_packet = dns_packet_unref(q->answer_full_packet);
        }

        SET_FOREACH(t, c->transactions) {

                switch (t->state) {

                case DNS_TRANSACTION_SUCCESS: {
                        /* We found a successful reply, merge it into the answer */

                        if (state == DNS_TRANSACTION_SUCCESS) {
                                r = dns_answer_extend(&q->answer, t->answer);
                                if (r < 0)
                                        goto fail;

                                q->answer_query_flags |= dns_transaction_source_to_query_flags(t->answer_source);
                        } else {
                                /* Override non-successful previous answers */
                                DNS_ANSWER_REPLACE(q->answer, dns_answer_ref(t->answer));
                                q->answer_query_flags = dns_transaction_source_to_query_flags(t->answer_source);
                        }

                        q->answer_rcode = t->answer_rcode;
                        q->answer_errno = 0;

                        DNS_PACKET_REPLACE(q->answer_full_packet, dns_packet_ref(t->received));

                        if (FLAGS_SET(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED)) {
                                has_authenticated = true;
                                dnssec_result_authenticated = t->answer_dnssec_result;
                        } else {
                                has_non_authenticated = true;
                                dnssec_result_non_authenticated = t->answer_dnssec_result;
                        }

                        if (FLAGS_SET(t->answer_query_flags, SD_RESOLVED_CONFIDENTIAL))
                                has_confidential = true;
                        else
                                has_non_confidential = true;

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
                        /* Any kind of failure? Store the data away, if there's nothing stored yet. */
                        if (state == DNS_TRANSACTION_SUCCESS)
                                continue;

                        /* If there's already an authenticated negative reply stored, then prefer that over any unauthenticated one */
                        if (FLAGS_SET(q->answer_query_flags, SD_RESOLVED_AUTHENTICATED) &&
                            !FLAGS_SET(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED))
                                continue;

                        DNS_ANSWER_REPLACE(q->answer, dns_answer_ref(t->answer));
                        q->answer_rcode = t->answer_rcode;
                        q->answer_dnssec_result = t->answer_dnssec_result;
                        q->answer_ede_rcode = t->answer_ede_rcode;
                        q->answer_ede_msg = t->answer_ede_msg ? strdup(t->answer_ede_msg) : NULL;
                        q->answer_query_flags = t->answer_query_flags | dns_transaction_source_to_query_flags(t->answer_source);
                        q->answer_errno = t->answer_errno;
                        DNS_PACKET_REPLACE(q->answer_full_packet, dns_packet_ref(t->received));

                        state = t->state;
                        break;
                }
        }

        if (state == DNS_TRANSACTION_SUCCESS) {
                SET_FLAG(q->answer_query_flags, SD_RESOLVED_AUTHENTICATED, has_authenticated && !has_non_authenticated);
                SET_FLAG(q->answer_query_flags, SD_RESOLVED_CONFIDENTIAL, has_confidential && !has_non_confidential);
                q->answer_dnssec_result = FLAGS_SET(q->answer_query_flags, SD_RESOLVED_AUTHENTICATED) ? dnssec_result_authenticated : dnssec_result_non_authenticated;
        }

        q->answer_protocol = c->scope->protocol;
        q->answer_family = c->scope->family;

        dns_search_domain_unref(q->answer_search_domain);
        q->answer_search_domain = dns_search_domain_ref(c->search_domain);

        r = dns_query_synthesize_reply(q, &state);
        if (r < 0)
                goto fail;

        dns_query_complete(q, state);
        return;

fail:
        q->answer_errno = -r;
        dns_query_complete(q, DNS_TRANSACTION_ERRNO);
}

void dns_query_ready(DnsQuery *q) {
        DnsQueryCandidate *bad = NULL;
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

static int dns_query_collect_question(DnsQuery *q, DnsQuestion *question) {
        _cleanup_(dns_question_unrefp) DnsQuestion *merged = NULL;
        int r;

        assert(q);

        if (dns_question_size(question) == 0)
                return 0;

        /* When redirecting, save the first element in the chain, for informational purposes when monitoring */
        r = dns_question_merge(q->collected_questions, question, &merged);
        if (r < 0)
                return r;

        dns_question_unref(q->collected_questions);
        q->collected_questions = TAKE_PTR(merged);

        return 0;
}

static int dns_query_cname_redirect(DnsQuery *q, const DnsResourceRecord *cname) {
        _cleanup_(dns_question_unrefp) DnsQuestion *nq_idna = NULL, *nq_utf8 = NULL;
        int r, k;

        assert(q);

        if (q->n_cname_redirects >= CNAME_REDIRECTS_MAX)
                return -ELOOP;
        q->n_cname_redirects++;

        r = dns_question_cname_redirect(q->question_idna, cname, &nq_idna);
        if (r < 0)
                return r;
        if (r > 0)
                log_debug("Following CNAME/DNAME %s %s %s.",
                          dns_question_first_name(q->question_idna),
                          special_glyph(SPECIAL_GLYPH_ARROW_RIGHT),
                          dns_question_first_name(nq_idna));

        k = dns_question_is_equal(q->question_idna, q->question_utf8);
        if (k < 0)
                return k;
        if (k > 0) {
                /* Same question? Shortcut new question generation */
                nq_utf8 = dns_question_ref(nq_idna);
                k = r;
        } else {
                k = dns_question_cname_redirect(q->question_utf8, cname, &nq_utf8);
                if (k < 0)
                        return k;
                if (k > 0)
                        log_debug("Following UTF8 CNAME/DNAME %s %s %s.",
                                  dns_question_first_name(q->question_utf8),
                                  special_glyph(SPECIAL_GLYPH_ARROW_RIGHT),
                                  dns_question_first_name(nq_utf8));
        }

        if (r == 0 && k == 0) /* No actual cname happened? */
                return -ELOOP;

        if (q->answer_protocol == DNS_PROTOCOL_DNS)
                /* Don't permit CNAME redirects from unicast DNS to LLMNR or MulticastDNS, so that global resources
                 * cannot invade the local namespace. The opposite way we permit: local names may redirect to global
                 * ones. */
                q->flags &= ~(SD_RESOLVED_LLMNR|SD_RESOLVED_MDNS); /* mask away the local protocols */

        /* Turn off searching for the new name */
        q->flags |= SD_RESOLVED_NO_SEARCH;

        r = dns_query_collect_question(q, q->question_idna);
        if (r < 0)
                return r;
        r = dns_query_collect_question(q, q->question_utf8);
        if (r < 0)
                return r;

        /* Install the redirected question */
        dns_question_unref(q->question_idna);
        q->question_idna = TAKE_PTR(nq_idna);

        dns_question_unref(q->question_utf8);
        q->question_utf8 = TAKE_PTR(nq_utf8);

        dns_query_unlink_candidates(q);

        /* Note that we do *not* reset the answer here, because the answer we previously got might already
         * include everything we need, let's check that first */

        q->state = DNS_TRANSACTION_NULL;

        return 0;
}

int dns_query_process_cname_one(DnsQuery *q) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL;
        DnsQuestion *question;
        DnsResourceRecord *rr;
        bool full_match = true;
        DnsResourceKey *k;
        int r;

        assert(q);

        /* Processes a CNAME redirect if there's one. Returns one of three values:
         *
         * CNAME_QUERY_MATCH   → direct RR match, caller should just use the RRs in this answer (and not
         *                       bother with any CNAME/DNAME stuff)
         *
         * CNAME_QUERY_NOMATCH → no match at all, neither direct nor CNAME/DNAME, caller might decide to
         *                       restart query or take things as NODATA reply.
         *
         * CNAME_QUERY_CNAME   → no direct RR match, but a CNAME/DNAME match that we now followed for one step.
         *
         * The function might also return a failure, in particular -ELOOP if we encountered too many
         * CNAMEs/DNAMEs in a chain or if following CNAMEs/DNAMEs was turned off.
         *
         * Note that this function doesn't actually restart the query. The caller can decide to do that in
         * case of CNAME_QUERY_CNAME, though. */

        if (!IN_SET(q->state, DNS_TRANSACTION_SUCCESS, DNS_TRANSACTION_NULL))
                return DNS_QUERY_NOMATCH;

        question = dns_query_question_for_protocol(q, q->answer_protocol);

        /* Small reminder: our question will consist of one or more RR keys that match in name, but not in
         * record type. Specifically, when we do an address lookup the question will typically consist of one
         * A and one AAAA key lookup for the same domain name. When we get a response from a server we need
         * to check if the answer answers all our questions to use it. Note that a response of CNAME/DNAME
         * can answer both an A and the AAAA question for us, but an A/AAAA response only the relevant
         * type.
         *
         * Hence we first check of the answers we collected are sufficient to answer all our questions
         * directly. If one question wasn't answered we go on, waiting for more replies. However, if there's
         * a CNAME/DNAME response we use it, and redirect to it, regardless if it was a response to the A or
         * the AAAA query. */

        DNS_QUESTION_FOREACH(k, question) {
                bool match = false;

                DNS_ANSWER_FOREACH(rr, q->answer) {
                        r = dns_resource_key_match_rr(k, rr, DNS_SEARCH_DOMAIN_NAME(q->answer_search_domain));
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                match = true; /* Yay, we found an RR that matches the key we are looking for */
                                break;
                        }
                }

                if (!match) {
                        /* Hmm. :-( there's no response for this key. This doesn't match. */
                        full_match = false;
                        break;
                }
        }

        if (full_match)
                return DNS_QUERY_MATCH; /* The answer can answer our question in full, no need to follow CNAMEs/DNAMEs */

        /* Let's see if there is a CNAME/DNAME to match. This case is simpler: we accept the CNAME/DNAME that
         * matches any of our questions. */
        DNS_ANSWER_FOREACH(rr, q->answer) {
                r = dns_question_matches_cname_or_dname(question, rr, DNS_SEARCH_DOMAIN_NAME(q->answer_search_domain));
                if (r < 0)
                        return r;
                if (r > 0 && !cname)
                        cname = dns_resource_record_ref(rr);
        }

        if (!cname)
                return DNS_QUERY_NOMATCH; /* No match and no CNAME/DNAME to follow */

        if (q->flags & SD_RESOLVED_NO_CNAME)
                return -ELOOP;

        if (!FLAGS_SET(q->answer_query_flags, SD_RESOLVED_AUTHENTICATED))
                q->previous_redirect_unauthenticated = true;
        if (!FLAGS_SET(q->answer_query_flags, SD_RESOLVED_CONFIDENTIAL))
                q->previous_redirect_non_confidential = true;
        if (!FLAGS_SET(q->answer_query_flags, SD_RESOLVED_SYNTHETIC))
                q->previous_redirect_non_synthetic = true;

        /* OK, let's actually follow the CNAME */
        r = dns_query_cname_redirect(q, cname);
        if (r < 0)
                return r;

        return DNS_QUERY_CNAME; /* Tell caller that we did a single CNAME/DNAME redirection step */
}

int dns_query_process_cname_many(DnsQuery *q) {
        int r;

        assert(q);

        /* Follows CNAMEs through the current packet: as long as the current packet can fulfill our
         * redirected CNAME queries we keep going, and restart the query once the current packet isn't good
         * enough anymore. It's a wrapper around dns_query_process_cname_one() and returns the same values,
         * but with extended semantics. Specifically:
         *
         * DNS_QUERY_MATCH   → as above
         *
         * DNS_QUERY_CNAME   → we ran into a CNAME/DNAME redirect that we could not answer from the current
         *                     message, and thus restarted the query to resolve it.
         *
         * DNS_QUERY_NOMATCH → we reached the end of CNAME/DNAME chain, and there are no direct matches nor a
         *                     CNAME/DNAME match. i.e. this is a NODATA case.
         *
         * Note that this function will restart the query for the caller if needed, and that's the case
         * DNS_QUERY_CNAME is returned.
         */

        r = dns_query_process_cname_one(q);
        if (r != DNS_QUERY_CNAME)
                return r; /* The first redirect is special: if it doesn't answer the question that's no
                           * reason to restart the query, we just accept this as a NODATA answer. */

        for (;;) {
                r = dns_query_process_cname_one(q);
                if (r < 0 || r == DNS_QUERY_MATCH)
                        return r;
                if (r == DNS_QUERY_NOMATCH) {
                        /* OK, so we followed one or more CNAME/DNAME RR but the existing packet can't answer
                         * this. Let's restart the query hence, with the new question. Why the different
                         * handling than the first chain element? Because if the server answers a direct
                         * question with an empty answer then this is a NODATA response. But if it responds
                         * with a CNAME chain that ultimately is incomplete (i.e. a non-empty but truncated
                         * CNAME chain) then we better follow up ourselves and ask for the rest of the
                         * chain. This is particular relevant since our cache will store CNAME/DNAME
                         * redirects that we learnt about for lookups of certain DNS types, but later on we
                         * can reuse this data even for other DNS types, but in that case need to follow up
                         * with the final lookup of the chain ourselves with the RR type we ourselves are
                         * interested in. */
                        r = dns_query_go(q);
                        if (r < 0)
                                return r;

                        return DNS_QUERY_CNAME;
                }

                /* So we found a CNAME that the existing packet already answers, again via a CNAME, let's
                 * continue going then. */
                assert(r == DNS_QUERY_CNAME);
        }
}

DnsQuestion* dns_query_question_for_protocol(DnsQuery *q, DnsProtocol protocol) {
        assert(q);

        if (q->question_bypass)
                return q->question_bypass->question;

        switch (protocol) {

        case DNS_PROTOCOL_DNS:
                return q->question_idna;

        case DNS_PROTOCOL_MDNS:
        case DNS_PROTOCOL_LLMNR:
                return q->question_utf8;

        default:
                return NULL;
        }
}

const char *dns_query_string(DnsQuery *q) {
        const char *name;
        int r;

        /* Returns a somewhat useful human-readable lookup key string for this query */

        if (q->question_bypass)
                return dns_question_first_name(q->question_bypass->question);

        if (q->request_address_string)
                return q->request_address_string;

        if (q->request_address_valid) {
                r = in_addr_to_string(q->request_family, &q->request_address, &q->request_address_string);
                if (r >= 0)
                        return q->request_address_string;
        }

        name = dns_question_first_name(q->question_utf8);
        if (name)
                return name;

        return dns_question_first_name(q->question_idna);
}

bool dns_query_fully_authenticated(DnsQuery *q) {
        assert(q);

        return FLAGS_SET(q->answer_query_flags, SD_RESOLVED_AUTHENTICATED) && !q->previous_redirect_unauthenticated;
}

bool dns_query_fully_confidential(DnsQuery *q) {
        assert(q);

        return FLAGS_SET(q->answer_query_flags, SD_RESOLVED_CONFIDENTIAL) && !q->previous_redirect_non_confidential;
}

bool dns_query_fully_authoritative(DnsQuery *q) {
        assert(q);

        /* We are authoritative for everything synthetic (except if a previous CNAME/DNAME) wasn't
         * synthetic. (Note: SD_RESOLVED_SYNTHETIC is reset on each CNAME/DNAME, hence the explicit check for
         * previous synthetic DNAME/CNAME redirections.) */
        if ((q->answer_query_flags & SD_RESOLVED_SYNTHETIC) && !q->previous_redirect_non_synthetic)
                return true;

        /* We are also authoritative for everything coming only from the trust anchor and the local
         * zones. (Note: the SD_RESOLVED_FROM_xyz flags we merge on each redirect, hence no need to
         * explicitly check previous redirects here.) */
        return (q->answer_query_flags & SD_RESOLVED_FROM_MASK & ~(SD_RESOLVED_FROM_TRUST_ANCHOR | SD_RESOLVED_FROM_ZONE)) == 0;
}
