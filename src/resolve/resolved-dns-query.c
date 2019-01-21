/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "dns-domain.h"
#include "dns-type.h"
#include "hostname-util.h"
#include "local-addresses.h"
#include "resolved-dns-query.h"
#include "resolved-dns-synthesize.h"
#include "resolved-etc-hosts.h"
#include "string-util.h"

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
                set_remove(t->notify_query_candidates_done, c);
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

        return mfree(c);
}

static int dns_query_candidate_next_search_domain(DnsQueryCandidate *c) {
        DnsSearchDomain *next = NULL;

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

        r = set_ensure_allocated(&t->notify_query_candidates_done, NULL);
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

        t->clamp_ttl = c->query->clamp_ttl;
        return 1;

gc:
        dns_transaction_gc(t);
        return r;
}

static int dns_query_candidate_go(DnsQueryCandidate *c) {
        DnsTransaction *t;
        Iterator i;
        int r;
        unsigned n = 0;

        assert(c);

        /* Start the transactions that are not started yet */
        SET_FOREACH(t, c->transactions, i) {
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
        Iterator i;

        assert(c);

        if (c->error_code != 0)
                return DNS_TRANSACTION_ERRNO;

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

static bool dns_query_candidate_is_routable(DnsQueryCandidate *c, uint16_t type) {
        int family;

        assert(c);

        /* Checks whether the specified RR type matches an address family that is routable on the link(s) the scope of
         * this candidate belongs to. Specifically, whether there's a routable IPv4 address on it if we query an A RR,
         * or a routable IPv6 address if we query an AAAA RR. */

        if (!c->query->suppress_unroutable_family)
                return true;

        if (c->scope->protocol != DNS_PROTOCOL_DNS)
                return true;

        family = dns_type_to_af(type);
        if (family < 0)
                return true;

        if (c->scope->link)
                return link_relevant(c->scope->link, family, false);
        else
                return manager_routable(c->scope->manager, family);
}

static int dns_query_candidate_setup_transactions(DnsQueryCandidate *c) {
        DnsQuestion *question;
        DnsResourceKey *key;
        int n = 0, r;

        assert(c);

        dns_query_candidate_stop(c);

        question = dns_query_question_for_protocol(c->query, c->scope->protocol);

        /* Create one transaction per question key */
        DNS_QUESTION_FOREACH(key, question) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *new_key = NULL;
                DnsResourceKey *qkey;

                if (!dns_query_candidate_is_routable(c, key->type))
                        continue;

                if (c->search_domain) {
                        r = dns_resource_key_new_append_suffix(&new_key, key, c->search_domain->name);
                        if (r < 0)
                                goto fail;

                        qkey = new_key;
                } else
                        qkey = key;

                if (!dns_scope_good_key(c->scope, qkey))
                        continue;

                r = dns_query_candidate_add_transaction(c, qkey);
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

static void dns_query_free_candidates(DnsQuery *q) {
        assert(q);

        while (q->candidates)
                dns_query_candidate_free(q->candidates);
}

static void dns_query_reset_answer(DnsQuery *q) {
        assert(q);

        q->answer = dns_answer_unref(q->answer);
        q->answer_rcode = 0;
        q->answer_dnssec_result = _DNSSEC_RESULT_INVALID;
        q->answer_errno = 0;
        q->answer_authenticated = false;
        q->answer_protocol = _DNS_PROTOCOL_INVALID;
        q->answer_family = AF_UNSPEC;
        q->answer_search_domain = dns_search_domain_unref(q->answer_search_domain);
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

        dns_query_free_candidates(q);

        dns_question_unref(q->question_idna);
        dns_question_unref(q->question_utf8);

        dns_query_reset_answer(q);

        sd_bus_message_unref(q->request);
        sd_bus_track_unref(q->bus_track);

        dns_packet_unref(q->request_dns_packet);
        dns_packet_unref(q->reply_dns_packet);

        if (q->request_dns_stream) {
                /* Detach the stream from our query, in case something else keeps a reference to it. */
                (void) set_remove(q->request_dns_stream->queries, q);
                q->request_dns_stream = dns_stream_unref(q->request_dns_stream);
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
                int ifindex,
                uint64_t flags) {

        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        DnsResourceKey *key;
        bool good = false;
        int r;
        char key_str[DNS_RESOURCE_KEY_STRING_MAX];

        assert(m);

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

        if (m->n_dns_queries >= QUERIES_MAX)
                return -EBUSY;

        q = new0(DnsQuery, 1);
        if (!q)
                return -ENOMEM;

        q->question_utf8 = dns_question_ref(question_utf8);
        q->question_idna = dns_question_ref(question_idna);
        q->ifindex = ifindex;
        q->flags = flags;
        q->answer_dnssec_result = _DNSSEC_RESULT_INVALID;
        q->answer_protocol = _DNS_PROTOCOL_INVALID;
        q->answer_family = AF_UNSPEC;

        /* First dump UTF8  question */
        DNS_QUESTION_FOREACH(key, question_utf8)
                log_debug("Looking up RR for %s.",
                          dns_resource_key_to_string(key, key_str, sizeof key_str));

        /* And then dump the IDNA question, but only what hasn't been dumped already through the UTF8 question. */
        DNS_QUESTION_FOREACH(key, question_idna) {
                r = dns_question_contains(question_utf8, key);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                log_debug("Looking up IDNA RR for %s.",
                          dns_resource_key_to_string(key, key_str, sizeof key_str));
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
        if ((q->flags & SD_RESOLVED_NO_SEARCH) == 0 &&
            dns_scope_name_needs_search_domain(s, dns_question_first_name(q->question_idna))) {
                /* OK, we need a search domain now. Let's find one for this scope */

                r = dns_query_candidate_next_search_domain(c);
                if (r <= 0) /* if there's no search domain, then we won't add any transaction. */
                        goto fail;
        }

        r = dns_query_candidate_setup_transactions(c);
        if (r < 0)
                goto fail;

        return 0;

fail:
        dns_query_candidate_free(c);
        return r;
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

        r = dns_synthesize_answer(
                        q->manager,
                        q->question_utf8,
                        q->ifindex,
                        &answer);
        if (r == -ENXIO) {
                /* If we get ENXIO this tells us to generate NXDOMAIN unconditionally. */

                dns_query_reset_answer(q);
                q->answer_rcode = DNS_RCODE_NXDOMAIN;
                q->answer_protocol = dns_synthesize_protocol(q->flags);
                q->answer_family = dns_synthesize_family(q->flags);
                q->answer_authenticated = true;
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
        q->answer_authenticated = true;

        *state = DNS_TRANSACTION_SUCCESS;

        return 1;
}

static int dns_query_try_etc_hosts(DnsQuery *q) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        int r;

        assert(q);

        /* Looks in /etc/hosts for matching entries. Note that this is done *before* the normal lookup is done. The
         * data from /etc/hosts hence takes precedence over the network. */

        r = manager_etc_hosts_lookup(
                        q->manager,
                        q->question_utf8,
                        &answer);
        if (r <= 0)
                return r;

        dns_query_reset_answer(q);

        q->answer = TAKE_PTR(answer);
        q->answer_rcode = DNS_RCODE_SUCCESS;
        q->answer_protocol = dns_synthesize_protocol(q->flags);
        q->answer_family = dns_synthesize_family(q->flags);
        q->answer_authenticated = true;

        return 1;
}

int dns_query_go(DnsQuery *q) {
        DnsScopeMatch found = DNS_SCOPE_NO;
        DnsScope *s, *first = NULL;
        DnsQueryCandidate *c;
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
                const char *name;

                name = dns_question_first_name(dns_query_question_for_protocol(q, s->protocol));
                if (!name)
                        continue;

                match = dns_scope_good_domain(s, q->ifindex, q->flags, name);
                if (match < 0) {
                        log_debug("Couldn't check if '%s' matches against scope, ignoring.", name);
                        continue;
                }

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
                const char *name;

                name = dns_question_first_name(dns_query_question_for_protocol(q, s->protocol));
                if (!name)
                        continue;

                match = dns_scope_good_domain(s, q->ifindex, q->flags, name);
                if (match < 0) {
                        log_debug("Couldn't check if '%s' matches against scope, ignoring.", name);
                        continue;
                }

                if (match < found)
                        continue;

                r = dns_query_add_candidate(q, s);
                if (r < 0)
                        goto fail;
        }

        dns_query_reset_answer(q);

        r = sd_event_add_time(
                        q->manager->event,
                        &q->timeout_event_source,
                        clock_boottime_or_monotonic(),
                        now(clock_boottime_or_monotonic()) + SD_RESOLVED_QUERY_TIMEOUT_USEC,
                        0, on_query_timeout, q);
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
                q->answer_authenticated = false;
                q->answer_errno = c->error_code;
        }

        SET_FOREACH(t, c->transactions, i) {

                switch (t->state) {

                case DNS_TRANSACTION_SUCCESS: {
                        /* We found a successfully reply, merge it into the answer */
                        r = dns_answer_extend(&q->answer, t->answer);
                        if (r < 0)
                                goto fail;

                        q->answer_rcode = t->answer_rcode;
                        q->answer_errno = 0;

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
                        /* Any kind of failure? Store the data away, if there's nothing stored yet. */
                        if (state == DNS_TRANSACTION_SUCCESS)
                                continue;

                        /* If there's already an authenticated negative reply stored, then prefer that over any unauthenticated one */
                        if (q->answer_authenticated && !t->answer_authenticated)
                                continue;

                        q->answer = dns_answer_unref(q->answer);
                        q->answer_rcode = t->answer_rcode;
                        q->answer_dnssec_result = t->answer_dnssec_result;
                        q->answer_authenticated = t->answer_authenticated;
                        q->answer_errno = t->answer_errno;

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
        _cleanup_(dns_question_unrefp) DnsQuestion *nq_idna = NULL, *nq_utf8 = NULL;
        int r, k;

        assert(q);

        q->n_cname_redirects++;
        if (q->n_cname_redirects > CNAME_MAX)
                return -ELOOP;

        r = dns_question_cname_redirect(q->question_idna, cname, &nq_idna);
        if (r < 0)
                return r;
        else if (r > 0)
                log_debug("Following CNAME/DNAME %s → %s.", dns_question_first_name(q->question_idna), dns_question_first_name(nq_idna));

        k = dns_question_is_equal(q->question_idna, q->question_utf8);
        if (k < 0)
                return r;
        if (k > 0) {
                /* Same question? Shortcut new question generation */
                nq_utf8 = dns_question_ref(nq_idna);
                k = r;
        } else {
                k = dns_question_cname_redirect(q->question_utf8, cname, &nq_utf8);
                if (k < 0)
                        return k;
                else if (k > 0)
                        log_debug("Following UTF8 CNAME/DNAME %s → %s.", dns_question_first_name(q->question_utf8), dns_question_first_name(nq_utf8));
        }

        if (r == 0 && k == 0) /* No actual cname happened? */
                return -ELOOP;

        if (q->answer_protocol == DNS_PROTOCOL_DNS) {
                /* Don't permit CNAME redirects from unicast DNS to LLMNR or MulticastDNS, so that global resources
                 * cannot invade the local namespace. The opposite way we permit: local names may redirect to global
                 * ones. */

                q->flags &= ~(SD_RESOLVED_LLMNR|SD_RESOLVED_MDNS); /* mask away the local protocols */
        }

        /* Turn off searching for the new name */
        q->flags |= SD_RESOLVED_NO_SEARCH;

        dns_question_unref(q->question_idna);
        q->question_idna = TAKE_PTR(nq_idna);

        dns_question_unref(q->question_utf8);
        q->question_utf8 = TAKE_PTR(nq_utf8);

        dns_query_free_candidates(q);
        dns_query_reset_answer(q);

        q->state = DNS_TRANSACTION_NULL;

        return 0;
}

int dns_query_process_cname(DnsQuery *q) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL;
        DnsQuestion *question;
        DnsResourceRecord *rr;
        int r;

        assert(q);

        if (!IN_SET(q->state, DNS_TRANSACTION_SUCCESS, DNS_TRANSACTION_NULL))
                return DNS_QUERY_NOMATCH;

        question = dns_query_question_for_protocol(q, q->answer_protocol);

        DNS_ANSWER_FOREACH(rr, q->answer) {
                r = dns_question_matches_rr(question, rr, DNS_SEARCH_DOMAIN_NAME(q->answer_search_domain));
                if (r < 0)
                        return r;
                if (r > 0)
                        return DNS_QUERY_MATCH; /* The answer matches directly, no need to follow cnames */

                r = dns_question_matches_cname_or_dname(question, rr, DNS_SEARCH_DOMAIN_NAME(q->answer_search_domain));
                if (r < 0)
                        return r;
                if (r > 0 && !cname)
                        cname = dns_resource_record_ref(rr);
        }

        if (!cname)
                return DNS_QUERY_NOMATCH; /* No match and no cname to follow */

        if (q->flags & SD_RESOLVED_NO_CNAME)
                return -ELOOP;

        if (!q->answer_authenticated)
                q->previous_redirect_unauthenticated = true;

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

DnsQuestion* dns_query_question_for_protocol(DnsQuery *q, DnsProtocol protocol) {
        assert(q);

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

        return q->answer_authenticated && !q->previous_redirect_unauthenticated;
}
