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

        sd_event_source_unref(t->tcp_event_source);
        safe_close(t->tcp_fd);

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

        t->tcp_fd = -1;
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
        t->tcp_event_source = sd_event_source_unref(t->tcp_event_source);
        t->tcp_fd = safe_close(t->tcp_fd);
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

static int on_tcp_ready(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        DnsQueryTransaction *t = userdata;
        int r;

        assert(t);

        if (revents & EPOLLOUT) {
                struct iovec iov[2];
                be16_t sz;
                ssize_t ss;

                sz = htobe16(t->sent->size);

                iov[0].iov_base = &sz;
                iov[0].iov_len = sizeof(sz);
                iov[1].iov_base = DNS_PACKET_DATA(t->sent);
                iov[1].iov_len = t->sent->size;

                IOVEC_INCREMENT(iov, 2, t->tcp_written);

                ss = writev(fd, iov, 2);
                if (ss < 0) {
                        if (errno != EINTR && errno != EAGAIN) {
                                dns_query_transaction_complete(t, DNS_QUERY_RESOURCES);
                                return -errno;
                        }
                } else
                        t->tcp_written += ss;

                /* Are we done? If so, disable the event source for EPOLLOUT */
                if (t->tcp_written >= sizeof(sz) + t->sent->size) {
                        r = sd_event_source_set_io_events(s, EPOLLIN);
                        if (r < 0) {
                                dns_query_transaction_complete(t, DNS_QUERY_RESOURCES);
                                return r;
                        }
                }
        }

        if (revents & (EPOLLIN|EPOLLHUP|EPOLLRDHUP)) {

                if (t->tcp_read < sizeof(t->tcp_read_size)) {
                        ssize_t ss;

                        ss = read(fd, (uint8_t*) &t->tcp_read_size + t->tcp_read, sizeof(t->tcp_read_size) - t->tcp_read);
                        if (ss < 0) {
                                if (errno != EINTR && errno != EAGAIN) {
                                        dns_query_transaction_complete(t, DNS_QUERY_RESOURCES);
                                        return -errno;
                                }
                        } else if (ss == 0) {
                                dns_query_transaction_complete(t, DNS_QUERY_RESOURCES);
                                return -EIO;
                        } else
                                t->tcp_read += ss;
                }

                if (t->tcp_read >= sizeof(t->tcp_read_size)) {

                        if (be16toh(t->tcp_read_size) < DNS_PACKET_HEADER_SIZE) {
                                dns_query_transaction_complete(t, DNS_QUERY_INVALID_REPLY);
                                return -EBADMSG;
                        }

                        if (t->tcp_read < sizeof(t->tcp_read_size) + be16toh(t->tcp_read_size)) {
                                ssize_t ss;

                                if (!t->received) {
                                        r = dns_packet_new(&t->received, t->scope->protocol, be16toh(t->tcp_read_size));
                                        if (r < 0) {
                                                dns_query_transaction_complete(t, DNS_QUERY_RESOURCES);
                                                return r;
                                        }
                                }

                                ss = read(fd,
                                          (uint8_t*) DNS_PACKET_DATA(t->received) + t->tcp_read - sizeof(t->tcp_read_size),
                                          sizeof(t->tcp_read_size) + be16toh(t->tcp_read_size) - t->tcp_read);
                                if (ss < 0) {
                                        if (errno != EINTR && errno != EAGAIN) {
                                                dns_query_transaction_complete(t, DNS_QUERY_RESOURCES);
                                                return -errno;
                                        }
                                } else if (ss == 0) {
                                        dns_query_transaction_complete(t, DNS_QUERY_RESOURCES);
                                        return -EIO;
                                }  else
                                        t->tcp_read += ss;
                        }

                        if (t->tcp_read >= sizeof(t->tcp_read_size) + be16toh(t->tcp_read_size)) {
                                t->received->size = be16toh(t->tcp_read_size);
                                dns_query_transaction_process_reply(t, t->received);
                                return 0;
                        }
                }
        }

        return 0;
}

static int dns_query_transaction_open_tcp(DnsQueryTransaction *t) {
        int r;

        assert(t);

        if (t->scope->protocol == DNS_PROTOCOL_DNS)
                return -ENOTSUP;

        if (t->tcp_fd >= 0)
                return 0;

        t->tcp_written = 0;
        t->tcp_read = 0;
        t->received = dns_packet_unref(t->received);

        t->tcp_fd = dns_scope_tcp_socket(t->scope);
        if (t->tcp_fd < 0)
                return t->tcp_fd;

        r = sd_event_add_io(t->scope->manager->event, &t->tcp_event_source, t->tcp_fd, EPOLLIN|EPOLLOUT, on_tcp_ready, t);
        if (r < 0) {
                t->tcp_fd = safe_close(t->tcp_fd);
                return r;
        }

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

        if (t->received != p) {
                dns_packet_unref(t->received);
                t->received = dns_packet_ref(p);
        }

        if (t->tcp_fd >= 0) {
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
                        /* Couldn't send? Try immediately again, with a new server */
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
        } else
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

        /* Try via UDP, and if that fails due to large size try via TCP */
        r = dns_scope_send(t->scope, t->sent);
        if (r == -EMSGSIZE)
                r = dns_query_transaction_open_tcp(t);
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

static int dns_query_add_transaction(DnsQuery *q, DnsScope *s) {
        DnsQueryTransaction *t;
        int r;

        assert(q);

        r = set_ensure_allocated(&q->transactions, NULL, NULL);
        if (r < 0)
                return r;

        LIST_FOREACH(transactions_by_scope, t, s->transactions)
                if (dns_question_is_superset(t->question, q->question))
                        break;

        if (!t) {
                r = dns_query_transaction_new(&t, s, q->question);
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

        r = dns_query_add_transaction(q, first);
        if (r < 0)
                return r;

        LIST_FOREACH(scopes, s, first->scopes_next) {
                DnsScopeMatch match;

                match = dns_scope_good_domain(s, name);
                if (match < 0)
                        return match;

                if (match != found)
                        continue;

                r = dns_query_add_transaction(q, s);
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
        DnsAnswer *failure_answer = NULL;
        int failure_rcode = 0, failure_ifindex = 0;
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

                /* One of the transactions is still going on, let's wait for it */
                if (t->state == DNS_QUERY_PENDING || t->state == DNS_QUERY_NULL)
                        return;

                /* One of the transactions is successful, let's use
                 * it, and copy its data out */
                if (t->state == DNS_QUERY_SUCCESS) {
                        if (t->received) {
                                q->answer = dns_answer_ref(t->received->answer);
                                q->answer_ifindex = t->received->ifindex;
                                q->answer_rcode = DNS_PACKET_RCODE(t->received);
                        } else {
                                q->answer = dns_answer_ref(t->cached);
                                q->answer_ifindex = t->scope->link ? t->scope->link->ifindex : 0;
                                q->answer_rcode = t->cached_rcode;
                        }

                        dns_query_complete(q, DNS_QUERY_SUCCESS);
                        return;
                }

                /* One of the transactions has failed, let's see
                 * whether we find anything better, but if not, return
                 * its response packet */
                if (t->state == DNS_QUERY_FAILURE) {
                        if (t->received) {
                                failure_answer = t->received->answer;
                                failure_ifindex = t->received->ifindex;
                                failure_rcode = DNS_PACKET_RCODE(t->received);
                        } else {
                                failure_answer = t->cached;
                                failure_ifindex = t->scope->link ? t->scope->link->ifindex : 0;
                                failure_rcode = t->cached_rcode;
                        }

                        state = DNS_QUERY_FAILURE;
                        continue;
                }

                if (state == DNS_QUERY_NO_SERVERS && t->state != DNS_QUERY_NO_SERVERS)
                        state = t->state;
        }

        if (state == DNS_QUERY_FAILURE) {
                q->answer = dns_answer_ref(failure_answer);
                q->answer_ifindex = failure_ifindex;
                q->answer_rcode = failure_rcode;
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
