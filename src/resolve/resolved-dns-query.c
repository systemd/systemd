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

static int dns_query_transaction_start(DnsQueryTransaction *t);

DnsQueryTransaction* dns_query_transaction_free(DnsQueryTransaction *t) {
        if (!t)
                return NULL;

        sd_event_source_unref(t->timeout_event_source);

        dns_packet_unref(t->sent);
        dns_packet_unref(t->received);

        sd_event_source_unref(t->tcp_event_source);
        safe_close(t->tcp_fd);

        if (t->query) {
                LIST_REMOVE(transactions_by_query, t->query->transactions, t);
                hashmap_remove(t->query->manager->dns_query_transactions, UINT_TO_PTR(t->id));
        }

        if (t->scope)
                LIST_REMOVE(transactions_by_scope, t->scope->transactions, t);

        free(t);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsQueryTransaction*, dns_query_transaction_free);

static int dns_query_transaction_new(DnsQuery *q, DnsQueryTransaction **ret, DnsScope *s) {
        _cleanup_(dns_query_transaction_freep) DnsQueryTransaction *t = NULL;
        int r;

        assert(q);
        assert(s);

        r = hashmap_ensure_allocated(&q->manager->dns_query_transactions, NULL, NULL);
        if (r < 0)
                return r;

        t = new0(DnsQueryTransaction, 1);
        if (!t)
                return -ENOMEM;

        t->tcp_fd = -1;

        do
                random_bytes(&t->id, sizeof(t->id));
        while (t->id == 0 ||
               hashmap_get(q->manager->dns_query_transactions, UINT_TO_PTR(t->id)));

        r = hashmap_put(q->manager->dns_query_transactions, UINT_TO_PTR(t->id), t);
        if (r < 0) {
                t->id = 0;
                return r;
        }

        LIST_PREPEND(transactions_by_query, q->transactions, t);
        t->query = q;

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

static void dns_query_transaction_set_state(DnsQueryTransaction *t, DnsQueryState state) {
        assert(t);

        if (t->state == state)
                return;

        t->state = state;

        if (state != DNS_QUERY_PENDING) {
                dns_query_transaction_stop(t);
                dns_query_finish(t->query);
        }
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
                                dns_query_transaction_set_state(t, DNS_QUERY_RESOURCES);
                                return -errno;
                        }
                } else
                        t->tcp_written += ss;

                /* Are we done? If so, disable the event source for EPOLLOUT */
                if (t->tcp_written >= sizeof(sz) + t->sent->size) {
                        r = sd_event_source_set_io_events(s, EPOLLIN);
                        if (r < 0) {
                                dns_query_transaction_set_state(t, DNS_QUERY_RESOURCES);
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
                                        dns_query_transaction_set_state(t, DNS_QUERY_RESOURCES);
                                        return -errno;
                                }
                        } else if (ss == 0) {
                                dns_query_transaction_set_state(t, DNS_QUERY_RESOURCES);
                                return -EIO;
                        } else
                                t->tcp_read += ss;
                }

                if (t->tcp_read >= sizeof(t->tcp_read_size)) {

                        if (be16toh(t->tcp_read_size) < DNS_PACKET_HEADER_SIZE) {
                                dns_query_transaction_set_state(t, DNS_QUERY_INVALID_REPLY);
                                return -EBADMSG;
                        }

                        if (t->tcp_read < sizeof(t->tcp_read_size) + be16toh(t->tcp_read_size)) {
                                ssize_t ss;

                                if (!t->received) {
                                        r = dns_packet_new(&t->received, be16toh(t->tcp_read_size));
                                        if (r < 0) {
                                                dns_query_transaction_set_state(t, DNS_QUERY_RESOURCES);
                                                return r;
                                        }
                                }

                                ss = read(fd,
                                          (uint8_t*) DNS_PACKET_DATA(t->received) + t->tcp_read - sizeof(t->tcp_read_size),
                                          sizeof(t->tcp_read_size) + be16toh(t->tcp_read_size) - t->tcp_read);
                                if (ss < 0) {
                                        if (errno != EINTR && errno != EAGAIN) {
                                                dns_query_transaction_set_state(t, DNS_QUERY_RESOURCES);
                                                return -errno;
                                        }
                                } else if (ss == 0) {
                                        dns_query_transaction_set_state(t, DNS_QUERY_RESOURCES);
                                        return -EIO;
                                }  else
                                        t->tcp_read += ss;
                        }

                        if (t->tcp_read >= sizeof(t->tcp_read_size) + be16toh(t->tcp_read_size)) {
                                t->received->size = be16toh(t->tcp_read_size);
                                dns_query_transaction_reply(t, t->received);
                                return 0;
                        }
                }
        }

        return 0;
}

static int dns_query_transaction_start_tcp(DnsQueryTransaction *t) {
        int r;

        assert(t);

        if (t->tcp_fd >= 0)
                return 0;

        t->tcp_written = 0;
        t->tcp_read = 0;
        t->received = dns_packet_unref(t->received);

        t->tcp_fd = dns_scope_tcp_socket(t->scope);
        if (t->tcp_fd < 0)
                return t->tcp_fd;

        r = sd_event_add_io(t->query->manager->event, &t->tcp_event_source, t->tcp_fd, EPOLLIN|EPOLLOUT, on_tcp_ready, t);
        if (r < 0) {
                t->tcp_fd = safe_close(t->tcp_fd);
                return r;
        }

        return 0;
}

void dns_query_transaction_reply(DnsQueryTransaction *t, DnsPacket *p) {
        int r;

        assert(t);
        assert(p);

        if (t->state != DNS_QUERY_PENDING)
                return;

        if (t->received != p) {
                dns_packet_unref(t->received);
                t->received = dns_packet_ref(p);
        }

        if (t->tcp_fd >= 0) {
                if (DNS_PACKET_TC(p)) {
                        /* Truncated via TCP? Somebody must be fucking with us */
                        dns_query_transaction_set_state(t, DNS_QUERY_INVALID_REPLY);
                        return;
                }

                if (DNS_PACKET_ID(p) != t->id) {
                        /* Not the reply to our query? Somebody must be fucking with us */
                        dns_query_transaction_set_state(t, DNS_QUERY_INVALID_REPLY);
                        return;
                }
        }

        if (DNS_PACKET_TC(p)) {
                /* Response was truncated, let's try again with good old TCP */
                r = dns_query_transaction_start_tcp(t);
                if (r == -ESRCH) {
                        /* No servers found? Damn! */
                        dns_query_transaction_set_state(t, DNS_QUERY_NO_SERVERS);
                        return;
                }
                if (r < 0) {
                        /* Couldn't send? Try immediately again, with a new server */
                        dns_scope_next_dns_server(t->scope);

                        r = dns_query_transaction_start(t);
                        if (r < 0) {
                                dns_query_transaction_set_state(t, DNS_QUERY_RESOURCES);
                                return;
                        }

                        return;
                }
        }

        if (DNS_PACKET_RCODE(p) == DNS_RCODE_SUCCESS)
                dns_query_transaction_set_state(t, DNS_QUERY_SUCCESS);
        else
                dns_query_transaction_set_state(t, DNS_QUERY_FAILURE);
}

static int on_transaction_timeout(sd_event_source *s, usec_t usec, void *userdata) {
        DnsQueryTransaction *t = userdata;
        int r;

        assert(s);
        assert(t);

        /* Timeout reached? Try again, with a new server */
        dns_scope_next_dns_server(t->scope);

        r = dns_query_transaction_start(t);
        if (r < 0)
                dns_query_transaction_set_state(t, DNS_QUERY_RESOURCES);

        return 0;
}

static int dns_query_make_packet(DnsQueryTransaction *t) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        unsigned n;
        int r;

        assert(t);

        if (t->sent)
                return 0;

        r = dns_packet_new_query(&p, 0);
        if (r < 0)
                return r;

        for (n = 0; n < t->query->n_keys; n++) {
                r = dns_packet_append_key(p, &t->query->keys[n], NULL);
                if (r < 0)
                        return r;
        }

        DNS_PACKET_HEADER(p)->qdcount = htobe16(t->query->n_keys);
        DNS_PACKET_HEADER(p)->id = t->id;

        t->sent = p;
        p = NULL;

        return 0;
}

static int dns_query_transaction_start(DnsQueryTransaction *t) {
        int r;

        assert(t);

        dns_query_transaction_stop(t);

        if (t->n_attempts >= ATTEMPTS_MAX) {
                dns_query_transaction_set_state(t, DNS_QUERY_ATTEMPTS_MAX);
                return 0;
        }

        r = dns_query_make_packet(t);
        if (r < 0)
                return r;

        t->n_attempts++;
        t->received = dns_packet_unref(t->received);

        /* Try via UDP, and if that fails due to large size try via TCP */
        r = dns_scope_send(t->scope, t->sent);
        if (r == -EMSGSIZE)
                r = dns_query_transaction_start_tcp(t);

        if (r == -ESRCH) {
                dns_query_transaction_set_state(t, DNS_QUERY_NO_SERVERS);
                return 0;
        }
        if (r < 0) {
                /* Couldn't send? Try immediately again, with a new server */
                dns_scope_next_dns_server(t->scope);

                return dns_query_transaction_start(t);
        }

        r = sd_event_add_time(t->query->manager->event, &t->timeout_event_source, CLOCK_MONOTONIC, now(CLOCK_MONOTONIC) + TRANSACTION_TIMEOUT_USEC, 0, on_transaction_timeout, t);
        if (r < 0)
                return r;

        dns_query_transaction_set_state(t, DNS_QUERY_PENDING);
        return 1;
}

DnsQuery *dns_query_free(DnsQuery *q) {
        unsigned n;

        if (!q)
                return NULL;

        sd_bus_message_unref(q->request);
        dns_packet_unref(q->received);
        sd_event_source_unref(q->timeout_event_source);

        while (q->transactions)
                dns_query_transaction_free(q->transactions);

        if (q->manager) {
                LIST_REMOVE(queries, q->manager->dns_queries, q);
                q->manager->n_dns_queries--;
        }

        for (n = 0; n < q->n_keys; n++)
                free(q->keys[n].name);
        free(q->keys);
        free(q);

        return NULL;
}

int dns_query_new(Manager *m, DnsQuery **ret, DnsResourceKey *keys, unsigned n_keys) {
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        const char *name = NULL;

        assert(m);

        if (n_keys <= 0 || n_keys >= 65535)
                return -EINVAL;

        if (m->n_dns_queries >= QUERIES_MAX)
                return -EBUSY;

        assert(keys);

        q = new0(DnsQuery, 1);
        if (!q)
                return -ENOMEM;

        q->keys = new(DnsResourceKey, n_keys);
        if (!q->keys)
                return -ENOMEM;

        for (q->n_keys = 0; q->n_keys < n_keys; q->n_keys++) {
                q->keys[q->n_keys].class = keys[q->n_keys].class;
                q->keys[q->n_keys].type = keys[q->n_keys].type;
                q->keys[q->n_keys].name = strdup(keys[q->n_keys].name);
                if (!q->keys[q->n_keys].name)
                        return -ENOMEM;

                if (!name)
                        name = q->keys[q->n_keys].name;
                else if (!dns_name_equal(name, q->keys[q->n_keys].name))
                        return -EINVAL;
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
        assert(q);

        q->timeout_event_source = sd_event_source_unref(q->timeout_event_source);

        while (q->transactions)
                dns_query_transaction_free(q->transactions);
}

static void dns_query_set_state(DnsQuery *q, DnsQueryState state) {
        DnsQueryState old_state;
        assert(q);

        if (q->state == state)
                return;

        old_state = q->state;
        q->state = state;

        if (!IN_SET(state, DNS_QUERY_NULL, DNS_QUERY_PENDING)) {
                dns_query_stop(q);

                if (old_state == DNS_QUERY_PENDING && q->complete)
                        q->complete(q);
        }
}

static int on_query_timeout(sd_event_source *s, usec_t usec, void *userdata) {
        DnsQuery *q = userdata;

        assert(s);
        assert(q);

        dns_query_set_state(q, DNS_QUERY_TIMEOUT);
        return 0;
}

int dns_query_start(DnsQuery *q) {
        DnsScopeMatch found = DNS_SCOPE_NO;
        DnsScope *s, *first = NULL;
        DnsQueryTransaction *t;
        int r;

        assert(q);

        if (q->state != DNS_QUERY_NULL)
                return 0;

        assert(q->n_keys > 0);

        LIST_FOREACH(scopes, s, q->manager->dns_scopes) {
                DnsScopeMatch match;

                match = dns_scope_test(s, q->keys[0].name);
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

        r = dns_query_transaction_new(q, NULL, first);
        if (r < 0)
                return r;

        LIST_FOREACH(scopes, s, first->scopes_next) {
                DnsScopeMatch match;

                match = dns_scope_test(s, q->keys[0].name);
                if (match < 0)
                        return match;

                if (match != found)
                        continue;

                r = dns_query_transaction_new(q, NULL, s);
                if (r < 0)
                        return r;
        }

        q->received = dns_packet_unref(q->received);

        r = sd_event_add_time(q->manager->event, &q->timeout_event_source, CLOCK_MONOTONIC, now(CLOCK_MONOTONIC) + QUERY_TIMEOUT_USEC, 0, on_query_timeout, q);
        if (r < 0)
                goto fail;

        dns_query_set_state(q, DNS_QUERY_PENDING);

        LIST_FOREACH(transactions_by_query, t, q->transactions) {

                r = dns_query_transaction_start(t);
                if (r < 0)
                        goto fail;

                if (q->state != DNS_QUERY_PENDING)
                        break;
        }

        return 1;

fail:
        dns_query_stop(q);
        return r;
}

void dns_query_finish(DnsQuery *q) {
        DnsQueryTransaction *t;
        DnsQueryState state = DNS_QUERY_NO_SERVERS;
        DnsPacket *received = NULL;

        assert(q);

        if (q->state != DNS_QUERY_PENDING)
                return;

        LIST_FOREACH(transactions_by_query, t, q->transactions) {

                /* One of the transactions is still going on, let's wait for it */
                if (t->state == DNS_QUERY_PENDING || t->state == DNS_QUERY_NULL)
                        return;

                /* One of the transactions is successful, let's use it */
                if (t->state == DNS_QUERY_SUCCESS) {
                        q->received = dns_packet_ref(t->received);
                        dns_query_set_state(q, DNS_QUERY_SUCCESS);
                        return;
                }

                /* One of the transactions has failed, let's see
                 * whether we find anything better, but if not, return
                 * its response packet */
                if (t->state == DNS_QUERY_FAILURE) {
                        received = t->received;
                        state = DNS_QUERY_FAILURE;
                        continue;
                }

                if (state == DNS_QUERY_NO_SERVERS && t->state != DNS_QUERY_NO_SERVERS)
                        state = t->state;
        }

        if (state == DNS_QUERY_FAILURE)
                q->received = dns_packet_ref(received);

        dns_query_set_state(q, state);
}

int dns_query_follow_cname(DnsQuery *q, const char *name) {
        DnsResourceKey *keys;
        unsigned i;

        assert(q);

        if (q->n_cname > CNAME_MAX)
                return -ELOOP;

        keys = new(DnsResourceKey, q->n_keys);
        if (!keys)
                return -ENOMEM;

        for (i = 0; i < q->n_keys; i++) {
                keys[i].class = q->keys[i].class;
                keys[i].type = q->keys[i].type;
                keys[i].name = strdup(name);
                if (!keys[i].name) {

                        for (; i > 0; i--)
                                free(keys[i-1].name);
                        free(keys);
                        return -ENOMEM;
                }
        }

        for (i = 0; i < q->n_keys; i++)
                free(q->keys[i].name);
        free(q->keys);

        q->keys = keys;

        q->n_cname++;

        dns_query_set_state(q, DNS_QUERY_NULL);
        return 0;
}

int dns_query_matches_rr(DnsQuery *q, DnsResourceRecord *rr) {
        unsigned i;
        int r;

        assert(q);
        assert(rr);

        for (i = 0; i < q->n_keys; i++) {

                if (rr->key.class != q->keys[i].class)
                        continue;

                if (rr->key.type != q->keys[i].type &&
                    q->keys[i].type != DNS_TYPE_ANY)
                        continue;

                r = dns_name_equal(rr->key.name, q->keys[i].name);
                if (r != 0)
                        return r;
        }

        return 0;
}

int dns_query_matches_cname(DnsQuery *q, DnsResourceRecord *rr) {
        unsigned i;
        int r;

        assert(q);
        assert(rr);

        for (i = 0; i < q->n_keys; i++) {

                if (rr->key.class != q->keys[i].class)
                        continue;

                if (rr->key.type != DNS_TYPE_CNAME)
                        continue;

                r = dns_name_equal(rr->key.name, q->keys[i].name);
                if (r != 0)
                        return r;
        }

        return 0;
}
