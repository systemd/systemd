/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-messages.h"

#include "af-list.h"
#include "alloc-util.h"
#include "dns-domain.h"
#include "errno-list.h"
#include "errno-util.h"
#include "fd-util.h"
#include "glyph-util.h"
#include "random-util.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-transaction.h"
#include "resolved-dnstls.h"
#include "resolved-llmnr.h"
#include "string-table.h"

#define TRANSACTIONS_MAX 4096
#define TRANSACTION_TCP_TIMEOUT_USEC (10U*USEC_PER_SEC)

/* After how much time to repeat classic DNS requests */
#define DNS_TIMEOUT_USEC (SD_RESOLVED_QUERY_TIMEOUT_USEC / DNS_TRANSACTION_ATTEMPTS_MAX)

static void dns_transaction_reset_answer(DnsTransaction *t) {
        assert(t);

        t->received = dns_packet_unref(t->received);
        t->answer = dns_answer_unref(t->answer);
        t->answer_rcode = 0;
        t->answer_dnssec_result = _DNSSEC_RESULT_INVALID;
        t->answer_source = _DNS_TRANSACTION_SOURCE_INVALID;
        t->answer_query_flags = 0;
        t->answer_nsec_ttl = UINT32_MAX;
        t->answer_errno = 0;
}

static void dns_transaction_flush_dnssec_transactions(DnsTransaction *t) {
        DnsTransaction *z;

        assert(t);

        while ((z = set_steal_first(t->dnssec_transactions))) {
                set_remove(z->notify_transactions, t);
                set_remove(z->notify_transactions_done, t);
                dns_transaction_gc(z);
        }
}

static void dns_transaction_close_connection(
                DnsTransaction *t,
                bool use_graveyard) { /* Set use_graveyard = false when you know the connection is already
                                       * dead, for example because you got a connection error back from the
                                       * kernel. In that case there's no point in keeping the fd around,
                                       * hence don't. */
        int r;

        assert(t);

        if (t->stream) {
                /* Let's detach the stream from our transaction, in case something else keeps a reference to it. */
                LIST_REMOVE(transactions_by_stream, t->stream->transactions, t);

                /* Remove packet in case it's still in the queue */
                dns_packet_unref(ordered_set_remove(t->stream->write_queue, t->sent));

                t->stream = dns_stream_unref(t->stream);
        }

        t->dns_udp_event_source = sd_event_source_disable_unref(t->dns_udp_event_source);

        /* If we have a UDP socket where we sent a packet, but never received one, then add it to the socket
         * graveyard, instead of closing it right away. That way it will stick around for a moment longer,
         * and the reply we might still get from the server will be eaten up instead of resulting in an ICMP
         * port unreachable error message. */

        /* Skip the graveyard stuff when we're shutting down, since that requires running event loop */
        if (!t->scope->manager->event || sd_event_get_state(t->scope->manager->event) == SD_EVENT_FINISHED)
                use_graveyard = false;

        if (use_graveyard && t->dns_udp_fd >= 0 && t->sent && !t->received) {
                r = manager_add_socket_to_graveyard(t->scope->manager, t->dns_udp_fd);
                if (r < 0)
                        log_debug_errno(r, "Failed to add UDP socket to graveyard, closing immediately: %m");
                else
                        TAKE_FD(t->dns_udp_fd);
        }

        t->dns_udp_fd = safe_close(t->dns_udp_fd);
}

static void dns_transaction_stop_timeout(DnsTransaction *t) {
        assert(t);

        t->timeout_event_source = sd_event_source_disable_unref(t->timeout_event_source);
}

DnsTransaction* dns_transaction_free(DnsTransaction *t) {
        DnsQueryCandidate *c;
        DnsZoneItem *i;
        DnsTransaction *z;

        if (!t)
                return NULL;

        log_debug("Freeing transaction %" PRIu16 ".", t->id);

        dns_transaction_close_connection(t, true);
        dns_transaction_stop_timeout(t);

        dns_packet_unref(t->sent);
        dns_transaction_reset_answer(t);

        dns_server_unref(t->server);

        if (t->scope) {
                if (t->key) {
                        DnsTransaction *first;

                        first = hashmap_get(t->scope->transactions_by_key, t->key);
                        LIST_REMOVE(transactions_by_key, first, t);
                        if (first)
                                hashmap_replace(t->scope->transactions_by_key, first->key, first);
                        else
                                hashmap_remove(t->scope->transactions_by_key, t->key);
                }

                LIST_REMOVE(transactions_by_scope, t->scope->transactions, t);

                if (t->id != 0)
                        hashmap_remove(t->scope->manager->dns_transactions, UINT_TO_PTR(t->id));
        }

        while ((c = set_steal_first(t->notify_query_candidates)))
                set_remove(c->transactions, t);
        set_free(t->notify_query_candidates);

        while ((c = set_steal_first(t->notify_query_candidates_done)))
                set_remove(c->transactions, t);
        set_free(t->notify_query_candidates_done);

        while ((i = set_steal_first(t->notify_zone_items)))
                i->probe_transaction = NULL;
        set_free(t->notify_zone_items);

        while ((i = set_steal_first(t->notify_zone_items_done)))
                i->probe_transaction = NULL;
        set_free(t->notify_zone_items_done);

        while ((z = set_steal_first(t->notify_transactions)))
                set_remove(z->dnssec_transactions, t);
        set_free(t->notify_transactions);

        while ((z = set_steal_first(t->notify_transactions_done)))
                set_remove(z->dnssec_transactions, t);
        set_free(t->notify_transactions_done);

        dns_transaction_flush_dnssec_transactions(t);
        set_free(t->dnssec_transactions);

        dns_answer_unref(t->validated_keys);
        dns_resource_key_unref(t->key);
        dns_packet_unref(t->bypass);

        return mfree(t);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsTransaction*, dns_transaction_free);

DnsTransaction* dns_transaction_gc(DnsTransaction *t) {
        assert(t);

        /* Returns !NULL if we can't gc yet. */

        if (t->block_gc > 0)
                return t;

        if (set_isempty(t->notify_query_candidates) &&
            set_isempty(t->notify_query_candidates_done) &&
            set_isempty(t->notify_zone_items) &&
            set_isempty(t->notify_zone_items_done) &&
            set_isempty(t->notify_transactions) &&
            set_isempty(t->notify_transactions_done))
                return dns_transaction_free(t);

        return t;
}

static uint16_t pick_new_id(Manager *m) {
        uint16_t new_id;

        /* Find a fresh, unused transaction id. Note that this loop is bounded because there's a limit on the
         * number of transactions, and it's much lower than the space of IDs. */

        assert_cc(TRANSACTIONS_MAX < 0xFFFF);

        do
                random_bytes(&new_id, sizeof(new_id));
        while (new_id == 0 ||
               hashmap_get(m->dns_transactions, UINT_TO_PTR(new_id)));

        return new_id;
}

static int key_ok(
                DnsScope *scope,
                DnsResourceKey *key) {

        /* Don't allow looking up invalid or pseudo RRs */
        if (!dns_type_is_valid_query(key->type))
                return -EINVAL;
        if (dns_type_is_obsolete(key->type))
                return -EOPNOTSUPP;

        /* We only support the IN class */
        if (!IN_SET(key->class, DNS_CLASS_IN, DNS_CLASS_ANY))
                return -EOPNOTSUPP;

        /* Don't allows DNSSEC RRs to be looked up via LLMNR/mDNS. They don't really make sense
         * there, and it speeds up our queries if we refuse this early */
        if (scope->protocol != DNS_PROTOCOL_DNS &&
            dns_type_is_dnssec(key->type))
                return -EOPNOTSUPP;

        return 0;
}

int dns_transaction_new(
                DnsTransaction **ret,
                DnsScope *s,
                DnsResourceKey *key,
                DnsPacket *bypass,
                uint64_t query_flags) {

        _cleanup_(dns_transaction_freep) DnsTransaction *t = NULL;
        int r;

        assert(ret);
        assert(s);

        if (key) {
                assert(!bypass);

                r = key_ok(s, key);
                if (r < 0)
                        return r;
        } else {
                DnsResourceKey *qk;
                assert(bypass);

                r = dns_packet_validate_query(bypass);
                if (r < 0)
                        return r;

                DNS_QUESTION_FOREACH(qk, bypass->question) {
                        r = key_ok(s, qk);
                        if (r < 0)
                                return r;
                }
        }

        if (hashmap_size(s->manager->dns_transactions) >= TRANSACTIONS_MAX)
                return -EBUSY;

        r = hashmap_ensure_allocated(&s->manager->dns_transactions, NULL);
        if (r < 0)
                return r;

        if (key) {
                r = hashmap_ensure_allocated(&s->transactions_by_key, &dns_resource_key_hash_ops);
                if (r < 0)
                        return r;
        }

        t = new(DnsTransaction, 1);
        if (!t)
                return -ENOMEM;

        *t = (DnsTransaction) {
                .dns_udp_fd = -EBADF,
                .answer_source = _DNS_TRANSACTION_SOURCE_INVALID,
                .answer_dnssec_result = _DNSSEC_RESULT_INVALID,
                .answer_nsec_ttl = UINT32_MAX,
                .key = dns_resource_key_ref(key),
                .query_flags = query_flags,
                .bypass = dns_packet_ref(bypass),
                .current_feature_level = _DNS_SERVER_FEATURE_LEVEL_INVALID,
                .clamp_feature_level_servfail = _DNS_SERVER_FEATURE_LEVEL_INVALID,
                .id = pick_new_id(s->manager),
        };

        r = hashmap_put(s->manager->dns_transactions, UINT_TO_PTR(t->id), t);
        if (r < 0) {
                t->id = 0;
                return r;
        }

        if (t->key) {
                DnsTransaction *first;

                first = hashmap_get(s->transactions_by_key, t->key);
                LIST_PREPEND(transactions_by_key, first, t);

                r = hashmap_replace(s->transactions_by_key, first->key, first);
                if (r < 0) {
                        LIST_REMOVE(transactions_by_key, first, t);
                        return r;
                }
        }

        LIST_PREPEND(transactions_by_scope, s->transactions, t);
        t->scope = s;

        s->manager->n_transactions_total++;

        if (ret)
                *ret = t;

        TAKE_PTR(t);
        return 0;
}

static void dns_transaction_shuffle_id(DnsTransaction *t) {
        uint16_t new_id;
        assert(t);

        /* Pick a new ID for this transaction. */

        new_id = pick_new_id(t->scope->manager);
        assert_se(hashmap_remove_and_put(t->scope->manager->dns_transactions, UINT_TO_PTR(t->id), UINT_TO_PTR(new_id), t) >= 0);

        log_debug("Transaction %" PRIu16 " is now %" PRIu16 ".", t->id, new_id);
        t->id = new_id;

        /* Make sure we generate a new packet with the new ID */
        t->sent = dns_packet_unref(t->sent);
}

static void dns_transaction_tentative(DnsTransaction *t, DnsPacket *p) {
        char key_str[DNS_RESOURCE_KEY_STRING_MAX];
        DnsZoneItem *z;

        assert(t);
        assert(p);
        assert(t->scope->protocol == DNS_PROTOCOL_LLMNR);

        if (manager_packet_from_local_address(t->scope->manager, p) != 0)
                return;

        log_debug("Transaction %" PRIu16 " for <%s> on scope %s on %s/%s got tentative packet from %s.",
                  t->id,
                  dns_resource_key_to_string(dns_transaction_key(t), key_str, sizeof key_str),
                  dns_protocol_to_string(t->scope->protocol),
                  t->scope->link ? t->scope->link->ifname : "*",
                  af_to_name_short(t->scope->family),
                  IN_ADDR_TO_STRING(p->family, &p->sender));

        /* RFC 4795, Section 4.1 says that the peer with the
         * lexicographically smaller IP address loses */
        if (memcmp(&p->sender, &p->destination, FAMILY_ADDRESS_SIZE(p->family)) >= 0) {
                log_debug("Peer has lexicographically larger IP address and thus lost in the conflict.");
                return;
        }

        log_debug("We have the lexicographically larger IP address and thus lost in the conflict.");

        t->block_gc++;

        while ((z = set_first(t->notify_zone_items))) {
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
        DnsQueryCandidate *c;
        DnsZoneItem *z;
        DnsTransaction *d;
        const char *st;
        char key_str[DNS_RESOURCE_KEY_STRING_MAX];

        assert(t);
        assert(!DNS_TRANSACTION_IS_LIVE(state));

        if (state == DNS_TRANSACTION_DNSSEC_FAILED) {
                dns_resource_key_to_string(dns_transaction_key(t), key_str, sizeof key_str);

                log_struct(LOG_NOTICE,
                           "MESSAGE_ID=" SD_MESSAGE_DNSSEC_FAILURE_STR,
                           LOG_MESSAGE("DNSSEC validation failed for question %s: %s",
                                       key_str, dnssec_result_to_string(t->answer_dnssec_result)),
                           "DNS_TRANSACTION=%" PRIu16, t->id,
                           "DNS_QUESTION=%s", key_str,
                           "DNSSEC_RESULT=%s", dnssec_result_to_string(t->answer_dnssec_result),
                           "DNS_SERVER=%s", strna(dns_server_string_full(t->server)),
                           "DNS_SERVER_FEATURE_LEVEL=%s", dns_server_feature_level_to_string(t->server->possible_feature_level));
        }

        /* Note that this call might invalidate the query. Callers
         * should hence not attempt to access the query or transaction
         * after calling this function. */

        if (state == DNS_TRANSACTION_ERRNO)
                st = errno_to_name(t->answer_errno);
        else
                st = dns_transaction_state_to_string(state);

        log_debug("%s transaction %" PRIu16 " for <%s> on scope %s on %s/%s now complete with <%s> from %s (%s; %s).",
                  t->bypass ? "Bypass" : "Regular",
                  t->id,
                  dns_resource_key_to_string(dns_transaction_key(t), key_str, sizeof key_str),
                  dns_protocol_to_string(t->scope->protocol),
                  t->scope->link ? t->scope->link->ifname : "*",
                  af_to_name_short(t->scope->family),
                  st,
                  t->answer_source < 0 ? "none" : dns_transaction_source_to_string(t->answer_source),
                  FLAGS_SET(t->query_flags, SD_RESOLVED_NO_VALIDATE) ? "not validated" :
                  (FLAGS_SET(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED) ? "authenticated" : "unsigned"),
                  FLAGS_SET(t->answer_query_flags, SD_RESOLVED_CONFIDENTIAL) ? "confidential" : "non-confidential");

        t->state = state;

        dns_transaction_close_connection(t, true);
        dns_transaction_stop_timeout(t);

        /* Notify all queries that are interested, but make sure the
         * transaction isn't freed while we are still looking at it */
        t->block_gc++;

        SET_FOREACH_MOVE(c, t->notify_query_candidates_done, t->notify_query_candidates)
                dns_query_candidate_notify(c);
        SWAP_TWO(t->notify_query_candidates, t->notify_query_candidates_done);

        SET_FOREACH_MOVE(z, t->notify_zone_items_done, t->notify_zone_items)
                dns_zone_item_notify(z);
        SWAP_TWO(t->notify_zone_items, t->notify_zone_items_done);
        if (t->probing && t->state == DNS_TRANSACTION_ATTEMPTS_MAX_REACHED)
                (void) dns_scope_announce(t->scope, false);

        SET_FOREACH_MOVE(d, t->notify_transactions_done, t->notify_transactions)
                dns_transaction_notify(d, t);
        SWAP_TWO(t->notify_transactions, t->notify_transactions_done);

        t->block_gc--;
        dns_transaction_gc(t);
}

static void dns_transaction_complete_errno(DnsTransaction *t, int error) {
        assert(t);
        assert(error != 0);

        t->answer_errno = abs(error);
        dns_transaction_complete(t, DNS_TRANSACTION_ERRNO);
}

static int dns_transaction_pick_server(DnsTransaction *t) {
        DnsServer *server;

        assert(t);
        assert(t->scope->protocol == DNS_PROTOCOL_DNS);

        /* Pick a DNS server and a feature level for it. */

        server = dns_scope_get_dns_server(t->scope);
        if (!server)
                return -ESRCH;

        /* If we changed the server invalidate the feature level clamping, as the new server might have completely
         * different properties. */
        if (server != t->server)
                t->clamp_feature_level_servfail = _DNS_SERVER_FEATURE_LEVEL_INVALID;

        t->current_feature_level = dns_server_possible_feature_level(server);

        /* Clamp the feature level if that is requested. */
        if (t->clamp_feature_level_servfail != _DNS_SERVER_FEATURE_LEVEL_INVALID &&
            t->current_feature_level > t->clamp_feature_level_servfail)
                t->current_feature_level = t->clamp_feature_level_servfail;

        log_debug("Using feature level %s for transaction %u.", dns_server_feature_level_to_string(t->current_feature_level), t->id);

        if (server == t->server)
                return 0;

        dns_server_unref(t->server);
        t->server = dns_server_ref(server);

        t->n_picked_servers++;

        log_debug("Using DNS server %s for transaction %u.", strna(dns_server_string_full(t->server)), t->id);

        return 1;
}

static void dns_transaction_retry(DnsTransaction *t, bool next_server) {
        int r;

        assert(t);

        /* Retries the transaction as it is, possibly on a different server */

        if (next_server && t->scope->protocol == DNS_PROTOCOL_DNS)
                log_debug("Retrying transaction %" PRIu16 ", after switching servers.", t->id);
        else
                log_debug("Retrying transaction %" PRIu16 ".", t->id);

        /* Before we try again, switch to a new server. */
        if (next_server)
                dns_scope_next_dns_server(t->scope, t->server);

        r = dns_transaction_go(t);
        if (r < 0)
                dns_transaction_complete_errno(t, r);
}

static bool dns_transaction_limited_retry(DnsTransaction *t) {
        assert(t);

        /* If we haven't tried all different servers yet, let's try again with a different server */

        if (t->n_picked_servers >= dns_scope_get_n_dns_servers(t->scope))
                return false;

        dns_transaction_retry(t, /* next_server= */ true);
        return true;
}

static int dns_transaction_maybe_restart(DnsTransaction *t) {
        int r;

        assert(t);

        /* Restarts the transaction, under a new ID if the feature level of the server changed since we first
         * tried, without changing DNS server. Returns > 0 if the transaction was restarted, 0 if not. */

        if (!t->server)
                return 0;

        if (t->current_feature_level <= dns_server_possible_feature_level(t->server))
                return 0;

        /* The server's current feature level is lower than when we sent the original query. We learnt something from
           the response or possibly an auxiliary DNSSEC response that we didn't know before.  We take that as reason to
           restart the whole transaction. This is a good idea to deal with servers that respond rubbish if we include
           OPT RR or DO bit. One of these cases is documented here, for example:
           https://open.nlnetlabs.nl/pipermail/dnssec-trigger/2014-November/000376.html */

        log_debug("Server feature level is now lower than when we began our transaction. Restarting with new ID.");
        dns_transaction_shuffle_id(t);

        r = dns_transaction_go(t);
        if (r < 0)
                return r;

        return 1;
}

static void on_transaction_stream_error(DnsTransaction *t, int error) {
        assert(t);

        dns_transaction_close_connection(t, true);

        if (ERRNO_IS_DISCONNECT(error)) {
                if (t->scope->protocol == DNS_PROTOCOL_LLMNR) {
                        /* If the LLMNR/TCP connection failed, the host doesn't support LLMNR, and we cannot answer the
                         * question on this scope. */
                        dns_transaction_complete(t, DNS_TRANSACTION_NOT_FOUND);
                        return;
                }

                dns_transaction_retry(t, true);
                return;
        }
        if (error != 0)
                dns_transaction_complete_errno(t, error);
}

static int dns_transaction_on_stream_packet(DnsTransaction *t, DnsStream *s, DnsPacket *p) {
        bool encrypted;

        assert(t);
        assert(s);
        assert(p);

        encrypted = s->encrypted;

        dns_transaction_close_connection(t, true);

        if (dns_packet_validate_reply(p) <= 0) {
                log_debug("Invalid TCP reply packet.");
                dns_transaction_complete(t, DNS_TRANSACTION_INVALID_REPLY);
                return 0;
        }

        dns_scope_check_conflicts(t->scope, p);

        t->block_gc++;
        dns_transaction_process_reply(t, p, encrypted);
        t->block_gc--;

        /* If the response wasn't useful, then complete the transition
         * now. After all, we are the worst feature set now with TCP
         * sockets, and there's really no point in retrying. */
        if (t->state == DNS_TRANSACTION_PENDING)
                dns_transaction_complete(t, DNS_TRANSACTION_INVALID_REPLY);
        else
                dns_transaction_gc(t);

        return 0;
}

static int on_stream_complete(DnsStream *s, int error) {
        assert(s);

        if (ERRNO_IS_DISCONNECT(error) && s->protocol != DNS_PROTOCOL_LLMNR) {
                log_debug_errno(error, "Connection failure for DNS TCP stream: %m");

                if (s->transactions) {
                        DnsTransaction *t;

                        t = s->transactions;
                        dns_server_packet_lost(t->server, IPPROTO_TCP, t->current_feature_level);
                }
        }

        if (error != 0)
                LIST_FOREACH(transactions_by_stream, t, s->transactions)
                        on_transaction_stream_error(t, error);

        return 0;
}

static int on_stream_packet(DnsStream *s, DnsPacket *p) {
        DnsTransaction *t;

        assert(s);
        assert(s->manager);
        assert(p);

        t = hashmap_get(s->manager->dns_transactions, UINT_TO_PTR(DNS_PACKET_ID(p)));
        if (t && t->stream == s) /* Validate that the stream we got this on actually is the stream the
                                  * transaction was using. */
                return dns_transaction_on_stream_packet(t, s, p);

        /* Ignore incorrect transaction id as an old transaction can have been canceled. */
        log_debug("Received unexpected TCP reply packet with id %" PRIu16 ", ignoring.", DNS_PACKET_ID(p));
        return 0;
}

static uint16_t dns_transaction_port(DnsTransaction *t) {
        assert(t);

        if (t->server->port > 0)
                return t->server->port;

        return DNS_SERVER_FEATURE_LEVEL_IS_TLS(t->current_feature_level) ? 853 : 53;
}

static int dns_transaction_emit_tcp(DnsTransaction *t) {
        usec_t stream_timeout_usec = DNS_STREAM_DEFAULT_TIMEOUT_USEC;
        _cleanup_(dns_stream_unrefp) DnsStream *s = NULL;
        _cleanup_close_ int fd = -EBADF;
        union sockaddr_union sa;
        DnsStreamType type;
        int r;

        assert(t);
        assert(t->sent);

        dns_transaction_close_connection(t, true);

        switch (t->scope->protocol) {

        case DNS_PROTOCOL_DNS:
                r = dns_transaction_pick_server(t);
                if (r < 0)
                        return r;

                if (manager_server_is_stub(t->scope->manager, t->server))
                        return -ELOOP;

                if (!t->bypass) {
                        if (!dns_server_dnssec_supported(t->server) && dns_type_is_dnssec(dns_transaction_key(t)->type))
                                return -EOPNOTSUPP;

                        r = dns_server_adjust_opt(t->server, t->sent, t->current_feature_level);
                        if (r < 0)
                                return r;
                }

                if (t->server->stream && (DNS_SERVER_FEATURE_LEVEL_IS_TLS(t->current_feature_level) == t->server->stream->encrypted))
                        s = dns_stream_ref(t->server->stream);
                else
                        fd = dns_scope_socket_tcp(t->scope, AF_UNSPEC, NULL, t->server, dns_transaction_port(t), &sa);

                /* Lower timeout in DNS-over-TLS opportunistic mode. In environments where DoT is blocked
                 * without ICMP response overly long delays when contacting DoT servers are nasty, in
                 * particular if multiple DNS servers are defined which we try in turn and all are
                 * blocked. Hence, substantially lower the timeout in that case. */
                if (DNS_SERVER_FEATURE_LEVEL_IS_TLS(t->current_feature_level) &&
                    dns_server_get_dns_over_tls_mode(t->server) == DNS_OVER_TLS_OPPORTUNISTIC)
                        stream_timeout_usec = DNS_STREAM_OPPORTUNISTIC_TLS_TIMEOUT_USEC;

                type = DNS_STREAM_LOOKUP;
                break;

        case DNS_PROTOCOL_LLMNR:
                /* When we already received a reply to this (but it was truncated), send to its sender address */
                if (t->received)
                        fd = dns_scope_socket_tcp(t->scope, t->received->family, &t->received->sender, NULL, t->received->sender_port, &sa);
                else {
                        union in_addr_union address;
                        int family = AF_UNSPEC;

                        /* Otherwise, try to talk to the owner of a
                         * the IP address, in case this is a reverse
                         * PTR lookup */

                        r = dns_name_address(dns_resource_key_name(dns_transaction_key(t)), &family, &address);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EINVAL;
                        if (family != t->scope->family)
                                return -ESRCH;

                        fd = dns_scope_socket_tcp(t->scope, family, &address, NULL, LLMNR_PORT, &sa);
                }

                type = DNS_STREAM_LLMNR_SEND;
                break;

        default:
                return -EAFNOSUPPORT;
        }

        if (!s) {
                if (fd < 0)
                        return fd;

                r = dns_stream_new(t->scope->manager, &s, type, t->scope->protocol, fd, &sa,
                                   on_stream_packet, on_stream_complete, stream_timeout_usec);
                if (r < 0)
                        return r;

                fd = -EBADF;

#if ENABLE_DNS_OVER_TLS
                if (t->scope->protocol == DNS_PROTOCOL_DNS &&
                    DNS_SERVER_FEATURE_LEVEL_IS_TLS(t->current_feature_level)) {

                        assert(t->server);
                        r = dnstls_stream_connect_tls(s, t->server);
                        if (r < 0)
                                return r;
                }
#endif

                if (t->server) {
                        dns_server_unref_stream(t->server);
                        s->server = dns_server_ref(t->server);
                        t->server->stream = dns_stream_ref(s);
                }

                /* The interface index is difficult to determine if we are
                 * connecting to the local host, hence fill this in right away
                 * instead of determining it from the socket */
                s->ifindex = dns_scope_ifindex(t->scope);
        }

        t->stream = TAKE_PTR(s);
        LIST_PREPEND(transactions_by_stream, t->stream->transactions, t);

        r = dns_stream_write_packet(t->stream, t->sent);
        if (r < 0) {
                dns_transaction_close_connection(t, /* use_graveyard= */ false);
                return r;
        }

        dns_transaction_reset_answer(t);

        t->tried_stream = true;

        return 0;
}

static void dns_transaction_cache_answer(DnsTransaction *t) {
        assert(t);

        /* For mDNS we cache whenever we get the packet, rather than
         * in each transaction. */
        if (!IN_SET(t->scope->protocol, DNS_PROTOCOL_DNS, DNS_PROTOCOL_LLMNR))
                return;

        /* Caching disabled? */
        if (t->scope->manager->enable_cache == DNS_CACHE_MODE_NO)
                return;

        /* If validation is turned off for this transaction, but DNSSEC is on, then let's not cache this */
        if (FLAGS_SET(t->query_flags, SD_RESOLVED_NO_VALIDATE) && t->scope->dnssec_mode != DNSSEC_NO)
                return;

        /* Packet from localhost? */
        if (!t->scope->manager->cache_from_localhost &&
            in_addr_is_localhost(t->received->family, &t->received->sender) != 0)
                return;

        dns_cache_put(&t->scope->cache,
                      t->scope->manager->enable_cache,
                      t->scope->protocol,
                      dns_transaction_key(t),
                      t->answer_rcode,
                      t->answer,
                      DNS_PACKET_CD(t->received) ? t->received : NULL, /* only cache full packets with CD on,
                                                                        * since our use case for caching them
                                                                        * is "bypass" mode which is only
                                                                        * enabled for CD packets. */
                      t->answer_query_flags,
                      t->answer_dnssec_result,
                      t->answer_nsec_ttl,
                      t->received->family,
                      &t->received->sender,
                      t->scope->manager->stale_retention_usec);
}

static bool dns_transaction_dnssec_is_live(DnsTransaction *t) {
        DnsTransaction *dt;

        assert(t);

        SET_FOREACH(dt, t->dnssec_transactions)
                if (DNS_TRANSACTION_IS_LIVE(dt->state))
                        return true;

        return false;
}

static int dns_transaction_dnssec_ready(DnsTransaction *t) {
        DnsTransaction *dt;
        int r;

        assert(t);

        /* Checks whether the auxiliary DNSSEC transactions of our transaction have completed, or are still
         * ongoing. Returns 0, if we aren't ready for the DNSSEC validation, positive if we are. */

        SET_FOREACH(dt, t->dnssec_transactions) {

                switch (dt->state) {

                case DNS_TRANSACTION_NULL:
                case DNS_TRANSACTION_PENDING:
                case DNS_TRANSACTION_VALIDATING:
                        /* Still ongoing */
                        return 0;

                case DNS_TRANSACTION_RCODE_FAILURE:
                        if (!IN_SET(dt->answer_rcode, DNS_RCODE_NXDOMAIN, DNS_RCODE_SERVFAIL)) {
                                log_debug("Auxiliary DNSSEC RR query failed with rcode=%s.", FORMAT_DNS_RCODE(dt->answer_rcode));
                                goto fail;
                        }

                        /* Fall-through: NXDOMAIN/SERVFAIL is good enough for us. This is because some DNS servers
                         * erroneously return NXDOMAIN/SERVFAIL for empty non-terminals (Akamai...) or missing DS
                         * records (Facebook), and we need to handle that nicely, when asking for parent SOA or similar
                         * RRs to make unsigned proofs. */

                case DNS_TRANSACTION_SUCCESS:
                        /* All good. */
                        break;

                case DNS_TRANSACTION_DNSSEC_FAILED:
                        /* We handle DNSSEC failures different from other errors, as we care about the DNSSEC
                         * validation result */

                        log_debug("Auxiliary DNSSEC RR query failed validation: %s", dnssec_result_to_string(dt->answer_dnssec_result));
                        t->answer_dnssec_result = dt->answer_dnssec_result; /* Copy error code over */
                        dns_transaction_complete(t, DNS_TRANSACTION_DNSSEC_FAILED);
                        return 0;

                default:
                        log_debug("Auxiliary DNSSEC RR query failed with %s", dns_transaction_state_to_string(dt->state));
                        goto fail;
                }
        }

        /* All is ready, we can go and validate */
        return 1;

fail:
        /* Some auxiliary DNSSEC transaction failed for some reason. Maybe we learned something about the
         * server due to this failure, and the feature level is now different? Let's see and restart the
         * transaction if so. If not, let's propagate the auxiliary failure.
         *
         * This is particularly relevant if an auxiliary request figured out that DNSSEC doesn't work, and we
         * are in permissive DNSSEC mode, and thus should restart things without DNSSEC magic. */
        r = dns_transaction_maybe_restart(t);
        if (r < 0)
                return r;
        if (r > 0)
                return 0; /* don't validate just yet, we restarted things */

        t->answer_dnssec_result = DNSSEC_FAILED_AUXILIARY;
        dns_transaction_complete(t, DNS_TRANSACTION_DNSSEC_FAILED);
        return 0;
}

static void dns_transaction_process_dnssec(DnsTransaction *t) {
        int r;

        assert(t);

        /* Are there ongoing DNSSEC transactions? If so, let's wait for them. */
        r = dns_transaction_dnssec_ready(t);
        if (r < 0)
                goto fail;
        if (r == 0) /* We aren't ready yet (or one of our auxiliary transactions failed, and we shouldn't validate now */
                return;

        /* See if we learnt things from the additional DNSSEC transactions, that we didn't know before, and better
         * restart the lookup immediately. */
        r = dns_transaction_maybe_restart(t);
        if (r < 0)
                goto fail;
        if (r > 0) /* Transaction got restarted... */
                return;

        /* All our auxiliary DNSSEC transactions are complete now. Try
         * to validate our RRset now. */
        r = dns_transaction_validate_dnssec(t);
        if (r == -EBADMSG) {
                dns_transaction_complete(t, DNS_TRANSACTION_INVALID_REPLY);
                return;
        }
        if (r < 0)
                goto fail;

        if (t->answer_dnssec_result == DNSSEC_INCOMPATIBLE_SERVER &&
            t->scope->dnssec_mode == DNSSEC_YES) {

                /*  We are not in automatic downgrade mode, and the server is bad. Let's try a different server, maybe
                 *  that works. */

                if (dns_transaction_limited_retry(t))
                        return;

                /* OK, let's give up, apparently all servers we tried didn't work. */
                dns_transaction_complete(t, DNS_TRANSACTION_DNSSEC_FAILED);
                return;
        }

        if (!IN_SET(t->answer_dnssec_result,
                    _DNSSEC_RESULT_INVALID,        /* No DNSSEC validation enabled */
                    DNSSEC_VALIDATED,              /* Answer is signed and validated successfully */
                    DNSSEC_UNSIGNED,               /* Answer is right-fully unsigned */
                    DNSSEC_INCOMPATIBLE_SERVER)) { /* Server does not do DNSSEC (Yay, we are downgrade attack vulnerable!) */
                dns_transaction_complete(t, DNS_TRANSACTION_DNSSEC_FAILED);
                return;
        }

        if (t->answer_dnssec_result == DNSSEC_INCOMPATIBLE_SERVER)
                dns_server_warn_downgrade(t->server);

        dns_transaction_cache_answer(t);

        if (t->answer_rcode == DNS_RCODE_SUCCESS)
                dns_transaction_complete(t, DNS_TRANSACTION_SUCCESS);
        else
                dns_transaction_complete(t, DNS_TRANSACTION_RCODE_FAILURE);

        return;

fail:
        dns_transaction_complete_errno(t, r);
}

static int dns_transaction_has_positive_answer(DnsTransaction *t, DnsAnswerFlags *flags) {
        int r;

        assert(t);

        /* Checks whether the answer is positive, i.e. either a direct
         * answer to the question, or a CNAME/DNAME for it */

        r = dns_answer_match_key(t->answer, dns_transaction_key(t), flags);
        if (r != 0)
                return r;

        r = dns_answer_find_cname_or_dname(t->answer, dns_transaction_key(t), NULL, flags);
        if (r != 0)
                return r;

        return false;
}

static int dns_transaction_fix_rcode(DnsTransaction *t) {
        int r;

        assert(t);

        /* Fix up the RCODE to SUCCESS if we get at least one matching RR in a response. Note that this contradicts the
         * DNS RFCs a bit. Specifically, RFC 6604 Section 3 clarifies that the RCODE shall say something about a
         * CNAME/DNAME chain element coming after the last chain element contained in the message, and not the first
         * one included. However, it also indicates that not all DNS servers implement this correctly. Moreover, when
         * using DNSSEC we usually only can prove the first element of a CNAME/DNAME chain anyway, hence let's settle
         * on always processing the RCODE as referring to the immediate look-up we do, i.e. the first element of a
         * CNAME/DNAME chain. This way, we uniformly handle CNAME/DNAME chains, regardless if the DNS server
         * incorrectly implements RCODE, whether DNSSEC is in use, or whether the DNS server only supplied us with an
         * incomplete CNAME/DNAME chain.
         *
         * Or in other words: if we get at least one positive reply in a message we patch NXDOMAIN to become SUCCESS,
         * and then rely on the CNAME chasing logic to figure out that there's actually a CNAME error with a new
         * lookup. */

        if (t->answer_rcode != DNS_RCODE_NXDOMAIN)
                return 0;

        r = dns_transaction_has_positive_answer(t, NULL);
        if (r <= 0)
                return r;

        t->answer_rcode = DNS_RCODE_SUCCESS;
        return 0;
}

void dns_transaction_process_reply(DnsTransaction *t, DnsPacket *p, bool encrypted) {
        bool retry_with_tcp = false;
        int r;

        assert(t);
        assert(p);
        assert(t->scope);
        assert(t->scope->manager);

        if (t->state != DNS_TRANSACTION_PENDING)
                return;

        /* Increment the total failure counter only when it is the first attempt at querying and the upstream
         * server returns a failure response code. This ensures a more accurate count of the number of queries
         * that received a failure response code, as it doesn't consider retries. */

        if (t->n_attempts == 1 && !IN_SET(DNS_PACKET_RCODE(p), DNS_RCODE_SUCCESS, DNS_RCODE_NXDOMAIN))
                t->scope->manager->n_failure_responses_total++;

        /* Note that this call might invalidate the query. Callers
         * should hence not attempt to access the query or transaction
         * after calling this function. */

        log_debug("Processing incoming packet of size %zu on transaction %" PRIu16" (rcode=%s).",
                  p->size,
                  t->id, FORMAT_DNS_RCODE(DNS_PACKET_RCODE(p)));

        switch (t->scope->protocol) {

        case DNS_PROTOCOL_LLMNR:
                /* For LLMNR we will not accept any packets from other interfaces */

                if (p->ifindex != dns_scope_ifindex(t->scope))
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

        case DNS_PROTOCOL_MDNS:
                /* For mDNS we will not accept any packets from other interfaces */

                if (p->ifindex != dns_scope_ifindex(t->scope))
                        return;

                if (p->family != t->scope->family)
                        return;

                break;

        case DNS_PROTOCOL_DNS:
                /* Note that we do not need to verify the
                 * addresses/port numbers of incoming traffic, as we
                 * invoked connect() on our UDP socket in which case
                 * the kernel already does the needed verification for
                 * us. */
                break;

        default:
                assert_not_reached();
        }

        if (t->received != p)
                DNS_PACKET_REPLACE(t->received, dns_packet_ref(p));

        t->answer_source = DNS_TRANSACTION_NETWORK;

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

        switch (t->scope->protocol) {

        case DNS_PROTOCOL_DNS:
                assert(t->server);

                if (!t->bypass &&
                    IN_SET(DNS_PACKET_RCODE(p), DNS_RCODE_FORMERR, DNS_RCODE_SERVFAIL, DNS_RCODE_NOTIMP)) {

                        /* Request failed, immediately try again with reduced features */

                        if (t->current_feature_level <= DNS_SERVER_FEATURE_LEVEL_UDP) {

                                /* This was already at UDP feature level? If so, it doesn't make sense to downgrade
                                 * this transaction anymore, but let's see if it might make sense to send the request
                                 * to a different DNS server instead. If not let's process the response, and accept the
                                 * rcode. Note that we don't retry on TCP, since that's a suitable way to mitigate
                                 * packet loss, but is not going to give us better rcodes should we actually have
                                 * managed to get them already at UDP level. */

                                if (dns_transaction_limited_retry(t))
                                        return;

                                /* Give up, accept the rcode */
                                log_debug("Server returned error: %s", FORMAT_DNS_RCODE(DNS_PACKET_RCODE(p)));
                                break;
                        }

                        /* SERVFAIL can happen for many reasons and may be transient.
                         * To avoid unnecessary downgrades retry once with the initial level.
                         * Check for clamp_feature_level_servfail having an invalid value as a sign that this is the
                         * first attempt to downgrade. If so, clamp to the current value so that the transaction
                         * is retried without actually downgrading. If the next try also fails we will downgrade by
                         * hitting the else branch below. */
                        if (DNS_PACKET_RCODE(p) == DNS_RCODE_SERVFAIL &&
                            t->clamp_feature_level_servfail < 0) {
                                t->clamp_feature_level_servfail = t->current_feature_level;
                                log_debug("Server returned error %s, retrying transaction.",
                                          FORMAT_DNS_RCODE(DNS_PACKET_RCODE(p)));
                        } else {
                                /* Reduce this feature level by one and try again. */
                                switch (t->current_feature_level) {
                                case DNS_SERVER_FEATURE_LEVEL_TLS_DO:
                                        t->clamp_feature_level_servfail = DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN;
                                        break;
                                case DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN + 1:
                                        /* Skip plain TLS when TLS is not supported */
                                        t->clamp_feature_level_servfail = DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN - 1;
                                        break;
                                default:
                                        t->clamp_feature_level_servfail = t->current_feature_level - 1;
                                }

                                log_debug("Server returned error %s, retrying transaction with reduced feature level %s.",
                                          FORMAT_DNS_RCODE(DNS_PACKET_RCODE(p)),
                                          dns_server_feature_level_to_string(t->clamp_feature_level_servfail));
                        }

                        dns_transaction_retry(t, false /* use the same server */);
                        return;
                }

                if (DNS_PACKET_RCODE(p) == DNS_RCODE_REFUSED) {
                        /* This server refused our request? If so, try again, use a different server */
                        log_debug("Server returned REFUSED, switching servers, and retrying.");

                        if (dns_transaction_limited_retry(t))
                                return;

                        break;
                }

                if (DNS_PACKET_TC(p))
                        dns_server_packet_truncated(t->server, t->current_feature_level);

                break;

        case DNS_PROTOCOL_LLMNR:
        case DNS_PROTOCOL_MDNS:
                dns_scope_packet_received(t->scope, p->timestamp - t->start_usec);
                break;

        default:
                assert_not_reached();
        }

        if (DNS_PACKET_TC(p)) {

                /* Truncated packets for mDNS are not allowed. Give up immediately. */
                if (t->scope->protocol == DNS_PROTOCOL_MDNS) {
                        dns_transaction_complete(t, DNS_TRANSACTION_INVALID_REPLY);
                        return;
                }

                /* Response was truncated, let's try again with good old TCP */
                log_debug("Reply truncated, retrying via TCP.");
                retry_with_tcp = true;

        } else if (t->scope->protocol == DNS_PROTOCOL_DNS &&
                   DNS_PACKET_IS_FRAGMENTED(p)) {

                /* Report the fragment size, so that we downgrade from LARGE to regular EDNS0 if needed */
                if (t->server)
                        dns_server_packet_udp_fragmented(t->server, dns_packet_size_unfragmented(p));

                if (t->current_feature_level > DNS_SERVER_FEATURE_LEVEL_UDP) {
                        /* Packet was fragmented. Let's retry with TCP to avoid fragmentation attack
                         * issues. (We don't do that on the lowest feature level however, since crappy DNS
                         * servers often do not implement TCP, hence falling back to TCP on fragmentation is
                         * counter-productive there.) */

                        log_debug("Reply fragmented, retrying via TCP. (Largest fragment size: %zu; Datagram size: %zu)",
                                  p->fragsize, p->size);
                        retry_with_tcp = true;
                }
        }

        if (retry_with_tcp) {
                r = dns_transaction_emit_tcp(t);
                if (r == -ESRCH) {
                        /* No servers found? Damn! */
                        dns_transaction_complete(t, DNS_TRANSACTION_NO_SERVERS);
                        return;
                }
                if (r == -EOPNOTSUPP) {
                        /* Tried to ask for DNSSEC RRs, on a server that doesn't do DNSSEC  */
                        dns_transaction_complete(t, DNS_TRANSACTION_RR_TYPE_UNSUPPORTED);
                        return;
                }
                if (r < 0) {
                        /* On LLMNR, if we cannot connect to the host,
                         * we immediately give up */
                        if (t->scope->protocol != DNS_PROTOCOL_DNS)
                                goto fail;

                        /* On DNS, couldn't send? Try immediately again, with a new server */
                        if (dns_transaction_limited_retry(t))
                                return;

                        /* No new server to try, give up */
                        dns_transaction_complete(t, DNS_TRANSACTION_ATTEMPTS_MAX_REACHED);
                }

                return;
        }

        /* After the superficial checks, actually parse the message. */
        r = dns_packet_extract(p);
        if (r < 0) {
                if (t->server) {
                        dns_server_packet_invalid(t->server, t->current_feature_level);

                        r = dns_transaction_maybe_restart(t);
                        if (r < 0)
                                goto fail;
                        if (r > 0) /* Transaction got restarted... */
                                return;
                }

                dns_transaction_complete(t, DNS_TRANSACTION_INVALID_REPLY);
                return;
        }

        if (t->server) {
                /* Report that we successfully received a valid packet with a good rcode after we initially got a bad
                 * rcode and subsequently downgraded the protocol */

                if (IN_SET(DNS_PACKET_RCODE(p), DNS_RCODE_SUCCESS, DNS_RCODE_NXDOMAIN) &&
                    t->clamp_feature_level_servfail != _DNS_SERVER_FEATURE_LEVEL_INVALID)
                        dns_server_packet_rcode_downgrade(t->server, t->clamp_feature_level_servfail);

                /* Report that the OPT RR was missing */
                if (!p->opt)
                        dns_server_packet_bad_opt(t->server, t->current_feature_level);

                /* Report that the server didn't copy our query DO bit from request to response */
                if (DNS_PACKET_DO(t->sent) && !DNS_PACKET_DO(t->received))
                        dns_server_packet_do_off(t->server, t->current_feature_level);

                /* Report that we successfully received a packet. We keep track of the largest packet
                 * size/fragment size we got. Which is useful for announcing the EDNS(0) packet size we can
                 * receive to our server. */
                dns_server_packet_received(t->server, p->ipproto, t->current_feature_level, dns_packet_size_unfragmented(p));
        }

        /* See if we know things we didn't know before that indicate we better restart the lookup immediately. */
        r = dns_transaction_maybe_restart(t);
        if (r < 0)
                goto fail;
        if (r > 0) /* Transaction got restarted... */
                return;

        /* When dealing with protocols other than mDNS only consider responses with equivalent query section
         * to the request. For mDNS this check doesn't make sense, because the section 6 of RFC6762 states
         * that "Multicast DNS responses MUST NOT contain any questions in the Question Section". */
        if (t->scope->protocol != DNS_PROTOCOL_MDNS) {
                r = dns_packet_is_reply_for(p, dns_transaction_key(t));
                if (r < 0)
                        goto fail;
                if (r == 0) {
                        dns_transaction_complete(t, DNS_TRANSACTION_INVALID_REPLY);
                        return;
                }
        }

        /* Install the answer as answer to the transaction. We ref the answer twice here: the main `answer`
         * field is later replaced by the DNSSEC validated subset. The 'answer_auxiliary' field carries the
         * original complete record set, including RRSIG and friends. We use this when passing data to
         * clients that ask for DNSSEC metadata. */
        DNS_ANSWER_REPLACE(t->answer, dns_answer_ref(p->answer));
        t->answer_rcode = DNS_PACKET_RCODE(p);
        t->answer_dnssec_result = _DNSSEC_RESULT_INVALID;
        SET_FLAG(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED, false);
        SET_FLAG(t->answer_query_flags, SD_RESOLVED_CONFIDENTIAL, encrypted);

        r = dns_transaction_fix_rcode(t);
        if (r < 0)
                goto fail;

        /* Block GC while starting requests for additional DNSSEC RRs */
        t->block_gc++;
        r = dns_transaction_request_dnssec_keys(t);
        t->block_gc--;

        /* Maybe the transaction is ready for GC'ing now? If so, free it and return. */
        if (!dns_transaction_gc(t))
                return;

        /* Requesting additional keys might have resulted in this transaction to fail, since the auxiliary
         * request failed for some reason. If so, we are not in pending state anymore, and we should exit
         * quickly. */
        if (t->state != DNS_TRANSACTION_PENDING)
                return;
        if (r < 0)
                goto fail;
        if (r > 0) {
                /* There are DNSSEC transactions pending now. Update the state accordingly. */
                t->state = DNS_TRANSACTION_VALIDATING;
                dns_transaction_close_connection(t, true);
                dns_transaction_stop_timeout(t);
                return;
        }

        dns_transaction_process_dnssec(t);
        return;

fail:
        dns_transaction_complete_errno(t, r);
}

static int on_dns_packet(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        DnsTransaction *t = ASSERT_PTR(userdata);
        int r;

        assert(t->scope);

        r = manager_recv(t->scope->manager, fd, DNS_PROTOCOL_DNS, &p);
        if (r < 0) {
                if (ERRNO_IS_DISCONNECT(r)) {
                        usec_t usec;

                        /* UDP connection failures get reported via ICMP and then are possibly delivered to us on the
                         * next recvmsg(). Treat this like a lost packet. */

                        log_debug_errno(r, "Connection failure for DNS UDP packet: %m");
                        assert_se(sd_event_now(t->scope->manager->event, CLOCK_BOOTTIME, &usec) >= 0);
                        dns_server_packet_lost(t->server, IPPROTO_UDP, t->current_feature_level);

                        dns_transaction_close_connection(t, /* use_graveyard = */ false);

                        if (dns_transaction_limited_retry(t)) /* Try a different server */
                                return 0;
                }
                dns_transaction_complete_errno(t, r);
                return 0;
        }
        if (r == 0)
                /* Spurious wakeup without any data */
                return 0;

        r = dns_packet_validate_reply(p);
        if (r < 0) {
                log_debug_errno(r, "Received invalid DNS packet as response, ignoring: %m");
                return 0;
        }
        if (r == 0) {
                log_debug("Received inappropriate DNS packet as response, ignoring.");
                return 0;
        }

        if (DNS_PACKET_ID(p) != t->id) {
                log_debug("Received packet with incorrect transaction ID, ignoring.");
                return 0;
        }

        dns_transaction_process_reply(t, p, false);
        return 0;
}

static int dns_transaction_emit_udp(DnsTransaction *t) {
        int r;

        assert(t);

        if (t->scope->protocol == DNS_PROTOCOL_DNS) {

                r = dns_transaction_pick_server(t);
                if (r < 0)
                        return r;

                if (manager_server_is_stub(t->scope->manager, t->server))
                        return -ELOOP;

                if (t->current_feature_level < DNS_SERVER_FEATURE_LEVEL_UDP || DNS_SERVER_FEATURE_LEVEL_IS_TLS(t->current_feature_level))
                        return -EAGAIN; /* Sorry, can't do UDP, try TCP! */

                if (!t->bypass && !dns_server_dnssec_supported(t->server) && dns_type_is_dnssec(dns_transaction_key(t)->type))
                        return -EOPNOTSUPP;

                if (r > 0 || t->dns_udp_fd < 0) { /* Server changed, or no connection yet. */
                        int fd;

                        dns_transaction_close_connection(t, true);

                        /* Before we allocate a new UDP socket, let's process the graveyard a bit to free some fds */
                        manager_socket_graveyard_process(t->scope->manager);

                        fd = dns_scope_socket_udp(t->scope, t->server);
                        if (fd < 0)
                                return fd;

                        r = sd_event_add_io(t->scope->manager->event, &t->dns_udp_event_source, fd, EPOLLIN, on_dns_packet, t);
                        if (r < 0) {
                                safe_close(fd);
                                return r;
                        }

                        (void) sd_event_source_set_description(t->dns_udp_event_source, "dns-transaction-udp");
                        t->dns_udp_fd = fd;
                }

                if (!t->bypass) {
                        r = dns_server_adjust_opt(t->server, t->sent, t->current_feature_level);
                        if (r < 0)
                                return r;
                }
        } else
                dns_transaction_close_connection(t, true);

        r = dns_scope_emit_udp(t->scope, t->dns_udp_fd, t->server ? t->server->family : AF_UNSPEC, t->sent);
        if (r < 0)
                return r;

        dns_transaction_reset_answer(t);

        return 0;
}

static int on_transaction_timeout(sd_event_source *s, usec_t usec, void *userdata) {
        DnsTransaction *t = ASSERT_PTR(userdata);

        assert(s);

        t->seen_timeout = true;

        if (t->initial_jitter_scheduled && !t->initial_jitter_elapsed) {
                log_debug("Initial jitter phase for transaction %" PRIu16 " elapsed.", t->id);
                t->initial_jitter_elapsed = true;
        } else {
                /* Timeout reached? Increase the timeout for the server used */
                switch (t->scope->protocol) {

                case DNS_PROTOCOL_DNS:
                        assert(t->server);
                        dns_server_packet_lost(t->server, t->stream ? IPPROTO_TCP : IPPROTO_UDP, t->current_feature_level);
                        break;

                case DNS_PROTOCOL_LLMNR:
                case DNS_PROTOCOL_MDNS:
                        dns_scope_packet_lost(t->scope, usec - t->start_usec);
                        break;

                default:
                        assert_not_reached();
                }

                log_debug("Timeout reached on transaction %" PRIu16 ".", t->id);
        }

        dns_transaction_retry(t, /* next_server= */ true); /* try a different server, but given this means
                                                            * packet loss, let's do so even if we already
                                                            * tried a bunch */
        return 0;
}

static int dns_transaction_setup_timeout(
                DnsTransaction *t,
                usec_t timeout_usec /* relative */,
                usec_t next_usec /* CLOCK_BOOTTIME */) {

        int r;

        assert(t);

        dns_transaction_stop_timeout(t);

        r = sd_event_add_time_relative(
                t->scope->manager->event,
                &t->timeout_event_source,
                CLOCK_BOOTTIME,
                timeout_usec, 0,
                on_transaction_timeout, t);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(t->timeout_event_source, "dns-transaction-timeout");

        t->next_attempt_after = next_usec;
        t->state = DNS_TRANSACTION_PENDING;
        return 0;
}

static usec_t transaction_get_resend_timeout(DnsTransaction *t) {
        assert(t);
        assert(t->scope);

        switch (t->scope->protocol) {

        case DNS_PROTOCOL_DNS:

                /* When we do TCP, grant a much longer timeout, as in this case there's no need for us to quickly
                 * resend, as the kernel does that anyway for us, and we really don't want to interrupt it in that
                 * needlessly. */
                if (t->stream)
                        return TRANSACTION_TCP_TIMEOUT_USEC;

                return DNS_TIMEOUT_USEC;

        case DNS_PROTOCOL_MDNS:
                if (t->probing)
                        return MDNS_PROBING_INTERVAL_USEC;

                /* See RFC 6762 Section 5.1 suggests that timeout should be a few seconds. */
                assert(t->n_attempts > 0);
                return (1 << (t->n_attempts - 1)) * USEC_PER_SEC;

        case DNS_PROTOCOL_LLMNR:
                return t->scope->resend_timeout;

        default:
                assert_not_reached();
        }
}

static void dns_transaction_randomize_answer(DnsTransaction *t) {
        int r;

        assert(t);

        /* Randomizes the order of the answer array. This is done for all cached responses, so that we return
         * a different order each time. We do this only for DNS traffic, in order to do some minimal, crappy
         * load balancing. We don't do this for LLMNR or mDNS, since the order (preferring link-local
         * addresses, and such like) might have meaning there, and load balancing is pointless. */

        if (t->scope->protocol != DNS_PROTOCOL_DNS)
                return;

        /* No point in randomizing, if there's just one RR */
        if (dns_answer_size(t->answer) <= 1)
                return;

        r = dns_answer_reserve_or_clone(&t->answer, 0);
        if (r < 0) /* If this fails, just don't randomize, this is non-essential stuff after all */
                return (void) log_debug_errno(r, "Failed to clone answer record, not randomizing RR order of answer: %m");

        dns_answer_randomize(t->answer);
}

static int dns_transaction_prepare(DnsTransaction *t, usec_t ts) {
        int r;

        assert(t);

        /* Returns 0 if dns_transaction_complete() has been called. In that case the transaction and query
         * candidate objects may have been invalidated and must not be accessed. Returns 1 if the transaction
         * has been prepared. */

        dns_transaction_stop_timeout(t);

        if (t->n_attempts == 1 && t->seen_timeout)
                t->scope->manager->n_timeouts_total++;

        if (!dns_scope_network_good(t->scope)) {
                dns_transaction_complete(t, DNS_TRANSACTION_NETWORK_DOWN);
                return 0;
        }

        if (t->n_attempts >= TRANSACTION_ATTEMPTS_MAX(t->scope->protocol)) {
                DnsTransactionState result;

                if (t->scope->protocol == DNS_PROTOCOL_LLMNR)
                        /* If we didn't find anything on LLMNR, it's not an error, but a failure to resolve
                         * the name. */
                        result = DNS_TRANSACTION_NOT_FOUND;
                else
                        result = DNS_TRANSACTION_ATTEMPTS_MAX_REACHED;

                dns_transaction_complete(t, result);
                return 0;
        }

        if (t->scope->protocol == DNS_PROTOCOL_LLMNR && t->tried_stream) {
                /* If we already tried via a stream, then we don't
                 * retry on LLMNR. See RFC 4795, Section 2.7. */
                dns_transaction_complete(t, DNS_TRANSACTION_ATTEMPTS_MAX_REACHED);
                return 0;
        }

        t->n_attempts++;
        t->start_usec = ts;

        dns_transaction_reset_answer(t);
        dns_transaction_flush_dnssec_transactions(t);

        /* Check the trust anchor. Do so only on classic DNS, since DNSSEC does not apply otherwise. */
        if (t->scope->protocol == DNS_PROTOCOL_DNS &&
            !FLAGS_SET(t->query_flags, SD_RESOLVED_NO_TRUST_ANCHOR)) {
                r = dns_trust_anchor_lookup_positive(&t->scope->manager->trust_anchor, dns_transaction_key(t), &t->answer);
                if (r < 0)
                        return r;
                if (r > 0) {
                        t->answer_rcode = DNS_RCODE_SUCCESS;
                        t->answer_source = DNS_TRANSACTION_TRUST_ANCHOR;
                        SET_FLAG(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED|SD_RESOLVED_CONFIDENTIAL, true);
                        dns_transaction_complete(t, DNS_TRANSACTION_SUCCESS);
                        return 0;
                }

                if (dns_name_is_root(dns_resource_key_name(dns_transaction_key(t))) &&
                    dns_transaction_key(t)->type == DNS_TYPE_DS) {

                        /* Hmm, this is a request for the root DS? A DS RR doesn't exist in the root zone,
                         * and if our trust anchor didn't know it either, this means we cannot do any DNSSEC
                         * logic anymore. */

                        if (t->scope->dnssec_mode == DNSSEC_ALLOW_DOWNGRADE) {
                                /* We are in downgrade mode. In this case, synthesize an unsigned empty
                                 * response, so that the any lookup depending on this one can continue
                                 * assuming there was no DS, and hence the root zone was unsigned. */

                                t->answer_rcode = DNS_RCODE_SUCCESS;
                                t->answer_source = DNS_TRANSACTION_TRUST_ANCHOR;
                                SET_FLAG(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED, false);
                                SET_FLAG(t->answer_query_flags, SD_RESOLVED_CONFIDENTIAL, true);
                                dns_transaction_complete(t, DNS_TRANSACTION_SUCCESS);
                        } else
                                /* If we are not in downgrade mode, then fail the lookup, because we cannot
                                 * reasonably answer it. There might be DS RRs, but we don't know them, and
                                 * the DNS server won't tell them to us (and even if it would, we couldn't
                                 * validate and trust them. */
                                dns_transaction_complete(t, DNS_TRANSACTION_NO_TRUST_ANCHOR);

                        return 0;
                }
        }

        /* Check the zone. */
        if (!FLAGS_SET(t->query_flags, SD_RESOLVED_NO_ZONE)) {
                r = dns_zone_lookup(&t->scope->zone, dns_transaction_key(t), dns_scope_ifindex(t->scope), &t->answer, NULL, NULL);
                if (r < 0)
                        return r;
                if (r > 0) {
                        t->answer_rcode = DNS_RCODE_SUCCESS;
                        t->answer_source = DNS_TRANSACTION_ZONE;
                        SET_FLAG(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED|SD_RESOLVED_CONFIDENTIAL, true);
                        dns_transaction_complete(t, DNS_TRANSACTION_SUCCESS);
                        return 0;
                }
        }

        /* Check the cache. */
        if (!FLAGS_SET(t->query_flags, SD_RESOLVED_NO_CACHE)) {

                /* Before trying the cache, let's make sure we figured out a server to use. Should this cause
                 * a change of server this might flush the cache. */
                (void) dns_scope_get_dns_server(t->scope);

                /* Let's then prune all outdated entries */
                dns_cache_prune(&t->scope->cache);

                /* For the initial attempt or when no stale data is requested, disable serve stale
                 * and answer the question from the cache (honors ttl property).
                 * On the second attempt, if StaleRetentionSec is greater than zero,
                 * try to answer the question using stale date (honors until property) */
                uint64_t query_flags = t->query_flags;
                if (t->n_attempts == 1 || t->scope->manager->stale_retention_usec == 0)
                        query_flags |= SD_RESOLVED_NO_STALE;

                r = dns_cache_lookup(
                                &t->scope->cache,
                                dns_transaction_key(t),
                                query_flags,
                                &t->answer_rcode,
                                &t->answer,
                                &t->received,
                                &t->answer_query_flags,
                                &t->answer_dnssec_result);
                if (r < 0)
                        return r;
                if (r > 0) {
                        dns_transaction_randomize_answer(t);

                        if (t->bypass && t->scope->protocol == DNS_PROTOCOL_DNS && !t->received)
                                /* When bypass mode is on, do not use cached data unless it came with a full
                                 * packet. */
                                dns_transaction_reset_answer(t);
                        else {
                                if (t->n_attempts > 1 && !FLAGS_SET(query_flags, SD_RESOLVED_NO_STALE)) {

                                        if (t->answer_rcode == DNS_RCODE_SUCCESS) {
                                                if (t->seen_timeout)
                                                        t->scope->manager->n_timeouts_served_stale_total++;
                                                else
                                                        t->scope->manager->n_failure_responses_served_stale_total++;
                                        }

                                        char key_str[DNS_RESOURCE_KEY_STRING_MAX];
                                        log_debug("Serve Stale response rcode=%s for %s",
                                                FORMAT_DNS_RCODE(t->answer_rcode),
                                                dns_resource_key_to_string(dns_transaction_key(t), key_str, sizeof key_str));
                                }

                                t->answer_source = DNS_TRANSACTION_CACHE;
                                if (t->answer_rcode == DNS_RCODE_SUCCESS)
                                        dns_transaction_complete(t, DNS_TRANSACTION_SUCCESS);
                                else
                                        dns_transaction_complete(t, DNS_TRANSACTION_RCODE_FAILURE);
                                return 0;
                        }
                }
        }

        if (FLAGS_SET(t->query_flags, SD_RESOLVED_NO_NETWORK)) {
                dns_transaction_complete(t, DNS_TRANSACTION_NO_SOURCE);
                return 0;
        }

        return 1;
}

static int dns_packet_append_zone(DnsPacket *p, DnsTransaction *t, DnsResourceKey *k, unsigned *nscount) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        bool tentative;
        int r;

        assert(p);
        assert(t);
        assert(k);

        if (k->type != DNS_TYPE_ANY)
                return 0;

        r = dns_zone_lookup(&t->scope->zone, k, t->scope->link->ifindex, &answer, NULL, &tentative);
        if (r < 0)
                return r;

        return dns_packet_append_answer(p, answer, nscount);
}

static int mdns_make_dummy_packet(DnsTransaction *t, DnsPacket **ret_packet, Set **ret_keys) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        _cleanup_set_free_ Set *keys = NULL;
        bool add_known_answers = false;
        unsigned qdcount;
        usec_t ts;
        int r;

        assert(t);
        assert(t->scope);
        assert(t->scope->protocol == DNS_PROTOCOL_MDNS);
        assert(ret_packet);
        assert(ret_keys);

        r = dns_packet_new_query(&p, t->scope->protocol, 0, false);
        if (r < 0)
                return r;

        r = dns_packet_append_key(p, dns_transaction_key(t), 0, NULL);
        if (r < 0)
                return r;

        qdcount = 1;

        if (dns_key_is_shared(dns_transaction_key(t)))
                add_known_answers = true;

        r = dns_packet_append_zone(p, t, dns_transaction_key(t), NULL);
        if (r < 0)
                return r;

        /* Save appended keys */
        r = set_ensure_put(&keys, &dns_resource_key_hash_ops, dns_transaction_key(t));
        if (r < 0)
                return r;

        assert_se(sd_event_now(t->scope->manager->event, CLOCK_BOOTTIME, &ts) >= 0);

        LIST_FOREACH(transactions_by_scope, other, t->scope->transactions) {

                /* Skip ourselves */
                if (other == t)
                        continue;

                if (other->state != DNS_TRANSACTION_PENDING)
                        continue;

                if (other->next_attempt_after > ts)
                        continue;

                if (!set_contains(keys, dns_transaction_key(other))) {
                        size_t saved_packet_size;

                        r = dns_packet_append_key(p, dns_transaction_key(other), 0, &saved_packet_size);
                        /* If we can't stuff more questions into the packet, just give up.
                         * One of the 'other' transactions will fire later and take care of the rest. */
                        if (r == -EMSGSIZE)
                                break;
                        if (r < 0)
                                return r;

                        r = dns_packet_append_zone(p, t, dns_transaction_key(other), NULL);
                        if (r == -EMSGSIZE) {
                                dns_packet_truncate(p, saved_packet_size);
                                break;
                        }
                        if (r < 0)
                                return r;

                        r = set_ensure_put(&keys, &dns_resource_key_hash_ops, dns_transaction_key(other));
                        if (r < 0)
                                return r;
                }

                r = dns_transaction_prepare(other, ts);
                if (r < 0)
                        return r;
                if (r == 0)
                        /* In this case, not only this transaction, but multiple transactions may be
                         * freed. Hence, we need to restart the loop. */
                        return -EAGAIN;

                usec_t timeout = transaction_get_resend_timeout(other);
                r = dns_transaction_setup_timeout(other, timeout, usec_add(ts, timeout));
                if (r < 0)
                        return r;

                if (dns_key_is_shared(dns_transaction_key(other)))
                        add_known_answers = true;

                qdcount++;
                if (qdcount >= UINT16_MAX)
                        break;
        }

        DNS_PACKET_HEADER(p)->qdcount = htobe16(qdcount);

        /* Append known answers section if we're asking for any shared record */
        if (add_known_answers) {
                r = dns_cache_export_shared_to_packet(&t->scope->cache, p, ts, 0);
                if (r < 0)
                        return r;
        }

        *ret_packet = TAKE_PTR(p);
        *ret_keys = TAKE_PTR(keys);
        return add_known_answers;
}

static int dns_transaction_make_packet_mdns(DnsTransaction *t) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL, *dummy = NULL;
        _cleanup_set_free_ Set *keys = NULL;
        bool add_known_answers;
        DnsResourceKey *k;
        unsigned c;
        int r;

        assert(t);
        assert(t->scope->protocol == DNS_PROTOCOL_MDNS);

        /* Discard any previously prepared packet, so we can start over and coalesce again */
        t->sent = dns_packet_unref(t->sent);

        /* First, create a dummy packet to calculate the number of known answers to be appended in the first packet. */
        for (;;) {
                r = mdns_make_dummy_packet(t, &dummy, &keys);
                if (r == -EAGAIN)
                        continue;
                if (r < 0)
                        return r;

                add_known_answers = r;
                break;
        }

        /* Then, create actual packet. */
        r = dns_packet_new_query(&p, t->scope->protocol, 0, false);
        if (r < 0)
                return r;

        /* Questions */
        c = 0;
        SET_FOREACH(k, keys) {
                r = dns_packet_append_key(p, k, 0, NULL);
                if (r < 0)
                        return r;
                c++;
        }
        DNS_PACKET_HEADER(p)->qdcount = htobe16(c);

        /* Known answers */
        if (add_known_answers) {
                usec_t ts;

                assert_se(sd_event_now(t->scope->manager->event, CLOCK_BOOTTIME, &ts) >= 0);

                r = dns_cache_export_shared_to_packet(&t->scope->cache, p, ts, be16toh(DNS_PACKET_HEADER(dummy)->ancount));
                if (r < 0)
                        return r;
        }

        /* Authorities */
        c = 0;
        SET_FOREACH(k, keys) {
                r = dns_packet_append_zone(p, t, k, &c);
                if (r < 0)
                        return r;
        }
        DNS_PACKET_HEADER(p)->nscount = htobe16(c);

        t->sent = TAKE_PTR(p);
        return 0;
}

static int dns_transaction_make_packet(DnsTransaction *t) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        int r;

        assert(t);

        if (t->scope->protocol == DNS_PROTOCOL_MDNS)
                return dns_transaction_make_packet_mdns(t);

        if (t->sent)
                return 0;

        if (t->bypass && t->bypass->protocol == t->scope->protocol) {
                /* If bypass logic is enabled and the protocol if the original packet and our scope match,
                 * take the original packet, copy it, and patch in our new ID */
                r = dns_packet_dup(&p, t->bypass);
                if (r < 0)
                        return r;
        } else {
                r = dns_packet_new_query(
                                &p, t->scope->protocol,
                                /* min_alloc_dsize = */ 0,
                                /* dnssec_cd = */ !FLAGS_SET(t->query_flags, SD_RESOLVED_NO_VALIDATE) &&
                                                  t->scope->dnssec_mode != DNSSEC_NO);
                if (r < 0)
                        return r;

                r = dns_packet_append_key(p, dns_transaction_key(t), 0, NULL);
                if (r < 0)
                        return r;

                DNS_PACKET_HEADER(p)->qdcount = htobe16(1);
        }

        DNS_PACKET_HEADER(p)->id = t->id;

        t->sent = TAKE_PTR(p);
        return 0;
}

int dns_transaction_go(DnsTransaction *t) {
        usec_t ts;
        int r;
        char key_str[DNS_RESOURCE_KEY_STRING_MAX];

        assert(t);

        /* Returns > 0 if the transaction is now pending, returns 0 if could be processed immediately and has
         * finished now. In the latter case, the transaction and query candidate objects must not be accessed.
         */

        assert_se(sd_event_now(t->scope->manager->event, CLOCK_BOOTTIME, &ts) >= 0);

        r = dns_transaction_prepare(t, ts);
        if (r <= 0)
                return r;

        log_debug("Firing %s transaction %" PRIu16 " for <%s> scope %s on %s/%s (validate=%s).",
                  t->bypass ? "bypass" : "regular",
                  t->id,
                  dns_resource_key_to_string(dns_transaction_key(t), key_str, sizeof key_str),
                  dns_protocol_to_string(t->scope->protocol),
                  t->scope->link ? t->scope->link->ifname : "*",
                  af_to_name_short(t->scope->family),
                  yes_no(!FLAGS_SET(t->query_flags, SD_RESOLVED_NO_VALIDATE)));

        if (!t->initial_jitter_scheduled &&
            IN_SET(t->scope->protocol, DNS_PROTOCOL_LLMNR, DNS_PROTOCOL_MDNS)) {
                usec_t jitter;

                /* RFC 4795 Section 2.7 suggests all LLMNR queries should be delayed by a random time from 0 to
                 * JITTER_INTERVAL.
                 * RFC 6762 Section 8.1 suggests initial probe queries should be delayed by a random time from
                 * 0 to 250ms. */

                t->initial_jitter_scheduled = true;
                t->n_attempts = 0;

                switch (t->scope->protocol) {

                case DNS_PROTOCOL_LLMNR:
                        jitter = random_u64_range(LLMNR_JITTER_INTERVAL_USEC);
                        break;

                case DNS_PROTOCOL_MDNS:
                        if (t->probing)
                                jitter = random_u64_range(MDNS_PROBING_INTERVAL_USEC);
                        else
                                jitter = 0;
                        break;
                default:
                        assert_not_reached();
                }

                r = dns_transaction_setup_timeout(t, jitter, ts);
                if (r < 0)
                        return r;

                log_debug("Delaying %s transaction %" PRIu16 " for " USEC_FMT "us.",
                          dns_protocol_to_string(t->scope->protocol),
                          t->id,
                          jitter);
                return 1;
        }

        /* Otherwise, we need to ask the network */
        r = dns_transaction_make_packet(t);
        if (r < 0)
                return r;

        if (t->scope->protocol == DNS_PROTOCOL_LLMNR &&
            (dns_name_endswith(dns_resource_key_name(dns_transaction_key(t)), "in-addr.arpa") > 0 ||
             dns_name_endswith(dns_resource_key_name(dns_transaction_key(t)), "ip6.arpa") > 0)) {

                /* RFC 4795, Section 2.4. says reverse lookups shall
                 * always be made via TCP on LLMNR */
                r = dns_transaction_emit_tcp(t);
        } else {
                /* Try via UDP, and if that fails due to large size or lack of
                 * support try via TCP */
                r = dns_transaction_emit_udp(t);
                if (r == -EMSGSIZE)
                        log_debug("Sending query via TCP since it is too large.");
                else if (r == -EAGAIN)
                        log_debug("Sending query via TCP since UDP isn't supported or DNS-over-TLS is selected.");
                else if (r == -EPERM)
                        log_debug("Sending query via TCP since UDP is blocked.");
                if (IN_SET(r, -EMSGSIZE, -EAGAIN, -EPERM))
                        r = dns_transaction_emit_tcp(t);
        }
        if (r == -ELOOP) {
                if (t->scope->protocol != DNS_PROTOCOL_DNS)
                        return r;

                /* One of our own stub listeners */
                log_debug_errno(r, "Detected that specified DNS server is our own extra listener, switching DNS servers.");

                dns_scope_next_dns_server(t->scope, t->server);

                if (dns_scope_get_dns_server(t->scope) == t->server) {
                        log_debug_errno(r, "Still pointing to extra listener after switching DNS servers, refusing operation.");
                        dns_transaction_complete(t, DNS_TRANSACTION_STUB_LOOP);
                        return 0;
                }

                return dns_transaction_go(t);
        }
        if (r == -ESRCH) {
                /* No servers to send this to? */
                dns_transaction_complete(t, DNS_TRANSACTION_NO_SERVERS);
                return 0;
        }
        if (r == -EOPNOTSUPP) {
                /* Tried to ask for DNSSEC RRs, on a server that doesn't do DNSSEC  */
                dns_transaction_complete(t, DNS_TRANSACTION_RR_TYPE_UNSUPPORTED);
                return 0;
        }
        if (t->scope->protocol == DNS_PROTOCOL_LLMNR && ERRNO_IS_NEG_DISCONNECT(r)) {
                /* On LLMNR, if we cannot connect to a host via TCP when doing reverse lookups. This means we cannot
                 * answer this request with this protocol. */
                dns_transaction_complete(t, DNS_TRANSACTION_NOT_FOUND);
                return 0;
        }
        if (r < 0) {
                if (t->scope->protocol != DNS_PROTOCOL_DNS)
                        return r;

                /* Couldn't send? Try immediately again, with a new server */
                dns_scope_next_dns_server(t->scope, t->server);

                return dns_transaction_go(t);
        }

        usec_t timeout = transaction_get_resend_timeout(t);
        r = dns_transaction_setup_timeout(t, timeout, usec_add(ts, timeout));
        if (r < 0)
                return r;

        return 1;
}

static int dns_transaction_find_cyclic(DnsTransaction *t, DnsTransaction *aux) {
        DnsTransaction *n;
        int r;

        assert(t);
        assert(aux);

        /* Try to find cyclic dependencies between transaction objects */

        if (t == aux)
                return 1;

        SET_FOREACH(n, aux->dnssec_transactions) {
                r = dns_transaction_find_cyclic(t, n);
                if (r != 0)
                        return r;
        }

        return 0;
}

static int dns_transaction_add_dnssec_transaction(DnsTransaction *t, DnsResourceKey *key, DnsTransaction **ret) {
        _cleanup_(dns_transaction_gcp) DnsTransaction *aux = NULL;
        int r;

        assert(t);
        assert(ret);
        assert(key);

        aux = dns_scope_find_transaction(t->scope, key, t->query_flags);
        if (!aux) {
                r = dns_transaction_new(&aux, t->scope, key, NULL, t->query_flags);
                if (r < 0)
                        return r;
        } else {
                if (set_contains(t->dnssec_transactions, aux)) {
                        *ret = aux;
                        return 0;
                }

                r = dns_transaction_find_cyclic(t, aux);
                if (r < 0)
                        return r;
                if (r > 0) {
                        char s[DNS_RESOURCE_KEY_STRING_MAX], saux[DNS_RESOURCE_KEY_STRING_MAX];

                        return log_debug_errno(SYNTHETIC_ERRNO(ELOOP),
                                               "Potential cyclic dependency, refusing to add transaction %" PRIu16 " (%s) as dependency for %" PRIu16 " (%s).",
                                               aux->id,
                                               dns_resource_key_to_string(dns_transaction_key(t), s, sizeof s),
                                               t->id,
                                               dns_resource_key_to_string(dns_transaction_key(aux), saux, sizeof saux));
                }
        }

        r = set_ensure_allocated(&aux->notify_transactions_done, NULL);
        if (r < 0)
                return r;

        r = set_ensure_put(&t->dnssec_transactions, NULL, aux);
        if (r < 0)
                return r;

        r = set_ensure_put(&aux->notify_transactions, NULL, t);
        if (r < 0) {
                (void) set_remove(t->dnssec_transactions, aux);
                return r;
        }

        *ret = TAKE_PTR(aux);
        return 1;
}

static int dns_transaction_request_dnssec_rr(DnsTransaction *t, DnsResourceKey *key) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL;
        DnsTransaction *aux;
        int r;

        assert(t);
        assert(key);

        /* Try to get the data from the trust anchor */
        r = dns_trust_anchor_lookup_positive(&t->scope->manager->trust_anchor, key, &a);
        if (r < 0)
                return r;
        if (r > 0) {
                r = dns_answer_extend(&t->validated_keys, a);
                if (r < 0)
                        return r;

                return 0;
        }

        /* This didn't work, ask for it via the network/cache then. */
        r = dns_transaction_add_dnssec_transaction(t, key, &aux);
        if (r == -ELOOP) /* This would result in a cyclic dependency */
                return 0;
        if (r < 0)
                return r;

        if (aux->state == DNS_TRANSACTION_NULL) {
                r = dns_transaction_go(aux);
                if (r < 0)
                        return r;
        }

        return 1;
}

static int dns_transaction_negative_trust_anchor_lookup(DnsTransaction *t, const char *name) {
        int r;

        assert(t);

        /* Check whether the specified name is in the NTA
         * database, either in the global one, or the link-local
         * one. */

        r = dns_trust_anchor_lookup_negative(&t->scope->manager->trust_anchor, name);
        if (r != 0)
                return r;

        if (!t->scope->link)
                return 0;

        return link_negative_trust_anchor_lookup(t->scope->link, name);
}

static int dns_transaction_has_negative_answer(DnsTransaction *t) {
        int r;

        assert(t);

        /* Checks whether the answer is negative, and lacks NSEC/NSEC3
         * RRs to prove it */

        r = dns_transaction_has_positive_answer(t, NULL);
        if (r < 0)
                return r;
        if (r > 0)
                return false;

        /* Is this key explicitly listed as a negative trust anchor?
         * If so, it's nothing we need to care about */
        r = dns_transaction_negative_trust_anchor_lookup(t, dns_resource_key_name(dns_transaction_key(t)));
        if (r < 0)
                return r;
        return !r;
}

static int dns_transaction_is_primary_response(DnsTransaction *t, DnsResourceRecord *rr) {
        int r;

        assert(t);
        assert(rr);

        /* Check if the specified RR is the "primary" response,
         * i.e. either matches the question precisely or is a
         * CNAME/DNAME for it. */

        r = dns_resource_key_match_rr(dns_transaction_key(t), rr, NULL);
        if (r != 0)
                return r;

        return dns_resource_key_match_cname_or_dname(dns_transaction_key(t), rr->key, NULL);
}

static bool dns_transaction_dnssec_supported(DnsTransaction *t) {
        assert(t);

        /* Checks whether our transaction's DNS server is assumed to be compatible with DNSSEC. Returns false as soon
         * as we changed our mind about a server, and now believe it is incompatible with DNSSEC. */

        if (t->scope->protocol != DNS_PROTOCOL_DNS)
                return false;

        /* If we have picked no server, then we are working from the cache or some other source, and DNSSEC might well
         * be supported, hence return true. */
        if (!t->server)
                return true;

        /* Note that we do not check the feature level actually used for the transaction but instead the feature level
         * the server is known to support currently, as the transaction feature level might be lower than what the
         * server actually supports, since we might have downgraded this transaction's feature level because we got a
         * SERVFAIL earlier and wanted to check whether downgrading fixes it. */

        return dns_server_dnssec_supported(t->server);
}

static bool dns_transaction_dnssec_supported_full(DnsTransaction *t) {
        DnsTransaction *dt;

        assert(t);

        /* Checks whether our transaction our any of the auxiliary transactions couldn't do DNSSEC. */

        if (!dns_transaction_dnssec_supported(t))
                return false;

        SET_FOREACH(dt, t->dnssec_transactions)
                if (!dns_transaction_dnssec_supported(dt))
                        return false;

        return true;
}

int dns_transaction_request_dnssec_keys(DnsTransaction *t) {
        DnsResourceRecord *rr;

        int r;

        assert(t);

        /*
         * Retrieve all auxiliary RRs for the answer we got, so that
         * we can verify signatures or prove that RRs are rightfully
         * unsigned. Specifically:
         *
         * - For RRSIG we get the matching DNSKEY
         * - For DNSKEY we get the matching DS
         * - For unsigned SOA/NS we get the matching DS
         * - For unsigned CNAME/DNAME/DS we get the parent SOA RR
         * - For other unsigned RRs we get the matching SOA RR
         * - For SOA/NS queries with no matching response RR, and no NSEC/NSEC3, the DS RR
         * - For DS queries with no matching response RRs, and no NSEC/NSEC3, the parent's SOA RR
         * - For other queries with no matching response RRs, and no NSEC/NSEC3, the SOA RR
         */

        if (FLAGS_SET(t->query_flags, SD_RESOLVED_NO_VALIDATE) || t->scope->dnssec_mode == DNSSEC_NO)
                return 0;
        if (t->answer_source != DNS_TRANSACTION_NETWORK)
                return 0; /* We only need to validate stuff from the network */
        if (!dns_transaction_dnssec_supported(t))
                return 0; /* If we can't do DNSSEC anyway there's no point in getting the auxiliary RRs */

        DNS_ANSWER_FOREACH(rr, t->answer) {

                if (dns_type_is_pseudo(rr->key->type))
                        continue;

                /* If this RR is in the negative trust anchor, we don't need to validate it. */
                r = dns_transaction_negative_trust_anchor_lookup(t, dns_resource_key_name(rr->key));
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                switch (rr->key->type) {

                case DNS_TYPE_RRSIG: {
                        /* For each RRSIG we request the matching DNSKEY */
                        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *dnskey = NULL;

                        /* If this RRSIG is about a DNSKEY RR and the
                         * signer is the same as the owner, then we
                         * already have the DNSKEY, and we don't have
                         * to look for more. */
                        if (rr->rrsig.type_covered == DNS_TYPE_DNSKEY) {
                                r = dns_name_equal(rr->rrsig.signer, dns_resource_key_name(rr->key));
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        continue;
                        }

                        /* If the signer is not a parent of our
                         * original query, then this is about an
                         * auxiliary RRset, but not anything we asked
                         * for. In this case we aren't interested,
                         * because we don't want to request additional
                         * RRs for stuff we didn't really ask for, and
                         * also to avoid request loops, where
                         * additional RRs from one transaction result
                         * in another transaction whose additional RRs
                         * point back to the original transaction, and
                         * we deadlock. */
                        r = dns_name_endswith(dns_resource_key_name(dns_transaction_key(t)), rr->rrsig.signer);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        dnskey = dns_resource_key_new(rr->key->class, DNS_TYPE_DNSKEY, rr->rrsig.signer);
                        if (!dnskey)
                                return -ENOMEM;

                        log_debug("Requesting DNSKEY to validate transaction %" PRIu16" (%s, RRSIG with key tag: %" PRIu16 ").",
                                  t->id, dns_resource_key_name(rr->key), rr->rrsig.key_tag);
                        r = dns_transaction_request_dnssec_rr(t, dnskey);
                        if (r < 0)
                                return r;
                        break;
                }

                case DNS_TYPE_DNSKEY: {
                        /* For each DNSKEY we request the matching DS */
                        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *ds = NULL;

                        /* If the DNSKEY we are looking at is not for
                         * zone we are interested in, nor any of its
                         * parents, we aren't interested, and don't
                         * request it. After all, we don't want to end
                         * up in request loops, and want to keep
                         * additional traffic down. */

                        r = dns_name_endswith(dns_resource_key_name(dns_transaction_key(t)), dns_resource_key_name(rr->key));
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        ds = dns_resource_key_new(rr->key->class, DNS_TYPE_DS, dns_resource_key_name(rr->key));
                        if (!ds)
                                return -ENOMEM;

                        log_debug("Requesting DS to validate transaction %" PRIu16" (%s, DNSKEY with key tag: %" PRIu16 ").",
                                  t->id, dns_resource_key_name(rr->key), dnssec_keytag(rr, false));
                        r = dns_transaction_request_dnssec_rr(t, ds);
                        if (r < 0)
                                return r;

                        break;
                }

                case DNS_TYPE_SOA:
                case DNS_TYPE_NS: {
                        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *ds = NULL;

                        /* For an unsigned SOA or NS, try to acquire
                         * the matching DS RR, as we are at a zone cut
                         * then, and whether a DS exists tells us
                         * whether the zone is signed. Do so only if
                         * this RR matches our original question,
                         * however. */

                        r = dns_resource_key_match_rr(dns_transaction_key(t), rr, NULL);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                /* Hmm, so this SOA RR doesn't match our original question. In this case, maybe this is
                                 * a negative reply, and we need the SOA RR's TTL in order to cache a negative entry?
                                 * If so, we need to validate it, too. */

                                r = dns_answer_match_key(t->answer, dns_transaction_key(t), NULL);
                                if (r < 0)
                                        return r;
                                if (r > 0) /* positive reply, we won't need the SOA and hence don't need to validate
                                            * it. */
                                        continue;

                                /* Only bother with this if the SOA/NS RR we are looking at is actually a parent of
                                 * what we are looking for, otherwise there's no value in it for us. */
                                r = dns_name_endswith(dns_resource_key_name(dns_transaction_key(t)), dns_resource_key_name(rr->key));
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;
                        }

                        r = dnssec_has_rrsig(t->answer, rr->key);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                continue;

                        ds = dns_resource_key_new(rr->key->class, DNS_TYPE_DS, dns_resource_key_name(rr->key));
                        if (!ds)
                                return -ENOMEM;

                        log_debug("Requesting DS to validate transaction %" PRIu16 " (%s, unsigned SOA/NS RRset).",
                                  t->id, dns_resource_key_name(rr->key));
                        r = dns_transaction_request_dnssec_rr(t, ds);
                        if (r < 0)
                                return r;

                        break;
                }

                case DNS_TYPE_DS:
                case DNS_TYPE_CNAME:
                case DNS_TYPE_DNAME: {
                        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *soa = NULL;
                        const char *name;

                        /* CNAMEs and DNAMEs cannot be located at a
                         * zone apex, hence ask for the parent SOA for
                         * unsigned CNAME/DNAME RRs, maybe that's the
                         * apex. But do all that only if this is
                         * actually a response to our original
                         * question.
                         *
                         * Similar for DS RRs, which are signed when
                         * the parent SOA is signed. */

                        r = dns_transaction_is_primary_response(t, rr);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        r = dnssec_has_rrsig(t->answer, rr->key);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                continue;

                        r = dns_answer_has_dname_for_cname(t->answer, rr);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                continue;

                        name = dns_resource_key_name(rr->key);
                        r = dns_name_parent(&name);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        soa = dns_resource_key_new(rr->key->class, DNS_TYPE_SOA, name);
                        if (!soa)
                                return -ENOMEM;

                        log_debug("Requesting parent SOA to validate transaction %" PRIu16 " (%s, unsigned CNAME/DNAME/DS RRset).",
                                  t->id, dns_resource_key_name(rr->key));
                        r = dns_transaction_request_dnssec_rr(t, soa);
                        if (r < 0)
                                return r;

                        break;
                }

                default: {
                        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *soa = NULL;

                        /* For other unsigned RRsets (including
                         * NSEC/NSEC3!), look for proof the zone is
                         * unsigned, by requesting the SOA RR of the
                         * zone. However, do so only if they are
                         * directly relevant to our original
                         * question. */

                        r = dns_transaction_is_primary_response(t, rr);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        r = dnssec_has_rrsig(t->answer, rr->key);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                continue;

                        soa = dns_resource_key_new(rr->key->class, DNS_TYPE_SOA, dns_resource_key_name(rr->key));
                        if (!soa)
                                return -ENOMEM;

                        log_debug("Requesting SOA to validate transaction %" PRIu16 " (%s, unsigned non-SOA/NS RRset <%s>).",
                                  t->id, dns_resource_key_name(rr->key), dns_resource_record_to_string(rr));
                        r = dns_transaction_request_dnssec_rr(t, soa);
                        if (r < 0)
                                return r;
                        break;
                }}
        }

        /* Above, we requested everything necessary to validate what
         * we got. Now, let's request what we need to validate what we
         * didn't get... */

        r = dns_transaction_has_negative_answer(t);
        if (r < 0)
                return r;
        if (r > 0) {
                const char *name, *signed_status;
                uint16_t type = 0;

                name = dns_resource_key_name(dns_transaction_key(t));
                signed_status = dns_answer_contains_nsec_or_nsec3(t->answer) ? "signed" : "unsigned";

                /* If this was a SOA or NS request, then check if there's a DS RR for the same domain. Note that this
                 * could also be used as indication that we are not at a zone apex, but in real world setups there are
                 * too many broken DNS servers (Hello, incapdns.net!) where non-terminal zones return NXDOMAIN even
                 * though they have further children. If this was a DS request, then it's signed when the parent zone
                 * is signed, hence ask the parent SOA in that case. If this was any other RR then ask for the SOA RR,
                 * to see if that is signed. */

                if (dns_transaction_key(t)->type == DNS_TYPE_DS) {
                        r = dns_name_parent(&name);
                        if (r > 0) {
                                type = DNS_TYPE_SOA;
                                log_debug("Requesting parent SOA (%s %s) to validate transaction %" PRIu16 " (%s, %s empty DS response).",
                                          special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), name, t->id,
                                          dns_resource_key_name(dns_transaction_key(t)), signed_status);
                        } else
                                name = NULL;

                } else if (IN_SET(dns_transaction_key(t)->type, DNS_TYPE_SOA, DNS_TYPE_NS)) {

                        type = DNS_TYPE_DS;
                        log_debug("Requesting DS (%s %s) to validate transaction %" PRIu16 " (%s, %s empty SOA/NS response).",
                                  special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), name, t->id, name, signed_status);

                } else {
                        type = DNS_TYPE_SOA;
                        log_debug("Requesting SOA (%s %s) to validate transaction %" PRIu16 " (%s, %s empty non-SOA/NS/DS response).",
                                  special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), name, t->id, name, signed_status);
                }

                if (name) {
                        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *soa = NULL;

                        soa = dns_resource_key_new(dns_transaction_key(t)->class, type, name);
                        if (!soa)
                                return -ENOMEM;

                        r = dns_transaction_request_dnssec_rr(t, soa);
                        if (r < 0)
                                return r;
                }
        }

        return dns_transaction_dnssec_is_live(t);
}

void dns_transaction_notify(DnsTransaction *t, DnsTransaction *source) {
        assert(t);
        assert(source);

        /* Invoked whenever any of our auxiliary DNSSEC transactions completed its work. If the state is still PENDING,
           we are still in the loop that adds further DNSSEC transactions, hence don't check if we are ready yet. If
           the state is VALIDATING however, we should check if we are complete now. */

        if (t->state == DNS_TRANSACTION_VALIDATING)
                dns_transaction_process_dnssec(t);
}

static int dns_transaction_validate_dnskey_by_ds(DnsTransaction *t) {
        DnsAnswerItem *item;
        int r;

        assert(t);

        /* Add all DNSKEY RRs from the answer that are validated by DS
         * RRs from the list of validated keys to the list of
         * validated keys. */

        DNS_ANSWER_FOREACH_ITEM(item, t->answer) {

                r = dnssec_verify_dnskey_by_ds_search(item->rr, t->validated_keys);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                /* If so, the DNSKEY is validated too. */
                r = dns_answer_add_extend(&t->validated_keys, item->rr, item->ifindex, item->flags|DNS_ANSWER_AUTHENTICATED, item->rrsig);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dns_transaction_requires_rrsig(DnsTransaction *t, DnsResourceRecord *rr) {
        int r;

        assert(t);
        assert(rr);

        /* Checks if the RR we are looking for must be signed with an
         * RRSIG. This is used for positive responses. */

        if (t->scope->dnssec_mode == DNSSEC_NO)
                return false;

        if (dns_type_is_pseudo(rr->key->type))
                return -EINVAL;

        r = dns_transaction_negative_trust_anchor_lookup(t, dns_resource_key_name(rr->key));
        if (r < 0)
                return r;
        if (r > 0)
                return false;

        switch (rr->key->type) {

        case DNS_TYPE_RRSIG:
                /* RRSIGs are the signatures themselves, they need no signing. */
                return false;

        case DNS_TYPE_SOA:
        case DNS_TYPE_NS: {
                DnsTransaction *dt;

                /* For SOA or NS RRs we look for a matching DS transaction */

                SET_FOREACH(dt, t->dnssec_transactions) {

                        if (dns_transaction_key(dt)->class != rr->key->class)
                                continue;
                        if (dns_transaction_key(dt)->type != DNS_TYPE_DS)
                                continue;

                        r = dns_name_equal(dns_resource_key_name(dns_transaction_key(dt)), dns_resource_key_name(rr->key));
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        /* We found a DS transactions for the SOA/NS
                         * RRs we are looking at. If it discovered signed DS
                         * RRs, then we need to be signed, too. */

                        if (!FLAGS_SET(dt->answer_query_flags, SD_RESOLVED_AUTHENTICATED))
                                return false;

                        return dns_answer_match_key(dt->answer, dns_transaction_key(dt), NULL);
                }

                /* We found nothing that proves this is safe to leave
                 * this unauthenticated, hence ask inist on
                 * authentication. */
                return true;
        }

        case DNS_TYPE_DS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME: {
                const char *parent = NULL;
                DnsTransaction *dt;

                /*
                 * CNAME/DNAME RRs cannot be located at a zone apex, hence look directly for the parent SOA.
                 *
                 * DS RRs are signed if the parent is signed, hence also look at the parent SOA
                 */

                SET_FOREACH(dt, t->dnssec_transactions) {

                        if (dns_transaction_key(dt)->class != rr->key->class)
                                continue;
                        if (dns_transaction_key(dt)->type != DNS_TYPE_SOA)
                                continue;

                        if (!parent) {
                                parent = dns_resource_key_name(rr->key);
                                r = dns_name_parent(&parent);
                                if (r < 0)
                                        return r;
                                if (r == 0) {
                                        if (rr->key->type == DNS_TYPE_DS)
                                                return true;

                                        /* A CNAME/DNAME without a parent? That's sooo weird. */
                                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                               "Transaction %" PRIu16 " claims CNAME/DNAME at root. Refusing.", t->id);
                                }
                        }

                        r = dns_name_equal(dns_resource_key_name(dns_transaction_key(dt)), parent);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        return FLAGS_SET(dt->answer_query_flags, SD_RESOLVED_AUTHENTICATED);
                }

                return true;
        }

        default: {
                DnsTransaction *dt;

                /* Any other kind of RR (including DNSKEY/NSEC/NSEC3). Let's see if our SOA lookup was authenticated */

                SET_FOREACH(dt, t->dnssec_transactions) {

                        if (dns_transaction_key(dt)->class != rr->key->class)
                                continue;
                        if (dns_transaction_key(dt)->type != DNS_TYPE_SOA)
                                continue;

                        r = dns_name_equal(dns_resource_key_name(dns_transaction_key(dt)), dns_resource_key_name(rr->key));
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        /* We found the transaction that was supposed to find the SOA RR for us. It was
                         * successful, but found no RR for us. This means we are not at a zone cut. In this
                         * case, we require authentication if the SOA lookup was authenticated too. */
                        return FLAGS_SET(dt->answer_query_flags, SD_RESOLVED_AUTHENTICATED);
                }

                return true;
        }}
}

static int dns_transaction_in_private_tld(DnsTransaction *t, const DnsResourceKey *key) {
        DnsTransaction *dt;
        const char *tld;
        int r;

        /* If DNSSEC downgrade mode is on, checks whether the
         * specified RR is one level below a TLD we have proven not to
         * exist. In such a case we assume that this is a private
         * domain, and permit it.
         *
         * This detects cases like the Fritz!Box router networks. Each
         * Fritz!Box router serves a private "fritz.box" zone, in the
         * non-existing TLD "box". Requests for the "fritz.box" domain
         * are served by the router itself, while requests for the
         * "box" domain will result in NXDOMAIN.
         *
         * Note that this logic is unable to detect cases where a
         * router serves a private DNS zone directly under
         * non-existing TLD. In such a case we cannot detect whether
         * the TLD is supposed to exist or not, as all requests we
         * make for it will be answered by the router's zone, and not
         * by the root zone. */

        assert(t);

        if (t->scope->dnssec_mode != DNSSEC_ALLOW_DOWNGRADE)
                return false; /* In strict DNSSEC mode what doesn't exist, doesn't exist */

        tld = dns_resource_key_name(key);
        r = dns_name_parent(&tld);
        if (r < 0)
                return r;
        if (r == 0)
                return false; /* Already the root domain */

        if (!dns_name_is_single_label(tld))
                return false;

        SET_FOREACH(dt, t->dnssec_transactions) {

                if (dns_transaction_key(dt)->class != key->class)
                        continue;

                r = dns_name_equal(dns_resource_key_name(dns_transaction_key(dt)), tld);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                /* We found an auxiliary lookup we did for the TLD. If
                 * that returned with NXDOMAIN, we know the TLD didn't
                 * exist, and hence this might be a private zone. */

                return dt->answer_rcode == DNS_RCODE_NXDOMAIN;
        }

        return false;
}

static int dns_transaction_requires_nsec(DnsTransaction *t) {
        char key_str[DNS_RESOURCE_KEY_STRING_MAX];
        DnsTransaction *dt;
        const char *name;
        uint16_t type = 0;
        int r;

        assert(t);

        /* Checks if we need to insist on NSEC/NSEC3 RRs for proving
         * this negative reply */

        if (t->scope->dnssec_mode == DNSSEC_NO)
                return false;

        if (dns_type_is_pseudo(dns_transaction_key(t)->type))
                return -EINVAL;

        r = dns_transaction_negative_trust_anchor_lookup(t, dns_resource_key_name(dns_transaction_key(t)));
        if (r < 0)
                return r;
        if (r > 0)
                return false;

        r = dns_transaction_in_private_tld(t, dns_transaction_key(t));
        if (r < 0)
                return r;
        if (r > 0) {
                /* The lookup is from a TLD that is proven not to
                 * exist, and we are in downgrade mode, hence ignore
                 * that fact that we didn't get any NSEC RRs. */

                log_info("Detected a negative query %s in a private DNS zone, permitting unsigned response.",
                         dns_resource_key_to_string(dns_transaction_key(t), key_str, sizeof key_str));
                return false;
        }

        name = dns_resource_key_name(dns_transaction_key(t));

        if (dns_transaction_key(t)->type == DNS_TYPE_DS) {

                /* We got a negative reply for this DS lookup? DS RRs are signed when their parent zone is signed,
                 * hence check the parent SOA in this case. */

                r = dns_name_parent(&name);
                if (r < 0)
                        return r;
                if (r == 0)
                        return true;

                type = DNS_TYPE_SOA;

        } else if (IN_SET(dns_transaction_key(t)->type, DNS_TYPE_SOA, DNS_TYPE_NS))
                /* We got a negative reply for this SOA/NS lookup? If so, check if there's a DS RR for this */
                type = DNS_TYPE_DS;
        else
                /* For all other negative replies, check for the SOA lookup */
                type = DNS_TYPE_SOA;

        /* For all other RRs we check the SOA on the same level to see
         * if it's signed. */

        SET_FOREACH(dt, t->dnssec_transactions) {

                if (dns_transaction_key(dt)->class != dns_transaction_key(t)->class)
                        continue;
                if (dns_transaction_key(dt)->type != type)
                        continue;

                r = dns_name_equal(dns_resource_key_name(dns_transaction_key(dt)), name);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                return FLAGS_SET(dt->answer_query_flags, SD_RESOLVED_AUTHENTICATED);
        }

        /* If in doubt, require NSEC/NSEC3 */
        return true;
}

static int dns_transaction_dnskey_authenticated(DnsTransaction *t, DnsResourceRecord *rr) {
        DnsResourceRecord *rrsig;
        bool found = false;
        int r;

        /* Checks whether any of the DNSKEYs used for the RRSIGs for
         * the specified RRset is authenticated (i.e. has a matching
         * DS RR). */

        r = dns_transaction_negative_trust_anchor_lookup(t, dns_resource_key_name(rr->key));
        if (r < 0)
                return r;
        if (r > 0)
                return false;

        DNS_ANSWER_FOREACH(rrsig, t->answer) {
                DnsTransaction *dt;

                r = dnssec_key_match_rrsig(rr->key, rrsig);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                SET_FOREACH(dt, t->dnssec_transactions) {

                        if (dns_transaction_key(dt)->class != rr->key->class)
                                continue;

                        if (dns_transaction_key(dt)->type == DNS_TYPE_DNSKEY) {

                                r = dns_name_equal(dns_resource_key_name(dns_transaction_key(dt)), rrsig->rrsig.signer);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;

                                /* OK, we found an auxiliary DNSKEY lookup. If that lookup is authenticated,
                                 * report this. */

                                if (FLAGS_SET(dt->answer_query_flags, SD_RESOLVED_AUTHENTICATED))
                                        return true;

                                found = true;

                        } else if (dns_transaction_key(dt)->type == DNS_TYPE_DS) {

                                r = dns_name_equal(dns_resource_key_name(dns_transaction_key(dt)), rrsig->rrsig.signer);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;

                                /* OK, we found an auxiliary DS lookup. If that lookup is authenticated and
                                 * non-zero, we won! */

                                if (!FLAGS_SET(dt->answer_query_flags, SD_RESOLVED_AUTHENTICATED))
                                        return false;

                                return dns_answer_match_key(dt->answer, dns_transaction_key(dt), NULL);
                        }
                }
        }

        return found ? false : -ENXIO;
}

static int dns_transaction_known_signed(DnsTransaction *t, DnsResourceRecord *rr) {
        assert(t);
        assert(rr);

        /* We know that the root domain is signed, hence if it appears
         * not to be signed, there's a problem with the DNS server */

        return rr->key->class == DNS_CLASS_IN &&
                dns_name_is_root(dns_resource_key_name(rr->key));
}

static int dns_transaction_check_revoked_trust_anchors(DnsTransaction *t) {
        DnsResourceRecord *rr;
        int r;

        assert(t);

        /* Maybe warn the user that we encountered a revoked DNSKEY
         * for a key from our trust anchor. Note that we don't care
         * whether the DNSKEY can be authenticated or not. It's
         * sufficient if it is self-signed. */

        DNS_ANSWER_FOREACH(rr, t->answer) {
                r = dns_trust_anchor_check_revoked(&t->scope->manager->trust_anchor, rr, t->answer);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dns_transaction_invalidate_revoked_keys(DnsTransaction *t) {
        bool changed;
        int r;

        assert(t);

        /* Removes all DNSKEY/DS objects from t->validated_keys that
         * our trust anchors database considers revoked. */

        do {
                DnsResourceRecord *rr;

                changed = false;

                DNS_ANSWER_FOREACH(rr, t->validated_keys) {
                        r = dns_trust_anchor_is_revoked(&t->scope->manager->trust_anchor, rr);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                r = dns_answer_remove_by_rr(&t->validated_keys, rr);
                                if (r < 0)
                                        return r;

                                assert(r > 0);
                                changed = true;
                                break;
                        }
                }
        } while (changed);

        return 0;
}

static int dns_transaction_copy_validated(DnsTransaction *t) {
        DnsTransaction *dt;
        int r;

        assert(t);

        /* Copy all validated RRs from the auxiliary DNSSEC transactions into our set of validated RRs */

        SET_FOREACH(dt, t->dnssec_transactions) {

                if (DNS_TRANSACTION_IS_LIVE(dt->state))
                        continue;

                if (!FLAGS_SET(dt->answer_query_flags, SD_RESOLVED_AUTHENTICATED))
                        continue;

                r = dns_answer_extend(&t->validated_keys, dt->answer);
                if (r < 0)
                        return r;
        }

        return 0;
}

typedef enum {
        DNSSEC_PHASE_DNSKEY,   /* Phase #1, only validate DNSKEYs */
        DNSSEC_PHASE_NSEC,     /* Phase #2, only validate NSEC+NSEC3 */
        DNSSEC_PHASE_ALL,      /* Phase #3, validate everything else */
} Phase;

static int dnssec_validate_records(
                DnsTransaction *t,
                Phase phase,
                bool *have_nsec,
                DnsAnswer **validated) {

        DnsResourceRecord *rr;
        int r;

        /* Returns negative on error, 0 if validation failed, 1 to restart validation, 2 when finished. */

        DNS_ANSWER_FOREACH(rr, t->answer) {
                _unused_ _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr_ref = dns_resource_record_ref(rr);
                DnsResourceRecord *rrsig = NULL;
                DnssecResult result;

                switch (rr->key->type) {
                case DNS_TYPE_RRSIG:
                        continue;

                case DNS_TYPE_DNSKEY:
                        /* We validate DNSKEYs only in the DNSKEY and ALL phases */
                        if (phase == DNSSEC_PHASE_NSEC)
                                continue;
                        break;

                case DNS_TYPE_NSEC:
                case DNS_TYPE_NSEC3:
                        *have_nsec = true;

                        /* We validate NSEC/NSEC3 only in the NSEC and ALL phases */
                        if (phase == DNSSEC_PHASE_DNSKEY)
                                continue;
                        break;

                default:
                        /* We validate all other RRs only in the ALL phases */
                        if (phase != DNSSEC_PHASE_ALL)
                                continue;
                }

                r = dnssec_verify_rrset_search(
                                t->answer,
                                rr->key,
                                t->validated_keys,
                                USEC_INFINITY,
                                &result,
                                &rrsig);
                if (r < 0)
                        return r;

                log_debug("Looking at %s: %s", strna(dns_resource_record_to_string(rr)), dnssec_result_to_string(result));

                if (result == DNSSEC_VALIDATED) {
                        assert(rrsig);

                        if (rr->key->type == DNS_TYPE_DNSKEY) {
                                /* If we just validated a DNSKEY RRset, then let's add these keys to
                                 * the set of validated keys for this transaction. */

                                r = dns_answer_copy_by_key(&t->validated_keys, t->answer, rr->key, DNS_ANSWER_AUTHENTICATED, rrsig);
                                if (r < 0)
                                        return r;

                                /* Some of the DNSKEYs we just added might already have been revoked,
                                 * remove them again in that case. */
                                r = dns_transaction_invalidate_revoked_keys(t);
                                if (r < 0)
                                        return r;
                        }

                        /* Add the validated RRset to the new list of validated RRsets, and remove it from
                         * the unvalidated RRsets.  We mark the RRset as authenticated and cacheable. */
                        r = dns_answer_move_by_key(validated, &t->answer, rr->key, DNS_ANSWER_AUTHENTICATED|DNS_ANSWER_CACHEABLE, rrsig);
                        if (r < 0)
                                return r;

                        manager_dnssec_verdict(t->scope->manager, DNSSEC_SECURE, rr->key);

                        /* Exit the loop, we dropped something from the answer, start from the beginning */
                        return 1;
                }

                /* If we haven't read all DNSKEYs yet a negative result of the validation is irrelevant, as
                 * there might be more DNSKEYs coming. Similar, if we haven't read all NSEC/NSEC3 RRs yet,
                 * we cannot do positive wildcard proofs yet, as those require the NSEC/NSEC3 RRs. */
                if (phase != DNSSEC_PHASE_ALL)
                        continue;

                if (result == DNSSEC_VALIDATED_WILDCARD) {
                        bool authenticated = false;
                        const char *source;

                        assert(rrsig);

                        /* This RRset validated, but as a wildcard. This means we need
                         * to prove via NSEC/NSEC3 that no matching non-wildcard RR exists. */

                        /* First step, determine the source of synthesis */
                        r = dns_resource_record_source(rrsig, &source);
                        if (r < 0)
                                return r;

                        r = dnssec_test_positive_wildcard(*validated,
                                                          dns_resource_key_name(rr->key),
                                                          source,
                                                          rrsig->rrsig.signer,
                                                          &authenticated);

                        /* Unless the NSEC proof showed that the key really doesn't exist something is off. */
                        if (r == 0)
                                result = DNSSEC_INVALID;
                        else {
                                r = dns_answer_move_by_key(
                                                validated,
                                                &t->answer,
                                                rr->key,
                                                authenticated ? (DNS_ANSWER_AUTHENTICATED|DNS_ANSWER_CACHEABLE) : 0,
                                                rrsig);
                                if (r < 0)
                                        return r;

                                manager_dnssec_verdict(t->scope->manager, authenticated ? DNSSEC_SECURE : DNSSEC_INSECURE, rr->key);

                                /* Exit the loop, we dropped something from the answer, start from the beginning */
                                return 1;
                        }
                }

                if (result == DNSSEC_NO_SIGNATURE) {
                        r = dns_transaction_requires_rrsig(t, rr);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                /* Data does not require signing. In that case, just copy it over,
                                 * but remember that this is by no means authenticated. */
                                r = dns_answer_move_by_key(
                                                validated,
                                                &t->answer,
                                                rr->key,
                                                0,
                                                NULL);
                                if (r < 0)
                                        return r;

                                manager_dnssec_verdict(t->scope->manager, DNSSEC_INSECURE, rr->key);
                                return 1;
                        }

                        r = dns_transaction_known_signed(t, rr);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                /* This is an RR we know has to be signed. If it isn't this means
                                 * the server is not attaching RRSIGs, hence complain. */

                                dns_server_packet_rrsig_missing(t->server, t->current_feature_level);

                                if (t->scope->dnssec_mode == DNSSEC_ALLOW_DOWNGRADE) {

                                        /* Downgrading is OK? If so, just consider the information unsigned */

                                        r = dns_answer_move_by_key(validated, &t->answer, rr->key, 0, NULL);
                                        if (r < 0)
                                                return r;

                                        manager_dnssec_verdict(t->scope->manager, DNSSEC_INSECURE, rr->key);
                                        return 1;
                                }

                                /* Otherwise, fail */
                                t->answer_dnssec_result = DNSSEC_INCOMPATIBLE_SERVER;
                                return 0;
                        }

                        r = dns_transaction_in_private_tld(t, rr->key);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                char s[DNS_RESOURCE_KEY_STRING_MAX];

                                /* The data is from a TLD that is proven not to exist, and we are in downgrade
                                 * mode, hence ignore the fact that this was not signed. */

                                log_info("Detected RRset %s is in a private DNS zone, permitting unsigned RRs.",
                                         dns_resource_key_to_string(rr->key, s, sizeof s));

                                r = dns_answer_move_by_key(validated, &t->answer, rr->key, 0, NULL);
                                if (r < 0)
                                        return r;

                                manager_dnssec_verdict(t->scope->manager, DNSSEC_INSECURE, rr->key);
                                return 1;
                        }
                }

                /* https://datatracker.ietf.org/doc/html/rfc6840#section-5.2 */
                if (result == DNSSEC_UNSUPPORTED_ALGORITHM) {
                        r = dns_answer_move_by_key(validated, &t->answer, rr->key, 0, NULL);
                        if (r < 0)
                                return r;

                        manager_dnssec_verdict(t->scope->manager, DNSSEC_INSECURE, rr->key);
                        return 1;
                }

                if (IN_SET(result,
                           DNSSEC_MISSING_KEY,
                           DNSSEC_SIGNATURE_EXPIRED)) {

                        r = dns_transaction_dnskey_authenticated(t, rr);
                        if (r < 0 && r != -ENXIO)
                                return r;
                        if (r == 0) {
                                /* The DNSKEY transaction was not authenticated, this means there's
                                 * no DS for this, which means it's OK if no keys are found for this signature. */

                                r = dns_answer_move_by_key(validated, &t->answer, rr->key, 0, NULL);
                                if (r < 0)
                                        return r;

                                manager_dnssec_verdict(t->scope->manager, DNSSEC_INSECURE, rr->key);
                                return 1;
                        }
                }

                r = dns_transaction_is_primary_response(t, rr);
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* Look for a matching DNAME for this CNAME */
                        r = dns_answer_has_dname_for_cname(t->answer, rr);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                /* Also look among the stuff we already validated */
                                r = dns_answer_has_dname_for_cname(*validated, rr);
                                if (r < 0)
                                        return r;
                        }

                        if (r == 0) {
                                if (IN_SET(result,
                                           DNSSEC_INVALID,
                                           DNSSEC_SIGNATURE_EXPIRED,
                                           DNSSEC_NO_SIGNATURE))
                                        manager_dnssec_verdict(t->scope->manager, DNSSEC_BOGUS, rr->key);
                                else /* DNSSEC_MISSING_KEY or DNSSEC_UNSUPPORTED_ALGORITHM */
                                        manager_dnssec_verdict(t->scope->manager, DNSSEC_INDETERMINATE, rr->key);

                                /* This is a primary response to our question, and it failed validation.
                                 * That's fatal. */
                                t->answer_dnssec_result = result;
                                return 0;
                        }

                        /* This is a primary response, but we do have a DNAME RR
                         * in the RR that can replay this CNAME, hence rely on
                         * that, and we can remove the CNAME in favour of it. */
                }

                /* This is just some auxiliary data. Just remove the RRset and continue. */
                r = dns_answer_remove_by_key(&t->answer, rr->key);
                if (r < 0)
                        return r;

                /* We dropped something from the answer, start from the beginning. */
                return 1;
        }

        return 2; /* Finito. */
}

int dns_transaction_validate_dnssec(DnsTransaction *t) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *validated = NULL;
        Phase phase;
        DnsAnswerFlags flags;
        int r;
        char key_str[DNS_RESOURCE_KEY_STRING_MAX];

        assert(t);

        /* We have now collected all DS and DNSKEY RRs in t->validated_keys, let's see which RRs we can now
         * authenticate with that. */

        if (FLAGS_SET(t->query_flags, SD_RESOLVED_NO_VALIDATE) || t->scope->dnssec_mode == DNSSEC_NO)
                return 0;

        /* Already validated */
        if (t->answer_dnssec_result != _DNSSEC_RESULT_INVALID)
                return 0;

        /* Our own stuff needs no validation */
        if (IN_SET(t->answer_source, DNS_TRANSACTION_ZONE, DNS_TRANSACTION_TRUST_ANCHOR)) {
                t->answer_dnssec_result = DNSSEC_VALIDATED;
                SET_FLAG(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED, true);
                return 0;
        }

        /* Cached stuff is not affected by validation. */
        if (t->answer_source != DNS_TRANSACTION_NETWORK)
                return 0;

        if (!dns_transaction_dnssec_supported_full(t)) {
                /* The server does not support DNSSEC, or doesn't augment responses with RRSIGs. */
                t->answer_dnssec_result = DNSSEC_INCOMPATIBLE_SERVER;
                log_debug("Not validating response for %" PRIu16 ", used server feature level does not support DNSSEC.", t->id);
                return 0;
        }

        log_debug("Validating response from transaction %" PRIu16 " (%s).",
                  t->id,
                  dns_resource_key_to_string(dns_transaction_key(t), key_str, sizeof key_str));

        /* First, see if this response contains any revoked trust
         * anchors we care about */
        r = dns_transaction_check_revoked_trust_anchors(t);
        if (r < 0)
                return r;

        /* Third, copy all RRs we acquired successfully from auxiliary RRs over. */
        r = dns_transaction_copy_validated(t);
        if (r < 0)
                return r;

        /* Second, see if there are DNSKEYs we already know a
         * validated DS for. */
        r = dns_transaction_validate_dnskey_by_ds(t);
        if (r < 0)
                return r;

        /* Fourth, remove all DNSKEY and DS RRs again that our trust
         * anchor says are revoked. After all we might have marked
         * some keys revoked above, but they might still be lingering
         * in our validated_keys list. */
        r = dns_transaction_invalidate_revoked_keys(t);
        if (r < 0)
                return r;

        phase = DNSSEC_PHASE_DNSKEY;
        for (;;) {
                bool have_nsec = false;

                r = dnssec_validate_records(t, phase, &have_nsec, &validated);
                if (r <= 0)
                        return r;

                /* Try again as long as we managed to achieve something */
                if (r == 1)
                        continue;

                if (phase == DNSSEC_PHASE_DNSKEY && have_nsec) {
                        /* OK, we processed all DNSKEYs, and there are NSEC/NSEC3 RRs, look at those now. */
                        phase = DNSSEC_PHASE_NSEC;
                        continue;
                }

                if (phase != DNSSEC_PHASE_ALL) {
                        /* OK, we processed all DNSKEYs and NSEC/NSEC3 RRs, look at all the rest now.
                         * Note that in this third phase we start to remove RRs we couldn't validate. */
                        phase = DNSSEC_PHASE_ALL;
                        continue;
                }

                /* We're done */
                break;
        }

        DNS_ANSWER_REPLACE(t->answer, TAKE_PTR(validated));

        /* At this point the answer only contains validated
         * RRsets. Now, let's see if it actually answers the question
         * we asked. If so, great! If it doesn't, then see if
         * NSEC/NSEC3 can prove this. */
        r = dns_transaction_has_positive_answer(t, &flags);
        if (r > 0) {
                /* Yes, it answers the question! */

                if (flags & DNS_ANSWER_AUTHENTICATED) {
                        /* The answer is fully authenticated, yay. */
                        t->answer_dnssec_result = DNSSEC_VALIDATED;
                        t->answer_rcode = DNS_RCODE_SUCCESS;
                        SET_FLAG(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED, true);
                } else {
                        /* The answer is not fully authenticated. */
                        t->answer_dnssec_result = DNSSEC_UNSIGNED;
                        SET_FLAG(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED, false);
                }

        } else if (r == 0) {
                DnssecNsecResult nr;
                bool authenticated = false;

                /* Bummer! Let's check NSEC/NSEC3 */
                r = dnssec_nsec_test(t->answer, dns_transaction_key(t), &nr, &authenticated, &t->answer_nsec_ttl);
                if (r < 0)
                        return r;

                switch (nr) {

                case DNSSEC_NSEC_NXDOMAIN:
                        /* NSEC proves the domain doesn't exist. Very good. */
                        log_debug("Proved NXDOMAIN via NSEC/NSEC3 for transaction %u (%s)", t->id, key_str);
                        t->answer_dnssec_result = DNSSEC_VALIDATED;
                        t->answer_rcode = DNS_RCODE_NXDOMAIN;
                        SET_FLAG(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED, authenticated);

                        manager_dnssec_verdict(t->scope->manager, authenticated ? DNSSEC_SECURE : DNSSEC_INSECURE, dns_transaction_key(t));
                        break;

                case DNSSEC_NSEC_NODATA:
                        /* NSEC proves that there's no data here, very good. */
                        log_debug("Proved NODATA via NSEC/NSEC3 for transaction %u (%s)", t->id, key_str);
                        t->answer_dnssec_result = DNSSEC_VALIDATED;
                        t->answer_rcode = DNS_RCODE_SUCCESS;
                        SET_FLAG(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED, authenticated);

                        manager_dnssec_verdict(t->scope->manager, authenticated ? DNSSEC_SECURE : DNSSEC_INSECURE, dns_transaction_key(t));
                        break;

                case DNSSEC_NSEC_OPTOUT:
                        /* NSEC3 says the data might not be signed */
                        log_debug("Data is NSEC3 opt-out via NSEC/NSEC3 for transaction %u (%s)", t->id, key_str);
                        t->answer_dnssec_result = DNSSEC_UNSIGNED;
                        SET_FLAG(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED, false);

                        manager_dnssec_verdict(t->scope->manager, DNSSEC_INSECURE, dns_transaction_key(t));
                        break;

                case DNSSEC_NSEC_NO_RR:
                        /* No NSEC data? Bummer! */

                        r = dns_transaction_requires_nsec(t);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                t->answer_dnssec_result = DNSSEC_NO_SIGNATURE;
                                manager_dnssec_verdict(t->scope->manager, DNSSEC_BOGUS, dns_transaction_key(t));
                        } else {
                                t->answer_dnssec_result = DNSSEC_UNSIGNED;
                                SET_FLAG(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED, false);
                                manager_dnssec_verdict(t->scope->manager, DNSSEC_INSECURE, dns_transaction_key(t));
                        }

                        break;

                case DNSSEC_NSEC_UNSUPPORTED_ALGORITHM:
                        /* We don't know the NSEC3 algorithm used? */
                        t->answer_dnssec_result = DNSSEC_UNSUPPORTED_ALGORITHM;
                        manager_dnssec_verdict(t->scope->manager, DNSSEC_INDETERMINATE, dns_transaction_key(t));
                        break;

                case DNSSEC_NSEC_FOUND:
                case DNSSEC_NSEC_CNAME:
                        /* NSEC says it needs to be there, but we couldn't find it? Bummer! */
                        t->answer_dnssec_result = DNSSEC_NSEC_MISMATCH;
                        manager_dnssec_verdict(t->scope->manager, DNSSEC_BOGUS, dns_transaction_key(t));
                        break;

                default:
                        assert_not_reached();
                }
        }

        return 1;
}

static const char* const dns_transaction_state_table[_DNS_TRANSACTION_STATE_MAX] = {
        [DNS_TRANSACTION_NULL]                 = "null",
        [DNS_TRANSACTION_PENDING]              = "pending",
        [DNS_TRANSACTION_VALIDATING]           = "validating",
        [DNS_TRANSACTION_RCODE_FAILURE]        = "rcode-failure",
        [DNS_TRANSACTION_SUCCESS]              = "success",
        [DNS_TRANSACTION_NO_SERVERS]           = "no-servers",
        [DNS_TRANSACTION_TIMEOUT]              = "timeout",
        [DNS_TRANSACTION_ATTEMPTS_MAX_REACHED] = "attempts-max-reached",
        [DNS_TRANSACTION_INVALID_REPLY]        = "invalid-reply",
        [DNS_TRANSACTION_ERRNO]                = "errno",
        [DNS_TRANSACTION_ABORTED]              = "aborted",
        [DNS_TRANSACTION_DNSSEC_FAILED]        = "dnssec-failed",
        [DNS_TRANSACTION_NO_TRUST_ANCHOR]      = "no-trust-anchor",
        [DNS_TRANSACTION_RR_TYPE_UNSUPPORTED]  = "rr-type-unsupported",
        [DNS_TRANSACTION_NETWORK_DOWN]         = "network-down",
        [DNS_TRANSACTION_NOT_FOUND]            = "not-found",
        [DNS_TRANSACTION_NO_SOURCE]            = "no-source",
        [DNS_TRANSACTION_STUB_LOOP]            = "stub-loop",
};
DEFINE_STRING_TABLE_LOOKUP(dns_transaction_state, DnsTransactionState);

static const char* const dns_transaction_source_table[_DNS_TRANSACTION_SOURCE_MAX] = {
        [DNS_TRANSACTION_NETWORK]      = "network",
        [DNS_TRANSACTION_CACHE]        = "cache",
        [DNS_TRANSACTION_ZONE]         = "zone",
        [DNS_TRANSACTION_TRUST_ANCHOR] = "trust-anchor",
};
DEFINE_STRING_TABLE_LOOKUP(dns_transaction_source, DnsTransactionSource);
