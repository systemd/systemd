/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "dns-answer.h"
#include "dns-domain.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "event-util.h"
#include "fd-util.h"
#include "log.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-transaction.h"
#include "resolved-link.h"
#include "resolved-manager.h"
#include "resolved-mdns.h"
#include "sort-util.h"
#include "time-util.h"

#define CLEAR_CACHE_FLUSH(x) (~MDNS_RR_CACHE_FLUSH_OR_QU & (x))

void manager_mdns_stop(Manager *m) {
        assert(m);

        m->mdns_ipv4_event_source = sd_event_source_disable_unref(m->mdns_ipv4_event_source);
        m->mdns_ipv4_fd = safe_close(m->mdns_ipv4_fd);

        m->mdns_ipv6_event_source = sd_event_source_disable_unref(m->mdns_ipv6_event_source);
        m->mdns_ipv6_fd = safe_close(m->mdns_ipv6_fd);
}

void manager_mdns_maybe_stop(Manager *m) {
        assert(m);

        /* This stops mDNS only when no interface enables mDNS. */

        Link *l;
        HASHMAP_FOREACH(l, m->links)
                if (link_get_mdns_support(l) != RESOLVE_SUPPORT_NO)
                        return;

        manager_mdns_stop(m);
}

int manager_mdns_start(Manager *m) {
        int r;

        assert(m);

        if (m->mdns_support == RESOLVE_SUPPORT_NO)
                return 0;

        r = manager_mdns_ipv4_fd(m);
        if (r == -EADDRINUSE)
                goto eaddrinuse;
        if (r < 0)
                return r;

        if (socket_ipv6_is_enabled()) {
                r = manager_mdns_ipv6_fd(m);
                if (r == -EADDRINUSE)
                        goto eaddrinuse;
                if (r < 0)
                        return r;
        }

        return 0;

eaddrinuse:
        log_warning("Another mDNS responder prohibits binding the socket to the same port. Turning off mDNS support.");
        m->mdns_support = RESOLVE_SUPPORT_NO;
        manager_mdns_stop(m);

        return 0;
}

static int mdns_rr_compare(DnsResourceRecord * const *a, DnsResourceRecord * const *b) {
        DnsResourceRecord *x = *(DnsResourceRecord **) a, *y = *(DnsResourceRecord **) b;
        size_t m;
        int r;

        assert(x);
        assert(y);

        r = CMP(CLEAR_CACHE_FLUSH(x->key->class), CLEAR_CACHE_FLUSH(y->key->class));
        if (r != 0)
                return r;

        r = CMP(x->key->type, y->key->type);
        if (r != 0)
                return r;

        r = dns_resource_record_to_wire_format(x, false);
        if (r < 0) {
                log_warning_errno(r, "Can't wire-format RR: %m");
                return 0;
        }

        r = dns_resource_record_to_wire_format(y, false);
        if (r < 0) {
                log_warning_errno(r, "Can't wire-format RR: %m");
                return 0;
        }

        m = MIN(DNS_RESOURCE_RECORD_RDATA_SIZE(x), DNS_RESOURCE_RECORD_RDATA_SIZE(y));

        r = memcmp(DNS_RESOURCE_RECORD_RDATA(x), DNS_RESOURCE_RECORD_RDATA(y), m);
        if (r != 0)
                return r;

        return CMP(DNS_RESOURCE_RECORD_RDATA_SIZE(x), DNS_RESOURCE_RECORD_RDATA_SIZE(y));
}

static int proposed_rrs_cmp(DnsResourceRecord **x, unsigned x_size, DnsResourceRecord **y, unsigned y_size) {
        unsigned m;
        int r;

        m = MIN(x_size, y_size);
        for (unsigned i = 0; i < m; i++) {
                r = mdns_rr_compare(&x[i], &y[i]);
                if (r != 0)
                        return r;
        }

        return CMP(x_size, y_size);
}

static int mdns_packet_extract_matching_rrs(DnsPacket *p, DnsResourceKey *key, DnsResourceRecord ***ret_rrs) {
        _cleanup_free_ DnsResourceRecord **list = NULL;
        size_t i, n = 0, size = 0;
        DnsResourceRecord *rr;
        int r;

        assert(p);
        assert(key);
        assert(ret_rrs);
        assert_return(DNS_PACKET_NSCOUNT(p) > 0, -EINVAL);

        i = 0;
        DNS_ANSWER_FOREACH(rr, p->answer) {
                if (i >= DNS_PACKET_ANCOUNT(p) && i < DNS_PACKET_ANCOUNT(p) + DNS_PACKET_NSCOUNT(p)) {
                        r = dns_resource_key_match_rr(key, rr, NULL);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                size++;
                }
                i++;
        }

        if (size == 0) {
                *ret_rrs = NULL;
                return 0;
        }

        list = new(DnsResourceRecord *, size);
        if (!list)
                return -ENOMEM;

        i = 0;
        DNS_ANSWER_FOREACH(rr, p->answer) {
                if (i >= DNS_PACKET_ANCOUNT(p) && i < DNS_PACKET_ANCOUNT(p) + DNS_PACKET_NSCOUNT(p)) {
                        r = dns_resource_key_match_rr(key, rr, NULL);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                list[n++] = rr;
                }
                i++;
        }

        assert(n == size);
        typesafe_qsort(list, size, mdns_rr_compare);

        *ret_rrs = TAKE_PTR(list);

        return size;
}

static int mdns_do_tiebreak(DnsResourceKey *key, DnsAnswer *answer, DnsPacket *p) {
        _cleanup_free_ DnsResourceRecord **our = NULL, **remote = NULL;
        DnsResourceRecord *rr;
        size_t i = 0, size;
        int r;

        size = dns_answer_size(answer);
        our = new(DnsResourceRecord *, size);
        if (!our)
                return -ENOMEM;

        DNS_ANSWER_FOREACH(rr, answer)
                our[i++] = rr;

        typesafe_qsort(our, size, mdns_rr_compare);

        r = mdns_packet_extract_matching_rrs(p, key, &remote);
        if (r < 0)
                return r;

        if (proposed_rrs_cmp(remote, r, our, size) > 0)
                return 1;

        return 0;
}

static bool mdns_should_reply_using_unicast(DnsPacket *p) {
        DnsQuestionItem *item;

        /* Work out if we should respond using multicast or unicast. */

        /* The query was a legacy "one-shot mDNS query", RFC 6762, sections 5.1 and 6.7 */
        if (p->sender_port != MDNS_PORT)
                return true;

        /* The query was a "direct unicast query", RFC 6762, section 5.5 */
        switch (p->family) {
        case AF_INET:
                if (!in4_addr_equal(&p->destination.in, &MDNS_MULTICAST_IPV4_ADDRESS))
                        return true;
                break;
        case AF_INET6:
                if (!in6_addr_equal(&p->destination.in6, &MDNS_MULTICAST_IPV6_ADDRESS))
                        return true;
                break;
        }

        /* All the questions in the query had a QU bit set, RFC 6762, section 5.4 */
        DNS_QUESTION_FOREACH_ITEM(item, p->question)
                if (!FLAGS_SET(item->flags, DNS_QUESTION_WANTS_UNICAST_REPLY))
                        return false;

        return true;
}

static bool sender_on_local_subnet(DnsScope *s, DnsPacket *p) {
        int r;

        /* Check whether the sender is on a local subnet. */

        if (!s->link)
                return false;

        LIST_FOREACH(addresses, a, s->link->addresses) {
                if (a->family != p->family)
                        continue;
                if (a->prefixlen == UCHAR_MAX) /* don't know subnet mask */
                        continue;

                r = in_addr_prefix_covers(a->family, &a->in_addr, a->prefixlen, &p->sender);
                if (r < 0)
                        log_debug_errno(r, "Failed to determine whether link address covers sender address: %m");
                if (r > 0)
                        return true;
        }

        return false;
}

static int mdns_scope_process_query(DnsScope *s, DnsPacket *p) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *full_answer = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr;
        bool tentative = false;
        bool legacy_query = p->sender_port != MDNS_PORT;
        bool unicast_reply;
        int r;

        assert(s);
        assert(p);

        r = dns_packet_extract(p);
        if (r < 0)
                return log_debug_errno(r, "Failed to extract resource records from incoming packet: %m");

        /* TODO: Support Known-Answers only packets gracefully. */
        if (dns_question_size(p->question) <= 0)
                return 0;

        unicast_reply = mdns_should_reply_using_unicast(p);
        if (unicast_reply && !sender_on_local_subnet(s, p)) {
                /* RFC 6762, section 5.5 recommends silently ignoring unicast queries
                 * from senders outside the local network, so that we don't reveal our
                 * internal network structure to outsiders. */
                log_debug("Sender wants a unicast reply, but is not on a local subnet. Ignoring.");
                return 0;
        }

        DNS_QUESTION_FOREACH(key, p->question) {
                _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL, *soa = NULL;
                DnsAnswerItem *item;

                r = dns_zone_lookup(&s->zone, key, 0, &answer, &soa, &tentative);
                if (r < 0)
                        return log_debug_errno(r, "Failed to look up key: %m");

                if (tentative && DNS_PACKET_NSCOUNT(p) > 0) {
                        /*
                         * A race condition detected with the probe packet from
                         * a remote host.
                         * Do simultaneous probe tiebreaking as described in
                         * RFC 6762, Section 8.2. In case we lost don't reply
                         * the question and withdraw conflicting RRs.
                         */
                        r = mdns_do_tiebreak(key, answer, p);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to do tiebreaking");

                        if (r > 0) { /* we lost */
                                DNS_ANSWER_FOREACH(rr, answer) {
                                        DnsZoneItem *i;

                                        i = dns_zone_get(&s->zone, rr);
                                        if (i)
                                                dns_zone_item_conflict(i);
                                }

                                continue;
                        }
                }

                if (dns_answer_isempty(answer))
                        continue;

                /* Copy answer items from full_answer to answer, tweaking them if needed. */
                if (full_answer) {
                        r = dns_answer_reserve(&full_answer, dns_answer_size(answer));
                        if (r < 0)
                                return log_debug_errno(r, "Failed to reserve space in answer");
                } else {
                        full_answer = dns_answer_new(dns_answer_size(answer));
                        if (!full_answer)
                                return log_oom();
                }

                DNS_ANSWER_FOREACH_ITEM(item, answer) {
                        DnsAnswerFlags flags = item->flags | DNS_ANSWER_REFUSE_TTL_NO_MATCH;
                        /* The cache-flush bit must not be set in legacy unicast responses.
                         * See section 6.7 of RFC 6762. */
                        if (legacy_query)
                                flags &= ~DNS_ANSWER_CACHE_FLUSH;
                        r = dns_answer_add(full_answer, item->rr, item->ifindex, flags, item->rrsig);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to extend answer: %m");
                }
        }

        if (dns_answer_isempty(full_answer))
                return 0;

        r = dns_scope_make_reply_packet(s, DNS_PACKET_ID(p), DNS_RCODE_SUCCESS,
                                        legacy_query ? p->question : NULL, full_answer,
                                        NULL, false, &reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to build reply packet: %m");

        if (!ratelimit_below(&s->ratelimit))
                return 0;

        if (unicast_reply) {
                reply->destination = p->sender;
                reply->destination_port = p->sender_port;
        }
        r = dns_scope_emit_udp(s, -1, AF_UNSPEC, reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to send reply packet: %m");

        return 0;
}

/* The soonest expiry the cache holds, if it falls inside the RFC 6762 section 10.1 window this timer
 * exists to service. USEC_INFINITY when nothing does — an empty cache, or an expiry past the window.
 * 't' is the caller's reading of the current clock: the deadline a firing was scheduled for is the
 * wrong reference, since it lags the clock by up to the timer's accuracy, and taking one reading per
 * caller keeps this decision and the fallback deadline built from it on the same instant. */
static usec_t mdns_goodbye_next_deadline(DnsScope *scope, usec_t t) {
        usec_t until;

        assert(scope);

        until = dns_cache_next_expiry(&scope->cache);

        return until > usec_add(t, MDNS_GOODBYE_DELAY) ? USEC_INFINITY : until;
}

/* force_reset=false means an armed timer keeps its deadline and 'until' is discarded outright —
 * event_reset_time() only asks whether the source is enabled, never how the deadlines compare. That
 * is safe here because of the bound both callers observe, not because the armed one is nearer: every
 * deadline armed is at most now + MDNS_GOODBYE_DELAY, and now only moves forward, so an armed
 * deadline is never past t_receipt + MDNS_GOODBYE_DELAY — the point by which a goodbye received at
 * t_receipt needs its pass. A caller wanting min() semantics would have to pass force_reset=true and
 * compare for itself.
 *
 * The deadline is floored here rather than at the call sites, so both of them obey the rate bound. */
static void mdns_goodbye_arm(DnsScope *scope, usec_t until, bool force_reset) {
        int r;

        assert(scope);
        assert(until != USEC_INFINITY);

        until = MAX(until, usec_add(now(CLOCK_BOOTTIME), MDNS_GOODBYE_MIN_INTERVAL));

        r = event_reset_time(scope->manager->event,
                             &scope->mdns_goodbye_event_source,
                             CLOCK_BOOTTIME,
                             until,
                             /* accuracy= */ 0,
                             mdns_goodbye_callback,
                             scope,
                             /* priority= */ 0,
                             "mdns-goodbye",
                             force_reset);
        if (r < 0) {
                log_warning_errno(r, "mDNS: Failed to arm goodbye timer, ignoring: %m");

                /* Release it rather than leaving it behind. A source event_reset_time() merely
                 * left disabled would be re-armed correctly next time, but a *failed* reset stops
                 * mid-sequence -- set_enabled(SD_EVENT_ONESHOT) may have landed while set_priority()
                 * or set_description() failed -- leaving an enabled source holding this arm's
                 * deadline, which the next force_reset=false arm would then keep while discarding
                 * its own. */
                scope->mdns_goodbye_event_source =
                        sd_event_source_disable_unref(scope->mdns_goodbye_event_source);
        }
}

int mdns_goodbye_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        DnsScope *scope = userdata;
        usec_t t, until;
        int r;

        assert(scope);

        /* 's' is not read below, but it is load-bearing all the same: the release path acts on
         * scope->mdns_goodbye_event_source on the assumption that it is this very source. Now that
         * the handler is callable from the test, say so. */
        assert(s == scope->mdns_goodbye_event_source);

        dns_cache_prune(&scope->cache);

        r = mdns_notify_browsers_goodbye(scope);
        if (r < 0)
                log_warning_errno(r, "mDNS: Failed to notify service subscribers of goodbyes, ignoring: %m");

        /* Keep going for as long as something expires within the goodbye window, re-arming right at
         * that expiry rather than a flat second out, so the prune that drops the record (and tells
         * the browsers) runs when the record actually expires. force_reset, because the source is
         * disabled by the time a real dispatch gets here, but a caller invoking this handler
         * directly still has it armed and the new deadline must win either way. */
        t = now(CLOCK_BOOTTIME);

        until = mdns_goodbye_next_deadline(scope, t);
        if (until == USEC_INFINITY)
                /* Nothing due within the window: release the timer, so the next goodbye arms a
                 * fresh one instead of finding this one still sitting there. */
                scope->mdns_goodbye_event_source =
                        sd_event_source_disable_unref(scope->mdns_goodbye_event_source);
        else
                mdns_goodbye_arm(scope, until, /* force_reset= */ true);

        return 0;
}

/* RFC 6762 section 10.1: a goodbye carries its records with TTL 0, and the receiver expires them a
 * second later rather than dropping them outright -- so they go into the cache with TTL 1 and the
 * removal is driven off that expiry. Returns whether the answer carried any, i.e. whether a goodbye
 * pass has to be armed once the cache has taken them; the arm has to wait for the put, because the
 * expiry it reads is the one the put computes. */
bool mdns_answer_rewrite_goodbye_ttls(DnsAnswer *answer) {
        DnsResourceRecord *rr;
        bool goodbye = false;

        DNS_ANSWER_FOREACH(rr, answer)
                if (rr->ttl == 0) {
                        log_debug("Got a goodbye packet");
                        rr->ttl = 1;
                        goodbye = true;
                }

        return goodbye;
}

/* Arm the goodbye pass against the expiry the put just computed, so the records are dropped — and
 * the service browsers told — when they actually come due. Other paths do prune and reconcile
 * (any matching unsolicited reply, a completing browse query, the TTL maintenance ladder), but
 * none of them is tied to this expiry, so none is a reliable trigger for it.
 *
 * The put need not have left anything due behind: a goodbye for a record we do not hold is not
 * cached at all (dns_cache_put_positive() declines TTL<=1 for a record it does not already have), a
 * cache-flush goodbye drops its record outright, caching may be off entirely, and what remains may
 * be an unrelated record hours out, which mdns_goodbye_next_deadline() rejects just the same. The
 * subscribers still have to hear about it, so fall back to the far end of the window: the
 * reconciliation the callback runs is what tells them, due record or not.
 *
 * An already armed timer keeps its deadline, and the callback re-arms for whatever is left — see
 * mdns_goodbye_arm(). */
void mdns_goodbye_arm_on_receipt(DnsScope *scope) {
        usec_t t, until;

        assert(scope);

        /* Prune first, as the callback does. Nothing else prunes this cache while no browse question
         * is live, so a stale entry left over from an earlier goodbye would otherwise be the soonest
         * "expiry" and drag the deadline down to the floor -- costing an extra prune-and-reconcile
         * pass before the one this goodbye actually needs. Dropping it here loses no removal: the
         * pass being armed is what tells the subscribers either way. */
        dns_cache_prune(&scope->cache);

        t = now(CLOCK_BOOTTIME);

        until = mdns_goodbye_next_deadline(scope, t);
        if (until == USEC_INFINITY)
                until = usec_add(t, MDNS_GOODBYE_DELAY);

        mdns_goodbye_arm(scope, until, /* force_reset= */ false);
}

static int on_mdns_packet(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        Manager *m = userdata;
        DnsScope *scope;
        int r;
        bool unsolicited_packet = true;

        r = manager_recv(m, fd, DNS_PROTOCOL_MDNS, &p);
        if (r <= 0)
                return r;

        /* Refuse traffic from the local host, to avoid query loops. However, allow legacy mDNS
         * unicast queries through anyway (we never send those ourselves, hence no risk).
         * i.e. check for the source port nr. */
        if (p->sender_port == MDNS_PORT && manager_packet_from_local_address(m, p)) {
                log_debug("Got mDNS UDP packet from local host, ignoring.");
                return 0;
        }

        scope = manager_find_scope(m, p);
        if (!scope) {
                log_debug("Got mDNS UDP packet on unknown scope. Ignoring.");
                return 0;
        }

        if (dns_packet_validate_reply(p) > 0) {
                DnsResourceRecord *rr;
                bool goodbye = false;

                /* RFC 6762 section 6:
                 * The source UDP port in all Multicast DNS responses MUST be 5353 (the well-known port
                 * assigned to mDNS). Multicast DNS implementations MUST silently ignore any Multicast DNS
                 * responses they receive where the source UDP port is not 5353. */
                if (p->sender_port != MDNS_PORT) {
                        log_debug("Got mDNS reply from non-mDNS port %u (not %i), ignoring.", p->sender_port, MDNS_PORT);
                        return 0;
                }

                log_debug("Got mDNS reply packet");

                /*
                 * mDNS is different from regular DNS and LLMNR with regard to handling responses.
                 * While on other protocols, we can ignore every answer that doesn't match a question
                 * we broadcast earlier, RFC6762, section 18.1 recommends looking at and caching all
                 * incoming information, regardless of the DNS packet ID.
                 *
                 * Hence, extract the packet here, and try to find a transaction for answer the we got
                 * and complete it. Also store the new information in scope's cache.
                 */
                r = dns_packet_extract(p);
                if (r < 0) {
                        log_debug("mDNS packet extraction failed.");
                        return 0;
                }

                dns_scope_check_conflicts(scope, p);

                DNS_ANSWER_FOREACH(rr, p->answer) {
                        const char *name;

                        name = dns_resource_key_name(rr->key);

                        /* If the received reply packet contains ANY record that is not .local
                         * or .in-addr.arpa or .ip6.arpa, we assume someone's playing tricks on
                         * us and discard the packet completely. */
                        if (!(dns_name_endswith(name, "in-addr.arpa") > 0 ||
                              dns_name_endswith(name, "ip6.arpa") > 0 ||
                              dns_name_endswith(name, "local") > 0))
                                return 0;
                }

                goodbye = mdns_answer_rewrite_goodbye_ttls(p->answer);

                dns_cache_put(
                                &scope->cache,
                                scope->manager->enable_cache,
                                DNS_PROTOCOL_MDNS,
                                /* key= */ NULL,
                                dns_packet_rcode(p),
                                p->answer,
                                /* full_packet= */ NULL,
                                /* query_flags= */ false,
                                _DNSSEC_RESULT_INVALID,
                                /* nsec_ttl= */ UINT32_MAX,
                                p->family,
                                &p->sender,
                                scope->manager->stale_retention_usec);

                /* The put above is what the goodbye timer reads: arm it now that it has run. */
                if (goodbye)
                        mdns_goodbye_arm_on_receipt(scope);

                for (bool match = true; match;) {
                        match = false;
                        LIST_FOREACH(transactions_by_scope, t, scope->transactions) {
                                if (t->state != DNS_TRANSACTION_PENDING)
                                        continue;

                                r = dns_answer_match_key(p->answer, dns_transaction_key(t), NULL);
                                if (r <= 0) {
                                        if (r < 0)
                                                log_debug_errno(r, "Failed to match resource key, ignoring: %m");
                                        continue;
                                }

                                unsolicited_packet = false;
                                /* This packet matches the transaction, let's pass it on as reply */
                                dns_transaction_process_reply(t, p, false);

                                /* The dns_transaction_process_reply() -> dns_transaction_complete() ->
                                 * dns_query_candidate_stop() may free multiple transactions. Hence, restart
                                 * the loop. */
                                match = true;
                                break;
                        }
                }
                /* Check if incoming packet key matches with active browse clients. If yes, update the same */
                if (unsolicited_packet)
                        mdns_notify_browsers_unsolicited_updates(m, p->answer, p->family);
        } else if (dns_packet_validate_query(p) > 0)  {
                log_debug("Got mDNS query packet for id %u", DNS_PACKET_ID(p));

                r = mdns_scope_process_query(scope, p);
                if (r < 0) {
                        log_debug_errno(r, "mDNS query processing failed: %m");
                        return 0;
                }
        } else
                log_debug("Invalid mDNS UDP packet.");

        return 0;
}

int manager_mdns_ipv4_fd(Manager *m) {
        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(MDNS_PORT),
        };
        _cleanup_close_ int s = -EBADF;
        int r;

        assert(m);

        if (m->mdns_ipv4_fd >= 0)
                return m->mdns_ipv4_fd;

        s = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (s < 0)
                return log_error_errno(errno, "mDNS-IPv4: Failed to create socket: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_TTL, 255);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv4: Failed to set IP_TTL: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_MULTICAST_TTL, 255);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv4: Failed to set IP_MULTICAST_TTL: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_MULTICAST_LOOP, true);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv4: Failed to set IP_MULTICAST_LOOP: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_PKTINFO, true);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv4: Failed to set IP_PKTINFO: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_RECVTTL, true);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv4: Failed to set IP_RECVTTL: %m");

        /* Disable Don't-Fragment bit in the IP header */
        r = setsockopt_int(s, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv4: Failed to set IP_MTU_DISCOVER: %m");

        /* See the section 15.1 of RFC6762 */
        /* first try to bind without SO_REUSEADDR to detect another mDNS responder */
        r = bind(s, &sa.sa, sizeof(sa.in));
        if (r < 0) {
                if (errno != EADDRINUSE)
                        return log_error_errno(errno, "mDNS-IPv4: Failed to bind socket: %m");

                log_warning("mDNS-IPv4: There appears to be another mDNS responder running, or previously systemd-resolved crashed with some outstanding transfers.");

                /* try again with SO_REUSEADDR */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
                if (r < 0)
                        return log_error_errno(r, "mDNS-IPv4: Failed to set SO_REUSEADDR: %m");

                r = bind(s, &sa.sa, sizeof(sa.in));
                if (r < 0)
                        return log_error_errno(errno, "mDNS-IPv4: Failed to bind socket: %m");
        } else {
                /* enable SO_REUSEADDR for the case that the user really wants multiple mDNS responders */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
                if (r < 0)
                        return log_error_errno(r, "mDNS-IPv4: Failed to set SO_REUSEADDR: %m");
        }

        r = sd_event_add_io(m->event, &m->mdns_ipv4_event_source, s, EPOLLIN, on_mdns_packet, m);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv4: Failed to create event source: %m");

        (void) sd_event_source_set_description(m->mdns_ipv4_event_source, "mdns-ipv4");

        return m->mdns_ipv4_fd = TAKE_FD(s);
}

int manager_mdns_ipv6_fd(Manager *m) {
        union sockaddr_union sa = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(MDNS_PORT),
        };
        _cleanup_close_ int s = -EBADF;
        int r;

        assert(m);

        if (m->mdns_ipv6_fd >= 0)
                return m->mdns_ipv6_fd;

        s = socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (s < 0)
                return log_error_errno(errno, "mDNS-IPv6: Failed to create socket: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 255);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv6: Failed to set IPV6_UNICAST_HOPS: %m");

        /* RFC 6762, section 11 recommends setting the TTL of UDP packets to 255. */
        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 255);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv6: Failed to set IPV6_MULTICAST_HOPS: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, true);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv6: Failed to set IPV6_MULTICAST_LOOP: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_V6ONLY, true);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv6: Failed to set IPV6_V6ONLY: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, true);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv6: Failed to set IPV6_RECVPKTINFO: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, true);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv6: Failed to set IPV6_RECVHOPLIMIT: %m");

        /* See the section 15.1 of RFC6762 */
        /* first try to bind without SO_REUSEADDR to detect another mDNS responder */
        r = bind(s, &sa.sa, sizeof(sa.in6));
        if (r < 0) {
                if (errno != EADDRINUSE)
                        return log_error_errno(errno, "mDNS-IPv6: Failed to bind socket: %m");

                log_warning("mDNS-IPv6: There appears to be another mDNS responder running, or previously systemd-resolved crashed with some outstanding transfers.");

                /* try again with SO_REUSEADDR */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
                if (r < 0)
                        return log_error_errno(r, "mDNS-IPv6: Failed to set SO_REUSEADDR: %m");

                r = bind(s, &sa.sa, sizeof(sa.in6));
                if (r < 0)
                        return log_error_errno(errno, "mDNS-IPv6: Failed to bind socket: %m");
        } else {
                /* enable SO_REUSEADDR for the case that the user really wants multiple mDNS responders */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
                if (r < 0)
                        return log_error_errno(r, "mDNS-IPv6: Failed to set SO_REUSEADDR: %m");
        }

        r = sd_event_add_io(m->event, &m->mdns_ipv6_event_source, s, EPOLLIN, on_mdns_packet, m);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv6: Failed to create event source: %m");

        (void) sd_event_source_set_description(m->mdns_ipv6_event_source, "mdns-ipv6");

        return m->mdns_ipv6_fd = TAKE_FD(s);
}
