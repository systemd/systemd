/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/ipv6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "dns-answer.h"
#include "dns-domain.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "list.h"
#include "log.h"
#include "random-util.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-transaction.h"
#include "resolved-dns-zone.h"
#include "resolved-link.h"
#include "resolved-manager.h"
#include "resolved-mdns.h"
#include "resolved-timeouts.h"
#include "sort-util.h"
#include "time-util.h"

#define CLEAR_CACHE_FLUSH(x) (~MDNS_RR_CACHE_FLUSH_OR_QU & (x))

/* Upper bound on replies deferred per scope, so that a flood of TC queries can't make us hold arbitrary
 * amounts of state */
#define MDNS_PENDING_REPLIES_MAX 64U

struct MdnsPendingReply {
        DnsScope *scope;

        int family;
        union in_addr_union sender;
        uint16_t sender_port;
        uint16_t id;
        bool unicast_reply;

        DnsAnswer *answer;
        sd_event_source *timer_event_source;

        LIST_FIELDS(MdnsPendingReply, pending_replies);
};

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

        r = dns_resource_record_to_wire_format(x, /* canonical= */ false);
        if (r < 0) {
                log_warning_errno(r, "Can't wire-format RR: %m");
                return 0;
        }

        r = dns_resource_record_to_wire_format(y, /* canonical= */ false);
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
                        r = dns_resource_key_match_rr(key, rr, /* search_domain= */ NULL);
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
                        r = dns_resource_key_match_rr(key, rr, /* search_domain= */ NULL);
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

static int mdns_scope_build_answer(DnsScope *s, DnsPacket *p, bool legacy_query, DnsAnswer **ret) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *full_answer = NULL;
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr;
        bool tentative = false;
        int r;

        assert(s);
        assert(p);
        assert(ret);

        DNS_QUESTION_FOREACH(key, p->question) {
                _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL, *soa = NULL;
                DnsAnswerItem *item;

                r = dns_zone_lookup(&s->zone, key, /* ifindex= */ 0, &answer, &soa, &tentative);
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

        *ret = TAKE_PTR(full_answer);
        return 0;
}

static int mdns_scope_send_reply(
                DnsScope *s,
                uint16_t id,
                DnsQuestion *question,
                DnsAnswer *answer,
                bool unicast_reply,
                const union in_addr_union *destination,
                uint16_t destination_port) {

        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
        int r;

        assert(s);
        assert(destination);

        if (dns_answer_isempty(answer))
                return 0;

        r = dns_scope_make_reply_packet(s, id, DNS_RCODE_SUCCESS, question, answer,
                                        /* soa= */ NULL, /* tentative= */ false, &reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to build reply packet: %m");

        if (!ratelimit_below(&s->ratelimit))
                return 0;

        if (unicast_reply) {
                reply->destination = *destination;
                reply->destination_port = destination_port;
        }
        r = dns_scope_emit_udp(s, -1, AF_UNSPEC, reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to send reply packet: %m");

        return 0;
}

int mdns_answer_suppress_known(DnsAnswer **answer, DnsAnswer *known) {
        DnsAnswerItem *k;
        int r;

        assert(answer);

        /* RFC 6762, Section 7.1: drop any record from our answer that the querier already listed in the
         * Answer section of its query, with a TTL at least half of the correct value. Records from the
         * Authority and Additional sections (e.g. the proposed records of a probe) don't count. */

        DNS_ANSWER_FOREACH_ITEM(k, known) {
                DnsResourceRecord *rr;
                bool suppress = false;

                if (!FLAGS_SET(k->flags, DNS_ANSWER_SECTION_ANSWER))
                        continue;

                DNS_ANSWER_FOREACH(rr, *answer) {
                        r = dns_resource_record_equal(rr, k->rr);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                suppress = (uint64_t) k->rr->ttl * 2 >= rr->ttl;
                                break;
                        }
                }

                if (suppress) {
                        r = dns_answer_remove_by_rr(answer, k->rr);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

MdnsPendingReply* mdns_pending_reply_free(MdnsPendingReply *pr) {
        if (!pr)
                return NULL;

        if (pr->scope) {
                LIST_REMOVE(pending_replies, pr->scope->mdns_pending_replies, pr);
                assert(pr->scope->n_mdns_pending_replies > 0);
                pr->scope->n_mdns_pending_replies--;
        }

        sd_event_source_disable_unref(pr->timer_event_source);
        dns_answer_unref(pr->answer);
        return mfree(pr);
}

static MdnsPendingReply* mdns_pending_reply_find(DnsScope *s, const DnsPacket *p) {
        assert(s);
        assert(p);

        LIST_FOREACH(pending_replies, pr, s->mdns_pending_replies)
                if (pr->family == p->family &&
                    pr->sender_port == p->sender_port &&
                    in_addr_equal(p->family, &pr->sender, &p->sender) > 0)
                        return pr;

        return NULL;
}

static int mdns_answer_drop_stale(DnsScope *s, DnsAnswer **answer) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *owned = NULL;
        DnsAnswerItem *item;
        int r;

        assert(s);
        assert(answer);

        /* Our zone might have changed while the reply was pending (e.g. a conflict was detected or a
         * service was removed). Don't announce anything we no longer own. */

        DNS_ANSWER_FOREACH_ITEM(item, *answer) {
                DnsZoneItem *i;

                i = dns_zone_get(&s->zone, item->rr);
                if (!i || i->state == DNS_ZONE_ITEM_WITHDRAWN)
                        continue;

                r = dns_answer_add_extend_full(&owned, item->rr, item->ifindex, item->flags, item->rrsig, item->until);
                if (r < 0)
                        return r;
        }

        dns_answer_unref(*answer);
        *answer = TAKE_PTR(owned);
        return 0;
}

static int on_mdns_pending_reply_timeout(sd_event_source *es, usec_t usec, void *userdata) {
        MdnsPendingReply *pr = ASSERT_PTR(userdata);
        int r;

        r = mdns_answer_drop_stale(pr->scope, &pr->answer);
        if (r < 0)
                log_debug_errno(r, "Failed to drop stale records from deferred mDNS reply, ignoring: %m");
        else if (dns_answer_isempty(pr->answer))
                log_debug("Nothing left to send in deferred mDNS reply, not replying.");
        else
                (void) mdns_scope_send_reply(pr->scope, pr->id, /* question= */ NULL, pr->answer,
                                             pr->unicast_reply, &pr->sender, pr->sender_port);

        mdns_pending_reply_free(pr);
        return 0;
}

static int mdns_scope_defer_reply(DnsScope *s, DnsPacket *p, DnsAnswer *answer, bool unicast_reply) {
        _cleanup_(mdns_pending_reply_freep) MdnsPendingReply *pr = NULL;
        MdnsPendingReply *existing;
        int r;

        assert(s);
        assert(p);

        /* RFC 6762, Section 7.2: the querier set the TC bit, so more Known-Answer packets are on their way.
         * Wait a random 400-500ms for them before replying. */

        existing = mdns_pending_reply_find(s, p);
        if (existing) {
                /* The querier sent another TC query before we replied. Merge the answers but keep the
                 * timer, so that a querier can't postpone our reply indefinitely. */
                r = dns_answer_extend(&existing->answer, answer);
                if (r < 0)
                        return log_debug_errno(r, "Failed to merge deferred mDNS reply: %m");

                existing->unicast_reply = existing->unicast_reply && unicast_reply;
                return 1;
        }

        if (s->n_mdns_pending_replies >= MDNS_PENDING_REPLIES_MAX) {
                log_debug("Too many deferred mDNS replies, replying immediately.");
                return 0;
        }

        pr = new(MdnsPendingReply, 1);
        if (!pr)
                return log_oom();

        *pr = (MdnsPendingReply) {
                .family = p->family,
                .sender = p->sender,
                .sender_port = p->sender_port,
                .id = DNS_PACKET_ID(p),
                .unicast_reply = unicast_reply,
                .answer = dns_answer_ref(answer),
        };

        r = sd_event_add_time_relative(
                        s->manager->event,
                        &pr->timer_event_source,
                        CLOCK_BOOTTIME,
                        MDNS_TC_DELAY_MIN_USEC +
                        random_u64_range(MDNS_TC_DELAY_MAX_USEC - MDNS_TC_DELAY_MIN_USEC),
                        /* accuracy= */ USEC_PER_MSEC,
                        on_mdns_pending_reply_timeout,
                        pr);
        if (r < 0)
                return log_debug_errno(r, "Failed to schedule deferred mDNS reply: %m");

        (void) sd_event_source_set_description(pr->timer_event_source, "mdns-pending-reply");

        pr->scope = s;
        LIST_PREPEND(pending_replies, s->mdns_pending_replies, pr);
        s->n_mdns_pending_replies++;

        log_debug("Query has TC bit set, deferring mDNS reply for more Known-Answer packets.");

        TAKE_PTR(pr);
        return 1;
}

static int mdns_scope_process_known_answers(DnsScope *s, DnsPacket *p) {
        MdnsPendingReply *pr;
        int r;

        assert(s);
        assert(p);

        /* RFC 6762, Section 7.2: while a reply to a query with the TC bit set is pending, any later packet
         * from the same querier may carry more Known-Answers, typically one with no questions at all. If we
         * have no reply pending for the sender, there's nothing to suppress. */

        pr = mdns_pending_reply_find(s, p);
        if (!pr)
                return 0;

        r = mdns_answer_suppress_known(&pr->answer, p->answer);
        if (r < 0)
                return log_debug_errno(r, "Failed to apply Known-Answer suppression: %m");

        return 0;
}

static int mdns_scope_process_query(DnsScope *s, DnsPacket *p) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        bool legacy_query = p->sender_port != MDNS_PORT;
        bool unicast_reply;
        int r;

        assert(s);
        assert(p);

        r = dns_packet_extract(p);
        if (r < 0)
                return log_debug_errno(r, "Failed to extract resource records from incoming packet: %m");

        /* Known-Answer suppression is a feature of multicast queriers, legacy queriers don't use it. */
        if (!legacy_query) {
                r = mdns_scope_process_known_answers(s, p);
                if (r < 0)
                        return r;
        }

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

        r = mdns_scope_build_answer(s, p, legacy_query, &answer);
        if (r < 0)
                return r;

        if (!legacy_query) {
                r = mdns_answer_suppress_known(&answer, p->answer);
                if (r < 0)
                        return log_debug_errno(r, "Failed to apply Known-Answer suppression: %m");
        }

        if (dns_answer_isempty(answer))
                return 0;

        if (DNS_PACKET_TC(p) && !legacy_query) {
                r = mdns_scope_defer_reply(s, p, answer, unicast_reply);
                if (r != 0)
                        return r;
        }

        return mdns_scope_send_reply(s, DNS_PACKET_ID(p),
                                     legacy_query ? p->question : NULL, answer,
                                     unicast_reply, &p->sender, p->sender_port);
}

static int mdns_goodbye_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        DnsScope *scope = userdata;
        int r;

        assert(s);
        assert(scope);

        scope->mdns_goodbye_event_source = sd_event_source_disable_unref(scope->mdns_goodbye_event_source);

        dns_cache_prune(&scope->cache);

        r = mdns_notify_browsers_goodbye(scope);
        if (r < 0)
                log_warning_errno(r, "mDNS: Failed to notify service subscribers of goodbyes, ignoring: %m");

        if (dns_cache_expiry_in_one_second(&scope->cache, usec)) {
                r = sd_event_add_time_relative(
                                scope->manager->event,
                                &scope->mdns_goodbye_event_source,
                                CLOCK_BOOTTIME,
                                USEC_PER_SEC,
                                /* accuracy= */ 0,
                                mdns_goodbye_callback,
                                scope);
                if (r < 0)
                        return log_warning_errno(r, "mDNS: Failed to re-schedule goodbye callback, ignoring: %m");
        }

        return 0;
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

                        if (rr->ttl == 0) {
                                log_debug("Got a goodbye packet");
                                /* See the section 10.1 of RFC6762 */
                                rr->ttl = 1;

                                /* Look at the cache 1 second later and remove stale entries.
                                 * This is particularly useful to keep service browsers updated on service removal,
                                 * as there are no other reliable triggers to propagate that info. */
                                if (!scope->mdns_goodbye_event_source) {
                                        r = sd_event_add_time_relative(
                                                        scope->manager->event,
                                                        &scope->mdns_goodbye_event_source,
                                                        CLOCK_BOOTTIME,
                                                        USEC_PER_SEC,
                                                        /* accuracy= */ 0,
                                                        mdns_goodbye_callback,
                                                        scope);
                                        if (r < 0)
                                                return r;
                                }
                        }
                }

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

                for (bool match = true; match;) {
                        match = false;
                        LIST_FOREACH(transactions_by_scope, t, scope->transactions) {
                                if (t->state != DNS_TRANSACTION_PENDING)
                                        continue;

                                r = dns_answer_match_key(p->answer, dns_transaction_key(t), /* ret_flags= */ NULL);
                                if (r <= 0) {
                                        if (r < 0)
                                                log_debug_errno(r, "Failed to match resource key, ignoring: %m");
                                        continue;
                                }

                                unsolicited_packet = false;
                                /* This packet matches the transaction, let's pass it on as reply */
                                dns_transaction_process_reply(t, p, /* encrypted= */ false);

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

        r = setsockopt_int(s, IPPROTO_IP, IP_MULTICAST_LOOP, /* value= */ true);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv4: Failed to set IP_MULTICAST_LOOP: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_PKTINFO, /* value= */ true);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv4: Failed to set IP_PKTINFO: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_RECVTTL, /* value= */ true);
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
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, /* value= */ true);
                if (r < 0)
                        return log_error_errno(r, "mDNS-IPv4: Failed to set SO_REUSEADDR: %m");

                r = bind(s, &sa.sa, sizeof(sa.in));
                if (r < 0)
                        return log_error_errno(errno, "mDNS-IPv4: Failed to bind socket: %m");
        } else {
                /* enable SO_REUSEADDR for the case that the user really wants multiple mDNS responders */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, /* value= */ true);
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

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, /* value= */ true);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv6: Failed to set IPV6_MULTICAST_LOOP: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_V6ONLY, /* value= */ true);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv6: Failed to set IPV6_V6ONLY: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, /* value= */ true);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv6: Failed to set IPV6_RECVPKTINFO: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, /* value= */ true);
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
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, /* value= */ true);
                if (r < 0)
                        return log_error_errno(r, "mDNS-IPv6: Failed to set SO_REUSEADDR: %m");

                r = bind(s, &sa.sa, sizeof(sa.in6));
                if (r < 0)
                        return log_error_errno(errno, "mDNS-IPv6: Failed to bind socket: %m");
        } else {
                /* enable SO_REUSEADDR for the case that the user really wants multiple mDNS responders */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, /* value= */ true);
                if (r < 0)
                        return log_error_errno(r, "mDNS-IPv6: Failed to set SO_REUSEADDR: %m");
        }

        r = sd_event_add_io(m->event, &m->mdns_ipv6_event_source, s, EPOLLIN, on_mdns_packet, m);
        if (r < 0)
                return log_error_errno(r, "mDNS-IPv6: Failed to create event source: %m");

        (void) sd_event_source_set_description(m->mdns_ipv6_event_source, "mdns-ipv6");

        return m->mdns_ipv6_fd = TAKE_FD(s);
}

static int mdns_announcement_packet_new(size_t max_size, DnsPacket **ret) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        int r;

        assert(ret);

        r = dns_packet_new(&p, DNS_PROTOCOL_MDNS, /* min_alloc_dsize= */ 0, max_size);
        if (r < 0)
                return r;

        DNS_PACKET_HEADER(p)->flags = htobe16(DNS_PACKET_MAKE_FLAGS(
                                                              1 /* qr */,
                                                              0 /* opcode */,
                                                              1 /* aa, see RFC 6762, section 18.4 */,
                                                              0 /* tc */,
                                                              0 /* (tentative) */,
                                                              0 /* (ra) */,
                                                              0 /* (ad) */,
                                                              0 /* (cd) */,
                                                              DNS_RCODE_SUCCESS));

        *ret = TAKE_PTR(p);
        return 0;
}

/* Append one record to the packet under construction, creating it first if there is none, and
 * count it in the packet's own header. Returns -EMSGSIZE when the record does not fit, which the
 * caller answers by sealing what it has (or by widening the packet), exactly as it would for a bare
 * dns_packet_append_rr(). */
static int mdns_announcement_packet_append(DnsPacket **p, size_t max_size, DnsAnswerItem *item) {
        int r;

        assert(p);
        assert(item);

        if (!*p) {
                r = mdns_announcement_packet_new(max_size, p);
                if (r < 0)
                        return r;
        }

        r = dns_packet_append_rr(*p, item->rr, item->flags,
                                 /* start= */ NULL, /* rdata_start= */ NULL);
        if (r < 0)
                return r;

        DNS_PACKET_HEADER(*p)->ancount = htobe16(DNS_PACKET_ANCOUNT(*p) + 1);
        return 0;
}

/* Push the announcement packet under construction onto the result array; its ancount has been kept
 * current by every append. A no-op without a packet or without any RRs appended yet. */
static int mdns_announcement_packet_seal(
                DnsPacket ***packets,
                size_t *n_packets,
                DnsPacket **p) {

        assert(packets);
        assert(n_packets);
        assert(p);

        if (!*p || DNS_PACKET_ANCOUNT(*p) == 0)
                return 0;

        if (!GREEDY_REALLOC(*packets, *n_packets + 1))
                return -ENOMEM;

        (*packets)[(*n_packets)++] = TAKE_PTR(*p);

        return 0;
}

/* The datagram size every host of the family must be able to accept: RFC 791 section 3.1 for IPv4,
 * RFC 8200 section 5's minimum link MTU for IPv6, which no link fragments. */
static size_t fallback_mtu(int family) {
        assert(IN_SET(family, AF_INET, AF_INET6));

        return family == AF_INET6 ? IPV6_MIN_MTU : MDNS_PACKET_UNKNOWN_MTU_IPV4;
}

/* Derive the two size bounds an announcement is packed to, from the address family and the link MTU
 * (0 while the link's MTU is not known yet, or too small to carry a packet).
 *
 * RFC 6762 section 17's hard ceiling -- "even when fragmentation is used, a Multicast DNS packet,
 * including IP and UDP headers, MUST NOT exceed 9000 bytes" -- binds every packet we emit, so it caps
 * the MTU-derived size on jumbo-frame links just as much as it caps the lone oversized-RR fallback.
 * A fragmented IPv6 datagram additionally carries an 8-byte Fragment extension header (RFC 8200
 * section 4.5) that counts against the ceiling. */
void mdns_announcement_max_sizes(
                int family,
                size_t link_mtu,
                size_t *ret_max_size,
                size_t *ret_fragmented_max) {

        size_t header_size, fragmented_max, max_size;

        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(ret_max_size);
        assert(ret_fragmented_max);

        header_size = udp_header_size(family);
        assert(MDNS_PACKET_FRAGMENTED_SIZE_MAX >
               header_size + sizeof(struct ip6_frag) + DNS_PACKET_HEADER_SIZE);
        fragmented_max = MDNS_PACKET_FRAGMENTED_SIZE_MAX - header_size -
                (family == AF_INET6 ? sizeof(struct ip6_frag) : 0);

        /* An unsolicited DNS-SD announcement (or goodbye) covers the whole zone, which easily outgrows
         * both the compression pointer range that dns_packet_append_name() can address and the interface
         * MTU that RFC 6762 section 17 expects multicast DNS messages to fit into. Instead of emitting
         * one oversized datagram, split the RRset across as many MTU-sized packets as needed. */
        if (link_mtu > header_size + DNS_PACKET_HEADER_SIZE)
                max_size = link_mtu - header_size;
        else
                /* Nothing to derive from: the MTU is not read yet (0), or subtracting the headers
                 * would underflow or leave less than the DNS header dns_packet_new() asserts room
                 * for. Assume what every host of the family must accept instead -- not the section
                 * 17 ceiling, which is the bound for a datagram deliberately fragmented to carry one
                 * record. A derivable bound is kept even where no record fits it: the records then
                 * go out one per fragmented packet, which is the only shape section 17 allows. */
                max_size = fallback_mtu(family) - header_size;

        *ret_max_size = MIN(max_size, fragmented_max);
        *ret_fragmented_max = fragmented_max;
}

/* Pack the answer's records into as many announcement packets of at most max_size bytes as needed,
 * in answer order, each with its ancount finalized. A single record that does not fit any packet
 * on its own is retried alone within fragmented_max -- RFC 6762 section 17 allows a lone resource
 * record to rely on IP fragmentation, up to a hard 9000-byte ceiling including headers -- and
 * dropped if even that bound cannot accommodate it, as is a record that cannot be encoded at any
 * size. Returns how many were dropped that way, so a caller can report it: nothing else
 * distinguishes an announcement that carried everything from one that did not. */
int mdns_announcement_packetize(
                DnsAnswer *answer,
                size_t max_size,
                size_t fragmented_max,
                DnsPacket ***ret_packets,
                size_t *ret_n_packets) {

        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        DnsPacket **packets = NULL;
        size_t n_packets = 0;
        DnsAnswerItem *item;
        unsigned n_skipped = 0;
        int r;

        assert(max_size <= fragmented_max);
        assert(ret_packets);
        assert(ret_n_packets);

        CLEANUP_ARRAY(packets, n_packets, dns_packet_unref_array);

        DNS_ANSWER_FOREACH_ITEM(item, answer) {
                r = mdns_announcement_packet_append(&p, max_size, item);
                if (r == -EMSGSIZE && p && DNS_PACKET_ANCOUNT(p) > 0) {
                        /* Packet full -- seal it and retry this RR in a fresh one. */
                        r = mdns_announcement_packet_seal(&packets, &n_packets, &p);
                        if (r < 0)
                                return r;

                        r = mdns_announcement_packet_append(&p, max_size, item);
                }
                if (r == -EMSGSIZE && max_size < fragmented_max) {
                        /* A single RR larger than the MTU. Emit it alone in an oversized packet
                         * within the section 17 fragmented-packet ceiling. */
                        p = dns_packet_unref(p);

                        r = mdns_announcement_packet_append(&p, fragmented_max, item);
                        if (r >= 0) {
                                /* Sealed alone: nothing that follows may be packed to this bound. */
                                r = mdns_announcement_packet_seal(&packets, &n_packets, &p);
                                if (r < 0)
                                        return r;

                                continue;
                        }
                }
                /* No packet we can build fits this record: too large even for the section 17
                 * ceiling, or not encodable at all (-E2BIG; -ENOSPC is defensive, no bound we pack
                 * to lets a packet grow that far). Skip it rather than fail the announcement --
                 * dns_packet_append_rr() rolled the packet back, so its neighbours are intact. An
                 * empty packet is dropped: the fragmented retry may have widened it, and the
                 * records that follow must not be packed to that bound. */
                if (IN_SET(r, -EMSGSIZE, -ENOSPC, -E2BIG)) {
                        log_debug_errno(r, "Skipping resource record that does not fit an mDNS packet: %m");
                        if (p && DNS_PACKET_ANCOUNT(p) == 0)
                                p = dns_packet_unref(p);
                        n_skipped++;
                        continue;
                }
                if (r < 0)
                        return r;
        }

        r = mdns_announcement_packet_seal(&packets, &n_packets, &p);
        if (r < 0)
                return r;

        *ret_n_packets = n_packets;
        *ret_packets = TAKE_PTR(packets);
        return (int) n_skipped;
}
