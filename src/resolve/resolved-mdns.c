/* SPDX-License-Identifier: LGPL-2.1+ */

#include <resolv.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "resolved-manager.h"
#include "resolved-mdns.h"
#include "sort-util.h"

#define CLEAR_CACHE_FLUSH(x) (~MDNS_RR_CACHE_FLUSH & (x))

void manager_mdns_stop(Manager *m) {
        assert(m);

        m->mdns_ipv4_event_source = sd_event_source_unref(m->mdns_ipv4_event_source);
        m->mdns_ipv4_fd = safe_close(m->mdns_ipv4_fd);

        m->mdns_ipv6_event_source = sd_event_source_unref(m->mdns_ipv6_event_source);
        m->mdns_ipv6_fd = safe_close(m->mdns_ipv6_fd);
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

        if (socket_ipv6_is_supported()) {
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
        unsigned n = 0, size = 0;
        int r;

        assert(p);
        assert(key);
        assert(ret_rrs);
        assert_return(DNS_PACKET_NSCOUNT(p) > 0, -EINVAL);

        for (size_t i = DNS_PACKET_ANCOUNT(p); i < (DNS_PACKET_ANCOUNT(p) + DNS_PACKET_NSCOUNT(p)); i++) {
                r = dns_resource_key_match_rr(key, p->answer->items[i].rr, NULL);
                if (r < 0)
                        return r;
                if (r > 0)
                        size++;
        }

        if (size == 0)
                return 0;

        list = new(DnsResourceRecord *, size);
        if (!list)
                return -ENOMEM;

        for (size_t i = DNS_PACKET_ANCOUNT(p); i < (DNS_PACKET_ANCOUNT(p) + DNS_PACKET_NSCOUNT(p)); i++) {
                r = dns_resource_key_match_rr(key, p->answer->items[i].rr, NULL);
                if (r < 0)
                        return r;
                if (r > 0)
                        list[n++] = p->answer->items[i].rr;
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

        assert(r > 0);

        if (proposed_rrs_cmp(remote, r, our, size) > 0)
                return 1;

        return 0;
}

static int mdns_scope_process_query(DnsScope *s, DnsPacket *p) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *full_answer = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr;
        bool tentative = false;
        int r;

        assert(s);
        assert(p);

        r = dns_packet_extract(p);
        if (r < 0)
                return log_debug_errno(r, "Failed to extract resource records from incoming packet: %m");

        assert_return((dns_question_size(p->question) > 0), -EINVAL);

        DNS_QUESTION_FOREACH(key, p->question) {
                _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL, *soa = NULL;

                r = dns_zone_lookup(&s->zone, key, 0, &answer, &soa, &tentative);
                if (r < 0)
                        return log_debug_errno(r, "Failed to lookup key: %m");

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

                r = dns_answer_extend(&full_answer, answer);
                if (r < 0)
                        return log_debug_errno(r, "Failed to extend answer: %m");
        }

        if (dns_answer_isempty(full_answer))
                return 0;

        r = dns_scope_make_reply_packet(s, DNS_PACKET_ID(p), DNS_RCODE_SUCCESS, NULL, full_answer, NULL, false, &reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to build reply packet: %m");

        if (!ratelimit_below(&s->ratelimit))
                return 0;

        r = dns_scope_emit_udp(s, -1, reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to send reply packet: %m");

        return 0;
}

static int on_mdns_packet(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        Manager *m = userdata;
        DnsScope *scope;
        int r;

        r = manager_recv(m, fd, DNS_PROTOCOL_MDNS, &p);
        if (r <= 0)
                return r;

        if (manager_our_packet(m, p))
                return 0;

        scope = manager_find_scope(m, p);
        if (!scope) {
                log_debug("Got mDNS UDP packet on unknown scope. Ignoring.");
                return 0;
        }

        if (dns_packet_validate_reply(p) > 0) {
                DnsResourceRecord *rr;

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
                        const char *name = dns_resource_key_name(rr->key);
                        DnsTransaction *t;

                        /* If the received reply packet contains ANY record that is not .local or .in-addr.arpa,
                         * we assume someone's playing tricks on us and discard the packet completely. */
                        if (!(dns_name_endswith(name, "in-addr.arpa") > 0 ||
                              dns_name_endswith(name, "local") > 0))
                                return 0;

                        if (rr->ttl == 0) {
                                log_debug("Got a goodbye packet");
                                /* See the section 10.1 of RFC6762 */
                                rr->ttl = 1;
                        }

                        t = dns_scope_find_transaction(scope, rr->key, false);
                        if (t)
                                dns_transaction_process_reply(t, p);

                        /* Also look for the various types of ANY transactions */
                        t = dns_scope_find_transaction(scope, &DNS_RESOURCE_KEY_CONST(rr->key->class, DNS_TYPE_ANY, dns_resource_key_name(rr->key)), false);
                        if (t)
                                dns_transaction_process_reply(t, p);

                        t = dns_scope_find_transaction(scope, &DNS_RESOURCE_KEY_CONST(DNS_CLASS_ANY, rr->key->type, dns_resource_key_name(rr->key)), false);
                        if (t)
                                dns_transaction_process_reply(t, p);

                        t = dns_scope_find_transaction(scope, &DNS_RESOURCE_KEY_CONST(DNS_CLASS_ANY, DNS_TYPE_ANY, dns_resource_key_name(rr->key)), false);
                        if (t)
                                dns_transaction_process_reply(t, p);
                }

                dns_cache_put(&scope->cache, scope->manager->enable_cache, NULL, DNS_PACKET_RCODE(p), p->answer, false, (uint32_t) -1, 0, p->family, &p->sender);

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
        _cleanup_close_ int s = -1;
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

        return m->mdns_ipv4_fd = TAKE_FD(s);
}

int manager_mdns_ipv6_fd(Manager *m) {
        union sockaddr_union sa = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(MDNS_PORT),
        };
        _cleanup_close_ int s = -1;
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

        /* RFC 4795, section 2.5 recommends setting the TTL of UDP packets to 255. */
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

        return m->mdns_ipv6_fd = TAKE_FD(s);
}
