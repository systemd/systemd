/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/tcp.h>

#include "sd-event.h"
#include "sd-json.h"

#include "af-list.h"
#include "alloc-util.h"
#include "dns-domain.h"
#include "dns-type.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hostname-util.h"
#include "log.h"
#include "random-util.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-delegate.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-query.h"
#include "resolved-dns-question.h"
#include "resolved-dns-rr.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-server.h"
#include "resolved-dns-synthesize.h"
#include "resolved-dns-transaction.h"
#include "resolved-dns-zone.h"
#include "resolved-dnssd.h"
#include "resolved-link.h"
#include "resolved-llmnr.h"
#include "resolved-manager.h"
#include "resolved-mdns.h"
#include "resolved-timeouts.h"
#include "set.h"
#include "socket-util.h"
#include "string-table.h"

#define MULTICAST_RATELIMIT_INTERVAL_USEC (1*USEC_PER_SEC)
#define MULTICAST_RATELIMIT_BURST 1000

/* After how much time to repeat LLMNR requests, see RFC 4795 Section 7 */
#define MULTICAST_RESEND_TIMEOUT_MIN_USEC (100 * USEC_PER_MSEC)
#define MULTICAST_RESEND_TIMEOUT_MAX_USEC (1 * USEC_PER_SEC)

int dns_scope_new(
                Manager *m,
                DnsScope **ret,
                DnsScopeOrigin origin,
                Link *link,
                DnsDelegate *delegate,
                DnsProtocol protocol,
                int family) {

        DnsScope *s;

        assert(m);
        assert(ret);
        assert(origin >= 0);
        assert(origin < _DNS_SCOPE_ORIGIN_MAX);

        assert(!!link == (origin == DNS_SCOPE_LINK));
        assert(!!delegate == (origin == DNS_SCOPE_DELEGATE));

        s = new(DnsScope, 1);
        if (!s)
                return -ENOMEM;

        *s = (DnsScope) {
                .manager = m,
                .link = link,
                .delegate = delegate,
                .origin = origin,
                .protocol = protocol,
                .family = family,
                .resend_timeout = MULTICAST_RESEND_TIMEOUT_MIN_USEC,

                /* Enforce ratelimiting for the multicast protocols */
                .ratelimit = { MULTICAST_RATELIMIT_INTERVAL_USEC, MULTICAST_RATELIMIT_BURST },
        };

        if (protocol == DNS_PROTOCOL_DNS) {
                /* Copy DNSSEC mode from the link if it is set there,
                 * otherwise take the manager's DNSSEC mode. Note that
                 * we copy this only at scope creation time, and do
                 * not update it from the on, even if the setting
                 * changes. */

                if (link) {
                        s->dnssec_mode = link_get_dnssec_mode(link);
                        s->dns_over_tls_mode = link_get_dns_over_tls_mode(link);
                } else {
                        s->dnssec_mode = manager_get_dnssec_mode(m);
                        s->dns_over_tls_mode = manager_get_dns_over_tls_mode(m);
                }

        } else {
                s->dnssec_mode = DNSSEC_NO;
                s->dns_over_tls_mode = DNS_OVER_TLS_NO;
        }

        LIST_PREPEND(scopes, m->dns_scopes, s);

        dns_scope_llmnr_membership(s, true);
        dns_scope_mdns_membership(s, true);

        log_debug("New scope on link %s, protocol %s, family %s, origin %s, delegate %s",
                  link ? link->ifname : "*",
                  dns_protocol_to_string(protocol),
                  family == AF_UNSPEC ? "*" : af_to_name(family),
                  dns_scope_origin_to_string(origin),
                  s->delegate ? s->delegate->id : "n/a");

        *ret = s;
        return 0;
}

static void dns_scope_abort_transactions(DnsScope *s) {
        assert(s);

        while (s->transactions) {
                DnsTransaction *t = s->transactions;

                /* Abort the transaction, but make sure it is not
                 * freed while we still look at it */

                t->block_gc++;
                if (DNS_TRANSACTION_IS_LIVE(t->state))
                        dns_transaction_complete(t, DNS_TRANSACTION_ABORTED);
                t->block_gc--;

                dns_transaction_free(t);
        }
}

DnsScope* dns_scope_free(DnsScope *s) {
        if (!s)
                return NULL;

        log_debug("Removing scope on link %s, protocol %s, family %s, origin %s, delegate %s",
                  s->link ? s->link->ifname : "*",
                  dns_protocol_to_string(s->protocol),
                  s->family == AF_UNSPEC ? "*" : af_to_name(s->family),
                  dns_scope_origin_to_string(s->origin),
                  s->delegate ? s->delegate->id : "n/a");

        dns_scope_llmnr_membership(s, false);
        dns_scope_mdns_membership(s, false);
        dns_scope_abort_transactions(s);

        while (s->query_candidates)
                dns_query_candidate_unref(s->query_candidates);

        hashmap_free(s->transactions_by_key);

        ordered_hashmap_free(s->conflict_queue);
        sd_event_source_disable_unref(s->conflict_event_source);

        sd_event_source_disable_unref(s->announce_event_source);

        sd_event_source_disable_unref(s->mdns_goodbye_event_source);

        dns_cache_flush(&s->cache);
        dns_zone_flush(&s->zone);

        LIST_REMOVE(scopes, s->manager->dns_scopes, s);
        return mfree(s);
}

DnsServer *dns_scope_get_dns_server(DnsScope *s) {
        assert(s);

        if (s->protocol != DNS_PROTOCOL_DNS)
                return NULL;

        if (s->link) {
                assert(!s->delegate);
                return link_get_dns_server(s->link);
        } else if (s->delegate)
                return dns_delegate_get_dns_server(s->delegate);
        else
                return manager_get_dns_server(s->manager);
}

unsigned dns_scope_get_n_dns_servers(DnsScope *s) {
        assert(s);

        if (s->protocol != DNS_PROTOCOL_DNS)
                return 0;

        if (s->link) {
                assert(!s->delegate);
                return s->link->n_dns_servers;
        } else if (s->delegate)
                return s->delegate->n_dns_servers;
        else
                return s->manager->n_dns_servers;
}

void dns_scope_next_dns_server(DnsScope *s, DnsServer *if_current) {
        assert(s);

        if (s->protocol != DNS_PROTOCOL_DNS)
                return;

        /* Changes to the next DNS server in the list. If 'if_current' is passed will do so only if the
         * current DNS server still matches it. */

        if (s->link)
                link_next_dns_server(s->link, if_current);
        else if (s->delegate)
                dns_delegate_next_dns_server(s->delegate, if_current);
        else
                manager_next_dns_server(s->manager, if_current);
}

void dns_scope_packet_received(DnsScope *s, usec_t rtt) {
        assert(s);

        if (rtt <= s->max_rtt)
                return;

        s->max_rtt = rtt;
        s->resend_timeout = MIN(MAX(MULTICAST_RESEND_TIMEOUT_MIN_USEC, s->max_rtt * 2), MULTICAST_RESEND_TIMEOUT_MAX_USEC);
}

void dns_scope_packet_lost(DnsScope *s, usec_t usec) {
        assert(s);

        if (s->resend_timeout <= usec)
                s->resend_timeout = MIN(s->resend_timeout * 2, MULTICAST_RESEND_TIMEOUT_MAX_USEC);
}

static int dns_scope_emit_one(DnsScope *s, int fd, int family, DnsPacket *p) {
        int r;

        assert(s);
        assert(p);
        assert(p->protocol == s->protocol);

        if (family == AF_UNSPEC) {
                if (s->family == AF_UNSPEC)
                        return -EAFNOSUPPORT;

                family = s->family;
        }

        switch (s->protocol) {

        case DNS_PROTOCOL_DNS: {
                size_t mtu, udp_size, min_mtu, socket_mtu = 0;

                assert(fd >= 0);

                if (DNS_PACKET_QDCOUNT(p) > 1) /* Classic DNS only allows one question per packet */
                        return -EOPNOTSUPP;

                if (p->size > DNS_PACKET_UNICAST_SIZE_MAX)
                        return -EMSGSIZE;

                /* Determine the local most accurate MTU */
                if (s->link)
                        mtu = s->link->mtu;
                else
                        mtu = manager_find_mtu(s->manager);

                /* Acquire the socket's PMDU MTU */
                r = socket_get_mtu(fd, family, &socket_mtu);
                if (r < 0 && !ERRNO_IS_DISCONNECT(r)) /* Will return ENOTCONN if no information is available yet */
                        return log_debug_errno(r, "Failed to read socket MTU: %m");

                /* Determine the appropriate UDP header size */
                udp_size = udp_header_size(family);
                min_mtu = udp_size + DNS_PACKET_HEADER_SIZE;

                log_debug("Emitting UDP, link MTU is %zu, socket MTU is %zu, minimal MTU is %zu",
                          mtu, socket_mtu, min_mtu);

                /* Clamp by the kernel's idea of the (path) MTU */
                if (socket_mtu != 0 && socket_mtu < mtu)
                        mtu = socket_mtu;

                /* Put a lower limit, in case all MTU data we acquired was rubbish */
                if (mtu < min_mtu)
                        mtu = min_mtu;

                /* Now check our packet size against the MTU we determined */
                if (udp_size + p->size > mtu)
                        return -EMSGSIZE; /* This means: try TCP instead */

                r = manager_write(s->manager, fd, p);
                if (r < 0)
                        return r;

                break;
        }

        case DNS_PROTOCOL_LLMNR: {
                union in_addr_union addr;

                assert(fd < 0);

                if (DNS_PACKET_QDCOUNT(p) > 1)
                        return -EOPNOTSUPP;

                if (!ratelimit_below(&s->ratelimit))
                        return -EBUSY;

                if (family == AF_INET) {
                        addr.in = LLMNR_MULTICAST_IPV4_ADDRESS;
                        fd = manager_llmnr_ipv4_udp_fd(s->manager);
                } else if (family == AF_INET6) {
                        addr.in6 = LLMNR_MULTICAST_IPV6_ADDRESS;
                        fd = manager_llmnr_ipv6_udp_fd(s->manager);
                } else
                        return -EAFNOSUPPORT;
                if (fd < 0)
                        return fd;

                assert(s->link);
                r = manager_send(s->manager, fd, s->link->ifindex, family, &addr, LLMNR_PORT, NULL, p);
                if (r < 0)
                        return r;

                break;
        }

        case DNS_PROTOCOL_MDNS: {
                union in_addr_union addr;
                assert(fd < 0);

                if (!ratelimit_below(&s->ratelimit))
                        return -EBUSY;

                if (family == AF_INET) {
                        if (in4_addr_is_null(&p->destination.in))
                                addr.in = MDNS_MULTICAST_IPV4_ADDRESS;
                        else
                                addr = p->destination;
                        fd = manager_mdns_ipv4_fd(s->manager);
                } else if (family == AF_INET6) {
                        if (in6_addr_is_null(&p->destination.in6))
                                addr.in6 = MDNS_MULTICAST_IPV6_ADDRESS;
                        else
                                addr = p->destination;
                        fd = manager_mdns_ipv6_fd(s->manager);
                } else
                        return -EAFNOSUPPORT;
                if (fd < 0)
                        return fd;

                assert(s->link);
                r = manager_send(s->manager, fd, s->link->ifindex, family, &addr, p->destination_port ?: MDNS_PORT, NULL, p);
                if (r < 0)
                        return r;

                break;
        }

        default:
                return -EAFNOSUPPORT;
        }

        return 1;
}

int dns_scope_emit_udp(DnsScope *s, int fd, int af, DnsPacket *p) {
        int r;

        assert(s);
        assert(p);
        assert(p->protocol == s->protocol);
        assert((s->protocol == DNS_PROTOCOL_DNS) == (fd >= 0));

        do {
                /* If there are multiple linked packets, set the TC bit in all but the last of them */
                if (p->more) {
                        assert(p->protocol == DNS_PROTOCOL_MDNS);
                        dns_packet_set_flags(p, true, true);
                }

                r = dns_scope_emit_one(s, fd, af, p);
                if (r < 0)
                        return r;

                p = p->more;
        } while (p);

        return 0;
}

static int dns_scope_socket(
                DnsScope *s,
                int type,
                int family,
                const union in_addr_union *address,
                DnsServer *server,
                uint16_t port,
                union sockaddr_union *ret_socket_address) {

        _cleanup_close_ int fd = -EBADF;
        union sockaddr_union sa;
        socklen_t salen;
        int r, ifindex;

        assert(s);

        if (server) {
                assert(family == AF_UNSPEC);
                assert(!address);

                ifindex = dns_server_ifindex(server);

                switch (server->family) {
                case AF_INET:
                        sa = (union sockaddr_union) {
                                .in.sin_family = server->family,
                                .in.sin_port = htobe16(port),
                                .in.sin_addr = server->address.in,
                        };
                        salen = sizeof(sa.in);
                        break;
                case AF_INET6:
                        sa = (union sockaddr_union) {
                                .in6.sin6_family = server->family,
                                .in6.sin6_port = htobe16(port),
                                .in6.sin6_addr = server->address.in6,
                                .in6.sin6_scope_id = ifindex,
                        };
                        salen = sizeof(sa.in6);
                        break;
                default:
                        return -EAFNOSUPPORT;
                }
        } else {
                assert(family != AF_UNSPEC);
                assert(address);

                ifindex = dns_scope_ifindex(s);

                switch (family) {
                case AF_INET:
                        sa = (union sockaddr_union) {
                                .in.sin_family = family,
                                .in.sin_port = htobe16(port),
                                .in.sin_addr = address->in,
                        };
                        salen = sizeof(sa.in);
                        break;
                case AF_INET6:
                        sa = (union sockaddr_union) {
                                .in6.sin6_family = family,
                                .in6.sin6_port = htobe16(port),
                                .in6.sin6_addr = address->in6,
                                .in6.sin6_scope_id = ifindex,
                        };
                        salen = sizeof(sa.in6);
                        break;
                default:
                        return -EAFNOSUPPORT;
                }
        }

        fd = socket(sa.sa.sa_family, type|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        if (type == SOCK_STREAM) {
                r = setsockopt_int(fd, IPPROTO_TCP, TCP_NODELAY, true);
                if (r < 0)
                        return r;
        }

        bool addr_is_nonlocal = s->link &&
            !manager_find_link_address(s->manager, sa.sa.sa_family, sockaddr_in_addr(&sa.sa)) &&
            in_addr_is_localhost(sa.sa.sa_family, sockaddr_in_addr(&sa.sa)) == 0;

        if (addr_is_nonlocal && ifindex != 0) {
                /* As a special exception we don't use UNICAST_IF if we notice that the specified IP address
                 * is on the local host. Otherwise, destination addresses on the local host result in
                 * EHOSTUNREACH, since Linux won't send the packets out of the specified interface, but
                 * delivers them directly to the local socket. */
                r = socket_set_unicast_if(fd, sa.sa.sa_family, ifindex);
                if (r < 0)
                        return r;
        }

        if (s->protocol == DNS_PROTOCOL_LLMNR) {
                /* RFC 4795, section 2.5 requires the TTL to be set to 1 */
                r = socket_set_ttl(fd, sa.sa.sa_family, 1);
                if (r < 0)
                        return r;
        }

        if (type == SOCK_DGRAM) {
                /* Set IP_RECVERR or IPV6_RECVERR to get ICMP error feedback. See discussion in #10345. */
                r = socket_set_recverr(fd, sa.sa.sa_family, true);
                if (r < 0)
                        return r;

                r = socket_set_recvpktinfo(fd, sa.sa.sa_family, true);
                if (r < 0)
                        return r;

                /* Turn of path MTU discovery for security reasons */
                r = socket_disable_pmtud(fd, sa.sa.sa_family);
                if (r < 0)
                        log_debug_errno(r, "Failed to disable UDP PMTUD, ignoring: %m");

                /* Learn about fragmentation taking place */
                r = socket_set_recvfragsize(fd, sa.sa.sa_family, true);
                if (r < 0)
                        log_debug_errno(r, "Failed to enable fragment size reception, ignoring: %m");
        }

        if (ret_socket_address)
                *ret_socket_address = sa;
        else {
                bool bound = false;

                /* Let's temporarily bind the socket to the specified ifindex. Older kernels only take
                 * the SO_BINDTODEVICE/SO_BINDTOINDEX ifindex into account when making routing decisions
                 * in connect() — and not IP_UNICAST_IF. We don't really want any of the other semantics of
                 * SO_BINDTODEVICE/SO_BINDTOINDEX, hence we immediately unbind the socket after the fact
                 * again.
                 */
                if (addr_is_nonlocal) {
                        r = socket_bind_to_ifindex(fd, ifindex);
                        if (r < 0)
                                return r;

                        bound = true;
                }

                r = connect(fd, &sa.sa, salen);
                if (r < 0 && errno != EINPROGRESS)
                        return -errno;

                if (bound) {
                        r = socket_bind_to_ifindex(fd, 0);
                        if (r < 0)
                                return r;
                }
        }

        return TAKE_FD(fd);
}

int dns_scope_socket_udp(DnsScope *s, DnsServer *server) {
        return dns_scope_socket(s, SOCK_DGRAM, AF_UNSPEC, NULL, server, dns_server_port(server), NULL);
}

int dns_scope_socket_tcp(DnsScope *s, int family, const union in_addr_union *address, DnsServer *server, uint16_t port, union sockaddr_union *ret_socket_address) {
        /* If ret_socket_address is not NULL, the caller is responsible
         * for calling connect() or sendmsg(). This is required by TCP
         * Fast Open, to be able to send the initial SYN packet along
         * with the first data packet. */
        return dns_scope_socket(s, SOCK_STREAM, family, address, server, port, ret_socket_address);
}

static DnsScopeMatch match_link_local_reverse_lookups(const char *domain) {
        assert(domain);

        if (dns_name_endswith(domain, "254.169.in-addr.arpa") > 0)
                return DNS_SCOPE_YES_BASE + 4; /* 4 labels match */

        if (dns_name_endswith(domain, "8.e.f.ip6.arpa") > 0 ||
            dns_name_endswith(domain, "9.e.f.ip6.arpa") > 0 ||
            dns_name_endswith(domain, "a.e.f.ip6.arpa") > 0 ||
            dns_name_endswith(domain, "b.e.f.ip6.arpa") > 0)
                return DNS_SCOPE_YES_BASE + 5; /* 5 labels match */

        return _DNS_SCOPE_MATCH_INVALID;
}

static DnsScopeMatch match_subnet_reverse_lookups(
                DnsScope *s,
                const char *domain,
                bool exclude_own) {

        union in_addr_union ia;
        int f, r;

        assert(s);
        assert(domain);

        /* Checks whether the specified domain is a reverse address domain (i.e. in the .in-addr.arpa or
         * .ip6.arpa area), and if so, whether the address matches any of the local subnets of the link the
         * scope is associated with. If so, our scope should consider itself relevant for any lookup in the
         * domain, since it apparently refers to hosts on this link's subnet.
         *
         * If 'exclude_own' is true this will return DNS_SCOPE_NO for any IP addresses assigned locally. This
         * is useful for LLMNR/mDNS as we never want to look up our own hostname on LLMNR/mDNS but always use
         * the locally synthesized one. */

        if (!s->link)
                return _DNS_SCOPE_MATCH_INVALID; /* No link, hence no local addresses to check */

        r = dns_name_address(domain, &f, &ia);
        if (r < 0)
                log_debug_errno(r, "Failed to determine whether '%s' is an address domain: %m", domain);
        if (r <= 0)
                return _DNS_SCOPE_MATCH_INVALID;

        if (s->family != AF_UNSPEC && f != s->family)
                return _DNS_SCOPE_MATCH_INVALID; /* Don't look for IPv4 addresses on LLMNR/mDNS over IPv6 and vice versa */

        if (in_addr_is_null(f, &ia))
                return DNS_SCOPE_NO;

        LIST_FOREACH(addresses, a, s->link->addresses) {

                if (a->family != f)
                        continue;

                /* Equals our own address? nah, let's not use this scope. The local synthesizer will pick it up for us. */
                if (exclude_own &&
                    in_addr_equal(f, &a->in_addr, &ia) > 0)
                        return DNS_SCOPE_NO;

                if (a->prefixlen == UCHAR_MAX) /* don't know subnet mask */
                        continue;

                /* Don't send mDNS queries for the IPv4 broadcast address */
                if (f == AF_INET && in_addr_equal(f, &a->in_addr_broadcast, &ia) > 0)
                        return DNS_SCOPE_NO;

                /* Check if the address is in the local subnet */
                r = in_addr_prefix_covers(f, &a->in_addr, a->prefixlen, &ia);
                if (r < 0)
                        log_debug_errno(r, "Failed to determine whether link address covers lookup address '%s': %m", domain);
                if (r > 0)
                        /* Note that we only claim zero labels match. This is so that this is at the same
                         * priority a DNS scope with "." as routing domain is. */
                        return DNS_SCOPE_YES_BASE + 0;
        }

        return _DNS_SCOPE_MATCH_INVALID;
}

/* https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml */
/* https://www.iana.org/assignments/locally-served-dns-zones/locally-served-dns-zones.xhtml */
static bool dns_refuse_special_use_domain(const char *domain, DnsQuestion *question) {
        /* RFC9462 § 6.4: resolvers SHOULD respond to queries of any type other than SVCB for
         * _dns.resolver.arpa. with NODATA and queries of any type for any domain name under
         * resolver.arpa with NODATA. */
        if (dns_name_equal(domain, "_dns.resolver.arpa") > 0) {
                DnsResourceKey *t;

                /* Only SVCB is permitted to _dns.resolver.arpa */
                DNS_QUESTION_FOREACH(t, question)
                        if (t->type == DNS_TYPE_SVCB)
                                return false;

                return true;
        }

        if (dns_name_endswith(domain, "resolver.arpa") > 0)
                return true;

        return false;
}

DnsScopeMatch dns_scope_good_domain(
                DnsScope *s,
                DnsQuery *q,
                uint64_t query_flags) {

        DnsQuestion *question;
        const char *domain;
        uint64_t flags;
        int ifindex, r;

        /* This returns the following return values:
         *
         *    DNS_SCOPE_NO         → This scope is not suitable for lookups of this domain, at all
         *    DNS_SCOPE_LAST_RESORT→ This scope is not suitable, unless we have no alternative
         *    DNS_SCOPE_MAYBE      → This scope is suitable, but only if nothing else wants it
         *    DNS_SCOPE_YES_BASE+n → This scope is suitable, and 'n' suffix labels match
         *
         *  (The idea is that the caller will only use the scopes with the longest 'n' returned. If no scopes return
         *  DNS_SCOPE_YES_BASE+n, then it should use those which returned DNS_SCOPE_MAYBE. It should never use those
         *  which returned DNS_SCOPE_NO.)
         */

        assert(s);
        assert(q);

        question = dns_query_question_for_protocol(q, s->protocol);
        if (!question)
                return DNS_SCOPE_NO;

        domain = dns_question_first_name(question);
        if (!domain)
                return DNS_SCOPE_NO;

        ifindex = q->ifindex;
        flags = q->flags;

        /* Checks if the specified domain is something to look up on this scope. Note that this accepts
         * non-qualified hostnames, i.e. those without any search path suffixed. */

        if (ifindex != 0 && (!s->link || s->link->ifindex != ifindex))
                return DNS_SCOPE_NO;

        if ((SD_RESOLVED_FLAGS_MAKE(s->protocol, s->family, false, false) & flags) == 0)
                return DNS_SCOPE_NO;

        /* Never resolve any loopback hostname or IP address via DNS, LLMNR or mDNS. Instead, always rely on
         * synthesized RRs for these. */
        if (is_localhost(domain) ||
            dns_name_endswith(domain, "127.in-addr.arpa") > 0 ||
            dns_name_equal(domain, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa") > 0)
                return DNS_SCOPE_NO;

        /* Never respond to some of the domains listed in RFC6303 + RFC6761 */
        if (dns_name_dont_resolve(domain))
                return DNS_SCOPE_NO;

        /* Avoid asking invalid questions of some special use domains */
        if (dns_refuse_special_use_domain(domain, question))
                return DNS_SCOPE_NO;

        /* Never go to network for the _gateway, _outbound, _localdnsstub, _localdnsproxy domain — they're something special, synthesized locally. */
        if (is_gateway_hostname(domain) ||
            is_outbound_hostname(domain) ||
            is_dns_stub_hostname(domain) ||
            is_dns_proxy_stub_hostname(domain))
                return DNS_SCOPE_NO;

        /* Don't look up the local host name via the network, unless user turned of local synthesis of it */
        if (manager_is_own_hostname(s->manager, domain) && shall_synthesize_own_hostname_rrs())
                return DNS_SCOPE_NO;

        /* Never send SOA or NS or DNSSEC request to LLMNR, where they make little sense. */
        r = dns_question_types_suitable_for_protocol(question, s->protocol);
        if (r <= 0)
                return DNS_SCOPE_NO;

        switch (s->protocol) {

        case DNS_PROTOCOL_DNS: {
                bool has_search_domains = false;
                DnsScopeMatch m;
                int n_best = -1;

                if (dns_name_is_root(domain)) {
                        DnsResourceKey *t;
                        bool found = false;

                        /* Refuse root name if only A and/or AAAA records are requested. */

                        DNS_QUESTION_FOREACH(t, question)
                                if (!IN_SET(t->type, DNS_TYPE_A, DNS_TYPE_AAAA)) {
                                        found = true;
                                        break;
                                }

                        if (!found)
                                return DNS_SCOPE_NO;
                }

                /* Never route things to scopes that lack DNS servers */
                if (!dns_scope_get_dns_server(s))
                        return DNS_SCOPE_NO;

                /* Route DS requests to the parent */
                const char *route_domain = domain;
                if (dns_question_contains_key_type(question, DNS_TYPE_DS))
                        (void) dns_name_parent(&route_domain);

                /* Always honour search domains for routing queries, except if this scope lacks DNS servers. Note that
                 * we return DNS_SCOPE_YES here, rather than just DNS_SCOPE_MAYBE, which means other wildcard scopes
                 * won't be considered anymore. */
                LIST_FOREACH(domains, d, dns_scope_get_search_domains(s)) {

                        if (!d->route_only && !dns_name_is_root(d->name))
                                has_search_domains = true;

                        if (dns_name_endswith(route_domain, d->name) > 0) {
                                int c;

                                c = dns_name_count_labels(d->name);
                                if (c < 0)
                                        continue;

                                if (c > n_best)
                                        n_best = c;
                        }
                }

                /* If there's a true search domain defined for this scope, and the query is single-label,
                 * then let's resolve things here, preferably. Note that LLMNR considers itself
                 * authoritative for single-label names too, at the same preference, see below. */
                if (has_search_domains && dns_name_is_single_label(domain))
                        return DNS_SCOPE_YES_BASE + 1;

                /* If ResolveUnicastSingleLabel=yes and the query is single-label, then bump match result
                   to prevent LLMNR monopoly among candidates. */
                if ((s->manager->resolve_unicast_single_label || (query_flags & SD_RESOLVED_RELAX_SINGLE_LABEL)) &&
                    dns_name_is_single_label(domain))
                        return DNS_SCOPE_YES_BASE + 1;

                /* Let's return the number of labels in the best matching result */
                if (n_best >= 0) {
                        assert(n_best <= DNS_SCOPE_YES_END - DNS_SCOPE_YES_BASE);
                        return DNS_SCOPE_YES_BASE + n_best;
                }

                /* Exclude link-local IP ranges */
                if (match_link_local_reverse_lookups(domain) >= DNS_SCOPE_YES_BASE ||
                    /* If networks use .local in their private setups, they are supposed to also add .local
                     * to their search domains, which we already checked above. Otherwise, we consider .local
                     * specific to mDNS and won't send such queries ordinary DNS servers. */
                    dns_name_endswith(domain, "local") > 0)
                        return DNS_SCOPE_NO;

                /* If the IP address to look up matches the local subnet, then implicitly synthesizes
                 * DNS_SCOPE_YES_BASE + 0 on this interface, i.e. preferably resolve IP addresses via the DNS
                 * server belonging to this interface. */
                m = match_subnet_reverse_lookups(s, domain, false);
                if (m >= 0)
                        return m;

                /* If there was no match at all, then see if this scope is suitable as default route. */
                if (!dns_scope_is_default_route(s))
                        return DNS_SCOPE_NO;

                /* Prefer suitable per-link scopes where possible */
                if (dns_server_is_fallback(dns_scope_get_dns_server(s)))
                        return DNS_SCOPE_LAST_RESORT;

                return DNS_SCOPE_MAYBE;
        }

        case DNS_PROTOCOL_MDNS: {
                DnsScopeMatch m;

                m = match_link_local_reverse_lookups(domain);
                if (m >= 0)
                        return m;

                m = match_subnet_reverse_lookups(s, domain, true);
                if (m >= 0)
                        return m;

                if ((s->family == AF_INET && dns_name_endswith(domain, "in-addr.arpa") > 0) ||
                    (s->family == AF_INET6 && dns_name_endswith(domain, "ip6.arpa") > 0))
                        return DNS_SCOPE_LAST_RESORT;

                if ((dns_name_endswith(domain, "local") > 0 && /* only resolve names ending in .local via mDNS */
                     dns_name_equal(domain, "local") == 0 &&   /* but not the single-label "local" name itself */
                     manager_is_own_hostname(s->manager, domain) <= 0)) /* never resolve the local hostname via mDNS */
                        return DNS_SCOPE_YES_BASE + 1; /* Return +1, as the top-level .local domain matches, i.e. one label */

                return DNS_SCOPE_NO;
        }

        case DNS_PROTOCOL_LLMNR: {
                DnsScopeMatch m;

                m = match_link_local_reverse_lookups(domain);
                if (m >= 0)
                        return m;

                m = match_subnet_reverse_lookups(s, domain, true);
                if (m >= 0)
                        return m;

                if ((s->family == AF_INET && dns_name_endswith(domain, "in-addr.arpa") > 0) ||
                    (s->family == AF_INET6 && dns_name_endswith(domain, "ip6.arpa") > 0))
                        return DNS_SCOPE_LAST_RESORT;

                if ((dns_name_is_single_label(domain) && /* only resolve single label names via LLMNR */
                     dns_name_equal(domain, "local") == 0 && /* don't resolve "local" with LLMNR, it's the top-level domain of mDNS after all, see above */
                     manager_is_own_hostname(s->manager, domain) <= 0))  /* never resolve the local hostname via LLMNR */
                        return DNS_SCOPE_YES_BASE + 1; /* Return +1, as we consider ourselves authoritative
                                                        * for single-label names, i.e. one label. This is
                                                        * particularly relevant as it means a "." route on some
                                                        * other scope won't pull all traffic away from
                                                        * us. (If people actually want to pull traffic away
                                                        * from us they should turn off LLMNR on the
                                                        * link). Note that unicast DNS scopes with search
                                                        * domains also consider themselves authoritative for
                                                        * single-label domains, at the same preference (see
                                                        * above). */

                return DNS_SCOPE_NO;
        }

        default:
                assert_not_reached();
        }
}

bool dns_scope_good_key(DnsScope *s, const DnsResourceKey *key) {
        int key_family;

        assert(s);
        assert(key);

        /* Check if it makes sense to resolve the specified key on this scope. Note that this call assumes a
         * fully qualified name, i.e. the search suffixes already appended. */

        if (!IN_SET(key->class, DNS_CLASS_IN, DNS_CLASS_ANY))
                return false;

        if (s->protocol == DNS_PROTOCOL_DNS) {

                /* On classic DNS, looking up non-address RRs is always fine. (Specifically, we want to
                 * permit looking up DNSKEY and DS records on the root and top-level domains.) */
                if (!dns_resource_key_is_address(key))
                        return true;

                /* Unless explicitly overridden, we refuse to look up A and AAAA RRs on the root and
                 * single-label domains, under the assumption that those should be resolved via LLMNR or
                 * search path only, and should not be leaked onto the internet. */
                const char* name = dns_resource_key_name(key);

                if (!s->manager->resolve_unicast_single_label &&
                    dns_name_is_single_label(name))
                        return false;

                return !dns_name_is_root(name);
        }

        /* Never route DNSSEC RR queries to LLMNR/mDNS scopes */
        if (dns_type_is_dnssec(key->type))
                return false;

        /* On mDNS and LLMNR, send A and AAAA queries only on the respective scopes */

        key_family = dns_type_to_af(key->type);
        if (key_family < 0)
                return true;

        return key_family == s->family;
}

static int dns_scope_multicast_membership(DnsScope *s, bool b, struct in_addr in, struct in6_addr in6) {
        int fd;

        assert(s);
        assert(s->link);

        if (s->family == AF_INET) {
                struct ip_mreqn mreqn = {
                        .imr_multiaddr = in,
                        .imr_ifindex = s->link->ifindex,
                };

                if (s->protocol == DNS_PROTOCOL_LLMNR)
                        fd = manager_llmnr_ipv4_udp_fd(s->manager);
                else
                        fd = manager_mdns_ipv4_fd(s->manager);

                if (fd < 0)
                        return fd;

                /* Always first try to drop membership before we add
                 * one. This is necessary on some devices, such as
                 * veth. */
                if (b)
                        (void) setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreqn, sizeof(mreqn));

                if (setsockopt(fd, IPPROTO_IP, b ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, &mreqn, sizeof(mreqn)) < 0)
                        return -errno;

        } else if (s->family == AF_INET6) {
                struct ipv6_mreq mreq = {
                        .ipv6mr_multiaddr = in6,
                        .ipv6mr_ifindex = s->link->ifindex,
                };

                if (s->protocol == DNS_PROTOCOL_LLMNR)
                        fd = manager_llmnr_ipv6_udp_fd(s->manager);
                else
                        fd = manager_mdns_ipv6_fd(s->manager);

                if (fd < 0)
                        return fd;

                if (b)
                        (void) setsockopt(fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

                if (setsockopt(fd, IPPROTO_IPV6, b ? IPV6_ADD_MEMBERSHIP : IPV6_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
                        return -errno;
        } else
                return -EAFNOSUPPORT;

        return 0;
}

int dns_scope_llmnr_membership(DnsScope *s, bool b) {
        assert(s);

        if (s->protocol != DNS_PROTOCOL_LLMNR)
                return 0;

        return dns_scope_multicast_membership(s, b, LLMNR_MULTICAST_IPV4_ADDRESS, LLMNR_MULTICAST_IPV6_ADDRESS);
}

int dns_scope_mdns_membership(DnsScope *s, bool b) {
        assert(s);

        if (s->protocol != DNS_PROTOCOL_MDNS)
                return 0;

        return dns_scope_multicast_membership(s, b, MDNS_MULTICAST_IPV4_ADDRESS, MDNS_MULTICAST_IPV6_ADDRESS);
}

int dns_scope_make_reply_packet(
                DnsScope *s,
                uint16_t id,
                int rcode,
                DnsQuestion *q,
                DnsAnswer *answer,
                DnsAnswer *soa,
                bool tentative,
                DnsPacket **ret) {

        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        unsigned n_answer = 0, n_soa = 0;
        int r;
        bool c_or_aa;

        assert(s);
        assert(ret);

        if (dns_question_isempty(q) &&
            dns_answer_isempty(answer) &&
            dns_answer_isempty(soa))
                return -EINVAL;

        r = dns_packet_new(&p, s->protocol, 0, DNS_PACKET_SIZE_MAX);
        if (r < 0)
                return r;

        /* mDNS answers must have the Authoritative Answer bit set, see RFC 6762, section 18.4. */
        c_or_aa = s->protocol == DNS_PROTOCOL_MDNS;

        DNS_PACKET_HEADER(p)->id = id;
        DNS_PACKET_HEADER(p)->flags = htobe16(DNS_PACKET_MAKE_FLAGS(
                                                              1 /* qr */,
                                                              0 /* opcode */,
                                                              c_or_aa,
                                                              0 /* tc */,
                                                              tentative,
                                                              0 /* (ra) */,
                                                              0 /* (ad) */,
                                                              0 /* (cd) */,
                                                              rcode));

        r = dns_packet_append_question(p, q);
        if (r < 0)
                return r;
        DNS_PACKET_HEADER(p)->qdcount = htobe16(dns_question_size(q));

        r = dns_packet_append_answer(p, answer, &n_answer);
        if (r < 0)
                return r;
        DNS_PACKET_HEADER(p)->ancount = htobe16(n_answer);

        r = dns_packet_append_answer(p, soa, &n_soa);
        if (r < 0)
                return r;
        DNS_PACKET_HEADER(p)->arcount = htobe16(n_soa);

        *ret = TAKE_PTR(p);

        return 0;
}

static void dns_scope_verify_conflicts(DnsScope *s, DnsPacket *p) {
        DnsResourceRecord *rr;
        DnsResourceKey *key;

        assert(s);
        assert(p);

        DNS_QUESTION_FOREACH(key, p->question)
                dns_zone_verify_conflicts(&s->zone, key);

        DNS_ANSWER_FOREACH(rr, p->answer)
                dns_zone_verify_conflicts(&s->zone, rr->key);
}

void dns_scope_process_query(DnsScope *s, DnsStream *stream, DnsPacket *p) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL, *soa = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
        DnsResourceKey *key = NULL;
        bool tentative = false;
        int r;

        assert(s);
        assert(p);

        if (p->protocol != DNS_PROTOCOL_LLMNR)
                return;

        if (p->ipproto == IPPROTO_UDP) {
                /* Don't accept UDP queries directed to anything but
                 * the LLMNR multicast addresses. See RFC 4795,
                 * section 2.5. */

                if (p->family == AF_INET && !in4_addr_equal(&p->destination.in, &LLMNR_MULTICAST_IPV4_ADDRESS))
                        return;

                if (p->family == AF_INET6 && !in6_addr_equal(&p->destination.in6, &LLMNR_MULTICAST_IPV6_ADDRESS))
                        return;
        }

        r = dns_packet_extract(p);
        if (r < 0) {
                log_debug_errno(r, "Failed to extract resource records from incoming packet: %m");
                return;
        }

        if (DNS_PACKET_LLMNR_C(p)) {
                /* Somebody notified us about a possible conflict */
                dns_scope_verify_conflicts(s, p);
                return;
        }

        if (dns_question_size(p->question) != 1)
                return (void) log_debug("Received LLMNR query without question or multiple questions, ignoring.");

        key = dns_question_first_key(p->question);

        r = dns_zone_lookup(&s->zone, key, 0, &answer, &soa, &tentative);
        if (r < 0) {
                log_debug_errno(r, "Failed to look up key: %m");
                return;
        }
        if (r == 0)
                return;

        if (answer)
                dns_answer_order_by_scope(answer, in_addr_is_link_local(p->family, &p->sender) > 0);

        r = dns_scope_make_reply_packet(s, DNS_PACKET_ID(p), DNS_RCODE_SUCCESS, p->question, answer, soa, tentative, &reply);
        if (r < 0) {
                log_debug_errno(r, "Failed to build reply packet: %m");
                return;
        }

        if (stream) {
                r = dns_stream_write_packet(stream, reply);
                if (r < 0) {
                        log_debug_errno(r, "Failed to enqueue reply packet: %m");
                        return;
                }

                /* Let's take an extra reference on this stream, so that it stays around after returning. The reference
                 * will be dangling until the stream is disconnected, and the default completion handler of the stream
                 * will then unref the stream and destroy it */
                if (DNS_STREAM_QUEUED(stream))
                        dns_stream_ref(stream);
        } else {
                int fd;

                if (!ratelimit_below(&s->ratelimit))
                        return;

                if (p->family == AF_INET)
                        fd = manager_llmnr_ipv4_udp_fd(s->manager);
                else if (p->family == AF_INET6)
                        fd = manager_llmnr_ipv6_udp_fd(s->manager);
                else {
                        log_debug("Unknown protocol");
                        return;
                }
                if (fd < 0) {
                        log_debug_errno(fd, "Failed to get reply socket: %m");
                        return;
                }

                /* Note that we always immediately reply to all LLMNR
                 * requests, and do not wait any time, since we
                 * verified uniqueness for all records. Also see RFC
                 * 4795, Section 2.7 */

                r = manager_send(s->manager, fd, p->ifindex, p->family, &p->sender, p->sender_port, NULL, reply);
                if (r < 0) {
                        log_debug_errno(r, "Failed to send reply packet: %m");
                        return;
                }
        }
}

DnsTransaction *dns_scope_find_transaction(
                DnsScope *scope,
                DnsResourceKey *key,
                uint64_t query_flags) {

        DnsTransaction *first;

        assert(scope);
        assert(key);

        /* Iterate through the list of transactions with a matching key */
        first = hashmap_get(scope->transactions_by_key, key);
        LIST_FOREACH(transactions_by_key, t, first) {

                /* These four flags must match exactly: we cannot use a validated response for a
                 * non-validating client, and we cannot use a non-validated response for a validating
                 * client. Similar, if the sources don't match things aren't usable either. */
                if (((query_flags ^ t->query_flags) &
                     (SD_RESOLVED_NO_VALIDATE|
                     SD_RESOLVED_NO_ZONE|
                      SD_RESOLVED_NO_TRUST_ANCHOR|
                      SD_RESOLVED_NO_NETWORK)) != 0)
                        continue;

                /* We can reuse a primary query if a regular one is requested, but not vice versa */
                if ((query_flags & SD_RESOLVED_REQUIRE_PRIMARY) &&
                    !(t->query_flags & SD_RESOLVED_REQUIRE_PRIMARY))
                        continue;

                /* Don't reuse a transaction that allowed caching when we got told not to use it */
                if ((query_flags & SD_RESOLVED_NO_CACHE) &&
                    !(t->query_flags & SD_RESOLVED_NO_CACHE))
                        continue;

                /* If we are asked to clamp ttls and the existing transaction doesn't do it, we can't
                 * reuse */
                if ((query_flags & SD_RESOLVED_CLAMP_TTL) &&
                    !(t->query_flags & SD_RESOLVED_CLAMP_TTL))
                        continue;

                return t;
        }

        return NULL;
}

static int dns_scope_make_conflict_packet(
                DnsScope *s,
                DnsResourceRecord *rr,
                DnsPacket **ret) {

        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        int r;

        assert(s);
        assert(rr);
        assert(ret);

        r = dns_packet_new(&p, s->protocol, 0, DNS_PACKET_SIZE_MAX);
        if (r < 0)
                return r;

        DNS_PACKET_HEADER(p)->flags = htobe16(DNS_PACKET_MAKE_FLAGS(
                                                              0 /* qr */,
                                                              0 /* opcode */,
                                                              1 /* conflict */,
                                                              0 /* tc */,
                                                              0 /* t */,
                                                              0 /* (ra) */,
                                                              0 /* (ad) */,
                                                              0 /* (cd) */,
                                                              0));

        /* For mDNS, the transaction ID should always be 0 */
        if (s->protocol != DNS_PROTOCOL_MDNS)
                random_bytes(&DNS_PACKET_HEADER(p)->id, sizeof(uint16_t));

        DNS_PACKET_HEADER(p)->qdcount = htobe16(1);
        DNS_PACKET_HEADER(p)->arcount = htobe16(1);

        r = dns_packet_append_key(p, rr->key, 0, NULL);
        if (r < 0)
                return r;

        r = dns_packet_append_rr(p, rr, 0, NULL, NULL);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(p);

        return 0;
}

static int on_conflict_dispatch(sd_event_source *es, usec_t usec, void *userdata) {
        DnsScope *scope = ASSERT_PTR(userdata);
        int r;

        assert(es);

        scope->conflict_event_source = sd_event_source_disable_unref(scope->conflict_event_source);

        for (;;) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
                _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

                rr = ordered_hashmap_steal_first_key_and_value(scope->conflict_queue, (void**) &key);
                if (!rr)
                        break;

                r = dns_scope_make_conflict_packet(scope, rr, &p);
                if (r < 0) {
                        log_error_errno(r, "Failed to make conflict packet: %m");
                        return 0;
                }

                r = dns_scope_emit_udp(scope, -1, AF_UNSPEC, p);
                if (r < 0)
                        log_debug_errno(r, "Failed to send conflict packet: %m");
        }

        return 0;
}

int dns_scope_notify_conflict(DnsScope *scope, DnsResourceRecord *rr) {
        int r;

        assert(scope);
        assert(rr);

        /* We don't send these queries immediately. Instead, we queue them, and send them after some jitter
         * delay.  We only place one RR per key in the conflict messages, not all of them. That should be
         * enough to indicate where there might be a conflict */
        r = ordered_hashmap_ensure_put(&scope->conflict_queue, &dns_resource_record_hash_ops_by_key, rr->key, rr);
        if (IN_SET(r, 0, -EEXIST))
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to queue conflicting RR: %m");

        dns_resource_key_ref(rr->key);
        dns_resource_record_ref(rr);

        if (scope->conflict_event_source)
                return 0;

        r = sd_event_add_time_relative(
                        scope->manager->event,
                        &scope->conflict_event_source,
                        CLOCK_BOOTTIME,
                        random_u64_range(LLMNR_JITTER_INTERVAL_USEC),
                        0,
                        on_conflict_dispatch, scope);
        if (r < 0)
                return log_debug_errno(r, "Failed to add conflict dispatch event: %m");

        (void) sd_event_source_set_description(scope->conflict_event_source, "scope-conflict");

        return 0;
}

void dns_scope_check_conflicts(DnsScope *scope, DnsPacket *p) {
        DnsResourceRecord *rr;
        int r;

        assert(scope);
        assert(p);

        if (!IN_SET(p->protocol, DNS_PROTOCOL_LLMNR, DNS_PROTOCOL_MDNS))
                return;

        if (DNS_PACKET_RRCOUNT(p) <= 0)
                return;

        if (p->protocol == DNS_PROTOCOL_LLMNR) {
                if (DNS_PACKET_LLMNR_C(p) != 0)
                        return;

                if (DNS_PACKET_LLMNR_T(p) != 0)
                        return;
        }

        if (manager_packet_from_local_address(scope->manager, p))
                return;

        r = dns_packet_extract(p);
        if (r < 0) {
                log_debug_errno(r, "Failed to extract packet: %m");
                return;
        }

        log_debug("Checking for conflicts...");

        DNS_ANSWER_FOREACH(rr, p->answer) {
                /* No conflict if it is DNS-SD RR used for service enumeration. */
                if (dns_resource_key_is_dnssd_ptr(rr->key))
                        continue;

                /* Check for conflicts against the local zone. If we
                 * found one, we won't check any further */
                r = dns_zone_check_conflicts(&scope->zone, rr);
                if (r != 0)
                        continue;

                /* Check for conflicts against the local cache. If so,
                 * send out an advisory query, to inform everybody */
                r = dns_cache_check_conflicts(&scope->cache, rr, p->family, &p->sender);
                if (r <= 0)
                        continue;

                dns_scope_notify_conflict(scope, rr);
        }
}

void dns_scope_dump(DnsScope *s, FILE *f) {
        assert(s);

        if (!f)
                f = stdout;

        fputs("[Scope protocol=", f);
        fputs(dns_protocol_to_string(s->protocol), f);

        if (s->link) {
                fputs(" interface=", f);
                fputs(s->link->ifname, f);
        }

        if (s->family != AF_UNSPEC) {
                fputs(" family=", f);
                fputs(af_to_name(s->family), f);
        }

        fputs(" origin=", f);
        fputs(dns_scope_origin_to_string(s->origin), f);

        if (s->delegate) {
                fputs(" id=", f);
                fputs(s->delegate->id, f);
        }

        fputs("]\n", f);

        if (!dns_zone_is_empty(&s->zone)) {
                fputs("ZONE:\n", f);
                dns_zone_dump(&s->zone, f);
        }

        if (!dns_cache_is_empty(&s->cache)) {
                fputs("CACHE:\n", f);
                dns_cache_dump(&s->cache, f);
        }
}

DnsSearchDomain *dns_scope_get_search_domains(DnsScope *s) {
        assert(s);

        if (s->protocol != DNS_PROTOCOL_DNS)
                return NULL;

        if (s->link)
                return s->link->search_domains;
        if (s->delegate)
                return s->delegate->search_domains;

        return s->manager->search_domains;
}

bool dns_scope_name_wants_search_domain(DnsScope *s, const char *name) {
        assert(s);

        if (s->protocol != DNS_PROTOCOL_DNS)
                return false;

        if (!dns_name_is_single_label(name))
                return false;

        /* If we allow single-label domain lookups on unicast DNS, and this scope has a search domain that matches
         * _exactly_ this name, then do not use search domains. */
        if (s->manager->resolve_unicast_single_label)
                LIST_FOREACH(domains, d, dns_scope_get_search_domains(s))
                        if (dns_name_equal(name, d->name) > 0)
                                return false;

        return true;
}

bool dns_scope_network_good(DnsScope *s) {
        /* Checks whether the network is in good state for lookups on this scope. For mDNS/LLMNR/Classic DNS scopes
         * bound to links this is easy, as they don't even exist if the link isn't in a suitable state. For the global
         * DNS scope we check whether there are any links that are up and have an address.
         *
         * Note that Linux routing is complex and even systems that superficially have no IPv4 address might
         * be able to route IPv4 (and similar for IPv6), hence let's make a check here independent of address
         * family. */

        if (s->link)
                return true;

        return manager_routable(s->manager);
}

int dns_scope_ifindex(DnsScope *s) {
        assert(s);

        if (s->link)
                return s->link->ifindex;

        return 0;
}

const char* dns_scope_ifname(DnsScope *s) {
        assert(s);

        if (s->link)
                return s->link->ifname;

        return NULL;
}

static int on_announcement_timeout(sd_event_source *s, usec_t usec, void *userdata) {
        DnsScope *scope = userdata;

        assert(s);

        scope->announce_event_source = sd_event_source_disable_unref(scope->announce_event_source);

        (void) dns_scope_announce(scope, false);
        return 0;
}

int dns_scope_announce(DnsScope *scope, bool goodbye) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        _cleanup_set_free_ Set *types = NULL;
        DnsZoneItem *z;
        unsigned size = 0;
        char *service_type;
        int r;

        if (!scope)
                return 0;

        if (scope->protocol != DNS_PROTOCOL_MDNS)
                return 0;

        r = sd_event_get_state(scope->manager->event);
        if (r < 0)
                return log_debug_errno(r, "Failed to get event loop state: %m");

        /* If this is called on exit, through manager_free() -> link_free(), then we cannot announce. */
        if (r == SD_EVENT_FINISHED)
                return 0;

        /* Check if we're done with probing. */
        LIST_FOREACH(transactions_by_scope, t, scope->transactions)
                if (t->probing && DNS_TRANSACTION_IS_LIVE(t->state))
                        return 0;

        /* Check if there're services pending conflict resolution. */
        if (manager_next_dnssd_names(scope->manager))
                return 0; /* we reach this point only if changing hostname didn't help */

        /* Calculate answer's size. */
        HASHMAP_FOREACH(z, scope->zone.by_key) {
                if (z->state != DNS_ZONE_ITEM_ESTABLISHED)
                        continue;

                if (z->rr->key->type == DNS_TYPE_PTR &&
                    !dns_zone_contains_name(&scope->zone, z->rr->ptr.name)) {
                        char key_str[DNS_RESOURCE_KEY_STRING_MAX];

                        log_debug("Skip PTR RR <%s> since its counterparts seem to be withdrawn", dns_resource_key_to_string(z->rr->key, key_str, sizeof key_str));
                        z->state = DNS_ZONE_ITEM_WITHDRAWN;
                        continue;
                }

                /* Collect service types for _services._dns-sd._udp.local RRs in a set. Only two-label names
                 * (not selective names) are considered according to RFC6763 § 9. */
                if (!scope->announced &&
                    dns_resource_key_is_dnssd_two_label_ptr(z->rr->key)) {
                        if (!set_contains(types, dns_resource_key_name(z->rr->key))) {
                                r = set_ensure_put(&types, &dns_name_hash_ops, dns_resource_key_name(z->rr->key));
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to add item to set: %m");
                        }
                }

                LIST_FOREACH(by_key, i, z)
                        size++;
        }

        answer = dns_answer_new(size + set_size(types));
        if (!answer)
                return log_oom();

        /* Second iteration, actually add RRs to the answer. */
        HASHMAP_FOREACH(z, scope->zone.by_key)
                LIST_FOREACH (by_key, i, z) {
                        DnsAnswerFlags flags;

                        if (i->state != DNS_ZONE_ITEM_ESTABLISHED)
                                continue;

                        if (dns_resource_key_is_dnssd_ptr(i->rr->key))
                                flags = goodbye ? DNS_ANSWER_GOODBYE : 0;
                        else
                                flags = goodbye ? (DNS_ANSWER_GOODBYE|DNS_ANSWER_CACHE_FLUSH) : DNS_ANSWER_CACHE_FLUSH;

                        r = dns_answer_add(answer, i->rr, 0, flags, NULL);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to add RR to announce: %m");
                }

        /* Since all the active services are in the zone make them discoverable now. */
        SET_FOREACH(service_type, types) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR,
                                                  "_services._dns-sd._udp.local");
                if (!rr)
                        return log_oom();

                rr->ptr.name = strdup(service_type);
                if (!rr->ptr.name)
                        return log_oom();

                rr->ttl = MDNS_DEFAULT_TTL;

                r = dns_zone_put(&scope->zone, scope, rr, false);
                if (r < 0)
                        log_warning_errno(r, "Failed to add DNS-SD PTR record to MDNS zone, ignoring: %m");

                r = dns_answer_add(answer, rr, 0, 0, NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add RR to announce: %m");
        }

        if (dns_answer_isempty(answer))
                return 0;

        r = dns_scope_make_reply_packet(scope, 0, DNS_RCODE_SUCCESS, NULL, answer, NULL, false, &p);
        if (r < 0)
                return log_debug_errno(r, "Failed to build reply packet: %m");

        r = dns_scope_emit_udp(scope, -1, AF_UNSPEC, p);
        if (r < 0)
                return log_debug_errno(r, "Failed to send reply packet: %m");

        /* In section 8.3 of RFC6762: "The Multicast DNS responder MUST send at least two unsolicited
         * responses, one second apart." */
        if (!scope->announced) {
                scope->announced = true;

                r = sd_event_add_time_relative(
                                scope->manager->event,
                                &scope->announce_event_source,
                                CLOCK_BOOTTIME,
                                MDNS_ANNOUNCE_DELAY,
                                0,
                                on_announcement_timeout, scope);
                if (r < 0)
                        return log_debug_errno(r, "Failed to schedule second announcement: %m");

                (void) sd_event_source_set_description(scope->announce_event_source, "mdns-announce");
        }

        return 0;
}

int dns_scope_add_dnssd_services(DnsScope *scope) {
        DnssdService *service;
        int r;

        assert(scope);

        if (hashmap_isempty(scope->manager->dnssd_services))
                return 0;

        scope->announced = false;

        HASHMAP_FOREACH(service, scope->manager->dnssd_services) {
                service->withdrawn = false;

                r = dns_zone_put(&scope->zone, scope, service->ptr_rr, false);
                if (r < 0)
                        log_warning_errno(r, "Failed to add PTR record to MDNS zone: %m");

                if (service->sub_ptr_rr) {
                        r = dns_zone_put(&scope->zone, scope, service->sub_ptr_rr, false);
                        if (r < 0)
                                log_warning_errno(r, "Failed to add selective PTR record to MDNS zone: %m");
                }

                r = dns_zone_put(&scope->zone, scope, service->srv_rr, true);
                if (r < 0)
                        log_warning_errno(r, "Failed to add SRV record to MDNS zone: %m");

                LIST_FOREACH(items, txt_data, service->txt_data_items) {
                        r = dns_zone_put(&scope->zone, scope, txt_data->rr, true);
                        if (r < 0)
                                log_warning_errno(r, "Failed to add TXT record to MDNS zone: %m");
                }
        }

        return 0;
}

int dns_scope_remove_dnssd_services(DnsScope *scope) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        DnssdService *service;
        int r;

        assert(scope);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR,
                                   "_services._dns-sd._udp.local");
        if (!key)
                return log_oom();

        r = dns_zone_remove_rrs_by_key(&scope->zone, key);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(service, scope->manager->dnssd_services) {
                dns_zone_remove_rr(&scope->zone, service->ptr_rr);
                dns_zone_remove_rr(&scope->zone, service->sub_ptr_rr);
                dns_zone_remove_rr(&scope->zone, service->srv_rr);
                LIST_FOREACH(items, txt_data, service->txt_data_items)
                        dns_zone_remove_rr(&scope->zone, txt_data->rr);
        }

        return 0;
}

static bool dns_scope_has_route_only_domains(DnsScope *scope) {
        DnsSearchDomain *first;
        bool route_only = false;

        assert(scope);
        assert(scope->protocol == DNS_PROTOCOL_DNS);

        /* Returns 'true' if this scope is suitable for queries to specific domains only. For that we check
         * if there are any route-only domains on this interface, as a heuristic to discern VPN-style links
         * from non-VPN-style links. Returns 'false' for all other cases, i.e. if the scope is intended to
         * take queries to arbitrary domains, i.e. has no routing domains set. */

        if (scope->link)
                first = scope->link->search_domains;
        else if (scope->delegate)
                first = scope->delegate->search_domains;
        else
                first = scope->manager->search_domains;

        LIST_FOREACH(domains, domain, first) {
                /* "." means "any domain", thus the interface takes any kind of traffic. Thus, we exit early
                 * here, as it doesn't really matter whether this link has any route-only domains or not,
                 * "~."  really trumps everything and clearly indicates that this interface shall receive all
                 * traffic it can get. */
                if (dns_name_is_root(DNS_SEARCH_DOMAIN_NAME(domain)))
                        return false;

                if (domain->route_only)
                        route_only = true;
        }

        return route_only;
}

bool dns_scope_is_default_route(DnsScope *scope) {
        assert(scope);

        /* Only use DNS scopes as default routes */
        if (scope->protocol != DNS_PROTOCOL_DNS)
                return false;

        if (scope->link) {

                /* Honour whatever is explicitly configured. This is really the best approach, and trumps any
                 * automatic logic. */
                if (scope->link->default_route >= 0)
                        return scope->link->default_route;

                /* Otherwise check if we have any route-only domains, as a sensible heuristic: if so, let's not
                 * volunteer as default route. */
                return !dns_scope_has_route_only_domains(scope);

        } else  if (scope->delegate) {

                if (scope->delegate->default_route >= 0)
                        return scope->delegate->default_route;

                /* Delegates are by default not used as default route */
                return false;
        } else
                /* The global DNS scope is always suitable as default route */
                return true;
}

int dns_scope_dump_cache_to_json(DnsScope *scope, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cache = NULL;
        int r;

        assert(scope);
        assert(ret);

        r = dns_cache_dump_to_json(&scope->cache, &cache);
        if (r < 0)
                return r;

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("protocol", dns_protocol_to_string(scope->protocol)),
                        SD_JSON_BUILD_PAIR_CONDITION(scope->family != AF_UNSPEC, "family", SD_JSON_BUILD_INTEGER(scope->family)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!scope->link, "ifindex", SD_JSON_BUILD_INTEGER(dns_scope_ifindex(scope))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!scope->link, "ifname", SD_JSON_BUILD_STRING(dns_scope_ifname(scope))),
                        SD_JSON_BUILD_PAIR_VARIANT("cache", cache));
}

int dns_type_suitable_for_protocol(uint16_t type, DnsProtocol protocol) {

        /* Tests whether it makes sense to route queries for the specified DNS RR types to the specified
         * protocol. For classic DNS pretty much all RR types are suitable, but for LLMNR/mDNS let's
         * allowlist only a few that make sense. We use this when routing queries so that we can more quickly
         * return errors for queries that will almost certainly fail/time out otherwise. For example, this
         * ensures that SOA, NS, or DS/DNSKEY queries are never routed to mDNS/LLMNR where they simply make
         * no sense. */

        if (dns_type_is_obsolete(type))
                return false;

        if (!dns_type_is_valid_query(type))
                return false;

        switch (protocol) {

        case DNS_PROTOCOL_DNS:
                return true;

        case DNS_PROTOCOL_LLMNR:
                return IN_SET(type,
                              DNS_TYPE_ANY,
                              DNS_TYPE_A,
                              DNS_TYPE_AAAA,
                              DNS_TYPE_CNAME,
                              DNS_TYPE_PTR,
                              DNS_TYPE_TXT);

        case DNS_PROTOCOL_MDNS:
                return IN_SET(type,
                              DNS_TYPE_ANY,
                              DNS_TYPE_A,
                              DNS_TYPE_AAAA,
                              DNS_TYPE_CNAME,
                              DNS_TYPE_PTR,
                              DNS_TYPE_TXT,
                              DNS_TYPE_SRV,
                              DNS_TYPE_NSEC,
                              DNS_TYPE_HINFO);

        default:
                return -EPROTONOSUPPORT;
        }
}

int dns_question_types_suitable_for_protocol(DnsQuestion *q, DnsProtocol protocol) {
        DnsResourceKey *key;
        int r;

        /* Tests whether the types in the specified question make any sense to be routed to the specified
         * protocol, i.e. if dns_type_suitable_for_protocol() is true for any of the contained RR types */

        DNS_QUESTION_FOREACH(key, q) {
                r = dns_type_suitable_for_protocol(key->type, protocol);
                if (r != 0)
                        return r;
        }

        return false;
}

static const char* const dns_scope_origin_table[_DNS_SCOPE_ORIGIN_MAX] = {
        [DNS_SCOPE_GLOBAL]   = "global",
        [DNS_SCOPE_LINK]     = "link",
        [DNS_SCOPE_DELEGATE] = "delegate",
};

DEFINE_STRING_TABLE_LOOKUP(dns_scope_origin, DnsScopeOrigin);
