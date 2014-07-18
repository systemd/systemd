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

#include <netinet/tcp.h>

#include "strv.h"
#include "socket-util.h"
#include "af-list.h"
#include "resolved-dns-domain.h"
#include "resolved-dns-scope.h"

#define SEND_TIMEOUT_USEC (2*USEC_PER_SEC)

int dns_scope_new(Manager *m, DnsScope **ret, Link *l, DnsProtocol protocol, int family) {
        DnsScope *s;

        assert(m);
        assert(ret);

        s = new0(DnsScope, 1);
        if (!s)
                return -ENOMEM;

        s->manager = m;
        s->link = l;
        s->protocol = protocol;
        s->family = family;

        LIST_PREPEND(scopes, m->dns_scopes, s);

        dns_scope_llmnr_membership(s, true);

        log_debug("New scope on link %s, protocol %s, family %s", l ? l->name : "*", dns_protocol_to_string(protocol), family == AF_UNSPEC ? "*" : af_to_name(family));

        *ret = s;
        return 0;
}

DnsScope* dns_scope_free(DnsScope *s) {
        if (!s)
                return NULL;

        log_debug("Removing scope on link %s, protocol %s, family %s", s->link ? s->link->name : "*", dns_protocol_to_string(s->protocol), s->family == AF_UNSPEC ? "*" : af_to_name(s->family));

        dns_scope_llmnr_membership(s, false);

        while (s->transactions) {
                DnsQuery *q;

                q = s->transactions->query;
                dns_query_transaction_free(s->transactions);

                dns_query_finish(q);
        }

        dns_cache_flush(&s->cache);

        LIST_REMOVE(scopes, s->manager->dns_scopes, s);
        strv_free(s->domains);
        free(s);

        return NULL;
}

DnsServer *dns_scope_get_server(DnsScope *s) {
        assert(s);

        if (s->protocol != DNS_PROTOCOL_DNS)
                return NULL;

        if (s->link)
                return link_get_dns_server(s->link);
        else
                return manager_get_dns_server(s->manager);
}

void dns_scope_next_dns_server(DnsScope *s) {
        assert(s);

        if (s->protocol != DNS_PROTOCOL_DNS)
                return;

        if (s->link)
                link_next_dns_server(s->link);
        else
                manager_next_dns_server(s->manager);
}

int dns_scope_send(DnsScope *s, DnsPacket *p) {
        union in_addr_union addr;
        int ifindex = 0, r;
        int family;
        uint16_t port;
        uint32_t mtu;
        int fd;

        assert(s);
        assert(p);
        assert(p->protocol == s->protocol);

        if (s->link) {
                mtu = s->link->mtu;
                ifindex = s->link->ifindex;
        } else
                mtu = manager_find_mtu(s->manager);

        if (s->protocol == DNS_PROTOCOL_DNS) {
                DnsServer *srv;

                srv = dns_scope_get_server(s);
                if (!srv)
                        return -ESRCH;

                family = srv->family;
                addr = srv->address;
                port = 53;

                if (p->size > DNS_PACKET_UNICAST_SIZE_MAX)
                        return -EMSGSIZE;

                if (p->size > mtu)
                        return -EMSGSIZE;

                if (family == AF_INET)
                        fd = manager_dns_ipv4_fd(s->manager);
                else if (family == AF_INET6)
                        fd = manager_dns_ipv6_fd(s->manager);
                else
                        return -EAFNOSUPPORT;
                if (fd < 0)
                        return fd;

        } else if (s->protocol == DNS_PROTOCOL_LLMNR) {

                if (DNS_PACKET_QDCOUNT(p) > 1)
                        return -ENOTSUP;

                family = s->family;
                port = 5355;

                if (family == AF_INET) {
                        addr.in = LLMNR_MULTICAST_IPV4_ADDRESS;
                        /* fd = manager_dns_ipv4_fd(s->manager); */
                        fd = manager_llmnr_ipv4_udp_fd(s->manager);
                } else if (family == AF_INET6) {
                        addr.in6 = LLMNR_MULTICAST_IPV6_ADDRESS;
                        fd = manager_llmnr_ipv6_udp_fd(s->manager);
                        /* fd = manager_dns_ipv6_fd(s->manager); */
                } else
                        return -EAFNOSUPPORT;
                if (fd < 0)
                        return fd;
        } else
                return -EAFNOSUPPORT;

        r = manager_send(s->manager, fd, ifindex, family, &addr, port, p);
        if (r < 0)
                return r;

        return 1;
}

int dns_scope_tcp_socket(DnsScope *s) {
        _cleanup_close_ int fd = -1;
        union sockaddr_union sa = {};
        socklen_t salen;
        int one, ifindex, ret;
        DnsServer *srv;
        int r;

        assert(s);

        srv = dns_scope_get_server(s);
        if (!srv)
                return -ESRCH;

        if (s->link)
                ifindex = s->link->ifindex;

        sa.sa.sa_family = srv->family;
        if (srv->family == AF_INET) {
                sa.in.sin_port = htobe16(53);
                sa.in.sin_addr = srv->address.in;
                salen = sizeof(sa.in);
        } else if (srv->family == AF_INET6) {
                sa.in6.sin6_port = htobe16(53);
                sa.in6.sin6_addr = srv->address.in6;
                sa.in6.sin6_scope_id = ifindex;
                salen = sizeof(sa.in6);
        } else
                return -EAFNOSUPPORT;

        fd = socket(srv->family, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        r = connect(fd, &sa.sa, salen);
        if (r < 0 && errno != EINPROGRESS)
                return -errno;

        ret = fd;
        fd = -1;
        return ret;
}

DnsScopeMatch dns_scope_good_domain(DnsScope *s, const char *domain) {
        char **i;

        assert(s);
        assert(domain);

        STRV_FOREACH(i, s->domains)
                if (dns_name_endswith(domain, *i))
                        return DNS_SCOPE_YES;

        if (dns_name_root(domain))
                return DNS_SCOPE_NO;

        if (is_localhost(domain))
                return DNS_SCOPE_NO;

        if (s->protocol == DNS_PROTOCOL_DNS) {
                if (dns_name_endswith(domain, "254.169.in-addr.arpa") ||
                    dns_name_endswith(domain, "0.8.e.f.ip6.arpa") ||
                    dns_name_single_label(domain))
                        return DNS_SCOPE_NO;

                return DNS_SCOPE_MAYBE;
        }

        if (s->protocol == DNS_PROTOCOL_MDNS) {
                if (dns_name_endswith(domain, "254.169.in-addr.arpa") ||
                    dns_name_endswith(domain, "0.8.e.f.ip6.arpa") ||
                    dns_name_endswith(domain, "local"))
                        return DNS_SCOPE_MAYBE;

                return DNS_SCOPE_NO;
        }

        if (s->protocol == DNS_PROTOCOL_LLMNR) {
                if (dns_name_endswith(domain, "254.169.in-addr.arpa") ||
                    dns_name_endswith(domain, "0.8.e.f.ip6.arpa") ||
                    dns_name_single_label(domain))
                        return DNS_SCOPE_MAYBE;

                return DNS_SCOPE_NO;
        }

        assert_not_reached("Unknown scope protocol");
}

int dns_scope_good_key(DnsScope *s, DnsResourceKey *key) {
        assert(s);
        assert(key);

        if (s->protocol == DNS_PROTOCOL_DNS)
                return true;

        /* On mDNS and LLMNR, send A and AAAA queries only on the
         * respective scopes */

        if (s->family == AF_INET && key->class == DNS_CLASS_IN && key->type == DNS_TYPE_AAAA)
                return false;

        if (s->family == AF_INET6 && key->class == DNS_CLASS_IN && key->type == DNS_TYPE_A)
                return false;

        return true;
}

int dns_scope_llmnr_membership(DnsScope *s, bool b) {
        int fd;

        if (s->family == AF_INET) {
                struct ip_mreqn mreqn = {
                        .imr_multiaddr = LLMNR_MULTICAST_IPV4_ADDRESS,
                        .imr_ifindex = s->link->ifindex,
                };

                fd = manager_llmnr_ipv4_udp_fd(s->manager);
                if (fd < 0)
                        return fd;

                if (setsockopt(fd, IPPROTO_IP, b ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, &mreqn, sizeof(mreqn)) < 0)
                        return -errno;

        } else if (s->family == AF_INET6) {
                struct ipv6_mreq mreq = {
                        .ipv6mr_multiaddr = LLMNR_MULTICAST_IPV6_ADDRESS,
                        .ipv6mr_interface = s->link->ifindex,
                };

                fd = manager_llmnr_ipv6_udp_fd(s->manager);
                if (fd < 0)
                        return fd;

                if (setsockopt(fd, IPPROTO_IPV6, b ? IPV6_ADD_MEMBERSHIP : IPV6_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
                        return -errno;
        } else
                return -EAFNOSUPPORT;

        return 0;
}
