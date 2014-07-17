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
#include "resolved-dns-domain.h"
#include "resolved-dns-scope.h"

#define SEND_TIMEOUT_USEC (2*USEC_PER_SEC)

int dns_scope_new(Manager *m, DnsScope **ret, DnsScopeType t) {
        DnsScope *s;

        assert(m);
        assert(ret);

        s = new0(DnsScope, 1);
        if (!s)
                return -ENOMEM;

        s->manager = m;
        s->type = t;

        LIST_PREPEND(scopes, m->dns_scopes, s);

        *ret = s;
        return 0;
}

DnsScope* dns_scope_free(DnsScope *s) {
        if (!s)
                return NULL;

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

        if (s->link)
                return link_get_dns_server(s->link);
        else
                return manager_get_dns_server(s->manager);
}

void dns_scope_next_dns_server(DnsScope *s) {
        assert(s);

        if (s->link)
                link_next_dns_server(s->link);
        else
                manager_next_dns_server(s->manager);
}

int dns_scope_send(DnsScope *s, DnsPacket *p) {
        int ifindex = 0;
        DnsServer *srv;
        int r;

        assert(s);
        assert(p);

        srv = dns_scope_get_server(s);
        if (!srv)
                return -ESRCH;

        if (s->link) {
                if (p->size > s->link->mtu)
                        return -EMSGSIZE;

                ifindex = s->link->ifindex;
        } else {
                uint32_t mtu;

                mtu = manager_find_mtu(s->manager);
                if (mtu > 0) {
                        if (p->size > mtu)
                                return -EMSGSIZE;
                }
        }

        if (p->size > DNS_PACKET_UNICAST_SIZE_MAX)
                return -EMSGSIZE;

        if (srv->family == AF_INET)
                r = manager_dns_ipv4_send(s->manager, srv, ifindex, p);
        else if (srv->family == AF_INET6)
                r = manager_dns_ipv6_send(s->manager, srv, ifindex, p);
        else
                return -EAFNOSUPPORT;

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

DnsScopeMatch dns_scope_test(DnsScope *s, const char *domain) {
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

        if (s->type == DNS_SCOPE_MDNS) {
                if (dns_name_endswith(domain, "254.169.in-addr.arpa") ||
                    dns_name_endswith(domain, "0.8.e.f.ip6.arpa"))
                        return DNS_SCOPE_YES;
                else if (dns_name_endswith(domain, "local") &&
                         !dns_name_single_label(domain))
                        return DNS_SCOPE_MAYBE;

                return DNS_SCOPE_NO;
        }

        if (s->type == DNS_SCOPE_DNS) {
                if (dns_name_endswith(domain, "254.169.in-addr.arpa") ||
                    dns_name_endswith(domain, "0.8.e.f.ip6.arpa") ||
                    dns_name_single_label(domain))
                        return DNS_SCOPE_NO;

                return DNS_SCOPE_MAYBE;
        }

        assert_not_reached("Unknown scope type");
}
