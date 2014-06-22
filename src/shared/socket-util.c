/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <sys/ioctl.h>

#include "macro.h"
#include "util.h"
#include "mkdir.h"
#include "path-util.h"
#include "socket-util.h"
#include "missing.h"
#include "fileio.h"

int socket_address_parse(SocketAddress *a, const char *s) {
        char *e, *n;
        unsigned u;
        int r;

        assert(a);
        assert(s);

        zero(*a);
        a->type = SOCK_STREAM;

        if (*s == '[') {
                /* IPv6 in [x:.....:z]:p notation */

                if (!socket_ipv6_is_supported()) {
                        log_warning("Binding to IPv6 address not available since kernel does not support IPv6.");
                        return -EAFNOSUPPORT;
                }

                e = strchr(s+1, ']');
                if (!e)
                        return -EINVAL;

                n = strndupa(s+1, e-s-1);

                errno = 0;
                if (inet_pton(AF_INET6, n, &a->sockaddr.in6.sin6_addr) <= 0)
                        return errno > 0 ? -errno : -EINVAL;

                e++;
                if (*e != ':')
                        return -EINVAL;

                e++;
                r = safe_atou(e, &u);
                if (r < 0)
                        return r;

                if (u <= 0 || u > 0xFFFF)
                        return -EINVAL;

                a->sockaddr.in6.sin6_family = AF_INET6;
                a->sockaddr.in6.sin6_port = htons((uint16_t) u);
                a->size = sizeof(struct sockaddr_in6);

        } else if (*s == '/') {
                /* AF_UNIX socket */

                size_t l;

                l = strlen(s);
                if (l >= sizeof(a->sockaddr.un.sun_path))
                        return -EINVAL;

                a->sockaddr.un.sun_family = AF_UNIX;
                memcpy(a->sockaddr.un.sun_path, s, l);
                a->size = offsetof(struct sockaddr_un, sun_path) + l + 1;

        } else if (*s == '@') {
                /* Abstract AF_UNIX socket */
                size_t l;

                l = strlen(s+1);
                if (l >= sizeof(a->sockaddr.un.sun_path) - 1)
                        return -EINVAL;

                a->sockaddr.un.sun_family = AF_UNIX;
                memcpy(a->sockaddr.un.sun_path+1, s+1, l);
                a->size = offsetof(struct sockaddr_un, sun_path) + 1 + l;

        } else {
                e = strchr(s, ':');
                if (e) {
                        r = safe_atou(e+1, &u);
                        if (r < 0)
                                return r;

                        if (u <= 0 || u > 0xFFFF)
                                return -EINVAL;

                        n = strndupa(s, e-s);

                        /* IPv4 in w.x.y.z:p notation? */
                        r = inet_pton(AF_INET, n, &a->sockaddr.in.sin_addr);
                        if (r < 0)
                                return -errno;

                        if (r > 0) {
                                /* Gotcha, it's a traditional IPv4 address */
                                a->sockaddr.in.sin_family = AF_INET;
                                a->sockaddr.in.sin_port = htons((uint16_t) u);
                                a->size = sizeof(struct sockaddr_in);
                        } else {
                                unsigned idx;

                                if (strlen(n) > IF_NAMESIZE-1)
                                        return -EINVAL;

                                /* Uh, our last resort, an interface name */
                                idx = if_nametoindex(n);
                                if (idx == 0)
                                        return -EINVAL;

                                if (!socket_ipv6_is_supported()) {
                                        log_warning("Binding to interface is not available since kernel does not support IPv6.");
                                        return -EAFNOSUPPORT;
                                }

                                a->sockaddr.in6.sin6_family = AF_INET6;
                                a->sockaddr.in6.sin6_port = htons((uint16_t) u);
                                a->sockaddr.in6.sin6_scope_id = idx;
                                a->sockaddr.in6.sin6_addr = in6addr_any;
                                a->size = sizeof(struct sockaddr_in6);
                        }
                } else {

                        /* Just a port */
                        r = safe_atou(s, &u);
                        if (r < 0)
                                return r;

                        if (u <= 0 || u > 0xFFFF)
                                return -EINVAL;

                        if (socket_ipv6_is_supported()) {
                                a->sockaddr.in6.sin6_family = AF_INET6;
                                a->sockaddr.in6.sin6_port = htons((uint16_t) u);
                                a->sockaddr.in6.sin6_addr = in6addr_any;
                                a->size = sizeof(struct sockaddr_in6);
                        } else {
                                a->sockaddr.in.sin_family = AF_INET;
                                a->sockaddr.in.sin_port = htons((uint16_t) u);
                                a->sockaddr.in.sin_addr.s_addr = INADDR_ANY;
                                a->size = sizeof(struct sockaddr_in);
                        }
                }
        }

        return 0;
}

int socket_address_parse_netlink(SocketAddress *a, const char *s) {
        int family;
        unsigned group = 0;
        _cleanup_free_ char *sfamily = NULL;
        assert(a);
        assert(s);

        zero(*a);
        a->type = SOCK_RAW;

        errno = 0;
        if (sscanf(s, "%ms %u", &sfamily, &group) < 1)
                return errno > 0 ? -errno : -EINVAL;

        family = netlink_family_from_string(sfamily);
        if (family < 0)
                return -EINVAL;

        a->sockaddr.nl.nl_family = AF_NETLINK;
        a->sockaddr.nl.nl_groups = group;

        a->type = SOCK_RAW;
        a->size = sizeof(struct sockaddr_nl);
        a->protocol = family;

        return 0;
}

int socket_address_verify(const SocketAddress *a) {
        assert(a);

        switch (socket_address_family(a)) {

        case AF_INET:
                if (a->size != sizeof(struct sockaddr_in))
                        return -EINVAL;

                if (a->sockaddr.in.sin_port == 0)
                        return -EINVAL;

                if (a->type != SOCK_STREAM && a->type != SOCK_DGRAM)
                        return -EINVAL;

                return 0;

        case AF_INET6:
                if (a->size != sizeof(struct sockaddr_in6))
                        return -EINVAL;

                if (a->sockaddr.in6.sin6_port == 0)
                        return -EINVAL;

                if (a->type != SOCK_STREAM && a->type != SOCK_DGRAM)
                        return -EINVAL;

                return 0;

        case AF_UNIX:
                if (a->size < offsetof(struct sockaddr_un, sun_path))
                        return -EINVAL;

                if (a->size > offsetof(struct sockaddr_un, sun_path)) {

                        if (a->sockaddr.un.sun_path[0] != 0) {
                                char *e;

                                /* path */
                                e = memchr(a->sockaddr.un.sun_path, 0, sizeof(a->sockaddr.un.sun_path));
                                if (!e)
                                        return -EINVAL;

                                if (a->size != offsetof(struct sockaddr_un, sun_path) + (e - a->sockaddr.un.sun_path) + 1)
                                        return -EINVAL;
                        }
                }

                if (a->type != SOCK_STREAM && a->type != SOCK_DGRAM && a->type != SOCK_SEQPACKET)
                        return -EINVAL;

                return 0;

        case AF_NETLINK:

                if (a->size != sizeof(struct sockaddr_nl))
                        return -EINVAL;

                if (a->type != SOCK_RAW && a->type != SOCK_DGRAM)
                        return -EINVAL;

                return 0;

        default:
                return -EAFNOSUPPORT;
        }
}

int socket_address_print(const SocketAddress *a, char **ret) {
        int r;

        assert(a);
        assert(ret);

        r = socket_address_verify(a);
        if (r < 0)
                return r;

        if (socket_address_family(a) == AF_NETLINK) {
                _cleanup_free_ char *sfamily = NULL;

                r = netlink_family_to_string_alloc(a->protocol, &sfamily);
                if (r < 0)
                        return r;

                r = asprintf(ret, "%s %u", sfamily, a->sockaddr.nl.nl_groups);
                if (r < 0)
                        return -ENOMEM;

                return 0;
        }

        return sockaddr_pretty(&a->sockaddr.sa, a->size, false, ret);
}

bool socket_address_can_accept(const SocketAddress *a) {
        assert(a);

        return
                a->type == SOCK_STREAM ||
                a->type == SOCK_SEQPACKET;
}

bool socket_address_equal(const SocketAddress *a, const SocketAddress *b) {
        assert(a);
        assert(b);

        /* Invalid addresses are unequal to all */
        if (socket_address_verify(a) < 0 ||
            socket_address_verify(b) < 0)
                return false;

        if (a->type != b->type)
                return false;

        if (a->size != b->size)
                return false;

        if (socket_address_family(a) != socket_address_family(b))
                return false;

        switch (socket_address_family(a)) {

        case AF_INET:
                if (a->sockaddr.in.sin_addr.s_addr != b->sockaddr.in.sin_addr.s_addr)
                        return false;

                if (a->sockaddr.in.sin_port != b->sockaddr.in.sin_port)
                        return false;

                break;

        case AF_INET6:
                if (memcmp(&a->sockaddr.in6.sin6_addr, &b->sockaddr.in6.sin6_addr, sizeof(a->sockaddr.in6.sin6_addr)) != 0)
                        return false;

                if (a->sockaddr.in6.sin6_port != b->sockaddr.in6.sin6_port)
                        return false;

                break;

        case AF_UNIX:

                if ((a->sockaddr.un.sun_path[0] == 0) != (b->sockaddr.un.sun_path[0] == 0))
                        return false;

                if (a->sockaddr.un.sun_path[0]) {
                        if (!strneq(a->sockaddr.un.sun_path, b->sockaddr.un.sun_path, sizeof(a->sockaddr.un.sun_path)))
                                return false;
                } else {
                        if (memcmp(a->sockaddr.un.sun_path, b->sockaddr.un.sun_path, a->size) != 0)
                                return false;
                }

                break;

        case AF_NETLINK:

                if (a->protocol != b->protocol)
                        return false;

                if (a->sockaddr.nl.nl_groups != b->sockaddr.nl.nl_groups)
                        return false;

                break;

        default:
                /* Cannot compare, so we assume the addresses are different */
                return false;
        }

        return true;
}

bool socket_address_is(const SocketAddress *a, const char *s, int type) {
        struct SocketAddress b;

        assert(a);
        assert(s);

        if (socket_address_parse(&b, s) < 0)
                return false;

        b.type = type;

        return socket_address_equal(a, &b);
}

bool socket_address_is_netlink(const SocketAddress *a, const char *s) {
        struct SocketAddress b;

        assert(a);
        assert(s);

        if (socket_address_parse_netlink(&b, s) < 0)
                return false;

        return socket_address_equal(a, &b);
}

const char* socket_address_get_path(const SocketAddress *a) {
        assert(a);

        if (socket_address_family(a) != AF_UNIX)
                return NULL;

        if (a->sockaddr.un.sun_path[0] == 0)
                return NULL;

        return a->sockaddr.un.sun_path;
}

bool socket_ipv6_is_supported(void) {
        _cleanup_free_ char *l = NULL;

        if (access("/sys/module/ipv6", F_OK) != 0)
                return 0;

        /* If we can't check "disable" parameter, assume enabled */
        if (read_one_line_file("/sys/module/ipv6/parameters/disable", &l) < 0)
                return 1;

        /* If module was loaded with disable=1 no IPv6 available */
        return l[0] == '0';
}

bool socket_address_matches_fd(const SocketAddress *a, int fd) {
        union sockaddr_union sa;
        socklen_t salen = sizeof(sa), solen;
        int protocol, type;

        assert(a);
        assert(fd >= 0);

        if (getsockname(fd, &sa.sa, &salen) < 0)
                return false;

        if (sa.sa.sa_family != a->sockaddr.sa.sa_family)
                return false;

        solen = sizeof(type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &solen) < 0)
                return false;

        if (type != a->type)
                return false;

        if (a->protocol != 0)  {
                solen = sizeof(protocol);
                if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &solen) < 0)
                        return false;

                if (protocol != a->protocol)
                        return false;
        }

        switch (sa.sa.sa_family) {

        case AF_INET:
                return sa.in.sin_port == a->sockaddr.in.sin_port &&
                        sa.in.sin_addr.s_addr == a->sockaddr.in.sin_addr.s_addr;

        case AF_INET6:
                return sa.in6.sin6_port == a->sockaddr.in6.sin6_port &&
                        memcmp(&sa.in6.sin6_addr, &a->sockaddr.in6.sin6_addr, sizeof(struct in6_addr)) == 0;

        case AF_UNIX:
                return salen == a->size &&
                        memcmp(sa.un.sun_path, a->sockaddr.un.sun_path, salen - offsetof(struct sockaddr_un, sun_path)) == 0;

        }

        return false;
}

int sockaddr_pretty(const struct sockaddr *_sa, socklen_t salen, bool translate_ipv6, char **ret) {
        union sockaddr_union *sa = (union sockaddr_union*) _sa;
        char *p;

        assert(sa);
        assert(salen >= sizeof(sa->sa.sa_family));

        switch (sa->sa.sa_family) {

        case AF_INET: {
                uint32_t a;

                a = ntohl(sa->in.sin_addr.s_addr);

                if (asprintf(&p,
                             "%u.%u.%u.%u:%u",
                             a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF,
                             ntohs(sa->in.sin_port)) < 0)
                        return -ENOMEM;

                break;
        }

        case AF_INET6: {
                static const unsigned char ipv4_prefix[] = {
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF
                };

                if (translate_ipv6 && memcmp(&sa->in6.sin6_addr, ipv4_prefix, sizeof(ipv4_prefix)) == 0) {
                        const uint8_t *a = sa->in6.sin6_addr.s6_addr+12;

                        if (asprintf(&p,
                                     "%u.%u.%u.%u:%u",
                                     a[0], a[1], a[2], a[3],
                                     ntohs(sa->in6.sin6_port)) < 0)
                                return -ENOMEM;
                } else {
                        char a[INET6_ADDRSTRLEN];

                        if (asprintf(&p,
                                     "[%s]:%u",
                                     inet_ntop(AF_INET6, &sa->in6.sin6_addr, a, sizeof(a)),
                                     ntohs(sa->in6.sin6_port)) < 0)
                                return -ENOMEM;
                }

                break;
        }

        case AF_UNIX:
                if (salen <= offsetof(struct sockaddr_un, sun_path)) {
                        p = strdup("<unnamed>");
                        if (!p)
                                return -ENOMEM;

                } else if (sa->un.sun_path[0] == 0) {
                        /* abstract */

                        /* FIXME: We assume we can print the
                         * socket path here and that it hasn't
                         * more than one NUL byte. That is
                         * actually an invalid assumption */

                        p = new(char, sizeof(sa->un.sun_path)+1);
                        if (!p)
                                return -ENOMEM;

                        p[0] = '@';
                        memcpy(p+1, sa->un.sun_path+1, sizeof(sa->un.sun_path)-1);
                        p[sizeof(sa->un.sun_path)] = 0;

                } else {
                        p = strndup(sa->un.sun_path, sizeof(sa->un.sun_path));
                        if (!ret)
                                return -ENOMEM;
                }

                break;

        default:
                return -ENOTSUP;
        }


        *ret = p;
        return 0;
}

int getpeername_pretty(int fd, char **ret) {
        union sockaddr_union sa;
        socklen_t salen;
        int r;

        assert(fd >= 0);
        assert(ret);

        salen = sizeof(sa);
        if (getpeername(fd, &sa.sa, &salen) < 0)
                return -errno;

        if (sa.sa.sa_family == AF_UNIX) {
                struct ucred ucred = {};

                /* UNIX connection sockets are anonymous, so let's use
                 * PID/UID as pretty credentials instead */

                r = getpeercred(fd, &ucred);
                if (r < 0)
                        return r;

                if (asprintf(ret, "PID "PID_FMT"/UID "UID_FMT, ucred.pid, ucred.uid) < 0)
                        return -ENOMEM;

                return 0;
        }

        /* For remote sockets we translate IPv6 addresses back to IPv4
         * if applicable, since that's nicer. */

        return sockaddr_pretty(&sa.sa, salen, true, ret);
}

int getsockname_pretty(int fd, char **ret) {
        union sockaddr_union sa;
        socklen_t salen;

        assert(fd >= 0);
        assert(ret);

        salen = sizeof(sa);
        if (getsockname(fd, &sa.sa, &salen) < 0)
                return -errno;

        /* For local sockets we do not translate IPv6 addresses back
         * to IPv6 if applicable, since this is usually used for
         * listening sockets where the difference between IPv4 and
         * IPv6 matters. */

        return sockaddr_pretty(&sa.sa, salen, false, ret);
}

int socket_address_unlink(SocketAddress *a) {
        assert(a);

        if (socket_address_family(a) != AF_UNIX)
                return 0;

        if (a->sockaddr.un.sun_path[0] == 0)
                return 0;

        if (unlink(a->sockaddr.un.sun_path) < 0)
                return -errno;

        return 1;
}

int in_addr_null(unsigned family, union in_addr_union *u) {
        assert(u);

        if (family == AF_INET)
                return u->in.s_addr == 0;

        if (family == AF_INET6)
                return
                        u->in6.s6_addr32[0] == 0 &&
                        u->in6.s6_addr32[1] == 0 &&
                        u->in6.s6_addr32[2] == 0 &&
                        u->in6.s6_addr32[3] == 0;

        return -EAFNOSUPPORT;
}


int in_addr_equal(unsigned family, union in_addr_union *a, union in_addr_union *b) {
        assert(a);
        assert(b);

        if (family == AF_INET)
                return a->in.s_addr == b->in.s_addr;

        if (family == AF_INET6)
                return
                        a->in6.s6_addr32[0] == b->in6.s6_addr32[0] &&
                        a->in6.s6_addr32[1] == b->in6.s6_addr32[1] &&
                        a->in6.s6_addr32[2] == b->in6.s6_addr32[2] &&
                        a->in6.s6_addr32[3] == b->in6.s6_addr32[3];

        return -EAFNOSUPPORT;
}

int in_addr_prefix_intersect(
                unsigned family,
                const union in_addr_union *a,
                unsigned aprefixlen,
                const union in_addr_union *b,
                unsigned bprefixlen) {

        unsigned m;

        assert(a);
        assert(b);

        /* Checks whether there are any addresses that are in both
         * networks */

        m = MIN(aprefixlen, bprefixlen);

        if (family == AF_INET) {
                uint32_t x, nm;

                x = be32toh(a->in.s_addr ^ b->in.s_addr);
                nm = (m == 0) ? 0 : 0xFFFFFFFFUL << (32 - m);

                return (x & nm) == 0;
        }

        if (family == AF_INET6) {
                unsigned i;

                if (m > 128)
                        m = 128;

                for (i = 0; i < 16; i++) {
                        uint8_t x, nm;

                        x = a->in6.s6_addr[i] ^ b->in6.s6_addr[i];

                        if (m < 8)
                                nm = 0xFF << (8 - m);
                        else
                                nm = 0xFF;

                        if ((x & nm) != 0)
                                return 0;

                        if (m > 8)
                                m -= 8;
                        else
                                m = 0;
                }

                return 1;
        }

        return -EAFNOSUPPORT;
}

int in_addr_prefix_next(unsigned family, union in_addr_union *u, unsigned prefixlen) {
        assert(u);

        /* Increases the network part of an address by one. Returns
         * positive it that succeeds, or 0 if this overflows. */

        if (prefixlen <= 0)
                return 0;

        if (family == AF_INET) {
                uint32_t c, n;

                if (prefixlen > 32)
                        prefixlen = 32;

                c = be32toh(u->in.s_addr);
                n = c + (1UL << (32 - prefixlen));
                if (n < c)
                        return 0;
                n &= 0xFFFFFFFFUL << (32 - prefixlen);

                u->in.s_addr = htobe32(n);
                return 1;
        }

        if (family == AF_INET6) {
                struct in6_addr add = {}, result;
                uint8_t overflow = 0;
                unsigned i;

                if (prefixlen > 128)
                        prefixlen = 128;

                /* First calculate what we have to add */
                add.s6_addr[(prefixlen-1) / 8] = 1 << (7 - (prefixlen-1) % 8);

                for (i = 16; i > 0; i--) {
                        unsigned j = i - 1;

                        result.s6_addr[j] = u->in6.s6_addr[j] + add.s6_addr[j] + overflow;
                        overflow = (result.s6_addr[j] < u->in6.s6_addr[j]);
                }

                if (overflow)
                        return 0;

                u->in6 = result;
                return 1;
        }

        return -EAFNOSUPPORT;
}

int in_addr_to_string(unsigned family, const union in_addr_union *u, char **ret) {
        char *x;
        size_t l;

        assert(u);
        assert(ret);

        if (family == AF_INET)
                l = INET_ADDRSTRLEN;
        else if (family == AF_INET6)
                l = INET6_ADDRSTRLEN;
        else
                return -EAFNOSUPPORT;

        x = new(char, l);
        if (!x)
                return -ENOMEM;

        errno = 0;
        if (!inet_ntop(family, u, x, l)) {
                free(x);
                return errno ? -errno : -EINVAL;
        }

        *ret = x;
        return 0;
}

int in_addr_from_string(unsigned family, const char *s, union in_addr_union *ret) {

        assert(s);
        assert(ret);

        if (!IN_SET(family, AF_INET, AF_INET6))
                return -EAFNOSUPPORT;

        errno = 0;
        if (inet_pton(family, s, ret) <= 0)
                return errno ? -errno : -EINVAL;

        return 0;
}

static const char* const netlink_family_table[] = {
        [NETLINK_ROUTE] = "route",
        [NETLINK_FIREWALL] = "firewall",
        [NETLINK_INET_DIAG] = "inet-diag",
        [NETLINK_NFLOG] = "nflog",
        [NETLINK_XFRM] = "xfrm",
        [NETLINK_SELINUX] = "selinux",
        [NETLINK_ISCSI] = "iscsi",
        [NETLINK_AUDIT] = "audit",
        [NETLINK_FIB_LOOKUP] = "fib-lookup",
        [NETLINK_CONNECTOR] = "connector",
        [NETLINK_NETFILTER] = "netfilter",
        [NETLINK_IP6_FW] = "ip6-fw",
        [NETLINK_DNRTMSG] = "dnrtmsg",
        [NETLINK_KOBJECT_UEVENT] = "kobject-uevent",
        [NETLINK_GENERIC] = "generic",
        [NETLINK_SCSITRANSPORT] = "scsitransport",
        [NETLINK_ECRYPTFS] = "ecryptfs"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(netlink_family, int, INT_MAX);

static const char* const socket_address_bind_ipv6_only_table[_SOCKET_ADDRESS_BIND_IPV6_ONLY_MAX] = {
        [SOCKET_ADDRESS_DEFAULT] = "default",
        [SOCKET_ADDRESS_BOTH] = "both",
        [SOCKET_ADDRESS_IPV6_ONLY] = "ipv6-only"
};

DEFINE_STRING_TABLE_LOOKUP(socket_address_bind_ipv6_only, SocketAddressBindIPv6Only);
