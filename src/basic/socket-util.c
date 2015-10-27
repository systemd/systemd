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

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "formats-util.h"
#include "macro.h"
#include "missing.h"
#include "parse-util.h"
#include "path-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "user-util.h"
#include "util.h"

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

int socket_address_parse_and_warn(SocketAddress *a, const char *s) {
        SocketAddress b;
        int r;

        /* Similar to socket_address_parse() but warns for IPv6 sockets when we don't support them. */

        r = socket_address_parse(&b, s);
        if (r < 0)
                return r;

        if (!socket_ipv6_is_supported() && b.sockaddr.sa.sa_family == AF_INET6) {
                log_warning("Binding to IPv6 address not available since kernel does not support IPv6.");
                return -EAFNOSUPPORT;
        }

        *a = b;
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

        return sockaddr_pretty(&a->sockaddr.sa, a->size, false, true, ret);
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
                if (a->size <= offsetof(struct sockaddr_un, sun_path) ||
                    b->size <= offsetof(struct sockaddr_un, sun_path))
                        return false;

                if ((a->sockaddr.un.sun_path[0] == 0) != (b->sockaddr.un.sun_path[0] == 0))
                        return false;

                if (a->sockaddr.un.sun_path[0]) {
                        if (!path_equal_or_files_same(a->sockaddr.un.sun_path, b->sockaddr.un.sun_path))
                                return false;
                } else {
                        if (a->size != b->size)
                                return false;

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
                return false;

        /* If we can't check "disable" parameter, assume enabled */
        if (read_one_line_file("/sys/module/ipv6/parameters/disable", &l) < 0)
                return true;

        /* If module was loaded with disable=1 no IPv6 available */
        return l[0] == '0';
}

bool socket_address_matches_fd(const SocketAddress *a, int fd) {
        SocketAddress b;
        socklen_t solen;

        assert(a);
        assert(fd >= 0);

        b.size = sizeof(b.sockaddr);
        if (getsockname(fd, &b.sockaddr.sa, &b.size) < 0)
                return false;

        if (b.sockaddr.sa.sa_family != a->sockaddr.sa.sa_family)
                return false;

        solen = sizeof(b.type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &b.type, &solen) < 0)
                return false;

        if (b.type != a->type)
                return false;

        if (a->protocol != 0)  {
                solen = sizeof(b.protocol);
                if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &b.protocol, &solen) < 0)
                        return false;

                if (b.protocol != a->protocol)
                        return false;
        }

        return socket_address_equal(a, &b);
}

int sockaddr_port(const struct sockaddr *_sa) {
        union sockaddr_union *sa = (union sockaddr_union*) _sa;

        assert(sa);

        if (!IN_SET(sa->sa.sa_family, AF_INET, AF_INET6))
                return -EAFNOSUPPORT;

        return ntohs(sa->sa.sa_family == AF_INET6 ?
                       sa->in6.sin6_port :
                       sa->in.sin_port);
}

int sockaddr_pretty(const struct sockaddr *_sa, socklen_t salen, bool translate_ipv6, bool include_port, char **ret) {
        union sockaddr_union *sa = (union sockaddr_union*) _sa;
        char *p;
        int r;

        assert(sa);
        assert(salen >= sizeof(sa->sa.sa_family));

        switch (sa->sa.sa_family) {

        case AF_INET: {
                uint32_t a;

                a = ntohl(sa->in.sin_addr.s_addr);

                if (include_port)
                        r = asprintf(&p,
                                     "%u.%u.%u.%u:%u",
                                     a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF,
                                     ntohs(sa->in.sin_port));
                else
                        r = asprintf(&p,
                                     "%u.%u.%u.%u",
                                     a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF);
                if (r < 0)
                        return -ENOMEM;
                break;
        }

        case AF_INET6: {
                static const unsigned char ipv4_prefix[] = {
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF
                };

                if (translate_ipv6 &&
                    memcmp(&sa->in6.sin6_addr, ipv4_prefix, sizeof(ipv4_prefix)) == 0) {
                        const uint8_t *a = sa->in6.sin6_addr.s6_addr+12;
                        if (include_port)
                                r = asprintf(&p,
                                             "%u.%u.%u.%u:%u",
                                             a[0], a[1], a[2], a[3],
                                             ntohs(sa->in6.sin6_port));
                        else
                                r = asprintf(&p,
                                             "%u.%u.%u.%u",
                                             a[0], a[1], a[2], a[3]);
                        if (r < 0)
                                return -ENOMEM;
                } else {
                        char a[INET6_ADDRSTRLEN];

                        inet_ntop(AF_INET6, &sa->in6.sin6_addr, a, sizeof(a));

                        if (include_port) {
                                r = asprintf(&p,
                                             "[%s]:%u",
                                             a,
                                             ntohs(sa->in6.sin6_port));
                                if (r < 0)
                                        return -ENOMEM;
                        } else {
                                p = strdup(a);
                                if (!p)
                                        return -ENOMEM;
                        }
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
                        if (!p)
                                return -ENOMEM;
                }

                break;

        default:
                return -EOPNOTSUPP;
        }


        *ret = p;
        return 0;
}

int getpeername_pretty(int fd, char **ret) {
        union sockaddr_union sa;
        socklen_t salen = sizeof(sa);
        int r;

        assert(fd >= 0);
        assert(ret);

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

        return sockaddr_pretty(&sa.sa, salen, true, true, ret);
}

int getsockname_pretty(int fd, char **ret) {
        union sockaddr_union sa;
        socklen_t salen = sizeof(sa);

        assert(fd >= 0);
        assert(ret);

        if (getsockname(fd, &sa.sa, &salen) < 0)
                return -errno;

        /* For local sockets we do not translate IPv6 addresses back
         * to IPv6 if applicable, since this is usually used for
         * listening sockets where the difference between IPv4 and
         * IPv6 matters. */

        return sockaddr_pretty(&sa.sa, salen, false, true, ret);
}

int socknameinfo_pretty(union sockaddr_union *sa, socklen_t salen, char **_ret) {
        int r;
        char host[NI_MAXHOST], *ret;

        assert(_ret);

        r = getnameinfo(&sa->sa, salen, host, sizeof(host), NULL, 0,
                        NI_IDN|NI_IDN_USE_STD3_ASCII_RULES);
        if (r != 0) {
                int saved_errno = errno;

                r = sockaddr_pretty(&sa->sa, salen, true, true, &ret);
                if (r < 0)
                        return r;

                log_debug_errno(saved_errno, "getnameinfo(%s) failed: %m", ret);
        } else {
                ret = strdup(host);
                if (!ret)
                        return -ENOMEM;
        }

        *_ret = ret;
        return 0;
}

int getnameinfo_pretty(int fd, char **ret) {
        union sockaddr_union sa;
        socklen_t salen = sizeof(sa);

        assert(fd >= 0);
        assert(ret);

        if (getsockname(fd, &sa.sa, &salen) < 0)
                return -errno;

        return socknameinfo_pretty(&sa, salen, ret);
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

bool sockaddr_equal(const union sockaddr_union *a, const union sockaddr_union *b) {
        assert(a);
        assert(b);

        if (a->sa.sa_family != b->sa.sa_family)
                return false;

        if (a->sa.sa_family == AF_INET)
                return a->in.sin_addr.s_addr == b->in.sin_addr.s_addr;

        if (a->sa.sa_family == AF_INET6)
                return memcmp(&a->in6.sin6_addr, &b->in6.sin6_addr, sizeof(a->in6.sin6_addr)) == 0;

        return false;
}

int fd_inc_sndbuf(int fd, size_t n) {
        int r, value;
        socklen_t l = sizeof(value);

        r = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && (size_t) value >= n*2)
                return 0;

        /* If we have the privileges we will ignore the kernel limit. */

        value = (int) n;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &value, sizeof(value)) < 0)
                if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value)) < 0)
                        return -errno;

        return 1;
}

int fd_inc_rcvbuf(int fd, size_t n) {
        int r, value;
        socklen_t l = sizeof(value);

        r = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && (size_t) value >= n*2)
                return 0;

        /* If we have the privileges we will ignore the kernel limit. */

        value = (int) n;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value)) < 0)
                if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value)) < 0)
                        return -errno;
        return 1;
}

static const char* const ip_tos_table[] = {
        [IPTOS_LOWDELAY] = "low-delay",
        [IPTOS_THROUGHPUT] = "throughput",
        [IPTOS_RELIABILITY] = "reliability",
        [IPTOS_LOWCOST] = "low-cost",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(ip_tos, int, 0xff);

int getpeercred(int fd, struct ucred *ucred) {
        socklen_t n = sizeof(struct ucred);
        struct ucred u;
        int r;

        assert(fd >= 0);
        assert(ucred);

        r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &u, &n);
        if (r < 0)
                return -errno;

        if (n != sizeof(struct ucred))
                return -EIO;

        /* Check if the data is actually useful and not suppressed due
         * to namespacing issues */
        if (u.pid <= 0)
                return -ENODATA;
        if (u.uid == UID_INVALID)
                return -ENODATA;
        if (u.gid == GID_INVALID)
                return -ENODATA;

        *ucred = u;
        return 0;
}

int getpeersec(int fd, char **ret) {
        socklen_t n = 64;
        char *s;
        int r;

        assert(fd >= 0);
        assert(ret);

        s = new0(char, n);
        if (!s)
                return -ENOMEM;

        r = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, s, &n);
        if (r < 0) {
                free(s);

                if (errno != ERANGE)
                        return -errno;

                s = new0(char, n);
                if (!s)
                        return -ENOMEM;

                r = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, s, &n);
                if (r < 0) {
                        free(s);
                        return -errno;
                }
        }

        if (isempty(s)) {
                free(s);
                return -EOPNOTSUPP;
        }

        *ret = s;
        return 0;
}

int send_one_fd(int transport_fd, int fd, int flags) {
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;

        assert(transport_fd >= 0);
        assert(fd >= 0);

        cmsg = CMSG_FIRSTHDR(&mh);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

        mh.msg_controllen = CMSG_SPACE(sizeof(int));
        if (sendmsg(transport_fd, &mh, MSG_NOSIGNAL | flags) < 0)
                return -errno;

        return 0;
}

int receive_one_fd(int transport_fd, int flags) {
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg, *found = NULL;

        assert(transport_fd >= 0);

        /*
         * Receive a single FD via @transport_fd. We don't care for
         * the transport-type. We retrieve a single FD at most, so for
         * packet-based transports, the caller must ensure to send
         * only a single FD per packet.  This is best used in
         * combination with send_one_fd().
         */

        if (recvmsg(transport_fd, &mh, MSG_NOSIGNAL | MSG_CMSG_CLOEXEC | flags) < 0)
                return -errno;

        CMSG_FOREACH(cmsg, &mh) {
                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_RIGHTS &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
                        assert(!found);
                        found = cmsg;
                        break;
                }
        }

        if (!found) {
                cmsg_close_all(&mh);
                return -EIO;
        }

        return *(int*) CMSG_DATA(found);
}
