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
        int r;
        char *e, *n;
        unsigned u;

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

                if (!(e = strchr(s+1, ']')))
                        return -EINVAL;

                if (!(n = strndup(s+1, e-s-1)))
                        return -ENOMEM;

                errno = 0;
                if (inet_pton(AF_INET6, n, &a->sockaddr.in6.sin6_addr) <= 0) {
                        free(n);
                        return errno > 0 ? -errno : -EINVAL;
                }

                free(n);

                e++;
                if (*e != ':')
                        return -EINVAL;

                e++;
                if ((r = safe_atou(e, &u)) < 0)
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

                if ((e = strchr(s, ':'))) {

                        if ((r = safe_atou(e+1, &u)) < 0)
                                return r;

                        if (u <= 0 || u > 0xFFFF)
                                return -EINVAL;

                        if (!(n = strndup(s, e-s)))
                                return -ENOMEM;

                        /* IPv4 in w.x.y.z:p notation? */
                        if ((r = inet_pton(AF_INET, n, &a->sockaddr.in4.sin_addr)) < 0) {
                                free(n);
                                return -errno;
                        }

                        if (r > 0) {
                                /* Gotcha, it's a traditional IPv4 address */
                                free(n);

                                a->sockaddr.in4.sin_family = AF_INET;
                                a->sockaddr.in4.sin_port = htons((uint16_t) u);
                                a->size = sizeof(struct sockaddr_in);
                        } else {
                                unsigned idx;

                                if (strlen(n) > IF_NAMESIZE-1) {
                                        free(n);
                                        return -EINVAL;
                                }

                                /* Uh, our last resort, an interface name */
                                idx = if_nametoindex(n);
                                free(n);

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
                                a->sockaddr.in4.sin_family = AF_INET;
                                a->sockaddr.in4.sin_port = htons((uint16_t) u);
                                a->sockaddr.in4.sin_addr.s_addr = INADDR_ANY;
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

                if (a->sockaddr.in4.sin_port == 0)
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
                                if (!(e = memchr(a->sockaddr.un.sun_path, 0, sizeof(a->sockaddr.un.sun_path))))
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

int socket_address_print(const SocketAddress *a, char **p) {
        int r;
        assert(a);
        assert(p);

        if ((r = socket_address_verify(a)) < 0)
                return r;

        switch (socket_address_family(a)) {

        case AF_INET: {
                char *ret;

                if (!(ret = new(char, INET_ADDRSTRLEN+1+5+1)))
                        return -ENOMEM;

                if (!inet_ntop(AF_INET, &a->sockaddr.in4.sin_addr, ret, INET_ADDRSTRLEN)) {
                        free(ret);
                        return -errno;
                }

                sprintf(strchr(ret, 0), ":%u", ntohs(a->sockaddr.in4.sin_port));
                *p = ret;
                return 0;
        }

        case AF_INET6: {
                char *ret;

                if (!(ret = new(char, 1+INET6_ADDRSTRLEN+2+5+1)))
                        return -ENOMEM;

                ret[0] = '[';
                if (!inet_ntop(AF_INET6, &a->sockaddr.in6.sin6_addr, ret+1, INET6_ADDRSTRLEN)) {
                        free(ret);
                        return -errno;
                }

                sprintf(strchr(ret, 0), "]:%u", ntohs(a->sockaddr.in6.sin6_port));
                *p = ret;
                return 0;
        }

        case AF_UNIX: {
                char *ret;

                if (a->size <= offsetof(struct sockaddr_un, sun_path)) {

                        if (!(ret = strdup("<unnamed>")))
                                return -ENOMEM;

                } else if (a->sockaddr.un.sun_path[0] == 0) {
                        /* abstract */

                        /* FIXME: We assume we can print the
                         * socket path here and that it hasn't
                         * more than one NUL byte. That is
                         * actually an invalid assumption */

                        if (!(ret = new(char, sizeof(a->sockaddr.un.sun_path)+1)))
                                return -ENOMEM;

                        ret[0] = '@';
                        memcpy(ret+1, a->sockaddr.un.sun_path+1, sizeof(a->sockaddr.un.sun_path)-1);
                        ret[sizeof(a->sockaddr.un.sun_path)] = 0;

                } else {

                        if (!(ret = strdup(a->sockaddr.un.sun_path)))
                                return -ENOMEM;
                }

                *p = ret;
                return 0;
        }

        case AF_NETLINK: {
                _cleanup_free_ char *sfamily = NULL;

                r = netlink_family_to_string_alloc(a->protocol, &sfamily);
                if (r < 0)
                        return r;
                r = asprintf(p, "%s %u", sfamily, a->sockaddr.nl.nl_groups);
                if (r < 0)
                        return -ENOMEM;

                return 0;
        }

        default:
                return -EINVAL;
        }
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
                if (a->sockaddr.in4.sin_addr.s_addr != b->sockaddr.in4.sin_addr.s_addr)
                        return false;

                if (a->sockaddr.in4.sin_port != b->sockaddr.in4.sin_port)
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
        char *l = 0;
        bool enabled;

        if (access("/sys/module/ipv6", F_OK) != 0)
                return 0;

        /* If we can't check "disable" parameter, assume enabled */
        if (read_one_line_file("/sys/module/ipv6/parameters/disable", &l) < 0)
                return 1;

        /* If module was loaded with disable=1 no IPv6 available */
        enabled = l[0] == '0';
        free(l);

        return enabled;
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
                return sa.in4.sin_port == a->sockaddr.in4.sin_port &&
                        sa.in4.sin_addr.s_addr == a->sockaddr.in4.sin_addr.s_addr;

        case AF_INET6:
                return sa.in6.sin6_port == a->sockaddr.in6.sin6_port &&
                        memcmp(&sa.in6.sin6_addr, &a->sockaddr.in6.sin6_addr, sizeof(struct in6_addr)) == 0;

        case AF_UNIX:
                return salen == a->size &&
                        memcmp(sa.un.sun_path, a->sockaddr.un.sun_path, salen - offsetof(struct sockaddr_un, sun_path)) == 0;

        }

        return false;
}

int make_socket_fd(const char* address, int flags) {
        SocketAddress a;
        int fd, r;
        _cleanup_free_ char *p = NULL;

        r = socket_address_parse(&a, address);
        if (r < 0) {
                log_error("failed to parse socket: %s", strerror(-r));
                return r;
        }

        fd = socket(socket_address_family(&a), flags, 0);
        if (fd < 0) {
                log_error("socket(): %m");
                return -errno;
        }

        r = socket_address_print(&a, &p);
        if (r < 0) {
                log_error("socket_address_print(): %s", strerror(-r));
                return r;
        }
        log_info("Listening on %s", p);

        r = bind(fd, &a.sockaddr.sa, a.size);
        if (r < 0) {
                log_error("bind to %s: %m", address);
                return -errno;
        }

        r = listen(fd, SOMAXCONN);
        if (r < 0) {
                log_error("listen on %s: %m", address);
                return -errno;
        }

        return fd;
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
