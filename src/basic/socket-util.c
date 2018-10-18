/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "utf8.h"
#include "util.h"

#if ENABLE_IDN
#  define IDN_FLAGS NI_IDN
#else
#  define IDN_FLAGS 0
#endif

static const char* const socket_address_type_table[] = {
        [SOCK_STREAM] = "Stream",
        [SOCK_DGRAM] = "Datagram",
        [SOCK_RAW] = "Raw",
        [SOCK_RDM] = "ReliableDatagram",
        [SOCK_SEQPACKET] = "SequentialPacket",
        [SOCK_DCCP] = "DatagramCongestionControl",
};

DEFINE_STRING_TABLE_LOOKUP(socket_address_type, int);

int socket_address_parse(SocketAddress *a, const char *s) {
        _cleanup_free_ char *n = NULL;
        char *e;
        int r;

        assert(a);
        assert(s);

        *a = (SocketAddress) {
                .type = SOCK_STREAM,
        };

        if (*s == '[') {
                uint16_t port;

                /* IPv6 in [x:.....:z]:p notation */

                e = strchr(s+1, ']');
                if (!e)
                        return -EINVAL;

                n = strndup(s+1, e-s-1);
                if (!n)
                        return -ENOMEM;

                errno = 0;
                if (inet_pton(AF_INET6, n, &a->sockaddr.in6.sin6_addr) <= 0)
                        return errno > 0 ? -errno : -EINVAL;

                e++;
                if (*e != ':')
                        return -EINVAL;

                e++;
                r = parse_ip_port(e, &port);
                if (r < 0)
                        return r;

                a->sockaddr.in6.sin6_family = AF_INET6;
                a->sockaddr.in6.sin6_port = htobe16(port);
                a->size = sizeof(struct sockaddr_in6);

        } else if (*s == '/') {
                /* AF_UNIX socket */

                size_t l;

                l = strlen(s);
                if (l >= sizeof(a->sockaddr.un.sun_path)) /* Note that we refuse non-NUL-terminated sockets when
                                                           * parsing (the kernel itself is less strict here in what it
                                                           * accepts) */
                        return -EINVAL;

                a->sockaddr.un.sun_family = AF_UNIX;
                memcpy(a->sockaddr.un.sun_path, s, l);
                a->size = offsetof(struct sockaddr_un, sun_path) + l + 1;

        } else if (*s == '@') {
                /* Abstract AF_UNIX socket */
                size_t l;

                l = strlen(s+1);
                if (l >= sizeof(a->sockaddr.un.sun_path) - 1) /* Note that we refuse non-NUL-terminate sockets here
                                                               * when parsing, even though abstract namespace sockets
                                                               * explicitly allow embedded NUL bytes and don't consider
                                                               * them special. But it's simply annoying to debug such
                                                               * sockets. */
                        return -EINVAL;

                a->sockaddr.un.sun_family = AF_UNIX;
                memcpy(a->sockaddr.un.sun_path+1, s+1, l);
                a->size = offsetof(struct sockaddr_un, sun_path) + 1 + l;

        } else if (startswith(s, "vsock:")) {
                /* AF_VSOCK socket in vsock:cid:port notation */
                const char *cid_start = s + STRLEN("vsock:");
                unsigned port;

                e = strchr(cid_start, ':');
                if (!e)
                        return -EINVAL;

                r = safe_atou(e+1, &port);
                if (r < 0)
                        return r;

                n = strndup(cid_start, e - cid_start);
                if (!n)
                        return -ENOMEM;

                if (!isempty(n)) {
                        r = safe_atou(n, &a->sockaddr.vm.svm_cid);
                        if (r < 0)
                                return r;
                } else
                        a->sockaddr.vm.svm_cid = VMADDR_CID_ANY;

                a->sockaddr.vm.svm_family = AF_VSOCK;
                a->sockaddr.vm.svm_port = port;
                a->size = sizeof(struct sockaddr_vm);

        } else {
                uint16_t port;

                e = strchr(s, ':');
                if (e) {
                        r = parse_ip_port(e + 1, &port);
                        if (r < 0)
                                return r;

                        n = strndup(s, e-s);
                        if (!n)
                                return -ENOMEM;

                        /* IPv4 in w.x.y.z:p notation? */
                        r = inet_pton(AF_INET, n, &a->sockaddr.in.sin_addr);
                        if (r < 0)
                                return -errno;

                        if (r > 0) {
                                /* Gotcha, it's a traditional IPv4 address */
                                a->sockaddr.in.sin_family = AF_INET;
                                a->sockaddr.in.sin_port = htobe16(port);
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
                                a->sockaddr.in6.sin6_port = htobe16(port);
                                a->sockaddr.in6.sin6_scope_id = idx;
                                a->sockaddr.in6.sin6_addr = in6addr_any;
                                a->size = sizeof(struct sockaddr_in6);
                        }
                } else {

                        /* Just a port */
                        r = parse_ip_port(s, &port);
                        if (r < 0)
                                return r;

                        if (socket_ipv6_is_supported()) {
                                a->sockaddr.in6.sin6_family = AF_INET6;
                                a->sockaddr.in6.sin6_port = htobe16(port);
                                a->sockaddr.in6.sin6_addr = in6addr_any;
                                a->size = sizeof(struct sockaddr_in6);
                        } else {
                                a->sockaddr.in.sin_family = AF_INET;
                                a->sockaddr.in.sin_port = htobe16(port);
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

                if (!IN_SET(a->type, SOCK_STREAM, SOCK_DGRAM))
                        return -EINVAL;

                return 0;

        case AF_INET6:
                if (a->size != sizeof(struct sockaddr_in6))
                        return -EINVAL;

                if (a->sockaddr.in6.sin6_port == 0)
                        return -EINVAL;

                if (!IN_SET(a->type, SOCK_STREAM, SOCK_DGRAM))
                        return -EINVAL;

                return 0;

        case AF_UNIX:
                if (a->size < offsetof(struct sockaddr_un, sun_path))
                        return -EINVAL;
                if (a->size > sizeof(struct sockaddr_un)+1) /* Allow one extra byte, since getsockname() on Linux will
                                                             * append a NUL byte if we have path sockets that are above
                                                             * sun_path' full size */
                        return -EINVAL;

                if (a->size > offsetof(struct sockaddr_un, sun_path) &&
                    a->sockaddr.un.sun_path[0] != 0) { /* Only validate file system sockets here */

                        const char *e;

                        e = memchr(a->sockaddr.un.sun_path, 0, sizeof(a->sockaddr.un.sun_path));
                        if (e) {
                                /* If there's an embedded NUL byte, make sure the size of the socket addresses matches it */
                                if (a->size != offsetof(struct sockaddr_un, sun_path) + (e - a->sockaddr.un.sun_path) + 1)
                                        return -EINVAL;
                        } else {
                                /* If there's no embedded NUL byte, then then the size needs to match the whole
                                 * structure or the structure with one extra NUL byte suffixed. (Yeah, Linux is awful,
                                 * and considers both equivalent: getsockname() even extends sockaddr_un beyond its
                                 * size if the path is non NUL terminated.)*/
                                if (!IN_SET(a->size, sizeof(a->sockaddr.un.sun_path), sizeof(a->sockaddr.un.sun_path)+1))
                                        return -EINVAL;
                        }
                }

                if (!IN_SET(a->type, SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET))
                        return -EINVAL;

                return 0;

        case AF_NETLINK:

                if (a->size != sizeof(struct sockaddr_nl))
                        return -EINVAL;

                if (!IN_SET(a->type, SOCK_RAW, SOCK_DGRAM))
                        return -EINVAL;

                return 0;

        case AF_VSOCK:
                if (a->size != sizeof(struct sockaddr_vm))
                        return -EINVAL;

                if (!IN_SET(a->type, SOCK_STREAM, SOCK_DGRAM))
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
                IN_SET(a->type, SOCK_STREAM, SOCK_SEQPACKET);
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
                        if (!path_equal_or_files_same(a->sockaddr.un.sun_path, b->sockaddr.un.sun_path, 0))
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

        case AF_VSOCK:
                if (a->sockaddr.vm.svm_cid != b->sockaddr.vm.svm_cid)
                        return false;

                if (a->sockaddr.vm.svm_port != b->sockaddr.vm.svm_port)
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

        /* Note that this is only safe because we know that there's an extra NUL byte after the sockaddr_un
         * structure. On Linux AF_UNIX file system socket addresses don't have to be NUL terminated if they take up the
         * full sun_path space. */
        assert_cc(sizeof(union sockaddr_union) >= sizeof(struct sockaddr_un)+1);
        return a->sockaddr.un.sun_path;
}

bool socket_ipv6_is_supported(void) {
        if (access("/proc/net/if_inet6", F_OK) != 0)
                return false;

        return true;
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

int sockaddr_port(const struct sockaddr *_sa, unsigned *ret_port) {
        union sockaddr_union *sa = (union sockaddr_union*) _sa;

        /* Note, this returns the port as 'unsigned' rather than 'uint16_t', as AF_VSOCK knows larger ports */

        assert(sa);

        switch (sa->sa.sa_family) {

        case AF_INET:
                *ret_port = be16toh(sa->in.sin_port);
                return 0;

        case AF_INET6:
                *ret_port = be16toh(sa->in6.sin6_port);
                return 0;

        case AF_VSOCK:
                *ret_port = sa->vm.svm_port;
                return 0;

        default:
                return -EAFNOSUPPORT;
        }
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

                a = be32toh(sa->in.sin_addr.s_addr);

                if (include_port)
                        r = asprintf(&p,
                                     "%u.%u.%u.%u:%u",
                                     a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF,
                                     be16toh(sa->in.sin_port));
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
                                             be16toh(sa->in6.sin6_port));
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
                                             be16toh(sa->in6.sin6_port));
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

        case AF_VSOCK:
                if (include_port)
                        r = asprintf(&p,
                                     "vsock:%u:%u",
                                     sa->vm.svm_cid,
                                     sa->vm.svm_port);
                else
                        r = asprintf(&p, "vsock:%u", sa->vm.svm_cid);
                if (r < 0)
                        return -ENOMEM;
                break;

        default:
                return -EOPNOTSUPP;
        }

        *ret = p;
        return 0;
}

int getpeername_pretty(int fd, bool include_port, char **ret) {
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

        return sockaddr_pretty(&sa.sa, salen, true, include_port, ret);
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

        r = getnameinfo(&sa->sa, salen, host, sizeof(host), NULL, 0, IDN_FLAGS);
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
        [NETLINK_ECRYPTFS] = "ecryptfs",
        [NETLINK_RDMA] = "rdma",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(netlink_family, int, INT_MAX);

static const char* const socket_address_bind_ipv6_only_table[_SOCKET_ADDRESS_BIND_IPV6_ONLY_MAX] = {
        [SOCKET_ADDRESS_DEFAULT] = "default",
        [SOCKET_ADDRESS_BOTH] = "both",
        [SOCKET_ADDRESS_IPV6_ONLY] = "ipv6-only"
};

DEFINE_STRING_TABLE_LOOKUP(socket_address_bind_ipv6_only, SocketAddressBindIPv6Only);

SocketAddressBindIPv6Only socket_address_bind_ipv6_only_or_bool_from_string(const char *n) {
        int r;

        r = parse_boolean(n);
        if (r > 0)
                return SOCKET_ADDRESS_IPV6_ONLY;
        if (r == 0)
                return SOCKET_ADDRESS_BOTH;

        return socket_address_bind_ipv6_only_from_string(n);
}

bool sockaddr_equal(const union sockaddr_union *a, const union sockaddr_union *b) {
        assert(a);
        assert(b);

        if (a->sa.sa_family != b->sa.sa_family)
                return false;

        if (a->sa.sa_family == AF_INET)
                return a->in.sin_addr.s_addr == b->in.sin_addr.s_addr;

        if (a->sa.sa_family == AF_INET6)
                return memcmp(&a->in6.sin6_addr, &b->in6.sin6_addr, sizeof(a->in6.sin6_addr)) == 0;

        if (a->sa.sa_family == AF_VSOCK)
                return a->vm.svm_cid == b->vm.svm_cid;

        return false;
}

int fd_inc_sndbuf(int fd, size_t n) {
        int r, value;
        socklen_t l = sizeof(value);

        r = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && (size_t) value >= n*2)
                return 0;

        /* If we have the privileges we will ignore the kernel limit. */

        if (setsockopt_int(fd, SOL_SOCKET, SO_SNDBUF, n) < 0) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_SNDBUFFORCE, n);
                if (r < 0)
                        return r;
        }

        return 1;
}

int fd_inc_rcvbuf(int fd, size_t n) {
        int r, value;
        socklen_t l = sizeof(value);

        r = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && (size_t) value >= n*2)
                return 0;

        /* If we have the privileges we will ignore the kernel limit. */

        if (setsockopt_int(fd, SOL_SOCKET, SO_RCVBUF, n) < 0) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_RCVBUFFORCE, n);
                if (r < 0)
                        return r;
        }

        return 1;
}

static const char* const ip_tos_table[] = {
        [IPTOS_LOWDELAY] = "low-delay",
        [IPTOS_THROUGHPUT] = "throughput",
        [IPTOS_RELIABILITY] = "reliability",
        [IPTOS_LOWCOST] = "low-cost",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(ip_tos, int, 0xff);

bool ifname_valid(const char *p) {
        bool numeric = true;

        /* Checks whether a network interface name is valid. This is inspired by dev_valid_name() in the kernel sources
         * but slightly stricter, as we only allow non-control, non-space ASCII characters in the interface name. We
         * also don't permit names that only container numbers, to avoid confusion with numeric interface indexes. */

        if (isempty(p))
                return false;

        if (strlen(p) >= IFNAMSIZ)
                return false;

        if (dot_or_dot_dot(p))
                return false;

        while (*p) {
                if ((unsigned char) *p >= 127U)
                        return false;

                if ((unsigned char) *p <= 32U)
                        return false;

                if (IN_SET(*p, ':', '/'))
                        return false;

                numeric = numeric && (*p >= '0' && *p <= '9');
                p++;
        }

        if (numeric)
                return false;

        return true;
}

bool address_label_valid(const char *p) {

        if (isempty(p))
                return false;

        if (strlen(p) >= IFNAMSIZ)
                return false;

        while (*p) {
                if ((uint8_t) *p >= 127U)
                        return false;

                if ((uint8_t) *p <= 31U)
                        return false;
                p++;
        }

        return true;
}

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

        /* Check if the data is actually useful and not suppressed due to namespacing issues */
        if (!pid_is_valid(u.pid))
                return -ENODATA;

        /* Note that we don't check UID/GID here, as namespace translation works differently there: instead of
         * receiving in "invalid" user/group we get the overflow UID/GID. */

        *ucred = u;
        return 0;
}

int getpeersec(int fd, char **ret) {
        _cleanup_free_ char *s = NULL;
        socklen_t n = 64;

        assert(fd >= 0);
        assert(ret);

        for (;;) {
                s = new0(char, n+1);
                if (!s)
                        return -ENOMEM;

                if (getsockopt(fd, SOL_SOCKET, SO_PEERSEC, s, &n) >= 0)
                        break;

                if (errno != ERANGE)
                        return -errno;

                s = mfree(s);
        }

        if (isempty(s))
                return -EOPNOTSUPP;

        *ret = TAKE_PTR(s);

        return 0;
}

int getpeergroups(int fd, gid_t **ret) {
        socklen_t n = sizeof(gid_t) * 64;
        _cleanup_free_ gid_t *d = NULL;

        assert(fd >= 0);
        assert(ret);

        for (;;) {
                d = malloc(n);
                if (!d)
                        return -ENOMEM;

                if (getsockopt(fd, SOL_SOCKET, SO_PEERGROUPS, d, &n) >= 0)
                        break;

                if (errno != ERANGE)
                        return -errno;

                d = mfree(d);
        }

        assert_se(n % sizeof(gid_t) == 0);
        n /= sizeof(gid_t);

        if ((socklen_t) (int) n != n)
                return -E2BIG;

        *ret = TAKE_PTR(d);

        return (int) n;
}

ssize_t send_one_fd_iov_sa(
                int transport_fd,
                int fd,
                struct iovec *iov, size_t iovlen,
                const struct sockaddr *sa, socklen_t len,
                int flags) {

        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr mh = {
                .msg_name = (struct sockaddr*) sa,
                .msg_namelen = len,
                .msg_iov = iov,
                .msg_iovlen = iovlen,
        };
        ssize_t k;

        assert(transport_fd >= 0);

        /*
         * We need either an FD or data to send.
         * If there's nothing, return an error.
         */
        if (fd < 0 && !iov)
                return -EINVAL;

        if (fd >= 0) {
                struct cmsghdr *cmsg;

                mh.msg_control = &control;
                mh.msg_controllen = sizeof(control);

                cmsg = CMSG_FIRSTHDR(&mh);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(int));
                memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

                mh.msg_controllen = CMSG_SPACE(sizeof(int));
        }
        k = sendmsg(transport_fd, &mh, MSG_NOSIGNAL | flags);
        if (k < 0)
                return (ssize_t) -errno;

        return k;
}

int send_one_fd_sa(
                int transport_fd,
                int fd,
                const struct sockaddr *sa, socklen_t len,
                int flags) {

        assert(fd >= 0);

        return (int) send_one_fd_iov_sa(transport_fd, fd, NULL, 0, sa, len, flags);
}

ssize_t receive_one_fd_iov(
                int transport_fd,
                struct iovec *iov, size_t iovlen,
                int flags,
                int *ret_fd) {

        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
                .msg_iov = iov,
                .msg_iovlen = iovlen,
        };
        struct cmsghdr *cmsg, *found = NULL;
        ssize_t k;

        assert(transport_fd >= 0);
        assert(ret_fd);

        /*
         * Receive a single FD via @transport_fd. We don't care for
         * the transport-type. We retrieve a single FD at most, so for
         * packet-based transports, the caller must ensure to send
         * only a single FD per packet.  This is best used in
         * combination with send_one_fd().
         */

        k = recvmsg(transport_fd, &mh, MSG_CMSG_CLOEXEC | flags);
        if (k < 0)
                return (ssize_t) -errno;

        CMSG_FOREACH(cmsg, &mh) {
                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_RIGHTS &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
                        assert(!found);
                        found = cmsg;
                        break;
                }
        }

        if (!found)
                cmsg_close_all(&mh);

        /* If didn't receive an FD or any data, return an error. */
        if (k == 0 && !found)
                return -EIO;

        if (found)
                *ret_fd = *(int*) CMSG_DATA(found);
        else
                *ret_fd = -1;

        return k;
}

int receive_one_fd(int transport_fd, int flags) {
        int fd;
        ssize_t k;

        k = receive_one_fd_iov(transport_fd, NULL, 0, flags, &fd);
        if (k == 0)
                return fd;

        /* k must be negative, since receive_one_fd_iov() only returns
         * a positive value if data was received through the iov. */
        assert(k < 0);
        return (int) k;
}

ssize_t next_datagram_size_fd(int fd) {
        ssize_t l;
        int k;

        /* This is a bit like FIONREAD/SIOCINQ, however a bit more powerful. The difference being: recv(MSG_PEEK) will
         * actually cause the next datagram in the queue to be validated regarding checksums, which FIONREAD doesn't
         * do. This difference is actually of major importance as we need to be sure that the size returned here
         * actually matches what we will read with recvmsg() next, as otherwise we might end up allocating a buffer of
         * the wrong size. */

        l = recv(fd, NULL, 0, MSG_PEEK|MSG_TRUNC);
        if (l < 0) {
                if (IN_SET(errno, EOPNOTSUPP, EFAULT))
                        goto fallback;

                return -errno;
        }
        if (l == 0)
                goto fallback;

        return l;

fallback:
        k = 0;

        /* Some sockets (AF_PACKET) do not support null-sized recv() with MSG_TRUNC set, let's fall back to FIONREAD
         * for them. Checksums don't matter for raw sockets anyway, hence this should be fine. */

        if (ioctl(fd, FIONREAD, &k) < 0)
                return -errno;

        return (ssize_t) k;
}

int flush_accept(int fd) {

        struct pollfd pollfd = {
                .fd = fd,
                .events = POLLIN,
        };
        int r;

        /* Similar to flush_fd() but flushes all incoming connection by accepting them and immediately closing them. */

        for (;;) {
                int cfd;

                r = poll(&pollfd, 1, 0);
                if (r < 0) {
                        if (errno == EINTR)
                                continue;

                        return -errno;

                } else if (r == 0)
                        return 0;

                cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
                if (cfd < 0) {
                        if (errno == EINTR)
                                continue;

                        if (errno == EAGAIN)
                                return 0;

                        return -errno;
                }

                close(cfd);
        }
}

struct cmsghdr* cmsg_find(struct msghdr *mh, int level, int type, socklen_t length) {
        struct cmsghdr *cmsg;

        assert(mh);

        CMSG_FOREACH(cmsg, mh)
                if (cmsg->cmsg_level == level &&
                    cmsg->cmsg_type == type &&
                    (length == (socklen_t) -1 || length == cmsg->cmsg_len))
                        return cmsg;

        return NULL;
}

int socket_ioctl_fd(void) {
        int fd;

        /* Create a socket to invoke the various network interface ioctl()s on. Traditionally only AF_INET was good for
         * that. Since kernel 4.6 AF_NETLINK works for this too. We first try to use AF_INET hence, but if that's not
         * available (for example, because it is made unavailable via SECCOMP or such), we'll fall back to the more
         * generic AF_NETLINK. */

        fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_GENERIC);
        if (fd < 0)
                return -errno;

        return fd;
}

int sockaddr_un_unlink(const struct sockaddr_un *sa) {
        const char *p, * nul;

        assert(sa);

        if (sa->sun_family != AF_UNIX)
                return -EPROTOTYPE;

        if (sa->sun_path[0] == 0) /* Nothing to do for abstract sockets */
                return 0;

        /* The path in .sun_path is not necessarily NUL terminated. Let's fix that. */
        nul = memchr(sa->sun_path, 0, sizeof(sa->sun_path));
        if (nul)
                p = sa->sun_path;
        else
                p = memdupa_suffix0(sa->sun_path, sizeof(sa->sun_path));

        if (unlink(p) < 0)
                return -errno;

        return 1;
}

int sockaddr_un_set_path(struct sockaddr_un *ret, const char *path) {
        size_t l;

        assert(ret);
        assert(path);

        /* Initialize ret->sun_path from the specified argument. This will interpret paths starting with '@' as
         * abstract namespace sockets, and those starting with '/' as regular filesystem sockets. It won't accept
         * anything else (i.e. no relative paths), to avoid ambiguities. Note that this function cannot be used to
         * reference paths in the abstract namespace that include NUL bytes in the name. */

        l = strlen(path);
        if (l == 0)
                return -EINVAL;
        if (!IN_SET(path[0], '/', '@'))
                return -EINVAL;
        if (path[1] == 0)
                return -EINVAL;

        /* Don't allow paths larger than the space in sockaddr_un. Note that we are a tiny bit more restrictive than
         * the kernel is: we insist on NUL termination (both for abstract namespace and regular file system socket
         * addresses!), which the kernel doesn't. We do this to reduce chance of incompatibility with other apps that
         * do not expect non-NUL terminated file system path*/
        if (l+1 > sizeof(ret->sun_path))
                return -EINVAL;

        *ret = (struct sockaddr_un) {
                .sun_family = AF_UNIX,
        };

        if (path[0] == '@') {
                /* Abstract namespace socket */
                memcpy(ret->sun_path + 1, path + 1, l); /* copy *with* trailing NUL byte */
                return (int) (offsetof(struct sockaddr_un, sun_path) + l); /* 🔥 *don't* 🔥 include trailing NUL in size */

        } else {
                assert(path[0] == '/');

                /* File system socket */
                memcpy(ret->sun_path, path, l + 1); /* copy *with* trailing NUL byte */
                return (int) (offsetof(struct sockaddr_un, sun_path) + l + 1); /* include trailing NUL in size */
        }
}
