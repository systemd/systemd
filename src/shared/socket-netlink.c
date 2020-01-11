/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <string.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "log.h"
#include "memory-util.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "string-util.h"

int resolve_ifname(sd_netlink **rtnl, const char *name) {
        int r;

        /* Like if_nametoindex, but resolves "alternative names" too. */

        assert(name);

        r = if_nametoindex(name);
        if (r > 0)
                return r;

        return rtnl_resolve_link_alternative_name(rtnl, name);
}

int resolve_interface(sd_netlink **rtnl, const char *name) {
        int r;

        /* Like resolve_ifname, but resolves interface numbers too. */

        assert(name);

        r = parse_ifindex(name);
        if (r > 0)
                return r;
        assert(r < 0);

        return resolve_ifname(rtnl, name);
}

int resolve_interface_or_warn(sd_netlink **rtnl, const char *name) {
        int r;

        r = resolve_interface(rtnl, name);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve interface \"%s\": %m", name);
        return r;
}

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
                        return errno_or_else(EINVAL);

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
                if (l >= sizeof(a->sockaddr.un.sun_path) - 1) /* Note that we refuse non-NUL-terminated sockets here
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
                                int idx;

                                /* Uh, our last resort, an interface name */
                                idx = resolve_ifname(NULL, n);
                                if (idx < 0)
                                        return idx;

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
        _cleanup_free_ char *word = NULL;
        unsigned group = 0;
        int family, r;

        assert(a);
        assert(s);

        zero(*a);
        a->type = SOCK_RAW;

        r = extract_first_word(&s, &word, NULL, 0);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        family = netlink_family_from_string(word);
        if (family < 0)
                return -EINVAL;

        if (!isempty(s)) {
                r = safe_atou(s, &group);
                if (r < 0)
                        return r;
        }

        a->sockaddr.nl.nl_family = AF_NETLINK;
        a->sockaddr.nl.nl_groups = group;

        a->type = SOCK_RAW;
        a->size = sizeof(struct sockaddr_nl);
        a->protocol = family;

        return 0;
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

int make_socket_fd(int log_level, const char* address, int type, int flags) {
        SocketAddress a;
        int fd, r;

        r = socket_address_parse(&a, address);
        if (r < 0)
                return log_error_errno(r, "Failed to parse socket address \"%s\": %m", address);

        a.type = type;

        fd = socket_address_listen(&a, type | flags, SOMAXCONN, SOCKET_ADDRESS_DEFAULT,
                                   NULL, false, false, false, 0755, 0644, NULL);
        if (fd < 0 || log_get_max_level() >= log_level) {
                _cleanup_free_ char *p = NULL;

                r = socket_address_print(&a, &p);
                if (r < 0)
                        return log_error_errno(r, "socket_address_print(): %m");

                if (fd < 0)
                        log_error_errno(fd, "Failed to listen on %s: %m", p);
                else
                        log_full(log_level, "Listening on %s", p);
        }

        return fd;
}

int in_addr_ifindex_from_string_auto(const char *s, int *family, union in_addr_union *ret_addr, int *ret_ifindex) {
        _cleanup_free_ char *buf = NULL;
        const char *suffix;
        int r, ifindex = 0;

        assert(s);
        assert(family);
        assert(ret_addr);

        /* Similar to in_addr_from_string_auto() but also parses an optionally appended IPv6 zone suffix ("scope id")
         * if one is found. */

        suffix = strchr(s, '%');
        if (suffix) {
                if (ret_ifindex) {
                        /* If we shall return the interface index, try to parse it */
                        ifindex = resolve_interface(NULL, suffix + 1);
                        if (ifindex < 0)
                                return ifindex;
                }

                s = buf = strndup(s, suffix - s);
                if (!buf)
                        return -ENOMEM;
        }

        r = in_addr_from_string_auto(s, family, ret_addr);
        if (r < 0)
                return r;

        if (ret_ifindex)
                *ret_ifindex = ifindex;

        return r;
}
