/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/net_namespace.h>
#include <string.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "log.h"
#include "memory-util.h"
#include "namespace-util.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "string-util.h"

int socket_address_parse(SocketAddress *a, const char *s) {
        uint16_t port;
        int r;

        assert(a);
        assert(s);

        r = socket_address_parse_unix(a, s);
        if (r == -EPROTO)
                r = socket_address_parse_vsock(a, s);
        if (r != -EPROTO)
                return r;

        r = parse_ip_port(s, &port);
        if (r == -ERANGE)
                return r; /* Valid port syntax, but the numerical value is wrong for a port. */
        if (r >= 0) {
                /* Just a port */
                if (socket_ipv6_is_supported())
                        *a = (SocketAddress) {
                                .sockaddr.in6 = {
                                        .sin6_family = AF_INET6,
                                        .sin6_port = htobe16(port),
                                        .sin6_addr = in6addr_any,
                                },
                                .size = sizeof(struct sockaddr_in6),
                        };
                else
                        *a = (SocketAddress) {
                                .sockaddr.in = {
                                        .sin_family = AF_INET,
                                        .sin_port = htobe16(port),
                                        .sin_addr.s_addr = INADDR_ANY,
                                },
                                .size = sizeof(struct sockaddr_in),
                        };

        } else {
                union in_addr_union address;
                int family, ifindex;

                r = in_addr_port_ifindex_name_from_string_auto(s, &family, &address, &port, &ifindex, NULL);
                if (r < 0)
                        return r;

                if (port == 0) /* No port, no go. */
                        return -EINVAL;

                if (family == AF_INET)
                        *a = (SocketAddress) {
                                .sockaddr.in = {
                                        .sin_family = AF_INET,
                                        .sin_addr = address.in,
                                        .sin_port = htobe16(port),
                                },
                                .size = sizeof(struct sockaddr_in),
                        };
                else if (family == AF_INET6)
                        *a = (SocketAddress) {
                                .sockaddr.in6 = {
                                        .sin6_family = AF_INET6,
                                        .sin6_addr = address.in6,
                                        .sin6_port = htobe16(port),
                                        .sin6_scope_id = ifindex,
                                },
                                .size = sizeof(struct sockaddr_in6),
                        };
                else
                        assert_not_reached();
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

        *a = (SocketAddress) {
                .type = SOCK_RAW,
                .sockaddr.nl.nl_family = AF_NETLINK,
                .sockaddr.nl.nl_groups = group,
                .protocol = family,
                .size = sizeof(struct sockaddr_nl),
        };

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

        fd = socket_address_listen(&a, type | flags, SOMAXCONN_DELUXE, SOCKET_ADDRESS_DEFAULT,
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

int in_addr_port_ifindex_name_from_string_auto(
                const char *s,
                int *ret_family,
                union in_addr_union *ret_address,
                uint16_t *ret_port,
                int *ret_ifindex,
                char **ret_server_name) {

        _cleanup_free_ char *buf1 = NULL, *buf2 = NULL, *name = NULL;
        int family, ifindex = 0, r;
        union in_addr_union a;
        uint16_t port = 0;
        const char *m;

        assert(s);

        /* This accepts the following:
         * 192.168.0.1:53#example.com
         * [2001:4860:4860::8888]:53%eth0#example.com
         *
         * If ret_port is NULL, then the port cannot be specified.
         * If ret_ifindex is NULL, then the interface index cannot be specified.
         * If ret_server_name is NULL, then server_name cannot be specified.
         *
         * ret_family is always AF_INET or AF_INET6.
         */

        m = strchr(s, '#');
        if (m) {
                if (!ret_server_name)
                        return -EINVAL;

                if (isempty(m + 1))
                        return -EINVAL;

                name = strdup(m + 1);
                if (!name)
                        return -ENOMEM;

                s = buf1 = strndup(s, m - s);
                if (!buf1)
                        return -ENOMEM;
        }

        m = strchr(s, '%');
        if (m) {
                if (!ret_ifindex)
                        return -EINVAL;

                if (isempty(m + 1))
                        return -EINVAL;

                if (!ifname_valid_full(m + 1, IFNAME_VALID_ALTERNATIVE | IFNAME_VALID_NUMERIC))
                        return -EINVAL; /* We want to return -EINVAL for syntactically invalid names,
                                         * and -ENODEV for valid but nonexistent interfaces. */

                ifindex = rtnl_resolve_interface(NULL, m + 1);
                if (ifindex < 0)
                        return ifindex;

                s = buf2 = strndup(s, m - s);
                if (!buf2)
                        return -ENOMEM;
        }

        m = strrchr(s, ':');
        if (m) {
                if (*s == '[') {
                        _cleanup_free_ char *ip_str = NULL;

                        if (!ret_port)
                                return -EINVAL;

                        if (*(m - 1) != ']')
                                return -EINVAL;

                        family = AF_INET6;

                        r = parse_ip_port(m + 1, &port);
                        if (r < 0)
                                return r;

                        ip_str = strndup(s + 1, m - s - 2);
                        if (!ip_str)
                                return -ENOMEM;

                        r = in_addr_from_string(family, ip_str, &a);
                        if (r < 0)
                                return r;
                } else {
                        /* First try to parse the string as IPv6 address without port number */
                        r = in_addr_from_string(AF_INET6, s, &a);
                        if (r < 0) {
                                /* Then the input should be IPv4 address with port number */
                                _cleanup_free_ char *ip_str = NULL;

                                if (!ret_port)
                                        return -EINVAL;

                                family = AF_INET;

                                ip_str = strndup(s, m - s);
                                if (!ip_str)
                                        return -ENOMEM;

                                r = in_addr_from_string(family, ip_str, &a);
                                if (r < 0)
                                        return r;

                                r = parse_ip_port(m + 1, &port);
                                if (r < 0)
                                        return r;
                        } else
                                family = AF_INET6;
                }
        } else {
                family = AF_INET;
                r = in_addr_from_string(family, s, &a);
                if (r < 0)
                        return r;
        }

        if (ret_family)
                *ret_family = family;
        if (ret_address)
                *ret_address = a;
        if (ret_port)
                *ret_port = port;
        if (ret_ifindex)
                *ret_ifindex = ifindex;
        if (ret_server_name)
                *ret_server_name = TAKE_PTR(name);

        return r;
}

struct in_addr_full *in_addr_full_free(struct in_addr_full *a) {
        if (!a)
                return NULL;

        free(a->server_name);
        free(a->cached_server_string);
        return mfree(a);
}

void in_addr_full_array_free(struct in_addr_full *addrs[], size_t n) {
        assert(addrs || n == 0);

        FOREACH_ARRAY(a, addrs, n)
                in_addr_full_freep(a);

        free(addrs);
}

int in_addr_full_new(
                int family,
                const union in_addr_union *a,
                uint16_t port,
                int ifindex,
                const char *server_name,
                struct in_addr_full **ret) {

        _cleanup_free_ char *name = NULL;
        struct in_addr_full *x;

        assert(ret);

        if (!isempty(server_name)) {
                name = strdup(server_name);
                if (!name)
                        return -ENOMEM;
        }

        x = new(struct in_addr_full, 1);
        if (!x)
                return -ENOMEM;

        *x = (struct in_addr_full) {
                .family = family,
                .address = *a,
                .port = port,
                .ifindex = ifindex,
                .server_name = TAKE_PTR(name),
        };

        *ret = x;
        return 0;
}

int in_addr_full_new_from_string(const char *s, struct in_addr_full **ret) {
        _cleanup_free_ char *server_name = NULL;
        int family, ifindex, r;
        union in_addr_union a;
        uint16_t port;

        assert(s);

        r = in_addr_port_ifindex_name_from_string_auto(s, &family, &a, &port, &ifindex, &server_name);
        if (r < 0)
                return r;

        return in_addr_full_new(family, &a, port, ifindex, server_name, ret);
}

const char* in_addr_full_to_string(struct in_addr_full *a) {
        assert(a);

        if (!a->cached_server_string)
                (void) in_addr_port_ifindex_name_to_string(
                                a->family,
                                &a->address,
                                a->port,
                                a->ifindex,
                                a->server_name,
                                &a->cached_server_string);

        return a->cached_server_string;
}

int netns_get_nsid(int netnsfd, uint32_t *ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_close_ int _netns_fd = -EBADF;
        int r;

        if (netnsfd < 0) {
                _netns_fd = namespace_open_by_type(NAMESPACE_NET);
                if (_netns_fd < 0)
                        return _netns_fd;

                netnsfd = _netns_fd;
        }

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return r;

        r = sd_rtnl_message_new_nsid(rtnl, &req, RTM_GETNSID);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_s32(req, NETNSA_FD, netnsfd);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *m = reply; m; m = sd_netlink_message_next(m)) {
                uint16_t type;

                r = sd_netlink_message_get_errno(m);
                if (r < 0)
                        return r;

                r = sd_netlink_message_get_type(m, &type);
                if (r < 0)
                        return r;
                if (type != RTM_NEWNSID)
                        continue;

                uint32_t u;
                r = sd_netlink_message_read_u32(m, NETNSA_NSID, &u);
                if (r < 0)
                        return r;

                if (u == (uint32_t) NETNSA_NSID_NOT_ASSIGNED) /* no NSID assigned yet */
                        return -ENODATA;

                if (ret)
                        *ret = u;

                return 0;
        }

        return -ENXIO;
}
