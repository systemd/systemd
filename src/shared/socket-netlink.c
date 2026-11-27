/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/net_namespace.h>
#include <linux/unix_diag.h>
#include <string.h>
#include <sys/stat.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "env-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "log.h"
#include "namespace-util.h"
#include "netlink-sock-diag.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "socket-label.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "web-util.h"

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

                r = in_addr_port_ifindex_name_from_string_auto(s, &family, &address, &port, &ifindex, /* ret_server_name= */ NULL);
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

        assert(a);

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

        r = extract_first_word(&s, &word, /* separators= */ NULL, /* flags= */ 0);
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

        fd = socket_address_listen(
                        &a,
                        type | flags,
                        SOMAXCONN_DELUXE, SOCKET_ADDRESS_DEFAULT,
                        /* bind_to_device= */ NULL,
                        /* reuse_port= */ false,
                        /* free_bind= */ false,
                        /* transparent= */ false,
                        0755,
                        0644,
                        /* selinux_label= */ NULL,
                        /* smack_label= */ NULL,
                        /* xattr_entrypoint= */ NULL,
                        /* xattr_listen= */ NULL);
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

                ifindex = rtnl_resolve_interface(/* rtnl= */ NULL, m + 1);
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

struct in_addr_full* in_addr_full_free(struct in_addr_full *a) {
        if (!a)
                return NULL;

        free(a->server_name);
        free(a->scheme);
        free(a->path);
        free(a->query);
        strv_free(a->params);
        free(a->cached_server_string);
        return mfree(a);
}

DEFINE_POINTER_ARRAY_FREE_FUNC(struct in_addr_full*, in_addr_full_free);

int in_addr_full_new(
                int family,
                const union in_addr_union *a,
                uint16_t port,
                int ifindex,
                const char *server_name,
                struct in_addr_full **ret) {

        _cleanup_free_ char *name = NULL;
        struct in_addr_full *x;

        assert(a);
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

        /* Accepts both the "address[:port][%ifname][#name]" form and the URI form, see
         * in_addr_full_new_from_uri() */

        r = in_addr_full_new_from_uri(s, ret);
        if (r != -EPROTONOSUPPORT)
                return r;

        r = in_addr_port_ifindex_name_from_string_auto(s, &family, &a, &port, &ifindex, &server_name);
        if (r < 0)
                return r;

        return in_addr_full_new(family, &a, port, ifindex, server_name, ret);
}

/* Like strstrafter(), but also terminates haystack where needle started. Returns NULL, leaving haystack
 * untouched, if needle is not found. */
static char* strstrafter_truncate(char *haystack, const char *needle) {
        char *p = strstrafter(haystack, needle);
        if (!p)
                return NULL;

        p[-strlen(needle)] = '\0';
        return p;
}

int in_addr_full_new_from_uri(const char *s, struct in_addr_full **ret) {
        _cleanup_(in_addr_full_freep) struct in_addr_full *a = NULL;
        _cleanup_free_ char *buf = NULL;
        char *authority, *path, *query, *fragment;
        const char *ifname;
        size_t n;
        int r;

        assert(s);
        assert(ret);

        /* Parses RFC 3986 "scheme://authority[/path][?query][#key[=value]&...]". The authority is an address
         * as accepted by in_addr_port_ifindex_name_from_string_auto(), without '%' and '#', with IPv6
         * addresses optionally in brackets also when no port is given. The fragment holds client-side
         * parameters: name= sets the server name, ifname= the interface, and all others are kept in
         * ->params, for the caller to check against the scheme. A key without '=' reads as an empty value.
         *
         * Returns -EPROTONOSUPPORT if s is not in URI form, so that callers can fall back to
         * in_addr_full_new_from_string(). */

        buf = strdup(s);
        if (!buf)
                return -ENOMEM;

        /* Cut from the right: only the fragment may contain '?', and only the fragment and query '/'. */
        fragment = strstrafter_truncate(buf, "#");
        query = strstrafter_truncate(buf, "?");
        authority = strstrafter_truncate(buf, "://");
        if (!authority)
                return -EPROTONOSUPPORT;
        path = strstrafter_truncate(authority, "/");

        if (!url_scheme_is_valid(ascii_strlower(buf)))
                return -EINVAL;

        a = new0(struct in_addr_full, 1);
        if (!a)
                return -ENOMEM;

        /* "[2001:db8::1]" without a port is valid in a URI, but not for the address parser. */
        n = strlen(authority);
        if (n > 2 && authority[0] == '[' && authority[n - 1] == ']') {
                authority[n - 1] = '\0';
                authority++;
                a->family = AF_INET6;
                r = in_addr_from_string(AF_INET6, authority, &a->address);
        } else
                r = in_addr_port_ifindex_name_from_string_auto(authority, &a->family, &a->address, &a->port,
                                                                /* ret_ifindex= */ NULL, /* ret_server_name= */ NULL);
        if (r < 0)
                return r;

        if (fragment) {
                a->params = strv_split(fragment, "&");
                if (!a->params)
                        return -ENOMEM;

                STRV_FOREACH(p, a->params)
                        if (!strchr(*p, '=') && !strextend(p, "="))
                                return -ENOMEM;

                if (!strv_env_is_valid(a->params))
                        return -EINVAL;
        }

        ifname = strv_env_get(a->params, "ifname");
        if (ifname) {
                if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE | IFNAME_VALID_NUMERIC))
                        return -EINVAL;

                a->ifindex = rtnl_resolve_interface(/* rtnl= */ NULL, ifname);
                if (a->ifindex < 0)
                        return a->ifindex;
        }

        if (strdup_to(&a->scheme, buf) < 0 ||
            strdup_to(&a->path, empty_to_null(path)) < 0 ||
            strdup_to(&a->query, query) < 0 ||
            strdup_to(&a->server_name, empty_to_null(strv_env_get(a->params, "name"))) < 0)
                return -ENOMEM;

        strv_env_unset(a->params, "name");
        strv_env_unset(a->params, "ifname");
        if (strv_isempty(a->params))
                a->params = strv_free(a->params);

        *ret = TAKE_PTR(a);
        return 0;
}

static int in_addr_full_to_uri(const struct in_addr_full *a, char **ret) {
        _cleanup_free_ char *addr = NULL, *s = NULL;
        bool first = true;
        int r;

        assert(a);
        assert(a->scheme);
        assert(ret);

        r = in_addr_to_string(a->family, &a->address, &addr);
        if (r < 0)
                return r;

        if (asprintf(&s, "%s://%s%s%s", a->scheme,
                     a->family == AF_INET6 ? "[" : "", addr, a->family == AF_INET6 ? "]" : "") < 0)
                return -ENOMEM;

        if (a->port != 0 && strextendf(&s, ":%" PRIu16, a->port) < 0)
                return -ENOMEM;

        if (!strextend(&s, a->path ? "/" : "", strempty(a->path), a->query ? "?" : "", strempty(a->query)))
                return -ENOMEM;

        /* name= and ifname= first, then the other parameters in the order they were given. A parameter with
         * an empty value is written as a bare key. */
        if (a->server_name) {
                if (!strextend(&s, "#name=", a->server_name))
                        return -ENOMEM;
                first = false;
        }

        if (a->ifindex > 0) {
                if (strextendf(&s, "%sifname=%i", first ? "#" : "&", a->ifindex) < 0)
                        return -ENOMEM;
                first = false;
        }

        STRV_FOREACH(p, a->params) {
                size_t k = strcspn(*p, "=");

                if (strextendf(&s, "%s%.*s%s", first ? "#" : "&", (int) k, *p, isempty(*p + k + 1) ? "" : *p + k) < 0)
                        return -ENOMEM;
                first = false;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

const char* in_addr_full_to_string(struct in_addr_full *a) {
        assert(a);

        if (!a->cached_server_string && a->scheme)
                (void) in_addr_full_to_uri(a, &a->cached_server_string);

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

        r = sd_netlink_call(rtnl, req, /* timeout= */ 0, &reply);
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

int af_unix_get_qlen(int fd, uint32_t *ret) {
        int r;

        assert(fd >= 0);
        assert(ret);

        /* Returns the current queue length for an AF_UNIX listening socket */

        struct stat st;
        if (fstat(fd, &st) < 0)
                return -errno;
        r = stat_verify_socket(&st);
        if (r < 0)
                return r;

        _cleanup_(sd_netlink_unrefp) sd_netlink *nl = NULL;
        r = sd_sock_diag_socket_open(&nl);
        if (r < 0)
                return r;

        uint64_t cookie;
        r = socket_get_cookie(fd, &cookie);
        if (r < 0)
                return r;

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        r = sd_sock_diag_message_new_unix(nl, &message, st.st_ino, cookie, UDIAG_SHOW_RQLEN);
        if (r < 0)
                return r;

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *reply = NULL;
        r = sd_netlink_call(nl, message, /* timeout= */ 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *m = reply; m; m = sd_netlink_message_next(m)) {
                r = sd_netlink_message_get_errno(m);
                if (r < 0)
                        return r;

                _cleanup_free_ void *data = NULL;
                size_t size = 0;

                r = sd_netlink_message_read_data(m, UNIX_DIAG_RQLEN, &size, &data);
                if (r == -ENODATA)
                        continue;
                if (r < 0)
                        return r;

                assert(size == sizeof(struct unix_diag_rqlen));
                const struct unix_diag_rqlen *udrql = ASSERT_PTR(data);

                *ret = udrql->udiag_rqueue;
                return 0;
        }

        return -ENODATA;
}
