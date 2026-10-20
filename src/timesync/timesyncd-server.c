/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dns-domain.h"
#include "in-addr-util.h"
#include "log.h"
#include "parse-util.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "timesyncd-manager.h"
#include "timesyncd-server.h"

static const char * const server_type_table[_SERVER_TYPE_MAX] = {
        [SERVER_SYSTEM]   = "system",
        [SERVER_FALLBACK] = "fallback",
        [SERVER_LINK]     = "link",
        [SERVER_RUNTIME]  = "runtime",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(server_type, ServerType);

int server_address_new(
                ServerName *n,
                ServerAddress **ret,
                const union sockaddr_union *sockaddr,
                socklen_t socklen) {

        ServerAddress *a, *tail;

        assert(n);
        assert(sockaddr);
        assert(socklen >= offsetof(struct sockaddr, sa_data));
        assert(socklen <= sizeof(union sockaddr_union));

        a = new(ServerAddress, 1);
        if (!a)
                return -ENOMEM;

        *a = (ServerAddress) {
                .name = n,
                .socklen = socklen,
        };

        memcpy(&a->sockaddr, sockaddr, socklen);

        tail = LIST_FIND_TAIL(addresses, n->addresses);
        LIST_INSERT_AFTER(addresses, n->addresses, tail, a);

        if (ret)
                *ret = a;

        return 0;
}

ServerAddress* server_address_free(ServerAddress *a) {
        if (!a)
                return NULL;

        if (a->name) {
                LIST_REMOVE(addresses, a->name->addresses, a);

                if (a->name->manager && a->name->manager->current_server_address == a)
                        manager_set_server_address(a->name->manager, NULL);
        }

        return mfree(a);
}

static int enable_ntp_server_defer_event(Manager *m, ServerType type) {
        int r;

        assert(m);
        assert((type >= 0) && (type < _SERVER_TYPE_MAX));

        m->ntp_server_change_mask |= 1U << type;

        r = bus_manager_emit_ntp_server_changed(m);
        if (r < 0)
                return r;

        return 1;
}

static int server_name_format(const char *host, uint16_t port, char **ret) {
        char port_str[DECIMAL_STR_MAX(uint16_t)];
        char *x;

        assert(host);
        assert(port > 0);
        assert(ret);

        /* If the default NTP port is used, it is not shown. */

        if (port == DEFAULT_NTP_PORT)
                return strdup_to(ret, host);

        xsprintf(port_str, "%" PRIu16, port);

        /* Append the port number. Square brackets are used for IPv6 addresses, to keep the result
         * unambiguous. */

        if (strchr(host, ':')) {
                _cleanup_free_ char *address = NULL;
                const char *zone = strchr(host, '%');

                if (zone) {
                        address = strndup(host, zone - host);
                        if (!address)
                                return -ENOMEM;
                }

                x = strjoin("[", address ?: host, "]:", port_str, zone);
        } else
                x = strjoin(host, ":", port_str);
        if (!x)
                return -ENOMEM;

        *ret = x;
        return 0;
}

int server_name_parse(const char *s, char **ret_host, uint16_t *ret_port) {
        _cleanup_free_ char *host = NULL;
        union in_addr_union address;
        uint16_t port = DEFAULT_NTP_PORT;
        int family, r;

        assert(s);

        if (isempty(s))
                return -EINVAL;

        /* Handle an optional interface zone suffix, such as "fe80::1%eth0". The zone is kept around
         * verbatim and resolved only when the name is looked up, since the interface might not exist
         * yet when the configuration is parsed (e.g. at early boot). */
        const char *zone = strrchr(s, '%');
        if (zone) {
                _cleanup_free_ char *address_string = NULL, *no_zone = NULL, *zone_string = NULL;

                no_zone = strndup(s, zone - s);
                if (!no_zone)
                        return -ENOMEM;

                zone_string = strdup(zone + 1);
                if (!zone_string)
                        return -ENOMEM;

                /* Accept both [address%zone]:port and [address]:port%zone. */
                char *end = strstr(zone_string, "]:");
                if (end) {
                        *end = 0;
                        if (!strextend(&no_zone, "]:", end + 2))
                                return -ENOMEM;
                }

                if (!ifname_valid_full(zone_string, IFNAME_VALID_ALTERNATIVE | IFNAME_VALID_NUMERIC) ||
                    strpbrk(zone_string, "[]#"))
                        return -EINVAL;

                r = in_addr_port_ifindex_name_from_string_auto(no_zone, &family, &address, &port,
                                                              /* ret_ifindex= */ NULL, /* ret_server_name= */ NULL);
                if (r < 0)
                        return r == -ENOMEM ? r : -EINVAL;

                if (family != AF_INET6)
                        return -EINVAL;

                r = in_addr_to_string(family, &address, &address_string);
                if (r < 0)
                        return r;

                host = strjoin(address_string, "%", zone_string);
                if (!host)
                        return -ENOMEM;

                if (port == 0)
                        port = DEFAULT_NTP_PORT;
        } else {
                r = in_addr_port_ifindex_name_from_string_auto(s, &family, &address, &port,
                                                              /* ret_ifindex= */ NULL, /* ret_server_name= */ NULL);
                if (r == -ENOMEM)
                        return r;
                if (r >= 0) {
                        /* An IP address, optionally with a port number. Note that
                         * in_addr_port_ifindex_name_from_string_auto() returns port 0 when no port
                         * number was specified. */

                        if (port == 0)
                                port = DEFAULT_NTP_PORT;

                        r = in_addr_to_string(family, &address, &host);
                        if (r < 0)
                                return r;
                } else {
                        const char *colon;

                        /* Not an IP address, hence this must be a DNS name, optionally followed by a
                         * port number. */

                        colon = strchr(s, ':');
                        if (colon) {
                                /* We already know this is not a valid IPv6 address, hence this must be
                                 * a "hostname:port" specification. More than one colon is thus not
                                 * allowed, and neither are square brackets (which are used only for
                                 * IPv6 addresses). */
                                if (strchr(colon + 1, ':') || strchr(s, '[') || strchr(s, ']'))
                                        return -EINVAL;

                                host = strndup(s, colon - s);
                                if (!host)
                                        return -ENOMEM;

                                if (isempty(host))
                                        return -EINVAL;

                                r = dns_name_is_valid(host);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        return -EINVAL;

                                r = parse_ip_port(colon + 1, &port);
                                if (r < 0)
                                        return -EINVAL;
                        } else {
                                if (strchr(s, '[') || strchr(s, ']'))
                                        return -EINVAL;

                                r = dns_name_is_valid(s);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        return -EINVAL;

                                host = strdup(s);
                                if (!host)
                                        return -ENOMEM;
                        }
                }
        }

        if (ret_host)
                *ret_host = TAKE_PTR(host);
        if (ret_port)
                *ret_port = port;

        return 0;
}

int server_name_new(
                Manager *m,
                ServerName **ret,
                ServerType type,
                const char *host,
                uint16_t port) {

        _cleanup_free_ char *string = NULL, *h = NULL;
        int r;
        ServerName *n;

        assert(m);
        assert(host);
        assert(port > 0);

        r = server_name_format(host, port, &string);
        if (r < 0)
                return r;

        h = strdup(host);
        if (!h)
                return -ENOMEM;

        n = new(ServerName, 1);
        if (!n)
                return -ENOMEM;

        *n = (ServerName) {
                .manager = m,
                .type = type,
                .string = TAKE_PTR(string),
                .host = TAKE_PTR(h),
                .port = port,
        };

        switch (type) {
        case SERVER_SYSTEM:
                LIST_APPEND(names, m->system_servers, n);
                break;
        case SERVER_LINK:
                LIST_APPEND(names, m->link_servers, n);
                break;
        case SERVER_FALLBACK:
                LIST_APPEND(names, m->fallback_servers, n);
                break;
        case SERVER_RUNTIME:
                LIST_APPEND(names, m->runtime_servers, n);
                break;
        default:
                assert_not_reached();
        }

        r = enable_ntp_server_defer_event(m, type);
        if (r < 0)
                log_debug_errno(r, "Failed to enable ntp server defer event, ignoring: %m");

        if (type != SERVER_FALLBACK &&
            m->current_server_name &&
            m->current_server_name->type == SERVER_FALLBACK)
                manager_set_server_name(m, NULL);

        log_debug("Added new %s server %s.", server_type_to_string(type), n->string);

        if (ret)
                *ret = n;

        return 0;
}

ServerName *server_name_free(ServerName *n) {
        int r;

        if (!n)
                return NULL;

        server_name_flush_addresses(n);

        if (n->manager) {
                if (n->type == SERVER_SYSTEM)
                        LIST_REMOVE(names, n->manager->system_servers, n);
                else if (n->type == SERVER_LINK)
                        LIST_REMOVE(names, n->manager->link_servers, n);
                else if (n->type == SERVER_FALLBACK)
                        LIST_REMOVE(names, n->manager->fallback_servers, n);
                else if (n->type == SERVER_RUNTIME)
                        LIST_REMOVE(names, n->manager->runtime_servers, n);
                else
                        assert_not_reached();

                r = enable_ntp_server_defer_event(n->manager, n->type);
                if (r < 0)
                        log_debug_errno(r, "Failed to enable ntp server defer event, ignoring: %m");

                if (n->manager->current_server_name == n)
                        manager_set_server_name(n->manager, NULL);
        }

        log_debug("Removed server %s.", n->string);

        free(n->string);
        free(n->host);
        return mfree(n);
}

void server_name_flush_addresses(ServerName *n) {
        assert(n);

        while (n->addresses)
                server_address_free(n->addresses);
}
