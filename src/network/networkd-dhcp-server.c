/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if_arp.h>
#include <linux/if.h>

#include "sd-dhcp-server.h"

#include "fd-util.h"
#include "fileio.h"
#include "networkd-address.h"
#include "networkd-dhcp-server.h"
#include "networkd-dhcp-server-bus.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "parse-util.h"
#include "socket-netlink.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

static bool link_dhcp4_server_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->network->bond)
                return false;

        if (link->iftype == ARPHRD_CAN)
                return false;

        return link->network->dhcp_server;
}

static Address* link_find_dhcp_server_address(Link *link) {
        Address *address;

        assert(link);
        assert(link->network);

        /* The first statically configured address if there is any */
        ORDERED_HASHMAP_FOREACH(address, link->network->addresses_by_section)
                if (address->family == AF_INET &&
                    in_addr_is_set(address->family, &address->in_addr))
                        return address;

        /* If that didn't work, find a suitable address we got from the pool */
        SET_FOREACH(address, link->pool_addresses)
                if (address->family == AF_INET)
                        return address;

        return NULL;
}

static int link_push_uplink_to_dhcp_server(
                Link *link,
                sd_dhcp_lease_server_type_t what,
                sd_dhcp_server *s) {

        _cleanup_free_ struct in_addr *addresses = NULL;
        size_t n_addresses = 0, n_allocated = 0;
        bool use_dhcp_lease_data = true;

        assert(link);

        if (!link->network)
                return 0;
        assert(link->network);

        log_link_debug(link, "Copying %s from link", dhcp_lease_server_type_to_string(what));

        switch (what) {

        case SD_DHCP_LEASE_DNS:
                /* For DNS we have a special case. We the data configured explicitly locally along with the
                 * data from the DHCP lease. */

                for (unsigned i = 0; i < link->network->n_dns; i++) {
                        struct in_addr ia;

                        /* Only look for IPv4 addresses */
                        if (link->network->dns[i]->family != AF_INET)
                                continue;

                        ia = link->network->dns[i]->address.in;

                        /* Never propagate obviously borked data */
                        if (in4_addr_is_null(&ia) || in4_addr_is_localhost(&ia))
                                continue;

                        if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + 1))
                                return log_oom();

                        addresses[n_addresses++] = ia;
                }

                use_dhcp_lease_data = link->network->dhcp_use_dns;
                break;

        case SD_DHCP_LEASE_NTP: {
                char **i;

                /* For NTP things are similar, but for NTP hostnames can be configured too, which we cannot
                 * propagate via DHCP. Hence let's only propagate those which are IP addresses. */

                STRV_FOREACH(i, link->network->ntp) {
                        union in_addr_union ia;

                        if (in_addr_from_string(AF_INET, *i, &ia) < 0)
                                continue;

                        /* Never propagate obviously borked data */
                        if (in4_addr_is_null(&ia.in) || in4_addr_is_localhost(&ia.in))
                                continue;

                        if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + 1))
                                return log_oom();

                        addresses[n_addresses++] = ia.in;
                }

                use_dhcp_lease_data = link->network->dhcp_use_ntp;
                break;
        }

        case SD_DHCP_LEASE_SIP:

                /* For SIP we don't allow explicit, local configuration, but there's control whether to use the data */
                use_dhcp_lease_data = link->network->dhcp_use_sip;
                break;

        case SD_DHCP_LEASE_POP3:
        case SD_DHCP_LEASE_SMTP:
        case SD_DHCP_LEASE_LPR:
                /* For the other server types we currently do not allow local configuration of server data,
                 * since there are typically no local consumers of the data. */
                break;

        default:
                assert_not_reached("Unexpected server type");
        }

        if (use_dhcp_lease_data && link->dhcp_lease) {
                const struct in_addr *da;

                int n = sd_dhcp_lease_get_servers(link->dhcp_lease, what, &da);
                if (n > 0) {
                        if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + n))
                                return log_oom();

                        for (int j = 0; j < n; j++)
                                if (in4_addr_is_non_local(&da[j]))
                                        addresses[n_addresses++] = da[j];
                }
        }

        if (n_addresses <= 0)
                return 0;

        return sd_dhcp_server_set_servers(s, what, addresses, n_addresses);
}

static int dhcp4_server_parse_dns_server_string_and_warn(Link *l, const char *string, struct in_addr **addresses, size_t *n_allocated, size_t *n_addresses) {
        for (;;) {
                _cleanup_free_ char *word = NULL, *server_name = NULL;
                union in_addr_union address;
                int family, r, ifindex = 0;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = in_addr_ifindex_name_from_string_auto(word, &family, &address, &ifindex, &server_name);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse DNS server address '%s', ignoring: %m", word);
                        continue;
                }

                /* Only look for IPv4 addresses */
                if (family != AF_INET)
                        continue;

                /* Never propagate obviously borked data */
                if (in4_addr_is_null(&address.in) || in4_addr_is_localhost(&address.in))
                        continue;

                if (!GREEDY_REALLOC(*addresses, *n_allocated, *n_addresses + 1))
                        return log_oom();

                (*addresses)[(*n_addresses)++] = address.in;
        }

        return 0;
}

static int dhcp4_server_set_dns_from_resolve_conf(Link *link) {
        _cleanup_free_ struct in_addr *addresses = NULL;
        size_t n_addresses = 0, n_allocated = 0;
        _cleanup_fclose_ FILE *f = NULL;
        int n = 0, r;

        f = fopen(PRIVATE_UPLINK_RESOLV_CONF, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to open " PRIVATE_UPLINK_RESOLV_CONF ": %m");
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *a;
                char *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read " PRIVATE_UPLINK_RESOLV_CONF ": %m");
                if (r == 0)
                        break;

                n++;

                l = strstrip(line);
                if (IN_SET(*l, '#', ';', 0))
                        continue;

                a = first_word(l, "nameserver");
                if (!a)
                        continue;

                r = dhcp4_server_parse_dns_server_string_and_warn(link, a, &addresses, &n_allocated, &n_addresses);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse DNS server address '%s', ignoring.", a);
        }

        if (n_addresses <= 0)
                return 0;

        return sd_dhcp_server_set_dns(link->dhcp_server, addresses, n_addresses);
}

int dhcp4_server_configure(Link *link) {
        bool acquired_uplink = false;
        sd_dhcp_option *p;
        Link *uplink = NULL;
        Address *address;
        int r;

        assert(link);

        if (!link_dhcp4_server_enabled(link))
                return 0;

        if (!(link->flags & IFF_UP))
                return 0;

        if (!link->dhcp_server) {
                r = sd_dhcp_server_new(&link->dhcp_server, link->ifindex);
                if (r < 0)
                        return r;

                r = sd_dhcp_server_attach_event(link->dhcp_server, link->manager->event, 0);
                if (r < 0)
                        return r;
        }

        r = sd_dhcp_server_set_callback(link->dhcp_server, dhcp_server_callback, link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to set callback for DHCPv4 server instance: %m");

        address = link_find_dhcp_server_address(link);
        if (!address)
                return log_link_error_errno(link, SYNTHETIC_ERRNO(EBUSY),
                                            "Failed to find suitable address for DHCPv4 server instance.");

        /* use the server address' subnet as the pool */
        r = sd_dhcp_server_configure_pool(link->dhcp_server, &address->in_addr.in, address->prefixlen,
                                          link->network->dhcp_server_pool_offset, link->network->dhcp_server_pool_size);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to configure address pool for DHCPv4 server instance: %m");

        /* TODO:
        r = sd_dhcp_server_set_router(link->dhcp_server, &main_address->in_addr.in);
        if (r < 0)
                return r;
        */

        if (link->network->dhcp_server_max_lease_time_usec > 0) {
                r = sd_dhcp_server_set_max_lease_time(link->dhcp_server,
                                                      DIV_ROUND_UP(link->network->dhcp_server_max_lease_time_usec, USEC_PER_SEC));
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set maximum lease time for DHCPv4 server instance: %m");
        }

        if (link->network->dhcp_server_default_lease_time_usec > 0) {
                r = sd_dhcp_server_set_default_lease_time(link->dhcp_server,
                                                          DIV_ROUND_UP(link->network->dhcp_server_default_lease_time_usec, USEC_PER_SEC));
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set default lease time for DHCPv4 server instance: %m");
        }

        for (sd_dhcp_lease_server_type_t type = 0; type < _SD_DHCP_LEASE_SERVER_TYPE_MAX; type ++) {

                if (!link->network->dhcp_server_emit[type].emit)
                        continue;

                if (link->network->dhcp_server_emit[type].n_addresses > 0)
                        /* Explicitly specified servers to emit */
                        r = sd_dhcp_server_set_servers(
                                        link->dhcp_server,
                                        type,
                                        link->network->dhcp_server_emit[type].addresses,
                                        link->network->dhcp_server_emit[type].n_addresses);
                else {
                        /* Emission is requested, but nothing explicitly configured. Let's find a suitable upling */
                        if (!acquired_uplink) {
                                uplink = manager_find_uplink(link->manager, link);
                                acquired_uplink = true;
                        }

                        if (uplink && uplink->network)
                                r = link_push_uplink_to_dhcp_server(uplink, type, link->dhcp_server);
                        else if (type == SD_DHCP_LEASE_DNS)
                                r = dhcp4_server_set_dns_from_resolve_conf(link);
                        else {
                                log_link_debug(link,
                                               "Not emitting %s on link, couldn't find suitable uplink.",
                                               dhcp_lease_server_type_to_string(type));
                                continue;
                        }
                }

                if (r < 0)
                        log_link_warning_errno(link, r,
                                               "Failed to set %s for DHCP server, ignoring: %m",
                                               dhcp_lease_server_type_to_string(type));
        }

        r = sd_dhcp_server_set_emit_router(link->dhcp_server, link->network->dhcp_server_emit_router);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set router emission for DHCP server: %m");

        if (link->network->dhcp_server_emit_timezone) {
                _cleanup_free_ char *buffer = NULL;
                const char *tz;

                if (link->network->dhcp_server_timezone)
                        tz = link->network->dhcp_server_timezone;
                else {
                        r = get_timezone(&buffer);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Failed to determine timezone: %m");

                        tz = buffer;
                }

                r = sd_dhcp_server_set_timezone(link->dhcp_server, tz);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set timezone for DHCP server: %m");
        }

        ORDERED_HASHMAP_FOREACH(p, link->network->dhcp_server_send_options) {
                r = sd_dhcp_server_add_option(link->dhcp_server, p);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set DHCPv4 option: %m");
        }

        ORDERED_HASHMAP_FOREACH(p, link->network->dhcp_server_send_vendor_options) {
                r = sd_dhcp_server_add_vendor_option(link->dhcp_server, p);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set DHCPv4 option: %m");
        }

        if (!sd_dhcp_server_is_running(link->dhcp_server)) {
                r = sd_dhcp_server_start(link->dhcp_server);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not start DHCPv4 server instance: %m");

                log_link_debug(link, "Offering DHCPv4 leases");
        }

        return 0;
}

int config_parse_dhcp_server_emit(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        NetworkDHCPServerEmitAddress *emit = data;

        assert(emit);
        assert(rvalue);

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *w = NULL;
                union in_addr_union a;
                int r;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = in_addr_from_string(AF_INET, w, &a);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse %s= address '%s', ignoring: %m", lvalue, w);
                        continue;
                }

                struct in_addr *m = reallocarray(emit->addresses, emit->n_addresses + 1, sizeof(struct in_addr));
                if (!m)
                        return log_oom();

                emit->addresses = m;
                emit->addresses[emit->n_addresses++] = a.in;
        }
}
