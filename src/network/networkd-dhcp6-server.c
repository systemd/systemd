/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if.h>
#include <linux/if_arp.h>

#include "sd-dhcp6-server.h"

#include "conf-parser.h"
#include "extract-word.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "networkd-address.h"
#include "networkd-dhcp6-server.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "socket-util.h"
#include "string-util.h"

static bool link_dhcp6_server_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->iftype == ARPHRD_CAN)
                return false;

        if (!socket_ipv6_is_supported())
                return false;

        if (link->network->bond)
                return false;

        return link->network->dhcp6_server;
}

static int dhcp6_server_find_address(Link *link, Address **ret) {
        Address *address;
        int r;

        assert(link);

        ORDERED_HASHMAP_FOREACH(address, link->network->addresses_by_section) {
                if (address->family != AF_INET6)
                        continue;

                if (in6_addr_is_null(&address->in_addr.in6))
                        continue;

                if (in6_addr_is_link_local(&address->in_addr.in6))
                        continue;

                r = address_get(link, address, ret);
                if (r >= 0)
                        return 0;
        }

        return -ENOENT;
}

static int dhcp6_server_configure(Link *link) {
        Address *address;
        int r;

        assert(link);
        assert(link->network);

        log_link_debug(link, "Configuring DHCPv6 Server.");

        if (link->dhcp6_server)
                return -EBUSY;

        r = dhcp6_server_find_address(link, &address);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "Failed to find suitable address for DHCPv6 server instance: %m");

        _cleanup_(sd_dhcp6_server_unrefp) sd_dhcp6_server *server = NULL;

        r = sd_dhcp6_server_new(&server, link->ifindex);
        if (r < 0)
                return r;

        r = sd_dhcp6_server_set_ifname(server, link->ifname);
        if (r < 0)
                return r;

        r = sd_dhcp6_server_attach_event(server, link->manager->event, 0);
        if (r < 0)
                return r;

        r = sd_dhcp6_server_set_address(server, &address->in_addr.in6, address->prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set address for DHCPv6 server: %m");

        r = sd_dhcp6_server_configure_pool(server, &address->in_addr.in6, address->prefixlen,
                                           link->network->dhcp6_server_pool_offset,
                                           link->network->dhcp6_server_pool_size);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to configure address pool for DHCPv6 server: %m");

        if (link->network->dhcp6_server_max_lease_time_usec > 0) {
                r = sd_dhcp6_server_set_max_lease_time(server, link->network->dhcp6_server_max_lease_time_usec);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set max lease time for DHCPv6 server: %m");
        }

        if (link->network->dhcp6_server_default_lease_time_usec > 0) {
                r = sd_dhcp6_server_set_default_lease_time(server, link->network->dhcp6_server_default_lease_time_usec);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set default lease time for DHCPv6 server: %m");
        }

        if (link->network->n_dhcp6_server_dns > 0) {
                r = sd_dhcp6_server_set_dns(server,
                                            link->network->dhcp6_server_dns,
                                            link->network->n_dhcp6_server_dns);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set DNS for DHCPv6 server: %m");
        }

        if (link->network->n_dhcp6_server_ntp > 0) {
                r = sd_dhcp6_server_set_ntp(server,
                                            link->network->dhcp6_server_ntp,
                                            link->network->n_dhcp6_server_ntp);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set NTP for DHCPv6 server: %m");
        }

        r = sd_dhcp6_server_set_rapid_commit(server, link->network->dhcp6_server_rapid_commit);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set rapid commit for DHCPv6 server: %m");

        link->dhcp6_server = TAKE_PTR(server);

        r = link_start_dhcp6_server(link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not start DHCPv6 server: %m");

        return 0;
}

int link_start_dhcp6_server(Link *link) {
        int r;

        assert(link);

        if (!link->dhcp6_server)
                return 0;

        if (!link_has_carrier(link))
                return 0;

        if (sd_dhcp6_server_is_running(link->dhcp6_server))
                return 0;

        r = sd_dhcp6_server_start(link->dhcp6_server);
        if (r < 0)
                return r;

        log_link_debug(link, "Offering DHCPv6 leases");
        return 0;
}

static bool dhcp6_server_is_ready_to_configure(Link *link) {
        Address *a;

        assert(link);
        assert(link->network);

        if (!link_is_ready_to_configure(link, /* allow_unmanaged= */ false))
                return false;

        if (!link_has_carrier(link))
                return false;

        if (!link->static_addresses_configured)
                return false;

        if (dhcp6_server_find_address(link, &a) < 0)
                return false;

        if (!address_is_ready(a))
                return false;

        return true;
}

static int dhcp6_server_process_request(Request *req, Link *link, void *userdata) {
        int r;

        assert(link);

        if (!dhcp6_server_is_ready_to_configure(link))
                return 0;

        r = dhcp6_server_configure(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure DHCPv6 server: %m");

        return 1;
}

int link_request_dhcp6_server(Link *link) {
        int r;

        assert(link);

        if (!link_dhcp6_server_enabled(link))
                return 0;

        if (link->dhcp6_server)
                return 0;

        log_link_debug(link, "Requesting DHCPv6 server.");
        r = link_queue_request(link, REQUEST_TYPE_DHCP6_SERVER, dhcp6_server_process_request, NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request configuration of DHCPv6 server: %m");

        return 0;
}

int config_parse_dhcp6_server_address(
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

        Network *network = ASSERT_PTR(userdata);
        struct in6_addr **addresses;
        size_t *n_addresses;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (streq(lvalue, "DNS")) {
                addresses = &network->dhcp6_server_dns;
                n_addresses = &network->n_dhcp6_server_dns;
        } else if (streq(lvalue, "NTP")) {
                addresses = &network->dhcp6_server_ntp;
                n_addresses = &network->n_dhcp6_server_ntp;
        } else
                assert_not_reached();

        if (isempty(rvalue)) {
                *addresses = mfree(*addresses);
                *n_addresses = 0;
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                union in_addr_union addr;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                r = in_addr_from_string(AF_INET6, word, &addr);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse IPv6 address '%s', ignoring: %m", word);
                        continue;
                }

                if (in6_addr_is_null(&addr.in6)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "DHCPv6 server address is null, ignoring: %s", word);
                        continue;
                }

                if (!GREEDY_REALLOC(*addresses, *n_addresses + 1))
                        return log_oom();

                (*addresses)[(*n_addresses)++] = addr.in6;
        }

        return 0;
}
