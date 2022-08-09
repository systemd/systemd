/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if_arp.h>
#include <linux/if.h>

#include "sd-dhcp-server.h"

#include "fd-util.h"
#include "fileio.h"
#include "networkd-address.h"
#include "networkd-dhcp-server-bus.h"
#include "networkd-dhcp-server-static-lease.h"
#include "networkd-dhcp-server.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "networkd-route-util.h"
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

        if (link->iftype == ARPHRD_CAN)
                return false;

        return link->network->dhcp_server;
}

void network_adjust_dhcp_server(Network *network) {
        assert(network);

        if (!network->dhcp_server)
                return;

        if (network->bond) {
                log_warning("%s: DHCPServer= is enabled for bond slave. Disabling DHCP server.",
                            network->filename);
                network->dhcp_server = false;
                return;
        }

        if (!in4_addr_is_set(&network->dhcp_server_address)) {
                Address *address;
                bool have = false;

                ORDERED_HASHMAP_FOREACH(address, network->addresses_by_section) {
                        if (section_is_invalid(address->section))
                                continue;

                        if (address->family != AF_INET)
                                continue;

                        if (in4_addr_is_localhost(&address->in_addr.in))
                                continue;

                        if (in4_addr_is_link_local(&address->in_addr.in))
                                continue;

                        if (in4_addr_is_set(&address->in_addr_peer.in))
                                continue;

                        have = true;
                        break;
                }
                if (!have) {
                        log_warning("%s: DHCPServer= is enabled, but no static address configured. "
                                    "Disabling DHCP server.",
                                    network->filename);
                        network->dhcp_server = false;
                        return;
                }
        }
}

int link_request_dhcp_server_address(Link *link) {
        _cleanup_(address_freep) Address *address = NULL;
        Address *existing;
        int r;

        assert(link);
        assert(link->network);

        if (!link_dhcp4_server_enabled(link))
                return 0;

        if (!in4_addr_is_set(&link->network->dhcp_server_address))
                return 0;

        r = address_new(&address);
        if (r < 0)
                return r;

        address->source = NETWORK_CONFIG_SOURCE_STATIC;
        address->family = AF_INET;
        address->in_addr.in = link->network->dhcp_server_address;
        address->prefixlen = link->network->dhcp_server_address_prefixlen;
        address_set_broadcast(address, link);

        if (address_get(link, address, &existing) >= 0 &&
            address_exists(existing) &&
            existing->source == NETWORK_CONFIG_SOURCE_STATIC)
                /* The same address seems explicitly configured in [Address] or [Network] section.
                 * Configure the DHCP server address only when it is not. */
                return 0;

        return link_request_static_address(link, TAKE_PTR(address), true);
}

static int link_find_dhcp_server_address(Link *link, Address **ret) {
        Address *address;

        assert(link);
        assert(link->network);

        /* If ServerAddress= is specified, then use the address. */
        if (in4_addr_is_set(&link->network->dhcp_server_address))
                return link_get_ipv4_address(link, &link->network->dhcp_server_address,
                                             link->network->dhcp_server_address_prefixlen, ret);

        /* If not, then select one from static addresses. */
        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_STATIC)
                        continue;
                if (!address_exists(address))
                        continue;
                if (address->family != AF_INET)
                        continue;
                if (in4_addr_is_localhost(&address->in_addr.in))
                        continue;
                if (in4_addr_is_link_local(&address->in_addr.in))
                        continue;
                if (in4_addr_is_set(&address->in_addr_peer.in))
                        continue;

                *ret = address;
                return 0;
        }

        return -ENOENT;
}

static int dhcp_server_find_uplink(Link *link, Link **ret) {
        assert(link);

        if (link->network->dhcp_server_uplink_name)
                return link_get_by_name(link->manager, link->network->dhcp_server_uplink_name, ret);

        if (link->network->dhcp_server_uplink_index > 0)
                return link_get_by_index(link->manager, link->network->dhcp_server_uplink_index, ret);

        if (link->network->dhcp_server_uplink_index == UPLINK_INDEX_AUTO) {
                /* It is not necessary to propagate error in automatic selection. */
                if (manager_find_uplink(link->manager, AF_INET, link, ret) < 0)
                        *ret = NULL;
                return 0;
        }

        *ret = NULL;
        return 0;
}

static int link_push_uplink_to_dhcp_server(
                Link *link,
                sd_dhcp_lease_server_type_t what,
                sd_dhcp_server *s) {

        _cleanup_free_ struct in_addr *addresses = NULL;
        bool use_dhcp_lease_data = true;
        size_t n_addresses = 0;

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

                        if (!GREEDY_REALLOC(addresses, n_addresses + 1))
                                return log_oom();

                        addresses[n_addresses++] = ia;
                }

                use_dhcp_lease_data = link->network->dhcp_use_dns;
                break;

        case SD_DHCP_LEASE_NTP: {
                /* For NTP things are similar, but for NTP hostnames can be configured too, which we cannot
                 * propagate via DHCP. Hence let's only propagate those which are IP addresses. */

                STRV_FOREACH(i, link->network->ntp) {
                        union in_addr_union ia;

                        if (in_addr_from_string(AF_INET, *i, &ia) < 0)
                                continue;

                        /* Never propagate obviously borked data */
                        if (in4_addr_is_null(&ia.in) || in4_addr_is_localhost(&ia.in))
                                continue;

                        if (!GREEDY_REALLOC(addresses, n_addresses + 1))
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
                assert_not_reached();
        }

        if (use_dhcp_lease_data && link->dhcp_lease) {
                const struct in_addr *da;

                int n = sd_dhcp_lease_get_servers(link->dhcp_lease, what, &da);
                if (n > 0) {
                        if (!GREEDY_REALLOC(addresses, n_addresses + n))
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

static int dhcp4_server_parse_dns_server_string_and_warn(
                const char *string,
                struct in_addr **addresses,
                size_t *n_addresses) {

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

                if (!GREEDY_REALLOC(*addresses, *n_addresses + 1))
                        return log_oom();

                (*addresses)[(*n_addresses)++] = address.in;
        }

        return 0;
}

static int dhcp4_server_set_dns_from_resolve_conf(Link *link) {
        _cleanup_free_ struct in_addr *addresses = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        size_t n_addresses = 0;
        int r;

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

                l = strstrip(line);
                if (IN_SET(*l, '#', ';', 0))
                        continue;

                a = first_word(l, "nameserver");
                if (!a)
                        continue;

                r = dhcp4_server_parse_dns_server_string_and_warn(a, &addresses, &n_addresses);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse DNS server address '%s', ignoring.", a);
        }

        if (n_addresses <= 0)
                return 0;

        return sd_dhcp_server_set_dns(link->dhcp_server, addresses, n_addresses);
}

static int dhcp4_server_configure(Link *link) {
        bool acquired_uplink = false;
        sd_dhcp_option *p;
        DHCPStaticLease *static_lease;
        Link *uplink = NULL;
        Address *address;
        bool bind_to_interface;
        int r;

        assert(link);

        log_link_debug(link, "Configuring DHCP Server.");

        if (link->dhcp_server)
                return -EBUSY;

        r = sd_dhcp_server_new(&link->dhcp_server, link->ifindex);
        if (r < 0)
                return r;

        r = sd_dhcp_server_attach_event(link->dhcp_server, link->manager->event, 0);
        if (r < 0)
                return r;

        r = sd_dhcp_server_set_callback(link->dhcp_server, dhcp_server_callback, link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to set callback for DHCPv4 server instance: %m");

        r = link_find_dhcp_server_address(link, &address);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to find suitable address for DHCPv4 server instance: %m");

        /* use the server address' subnet as the pool */
        r = sd_dhcp_server_configure_pool(link->dhcp_server, &address->in_addr.in, address->prefixlen,
                                          link->network->dhcp_server_pool_offset, link->network->dhcp_server_pool_size);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to configure address pool for DHCPv4 server instance: %m");

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

        r = sd_dhcp_server_set_boot_server_address(link->dhcp_server, &link->network->dhcp_server_boot_server_address);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to set boot server address for DHCPv4 server instance: %m");

        r = sd_dhcp_server_set_boot_server_name(link->dhcp_server, link->network->dhcp_server_boot_server_name);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to set boot server name for DHCPv4 server instance: %m");

        r = sd_dhcp_server_set_boot_filename(link->dhcp_server, link->network->dhcp_server_boot_filename);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to set boot filename for DHCPv4 server instance: %m");

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
                                (void) dhcp_server_find_uplink(link, &uplink);
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

        if (link->network->dhcp_server_emit_router) {
                r = sd_dhcp_server_set_router(link->dhcp_server, &link->network->dhcp_server_router);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set router address for DHCP server: %m");
        }

        r = sd_dhcp_server_set_relay_target(link->dhcp_server, &link->network->dhcp_server_relay_target);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set relay target for DHCP server: %m");

        bind_to_interface = sd_dhcp_server_is_in_relay_mode(link->dhcp_server) ? false : link->network->dhcp_server_bind_to_interface;
        r = sd_dhcp_server_set_bind_to_interface(link->dhcp_server, bind_to_interface);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set interface binding for DHCP server: %m");

        r = sd_dhcp_server_set_relay_agent_information(link->dhcp_server, link->network->dhcp_server_relay_agent_circuit_id, link->network->dhcp_server_relay_agent_remote_id);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set agent circuit/remote id for DHCP server: %m");

        if (link->network->dhcp_server_emit_timezone) {
                _cleanup_free_ char *buffer = NULL;
                const char *tz = NULL;

                if (link->network->dhcp_server_timezone)
                        tz = link->network->dhcp_server_timezone;
                else {
                        r = get_timezone(&buffer);
                        if (r < 0)
                                log_link_warning_errno(link, r, "Failed to determine timezone, not sending timezone: %m");
                        else
                                tz = buffer;
                }

                if (tz) {
                        r = sd_dhcp_server_set_timezone(link->dhcp_server, tz);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Failed to set timezone for DHCP server: %m");
                }
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

        HASHMAP_FOREACH(static_lease, link->network->dhcp_static_leases_by_section) {
                r = sd_dhcp_server_set_static_lease(link->dhcp_server, &static_lease->address, static_lease->client_id, static_lease->client_id_size);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set DHCPv4 static lease for DHCP server: %m");
        }

        r = sd_dhcp_server_start(link->dhcp_server);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not start DHCPv4 server instance: %m");

        log_link_debug(link, "Offering DHCPv4 leases");
        return 0;
}

static bool dhcp_server_is_ready_to_configure(Link *link) {
        Link *uplink = NULL;
        Address *a;

        assert(link);

        if (!link_is_ready_to_configure(link, /* allow_unmanaged = */ false))
                return false;

        if (!link_has_carrier(link))
                return false;

        if (!link->static_addresses_configured)
                return false;

        if (link_find_dhcp_server_address(link, &a) < 0)
                return false;

        if (!address_is_ready(a))
                return false;

        if (dhcp_server_find_uplink(link, &uplink) < 0)
                return false;

        if (uplink && !uplink->network)
                return false;

        return true;
}

static int dhcp_server_process_request(Request *req, Link *link, void *userdata) {
        int r;

        assert(link);

        if (!dhcp_server_is_ready_to_configure(link))
                return 0;

        r = dhcp4_server_configure(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure DHCP server: %m");

        return 1;
}

int link_request_dhcp_server(Link *link) {
        int r;

        assert(link);

        if (!link_dhcp4_server_enabled(link))
                return 0;

        if (link->dhcp_server)
                return 0;

        log_link_debug(link, "Requesting DHCP server.");
        r = link_queue_request(link, REQUEST_TYPE_DHCP_SERVER, dhcp_server_process_request, NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request configuration of DHCP server: %m");

        return 0;
}

int config_parse_dhcp_server_relay_agent_suboption(
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

        char **suboption_value = data;
        char* p;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *suboption_value = mfree(*suboption_value);
                return 0;
        }

        p = startswith(rvalue, "string:");
        if (!p) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to parse %s=%s'. Invalid format, ignoring.", lvalue, rvalue);
                return 0;
        }
        return free_and_strdup(suboption_value, empty_to_null(p));
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

        NetworkDHCPServerEmitAddress *emit = ASSERT_PTR(data);

        assert(rvalue);

        if (isempty(rvalue)) {
                emit->addresses = mfree(emit->addresses);
                emit->n_addresses = 0;
                return 0;
        }

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

                if (streq(w, "_server_address"))
                        a = IN_ADDR_NULL; /* null address will be converted to the server address. */
                else {
                        r = in_addr_from_string(AF_INET, w, &a);
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "Failed to parse %s= address '%s', ignoring: %m", lvalue, w);
                                continue;
                        }

                        if (in4_addr_is_null(&a.in)) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0,
                                           "Found a null address in %s=, ignoring.", lvalue);
                                continue;
                        }
                }

                if (!GREEDY_REALLOC(emit->addresses, emit->n_addresses + 1))
                        return log_oom();

                emit->addresses[emit->n_addresses++] = a.in;
        }
}

int config_parse_dhcp_server_address(
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
        union in_addr_union a;
        unsigned char prefixlen;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->dhcp_server_address = (struct in_addr) {};
                network->dhcp_server_address_prefixlen = 0;
                return 0;
        }

        r = in_addr_prefix_from_string(rvalue, AF_INET, &a, &prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }
        if (in4_addr_is_null(&a.in) || in4_addr_is_localhost(&a.in)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "DHCP server address cannot be the ANY address or a localhost address, "
                           "ignoring assignment: %s", rvalue);
                return 0;
        }

        network->dhcp_server_address = a.in;
        network->dhcp_server_address_prefixlen = prefixlen;
        return 0;
}
