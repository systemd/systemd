/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>
#include <netinet/in.h>

#include "sd-dhcp-server.h"

#include "conf-parser.h"
#include "dhcp-protocol.h"
#include "dhcp-server-lease-internal.h"
#include "dns-domain.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "hostname-setup.h"
#include "network-common.h"
#include "networkd-address.h"
#include "networkd-dhcp-server.h"
#include "networkd-dhcp-server-bus.h"
#include "networkd-dhcp-server-static-lease.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-ntp.h"
#include "networkd-queue.h"
#include "networkd-route-util.h"
#include "path-util.h"
#include "set.h"
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

int network_adjust_dhcp_server(Network *network, Set **addresses) {
        int r;

        assert(network);
        assert(addresses);

        if (!network->dhcp_server)
                return 0;

        if (network->bond) {
                log_warning("%s: DHCPServer= is enabled for bond slave. Disabling DHCP server.",
                            network->filename);
                network->dhcp_server = false;
                return 0;
        }

        assert(network->dhcp_server_address_prefixlen <= 32);

        if (network->dhcp_server_address_prefixlen == 0) {
                Address *address;

                /* If the server address is not specified, then find suitable static address. */

                ORDERED_HASHMAP_FOREACH(address, network->addresses_by_section) {
                        assert(!section_is_invalid(address->section));

                        if (address->family != AF_INET)
                                continue;

                        if (in4_addr_is_localhost(&address->in_addr.in))
                                continue;

                        if (in4_addr_is_link_local(&address->in_addr.in))
                                continue;

                        if (in4_addr_is_set(&address->in_addr_peer.in))
                                continue;

                        /* TODO: check if the prefix length is small enough for the pool. */

                        network->dhcp_server_address = address;
                        address->used_by_dhcp_server = true;
                        break;
                }
                if (!network->dhcp_server_address) {
                        log_warning("%s: DHCPServer= is enabled, but no suitable static address configured. "
                                    "Disabling DHCP server.",
                                    network->filename);
                        network->dhcp_server = false;
                        return 0;
                }

        } else {
                _cleanup_(address_unrefp) Address *a = NULL;
                Address *existing;
                unsigned line;

                /* TODO: check if the prefix length is small enough for the pool. */

                /* If an address is explicitly specified, then check if the corresponding [Address] section
                 * is configured, and add one if not. */

                existing = set_get(*addresses,
                                   &(Address) {
                                           .family = AF_INET,
                                           .in_addr.in = network->dhcp_server_address_in_addr,
                                           .prefixlen = network->dhcp_server_address_prefixlen,
                                   });
                if (existing) {
                        /* Corresponding [Address] section already exists. */
                        network->dhcp_server_address = existing;
                        return 0;
                }

                r = ordered_hashmap_by_section_find_unused_line(network->addresses_by_section, network->filename, &line);
                if (r < 0)
                        return log_warning_errno(r, "%s: Failed to find unused line number for DHCP server address: %m",
                                                 network->filename);

                r = address_new_static(network, network->filename, line, &a);
                if (r < 0)
                        return log_warning_errno(r, "%s: Failed to add new static address object for DHCP server: %m",
                                                 network->filename);

                a->family = AF_INET;
                a->prefixlen = network->dhcp_server_address_prefixlen;
                a->in_addr.in = network->dhcp_server_address_in_addr;
                a->requested_as_null = !in4_addr_is_set(&network->dhcp_server_address_in_addr);
                a->used_by_dhcp_server = true;

                r = address_section_verify(a);
                if (r < 0)
                        return r;

                r = set_ensure_put(addresses, &address_hash_ops, a);
                if (r < 0)
                        return log_oom();
                assert(r > 0);

                network->dhcp_server_address = TAKE_PTR(a);
        }

        return 0;
}

static DHCPServerPersistLeases link_get_dhcp_server_persist_leases(Link *link) {
        assert(link);
        assert(link->manager);
        assert(link->network);

        if (in4_addr_is_set(&link->network->dhcp_server_relay_target))
                return DHCP_SERVER_PERSIST_LEASES_NO; /* On relay mode. Nothing saved in the persistent storage. */

        if (link->network->dhcp_server_persist_leases >= 0)
                return link->network->dhcp_server_persist_leases;

        return link->manager->dhcp_server_persist_leases;
}

static int link_get_dhcp_server_lease_file(Link *link, int *ret_dir_fd, char **ret_path) {
        assert(link);
        assert(link->ifname);
        assert(ret_dir_fd);
        assert(ret_path);

        /* This does not copy fd. Do not close fd stored in ret_dir_fd. */

        switch (link_get_dhcp_server_persist_leases(link)) {
        case DHCP_SERVER_PERSIST_LEASES_NO:
                *ret_dir_fd = -EBADF;
                *ret_path = NULL;
                return 0;

        case DHCP_SERVER_PERSIST_LEASES_YES: {
                if (link->manager->persistent_storage_fd < 0)
                        return -EBUSY; /* persistent storage is not ready. */

                char *p = path_join("dhcp-server-lease", link->ifname);
                if (!p)
                        return -ENOMEM;

                *ret_dir_fd = link->manager->persistent_storage_fd;
                *ret_path = p;
                return 1;
        }
        case DHCP_SERVER_PERSIST_LEASES_RUNTIME: {
                char *p = path_join("/run/systemd/netif/dhcp-server-lease", link->ifname);
                if (!p)
                        return -ENOMEM;

                *ret_dir_fd = AT_FDCWD;
                *ret_path = p;
                return 1;
        }
        default:
                assert_not_reached();
        }
}

int address_acquire_from_dhcp_server_leases_file(Link *link, const Address *address, union in_addr_union *ret) {
        int r;

        assert(link);
        assert(link->manager);
        assert(address);
        assert(ret);

        /* If the DHCP server address is configured as a null address, reuse the server address of the
         * previous instance. */
        if (address->family != AF_INET)
                return -ENOENT;

        if (!address->used_by_dhcp_server)
                return -ENOENT;

        if (!link_dhcp4_server_enabled(link))
                return -ENOENT;

        _cleanup_free_ char *lease_file = NULL;
        int dir_fd;
        r = link_get_dhcp_server_lease_file(link, &dir_fd, &lease_file);
        if (r < 0)
                return r;
        if (r == 0) /* persistent leases is disabled */
                return -ENOENT;

        struct in_addr a;
        uint8_t prefixlen;
        r = dhcp_server_leases_file_get_server_address(
                        dir_fd,
                        lease_file,
                        &a,
                        &prefixlen);
        if (r == -ENOENT)
                return r;
        if (r < 0)
                return log_warning_errno(r, "Failed to load lease file %s: %s",
                                         lease_file,
                                         r == -ENXIO ? "expected JSON content not found" :
                                         r == -EINVAL ? "invalid JSON" :
                                         STRERROR(r));

        if (prefixlen != address->prefixlen)
                return -ENOENT;

        ret->in = a;
        return 0;
}

int link_start_dhcp4_server(Link *link) {
        int r;

        assert(link);
        assert(link->manager);

        if (!link->dhcp_server)
                return 0; /* Not configured yet. */

        if (!link_has_carrier(link))
                return 0;

        if (sd_dhcp_server_is_running(link->dhcp_server))
                return 0; /* already started. */

        /* TODO: Maybe, also check the system time is synced. If the system does not have RTC battery, then
         * the realtime clock in not usable in the early boot stage, and all saved leases may be wrongly
         * handled as expired and dropped. */
        _cleanup_free_ char *lease_file = NULL;
        int dir_fd;
        r = link_get_dhcp_server_lease_file(link, &dir_fd, &lease_file);
        if (r == -EBUSY)
                return 0; /* persistent storage is not ready. */
        if (r < 0)
                return r;
        if (r > 0) {
                r = sd_dhcp_server_set_lease_file(link->dhcp_server, dir_fd, lease_file);
                if (r < 0)
                        return r;
        }

        r = sd_dhcp_server_start(link->dhcp_server);
        if (r < 0)
                return r;

        log_link_debug(link, "Offering DHCPv4 leases");
        return 0;
}

void manager_toggle_dhcp4_server_state(Manager *manager, bool start) {
        Link *link;
        int r;

        assert(manager);

        HASHMAP_FOREACH(link, manager->links_by_index) {
                if (!link->dhcp_server)
                        continue;
                if (link_get_dhcp_server_persist_leases(link) != DHCP_SERVER_PERSIST_LEASES_YES)
                        continue;

                /* Even if 'start' is true, first we need to stop the server. Otherwise, we cannot (re)set
                 * the lease file in link_start_dhcp4_server(). */
                r = sd_dhcp_server_stop(link->dhcp_server);
                if (r < 0)
                        log_link_debug_errno(link, r, "Failed to stop DHCP server, ignoring: %m");

                if (!start)
                        continue;

                r = link_start_dhcp4_server(link);
                if (r < 0)
                        log_link_debug_errno(link, r, "Failed to start DHCP server, ignoring: %m");
        }
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

                use_dhcp_lease_data = link_get_use_dns(link, NETWORK_CONFIG_SOURCE_DHCP4);
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

                use_dhcp_lease_data = link_get_use_ntp(link, NETWORK_CONFIG_SOURCE_DHCP4);
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

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read " PRIVATE_UPLINK_RESOLV_CONF ": %m");
                if (r == 0)
                        break;

                if (IN_SET(*line, '#', ';', 0))
                        continue;

                a = first_word(line, "nameserver");
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

static int dhcp_server_set_domain(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->dhcp_server);

        if (!link->network->dhcp_server_emit_domain)
                return 0;

        if (link->network->dhcp_server_domain)
                return sd_dhcp_server_set_domain_name(link->dhcp_server, link->network->dhcp_server_domain);

        /* When domain is not specified, use the domain part of the current hostname. */
        _cleanup_free_ char *hostname = NULL;
        r = gethostname_full(GET_HOSTNAME_ALLOW_LOCALHOST | GET_HOSTNAME_FALLBACK_DEFAULT, &hostname);
        if (r < 0)
                return r;

        const char *domain = hostname;
        r = dns_name_parent(&domain);
        if (r < 0)
                return r;

        if (isempty(domain))
                return -ENXIO;

        return sd_dhcp_server_set_domain_name(link->dhcp_server, domain);
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
        assert(link->network);
        assert(link->network->dhcp_server_address);

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

        r = address_get(link, link->network->dhcp_server_address, &address);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to find suitable address for DHCPv4 server instance: %m");

        /* use the server address' subnet as the pool */
        r = sd_dhcp_server_configure_pool(link->dhcp_server, &address->in_addr.in, address->prefixlen,
                                          link->network->dhcp_server_pool_offset, link->network->dhcp_server_pool_size);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to configure address pool for DHCPv4 server instance: %m");

        if (link->network->dhcp_server_max_lease_time_usec > 0) {
                r = sd_dhcp_server_set_max_lease_time(link->dhcp_server, link->network->dhcp_server_max_lease_time_usec);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set maximum lease time for DHCPv4 server instance: %m");
        }

        if (link->network->dhcp_server_default_lease_time_usec > 0) {
                r = sd_dhcp_server_set_default_lease_time(link->dhcp_server, link->network->dhcp_server_default_lease_time_usec);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set default lease time for DHCPv4 server instance: %m");
        }

        r = sd_dhcp_server_set_ipv6_only_preferred_usec(link->dhcp_server, link->network->dhcp_server_ipv6_only_preferred_usec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set IPv6 only preferred time for DHCPv4 server instance: %m");

        r = sd_dhcp_server_set_boot_server_address(link->dhcp_server, &link->network->dhcp_server_boot_server_address);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to set boot server address for DHCPv4 server instance: %m");

        r = sd_dhcp_server_set_boot_server_name(link->dhcp_server, link->network->dhcp_server_boot_server_name);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to set boot server name for DHCPv4 server instance: %m");

        r = sd_dhcp_server_set_boot_filename(link->dhcp_server, link->network->dhcp_server_boot_filename);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to set boot filename for DHCPv4 server instance: %m");

        r = sd_dhcp_server_set_rapid_commit(link->dhcp_server, link->network->dhcp_server_rapid_commit);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to %s Rapid Commit support for DHCPv4 server instance: %m",
                                              enable_disable(link->network->dhcp_server_rapid_commit));

        for (sd_dhcp_lease_server_type_t type = 0; type < _SD_DHCP_LEASE_SERVER_TYPE_MAX; type++) {

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

        r = dhcp_server_set_domain(link);
        if (r == -ENXIO)
                log_link_warning_errno(link, r, "Cannot get domain from the current hostname, DHCP server will not emit domain option.");
        else if (r < 0)
                return log_link_error_errno(link, r, "Failed to set domain name for DHCP server: %m");

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

        r = link_start_dhcp4_server(link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not start DHCPv4 server instance: %m");

        return 0;
}

static bool dhcp_server_is_ready_to_configure(Link *link) {
        Link *uplink = NULL;
        Address *a;

        assert(link);
        assert(link->network);
        assert(link->network->dhcp_server_address);

        if (!link_is_ready_to_configure(link, /* allow_unmanaged = */ false))
                return false;

        if (!link_has_carrier(link))
                return false;

        if (!link->static_addresses_configured)
                return false;

        if (address_get(link, link->network->dhcp_server_address, &a) < 0)
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
                network->dhcp_server_address_in_addr = (struct in_addr) {};
                network->dhcp_server_address_prefixlen = 0;
                return 0;
        }

        r = in_addr_prefix_from_string(rvalue, AF_INET, &a, &prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }
        if (in4_addr_is_localhost(&a.in) || in4_addr_is_link_local(&a.in)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "DHCP server address cannot be a localhost or link-local address, "
                           "ignoring assignment: %s", rvalue);
                return 0;
        }

        network->dhcp_server_address_in_addr = a.in;
        network->dhcp_server_address_prefixlen = prefixlen;
        return 0;
}

int config_parse_dhcp_server_ipv6_only_preferred(
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

        usec_t t, *usec = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *usec = 0;
                return 0;
        }

        r = parse_sec(rvalue, &t);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse [%s] %s=, ignoring assignment: %s", section, lvalue, rvalue);
                return 0;
        }

        if (t < MIN_V6ONLY_WAIT_USEC && !network_test_mode_enabled()) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid [%s] %s=, ignoring assignment: %s", section, lvalue, rvalue);
                return 0;
        }

        *usec = t;
        return 0;
}

static const char* const dhcp_server_persist_leases_table[_DHCP_SERVER_PERSIST_LEASES_MAX] = {
        [DHCP_SERVER_PERSIST_LEASES_NO]      = "no",
        [DHCP_SERVER_PERSIST_LEASES_YES]     = "yes",
        [DHCP_SERVER_PERSIST_LEASES_RUNTIME] = "runtime",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(
                dhcp_server_persist_leases,
                DHCPServerPersistLeases,
                DHCP_SERVER_PERSIST_LEASES_YES);

DEFINE_CONFIG_PARSE_ENUM(
                config_parse_dhcp_server_persist_leases,
                dhcp_server_persist_leases,
                DHCPServerPersistLeases);
