/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include <ctype.h>
#include <net/if.h>

#include "conf-files.h"
#include "conf-parser.h"
#include "util.h"
#include "hostname-util.h"
#include "dns-domain.h"
#include "network-internal.h"

#include "networkd.h"
#include "networkd-network.h"

static int network_load_one(Manager *manager, const char *filename) {
        _cleanup_network_free_ Network *network = NULL;
        _cleanup_fclose_ FILE *file = NULL;
        char *d;
        Route *route;
        Address *address;
        int r;

        assert(manager);
        assert(filename);

        file = fopen(filename, "re");
        if (!file) {
                if (errno == ENOENT)
                        return 0;
                else
                        return -errno;
        }

        if (null_or_empty_fd(fileno(file))) {
                log_debug("Skipping empty file: %s", filename);
                return 0;
        }

        network = new0(Network, 1);
        if (!network)
                return log_oom();

        network->manager = manager;

        LIST_HEAD_INIT(network->static_addresses);
        LIST_HEAD_INIT(network->static_routes);
        LIST_HEAD_INIT(network->static_fdb_entries);

        network->stacked_netdevs = hashmap_new(&string_hash_ops);
        if (!network->stacked_netdevs)
                return log_oom();

        network->addresses_by_section = hashmap_new(NULL);
        if (!network->addresses_by_section)
                return log_oom();

        network->routes_by_section = hashmap_new(NULL);
        if (!network->routes_by_section)
                return log_oom();

        network->fdb_entries_by_section = hashmap_new(NULL);
        if (!network->fdb_entries_by_section)
                return log_oom();

        network->filename = strdup(filename);
        if (!network->filename)
                return log_oom();

        network->name = strdup(basename(filename));
        if (!network->name)
                return log_oom();

        d = strrchr(network->name, '.');
        if (!d)
                return -EINVAL;

        assert(streq(d, ".network"));

        *d = '\0';

        network->dhcp = ADDRESS_FAMILY_NO;
        network->dhcp_ntp = true;
        network->dhcp_dns = true;
        network->dhcp_hostname = true;
        network->dhcp_routes = true;
        network->dhcp_sendhost = true;
        network->dhcp_route_metric = DHCP_ROUTE_METRIC;
        network->dhcp_client_identifier = DHCP_CLIENT_ID_DUID;

        network->dhcp_server_emit_dns = true;
        network->dhcp_server_emit_ntp = true;
        network->dhcp_server_emit_timezone = true;

        network->use_bpdu = true;
        network->allow_port_to_be_root = true;
        network->unicast_flood = true;

        network->llmnr = RESOLVE_SUPPORT_YES;

        network->link_local = ADDRESS_FAMILY_IPV6;

        network->ipv6_privacy_extensions = IPV6_PRIVACY_EXTENSIONS_NO;

        r = config_parse(NULL, filename, file,
                         "Match\0"
                         "Link\0"
                         "Network\0"
                         "Address\0"
                         "Route\0"
                         "DHCP\0"
                         "DHCPv4\0" /* compat */
                         "DHCPServer\0"
                         "Bridge\0"
                         "BridgeFDB\0",
                         config_item_perf_lookup, network_network_gperf_lookup,
                         false, false, true, network);
        if (r < 0)
                return r;

        /* IPMasquerade=yes implies IPForward=yes */
        if (network->ip_masquerade)
                network->ip_forward |= ADDRESS_FAMILY_IPV4;

        LIST_PREPEND(networks, manager->networks, network);

        r = hashmap_ensure_allocated(&manager->networks_by_name, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_put(manager->networks_by_name, network->name, network);
        if (r < 0)
                return r;

        LIST_FOREACH(routes, route, network->static_routes) {
                if (!route->family) {
                        log_warning("Route section without Gateway field configured in %s. "
                                    "Ignoring", filename);
                        return 0;
                }
        }

        LIST_FOREACH(addresses, address, network->static_addresses) {
                if (!address->family) {
                        log_warning("Address section without Address field configured in %s. "
                                    "Ignoring", filename);
                        return 0;
                }
        }

        network = NULL;

        return 0;
}

int network_load(Manager *manager) {
        Network *network;
        _cleanup_strv_free_ char **files = NULL;
        char **f;
        int r;

        assert(manager);

        while ((network = manager->networks))
                network_free(network);

        r = conf_files_list_strv(&files, ".network", NULL, network_dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate network files: %m");

        STRV_FOREACH_BACKWARDS(f, files) {
                r = network_load_one(manager, *f);
                if (r < 0)
                        return r;
        }

        return 0;
}

void network_free(Network *network) {
        NetDev *netdev;
        Route *route;
        Address *address;
        FdbEntry *fdb_entry;
        Iterator i;

        if (!network)
                return;

        free(network->filename);

        free(network->match_mac);
        strv_free(network->match_path);
        strv_free(network->match_driver);
        strv_free(network->match_type);
        strv_free(network->match_name);

        free(network->description);
        free(network->dhcp_vendor_class_identifier);
        free(network->hostname);

        free(network->mac);

        strv_free(network->ntp);
        strv_free(network->dns);
        strv_free(network->domains);
        strv_free(network->bind_carrier);

        netdev_unref(network->bridge);

        netdev_unref(network->bond);

        HASHMAP_FOREACH(netdev, network->stacked_netdevs, i) {
                hashmap_remove(network->stacked_netdevs, netdev->ifname);
                netdev_unref(netdev);
        }
        hashmap_free(network->stacked_netdevs);

        while ((route = network->static_routes))
                route_free(route);

        while ((address = network->static_addresses))
                address_free(address);

        while ((fdb_entry = network->static_fdb_entries))
                fdb_entry_free(fdb_entry);

        hashmap_free(network->addresses_by_section);
        hashmap_free(network->routes_by_section);
        hashmap_free(network->fdb_entries_by_section);

        if (network->manager) {
                if (network->manager->networks)
                        LIST_REMOVE(networks, network->manager->networks, network);

                if (network->manager->networks_by_name)
                        hashmap_remove(network->manager->networks_by_name, network->name);
        }

        free(network->name);

        condition_free_list(network->match_host);
        condition_free_list(network->match_virt);
        condition_free_list(network->match_kernel);
        condition_free_list(network->match_arch);

        free(network->dhcp_server_timezone);
        free(network->dhcp_server_dns);
        free(network->dhcp_server_ntp);

        free(network);
}

int network_get_by_name(Manager *manager, const char *name, Network **ret) {
        Network *network;

        assert(manager);
        assert(name);
        assert(ret);

        network = hashmap_get(manager->networks_by_name, name);
        if (!network)
                return -ENOENT;

        *ret = network;

        return 0;
}

int network_get(Manager *manager, struct udev_device *device,
                const char *ifname, const struct ether_addr *address,
                Network **ret) {
        Network *network;
        struct udev_device *parent;
        const char *path = NULL, *parent_driver = NULL, *driver = NULL, *devtype = NULL;

        assert(manager);
        assert(ret);

        if (device) {
                path = udev_device_get_property_value(device, "ID_PATH");

                parent = udev_device_get_parent(device);
                if (parent)
                        parent_driver = udev_device_get_driver(parent);

                driver = udev_device_get_property_value(device, "ID_NET_DRIVER");

                devtype = udev_device_get_devtype(device);
        }

        LIST_FOREACH(networks, network, manager->networks) {
                if (net_match_config(network->match_mac, network->match_path,
                                     network->match_driver, network->match_type,
                                     network->match_name, network->match_host,
                                     network->match_virt, network->match_kernel,
                                     network->match_arch,
                                     address, path, parent_driver, driver,
                                     devtype, ifname)) {
                        if (network->match_name && device) {
                                const char *attr;
                                uint8_t name_assign_type = NET_NAME_UNKNOWN;

                                attr = udev_device_get_sysattr_value(device, "name_assign_type");
                                if (attr)
                                        (void) safe_atou8(attr, &name_assign_type);

                                if (name_assign_type == NET_NAME_ENUM)
                                        log_warning("%-*s: found matching network '%s', based on potentially unpredictable ifname",
                                                    IFNAMSIZ, ifname, network->filename);
                                else
                                        log_debug("%-*s: found matching network '%s'", IFNAMSIZ, ifname, network->filename);
                        } else
                                log_debug("%-*s: found matching network '%s'", IFNAMSIZ, ifname, network->filename);

                        *ret = network;
                        return 0;
                }
        }

        *ret = NULL;

        return -ENOENT;
}

int network_apply(Manager *manager, Network *network, Link *link) {
        int r;

        link->network = network;

        if (network->ipv4ll_route) {
                Route *route;

                r = route_new_static(network, 0, &route);
                if (r < 0)
                        return r;

                r = inet_pton(AF_INET, "169.254.0.0", &route->dst_addr.in);
                if (r == 0)
                        return -EINVAL;
                if (r < 0)
                        return -errno;

                route->family = AF_INET;
                route->dst_prefixlen = 16;
                route->scope = RT_SCOPE_LINK;
                route->metrics = IPV4LL_ROUTE_METRIC;
                route->protocol = RTPROT_STATIC;
        }

        if (network->dns || network->ntp) {
                r = link_save(link);
                if (r < 0)
                        return r;
        }

        return 0;
}

int config_parse_netdev(const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {
        Network *network = userdata;
        _cleanup_free_ char *kind_string = NULL;
        char *p;
        NetDev *netdev;
        NetDevKind kind;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        kind_string = strdup(lvalue);
        if (!kind_string)
                return log_oom();

        /* the keys are CamelCase versions of the kind */
        for (p = kind_string; *p; p++)
                *p = tolower(*p);

        kind = netdev_kind_from_string(kind_string);
        if (kind == _NETDEV_KIND_INVALID) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Invalid NetDev kind: %s", lvalue);
                return 0;
        }

        r = netdev_get(network->manager, rvalue, &netdev);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "%s could not be found, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        if (netdev->kind != kind) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "NetDev is not a %s, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        switch (kind) {
        case NETDEV_KIND_BRIDGE:
                network->bridge = netdev;

                break;
        case NETDEV_KIND_BOND:
                network->bond = netdev;

                break;
        case NETDEV_KIND_VLAN:
        case NETDEV_KIND_MACVLAN:
        case NETDEV_KIND_MACVTAP:
        case NETDEV_KIND_IPVLAN:
        case NETDEV_KIND_VXLAN:
                r = hashmap_put(network->stacked_netdevs, netdev->ifname, netdev);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Can not add VLAN '%s' to network: %m",
                                   rvalue);
                        return 0;
                }

                break;
        default:
                assert_not_reached("Can not parse NetDev");
        }

        netdev_ref(netdev);

        return 0;
}

int config_parse_domains(const char *unit,
                         const char *filename,
                         unsigned line,
                         const char *section,
                         unsigned section_line,
                         const char *lvalue,
                         int ltype,
                         const char *rvalue,
                         void *data,
                         void *userdata) {
        Network *network = userdata;
        char ***domains = data;
        char **domain;
        int r;

        r = config_parse_strv(unit, filename, line, section, section_line,
                              lvalue, ltype, rvalue, domains, userdata);
        if (r < 0)
                return r;

        strv_uniq(*domains);
        network->wildcard_domain = !!strv_find(*domains, "*");

        STRV_FOREACH(domain, *domains) {
                if (is_localhost(*domain))
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL, "'localhost' domain names may not be configured, ignoring assignment: %s", *domain);
                else {
                        r = dns_name_is_valid(*domain);
                        if (r <= 0 && !streq(*domain, "*")) {
                                if (r < 0)
                                        log_error_errno(r, "Failed to validate domain name: %s: %m", *domain);
                                if (r == 0)
                                        log_warning("Domain name is not valid, ignoring assignment: %s", *domain);
                        } else
                                continue;
                }

                strv_remove(*domains, *domain);

                /* We removed one entry, make sure we don't skip the next one */
                domain--;
        }

        return 0;
}

int config_parse_tunnel(const char *unit,
                        const char *filename,
                        unsigned line,
                        const char *section,
                        unsigned section_line,
                        const char *lvalue,
                        int ltype,
                        const char *rvalue,
                        void *data,
                        void *userdata) {
        Network *network = userdata;
        NetDev *netdev;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = netdev_get(network->manager, rvalue, &netdev);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Tunnel is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (netdev->kind != NETDEV_KIND_IPIP &&
            netdev->kind != NETDEV_KIND_SIT &&
            netdev->kind != NETDEV_KIND_GRE &&
            netdev->kind != NETDEV_KIND_GRETAP &&
            netdev->kind != NETDEV_KIND_IP6GRE &&
            netdev->kind != NETDEV_KIND_IP6GRETAP &&
            netdev->kind != NETDEV_KIND_VTI &&
            netdev->kind != NETDEV_KIND_VTI6 &&
            netdev->kind != NETDEV_KIND_IP6TNL
            ) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "NetDev is not a tunnel, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = hashmap_put(network->stacked_netdevs, netdev->ifname, netdev);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Cannot add VLAN '%s' to network, ignoring: %m", rvalue);
                return 0;
        }

        netdev_ref(netdev);

        return 0;
}

int config_parse_ipv4ll(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        AddressFamilyBoolean *link_local = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* Note that this is mostly like
         * config_parse_address_family_boolean(), except that it
         * applies only to IPv4 */

        if (parse_boolean(rvalue))
                *link_local |= ADDRESS_FAMILY_IPV4;
        else
                *link_local &= ~ADDRESS_FAMILY_IPV4;

        return 0;
}

int config_parse_dhcp(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        AddressFamilyBoolean *dhcp = data, s;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* Note that this is mostly like
         * config_parse_address_family_boolean(), except that it
         * understands some old names for the enum values */

        s = address_family_boolean_from_string(rvalue);
        if (s < 0) {

                /* Previously, we had a slightly different enum here,
                 * support its values for compatbility. */

                if (streq(rvalue, "none"))
                        s = ADDRESS_FAMILY_NO;
                else if (streq(rvalue, "v4"))
                        s = ADDRESS_FAMILY_IPV4;
                else if (streq(rvalue, "v6"))
                        s = ADDRESS_FAMILY_IPV6;
                else if (streq(rvalue, "both"))
                        s = ADDRESS_FAMILY_YES;
                else {
                        log_syntax(unit, LOG_ERR, filename, line, s, "Failed to parse DHCP option, ignoring: %s", rvalue);
                        return 0;
                }
        }

        *dhcp = s;
        return 0;
}

static const char* const dhcp_client_identifier_table[_DHCP_CLIENT_ID_MAX] = {
        [DHCP_CLIENT_ID_MAC] = "mac",
        [DHCP_CLIENT_ID_DUID] = "duid"
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(dhcp_client_identifier, DCHPClientIdentifier);
DEFINE_CONFIG_PARSE_ENUM(config_parse_dhcp_client_identifier, dhcp_client_identifier, DCHPClientIdentifier, "Failed to parse client identifier type");

int config_parse_ipv6token(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        union in_addr_union buffer;
        struct in6_addr *token = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(token);

        r = in_addr_from_string(AF_INET6, rvalue, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse IPv6 token, ignoring: %s", rvalue);
                return 0;
        }

        r = in_addr_is_null(AF_INET6, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "IPv6 token can not be the ANY address, ignoring: %s", rvalue);
                return 0;
        }

        if ((buffer.in6.s6_addr32[0] | buffer.in6.s6_addr32[1]) != 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "IPv6 token can not be longer than 64 bits, ignoring: %s", rvalue);
                return 0;
        }

        *token = buffer.in6;

        return 0;
}

static const char* const ipv6_privacy_extensions_table[_IPV6_PRIVACY_EXTENSIONS_MAX] = {
        [IPV6_PRIVACY_EXTENSIONS_NO] = "no",
        [IPV6_PRIVACY_EXTENSIONS_PREFER_PUBLIC] = "prefer-public",
        [IPV6_PRIVACY_EXTENSIONS_YES] = "yes",
};

DEFINE_STRING_TABLE_LOOKUP(ipv6_privacy_extensions, IPv6PrivacyExtensions);

int config_parse_ipv6_privacy_extensions(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        IPv6PrivacyExtensions *ipv6_privacy_extensions = data;
        int k;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(ipv6_privacy_extensions);

        /* Our enum shall be a superset of booleans, hence first try
         * to parse as boolean, and then as enum */

        k = parse_boolean(rvalue);
        if (k > 0)
                *ipv6_privacy_extensions = IPV6_PRIVACY_EXTENSIONS_YES;
        else if (k == 0)
                *ipv6_privacy_extensions = IPV6_PRIVACY_EXTENSIONS_NO;
        else {
                IPv6PrivacyExtensions s;

                s = ipv6_privacy_extensions_from_string(rvalue);
                if (s < 0) {

                        if (streq(rvalue, "kernel"))
                                s = _IPV6_PRIVACY_EXTENSIONS_INVALID;
                        else {
                                log_syntax(unit, LOG_ERR, filename, line, s, "Failed to parse IPv6 privacy extensions option, ignoring: %s", rvalue);
                                return 0;
                        }
                }

                *ipv6_privacy_extensions = s;
        }

        return 0;
}

int config_parse_hostname(
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

        char **hostname = data, *hn = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = config_parse_string(unit, filename, line, section, section_line, lvalue, ltype, rvalue, &hn, userdata);
        if (r < 0)
                return r;

        if (!hostname_is_valid(hn, false)) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Hostname is not valid, ignoring assignment: %s", rvalue);
                free(hn);
                return 0;
        }

        free(*hostname);
        *hostname = hostname_cleanup(hn);
        return 0;
}

int config_parse_timezone(
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

        char **datap = data, *tz = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = config_parse_string(unit, filename, line, section, section_line, lvalue, ltype, rvalue, &tz, userdata);
        if (r < 0)
                return r;

        if (!timezone_is_valid(tz)) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Timezone is not valid, ignoring assignment: %s", rvalue);
                free(tz);
                return 0;
        }

        free(*datap);
        *datap = tz;

        return 0;
}

int config_parse_dhcp_server_dns(
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

        Network *n = data;
        const char *p = rvalue;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        for (;;) {
                _cleanup_free_ char *w = NULL;
                struct in_addr a, *m;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }

                if (r == 0)
                        return 0;

                if (inet_pton(AF_INET, w, &a) <= 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse DNS server address, ignoring: %s", w);
                        continue;
                }

                m = realloc(n->dhcp_server_dns, (n->n_dhcp_server_dns + 1) * sizeof(struct in_addr));
                if (!m)
                        return log_oom();

                m[n->n_dhcp_server_dns++] = a;
                n->dhcp_server_dns = m;
        }
}

int config_parse_dhcp_server_ntp(
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

        Network *n = data;
        const char *p = rvalue;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        for (;;) {
                _cleanup_free_ char *w = NULL;
                struct in_addr a, *m;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, r, line, "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }

                if (r == 0)
                        return 0;

                if (inet_pton(AF_INET, w, &a) <= 0) {
                        log_syntax(unit, LOG_ERR, filename, r, line, "Failed to parse NTP server address, ignoring: %s", w);
                        continue;
                }

                m = realloc(n->dhcp_server_ntp, (n->n_dhcp_server_ntp + 1) * sizeof(struct in_addr));
                if (!m)
                        return log_oom();

                m[n->n_dhcp_server_ntp++] = a;
                n->dhcp_server_ntp = m;
        }
}
