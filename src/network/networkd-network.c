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

#include "networkd.h"
#include "networkd-netdev.h"
#include "networkd-link.h"
#include "network-internal.h"
#include "path-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "util.h"

static int network_load_one(Manager *manager, const char *filename) {
        _cleanup_network_free_ Network *network = NULL;
        _cleanup_fclose_ FILE *file = NULL;
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

        network->stacked_netdevs = hashmap_new(&string_hash_ops);
        if (!network->stacked_netdevs)
                return log_oom();

        network->addresses_by_section = hashmap_new(NULL);
        if (!network->addresses_by_section)
                return log_oom();

        network->routes_by_section = hashmap_new(NULL);
        if (!network->routes_by_section)
                return log_oom();

        network->filename = strdup(filename);
        if (!network->filename)
                return log_oom();

        network->dhcp = DHCP_SUPPORT_NONE;
        network->dhcp_ntp = true;
        network->dhcp_dns = true;
        network->dhcp_hostname = true;
        network->dhcp_routes = true;
        network->dhcp_sendhost = true;
        network->dhcp_route_metric = DHCP_ROUTE_METRIC;

        network->llmnr = LLMNR_SUPPORT_YES;

        r = config_parse(NULL, filename, file,
                         "Match\0"
                         "Link\0"
                         "Network\0"
                         "Address\0"
                         "Route\0"
                         "DHCP\0"
                         "DHCPv4\0"
                         "Bridge\0",
                         config_item_perf_lookup, network_network_gperf_lookup,
                         false, false, true, network);
        if (r < 0)
                return r;

        LIST_PREPEND(networks, manager->networks, network);

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
        Iterator i;

        if (!network)
                return;

        free(network->filename);

        free(network->match_mac);
        free(network->match_path);
        free(network->match_driver);
        free(network->match_type);
        free(network->match_name);

        free(network->description);
        free(network->dhcp_vendor_class_identifier);

        free(network->mac);

        strv_free(network->ntp);
        strv_free(network->dns);
        strv_free(network->domains);

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

        hashmap_free(network->addresses_by_section);
        hashmap_free(network->routes_by_section);

        if (network->manager && network->manager->networks)
                LIST_REMOVE(networks, network->manager->networks, network);

        condition_free_list(network->match_host);
        condition_free_list(network->match_virt);
        condition_free_list(network->match_kernel);
        condition_free_list(network->match_arch);

        free(network);
}

int network_get(Manager *manager, struct udev_device *device,
                const char *ifname, const struct ether_addr *address,
                Network **ret) {
        Network *network;

        assert(manager);
        assert(ret);

        LIST_FOREACH(networks, network, manager->networks) {
                if (net_match_config(network->match_mac, network->match_path,
                                     network->match_driver, network->match_type,
                                     network->match_name, network->match_host,
                                     network->match_virt, network->match_kernel,
                                     network->match_arch,
                                     address,
                                     udev_device_get_property_value(device, "ID_PATH"),
                                     udev_device_get_driver(udev_device_get_parent(device)),
                                     udev_device_get_property_value(device, "ID_NET_DRIVER"),
                                     udev_device_get_devtype(device),
                                     ifname)) {
                        if (network->match_name) {
                                const char *attr;
                                uint8_t name_assign_type = NET_NAME_UNKNOWN;

                                attr = udev_device_get_sysattr_value(device, "name_assign_type");
                                if (attr)
                                        (void)safe_atou8(attr, &name_assign_type);

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
        case NETDEV_KIND_VXLAN:
                r = hashmap_put(network->stacked_netdevs, netdev->ifname, netdev);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Can not add VLAN '%s' to network: %s",
                                   rvalue, strerror(-r));
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
                else if (!hostname_is_valid(*domain)) {
                        if (!streq(*domain, "*"))
                                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "domain name is not valid, ignoring assignment: %s", *domain);
                } else
                        continue;

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
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Tunnel is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (netdev->kind != NETDEV_KIND_IPIP &&
            netdev->kind != NETDEV_KIND_SIT &&
            netdev->kind != NETDEV_KIND_GRE &&
            netdev->kind != NETDEV_KIND_VTI) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "NetDev is not a tunnel, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = hashmap_put(network->stacked_netdevs, netdev->ifname, netdev);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Can not add VLAN '%s' to network: %s",
                           rvalue, strerror(-r));
                return 0;
        }

        netdev_ref(netdev);

        return 0;
}

static const char* const dhcp_support_table[_DHCP_SUPPORT_MAX] = {
        [DHCP_SUPPORT_NONE] = "none",
        [DHCP_SUPPORT_BOTH] = "both",
        [DHCP_SUPPORT_V4] = "v4",
        [DHCP_SUPPORT_V6] = "v6",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp_support, DHCPSupport);

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

        DHCPSupport *dhcp = data;
        int k;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* Our enum shall be a superset of booleans, hence first try
         * to parse as boolean, and then as enum */

        k = parse_boolean(rvalue);
        if (k > 0)
                *dhcp = DHCP_SUPPORT_BOTH;
        else if (k == 0)
                *dhcp = DHCP_SUPPORT_NONE;
        else {
                DHCPSupport s;

                s = dhcp_support_from_string(rvalue);
                if (s < 0){
                        log_syntax(unit, LOG_ERR, filename, line, -s, "Failed to parse DHCP option, ignoring: %s", rvalue);
                        return 0;
                }

                *dhcp = s;
        }

        return 0;
}

static const char* const llmnr_support_table[_LLMNR_SUPPORT_MAX] = {
        [LLMNR_SUPPORT_NO] = "no",
        [LLMNR_SUPPORT_YES] = "yes",
        [LLMNR_SUPPORT_RESOLVE] = "resolve",
};

DEFINE_STRING_TABLE_LOOKUP(llmnr_support, LLMNRSupport);

int config_parse_llmnr(
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

        LLMNRSupport *llmnr = data;
        int k;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* Our enum shall be a superset of booleans, hence first try
         * to parse as boolean, and then as enum */

        k = parse_boolean(rvalue);
        if (k > 0)
                *llmnr = LLMNR_SUPPORT_YES;
        else if (k == 0)
                *llmnr = LLMNR_SUPPORT_NO;
        else {
                LLMNRSupport s;

                s = llmnr_support_from_string(rvalue);
                if (s < 0){
                        log_syntax(unit, LOG_ERR, filename, line, -s, "Failed to parse LLMNR option, ignoring: %s", rvalue);
                        return 0;
                }

                *llmnr = s;
        }

        return 0;
}
