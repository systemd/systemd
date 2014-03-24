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

#include "networkd.h"
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
                        return errno;
        }

        network = new0(Network, 1);
        if (!network)
                return log_oom();

        network->manager = manager;

        LIST_HEAD_INIT(network->static_addresses);
        LIST_HEAD_INIT(network->static_routes);

        network->vlans = hashmap_new(string_hash_func, string_compare_func);
        if (!network->vlans)
                return log_oom();

        network->macvlans = hashmap_new(uint64_hash_func, uint64_compare_func);
        if (!network->macvlans)
                return log_oom();

        network->addresses_by_section = hashmap_new(uint64_hash_func, uint64_compare_func);
        if (!network->addresses_by_section)
                return log_oom();

        network->routes_by_section = hashmap_new(uint64_hash_func, uint64_compare_func);
        if (!network->routes_by_section)
                return log_oom();

        network->dns = set_new(NULL, NULL);
        if (!network->dns)
                return log_oom();

        network->filename = strdup(filename);
        if (!network->filename)
                return log_oom();

        network->dhcp_dns = true;
        network->dhcp_hostname = true;
        network->dhcp_domainname = true;

        r = config_parse(NULL, filename, file, "Match\0Network\0Address\0Route\0DHCPv4\0", config_item_perf_lookup,
                        (void*) network_network_gperf_lookup, false, false, network);
        if (r < 0) {
                log_warning("Could not parse config file %s: %s", filename, strerror(-r));
                return r;
        }

        LIST_PREPEND(networks, manager->networks, network);

        LIST_FOREACH(static_routes, route, network->static_routes) {
                if (!route->family) {
                        log_warning("Route section without Gateway field configured in %s. "
                                    "Ignoring", filename);
                        return 0;
                }
        }

        LIST_FOREACH(static_addresses, address, network->static_addresses) {
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
        if (r < 0) {
                log_error("Failed to enumerate network files: %s", strerror(-r));
                return r;
        }

        STRV_FOREACH_BACKWARDS(f, files) {
                r = network_load_one(manager, *f);
                if (r < 0)
                        return r;
        }

        return 0;
}

void network_free(Network *network) {
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

        SET_FOREACH(address, network->dns, i)
                address_free(address);

        set_free(network->dns);

        hashmap_free(network->vlans);

        hashmap_free(network->macvlans);

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

int network_get(Manager *manager, struct udev_device *device, Network **ret) {
        Network *network;

        assert(manager);
        assert(device);
        assert(ret);

        LIST_FOREACH(networks, network, manager->networks) {
                if (net_match_config(network->match_mac, network->match_path,
                                        network->match_driver, network->match_type,
                                        network->match_name, network->match_host,
                                        network->match_virt, network->match_kernel,
                                        network->match_arch,
                                        udev_device_get_sysattr_value(device, "address"),
                                        udev_device_get_property_value(device, "ID_PATH"),
                                        udev_device_get_driver(udev_device_get_parent(device)),
                                        udev_device_get_property_value(device, "ID_NET_DRIVER"),
                                        udev_device_get_devtype(device),
                                        udev_device_get_sysname(device))) {
                        log_debug("%s: found matching network '%s'",
                                        udev_device_get_sysname(device),
                                        network->filename);
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

        if (network->dns) {
                r = manager_update_resolv_conf(manager);
                if (r < 0)
                        return r;
        }

        return 0;
}

int config_parse_bridge(const char *unit,
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
                           "Bridge is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (netdev->kind != NETDEV_KIND_BRIDGE) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "NetDev is not a bridge, ignoring assignment: %s", rvalue);
                return 0;
        }

        network->bridge = netdev;

        return 0;
}

int config_parse_bond(const char *unit,
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
                           "Bond is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (netdev->kind != NETDEV_KIND_BOND) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "NetDev is not a bond, ignoring assignment: %s", rvalue);
                return 0;
        }

        network->bond = netdev;

        return 0;
}

int config_parse_vlan(const char *unit,
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
                           "VLAN is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (netdev->kind != NETDEV_KIND_VLAN) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "NetDev is not a VLAN, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = hashmap_put(network->vlans, &netdev->vlanid, netdev);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Can not add VLAN to network: %s", rvalue);
                return 0;
        }

        return 0;
}

int config_parse_macvlan(const char *unit,
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
                           "MACVLAN is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (netdev->kind != NETDEV_KIND_MACVLAN) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "NetDev is not a MACVLAN, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = hashmap_put(network->macvlans, netdev->name, netdev);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Can not add MACVLAN to network: %s", rvalue);
                return 0;
        }

        return 0;
}
