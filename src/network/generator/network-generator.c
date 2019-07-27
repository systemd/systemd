/* SPDX-License-Identifier: LGPL-2.1+ */

#include "ether-addr-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hostname-util.h"
#include "log.h"
#include "macro.h"
#include "network-generator.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

/*
  # .network
  ip={dhcp|on|any|dhcp6|auto6|either6}
  ip=<interface>:{dhcp|on|any|dhcp6|auto6}[:[<mtu>][:<macaddr>]]
  ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}[:[<mtu>][:<macaddr>]]
  ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}[:[<dns1>][:<dns2>]]
  rd.route=<net>/<netmask>:<gateway>[:<interface>]
  nameserver=<IP> [nameserver=<IP> ...]
  rd.peerdns=0

  # .link
  ifname=<interface>:<MAC>

  # .netdev
  vlan=<vlanname>:<phydevice>
  bond=<bondname>[:<bondslaves>:[:<options>[:<mtu>]]]
  team=<teammaster>:<teamslaves> # not supported
  bridge=<bridgename>:<ethnames>

  # ignored
  bootdev=<interface>
  BOOTIF=<MAC>
  rd.bootif=0
  biosdevname=0
  rd.neednet=1
*/

static const char * const dracut_dhcp_type_table[_DHCP_TYPE_MAX] = {
        [DHCP_TYPE_NONE]    = "none",
        [DHCP_TYPE_OFF]     = "off",
        [DHCP_TYPE_ON]      = "on",
        [DHCP_TYPE_ANY]     = "any",
        [DHCP_TYPE_DHCP]    = "dhcp",
        [DHCP_TYPE_DHCP6]   = "dhcp6",
        [DHCP_TYPE_AUTO6]   = "auto6",
        [DHCP_TYPE_EITHER6] = "either6",
        [DHCP_TYPE_IBFT]    = "ibft",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(dracut_dhcp_type, DHCPType);

static const char * const networkd_dhcp_type_table[_DHCP_TYPE_MAX] = {
        [DHCP_TYPE_NONE]    = "no",
        [DHCP_TYPE_OFF]     = "no",
        [DHCP_TYPE_ON]      = "yes",
        [DHCP_TYPE_ANY]     = "yes",
        [DHCP_TYPE_DHCP]    = "ipv4",
        [DHCP_TYPE_DHCP6]   = "ipv6",
        [DHCP_TYPE_AUTO6]   = "no",   /* TODO: enable other setting? */
        [DHCP_TYPE_EITHER6] = "ipv6", /* TODO: enable other setting? */
        [DHCP_TYPE_IBFT]    = "no",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(networkd_dhcp_type, DHCPType);

static Address *address_free(Address *address) {
        if (!address)
                return NULL;

        if (address->network)
                LIST_REMOVE(addresses, address->network->addresses, address);

        return mfree(address);
}

static int address_new(Network *network, int family, unsigned char prefixlen,
                       union in_addr_union *addr, union in_addr_union *peer, Address **ret) {
        Address *address;

        assert(network);

        address = new(Address, 1);
        if (!address)
                return -ENOMEM;

        *address = (Address) {
                .family = family,
                .prefixlen = prefixlen,
                .address = *addr,
                .peer = *peer,
        };

        LIST_PREPEND(addresses, network->addresses, address);

        address->network = network;

        if (ret)
                *ret = address;
        return 0;
}

static Route *route_free(Route *route) {
        if (!route)
                return NULL;

        if (route->network)
                LIST_REMOVE(routes, route->network->routes, route);

        return mfree(route);
}

static int route_new(Network *network, int family, unsigned char prefixlen,
                     union in_addr_union *dest, union in_addr_union *gateway, Route **ret) {
        Route *route;

        assert(network);

        route = new(Route, 1);
        if (!route)
                return -ENOMEM;

        *route = (Route) {
                .family = family,
                .prefixlen = prefixlen,
                .dest = dest ? *dest : IN_ADDR_NULL,
                .gateway = *gateway,
        };

        LIST_PREPEND(routes, network->routes, route);

        route->network = network;

        if (ret)
                *ret = route;
        return 0;
}

static Network *network_free(Network *network) {
        Address *address;
        Route *route;

        if (!network)
                return NULL;

        free(network->ifname);
        free(network->hostname);
        strv_free(network->dns);
        free(network->vlan);
        free(network->bridge);
        free(network->bond);

        while ((address = network->addresses))
                address_free(address);

        while ((route = network->routes))
                route_free(route);

        return mfree(network);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Network*, network_free);

static int network_new(Context *context, const char *name, Network **ret) {
        _cleanup_(network_freep) Network *network = NULL;
        _cleanup_free_ char *ifname = NULL;
        int r;

        assert(context);

        if (!isempty(name) && !ifname_valid(name))
                return -EINVAL;

        ifname = strdup(name);
        if (!ifname)
                return -ENOMEM;

        network = new(Network, 1);
        if (!network)
                return -ENOMEM;

        *network = (Network) {
                .ifname = TAKE_PTR(ifname),
                .dhcp_type = _DHCP_TYPE_INVALID,
                .dhcp_use_dns = -1,
        };

        r = hashmap_ensure_allocated(&context->networks_by_name, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_put(context->networks_by_name, network->ifname, network);
        if (r < 0)
                return r;

        if (ret)
                *ret = network;

        TAKE_PTR(network);
        return 0;
}

Network *network_get(Context *context, const char *ifname) {
        return hashmap_get(context->networks_by_name, ifname);
}

static NetDev *netdev_free(NetDev *netdev) {
        if (!netdev)
                return NULL;

        free(netdev->ifname);
        free(netdev->kind);
        return mfree(netdev);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(NetDev*, netdev_free);

static int netdev_new(Context *context, const char *_kind, const char *_ifname, NetDev **ret) {
        _cleanup_(netdev_freep) NetDev *netdev = NULL;
        _cleanup_free_ char *kind = NULL, *ifname = NULL;
        int r;

        assert(context);

        if (!ifname_valid(_ifname))
                return -EINVAL;

        kind = strdup(_kind);
        if (!kind)
                return -ENOMEM;

        ifname = strdup(_ifname);
        if (!ifname)
                return -ENOMEM;

        netdev = new(NetDev, 1);
        if (!netdev)
                return -ENOMEM;

        *netdev = (NetDev) {
                .kind = TAKE_PTR(kind),
                .ifname = TAKE_PTR(ifname),
        };

        r = hashmap_ensure_allocated(&context->netdevs_by_name, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_put(context->netdevs_by_name, netdev->ifname, netdev);
        if (r < 0)
                return r;

        if (ret)
                *ret = netdev;

        TAKE_PTR(netdev);
        return 0;
}

NetDev *netdev_get(Context *context, const char *ifname) {
        return hashmap_get(context->netdevs_by_name, ifname);
}

static Link *link_free(Link *link) {
        if (!link)
                return NULL;

        free(link->ifname);
        return mfree(link);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Link*, link_free);

static int link_new(Context *context, const char *name, struct ether_addr *mac, Link **ret) {
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_free_ char *ifname = NULL;
        int r;

        assert(context);

        if (!ifname_valid(name))
                return -EINVAL;

        ifname = strdup(name);
        if (!ifname)
                return -ENOMEM;

        link = new(Link, 1);
        if (!link)
                return -ENOMEM;

        *link = (Link) {
                .ifname = TAKE_PTR(ifname),
                .mac = *mac,
        };

        r = hashmap_ensure_allocated(&context->links_by_name, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_put(context->links_by_name, link->ifname, link);
        if (r < 0)
                return r;

        if (ret)
                *ret = link;

        TAKE_PTR(link);
        return 0;
}

Link *link_get(Context *context, const char *ifname) {
        return hashmap_get(context->links_by_name, ifname);
}

static int network_set_dhcp_type(Context *context, const char *ifname, const char *dhcp_type) {
        Network *network;
        DHCPType t;
        int r;

        t = dracut_dhcp_type_from_string(dhcp_type);
        if (t < 0)
                return -EINVAL;

        network = network_get(context, ifname);
        if (!network) {
                r = network_new(context, ifname, &network);
                if (r < 0)
                        return r;
        }

        network->dhcp_type = t;
        return 0;
}

static int network_set_hostname(Context *context, const char *ifname, const char *hostname) {
        Network *network;

        network = network_get(context, ifname);
        if (!network)
                return -ENODEV;

        return free_and_strdup(&network->hostname, hostname);
}

static int network_set_mtu(Context *context, const char *ifname, int family, const char *mtu) {
        Network *network;

        network = network_get(context, ifname);
        if (!network)
                return -ENODEV;

        return parse_mtu(family, mtu, &network->mtu);
}

static int network_set_mac_address(Context *context, const char *ifname, const char *mac) {
        Network *network;

        network = network_get(context, ifname);
        if (!network)
                return -ENODEV;

        return ether_addr_from_string(mac, &network->mac);
}

static int network_set_address(Context *context, const char *ifname, int family, unsigned char prefixlen,
                               union in_addr_union *addr, union in_addr_union *peer) {
        Network *network;

        if (in_addr_is_null(family, addr) != 0)
                return 0;

        network = network_get(context, ifname);
        if (!network)
                return -ENODEV;

        return address_new(network, family, prefixlen, addr, peer, NULL);
}

static int network_set_route(Context *context, const char *ifname, int family, unsigned char prefixlen,
                             union in_addr_union *dest, union in_addr_union *gateway) {
        Network *network;
        int r;

        if (in_addr_is_null(family, gateway) != 0)
                return 0;

        network = network_get(context, ifname);
        if (!network) {
                r = network_new(context, ifname, &network);
                if (r < 0)
                        return r;
        }

        return route_new(network, family, prefixlen, dest, gateway, NULL);
}

static int network_set_dns(Context *context, const char *ifname, const char *dns) {
        union in_addr_union a;
        Network *network;
        int family, r;

        r = in_addr_from_string_auto(dns, &family, &a);
        if (r < 0)
                return r;

        network = network_get(context, ifname);
        if (!network) {
                r = network_new(context, ifname, &network);
                if (r < 0)
                        return r;
        }

        return strv_extend(&network->dns, dns);
}

static int network_set_dhcp_use_dns(Context *context, const char *ifname, bool value) {
        Network *network;
        int r;

        network = network_get(context, ifname);
        if (!network) {
                r = network_new(context, ifname, &network);
                if (r < 0)
                        return r;
        }

        network->dhcp_use_dns = value;

        return 0;
}

static int network_set_vlan(Context *context, const char *ifname, const char *value) {
        Network *network;
        int r;

        network = network_get(context, ifname);
        if (!network) {
                r = network_new(context, ifname, &network);
                if (r < 0)
                        return r;
        }

        return free_and_strdup(&network->vlan, value);
}

static int network_set_bridge(Context *context, const char *ifname, const char *value) {
        Network *network;
        int r;

        network = network_get(context, ifname);
        if (!network) {
                r = network_new(context, ifname, &network);
                if (r < 0)
                        return r;
        }

        return free_and_strdup(&network->bridge, value);
}

static int network_set_bond(Context *context, const char *ifname, const char *value) {
        Network *network;
        int r;

        network = network_get(context, ifname);
        if (!network) {
                r = network_new(context, ifname, &network);
                if (r < 0)
                        return r;
        }

        return free_and_strdup(&network->bond, value);
}

static int parse_cmdline_ip_mtu_mac(Context *context, const char *ifname, int family, const char *value) {
        const char *mtu, *p;
        int r;

        /* [<mtu>][:<macaddr>] */

        p = strchr(value, ':');
        if (!p)
                mtu = value;
        else
                mtu = strndupa(value, p - value);

        r = network_set_mtu(context, ifname, family, mtu);
        if (r < 0)
                return r;

        if (!p)
                return 0;

        r = network_set_mac_address(context, ifname, p + 1);
        if (r < 0)
                return r;

        return 0;
}

static int parse_ip_address_one(int family, const char **value, union in_addr_union *ret) {
        const char *p = *value, *q, *buf;
        int r;

        if (p[0] == ':') {
                *value = p + 1;
                return 0;
        }

        if (family == AF_INET6) {
                if (p[0] != '[')
                        return -EINVAL;

                q = strchr(p + 1, ']');
                if (!q)
                        return -EINVAL;

                if (q[1] != ':')
                        return -EINVAL;

                buf = strndupa(p + 1, q - p - 1);
                p = q + 2;
        } else {
                q = strchr(p, ':');
                if (!q)
                        return -EINVAL;

                buf = strndupa(p, q - p);
                p = q + 1;
        }

        r = in_addr_from_string(family, buf, ret);
        if (r < 0)
                return r;

        *value = p;
        return 1;
}

static int parse_netmask_or_prefixlen(int family, const char **value, unsigned char *ret) {
        union in_addr_union netmask;
        const char *p, *q;
        int r;

        r = parse_ip_address_one(family, value, &netmask);
        if (r > 0) {
                if (family == AF_INET6)
                        /* TODO: Not supported yet. */
                        return -EINVAL;

                *ret = in4_addr_netmask_to_prefixlen(&netmask.in);
        } else if (r == 0)
                *ret = family == AF_INET6 ? 128 : 32;
        else {
                p = strchr(*value, ':');
                if (!p)
                        return -EINVAL;

                q = strndupa(*value, p - *value);
                r = safe_atou8(q, ret);
                if (r < 0)
                        return r;

                *value = p + 1;
        }

        return 0;
}

static int parse_cmdline_ip_address(Context *context, int family, const char *value) {
        union in_addr_union addr = {}, peer = {}, gateway = {};
        const char *hostname, *ifname, *dhcp_type, *dns, *p;
        unsigned char prefixlen;
        int r;

        /* ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}[:[<mtu>][:<macaddr>]]
         * ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}[:[<dns1>][:<dns2>]] */

        r = parse_ip_address_one(family, &value, &addr);
        if (r < 0)
                return r;
        r = parse_ip_address_one(family, &value, &peer);
        if (r < 0)
                return r;
        r = parse_ip_address_one(family, &value, &gateway);
        if (r < 0)
                return r;
        r = parse_netmask_or_prefixlen(family, &value, &prefixlen);
        if (r < 0)
                return r;

        /* hostname */
        p = strchr(value, ':');
        if (!p)
                return -EINVAL;

        hostname = strndupa(value, p - value);
        if (!hostname_is_valid(hostname, false))
                return -EINVAL;

        value = p + 1;

        /* ifname */
        p = strchr(value, ':');
        if (!p)
                return -EINVAL;

        ifname = strndupa(value, p - value);

        value = p + 1;

        /* dhcp_type */
        p = strchr(value, ':');
        if (!p)
                dhcp_type = value;
        else
                dhcp_type = strndupa(value, p - value);

        r = network_set_dhcp_type(context, ifname, dhcp_type);
        if (r < 0)
                return r;

        /* set values */
        r = network_set_hostname(context, ifname, hostname);
        if (r < 0)
                return r;

        r = network_set_address(context, ifname, family, prefixlen, &addr, &peer);
        if (r < 0)
                return r;

        r = network_set_route(context, ifname, family, 0, NULL, &gateway);
        if (r < 0)
                return r;

        if (!p)
                return 0;

        /* First, try [<mtu>][:<macaddr>] */
        r = parse_cmdline_ip_mtu_mac(context, ifname, AF_UNSPEC, p + 1);
        if (r >= 0)
                return 0;

        /* Next, try [<dns1>][:<dns2>] */
        value = p + 1;
        p = strchr(value, ':');
        if (!p) {
                r = network_set_dns(context, ifname, value);
                if (r < 0)
                        return r;
        } else {
                dns = strndupa(value, p - value);
                r = network_set_dns(context, ifname, dns);
                if (r < 0)
                        return r;
                r = network_set_dns(context, ifname, p + 1);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int parse_cmdline_ip_interface(Context *context, const char *value) {
        const char *ifname, *dhcp_type, *p;
        int r;

        /* ip=<interface>:{dhcp|on|any|dhcp6|auto6}[:[<mtu>][:<macaddr>]] */

        p = strchr(value, ':');
        if (!p)
                return -EINVAL;

        ifname = strndupa(value, p - value);

        value = p + 1;
        p = strchr(value, ':');
        if (!p)
                dhcp_type = value;
        else
                dhcp_type = strndupa(value, p - value);

        r = network_set_dhcp_type(context, ifname, dhcp_type);
        if (r < 0)
                return r;

        if (!p)
                return 0;

        return parse_cmdline_ip_mtu_mac(context, ifname, AF_UNSPEC, p + 1);
}

static int parse_cmdline_ip(Context *context, const char *key, const char *value) {
        const char *p;
        int r;

        if (proc_cmdline_value_missing(key, value))
                return -EINVAL;

        p = strchr(value, ':');
        if (!p)
                /* ip={dhcp|on|any|dhcp6|auto6|either6} */
                return network_set_dhcp_type(context, "", value);

        if (value[0] == '[')
                return parse_cmdline_ip_address(context, AF_INET6, value);

        r = parse_cmdline_ip_address(context, AF_INET, value);
        if (r < 0)
                return parse_cmdline_ip_interface(context, value);

        return 0;
}

static int parse_cmdline_rd_route(Context *context, const char *key, const char *value) {
        union in_addr_union addr = {}, gateway = {};
        unsigned char prefixlen;
        const char *buf, *p;
        int family, r;

        /* rd.route=<net>/<netmask>:<gateway>[:<interface>] */

        if (proc_cmdline_value_missing(key, value))
                return -EINVAL;

        if (value[0] == '[') {
                p = strchr(value, ']');
                if (!p)
                        return -EINVAL;

                if (p[1] != ':')
                        return -EINVAL;

                buf = strndupa(value + 1, p - value - 1);
                value = p + 2;
                family = AF_INET6;
        } else {
                p = strchr(value, ':');
                if (!p)
                        return -EINVAL;

                buf = strndupa(value, p - value);
                value = p + 1;
                family = AF_INET;
        }

        r = in_addr_prefix_from_string(buf, family, &addr, &prefixlen);
        if (r < 0)
                return r;

        p = strchr(value, ':');
        if (!p)
                value = strjoina(value, ":");

        r = parse_ip_address_one(family, &value, &gateway);
        if (r < 0)
                return r;

        return network_set_route(context, value, family, prefixlen, &addr, &gateway);
}

static int parse_cmdline_nameserver(Context *context, const char *key, const char *value) {
        if (proc_cmdline_value_missing(key, value))
                return -EINVAL;

        return network_set_dns(context, "", value);
}

static int parse_cmdline_rd_peerdns(Context *context, const char *key, const char *value) {
        int r;

        if (proc_cmdline_value_missing(key, value))
                return network_set_dhcp_use_dns(context, "", true);

        r = parse_boolean(value);
        if (r < 0)
                return r;

        return network_set_dhcp_use_dns(context, "", r);
}

static int parse_cmdline_vlan(Context *context, const char *key, const char *value) {
        const char *name, *p;
        NetDev *netdev;
        int r;

        if (proc_cmdline_value_missing(key, value))
                return -EINVAL;

        p = strchr(value, ':');
        if (!p)
                return -EINVAL;

        name = strndupa(value, p - value);

        netdev = netdev_get(context, name);
        if (!netdev) {
                r = netdev_new(context, "vlan", name, &netdev);
                if (r < 0)
                        return r;
        }

        return network_set_vlan(context, p + 1, name);
}

static int parse_cmdline_bridge(Context *context, const char *key, const char *value) {
        const char *name, *p;
        NetDev *netdev;
        int r;

        if (proc_cmdline_value_missing(key, value))
                return -EINVAL;

        p = strchr(value, ':');
        if (!p)
                return -EINVAL;

        name = strndupa(value, p - value);

        netdev = netdev_get(context, name);
        if (!netdev) {
                r = netdev_new(context, "bridge", name, &netdev);
                if (r < 0)
                        return r;
        }

        p++;
        if (isempty(p))
                return -EINVAL;

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, ",", 0);
                if (r == 0)
                        return 0;
                if (r < 0)
                        return r;

                r = network_set_bridge(context, word, name);
                if (r < 0)
                        return r;
        }
}

static int parse_cmdline_bond(Context *context, const char *key, const char *value) {
        const char *name, *slaves, *p;
        NetDev *netdev;
        int r;

        if (proc_cmdline_value_missing(key, value))
                return -EINVAL;

        p = strchr(value, ':');
        if (!p)
                return -EINVAL;

        name = strndupa(value, p - value);

        netdev = netdev_get(context, name);
        if (!netdev) {
                r = netdev_new(context, "bond", name, &netdev);
                if (r < 0)
                        return r;
        }

        value = p + 1;
        p = strchr(value, ':');
        if (!p)
                slaves = value;
        else
                slaves = strndupa(value, p - value);

        if (isempty(slaves))
                return -EINVAL;

        for (const char *q = slaves; ; ) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&q, &word, ",", 0);
                if (r == 0)
                        break;
                if (r < 0)
                        return r;

                r = network_set_bond(context, word, name);
                if (r < 0)
                        return r;
        }

        if (!p)
                return 0;

        value = p + 1;
        p = strchr(value, ':');
        if (!p)
                /* TODO: set bonding options */
                return 0;

        return parse_mtu(AF_UNSPEC, p + 1, &netdev->mtu);
}

static int parse_cmdline_ifname(Context *context, const char *key, const char *value) {
        struct ether_addr mac;
        const char *name, *p;
        int r;

        /* ifname=<interface>:<MAC> */

        if (proc_cmdline_value_missing(key, value))
                return -EINVAL;

        p = strchr(value, ':');
        if (!p)
                return -EINVAL;

        name = strndupa(value, p - value);

        r = ether_addr_from_string(p + 1, &mac);
        if (r < 0)
                return r;

        return link_new(context, name, &mac, NULL);
}

int parse_cmdline_item(const char *key, const char *value, void *data) {
        Context *context = data;

        assert(key);
        assert(data);

        if (streq(key, "ip"))
                return parse_cmdline_ip(context, key, value);
        if (streq(key, "rd.route"))
                return parse_cmdline_rd_route(context, key, value);
        if (streq(key, "nameserver"))
                return parse_cmdline_nameserver(context, key, value);
        if (streq(key, "rd.peerdns"))
                return parse_cmdline_rd_peerdns(context, key, value);
        if (streq(key, "vlan"))
                return parse_cmdline_vlan(context, key, value);
        if (streq(key, "bridge"))
                return parse_cmdline_bridge(context, key, value);
        if (streq(key, "bond"))
                return parse_cmdline_bond(context, key, value);
        if (streq(key, "ifname"))
                return parse_cmdline_ifname(context, key, value);

        return 0;
}

int context_merge_networks(Context *context) {
        Network *all, *network;
        Route *route;
        Iterator i;
        int r;

        assert(context);

        /* Copy settings about the following options
           rd.route=<net>/<netmask>:<gateway>[:<interface>]
           nameserver=<IP> [nameserver=<IP> ...]
           rd.peerdns=0 */

        all = network_get(context, "");
        if (!all)
                return 0;

        if (hashmap_size(context->networks_by_name) <= 1)
                return 0;

        HASHMAP_FOREACH(network, context->networks_by_name, i) {
                if (network == all)
                        continue;

                network->dhcp_use_dns = all->dhcp_use_dns;

                r = strv_extend_strv(&network->dns, all->dns, false);
                if (r < 0)
                        return r;

                LIST_FOREACH(routes, route, all->routes) {
                        r = route_new(network, route->family, route->prefixlen, &route->dest, &route->gateway, NULL);
                        if (r < 0)
                                return r;
                }
        }

        assert_se(hashmap_remove(context->networks_by_name, "") == all);
        network_free(all);
        return 0;
}

void context_clear(Context *context) {
        if (!context)
                return;

        hashmap_free_with_destructor(context->networks_by_name, network_free);
        hashmap_free_with_destructor(context->netdevs_by_name, netdev_free);
        hashmap_free_with_destructor(context->links_by_name, link_free);
}

static int address_dump(Address *address, FILE *f) {
        _cleanup_free_ char *addr = NULL, *peer = NULL;
        int r;

        r = in_addr_prefix_to_string(address->family, &address->address, address->prefixlen, &addr);
        if (r < 0)
                return r;

        if (in_addr_is_null(address->family, &address->peer) == 0) {
                r = in_addr_to_string(address->family, &address->peer, &peer);
                if (r < 0)
                        return r;
        }

        fprintf(f,
                "\n[Address]\n"
                "Address=%s\n",
                addr);

        if (peer)
                fprintf(f, "Peer=%s\n", peer);

        return 0;
}

static int route_dump(Route *route, FILE *f) {
        _cleanup_free_ char *dest = NULL, *gateway = NULL;
        int r;

        if (in_addr_is_null(route->family, &route->dest) == 0) {
                r = in_addr_prefix_to_string(route->family, &route->dest, route->prefixlen, &dest);
                if (r < 0)
                        return r;
        }

        r = in_addr_to_string(route->family, &route->gateway, &gateway);
        if (r < 0)
                return r;

        fputs("\n[Route]\n", f);
        if (dest)
                fprintf(f, "Destination=%s\n", dest);
        fprintf(f, "Gateway=%s\n", gateway);

        return 0;
}

void network_dump(Network *network, FILE *f) {
        char mac[ETHER_ADDR_TO_STRING_MAX];
        Address *address;
        Route *route;
        const char *dhcp;
        char **dns;

        assert(network);
        assert(f);

        fprintf(f,
                "[Match]\n"
                "Name=%s\n",
                isempty(network->ifname) ? "*" : network->ifname);

        fputs("\n[Link]\n", f);

        if (!ether_addr_is_null(&network->mac))
                fprintf(f, "MACAddress=%s\n", ether_addr_to_string(&network->mac, mac));
        if (network->mtu > 0)
                fprintf(f, "MTUBytes=%" PRIu32 "\n", network->mtu);

        fputs("\n[Network]\n", f);

        dhcp = networkd_dhcp_type_to_string(network->dhcp_type);
        if (dhcp)
                fprintf(f, "DHCP=%s\n", dhcp);

        if (!strv_isempty(network->dns))
                STRV_FOREACH(dns, network->dns)
                        fprintf(f, "DNS=%s\n", *dns);

        if (network->vlan)
                fprintf(f, "VLAN=%s\n", network->vlan);

        if (network->bridge)
                fprintf(f, "Bridge=%s\n", network->bridge);

        if (network->bond)
                fprintf(f, "Bond=%s\n", network->bond);

        fputs("\n[DHCP]\n", f);

        if (!isempty(network->hostname))
                fprintf(f, "Hostname=%s\n", network->hostname);

        if (network->dhcp_use_dns >= 0)
                fprintf(f, "UseDNS=%s\n", yes_no(network->dhcp_use_dns));

        LIST_FOREACH(addresses, address, network->addresses)
                (void) address_dump(address, f);

        LIST_FOREACH(routes, route, network->routes)
                (void) route_dump(route, f);
}

void netdev_dump(NetDev *netdev, FILE *f) {
        assert(netdev);
        assert(f);

        fprintf(f,
                "[NetDev]\n"
                "Kind=%s\n"
                "Name=%s\n",
                netdev->kind,
                netdev->ifname);

        if (netdev->mtu > 0)
                fprintf(f, "MTUBytes=%" PRIu32 "\n", netdev->mtu);
}

void link_dump(Link *link, FILE *f) {
        char mac[ETHER_ADDR_TO_STRING_MAX];

        assert(link);
        assert(f);

        fputs("[Match]\n", f);

        if (!ether_addr_is_null(&link->mac))
                fprintf(f, "MACAddress=%s\n", ether_addr_to_string(&link->mac, mac));

        fprintf(f,
                "\n[Link]\n"
                "Name=%s\n",
                link->ifname);
}

int network_format(Network *network, char **ret) {
        _cleanup_free_ char *s = NULL;
        size_t sz = 0;
        int r;

        assert(network);
        assert(ret);

        {
                _cleanup_fclose_ FILE *f = NULL;

                f = open_memstream_unlocked(&s, &sz);
                if (!f)
                        return -ENOMEM;

                network_dump(network, f);

                /* Add terminating 0, so that the output buffer is a valid string. */
                fputc('\0', f);

                r = fflush_and_check(f);
        }
        if (r < 0)
                return r;

        assert(s);
        *ret = TAKE_PTR(s);
        assert(sz > 0);
        return (int) sz - 1;
}

int netdev_format(NetDev *netdev, char **ret) {
        _cleanup_free_ char *s = NULL;
        size_t sz = 0;
        int r;

        assert(netdev);
        assert(ret);

        {
                _cleanup_fclose_ FILE *f = NULL;

                f = open_memstream_unlocked(&s, &sz);
                if (!f)
                        return -ENOMEM;

                netdev_dump(netdev, f);

                /* Add terminating 0, so that the output buffer is a valid string. */
                fputc('\0', f);

                r = fflush_and_check(f);
        }
        if (r < 0)
                return r;

        assert(s);
        *ret = TAKE_PTR(s);
        assert(sz > 0);
        return (int) sz - 1;
}

int link_format(Link *link, char **ret) {
        _cleanup_free_ char *s = NULL;
        size_t sz = 0;
        int r;

        assert(link);
        assert(ret);

        {
                _cleanup_fclose_ FILE *f = NULL;

                f = open_memstream_unlocked(&s, &sz);
                if (!f)
                        return -ENOMEM;

                link_dump(link, f);

                /* Add terminating 0, so that the output buffer is a valid string. */
                fputc('\0', f);

                r = fflush_and_check(f);
        }
        if (r < 0)
                return r;

        assert(s);
        *ret = TAKE_PTR(s);
        assert(sz > 0);
        return (int) sz - 1;
}
