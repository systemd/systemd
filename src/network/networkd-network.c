/* SPDX-License-Identifier: LGPL-2.1+ */

#include <ctype.h>
#include <net/if.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "missing_network.h"
#include "network-internal.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "parse-util.h"
#include "set.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

/* Let's assume that anything above this number is a user misconfiguration. */
#define MAX_NTP_SERVERS 128

/* Set defaults following RFC7844 */
void network_apply_anonymize_if_set(Network *network) {
        if (!network->dhcp_anonymize)
                return;
        /* RFC7844 3.7
         SHOULD NOT send the Host Name option */
        network->dhcp_send_hostname = false;
        /* RFC7844 section 3.:
         MAY contain the Client Identifier option
         Section 3.5:
         clients MUST use client identifiers based solely
         on the link-layer address */
        /* NOTE: Using MAC, as it does not reveal extra information,
        * and some servers might not answer if this option is not sent */
        network->dhcp_client_identifier = DHCP_CLIENT_ID_MAC;
        /* RFC 7844 3.10:
         SHOULD NOT use the Vendor Class Identifier option */
        network->dhcp_vendor_class_identifier = mfree(network->dhcp_vendor_class_identifier);
        /* RFC7844 section 3.6.:
         The client intending to protect its privacy SHOULD only request a
         minimal number of options in the PRL and SHOULD also randomly shuffle
         the ordering of option codes in the PRL.  If this random ordering
         cannot be implemented, the client MAY order the option codes in the
         PRL by option code number (lowest to highest).
        */
        /* NOTE: dhcp_use_mtu is false by default,
        * though it was not initiallized to any value in network_load_one.
        * Maybe there should be another var called *send*?
        * (to use the MTU sent by the server but to do not send
        * the option in the PRL). */
        network->dhcp_use_mtu = false;
        /* NOTE: when Anonymize=yes, the PRL route options are sent by default,
         * but this is needed to use them. */
        network->dhcp_use_routes = true;
        /* RFC7844 section 3.6.
        * same comments as previous option */
        network->dhcp_use_timezone = false;
}

static int network_resolve_netdev_one(Network *network, const char *name, NetDevKind kind, NetDev **ret_netdev) {
        const char *kind_string;
        NetDev *netdev;
        int r;

        /* For test-networkd-conf, the check must be earlier than the assertions. */
        if (!name)
                return 0;

        assert(network);
        assert(network->manager);
        assert(network->filename);
        assert(ret_netdev);

        if (kind == _NETDEV_KIND_TUNNEL)
                kind_string = "tunnel";
        else {
                kind_string = netdev_kind_to_string(kind);
                if (!kind_string)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "%s: Invalid NetDev kind of %s, ignoring assignment.",
                                               network->filename, name);
        }

        r = netdev_get(network->manager, name, &netdev);
        if (r < 0)
                return log_error_errno(r, "%s: %s NetDev could not be found, ignoring assignment.",
                                       network->filename, name);

        if (netdev->kind != kind && !(kind == _NETDEV_KIND_TUNNEL &&
                                      IN_SET(netdev->kind,
                                             NETDEV_KIND_IPIP,
                                             NETDEV_KIND_SIT,
                                             NETDEV_KIND_GRE,
                                             NETDEV_KIND_GRETAP,
                                             NETDEV_KIND_IP6GRE,
                                             NETDEV_KIND_IP6GRETAP,
                                             NETDEV_KIND_VTI,
                                             NETDEV_KIND_VTI6,
                                             NETDEV_KIND_IP6TNL,
                                             NETDEV_KIND_ERSPAN)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: NetDev %s is not a %s, ignoring assignment",
                                       network->filename, name, kind_string);

        *ret_netdev = netdev_ref(netdev);
        return 1;
}

static int network_resolve_stacked_netdevs(Network *network) {
        void *name, *kind;
        Iterator i;
        int r;

        assert(network);

        HASHMAP_FOREACH_KEY(kind, name, network->stacked_netdev_names, i) {
                _cleanup_(netdev_unrefp) NetDev *netdev = NULL;

                r = network_resolve_netdev_one(network, name, PTR_TO_INT(kind), &netdev);
                if (r <= 0)
                        continue;

                r = hashmap_ensure_allocated(&network->stacked_netdevs, &string_hash_ops);
                if (r < 0)
                        return log_oom();

                r = hashmap_put(network->stacked_netdevs, netdev->ifname, netdev);
                if (r < 0)
                        return log_error_errno(r, "%s: Failed to add NetDev '%s' to network: %m",
                                               network->filename, (const char *) name);

                netdev = NULL;
        }

        return 0;
}

static uint32_t network_get_stacked_netdevs_mtu(Network *network) {
        uint32_t mtu = 0;
        NetDev *dev;
        Iterator i;

        HASHMAP_FOREACH(dev, network->stacked_netdevs, i)
                if (dev->kind == NETDEV_KIND_VLAN && dev->mtu > 0)
                        /* See vlan_dev_change_mtu() in kernel.
                         * Note that the additional 4bytes may not be necessary for all devices. */
                        mtu = MAX(mtu, dev->mtu + 4);

                else if (dev->kind == NETDEV_KIND_MACVLAN && dev->mtu > mtu)
                        /* See macvlan_change_mtu() in kernel. */
                        mtu = dev->mtu;

        return mtu;
}

int network_verify(Network *network) {
        Address *address, *address_next;
        Route *route, *route_next;
        FdbEntry *fdb, *fdb_next;
        Neighbor *neighbor, *neighbor_next;
        AddressLabel *label, *label_next;
        Prefix *prefix, *prefix_next;
        RoutingPolicyRule *rule, *rule_next;
        uint32_t mtu;

        assert(network);
        assert(network->filename);

        /* skip out early if configuration does not match the environment */
        if (!condition_test_list(network->conditions, NULL, NULL, NULL))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: Conditions in the file do not match the system environment, skipping.",
                                       network->filename);

        (void) network_resolve_netdev_one(network, network->bond_name, NETDEV_KIND_BOND, &network->bond);
        (void) network_resolve_netdev_one(network, network->bridge_name, NETDEV_KIND_BRIDGE, &network->bridge);
        (void) network_resolve_netdev_one(network, network->vrf_name, NETDEV_KIND_VRF, &network->vrf);
        (void) network_resolve_stacked_netdevs(network);

        /* Free unnecessary entries. */
        network->bond_name = mfree(network->bond_name);
        network->bridge_name = mfree(network->bridge_name);
        network->vrf_name = mfree(network->vrf_name);
        network->stacked_netdev_names = hashmap_free_free_key(network->stacked_netdev_names);

        if (network->bond) {
                /* Bonding slave does not support addressing. */
                if (network->ipv6_accept_ra > 0) {
                        log_warning("%s: Cannot enable IPv6AcceptRA= when Bond= is specified, disabling IPv6AcceptRA=.",
                                    network->filename);
                        network->ipv6_accept_ra = 0;
                }
                if (network->link_local >= 0 && network->link_local != ADDRESS_FAMILY_NO) {
                        log_warning("%s: Cannot enable LinkLocalAddressing= when Bond= is specified, disabling LinkLocalAddressing=.",
                                    network->filename);
                        network->link_local = ADDRESS_FAMILY_NO;
                }
                if (network->dhcp != ADDRESS_FAMILY_NO) {
                        log_warning("%s: Cannot enable DHCP= when Bond= is specified, disabling DHCP=.",
                                    network->filename);
                        network->dhcp = ADDRESS_FAMILY_NO;
                }
                if (network->dhcp_server) {
                        log_warning("%s: Cannot enable DHCPServer= when Bond= is specified, disabling DHCPServer=.",
                                    network->filename);
                        network->dhcp_server = false;
                }
                if (network->n_static_addresses > 0) {
                        log_warning("%s: Cannot set addresses when Bond= is specified, ignoring addresses.",
                                    network->filename);
                        while ((address = network->static_addresses))
                                address_free(address);
                }
                if (network->n_static_routes > 0) {
                        log_warning("%s: Cannot set routes when Bond= is specified, ignoring routes.",
                                    network->filename);
                        while ((route = network->static_routes))
                                route_free(route);
                }
        }

        if (network->link_local < 0)
                network->link_local = network->bridge ? ADDRESS_FAMILY_NO : ADDRESS_FAMILY_IPV6;

        if (network->ipv6_accept_ra < 0 && network->bridge)
                network->ipv6_accept_ra = false;

        /* IPMasquerade=yes implies IPForward=yes */
        if (network->ip_masquerade)
                network->ip_forward |= ADDRESS_FAMILY_IPV4;

        network->mtu_is_set = network->mtu > 0;
        mtu = network_get_stacked_netdevs_mtu(network);
        if (network->mtu < mtu) {
                if (network->mtu_is_set)
                        log_notice("%s: Bumping MTUBytes= from %"PRIu32" to %"PRIu32" because of stacked device",
                                   network->filename, network->mtu, mtu);
                network->mtu = mtu;
        }

        if (network->mtu_is_set && network->dhcp_use_mtu) {
                log_warning("%s: MTUBytes= in [Link] section and UseMTU= in [DHCP] section are set. "
                            "Disabling UseMTU=.", network->filename);
                network->dhcp_use_mtu = false;
        }

        LIST_FOREACH_SAFE(addresses, address, address_next, network->static_addresses)
                if (address_section_verify(address) < 0)
                        address_free(address);

        LIST_FOREACH_SAFE(routes, route, route_next, network->static_routes)
                if (route_section_verify(route, network) < 0)
                        route_free(route);

        LIST_FOREACH_SAFE(static_fdb_entries, fdb, fdb_next, network->static_fdb_entries)
                if (section_is_invalid(fdb->section))
                        fdb_entry_free(fdb);

        LIST_FOREACH_SAFE(neighbors, neighbor, neighbor_next, network->neighbors)
                if (section_is_invalid(neighbor->section))
                        neighbor_free(neighbor);

        LIST_FOREACH_SAFE(labels, label, label_next, network->address_labels)
                if (section_is_invalid(label->section))
                        address_label_free(label);

        LIST_FOREACH_SAFE(prefixes, prefix, prefix_next, network->static_prefixes)
                if (section_is_invalid(prefix->section))
                        prefix_free(prefix);

        LIST_FOREACH_SAFE(rules, rule, rule_next, network->rules)
                if (section_is_invalid(rule->section))
                        routing_policy_rule_free(rule);

        return 0;
}

int network_load_one(Manager *manager, const char *filename) {
        _cleanup_free_ char *fname = NULL, *name = NULL;
        _cleanup_(network_freep) Network *network = NULL;
        _cleanup_fclose_ FILE *file = NULL;
        const char *dropin_dirname;
        char *d;
        int r;

        assert(manager);
        assert(filename);

        file = fopen(filename, "re");
        if (!file) {
                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        if (null_or_empty_fd(fileno(file))) {
                log_debug("Skipping empty file: %s", filename);
                return 0;
        }

        fname = strdup(filename);
        if (!fname)
                return log_oom();

        name = strdup(basename(filename));
        if (!name)
                return log_oom();

        d = strrchr(name, '.');
        if (!d)
                return -EINVAL;

        *d = '\0';

        dropin_dirname = strjoina(name, ".network.d");

        network = new(Network, 1);
        if (!network)
                return log_oom();

        *network = (Network) {
                .filename = TAKE_PTR(fname),
                .name = TAKE_PTR(name),

                .required_for_online = true,
                .required_operstate_for_online = LINK_OPERSTATE_DEGRADED,
                .dhcp = ADDRESS_FAMILY_NO,
                .dhcp_use_ntp = true,
                .dhcp_use_dns = true,
                .dhcp_use_hostname = true,
                .dhcp_use_routes = true,
                /* NOTE: this var might be overwriten by network_apply_anonymize_if_set */
                .dhcp_send_hostname = true,
                /* To enable/disable RFC7844 Anonymity Profiles */
                .dhcp_anonymize = false,
                .dhcp_route_metric = DHCP_ROUTE_METRIC,
                /* NOTE: this var might be overwrite by network_apply_anonymize_if_set */
                .dhcp_client_identifier = DHCP_CLIENT_ID_DUID,
                .dhcp_route_table = RT_TABLE_MAIN,
                .dhcp_route_table_set = false,
                /* NOTE: from man: UseMTU=... Defaults to false*/
                .dhcp_use_mtu = false,
                /* NOTE: from man: UseTimezone=... Defaults to "no".*/
                .dhcp_use_timezone = false,
                .rapid_commit = true,

                .dhcp_server_emit_dns = true,
                .dhcp_server_emit_ntp = true,
                .dhcp_server_emit_router = true,
                .dhcp_server_emit_timezone = true,

                .router_emit_dns = true,
                .router_emit_domains = true,

                .use_bpdu = -1,
                .hairpin = -1,
                .fast_leave = -1,
                .allow_port_to_be_root = -1,
                .unicast_flood = -1,
                .multicast_flood = -1,
                .multicast_to_unicast = -1,
                .neighbor_suppression = -1,
                .learning = -1,
                .priority = LINK_BRIDGE_PORT_PRIORITY_INVALID,

                .lldp_mode = LLDP_MODE_ROUTERS_ONLY,

                .dns_default_route = -1,
                .llmnr = RESOLVE_SUPPORT_YES,
                .mdns = RESOLVE_SUPPORT_NO,
                .dnssec_mode = _DNSSEC_MODE_INVALID,
                .dns_over_tls_mode = _DNS_OVER_TLS_MODE_INVALID,

                /* If LinkLocalAddressing= is not set, then set to ADDRESS_FAMILY_IPV6 later. */
                .link_local = _ADDRESS_FAMILY_BOOLEAN_INVALID,

                .ipv6_privacy_extensions = IPV6_PRIVACY_EXTENSIONS_NO,
                .ipv6_accept_ra = -1,
                .ipv6_dad_transmits = -1,
                .ipv6_hop_limit = -1,
                .ipv6_proxy_ndp = -1,
                .duid.type = _DUID_TYPE_INVALID,
                .proxy_arp = -1,
                .arp = -1,
                .multicast = -1,
                .allmulticast = -1,
                .ipv6_accept_ra_use_dns = true,
                .ipv6_accept_ra_use_autonomous_prefix = true,
                .ipv6_accept_ra_use_onlink_prefix = true,
                .ipv6_accept_ra_route_table = RT_TABLE_MAIN,
                .ipv6_accept_ra_route_table_set = false,

                .can_triple_sampling = -1,
        };

        r = config_parse_many(filename, NETWORK_DIRS, dropin_dirname,
                              "Match\0"
                              "Link\0"
                              "Network\0"
                              "Address\0"
                              "Neighbor\0"
                              "IPv6AddressLabel\0"
                              "RoutingPolicyRule\0"
                              "Route\0"
                              "DHCP\0"
                              "DHCPv4\0" /* compat */
                              "DHCPServer\0"
                              "IPv6AcceptRA\0"
                              "IPv6NDPProxyAddress\0"
                              "Bridge\0"
                              "BridgeFDB\0"
                              "BridgeVLAN\0"
                              "IPv6PrefixDelegation\0"
                              "IPv6Prefix\0"
                              "CAN\0",
                              config_item_perf_lookup, network_network_gperf_lookup,
                              CONFIG_PARSE_WARN, network);
        if (r < 0)
                return r;

        network_apply_anonymize_if_set(network);

        r = network_add_ipv4ll_route(network);
        if (r < 0)
                log_warning_errno(r, "%s: Failed to add IPv4LL route, ignoring: %m", network->filename);

        LIST_PREPEND(networks, manager->networks, network);
        network->manager = manager;

        r = hashmap_ensure_allocated(&manager->networks_by_name, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_put(manager->networks_by_name, network->name, network);
        if (r < 0)
                return r;

        if (network_verify(network) < 0)
                return 0;

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

        r = conf_files_list_strv(&files, ".network", NULL, 0, NETWORK_DIRS);
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
        IPv6ProxyNDPAddress *ipv6_proxy_ndp_address;
        RoutingPolicyRule *rule;
        FdbEntry *fdb_entry;
        Neighbor *neighbor;
        AddressLabel *label;
        Prefix *prefix;
        Address *address;
        Route *route;

        if (!network)
                return;

        free(network->filename);

        set_free_free(network->match_mac);
        strv_free(network->match_path);
        strv_free(network->match_driver);
        strv_free(network->match_type);
        strv_free(network->match_name);
        condition_free_list(network->conditions);

        free(network->description);
        free(network->dhcp_vendor_class_identifier);
        strv_free(network->dhcp_user_class);
        free(network->dhcp_hostname);

        free(network->mac);

        strv_free(network->ntp);
        free(network->dns);
        ordered_set_free_free(network->search_domains);
        ordered_set_free_free(network->route_domains);
        strv_free(network->bind_carrier);

        ordered_set_free_free(network->router_search_domains);
        free(network->router_dns);

        free(network->bridge_name);
        free(network->bond_name);
        free(network->vrf_name);
        hashmap_free_free_key(network->stacked_netdev_names);
        netdev_unref(network->bridge);
        netdev_unref(network->bond);
        netdev_unref(network->vrf);
        hashmap_free_with_destructor(network->stacked_netdevs, netdev_unref);

        while ((route = network->static_routes))
                route_free(route);

        while ((address = network->static_addresses))
                address_free(address);

        while ((fdb_entry = network->static_fdb_entries))
                fdb_entry_free(fdb_entry);

        while ((ipv6_proxy_ndp_address = network->ipv6_proxy_ndp_addresses))
                ipv6_proxy_ndp_address_free(ipv6_proxy_ndp_address);

        while ((neighbor = network->neighbors))
                neighbor_free(neighbor);

        while ((label = network->address_labels))
                address_label_free(label);

        while ((prefix = network->static_prefixes))
                prefix_free(prefix);

        while ((rule = network->rules))
                routing_policy_rule_free(rule);

        hashmap_free(network->addresses_by_section);
        hashmap_free(network->routes_by_section);
        hashmap_free(network->fdb_entries_by_section);
        hashmap_free(network->neighbors_by_section);
        hashmap_free(network->address_labels_by_section);
        hashmap_free(network->prefixes_by_section);
        hashmap_free(network->rules_by_section);

        if (network->manager) {
                if (network->manager->networks)
                        LIST_REMOVE(networks, network->manager->networks, network);

                if (network->manager->networks_by_name && network->name)
                        hashmap_remove(network->manager->networks_by_name, network->name);

                if (network->manager->duids_requesting_uuid)
                        set_remove(network->manager->duids_requesting_uuid, &network->duid);
        }

        free(network->name);

        free(network->dhcp_server_timezone);
        free(network->dhcp_server_dns);
        free(network->dhcp_server_ntp);

        set_free_free(network->dnssec_negative_trust_anchors);

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

int network_get(Manager *manager, sd_device *device,
                const char *ifname, const struct ether_addr *address,
                Network **ret) {
        const char *path = NULL, *driver = NULL, *devtype = NULL;
        Network *network;

        assert(manager);
        assert(ret);

        if (device) {
                (void) sd_device_get_property_value(device, "ID_PATH", &path);

                (void) sd_device_get_property_value(device, "ID_NET_DRIVER", &driver);

                (void) sd_device_get_devtype(device, &devtype);
        }

        LIST_FOREACH(networks, network, manager->networks) {
                if (net_match_config(network->match_mac, network->match_path,
                                     network->match_driver, network->match_type,
                                     network->match_name,
                                     address, path, driver, devtype, ifname)) {
                        if (network->match_name && device) {
                                const char *attr;
                                uint8_t name_assign_type = NET_NAME_UNKNOWN;

                                if (sd_device_get_sysattr_value(device, "name_assign_type", &attr) >= 0)
                                        (void) safe_atou8(attr, &name_assign_type);

                                if (name_assign_type == NET_NAME_ENUM)
                                        log_warning("%s: found matching network '%s', based on potentially unpredictable ifname",
                                                    ifname, network->filename);
                                else
                                        log_debug("%s: found matching network '%s'", ifname, network->filename);
                        } else
                                log_debug("%s: found matching network '%s'", ifname, network->filename);

                        *ret = network;
                        return 0;
                }
        }

        *ret = NULL;

        return -ENOENT;
}

int network_apply(Network *network, Link *link) {
        assert(network);
        assert(link);

        link->network = network;

        if (network->n_dns > 0 ||
            !strv_isempty(network->ntp) ||
            !ordered_set_isempty(network->search_domains) ||
            !ordered_set_isempty(network->route_domains))
                link_dirty(link);

        return 0;
}

bool network_has_static_ipv6_addresses(Network *network) {
        Address *address;

        assert(network);

        LIST_FOREACH(addresses, address, network->static_addresses) {
                if (address->family == AF_INET6)
                        return true;
        }

        return false;
}

int config_parse_stacked_netdev(const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {
        _cleanup_free_ char *name = NULL;
        NetDevKind kind = ltype;
        Hashmap **h = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);
        assert(IN_SET(kind,
                      NETDEV_KIND_VLAN, NETDEV_KIND_MACVLAN, NETDEV_KIND_MACVTAP,
                      NETDEV_KIND_IPVLAN, NETDEV_KIND_VXLAN, NETDEV_KIND_L2TP,
                      _NETDEV_KIND_TUNNEL));

        if (!ifname_valid(rvalue)) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Invalid netdev name in %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        name = strdup(rvalue);
        if (!name)
                return log_oom();

        r = hashmap_ensure_allocated(h, &string_hash_ops);
        if (r < 0)
                return log_oom();

        r = hashmap_put(*h, name, INT_TO_PTR(kind));
        if (r < 0)
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Cannot add NetDev '%s' to network, ignoring assignment: %m", name);
        else if (r == 0)
                log_syntax(unit, LOG_DEBUG, filename, line, r,
                           "NetDev '%s' specified twice, ignoring.", name);
        else
                name = NULL;

        return 0;
}

int config_parse_domains(
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

        const char *p;
        Network *n = data;
        int r;

        assert(n);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                n->search_domains = ordered_set_free_free(n->search_domains);
                n->route_domains = ordered_set_free_free(n->route_domains);
                return 0;
        }

        p = rvalue;
        for (;;) {
                _cleanup_free_ char *w = NULL, *normalized = NULL;
                const char *domain;
                bool is_route;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to extract search or route domain, ignoring: %s", rvalue);
                        break;
                }
                if (r == 0)
                        break;

                is_route = w[0] == '~';
                domain = is_route ? w + 1 : w;

                if (dns_name_is_root(domain) || streq(domain, "*")) {
                        /* If the root domain appears as is, or the special token "*" is found, we'll
                         * consider this as routing domain, unconditionally. */
                        is_route = true;
                        domain = "."; /* make sure we don't allow empty strings, thus write the root
                                       * domain as "." */
                } else {
                        r = dns_name_normalize(domain, 0, &normalized);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r,
                                           "'%s' is not a valid domain name, ignoring.", domain);
                                continue;
                        }

                        domain = normalized;

                        if (is_localhost(domain)) {
                                log_syntax(unit, LOG_ERR, filename, line, 0,
                                           "'localhost' domain may not be configured as search or route domain, ignoring assignment: %s",
                                           domain);
                                continue;
                        }
                }

                OrderedSet **set = is_route ? &n->route_domains : &n->search_domains;
                r = ordered_set_ensure_allocated(set, &string_hash_ops);
                if (r < 0)
                        return r;

                r = ordered_set_put_strdup(*set, domain);
                if (r < 0)
                        return log_oom();
        }

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

        SET_FLAG(*link_local, ADDRESS_FAMILY_IPV4, parse_boolean(rvalue));

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
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Failed to parse DHCP option, ignoring: %s", rvalue);
                        return 0;
                }

                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "DHCP=%s is deprecated, please use DHCP=%s instead.",
                           rvalue, address_family_boolean_to_string(s));
        }

        *dhcp = s;
        return 0;
}

static const char* const dhcp_client_identifier_table[_DHCP_CLIENT_ID_MAX] = {
        [DHCP_CLIENT_ID_MAC] = "mac",
        [DHCP_CLIENT_ID_DUID] = "duid",
        [DHCP_CLIENT_ID_DUID_ONLY] = "duid-only",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(dhcp_client_identifier, DHCPClientIdentifier);
DEFINE_CONFIG_PARSE_ENUM(config_parse_dhcp_client_identifier, dhcp_client_identifier, DHCPClientIdentifier,
                         "Failed to parse client identifier type");

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
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse IPv6 token, ignoring: %s", rvalue);
                return 0;
        }

        if (in_addr_is_null(AF_INET6, &buffer)) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "IPv6 token cannot be the ANY address, ignoring: %s", rvalue);
                return 0;
        }

        if ((buffer.in6.s6_addr32[0] | buffer.in6.s6_addr32[1]) != 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "IPv6 token cannot be longer than 64 bits, ignoring: %s", rvalue);
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
                                log_syntax(unit, LOG_ERR, filename, line, 0,
                                           "Failed to parse IPv6 privacy extensions option, ignoring: %s", rvalue);
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

        _cleanup_free_ char *hn = NULL;
        char **hostname = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = config_parse_string(unit, filename, line, section, section_line, lvalue, ltype, rvalue, &hn, userdata);
        if (r < 0)
                return r;

        if (!hostname_is_valid(hn, false)) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Hostname is not valid, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = dns_name_is_valid(hn);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to check validity of hostname '%s', ignoring assignment: %m", rvalue);
                return 0;
        }
        if (r == 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Hostname is not a valid DNS domain name, ignoring assignment: %s", rvalue);
                return 0;
        }

        return free_and_replace(*hostname, hn);
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

        _cleanup_free_ char *tz = NULL;
        char **datap = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = config_parse_string(unit, filename, line, section, section_line, lvalue, ltype, rvalue, &tz, userdata);
        if (r < 0)
                return r;

        if (!timezone_is_valid(tz, LOG_ERR)) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Timezone is not valid, ignoring assignment: %s", rvalue);
                return 0;
        }

        return free_and_replace(*datap, tz);
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
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                if (inet_pton(AF_INET, w, &a) <= 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Failed to parse DNS server address, ignoring: %s", w);
                        continue;
                }

                m = reallocarray(n->dhcp_server_dns, n->n_dhcp_server_dns + 1, sizeof(struct in_addr));
                if (!m)
                        return log_oom();

                m[n->n_dhcp_server_dns++] = a;
                n->dhcp_server_dns = m;
        }

        return 0;
}

int config_parse_radv_dns(
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
                union in_addr_union a;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                if (in_addr_from_string(AF_INET6, w, &a) >= 0) {
                        struct in6_addr *m;

                        m = reallocarray(n->router_dns, n->n_router_dns + 1, sizeof(struct in6_addr));
                        if (!m)
                                return log_oom();

                        m[n->n_router_dns++] = a.in6;
                        n->router_dns = m;

                } else
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Failed to parse DNS server address, ignoring: %s", w);
        }

        return 0;
}

int config_parse_radv_search_domains(
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
                _cleanup_free_ char *w = NULL, *idna = NULL;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                r = dns_name_apply_idna(w, &idna);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to apply IDNA to domain name '%s', ignoring: %m", w);
                        continue;
                } else if (r == 0)
                        /* transfer ownership to simplify subsequent operations */
                        idna = TAKE_PTR(w);

                r = ordered_set_ensure_allocated(&n->router_search_domains, &string_hash_ops);
                if (r < 0)
                        return r;

                r = ordered_set_consume(n->router_search_domains, TAKE_PTR(idna));
                if (r < 0)
                        return r;
        }

        return 0;
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
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                if (inet_pton(AF_INET, w, &a) <= 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Failed to parse NTP server address, ignoring: %s", w);
                        continue;
                }

                m = reallocarray(n->dhcp_server_ntp, n->n_dhcp_server_ntp + 1, sizeof(struct in_addr));
                if (!m)
                        return log_oom();

                m[n->n_dhcp_server_ntp++] = a;
                n->dhcp_server_ntp = m;
        }
}

int config_parse_dns(
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

        Network *n = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        for (;;) {
                _cleanup_free_ char *w = NULL;
                union in_addr_union a;
                struct in_addr_data *m;
                int family;

                r = extract_first_word(&rvalue, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        break;
                }
                if (r == 0)
                        break;

                r = in_addr_from_string_auto(w, &family, &a);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse dns server address, ignoring: %s", w);
                        continue;
                }

                m = reallocarray(n->dns, n->n_dns + 1, sizeof(struct in_addr_data));
                if (!m)
                        return log_oom();

                m[n->n_dns++] = (struct in_addr_data) {
                        .family = family,
                        .address = a,
                };

                n->dns = m;
        }

        return 0;
}

int config_parse_dnssec_negative_trust_anchors(
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

        const char *p = rvalue;
        Network *n = data;
        int r;

        assert(n);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                n->dnssec_negative_trust_anchors = set_free_free(n->dnssec_negative_trust_anchors);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *w = NULL;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to extract negative trust anchor domain, ignoring: %s", rvalue);
                        break;
                }
                if (r == 0)
                        break;

                r = dns_name_is_valid(w);
                if (r <= 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "%s is not a valid domain name, ignoring.", w);
                        continue;
                }

                r = set_ensure_allocated(&n->dnssec_negative_trust_anchors, &dns_name_hash_ops);
                if (r < 0)
                        return log_oom();

                r = set_put(n->dnssec_negative_trust_anchors, w);
                if (r < 0)
                        return log_oom();
                if (r > 0)
                        w = NULL;
        }

        return 0;
}

int config_parse_ntp(
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

        char ***l = data;
        int r;

        assert(l);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *l = strv_free(*l);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *w = NULL;

                r = extract_first_word(&rvalue, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to extract NTP server name, ignoring: %s", rvalue);
                        break;
                }
                if (r == 0)
                        break;

                r = dns_name_is_valid_or_address(w);
                if (r <= 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "%s is not a valid domain name or IP address, ignoring.", w);
                        continue;
                }

                if (strv_length(*l) > MAX_NTP_SERVERS) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "More than %u NTP servers specified, ignoring \"%s\" and any subsequent entries.",
                                   MAX_NTP_SERVERS, w);
                        break;
                }

                r = strv_consume(l, TAKE_PTR(w));
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

int config_parse_dhcp_user_class(
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

        char ***l = data;
        int r;

        assert(l);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *l = strv_free(*l);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *w = NULL;

                r = extract_first_word(&rvalue, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to split user classes option, ignoring: %s", rvalue);
                        break;
                }
                if (r == 0)
                        break;

                if (strlen(w) > 255) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "%s length is not in the range 1-255, ignoring.", w);
                        continue;
                }

                r = strv_push(l, w);
                if (r < 0)
                        return log_oom();

                w = NULL;
        }

        return 0;
}

int config_parse_section_route_table(
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

        Network *network = data;
        uint32_t rt;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atou32(rvalue, &rt);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse RouteTable=%s, ignoring assignment: %m", rvalue);
                return 0;
        }

        if (streq_ptr(section, "DHCP")) {
                network->dhcp_route_table = rt;
                network->dhcp_route_table_set = true;
        } else { /* section is IPv6AcceptRA */
                network->ipv6_accept_ra_route_table = rt;
                network->ipv6_accept_ra_route_table_set = true;
        }

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_dhcp_use_domains, dhcp_use_domains, DHCPUseDomains,
                         "Failed to parse DHCP use domains setting");

static const char* const dhcp_use_domains_table[_DHCP_USE_DOMAINS_MAX] = {
        [DHCP_USE_DOMAINS_NO] = "no",
        [DHCP_USE_DOMAINS_ROUTE] = "route",
        [DHCP_USE_DOMAINS_YES] = "yes",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(dhcp_use_domains, DHCPUseDomains, DHCP_USE_DOMAINS_YES);

DEFINE_CONFIG_PARSE_ENUM(config_parse_lldp_mode, lldp_mode, LLDPMode, "Failed to parse LLDP= setting.");

static const char* const lldp_mode_table[_LLDP_MODE_MAX] = {
        [LLDP_MODE_NO] = "no",
        [LLDP_MODE_YES] = "yes",
        [LLDP_MODE_ROUTERS_ONLY] = "routers-only",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(lldp_mode, LLDPMode, LLDP_MODE_YES);

int config_parse_iaid(const char *unit,
                      const char *filename,
                      unsigned line,
                      const char *section,
                      unsigned section_line,
                      const char *lvalue,
                      int ltype,
                      const char *rvalue,
                      void *data,
                      void *userdata) {
        Network *network = data;
        uint32_t iaid;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(network);

        r = safe_atou32(rvalue, &iaid);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Unable to read IAID, ignoring assignment: %s", rvalue);
                return 0;
        }

        network->iaid = iaid;
        network->iaid_set = true;

        return 0;
}

int config_parse_required_for_online(
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

        Network *network = data;
        LinkOperationalState s;
        bool required = true;
        int r;

        if (isempty(rvalue)) {
                network->required_for_online = true;
                network->required_operstate_for_online = LINK_OPERSTATE_DEGRADED;
                return 0;
        }

        s = link_operstate_from_string(rvalue);
        if (s < 0) {
                r = parse_boolean(rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse %s= setting, ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }

                required = r;
                s = LINK_OPERSTATE_DEGRADED;
        }

        network->required_for_online = required;
        network->required_operstate_for_online = s;

        return 0;
}
