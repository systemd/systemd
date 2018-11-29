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
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static void network_config_hash_func(const NetworkConfigSection *c, struct siphash *state) {
        siphash24_compress(c->filename, strlen(c->filename), state);
        siphash24_compress(&c->line, sizeof(c->line), state);
}

static int network_config_compare_func(const NetworkConfigSection *x, const NetworkConfigSection *y) {
        int r;

        r = strcmp(x->filename, y->filename);
        if (r != 0)
                return r;

        return CMP(x->line, y->line);
}

DEFINE_HASH_OPS(network_config_hash_ops, NetworkConfigSection, network_config_hash_func, network_config_compare_func);

int network_config_section_new(const char *filename, unsigned line, NetworkConfigSection **s) {
        NetworkConfigSection *cs;

        cs = malloc0(offsetof(NetworkConfigSection, filename) + strlen(filename) + 1);
        if (!cs)
                return -ENOMEM;

        strcpy(cs->filename, filename);
        cs->line = line;

        *s = TAKE_PTR(cs);

        return 0;
}

void network_config_section_free(NetworkConfigSection *cs) {
        free(cs);
}

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

int network_load_one(Manager *manager, const char *filename) {
        _cleanup_(network_freep) Network *network = NULL;
        _cleanup_fclose_ FILE *file = NULL;
        char *d;
        const char *dropin_dirname;
        Route *route;
        Address *address;
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

        network = new(Network, 1);
        if (!network)
                return log_oom();

        *network = (Network) {
                .manager = manager,

                .required_for_online = true,
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
                .multicast_to_unicast = -1,
                .priority = LINK_BRIDGE_PORT_PRIORITY_INVALID,

                .lldp_mode = LLDP_MODE_ROUTERS_ONLY,

                .llmnr = RESOLVE_SUPPORT_YES,
                .mdns = RESOLVE_SUPPORT_NO,
                .dnssec_mode = _DNSSEC_MODE_INVALID,
                .dns_over_tls_mode = _DNS_OVER_TLS_MODE_INVALID,

                .link_local = ADDRESS_FAMILY_IPV6,

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
                .ipv6_accept_ra_route_table = RT_TABLE_MAIN,
        };

        network->filename = strdup(filename);
        if (!network->filename)
                return log_oom();

        network->name = strdup(basename(filename));
        if (!network->name)
                return log_oom();

        d = strrchr(network->name, '.');
        if (!d)
                return -EINVAL;

        *d = '\0';

        dropin_dirname = strjoina(network->name, ".network.d");

        r = config_parse_many(filename, network_dirs, dropin_dirname,
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

        /* IPMasquerade=yes implies IPForward=yes */
        if (network->ip_masquerade)
                network->ip_forward |= ADDRESS_FAMILY_IPV4;

        if (network->mtu > 0 && network->dhcp_use_mtu) {
                log_warning("MTUBytes= in [Link] section and UseMTU= in [DHCP] section are set in %s. "
                            "Disabling UseMTU=.", filename);
                network->dhcp_use_mtu = false;
        }

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

        r = conf_files_list_strv(&files, ".network", NULL, 0, network_dirs);
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

        free(network->description);
        free(network->dhcp_vendor_class_identifier);
        strv_free(network->dhcp_user_class);
        free(network->dhcp_hostname);

        free(network->mac);

        strv_free(network->ntp);
        free(network->dns);
        strv_free(network->search_domains);
        strv_free(network->route_domains);
        strv_free(network->bind_carrier);

        strv_free(network->router_search_domains);
        free(network->router_dns);

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

        condition_free_list(network->match_host);
        condition_free_list(network->match_virt);
        condition_free_list(network->match_kernel_cmdline);
        condition_free_list(network->match_kernel_version);
        condition_free_list(network->match_arch);

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
        const char *path = NULL, *parent_driver = NULL, *driver = NULL, *devtype = NULL;
        sd_device *parent;
        Network *network;

        assert(manager);
        assert(ret);

        if (device) {
                (void) sd_device_get_property_value(device, "ID_PATH", &path);

                if (sd_device_get_parent(device, &parent) >= 0)
                        (void) sd_device_get_driver(parent, &parent_driver);

                (void) sd_device_get_property_value(device, "ID_NET_DRIVER", &driver);

                (void) sd_device_get_devtype(device, &devtype);
        }

        LIST_FOREACH(networks, network, manager->networks) {
                if (net_match_config(network->match_mac, network->match_path,
                                     network->match_driver, network->match_type,
                                     network->match_name, network->match_host,
                                     network->match_virt, network->match_kernel_cmdline,
                                     network->match_kernel_version, network->match_arch,
                                     address, path, parent_driver, driver,
                                     devtype, ifname)) {
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
        int r;

        assert(network);
        assert(link);

        link->network = network;

        if (network->ipv4ll_route) {
                Route *route;

                r = route_new_static(network, NULL, 0, &route);
                if (r < 0)
                        return r;

                r = inet_pton(AF_INET, "169.254.0.0", &route->dst.in);
                if (r == 0)
                        return -EINVAL;
                if (r < 0)
                        return -errno;

                route->family = AF_INET;
                route->dst_prefixlen = 16;
                route->scope = RT_SCOPE_LINK;
                route->priority = IPV4LL_ROUTE_METRIC;
                route->protocol = RTPROT_STATIC;
        }

        if (network->n_dns > 0 ||
            !strv_isempty(network->ntp) ||
            !strv_isempty(network->search_domains) ||
            !strv_isempty(network->route_domains))
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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid NetDev kind: %s", lvalue);
                return 0;
        }

        r = netdev_get(network->manager, rvalue, &netdev);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "%s could not be found, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        if (netdev->kind != kind) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "NetDev is not a %s, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        switch (kind) {
        case NETDEV_KIND_BRIDGE:
                network->bridge = netdev_unref(network->bridge);
                network->bridge = netdev;

                break;
        case NETDEV_KIND_BOND:
                network->bond = netdev_unref(network->bond);
                network->bond = netdev;

                break;
        case NETDEV_KIND_VRF:
                network->vrf = netdev_unref(network->vrf);
                network->vrf = netdev;

                break;
        case NETDEV_KIND_VLAN:
        case NETDEV_KIND_MACVLAN:
        case NETDEV_KIND_MACVTAP:
        case NETDEV_KIND_IPVLAN:
        case NETDEV_KIND_VXLAN:
        case NETDEV_KIND_VCAN:
                r = hashmap_ensure_allocated(&network->stacked_netdevs, &string_hash_ops);
                if (r < 0)
                        return log_oom();

                r = hashmap_put(network->stacked_netdevs, netdev->ifname, netdev);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Cannot add NetDev '%s' to network: %m", rvalue);
                        return 0;
                }

                break;
        default:
                assert_not_reached("Cannot parse NetDev");
        }

        netdev_ref(netdev);

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
                n->search_domains = strv_free(n->search_domains);
                n->route_domains = strv_free(n->route_domains);
                return 0;
        }

        p = rvalue;
        for (;;) {
                _cleanup_free_ char *w = NULL, *normalized = NULL;
                const char *domain;
                bool is_route;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract search or route domain, ignoring: %s", rvalue);
                        break;
                }
                if (r == 0)
                        break;

                is_route = w[0] == '~';
                domain = is_route ? w + 1 : w;

                if (dns_name_is_root(domain) || streq(domain, "*")) {
                        /* If the root domain appears as is, or the special token "*" is found, we'll consider this as
                         * routing domain, unconditionally. */
                        is_route = true;
                        domain = "."; /* make sure we don't allow empty strings, thus write the root domain as "." */

                } else {
                        r = dns_name_normalize(domain, &normalized);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r, "'%s' is not a valid domain name, ignoring.", domain);
                                continue;
                        }

                        domain = normalized;

                        if (is_localhost(domain)) {
                                log_syntax(unit, LOG_ERR, filename, line, 0, "'localhost' domain names may not be configure as search or route domains, ignoring assignment: %s", domain);
                                continue;
                        }
                }

                if (is_route) {
                        r = strv_extend(&n->route_domains, domain);
                        if (r < 0)
                                return log_oom();

                } else {
                        r = strv_extend(&n->search_domains, domain);
                        if (r < 0)
                                return log_oom();
                }
        }

        strv_uniq(n->route_domains);
        strv_uniq(n->search_domains);

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

        if (!IN_SET(netdev->kind,
                    NETDEV_KIND_IPIP,
                    NETDEV_KIND_SIT,
                    NETDEV_KIND_GRE,
                    NETDEV_KIND_GRETAP,
                    NETDEV_KIND_IP6GRE,
                    NETDEV_KIND_IP6GRETAP,
                    NETDEV_KIND_VTI,
                    NETDEV_KIND_VTI6,
                    NETDEV_KIND_IP6TNL)) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "NetDev is not a tunnel, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = hashmap_ensure_allocated(&network->stacked_netdevs, &string_hash_ops);
        if (r < 0)
                return log_oom();

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
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse DHCP option, ignoring: %s", rvalue);
                        return 0;
                }
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
DEFINE_CONFIG_PARSE_ENUM(config_parse_dhcp_client_identifier, dhcp_client_identifier, DHCPClientIdentifier, "Failed to parse client identifier type");

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
        if (r != 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "IPv6 token cannot be the ANY address, ignoring: %s", rvalue);
                return 0;
        }

        if ((buffer.in6.s6_addr32[0] | buffer.in6.s6_addr32[1]) != 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "IPv6 token cannot be longer than 64 bits, ignoring: %s", rvalue);
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
                                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse IPv6 privacy extensions option, ignoring: %s", rvalue);
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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Hostname is not valid, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = dns_name_is_valid(hn);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to check validity of hostname '%s', ignoring assignment: %m", rvalue);
                return 0;
        }
        if (r == 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Hostname is not a valid DNS domain name, ignoring assignment: %s", rvalue);
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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Timezone is not valid, ignoring assignment: %s", rvalue);
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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                if (inet_pton(AF_INET, w, &a) <= 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse DNS server address, ignoring: %s", w);
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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract word, ignoring: %s", rvalue);
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
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse DNS server address, ignoring: %s", w);

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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                r = dns_name_apply_idna(w, &idna);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to apply IDNA to domain name '%s', ignoring: %m", w);
                        continue;
                }
                if (r > 0) {
                        r = strv_push(&n->router_search_domains, idna);
                        if (r >= 0)
                                idna = NULL;
                } else {
                        r = strv_push(&n->router_search_domains, w);
                        if (r >= 0)
                                w = NULL;
                }
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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                if (inet_pton(AF_INET, w, &a) <= 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse NTP server address, ignoring: %s", w);
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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        break;
                }
                if (r == 0)
                        break;

                r = in_addr_from_string_auto(w, &family, &a);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse dns server address, ignoring: %s", w);
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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract negative trust anchor domain, ignoring: %s", rvalue);
                        break;
                }
                if (r == 0)
                        break;

                r = dns_name_is_valid(w);
                if (r <= 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "%s is not a valid domain name, ignoring.", w);
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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to extract NTP server name, ignoring: %s", rvalue);
                        break;
                }
                if (r == 0)
                        break;

                r = dns_name_is_valid_or_address(w);
                if (r <= 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "%s is not a valid domain name or IP address, ignoring.", w);
                        continue;
                }

                r = strv_push(l, w);
                if (r < 0)
                        return log_oom();

                w = NULL;
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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to split user classes option, ignoring: %s", rvalue);
                        break;
                }
                if (r == 0)
                        break;

                if (strlen(w) > 255) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "%s length is not in the range 1-255, ignoring.", w);
                        continue;
                }

                r = strv_push(l, w);
                if (r < 0)
                        return log_oom();

                w = NULL;
        }

        return 0;
}

int config_parse_dhcp_route_table(const char *unit,
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
                           "Unable to read RouteTable, ignoring assignment: %s", rvalue);
                return 0;
        }

        network->dhcp_route_table = rt;
        network->dhcp_route_table_set = true;

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_dhcp_use_domains, dhcp_use_domains, DHCPUseDomains, "Failed to parse DHCP use domains setting");

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
