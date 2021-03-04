/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <netinet/in.h>
#include <linux/netdevice.h>
#include <unistd.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "net-condition.h"
#include "networkd-address-label.h"
#include "networkd-address.h"
#include "networkd-dhcp-common.h"
#include "networkd-dhcp-server.h"
#include "networkd-fdb.h"
#include "networkd-manager.h"
#include "networkd-mdb.h"
#include "networkd-ndisc.h"
#include "networkd-neighbor.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
#include "networkd-radv.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-sriov.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "set.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tc.h"
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
         the ordering of option codes in the PRL. If this random ordering
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
        int r;

        assert(network);

        HASHMAP_FOREACH_KEY(kind, name, network->stacked_netdev_names) {
                _cleanup_(netdev_unrefp) NetDev *netdev = NULL;

                r = network_resolve_netdev_one(network, name, PTR_TO_INT(kind), &netdev);
                if (r <= 0)
                        continue;

                r = hashmap_ensure_put(&network->stacked_netdevs, &string_hash_ops, netdev->ifname, netdev);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_error_errno(r, "%s: Failed to add NetDev '%s' to network: %m",
                                               network->filename, (const char *) name);

                netdev = NULL;
        }

        return 0;
}

int network_verify(Network *network) {
        assert(network);
        assert(network->filename);

        if (net_match_is_empty(&network->match) && !network->conditions)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: No valid settings found in the [Match] section, ignoring file. "
                                         "To match all interfaces, add Name=* in the [Match] section.",
                                         network->filename);

        /* skip out early if configuration does not match the environment */
        if (!condition_test_list(network->conditions, environ, NULL, NULL, NULL))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: Conditions in the file do not match the system environment, skipping.",
                                       network->filename);

        (void) network_resolve_netdev_one(network, network->batadv_name, NETDEV_KIND_BATADV, &network->batadv);
        (void) network_resolve_netdev_one(network, network->bond_name, NETDEV_KIND_BOND, &network->bond);
        (void) network_resolve_netdev_one(network, network->bridge_name, NETDEV_KIND_BRIDGE, &network->bridge);
        (void) network_resolve_netdev_one(network, network->vrf_name, NETDEV_KIND_VRF, &network->vrf);
        (void) network_resolve_stacked_netdevs(network);

        /* Free unnecessary entries. */
        network->batadv_name = mfree(network->batadv_name);
        network->bond_name = mfree(network->bond_name);
        network->bridge_name = mfree(network->bridge_name);
        network->vrf_name = mfree(network->vrf_name);
        network->stacked_netdev_names = hashmap_free_free_key(network->stacked_netdev_names);

        if (network->bond) {
                /* Bonding slave does not support addressing. */
                if (network->link_local >= 0 && network->link_local != ADDRESS_FAMILY_NO) {
                        log_warning("%s: Cannot enable LinkLocalAddressing= when Bond= is specified, disabling LinkLocalAddressing=.",
                                    network->filename);
                        network->link_local = ADDRESS_FAMILY_NO;
                }
                if (network->dhcp_server) {
                        log_warning("%s: Cannot enable DHCPServer= when Bond= is specified, disabling DHCPServer=.",
                                    network->filename);
                        network->dhcp_server = false;
                }
                if (!ordered_hashmap_isempty(network->addresses_by_section))
                        log_warning("%s: Cannot set addresses when Bond= is specified, ignoring addresses.",
                                    network->filename);
                if (!hashmap_isempty(network->routes_by_section))
                        log_warning("%s: Cannot set routes when Bond= is specified, ignoring routes.",
                                    network->filename);

                network->addresses_by_section = ordered_hashmap_free_with_destructor(network->addresses_by_section, address_free);
                network->routes_by_section = hashmap_free_with_destructor(network->routes_by_section, route_free);
        }

        if (network->link_local < 0)
                network->link_local = network->bridge ? ADDRESS_FAMILY_NO : ADDRESS_FAMILY_IPV6;

        /* IPMasquerade implies IPForward */
        network->ip_forward |= network->ip_masquerade;

        network_adjust_ipv6_accept_ra(network);
        network_adjust_dhcp(network);
        network_adjust_radv(network);

        if (network->mtu > 0 && network->dhcp_use_mtu) {
                log_warning("%s: MTUBytes= in [Link] section and UseMTU= in [DHCP] section are set. "
                            "Disabling UseMTU=.", network->filename);
                network->dhcp_use_mtu = false;
        }

        if (network->dhcp_use_gateway < 0)
                network->dhcp_use_gateway = network->dhcp_use_routes;

        if (network->dhcp_critical >= 0) {
                if (network->keep_configuration >= 0)
                        log_warning("%s: Both KeepConfiguration= and deprecated CriticalConnection= are set. "
                                    "Ignoring CriticalConnection=.", network->filename);
                else if (network->dhcp_critical)
                        /* CriticalConnection=yes also preserve foreign static configurations. */
                        network->keep_configuration = KEEP_CONFIGURATION_YES;
                else
                        network->keep_configuration = KEEP_CONFIGURATION_NO;
        }

        if (!strv_isempty(network->bind_carrier)) {
                if (!IN_SET(network->activation_policy, _ACTIVATION_POLICY_INVALID, ACTIVATION_POLICY_BOUND))
                        log_warning("%s: ActivationPolicy=bound is required with BindCarrier=. "
                                    "Setting ActivationPolicy=bound.", network->filename);
                network->activation_policy = ACTIVATION_POLICY_BOUND;
        } else if (network->activation_policy == ACTIVATION_POLICY_BOUND) {
                log_warning("%s: ActivationPolicy=bound requires BindCarrier=. "
                            "Ignoring ActivationPolicy=bound.", network->filename);
                network->activation_policy = ACTIVATION_POLICY_UP;
        }

        if (network->activation_policy == _ACTIVATION_POLICY_INVALID)
                network->activation_policy = ACTIVATION_POLICY_UP;

        if (network->activation_policy == ACTIVATION_POLICY_ALWAYS_UP) {
                if (network->ignore_carrier_loss == false)
                        log_warning("%s: IgnoreCarrierLoss=false conflicts with ActivationPolicy=always-up. "
                                    "Setting IgnoreCarrierLoss=true.", network->filename);
                network->ignore_carrier_loss = true;
        }

        if (network->ignore_carrier_loss < 0)
                network->ignore_carrier_loss = network->configure_without_carrier;

        if (network->keep_configuration < 0)
                network->keep_configuration = KEEP_CONFIGURATION_NO;

        if (network->ipv6_proxy_ndp == 0 && !set_isempty(network->ipv6_proxy_ndp_addresses)) {
                log_warning("%s: IPv6ProxyNDP= is disabled. Ignoring IPv6ProxyNDPAddress=.", network->filename);
                network->ipv6_proxy_ndp_addresses = set_free_free(network->ipv6_proxy_ndp_addresses);
        }

        network_drop_invalid_addresses(network);
        network_drop_invalid_routes(network);
        network_drop_invalid_nexthops(network);
        network_drop_invalid_fdb_entries(network);
        network_drop_invalid_mdb_entries(network);
        network_drop_invalid_neighbors(network);
        network_drop_invalid_address_labels(network);
        network_drop_invalid_prefixes(network);
        network_drop_invalid_route_prefixes(network);
        network_drop_invalid_routing_policy_rules(network);
        network_drop_invalid_traffic_control(network);
        network_drop_invalid_sr_iov(network);

        return 0;
}

int network_load_one(Manager *manager, OrderedHashmap **networks, const char *filename) {
        _cleanup_free_ char *fname = NULL, *name = NULL;
        _cleanup_(network_unrefp) Network *network = NULL;
        const char *dropin_dirname;
        char *d;
        int r;

        assert(manager);
        assert(filename);

        r = null_or_empty_path(filename);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;
        if (r > 0) {
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

                .manager = manager,
                .n_ref = 1,

                .required_for_online = true,
                .required_operstate_for_online = LINK_OPERSTATE_RANGE_DEFAULT,
                .activation_policy = _ACTIVATION_POLICY_INVALID,
                .arp = -1,
                .multicast = -1,
                .allmulticast = -1,
                .promiscuous = -1,

                .configure_without_carrier = false,
                .ignore_carrier_loss = -1,
                .keep_configuration = _KEEP_CONFIGURATION_INVALID,

                .dhcp = ADDRESS_FAMILY_NO,
                .duid.type = _DUID_TYPE_INVALID,
                .dhcp_critical = -1,
                .dhcp_use_ntp = true,
                .dhcp_use_sip = true,
                .dhcp_use_dns = true,
                .dhcp_use_hostname = true,
                .dhcp_use_routes = true,
                .dhcp_use_gateway = -1,
                /* NOTE: this var might be overwritten by network_apply_anonymize_if_set */
                .dhcp_send_hostname = true,
                .dhcp_send_release = true,
                /* To enable/disable RFC7844 Anonymity Profiles */
                .dhcp_anonymize = false,
                .dhcp_route_metric = DHCP_ROUTE_METRIC,
                /* NOTE: this var might be overwritten by network_apply_anonymize_if_set */
                .dhcp_client_identifier = DHCP_CLIENT_ID_DUID,
                .dhcp_route_table = RT_TABLE_MAIN,
                .dhcp_route_table_set = false,
                /* NOTE: from man: UseMTU=... Defaults to false*/
                .dhcp_use_mtu = false,
                /* NOTE: from man: UseTimezone=... Defaults to "no".*/
                .dhcp_use_timezone = false,
                .dhcp_ip_service_type = -1,

                .dhcp6_use_address = true,
                .dhcp6_use_dns = true,
                .dhcp6_use_hostname = true,
                .dhcp6_use_ntp = true,
                .dhcp6_rapid_commit = true,
                .dhcp6_route_metric = DHCP_ROUTE_METRIC,

                .dhcp6_pd = -1,
                .dhcp6_pd_announce = true,
                .dhcp6_pd_assign = true,
                .dhcp6_pd_manage_temporary_address = true,
                .dhcp6_pd_subnet_id = -1,

                .dhcp_server_emit[SD_DHCP_LEASE_DNS].emit = true,
                .dhcp_server_emit[SD_DHCP_LEASE_NTP].emit = true,
                .dhcp_server_emit[SD_DHCP_LEASE_SIP].emit = true,

                .dhcp_server_emit_router = true,
                .dhcp_server_emit_timezone = true,

                .router_lifetime_usec = 30 * USEC_PER_MINUTE,
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
                .bridge_proxy_arp = -1,
                .bridge_proxy_arp_wifi = -1,
                .priority = LINK_BRIDGE_PORT_PRIORITY_INVALID,
                .multicast_router = _MULTICAST_ROUTER_INVALID,

                .lldp_mode = LLDP_MODE_ROUTERS_ONLY,

                .dns_default_route = -1,
                .llmnr = RESOLVE_SUPPORT_YES,
                .mdns = RESOLVE_SUPPORT_NO,
                .dnssec_mode = _DNSSEC_MODE_INVALID,
                .dns_over_tls_mode = _DNS_OVER_TLS_MODE_INVALID,

                /* If LinkLocalAddressing= is not set, then set to ADDRESS_FAMILY_IPV6 later. */
                .link_local = _ADDRESS_FAMILY_INVALID,
                .ipv6ll_address_gen_mode = _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_INVALID,

                .ipv4_accept_local = -1,
                .ipv4_route_localnet = -1,
                .ipv6_privacy_extensions = IPV6_PRIVACY_EXTENSIONS_NO,
                .ipv6_accept_ra = -1,
                .ipv6_dad_transmits = -1,
                .ipv6_hop_limit = -1,
                .ipv6_proxy_ndp = -1,
                .proxy_arp = -1,

                .ipv6_accept_ra_use_dns = true,
                .ipv6_accept_ra_use_autonomous_prefix = true,
                .ipv6_accept_ra_use_onlink_prefix = true,
                .ipv6_accept_ra_route_table = RT_TABLE_MAIN,
                .ipv6_accept_ra_route_table_set = false,
                .ipv6_accept_ra_start_dhcp6_client = IPV6_ACCEPT_RA_START_DHCP6_CLIENT_YES,

                .can_triple_sampling = -1,
                .can_berr_reporting = -1,
                .can_termination = -1,
                .can_listen_only = -1,
                .can_fd_mode = -1,
                .can_non_iso = -1,
        };

        r = config_parse_many(
                        STRV_MAKE_CONST(filename), NETWORK_DIRS, dropin_dirname,
                        "Match\0"
                        "Link\0"
                        "SR-IOV\0"
                        "Network\0"
                        "Address\0"
                        "Neighbor\0"
                        "IPv6AddressLabel\0"
                        "RoutingPolicyRule\0"
                        "Route\0"
                        "NextHop\0"
                        "DHCP\0" /* compat */
                        "DHCPv4\0"
                        "DHCPv6\0"
                        "DHCPv6PrefixDelegation\0"
                        "DHCPServer\0"
                        "IPv6AcceptRA\0"
                        "IPv6NDPProxyAddress\0"
                        "Bridge\0"
                        "BridgeFDB\0"
                        "BridgeMDB\0"
                        "BridgeVLAN\0"
                        "IPv6SendRA\0"
                        "IPv6PrefixDelegation\0"
                        "IPv6Prefix\0"
                        "IPv6RoutePrefix\0"
                        "LLDP\0"
                        "TrafficControlQueueingDiscipline\0"
                        "CAN\0"
                        "QDisc\0"
                        "BFIFO\0"
                        "CAKE\0"
                        "ControlledDelay\0"
                        "DeficitRoundRobinScheduler\0"
                        "DeficitRoundRobinSchedulerClass\0"
                        "EnhancedTransmissionSelection\0"
                        "FairQueueing\0"
                        "FairQueueingControlledDelay\0"
                        "FlowQueuePIE\0"
                        "GenericRandomEarlyDetection\0"
                        "HeavyHitterFilter\0"
                        "HierarchyTokenBucket\0"
                        "HierarchyTokenBucketClass\0"
                        "NetworkEmulator\0"
                        "PFIFO\0"
                        "PFIFOFast\0"
                        "PFIFOHeadDrop\0"
                        "PIE\0"
                        "QuickFairQueueing\0"
                        "QuickFairQueueingClass\0"
                        "StochasticFairBlue\0"
                        "StochasticFairnessQueueing\0"
                        "TokenBucketFilter\0"
                        "TrivialLinkEqualizer\0",
                        config_item_perf_lookup, network_network_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        network,
                        &network->timestamp);
        if (r < 0)
                return r;

        network_apply_anonymize_if_set(network);

        r = network_add_ipv4ll_route(network);
        if (r < 0)
                log_warning_errno(r, "%s: Failed to add IPv4LL route, ignoring: %m", network->filename);

        r = network_add_default_route_on_device(network);
        if (r < 0)
                log_warning_errno(r, "%s: Failed to add default route on device, ignoring: %m",
                                  network->filename);

        if (network_verify(network) < 0)
                /* Ignore .network files that do not match the conditions. */
                return 0;

        r = ordered_hashmap_ensure_put(networks, &string_hash_ops, network->name, network);
        if (r < 0)
                return r;

        TAKE_PTR(network);
        return 0;
}

int network_load(Manager *manager, OrderedHashmap **networks) {
        _cleanup_strv_free_ char **files = NULL;
        char **f;
        int r;

        assert(manager);

        ordered_hashmap_clear_with_destructor(*networks, network_unref);

        r = conf_files_list_strv(&files, ".network", NULL, 0, NETWORK_DIRS);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate network files: %m");

        STRV_FOREACH(f, files) {
                r = network_load_one(manager, networks, *f);
                if (r < 0)
                        log_error_errno(r, "Failed to load %s, ignoring: %m", *f);
        }

        return 0;
}

int network_reload(Manager *manager) {
        OrderedHashmap *new_networks = NULL;
        Network *n, *old;
        int r;

        assert(manager);

        r = network_load(manager, &new_networks);
        if (r < 0)
                goto failure;

        ORDERED_HASHMAP_FOREACH(n, new_networks) {
                r = network_get_by_name(manager, n->name, &old);
                if (r < 0)
                        continue; /* The .network file is new. */

                if (n->timestamp != old->timestamp)
                        continue; /* The .network file is modified. */

                if (!streq(n->filename, old->filename))
                        continue;

                r = ordered_hashmap_replace(new_networks, old->name, old);
                if (r < 0)
                        goto failure;

                network_ref(old);
                network_unref(n);
        }

        ordered_hashmap_free_with_destructor(manager->networks, network_unref);
        manager->networks = new_networks;

        return 0;

failure:
        ordered_hashmap_free_with_destructor(new_networks, network_unref);

        return r;
}

static Network *network_free(Network *network) {
        if (!network)
                return NULL;

        free(network->filename);

        net_match_clear(&network->match);
        condition_free_list(network->conditions);

        free(network->description);
        free(network->dhcp_vendor_class_identifier);
        free(network->dhcp_mudurl);
        strv_free(network->dhcp_user_class);
        free(network->dhcp_hostname);
        set_free(network->dhcp_deny_listed_ip);
        set_free(network->dhcp_allow_listed_ip);
        set_free(network->dhcp_request_options);
        set_free(network->dhcp6_request_options);
        free(network->mac);
        free(network->dhcp6_mudurl);
        strv_free(network->dhcp6_user_class);
        strv_free(network->dhcp6_vendor_class);

        strv_free(network->ntp);
        for (unsigned i = 0; i < network->n_dns; i++)
                in_addr_full_free(network->dns[i]);
        free(network->dns);
        ordered_set_free(network->search_domains);
        ordered_set_free(network->route_domains);
        strv_free(network->bind_carrier);

        ordered_set_free(network->router_search_domains);
        free(network->router_dns);
        set_free_free(network->ndisc_deny_listed_router);
        set_free_free(network->ndisc_allow_listed_router);
        set_free_free(network->ndisc_deny_listed_prefix);
        set_free_free(network->ndisc_allow_listed_prefix);
        set_free_free(network->ndisc_deny_listed_route_prefix);
        set_free_free(network->ndisc_allow_listed_route_prefix);

        free(network->batadv_name);
        free(network->bridge_name);
        free(network->bond_name);
        free(network->vrf_name);
        hashmap_free_free_key(network->stacked_netdev_names);
        netdev_unref(network->bridge);
        netdev_unref(network->bond);
        netdev_unref(network->vrf);
        hashmap_free_with_destructor(network->stacked_netdevs, netdev_unref);

        set_free_free(network->ipv6_proxy_ndp_addresses);
        ordered_hashmap_free_with_destructor(network->addresses_by_section, address_free);
        hashmap_free_with_destructor(network->routes_by_section, route_free);
        hashmap_free_with_destructor(network->nexthops_by_section, nexthop_free);
        hashmap_free_with_destructor(network->fdb_entries_by_section, fdb_entry_free);
        hashmap_free_with_destructor(network->mdb_entries_by_section, mdb_entry_free);
        hashmap_free_with_destructor(network->neighbors_by_section, neighbor_free);
        hashmap_free_with_destructor(network->address_labels_by_section, address_label_free);
        hashmap_free_with_destructor(network->prefixes_by_section, prefix_free);
        hashmap_free_with_destructor(network->route_prefixes_by_section, route_prefix_free);
        hashmap_free_with_destructor(network->rules_by_section, routing_policy_rule_free);
        ordered_hashmap_free_with_destructor(network->sr_iov_by_section, sr_iov_free);
        ordered_hashmap_free_with_destructor(network->tc_by_section, traffic_control_free);

        if (network->manager &&
            network->manager->duids_requesting_uuid)
                set_remove(network->manager->duids_requesting_uuid, &network->duid);

        free(network->name);

        free(network->dhcp_server_timezone);

        for (sd_dhcp_lease_server_type_t t = 0; t < _SD_DHCP_LEASE_SERVER_TYPE_MAX; t++)
                free(network->dhcp_server_emit[t].addresses);

        set_free_free(network->dnssec_negative_trust_anchors);

        free(network->lldp_mud);

        ordered_hashmap_free(network->dhcp_client_send_options);
        ordered_hashmap_free(network->dhcp_client_send_vendor_options);
        ordered_hashmap_free(network->dhcp_server_send_options);
        ordered_hashmap_free(network->dhcp_server_send_vendor_options);
        ordered_set_free(network->ipv6_tokens);
        ordered_hashmap_free(network->dhcp6_client_send_options);
        ordered_hashmap_free(network->dhcp6_client_send_vendor_options);

        return mfree(network);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Network, network, network_free);

int network_get_by_name(Manager *manager, const char *name, Network **ret) {
        Network *network;

        assert(manager);
        assert(name);
        assert(ret);

        network = ordered_hashmap_get(manager->networks, name);
        if (!network)
                return -ENOENT;

        *ret = network;

        return 0;
}

int network_get(Manager *manager, unsigned short iftype, sd_device *device,
                const char *ifname, char * const *alternative_names, const char *driver,
                const struct ether_addr *mac, const struct ether_addr *permanent_mac,
                enum nl80211_iftype wlan_iftype, const char *ssid, const struct ether_addr *bssid,
                Network **ret) {
        Network *network;

        assert(manager);
        assert(ret);

        ORDERED_HASHMAP_FOREACH(network, manager->networks)
                if (net_match_config(&network->match, device, mac, permanent_mac, driver, iftype,
                                     ifname, alternative_names, wlan_iftype, ssid, bssid)) {
                        if (network->match.ifname && device) {
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

        *ret = NULL;

        return -ENOENT;
}

bool network_has_static_ipv6_configurations(Network *network) {
        Address *address;
        Route *route;
        FdbEntry *fdb;
        MdbEntry *mdb;
        Neighbor *neighbor;

        assert(network);

        ORDERED_HASHMAP_FOREACH(address, network->addresses_by_section)
                if (address->family == AF_INET6)
                        return true;

        HASHMAP_FOREACH(route, network->routes_by_section)
                if (route->family == AF_INET6)
                        return true;

        HASHMAP_FOREACH(fdb, network->fdb_entries_by_section)
                if (fdb->family == AF_INET6)
                        return true;

        HASHMAP_FOREACH(mdb, network->mdb_entries_by_section)
                if (mdb->family == AF_INET6)
                        return true;

        HASHMAP_FOREACH(neighbor, network->neighbors_by_section)
                if (neighbor->family == AF_INET6)
                        return true;

        if (!hashmap_isempty(network->address_labels_by_section))
                return true;

        if (!hashmap_isempty(network->prefixes_by_section))
                return true;

        if (!hashmap_isempty(network->route_prefixes_by_section))
                return true;

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
                      NETDEV_KIND_IPVLAN, NETDEV_KIND_IPVTAP, NETDEV_KIND_VXLAN,
                      NETDEV_KIND_L2TP, NETDEV_KIND_MACSEC, _NETDEV_KIND_TUNNEL,
                      NETDEV_KIND_XFRM));

        if (!ifname_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid netdev name in %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        name = strdup(rvalue);
        if (!name)
                return log_oom();

        r = hashmap_ensure_put(h, &string_hash_ops, name, INT_TO_PTR(kind));
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Cannot add NetDev '%s' to network, ignoring assignment: %m", name);
        else if (r == 0)
                log_syntax(unit, LOG_DEBUG, filename, line, r,
                           "NetDev '%s' specified twice, ignoring.", name);
        else
                TAKE_PTR(name);

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

        Network *n = data;
        int r;

        assert(n);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                n->search_domains = ordered_set_free(n->search_domains);
                n->route_domains = ordered_set_free(n->route_domains);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *w = NULL, *normalized = NULL;
                const char *domain;
                bool is_route;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract search or route domain, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

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
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "'%s' is not a valid domain name, ignoring.", domain);
                                continue;
                        }

                        domain = normalized;

                        if (is_localhost(domain)) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0,
                                           "'localhost' domain may not be configured as search or route domain, ignoring assignment: %s",
                                           domain);
                                continue;
                        }
                }

                OrderedSet **set = is_route ? &n->route_domains : &n->search_domains;
                r = ordered_set_ensure_allocated(set, &string_hash_ops_free);
                if (r < 0)
                        return log_oom();

                r = ordered_set_put_strdup(*set, domain);
                if (r < 0)
                        return log_oom();
        }
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

        if (!hostname_is_valid(hn, 0)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Hostname is not valid, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = dns_name_is_valid(hn);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to check validity of hostname '%s', ignoring assignment: %m", rvalue);
                return 0;
        }
        if (r == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
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

        if (!timezone_is_valid(tz, LOG_WARNING)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Timezone is not valid, ignoring assignment: %s", rvalue);
                return 0;
        }

        return free_and_replace(*datap, tz);
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

        if (isempty(rvalue)) {
                for (unsigned i = 0; i < n->n_dns; i++)
                        in_addr_full_free(n->dns[i]);
                n->dns = mfree(n->dns);
                n->n_dns = 0;
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_(in_addr_full_freep) struct in_addr_full *dns = NULL;
                _cleanup_free_ char *w = NULL;
                struct in_addr_full **m;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = in_addr_full_new_from_string(w, &dns);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse dns server address, ignoring: %s", w);
                        continue;
                }

                if (IN_SET(dns->port, 53, 853))
                        dns->port = 0;

                m = reallocarray(n->dns, n->n_dns + 1, sizeof(struct in_addr_full*));
                if (!m)
                        return log_oom();

                m[n->n_dns++] = TAKE_PTR(dns);
                n->dns = m;
        }
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

        Network *n = data;
        int r;

        assert(n);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                n->dnssec_negative_trust_anchors = set_free_free(n->dnssec_negative_trust_anchors);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *w = NULL;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract negative trust anchor domain, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = dns_name_is_valid(w);
                if (r <= 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "%s is not a valid domain name, ignoring.", w);
                        continue;
                }

                r = set_ensure_consume(&n->dnssec_negative_trust_anchors, &dns_name_hash_ops, TAKE_PTR(w));
                if (r < 0)
                        return log_oom();
        }
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

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *w = NULL;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract NTP server name, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = dns_name_is_valid_or_address(w);
                if (r <= 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "%s is not a valid domain name or IP address, ignoring.", w);
                        continue;
                }

                if (strv_length(*l) > MAX_NTP_SERVERS) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "More than %u NTP servers specified, ignoring \"%s\" and any subsequent entries.",
                                   MAX_NTP_SERVERS, w);
                        return 0;
                }

                r = strv_consume(l, TAKE_PTR(w));
                if (r < 0)
                        return log_oom();
        }
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
        LinkOperationalStateRange range;
        bool required = true;
        int r;

        if (isempty(rvalue)) {
                network->required_for_online = true;
                network->required_operstate_for_online = LINK_OPERSTATE_RANGE_DEFAULT;
                return 0;
        }

        r = parse_operational_state_range(rvalue, &range);
        if (r < 0) {
                r = parse_boolean(rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse %s= setting, ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }

                required = r;
                range = LINK_OPERSTATE_RANGE_DEFAULT;
        }

        network->required_for_online = required;
        network->required_operstate_for_online = range;

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_keep_configuration, keep_configuration, KeepConfiguration,
                         "Failed to parse KeepConfiguration= setting");

static const char* const keep_configuration_table[_KEEP_CONFIGURATION_MAX] = {
        [KEEP_CONFIGURATION_NO]           = "no",
        [KEEP_CONFIGURATION_DHCP_ON_STOP] = "dhcp-on-stop",
        [KEEP_CONFIGURATION_DHCP]         = "dhcp",
        [KEEP_CONFIGURATION_STATIC]       = "static",
        [KEEP_CONFIGURATION_YES]          = "yes",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(keep_configuration, KeepConfiguration, KEEP_CONFIGURATION_YES);

static const char* const ipv6_link_local_address_gen_mode_table[_IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_MAX] = {
        [IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_EUI64] = "eui64",
        [IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_NONE] = "none",
        [IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_STABLE_PRIVACY] = "stable-privacy",
        [IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_RANDOM] = "random",
};

DEFINE_STRING_TABLE_LOOKUP(ipv6_link_local_address_gen_mode, IPv6LinkLocalAddressGenMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_ipv6_link_local_address_gen_mode, ipv6_link_local_address_gen_mode, IPv6LinkLocalAddressGenMode, "Failed to parse IPv6 link local address generation mode");

static const char* const activation_policy_table[_ACTIVATION_POLICY_MAX] = {
        [ACTIVATION_POLICY_UP] =          "up",
        [ACTIVATION_POLICY_ALWAYS_UP] =   "always-up",
        [ACTIVATION_POLICY_MANUAL] =      "manual",
        [ACTIVATION_POLICY_ALWAYS_DOWN] = "always-down",
        [ACTIVATION_POLICY_DOWN] =        "down",
        [ACTIVATION_POLICY_BOUND] =       "bound",
};

DEFINE_STRING_TABLE_LOOKUP(activation_policy, ActivationPolicy);
DEFINE_CONFIG_PARSE_ENUM(config_parse_activation_policy, activation_policy, ActivationPolicy, "Failed to parse activation policy");
