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
#include "netdev/macvlan.h"
#include "networkd-address-label.h"
#include "networkd-address.h"
#include "networkd-bridge-fdb.h"
#include "networkd-bridge-mdb.h"
#include "networkd-dhcp-common.h"
#include "networkd-dhcp-server-static-lease.h"
#include "networkd-ipv6-proxy-ndp.h"
#include "networkd-manager.h"
#include "networkd-ndisc.h"
#include "networkd-neighbor.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
#include "networkd-radv.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-sriov.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "qdisc.h"
#include "radv-internal.h"
#include "set.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tclass.h"

/* Let's assume that anything above this number is a user misconfiguration. */
#define MAX_NTP_SERVERS 128U

static int network_resolve_netdev_one(Network *network, const char *name, NetDevKind kind, NetDev **ret) {
        const char *kind_string;
        NetDev *netdev;
        int r;

        /* For test-networkd-conf, the check must be earlier than the assertions. */
        if (!name)
                return 0;

        assert(network);
        assert(network->manager);
        assert(network->filename);
        assert(ret);

        if (kind == _NETDEV_KIND_TUNNEL)
                kind_string = "tunnel";
        else {
                kind_string = netdev_kind_to_string(kind);
                if (!kind_string)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: Invalid NetDev kind of %s, ignoring assignment.",
                                                 network->filename, name);
        }

        r = netdev_get(network->manager, name, &netdev);
        if (r < 0)
                return log_warning_errno(r, "%s: %s NetDev could not be found, ignoring assignment.",
                                         network->filename, name);

        if (netdev->kind != kind && !(kind == _NETDEV_KIND_TUNNEL &&
                                      IN_SET(netdev->kind,
                                             NETDEV_KIND_ERSPAN,
                                             NETDEV_KIND_GRE,
                                             NETDEV_KIND_GRETAP,
                                             NETDEV_KIND_IP6GRE,
                                             NETDEV_KIND_IP6GRETAP,
                                             NETDEV_KIND_IP6TNL,
                                             NETDEV_KIND_IPIP,
                                             NETDEV_KIND_SIT,
                                             NETDEV_KIND_VTI,
                                             NETDEV_KIND_VTI6)))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: NetDev %s is not a %s, ignoring assignment",
                                         network->filename, name, kind_string);

        *ret = netdev_ref(netdev);
        return 1;
}

static int network_resolve_stacked_netdevs(Network *network) {
        void *name, *kind;
        int r;

        assert(network);

        HASHMAP_FOREACH_KEY(kind, name, network->stacked_netdev_names) {
                _cleanup_(netdev_unrefp) NetDev *netdev = NULL;

                if (network_resolve_netdev_one(network, name, PTR_TO_INT(kind), &netdev) <= 0)
                        continue;

                r = hashmap_ensure_put(&network->stacked_netdevs, &string_hash_ops, netdev->ifname, netdev);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        log_warning_errno(r, "%s: Failed to add NetDev '%s' to network, ignoring: %m",
                                          network->filename, (const char *) name);

                netdev = NULL;
        }

        return 0;
}

int network_verify(Network *network) {
        int r;

        assert(network);
        assert(network->manager);
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

        if (network->keep_master) {
                if (network->batadv_name)
                        log_warning("%s: BatmanAdvanced= set with KeepMaster= enabled, ignoring BatmanAdvanced=.",
                                    network->filename);
                if (network->bond_name)
                        log_warning("%s: Bond= set with KeepMaster= enabled, ignoring Bond=.",
                                    network->filename);
                if (network->bridge_name)
                        log_warning("%s: Bridge= set with KeepMaster= enabled, ignoring Bridge=.",
                                    network->filename);
                if (network->vrf_name)
                        log_warning("%s: VRF= set with KeepMaster= enabled, ignoring VRF=.",
                                    network->filename);

                network->batadv_name = mfree(network->batadv_name);
                network->bond_name = mfree(network->bond_name);
                network->bridge_name = mfree(network->bridge_name);
                network->vrf_name = mfree(network->vrf_name);
        }

        (void) network_resolve_netdev_one(network, network->batadv_name, NETDEV_KIND_BATADV, &network->batadv);
        (void) network_resolve_netdev_one(network, network->bond_name, NETDEV_KIND_BOND, &network->bond);
        (void) network_resolve_netdev_one(network, network->bridge_name, NETDEV_KIND_BRIDGE, &network->bridge);
        (void) network_resolve_netdev_one(network, network->vrf_name, NETDEV_KIND_VRF, &network->vrf);
        r = network_resolve_stacked_netdevs(network);
        if (r < 0)
                return r;

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
                if (!ordered_hashmap_isempty(network->addresses_by_section))
                        log_warning("%s: Cannot set addresses when Bond= is specified, ignoring addresses.",
                                    network->filename);
                if (!hashmap_isempty(network->routes_by_section))
                        log_warning("%s: Cannot set routes when Bond= is specified, ignoring routes.",
                                    network->filename);

                network->addresses_by_section = ordered_hashmap_free(network->addresses_by_section);
                network->routes_by_section = hashmap_free_with_destructor(network->routes_by_section, route_free);
        }

        if (network->link_local < 0) {
                network->link_local = ADDRESS_FAMILY_IPV6;

                if (network->keep_master || network->bridge)
                        network->link_local = ADDRESS_FAMILY_NO;
                else {
                        NetDev *netdev;

                        HASHMAP_FOREACH(netdev, network->stacked_netdevs) {
                                MacVlan *m;

                                if (netdev->kind == NETDEV_KIND_MACVLAN)
                                        m = MACVLAN(netdev);
                                else if (netdev->kind == NETDEV_KIND_MACVTAP)
                                        m = MACVTAP(netdev);
                                else
                                        continue;

                                if (m->mode == NETDEV_MACVLAN_MODE_PASSTHRU)
                                        network->link_local = ADDRESS_FAMILY_NO;

                                /* There won't be a passthru MACVLAN/MACVTAP if there's already one in another mode */
                                break;
                        }
                }
        }

        if (network->ipv6ll_address_gen_mode == IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_NONE)
                SET_FLAG(network->link_local, ADDRESS_FAMILY_IPV6, false);

        if (in6_addr_is_set(&network->ipv6ll_stable_secret) &&
            network->ipv6ll_address_gen_mode < 0)
                network->ipv6ll_address_gen_mode = IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_STABLE_PRIVACY;

        /* IPMasquerade implies IPForward */
        network->ip_forward |= network->ip_masquerade;

        network_adjust_ipv6_proxy_ndp(network);
        network_adjust_ipv6_accept_ra(network);
        network_adjust_dhcp(network);
        network_adjust_radv(network);
        network_adjust_bridge_vlan(network);

        if (network->mtu > 0 && network->dhcp_use_mtu) {
                log_warning("%s: MTUBytes= in [Link] section and UseMTU= in [DHCP] section are set. "
                            "Disabling UseMTU=.", network->filename);
                network->dhcp_use_mtu = false;
        }

        if (network->dhcp_critical >= 0) {
                if (network->keep_configuration >= 0) {
                        if (network->manager->keep_configuration < 0)
                                log_warning("%s: Both KeepConfiguration= and deprecated CriticalConnection= are set. "
                                            "Ignoring CriticalConnection=.", network->filename);
                } else if (network->dhcp_critical)
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
                if (network->ignore_carrier_loss_set && network->ignore_carrier_loss_usec < USEC_INFINITY)
                        log_warning("%s: IgnoreCarrierLoss=no or finite timespan conflicts with ActivationPolicy=always-up. "
                                    "Setting IgnoreCarrierLoss=yes.", network->filename);
                network->ignore_carrier_loss_set = true;
                network->ignore_carrier_loss_usec = USEC_INFINITY;
        }

        if (!network->ignore_carrier_loss_set) /* Set implied default. */
                network->ignore_carrier_loss_usec = network->configure_without_carrier ? USEC_INFINITY : 0;

        if (IN_SET(network->activation_policy, ACTIVATION_POLICY_DOWN, ACTIVATION_POLICY_ALWAYS_DOWN, ACTIVATION_POLICY_MANUAL)) {
                if (network->required_for_online < 0 ||
                    (network->required_for_online == true && network->activation_policy == ACTIVATION_POLICY_ALWAYS_DOWN)) {
                        log_debug("%s: Setting RequiredForOnline=no because ActivationPolicy=%s.", network->filename,
                                  activation_policy_to_string(network->activation_policy));
                        network->required_for_online = false;
                } else if (network->required_for_online == true)
                        log_warning("%s: RequiredForOnline=yes and ActivationPolicy=%s, "
                                    "this may cause a delay at boot.", network->filename,
                                    activation_policy_to_string(network->activation_policy));
        }

        if (network->required_for_online < 0)
                network->required_for_online = true;

        if (network->keep_configuration < 0)
                network->keep_configuration = KEEP_CONFIGURATION_NO;

        if (network->ipv6_proxy_ndp == 0 && !set_isempty(network->ipv6_proxy_ndp_addresses)) {
                log_warning("%s: IPv6ProxyNDP= is disabled. Ignoring IPv6ProxyNDPAddress=.", network->filename);
                network->ipv6_proxy_ndp_addresses = set_free_free(network->ipv6_proxy_ndp_addresses);
        }

        r = network_drop_invalid_addresses(network);
        if (r < 0)
                return r; /* network_drop_invalid_addresses() logs internally. */
        network_drop_invalid_routes(network);
        r = network_drop_invalid_nexthops(network);
        if (r < 0)
                return r;
        network_drop_invalid_bridge_fdb_entries(network);
        network_drop_invalid_bridge_mdb_entries(network);
        r = network_drop_invalid_neighbors(network);
        if (r < 0)
                return r;
        network_drop_invalid_address_labels(network);
        network_drop_invalid_prefixes(network);
        network_drop_invalid_route_prefixes(network);
        network_drop_invalid_routing_policy_rules(network);
        network_drop_invalid_qdisc(network);
        network_drop_invalid_tclass(network);
        r = sr_iov_drop_invalid_sections(UINT32_MAX, network->sr_iov_by_section);
        if (r < 0)
                return r; /* sr_iov_drop_invalid_sections() logs internally. */
        network_drop_invalid_static_leases(network);

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
        if (r < 0)
                return log_warning_errno(r, "Failed to check if \"%s\" is empty: %m", filename);
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
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid file name: %s", filename);

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

                .required_for_online = -1,
                .required_operstate_for_online = LINK_OPERSTATE_RANGE_DEFAULT,
                .activation_policy = _ACTIVATION_POLICY_INVALID,
                .group = -1,
                .arp = -1,
                .multicast = -1,
                .allmulticast = -1,
                .promiscuous = -1,

                .keep_configuration = manager->keep_configuration,

                .dhcp_duid.type = _DUID_TYPE_INVALID,
                .dhcp_critical = -1,
                .dhcp_use_ntp = true,
                .dhcp_routes_to_ntp = true,
                .dhcp_use_sip = true,
                .dhcp_use_captive_portal = true,
                .dhcp_use_dns = true,
                .dhcp_routes_to_dns = true,
                .dhcp_use_hostname = true,
                .dhcp_use_routes = true,
                .dhcp_use_gateway = -1,
                .dhcp_send_hostname = true,
                .dhcp_send_release = true,
                .dhcp_route_metric = DHCP_ROUTE_METRIC,
                .dhcp_use_rapid_commit = -1,
                .dhcp_client_identifier = _DHCP_CLIENT_ID_INVALID,
                .dhcp_route_table = RT_TABLE_MAIN,
                .dhcp_ip_service_type = -1,
                .dhcp_broadcast = -1,
                .dhcp_ipv6_only_mode = -1,

                .dhcp6_use_address = true,
                .dhcp6_use_pd_prefix = true,
                .dhcp6_use_dns = true,
                .dhcp6_use_hostname = true,
                .dhcp6_use_ntp = true,
                .dhcp6_use_captive_portal = true,
                .dhcp6_use_rapid_commit = true,
                .dhcp6_send_hostname = true,
                .dhcp6_duid.type = _DUID_TYPE_INVALID,
                .dhcp6_client_start_mode = _DHCP6_CLIENT_START_MODE_INVALID,
                .dhcp6_send_release = true,

                .dhcp_pd = -1,
                .dhcp_pd_announce = true,
                .dhcp_pd_assign = true,
                .dhcp_pd_manage_temporary_address = true,
                .dhcp_pd_subnet_id = -1,
                .dhcp_pd_route_metric = DHCP6PD_ROUTE_METRIC,

                .dhcp_server_bind_to_interface = true,
                .dhcp_server_emit[SD_DHCP_LEASE_DNS].emit = true,
                .dhcp_server_emit[SD_DHCP_LEASE_NTP].emit = true,
                .dhcp_server_emit[SD_DHCP_LEASE_SIP].emit = true,
                .dhcp_server_emit_router = true,
                .dhcp_server_emit_timezone = true,
                .dhcp_server_rapid_commit = true,

                .router_lifetime_usec = RADV_DEFAULT_ROUTER_LIFETIME_USEC,
                .router_dns_lifetime_usec = RADV_DEFAULT_VALID_LIFETIME_USEC,
                .router_emit_dns = true,
                .router_emit_domains = true,

                .use_bpdu = -1,
                .hairpin = -1,
                .isolated = -1,
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

                .bridge_vlan_pvid = BRIDGE_VLAN_KEEP_PVID,

                .lldp_mode = LLDP_MODE_ROUTERS_ONLY,
                .lldp_multicast_mode = _SD_LLDP_MULTICAST_MODE_INVALID,

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
                .ipv6_privacy_extensions = _IPV6_PRIVACY_EXTENSIONS_INVALID,
                .ipv6_dad_transmits = -1,
                .ipv6_proxy_ndp = -1,
                .proxy_arp = -1,
                .proxy_arp_pvlan = -1,
                .ipv4_rp_filter = _IP_REVERSE_PATH_FILTER_INVALID,

                .ipv6_accept_ra = -1,
                .ipv6_accept_ra_use_dns = true,
                .ipv6_accept_ra_use_gateway = true,
                .ipv6_accept_ra_use_captive_portal = true,
                .ipv6_accept_ra_use_route_prefix = true,
                .ipv6_accept_ra_use_autonomous_prefix = true,
                .ipv6_accept_ra_use_onlink_prefix = true,
                .ipv6_accept_ra_use_mtu = true,
                .ipv6_accept_ra_use_hop_limit = true,
                .ipv6_accept_ra_use_icmp6_ratelimit = true,
                .ipv6_accept_ra_route_table = RT_TABLE_MAIN,
                .ipv6_accept_ra_route_metric_high = IPV6RA_ROUTE_METRIC_HIGH,
                .ipv6_accept_ra_route_metric_medium = IPV6RA_ROUTE_METRIC_MEDIUM,
                .ipv6_accept_ra_route_metric_low = IPV6RA_ROUTE_METRIC_LOW,
                .ipv6_accept_ra_start_dhcp6_client = IPV6_ACCEPT_RA_START_DHCP6_CLIENT_YES,

                .can_termination = -1,

                .ipoib_mode = _IP_OVER_INFINIBAND_MODE_INVALID,
                .ipoib_umcast = -1,
        };

        r = config_parse_many(
                        STRV_MAKE_CONST(filename), NETWORK_DIRS, dropin_dirname, /* root = */ NULL,
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
                        "DHCPv6PrefixDelegation\0" /* compat */
                        "DHCPPrefixDelegation\0"
                        "DHCPServer\0"
                        "DHCPServerStaticLease\0"
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
                        "IPv6PREF64Prefix\0"
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
                        &network->stats_by_path,
                        &network->dropins);
        if (r < 0)
                return r; /* config_parse_many() logs internally. */

        r = network_add_ipv4ll_route(network);
        if (r < 0)
                return log_warning_errno(r, "%s: Failed to add IPv4LL route: %m", network->filename);

        r = network_add_default_route_on_device(network);
        if (r < 0)
                return log_warning_errno(r, "%s: Failed to add default route on device: %m",
                                         network->filename);

        r = network_verify(network);
        if (r < 0)
                return r; /* network_verify() logs internally. */

        r = ordered_hashmap_ensure_put(networks, &string_hash_ops, network->name, network);
        if (r < 0)
                return log_warning_errno(r, "%s: Failed to store configuration into hashmap: %m", filename);

        TAKE_PTR(network);
        return 0;
}

int network_load(Manager *manager, OrderedHashmap **networks) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(manager);

        ordered_hashmap_clear_with_destructor(*networks, network_unref);

        r = conf_files_list_strv(&files, ".network", NULL, 0, NETWORK_DIRS);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate network files: %m");

        STRV_FOREACH(f, files)
                (void) network_load_one(manager, networks, *f);

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
                if (r < 0) {
                        log_debug("Found new .network file: %s", n->filename);
                        continue;
                }

                if (!stats_by_path_equal(n->stats_by_path, old->stats_by_path)) {
                        log_debug("Found updated .network file: %s", n->filename);
                        continue;
                }

                r = ordered_hashmap_replace(new_networks, old->name, old);
                if (r < 0)
                        goto failure;

                network_ref(old);
                network_unref(n);
        }

        ordered_hashmap_free_with_destructor(manager->networks, network_unref);
        manager->networks = new_networks;

        r = manager_build_dhcp_pd_subnet_ids(manager);
        if (r < 0)
                return r;

        r = manager_build_nexthop_ids(manager);
        if (r < 0)
                return r;

        return 0;

failure:
        ordered_hashmap_free_with_destructor(new_networks, network_unref);

        return r;
}

int manager_build_dhcp_pd_subnet_ids(Manager *manager) {
        Network *n;
        int r;

        assert(manager);

        set_clear(manager->dhcp_pd_subnet_ids);

        ORDERED_HASHMAP_FOREACH(n, manager->networks) {
                if (n->unmanaged)
                        continue;

                if (!n->dhcp_pd)
                        continue;

                if (n->dhcp_pd_subnet_id < 0)
                        continue;

                r = set_ensure_put(&manager->dhcp_pd_subnet_ids, &uint64_hash_ops, &n->dhcp_pd_subnet_id);
                if (r < 0)
                        return r;
        }

        return 0;
}

static Network *network_free(Network *network) {
        if (!network)
                return NULL;

        free(network->name);
        free(network->filename);
        free(network->description);
        strv_free(network->dropins);
        hashmap_free(network->stats_by_path);

        /* conditions */
        net_match_clear(&network->match);
        condition_free_list(network->conditions);

        /* link settings */
        strv_free(network->bind_carrier);

        /* NTP */
        strv_free(network->ntp);

        /* DNS */
        for (unsigned i = 0; i < network->n_dns; i++)
                in_addr_full_free(network->dns[i]);
        free(network->dns);
        ordered_set_free(network->search_domains);
        ordered_set_free(network->route_domains);
        set_free_free(network->dnssec_negative_trust_anchors);

        /* DHCP server */
        free(network->dhcp_server_relay_agent_circuit_id);
        free(network->dhcp_server_relay_agent_remote_id);
        free(network->dhcp_server_boot_server_name);
        free(network->dhcp_server_boot_filename);
        free(network->dhcp_server_timezone);
        free(network->dhcp_server_uplink_name);
        for (sd_dhcp_lease_server_type_t t = 0; t < _SD_DHCP_LEASE_SERVER_TYPE_MAX; t++)
                free(network->dhcp_server_emit[t].addresses);
        ordered_hashmap_free(network->dhcp_server_send_options);
        ordered_hashmap_free(network->dhcp_server_send_vendor_options);

        /* DHCP client */
        free(network->dhcp_vendor_class_identifier);
        free(network->dhcp_mudurl);
        free(network->dhcp_hostname);
        free(network->dhcp_label);
        set_free(network->dhcp_deny_listed_ip);
        set_free(network->dhcp_allow_listed_ip);
        strv_free(network->dhcp_user_class);
        set_free(network->dhcp_request_options);
        ordered_hashmap_free(network->dhcp_client_send_options);
        ordered_hashmap_free(network->dhcp_client_send_vendor_options);
        free(network->dhcp_netlabel);
        nft_set_context_clear(&network->dhcp_nft_set_context);

        /* DHCPv6 client */
        free(network->dhcp6_mudurl);
        free(network->dhcp6_hostname);
        strv_free(network->dhcp6_user_class);
        strv_free(network->dhcp6_vendor_class);
        set_free(network->dhcp6_request_options);
        ordered_hashmap_free(network->dhcp6_client_send_options);
        ordered_hashmap_free(network->dhcp6_client_send_vendor_options);
        free(network->dhcp6_netlabel);
        nft_set_context_clear(&network->dhcp6_nft_set_context);

        /* DHCP PD */
        free(network->dhcp_pd_uplink_name);
        set_free(network->dhcp_pd_tokens);
        free(network->dhcp_pd_netlabel);
        nft_set_context_clear(&network->dhcp_pd_nft_set_context);

        /* Router advertisement */
        ordered_set_free(network->router_search_domains);
        free(network->router_dns);
        free(network->router_uplink_name);

        /* NDisc */
        set_free(network->ndisc_deny_listed_router);
        set_free(network->ndisc_allow_listed_router);
        set_free(network->ndisc_deny_listed_prefix);
        set_free(network->ndisc_allow_listed_prefix);
        set_free(network->ndisc_deny_listed_route_prefix);
        set_free(network->ndisc_allow_listed_route_prefix);
        set_free(network->ndisc_tokens);
        free(network->ndisc_netlabel);
        nft_set_context_clear(&network->ndisc_nft_set_context);

        /* LLDP */
        free(network->lldp_mudurl);

        /* netdev */
        free(network->batadv_name);
        free(network->bridge_name);
        free(network->bond_name);
        free(network->vrf_name);
        hashmap_free_free_key(network->stacked_netdev_names);
        netdev_unref(network->bridge);
        netdev_unref(network->bond);
        netdev_unref(network->vrf);
        hashmap_free_with_destructor(network->stacked_netdevs, netdev_unref);

        /* static configs */
        set_free_free(network->ipv6_proxy_ndp_addresses);
        ordered_hashmap_free(network->addresses_by_section);
        hashmap_free_with_destructor(network->routes_by_section, route_free);
        ordered_hashmap_free(network->nexthops_by_section);
        hashmap_free_with_destructor(network->bridge_fdb_entries_by_section, bridge_fdb_free);
        hashmap_free_with_destructor(network->bridge_mdb_entries_by_section, bridge_mdb_free);
        ordered_hashmap_free(network->neighbors_by_section);
        hashmap_free_with_destructor(network->address_labels_by_section, address_label_free);
        hashmap_free_with_destructor(network->prefixes_by_section, prefix_free);
        hashmap_free_with_destructor(network->route_prefixes_by_section, route_prefix_free);
        hashmap_free_with_destructor(network->pref64_prefixes_by_section, pref64_prefix_free);
        hashmap_free_with_destructor(network->rules_by_section, routing_policy_rule_free);
        hashmap_free_with_destructor(network->dhcp_static_leases_by_section, dhcp_static_lease_free);
        ordered_hashmap_free_with_destructor(network->sr_iov_by_section, sr_iov_free);
        hashmap_free_with_destructor(network->qdiscs_by_section, qdisc_free);
        hashmap_free_with_destructor(network->tclasses_by_section, tclass_free);

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

bool network_has_static_ipv6_configurations(Network *network) {
        Address *address;
        Route *route;
        BridgeFDB *fdb;
        BridgeMDB *mdb;
        Neighbor *neighbor;

        assert(network);

        ORDERED_HASHMAP_FOREACH(address, network->addresses_by_section)
                if (address->family == AF_INET6)
                        return true;

        HASHMAP_FOREACH(route, network->routes_by_section)
                if (route->family == AF_INET6)
                        return true;

        HASHMAP_FOREACH(fdb, network->bridge_fdb_entries_by_section)
                if (fdb->family == AF_INET6)
                        return true;

        HASHMAP_FOREACH(mdb, network->bridge_mdb_entries_by_section)
                if (mdb->family == AF_INET6)
                        return true;

        ORDERED_HASHMAP_FOREACH(neighbor, network->neighbors_by_section)
                if (neighbor->family == AF_INET6)
                        return true;

        if (!hashmap_isempty(network->address_labels_by_section))
                return true;

        if (!hashmap_isempty(network->prefixes_by_section))
                return true;

        if (!hashmap_isempty(network->route_prefixes_by_section))
                return true;

        if (!hashmap_isempty(network->pref64_prefixes_by_section))
                return true;

        return false;
}

int config_parse_stacked_netdev(
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

        _cleanup_free_ char *name = NULL;
        NetDevKind kind = ltype;
        Hashmap **h = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(IN_SET(kind,
                      NETDEV_KIND_IPOIB,
                      NETDEV_KIND_IPVLAN,
                      NETDEV_KIND_IPVTAP,
                      NETDEV_KIND_MACSEC,
                      NETDEV_KIND_MACVLAN,
                      NETDEV_KIND_MACVTAP,
                      NETDEV_KIND_VLAN,
                      NETDEV_KIND_VXLAN,
                      NETDEV_KIND_XFRM,
                      _NETDEV_KIND_TUNNEL));

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

        Network *n = ASSERT_PTR(userdata);
        int r;

        assert(filename);
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
                r = ordered_set_put_strdup(set, domain);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return log_oom();
        }
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

        char **tz = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *tz = mfree(*tz);
                return 0;
        }

        r = verify_timezone(rvalue, LOG_WARNING);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Timezone is not valid, ignoring assignment: %s", rvalue);
                return 0;
        }

        return free_and_strdup_warn(tz, rvalue);
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

        Network *n = ASSERT_PTR(userdata);
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

        Set **nta = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *nta = set_free_free(*nta);
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

                r = set_ensure_consume(nta, &dns_name_hash_ops, TAKE_PTR(w));
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

        char ***l = ASSERT_PTR(data);
        int r;

        assert(filename);
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

        Network *network = ASSERT_PTR(userdata);
        LinkOperationalStateRange range;
        bool required = true;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->required_for_online = -1;
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

int config_parse_link_group(
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
        int r;
        int32_t group;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->group = -1;
                return 0;
        }

        r = safe_atoi32(rvalue, &group);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse Group=, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (group < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Value of Group= must be in the range 0…2147483647, ignoring assignment: %s", rvalue);
                return 0;
        }

        network->group = group;
        return 0;
}

int config_parse_ignore_carrier_loss(
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
        usec_t usec;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->ignore_carrier_loss_set = false;
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r >= 0) {
                network->ignore_carrier_loss_set = true;
                network->ignore_carrier_loss_usec = r > 0 ? USEC_INFINITY : 0;
                return 0;
        }

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        network->ignore_carrier_loss_set = true;
        network->ignore_carrier_loss_usec = usec;
        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_required_family_for_online, link_required_address_family, AddressFamily,
                         "Failed to parse RequiredFamilyForOnline= setting");

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
