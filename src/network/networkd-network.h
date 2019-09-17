/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"
#include "sd-device.h"

#include "condition.h"
#include "conf-parser.h"
#include "hashmap.h"
#include "netdev/bridge.h"
#include "netdev/netdev.h"
#include "networkd-address-label.h"
#include "networkd-address.h"
#include "networkd-brvlan.h"
#include "networkd-dhcp-common.h"
#include "networkd-dhcp4.h"
#include "networkd-fdb.h"
#include "networkd-ipv6-proxy-ndp.h"
#include "networkd-lldp-rx.h"
#include "networkd-lldp-tx.h"
#include "networkd-neighbor.h"
#include "networkd-radv.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-util.h"
#include "ordered-set.h"
#include "resolve-util.h"

typedef enum IPv6PrivacyExtensions {
        /* The values map to the kernel's /proc/sys/net/ipv6/conf/xxx/use_tempaddr values */
        IPV6_PRIVACY_EXTENSIONS_NO,
        IPV6_PRIVACY_EXTENSIONS_PREFER_PUBLIC,
        IPV6_PRIVACY_EXTENSIONS_YES, /* aka prefer-temporary */
        _IPV6_PRIVACY_EXTENSIONS_MAX,
        _IPV6_PRIVACY_EXTENSIONS_INVALID = -1,
} IPv6PrivacyExtensions;

typedef enum KeepConfiguration {
        KEEP_CONFIGURATION_NO            = 0,
        KEEP_CONFIGURATION_DHCP_ON_START = 1 << 0,
        KEEP_CONFIGURATION_DHCP_ON_STOP  = 1 << 1,
        KEEP_CONFIGURATION_DHCP          = KEEP_CONFIGURATION_DHCP_ON_START | KEEP_CONFIGURATION_DHCP_ON_STOP,
        KEEP_CONFIGURATION_STATIC        = 1 << 2,
        KEEP_CONFIGURATION_YES           = KEEP_CONFIGURATION_DHCP | KEEP_CONFIGURATION_STATIC,
        _KEEP_CONFIGURATION_MAX,
        _KEEP_CONFIGURATION_INVALID = -1,
} KeepConfiguration;

typedef struct Manager Manager;

struct Network {
        Manager *manager;

        char *filename;
        char *name;

        unsigned n_ref;

        Set *match_mac;
        char **match_path;
        char **match_driver;
        char **match_type;
        char **match_name;
        char **match_property;
        LIST_HEAD(Condition, conditions);

        char *description;

        NetDev *bridge;
        NetDev *bond;
        NetDev *vrf;
        NetDev *xfrm;
        Hashmap *stacked_netdevs;
        char *bridge_name;
        char *bond_name;
        char *vrf_name;
        Hashmap *stacked_netdev_names;

        /* DHCP Client Support */
        AddressFamily dhcp;
        DHCPClientIdentifier dhcp_client_identifier;
        char *dhcp_vendor_class_identifier;
        char **dhcp_user_class;
        char *dhcp_hostname;
        uint64_t dhcp_max_attempts;
        unsigned dhcp_route_metric;
        uint32_t dhcp_route_table;
        uint16_t dhcp_client_port;
        bool dhcp_anonymize;
        bool dhcp_send_hostname;
        bool dhcp_broadcast;
        int dhcp_critical;
        bool dhcp_use_dns;
        bool dhcp_routes_to_dns;
        bool dhcp_use_ntp;
        bool dhcp_use_mtu;
        bool dhcp_use_routes;
        bool dhcp_use_timezone;
        bool rapid_commit;
        bool dhcp_use_hostname;
        bool dhcp_route_table_set;
        bool dhcp_send_release;
        DHCPUseDomains dhcp_use_domains;
        Set *dhcp_black_listed_ip;

        /* DHCPv6 Client support*/
        bool dhcp6_use_dns;
        bool dhcp6_use_ntp;

        /* DHCP Server Support */
        bool dhcp_server;
        bool dhcp_server_emit_dns;
        struct in_addr *dhcp_server_dns;
        unsigned n_dhcp_server_dns;
        bool dhcp_server_emit_ntp;
        struct in_addr *dhcp_server_ntp;
        unsigned n_dhcp_server_ntp;
        bool dhcp_server_emit_router;
        bool dhcp_server_emit_timezone;
        char *dhcp_server_timezone;
        usec_t dhcp_server_default_lease_time_usec, dhcp_server_max_lease_time_usec;
        uint32_t dhcp_server_pool_offset;
        uint32_t dhcp_server_pool_size;

        /* IPV4LL Support */
        AddressFamily link_local;
        bool ipv4ll_route;

        bool default_route_on_device;

        /* IPv6 prefix delegation support */
        RADVPrefixDelegation router_prefix_delegation;
        usec_t router_lifetime_usec;
        uint8_t router_preference;
        bool router_managed;
        bool router_other_information;
        bool router_emit_dns;
        bool router_emit_domains;
        usec_t router_dns_lifetime_usec;
        struct in6_addr *router_dns;
        unsigned n_router_dns;
        OrderedSet *router_search_domains;
        bool dhcp6_force_pd_other_information; /* Start DHCPv6 PD also when 'O'
                                                  RA flag is set, see RFC 7084,
                                                  WPD-4 */

        /* Bridge Support */
        int use_bpdu;
        int hairpin;
        int fast_leave;
        int allow_port_to_be_root;
        int unicast_flood;
        int multicast_flood;
        int multicast_to_unicast;
        int neighbor_suppression;
        int learning;
        int bridge_proxy_arp;
        int bridge_proxy_arp_wifi;
        uint32_t cost;
        uint16_t priority;
        MulticastRouter multicast_router;

        bool use_br_vlan;
        uint16_t pvid;
        uint32_t br_vid_bitmap[BRIDGE_VLAN_BITMAP_LEN];
        uint32_t br_untagged_bitmap[BRIDGE_VLAN_BITMAP_LEN];

        /* CAN support */
        size_t can_bitrate;
        unsigned can_sample_point;
        usec_t can_restart_us;
        int can_triple_sampling;

        AddressFamily ip_forward;
        bool ip_masquerade;

        int ipv6_accept_ra;
        int ipv6_dad_transmits;
        int ipv6_hop_limit;
        int ipv6_proxy_ndp;
        int proxy_arp;
        uint32_t ipv6_mtu;

        bool ipv6_accept_ra_use_dns;
        bool ipv6_accept_ra_use_autonomous_prefix;
        bool ipv6_accept_ra_use_onlink_prefix;
        bool active_slave;
        bool primary_slave;
        DHCPUseDomains ipv6_accept_ra_use_domains;
        uint32_t ipv6_accept_ra_route_table;
        bool ipv6_accept_ra_route_table_set;
        Set *ndisc_black_listed_prefix;

        union in_addr_union ipv6_token;
        IPv6PrivacyExtensions ipv6_privacy_extensions;

        struct ether_addr *mac;
        uint32_t mtu;
        int arp;
        int multicast;
        int allmulticast;
        bool unmanaged;
        bool configure_without_carrier;
        bool ignore_carrier_loss;
        KeepConfiguration keep_configuration;
        uint32_t iaid;
        DUID duid;

        bool iaid_set;

        bool required_for_online; /* Is this network required to be considered online? */
        LinkOperationalState required_operstate_for_online;

        LLDPMode lldp_mode; /* LLDP reception */
        LLDPEmit lldp_emit; /* LLDP transmission */

        LIST_HEAD(Address, static_addresses);
        LIST_HEAD(Route, static_routes);
        LIST_HEAD(FdbEntry, static_fdb_entries);
        LIST_HEAD(IPv6ProxyNDPAddress, ipv6_proxy_ndp_addresses);
        LIST_HEAD(Neighbor, neighbors);
        LIST_HEAD(AddressLabel, address_labels);
        LIST_HEAD(Prefix, static_prefixes);
        LIST_HEAD(Prefix, static_route_prefixes);
        LIST_HEAD(RoutingPolicyRule, rules);

        unsigned n_static_addresses;
        unsigned n_static_routes;
        unsigned n_static_fdb_entries;
        unsigned n_ipv6_proxy_ndp_addresses;
        unsigned n_neighbors;
        unsigned n_address_labels;
        unsigned n_static_prefixes;
        unsigned n_static_route_prefixes;
        unsigned n_rules;

        Hashmap *addresses_by_section;
        Hashmap *routes_by_section;
        Hashmap *fdb_entries_by_section;
        Hashmap *neighbors_by_section;
        Hashmap *address_labels_by_section;
        Hashmap *prefixes_by_section;
        Hashmap *route_prefixes_by_section;
        Hashmap *rules_by_section;

        /* All kinds of DNS configuration */
        struct in_addr_data *dns;
        unsigned n_dns;
        OrderedSet *search_domains, *route_domains;

        int dns_default_route;
        ResolveSupport llmnr;
        ResolveSupport mdns;
        DnssecMode dnssec_mode;
        DnsOverTlsMode dns_over_tls_mode;
        Set *dnssec_negative_trust_anchors;

        char **ntp;
        char **bind_carrier;
};

Network *network_ref(Network *network);
Network *network_unref(Network *network);
DEFINE_TRIVIAL_CLEANUP_FUNC(Network*, network_unref);

int network_load(Manager *manager);
int network_load_one(Manager *manager, const char *filename);
int network_verify(Network *network);

int network_get_by_name(Manager *manager, const char *name, Network **ret);
int network_get(Manager *manager, sd_device *device, const char *ifname, const struct ether_addr *mac, Network **ret);
int network_apply(Network *network, Link *link);
void network_apply_anonymize_if_set(Network *network);

bool network_has_static_ipv6_configurations(Network *network);

CONFIG_PARSER_PROTOTYPE(config_parse_stacked_netdev);
CONFIG_PARSER_PROTOTYPE(config_parse_tunnel);
CONFIG_PARSER_PROTOTYPE(config_parse_ipv6token);
CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_privacy_extensions);
CONFIG_PARSER_PROTOTYPE(config_parse_domains);
CONFIG_PARSER_PROTOTYPE(config_parse_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_hostname);
CONFIG_PARSER_PROTOTYPE(config_parse_timezone);
CONFIG_PARSER_PROTOTYPE(config_parse_dnssec_negative_trust_anchors);
CONFIG_PARSER_PROTOTYPE(config_parse_ntp);
CONFIG_PARSER_PROTOTYPE(config_parse_required_for_online);
CONFIG_PARSER_PROTOTYPE(config_parse_keep_configuration);

const struct ConfigPerfItem* network_network_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

const char* ipv6_privacy_extensions_to_string(IPv6PrivacyExtensions i) _const_;
IPv6PrivacyExtensions ipv6_privacy_extensions_from_string(const char *s) _pure_;

const char* keep_configuration_to_string(KeepConfiguration i) _const_;
KeepConfiguration keep_configuration_from_string(const char *s) _pure_;
