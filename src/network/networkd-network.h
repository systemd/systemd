/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/nl80211.h>

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-lldp-tx.h"

#include "bridge.h"
#include "condition.h"
#include "conf-parser.h"
#include "firewall-util.h"
#include "hashmap.h"
#include "ipoib.h"
#include "net-condition.h"
#include "netdev.h"
#include "networkd-address.h"
#include "networkd-bridge-vlan.h"
#include "networkd-dhcp-common.h"
#include "networkd-dhcp4.h"
#include "networkd-dhcp6.h"
#include "networkd-ipv6ll.h"
#include "networkd-lldp-rx.h"
#include "networkd-ndisc.h"
#include "networkd-radv.h"
#include "networkd-sysctl.h"
#include "networkd-util.h"
#include "ordered-set.h"
#include "resolve-util.h"
#include "socket-netlink.h"

typedef enum KeepConfiguration {
        KEEP_CONFIGURATION_NO            = 0,
        KEEP_CONFIGURATION_DHCP_ON_START = 1 << 0,
        KEEP_CONFIGURATION_DHCP_ON_STOP  = 1 << 1,
        KEEP_CONFIGURATION_DHCP          = KEEP_CONFIGURATION_DHCP_ON_START | KEEP_CONFIGURATION_DHCP_ON_STOP,
        KEEP_CONFIGURATION_STATIC        = 1 << 2,
        KEEP_CONFIGURATION_YES           = KEEP_CONFIGURATION_DHCP | KEEP_CONFIGURATION_STATIC,
        _KEEP_CONFIGURATION_MAX,
        _KEEP_CONFIGURATION_INVALID = -EINVAL,
} KeepConfiguration;

typedef enum ActivationPolicy {
        ACTIVATION_POLICY_UP,
        ACTIVATION_POLICY_ALWAYS_UP,
        ACTIVATION_POLICY_MANUAL,
        ACTIVATION_POLICY_ALWAYS_DOWN,
        ACTIVATION_POLICY_DOWN,
        ACTIVATION_POLICY_BOUND,
        _ACTIVATION_POLICY_MAX,
        _ACTIVATION_POLICY_INVALID = -EINVAL,
} ActivationPolicy;

typedef struct Manager Manager;

typedef struct NetworkDHCPServerEmitAddress {
        bool emit;
        struct in_addr *addresses;
        size_t n_addresses;
} NetworkDHCPServerEmitAddress;

struct Network {
        Manager *manager;

        unsigned n_ref;

        char *name;
        char *filename;
        char **dropins;
        Hashmap *stats_by_path;
        char *description;

        /* [Match] section */
        NetMatch match;
        LIST_HEAD(Condition, conditions);

        /* Master or stacked netdevs */
        bool keep_master;
        NetDev *batadv;
        NetDev *bridge;
        NetDev *bond;
        NetDev *vrf;
        NetDev *xfrm;
        Hashmap *stacked_netdevs;
        char *batadv_name;
        char *bridge_name;
        char *bond_name;
        char *vrf_name;
        Hashmap *stacked_netdev_names;

        /* [Link] section */
        struct hw_addr_data hw_addr;
        uint32_t mtu;
        int32_t group;
        int arp;
        int multicast;
        int allmulticast;
        int promiscuous;
        bool unmanaged;
        int required_for_online; /* Is this network required to be considered online? */
        LinkOperationalStateRange required_operstate_for_online;
        AddressFamily required_family_for_online;
        ActivationPolicy activation_policy;

        /* misc settings */
        bool configure_without_carrier;
        bool ignore_carrier_loss_set;
        usec_t ignore_carrier_loss_usec; /* timespan */
        KeepConfiguration keep_configuration;
        char **bind_carrier;
        bool default_route_on_device;
        AddressFamily ip_masquerade;

        /* DHCP Client Support */
        AddressFamily dhcp;
        struct in_addr dhcp_request_address;
        DHCPClientIdentifier dhcp_client_identifier;
        DUID dhcp_duid;
        uint32_t dhcp_iaid;
        bool dhcp_iaid_set;
        char *dhcp_vendor_class_identifier;
        char *dhcp_mudurl;
        char **dhcp_user_class;
        char *dhcp_hostname;
        char *dhcp_label;
        uint64_t dhcp_max_attempts;
        uint32_t dhcp_route_metric;
        bool dhcp_route_metric_set;
        uint32_t dhcp_route_table;
        bool dhcp_route_table_set;
        usec_t dhcp_fallback_lease_lifetime_usec;
        uint32_t dhcp_route_mtu;
        uint16_t dhcp_client_port;
        int dhcp_critical;
        int dhcp_ip_service_type;
        int dhcp_socket_priority;
        bool dhcp_socket_priority_set;
        bool dhcp_anonymize;
        bool dhcp_send_hostname;
        bool dhcp_send_hostname_set;
        int dhcp_broadcast;
        int dhcp_ipv6_only_mode;
        int dhcp_use_rapid_commit;
        bool dhcp_use_dns;
        bool dhcp_use_dns_set;
        bool dhcp_routes_to_dns;
        bool dhcp_use_ntp;
        bool dhcp_use_ntp_set;
        bool dhcp_routes_to_ntp;
        bool dhcp_use_sip;
        bool dhcp_use_captive_portal;
        bool dhcp_use_mtu;
        bool dhcp_use_routes;
        int dhcp_use_gateway;
        bool dhcp_quickack;
        uint32_t dhcp_initial_congestion_window;
        uint32_t dhcp_advertised_receive_window;
        bool dhcp_use_timezone;
        bool dhcp_use_hostname;
        bool dhcp_use_6rd;
        bool dhcp_send_release;
        bool dhcp_send_decline;
        DHCPUseDomains dhcp_use_domains;
        bool dhcp_use_domains_set;
        Set *dhcp_deny_listed_ip;
        Set *dhcp_allow_listed_ip;
        Set *dhcp_request_options;
        OrderedHashmap *dhcp_client_send_options;
        OrderedHashmap *dhcp_client_send_vendor_options;
        char *dhcp_netlabel;
        NFTSetContext dhcp_nft_set_context;

        /* DHCPv6 Client support */
        bool dhcp6_use_address;
        bool dhcp6_use_pd_prefix;
        bool dhcp6_send_hostname;
        bool dhcp6_send_hostname_set;
        bool dhcp6_use_dns;
        bool dhcp6_use_dns_set;
        bool dhcp6_use_hostname;
        bool dhcp6_use_ntp;
        bool dhcp6_use_ntp_set;
        bool dhcp6_use_captive_portal;
        bool dhcp6_use_rapid_commit;
        DHCPUseDomains dhcp6_use_domains;
        bool dhcp6_use_domains_set;
        uint32_t dhcp6_iaid;
        bool dhcp6_iaid_set;
        bool dhcp6_iaid_set_explicitly;
        DUID dhcp6_duid;
        uint8_t dhcp6_pd_prefix_length;
        struct in6_addr dhcp6_pd_prefix_hint;
        char *dhcp6_hostname;
        char *dhcp6_mudurl;
        char **dhcp6_user_class;
        char **dhcp6_vendor_class;
        DHCP6ClientStartMode dhcp6_client_start_mode;
        OrderedHashmap *dhcp6_client_send_options;
        OrderedHashmap *dhcp6_client_send_vendor_options;
        Set *dhcp6_request_options;
        char *dhcp6_netlabel;
        bool dhcp6_send_release;
        NFTSetContext dhcp6_nft_set_context;

        /* DHCP Server Support */
        bool dhcp_server;
        bool dhcp_server_bind_to_interface;
        unsigned char dhcp_server_address_prefixlen;
        struct in_addr dhcp_server_address_in_addr;
        const Address *dhcp_server_address;
        int dhcp_server_uplink_index;
        char *dhcp_server_uplink_name;
        struct in_addr dhcp_server_relay_target;
        char *dhcp_server_relay_agent_circuit_id;
        char *dhcp_server_relay_agent_remote_id;
        NetworkDHCPServerEmitAddress dhcp_server_emit[_SD_DHCP_LEASE_SERVER_TYPE_MAX];
        bool dhcp_server_emit_router;
        struct in_addr dhcp_server_router;
        bool dhcp_server_emit_timezone;
        char *dhcp_server_timezone;
        usec_t dhcp_server_default_lease_time_usec, dhcp_server_max_lease_time_usec;
        uint32_t dhcp_server_pool_offset;
        uint32_t dhcp_server_pool_size;
        OrderedHashmap *dhcp_server_send_options;
        OrderedHashmap *dhcp_server_send_vendor_options;
        struct in_addr dhcp_server_boot_server_address;
        char *dhcp_server_boot_server_name;
        char *dhcp_server_boot_filename;
        usec_t dhcp_server_ipv6_only_preferred_usec;
        bool dhcp_server_rapid_commit;

        /* link-local addressing support */
        AddressFamily link_local;
        IPv6LinkLocalAddressGenMode ipv6ll_address_gen_mode;
        struct in6_addr ipv6ll_stable_secret;
        struct in_addr ipv4ll_start_address;
        bool ipv4ll_route;

        /* IPv6 RA support */
        RADVPrefixDelegation router_prefix_delegation;
        usec_t router_lifetime_usec;
        uint8_t router_preference;
        usec_t router_retransmit_usec;
        uint8_t router_hop_limit;
        bool router_managed;
        bool router_other_information;
        bool router_emit_dns;
        bool router_emit_domains;
        usec_t router_dns_lifetime_usec;
        struct in6_addr *router_dns;
        unsigned n_router_dns;
        OrderedSet *router_search_domains;
        int router_uplink_index;
        char *router_uplink_name;
        /* Mobile IPv6 Home Agent */
        bool router_home_agent_information;
        uint16_t router_home_agent_preference;
        usec_t home_agent_lifetime_usec;

        /* DHCP Prefix Delegation support */
        int dhcp_pd;
        bool dhcp_pd_announce;
        bool dhcp_pd_assign;
        bool dhcp_pd_manage_temporary_address;
        int64_t dhcp_pd_subnet_id;
        uint32_t dhcp_pd_route_metric;
        Set *dhcp_pd_tokens;
        int dhcp_pd_uplink_index;
        char *dhcp_pd_uplink_name;
        char *dhcp_pd_netlabel;
        NFTSetContext dhcp_pd_nft_set_context;

        /* Bridge Support */
        int use_bpdu;
        int hairpin;
        int isolated;
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

        /* Bridge VLAN */
        uint16_t bridge_vlan_pvid;
        uint32_t bridge_vlan_bitmap[BRIDGE_VLAN_BITMAP_LEN];
        uint32_t bridge_vlan_untagged_bitmap[BRIDGE_VLAN_BITMAP_LEN];

        /* CAN support */
        uint32_t can_bitrate;
        unsigned can_sample_point;
        nsec_t can_time_quanta_ns;
        uint32_t can_propagation_segment;
        uint32_t can_phase_buffer_segment_1;
        uint32_t can_phase_buffer_segment_2;
        uint32_t can_sync_jump_width;
        uint32_t can_data_bitrate;
        unsigned can_data_sample_point;
        nsec_t can_data_time_quanta_ns;
        uint32_t can_data_propagation_segment;
        uint32_t can_data_phase_buffer_segment_1;
        uint32_t can_data_phase_buffer_segment_2;
        uint32_t can_data_sync_jump_width;
        usec_t can_restart_us;
        uint32_t can_control_mode_mask;
        uint32_t can_control_mode_flags;
        uint16_t can_termination;
        bool can_termination_set;

        /* IPoIB support */
        IPoIBMode ipoib_mode;
        int ipoib_umcast;

        /* sysctl settings */
        AddressFamily ip_forward;
        int ipv4_accept_local;
        int ipv4_route_localnet;
        int ipv6_dad_transmits;
        uint8_t ipv6_hop_limit;
        int proxy_arp;
        int proxy_arp_pvlan;
        uint32_t ipv6_mtu;
        IPv6PrivacyExtensions ipv6_privacy_extensions;
        IPReversePathFilter ipv4_rp_filter;
        int ipv6_proxy_ndp;
        Set *ipv6_proxy_ndp_addresses;

        /* IPv6 accept RA */
        int ipv6_accept_ra;
        bool ipv6_accept_ra_use_dns;
        bool ipv6_accept_ra_use_gateway;
        bool ipv6_accept_ra_use_route_prefix;
        bool ipv6_accept_ra_use_autonomous_prefix;
        bool ipv6_accept_ra_use_onlink_prefix;
        bool ipv6_accept_ra_use_mtu;
        bool ipv6_accept_ra_use_hop_limit;
        bool ipv6_accept_ra_use_icmp6_ratelimit;
        bool ipv6_accept_ra_quickack;
        bool ipv6_accept_ra_use_captive_portal;
        bool ipv6_accept_ra_use_pref64;
        bool active_slave;
        bool primary_slave;
        DHCPUseDomains ipv6_accept_ra_use_domains;
        IPv6AcceptRAStartDHCP6Client ipv6_accept_ra_start_dhcp6_client;
        uint32_t ipv6_accept_ra_route_table;
        bool ipv6_accept_ra_route_table_set;
        uint32_t ipv6_accept_ra_route_metric_high;
        uint32_t ipv6_accept_ra_route_metric_medium;
        uint32_t ipv6_accept_ra_route_metric_low;
        bool ipv6_accept_ra_route_metric_set;
        Set *ndisc_deny_listed_router;
        Set *ndisc_allow_listed_router;
        Set *ndisc_deny_listed_prefix;
        Set *ndisc_allow_listed_prefix;
        Set *ndisc_deny_listed_route_prefix;
        Set *ndisc_allow_listed_route_prefix;
        Set *ndisc_tokens;
        char *ndisc_netlabel;
        NFTSetContext ndisc_nft_set_context;

        /* LLDP support */
        LLDPMode lldp_mode; /* LLDP reception */
        sd_lldp_multicast_mode_t lldp_multicast_mode; /* LLDP transmission */
        char *lldp_mudurl;  /* LLDP MUD URL */

        OrderedHashmap *addresses_by_section;
        Hashmap *routes_by_section;
        OrderedHashmap *nexthops_by_section;
        Hashmap *bridge_fdb_entries_by_section;
        Hashmap *bridge_mdb_entries_by_section;
        OrderedHashmap *neighbors_by_section;
        Hashmap *address_labels_by_section;
        Hashmap *prefixes_by_section;
        Hashmap *route_prefixes_by_section;
        Hashmap *pref64_prefixes_by_section;
        Hashmap *rules_by_section;
        Hashmap *dhcp_static_leases_by_section;
        Hashmap *qdiscs_by_section;
        Hashmap *tclasses_by_section;
        OrderedHashmap *sr_iov_by_section;

        /* All kinds of DNS configuration */
        struct in_addr_full **dns;
        unsigned n_dns;
        OrderedSet *search_domains, *route_domains;
        int dns_default_route;
        ResolveSupport llmnr;
        ResolveSupport mdns;
        DnssecMode dnssec_mode;
        DnsOverTlsMode dns_over_tls_mode;
        Set *dnssec_negative_trust_anchors;

        /* NTP */
        char **ntp;
};

Network *network_ref(Network *network);
Network *network_unref(Network *network);
DEFINE_TRIVIAL_CLEANUP_FUNC(Network*, network_unref);

int network_load(Manager *manager, OrderedHashmap **networks);
int network_reload(Manager *manager);
int network_load_one(Manager *manager, OrderedHashmap **networks, const char *filename);
int network_verify(Network *network);

int manager_build_dhcp_pd_subnet_ids(Manager *manager);

int network_get_by_name(Manager *manager, const char *name, Network **ret);
void network_apply_anonymize_if_set(Network *network);

bool network_has_static_ipv6_configurations(Network *network);

CONFIG_PARSER_PROTOTYPE(config_parse_stacked_netdev);
CONFIG_PARSER_PROTOTYPE(config_parse_tunnel);
CONFIG_PARSER_PROTOTYPE(config_parse_domains);
CONFIG_PARSER_PROTOTYPE(config_parse_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_timezone);
CONFIG_PARSER_PROTOTYPE(config_parse_dnssec_negative_trust_anchors);
CONFIG_PARSER_PROTOTYPE(config_parse_ntp);
CONFIG_PARSER_PROTOTYPE(config_parse_required_for_online);
CONFIG_PARSER_PROTOTYPE(config_parse_required_family_for_online);
CONFIG_PARSER_PROTOTYPE(config_parse_keep_configuration);
CONFIG_PARSER_PROTOTYPE(config_parse_activation_policy);
CONFIG_PARSER_PROTOTYPE(config_parse_link_group);
CONFIG_PARSER_PROTOTYPE(config_parse_ignore_carrier_loss);

const struct ConfigPerfItem* network_network_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

const char* keep_configuration_to_string(KeepConfiguration i) _const_;
KeepConfiguration keep_configuration_from_string(const char *s) _pure_;

const char* activation_policy_to_string(ActivationPolicy i) _const_;
ActivationPolicy activation_policy_from_string(const char *s) _pure_;
