/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-lease.h"
#include "sd-lldp-tx.h"

#include "bridge.h"
#include "firewall-util.h"
#include "ipoib.h"
#include "net-condition.h"
#include "network-util.h"
#include "networkd-bridge-vlan.h"
#include "networkd-dhcp-common.h"
#include "networkd-dhcp-server.h"
#include "networkd-dhcp4.h"
#include "networkd-dhcp6.h"
#include "networkd-dns.h"
#include "networkd-forward.h"
#include "networkd-ipv6ll.h"
#include "networkd-lldp-rx.h"
#include "networkd-ndisc.h"
#include "networkd-radv.h"
#include "networkd-sysctl.h"
#include "resolve-util.h"

typedef enum KeepConfiguration {
        KEEP_CONFIGURATION_NO               = 0,
        KEEP_CONFIGURATION_DYNAMIC_ON_START = 1 << 0,
        KEEP_CONFIGURATION_DYNAMIC_ON_STOP  = 1 << 1,
        KEEP_CONFIGURATION_DYNAMIC          = KEEP_CONFIGURATION_DYNAMIC_ON_START | KEEP_CONFIGURATION_DYNAMIC_ON_STOP,
        KEEP_CONFIGURATION_STATIC           = 1 << 2,
        KEEP_CONFIGURATION_YES              = KEEP_CONFIGURATION_DYNAMIC | KEEP_CONFIGURATION_STATIC,
        _KEEP_CONFIGURATION_MAX,
        _KEEP_CONFIGURATION_INVALID         = -EINVAL,
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

typedef struct NetworkDHCPServerEmitAddress {
        bool emit;
        struct in_addr *addresses;
        size_t n_addresses;
} NetworkDHCPServerEmitAddress;

typedef struct Network {
        /* Pointers and other 8-byte aligned types */
        Manager *manager;

        char *name;
        char *filename;
        char **dropins;
        Hashmap *stats_by_path;
        char *description;
        char **bind_carrier;
        char **ntp;
        /* Master or stacked netdevs */
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
        struct in_addr_full **dns;
        OrderedSet *search_domains, *route_domains;
        Set *dnssec_negative_trust_anchors;
        char *dhcp_vendor_class_identifier;
        char *dhcp_mudurl;
        char **dhcp_user_class;
        char *dhcp_hostname;
        char *dhcp_label;
        Set *dhcp_deny_listed_ip;
        Set *dhcp_allow_listed_ip;
        Set *dhcp_request_options;
        OrderedHashmap *dhcp_client_send_options;
        OrderedHashmap *dhcp_client_send_vendor_options;
        char *dhcp_netlabel;
        char *dhcp6_hostname;
        char *dhcp6_mudurl;
        char **dhcp6_user_class;
        char **dhcp6_vendor_class;
        OrderedHashmap *dhcp6_client_send_options;
        OrderedHashmap *dhcp6_client_send_vendor_options;
        Set *dhcp6_request_options;
        char *dhcp6_netlabel;
        const Address *dhcp_server_address;
        char *dhcp_server_uplink_name;
        char *dhcp_server_relay_agent_circuit_id;
        char *dhcp_server_relay_agent_remote_id;
        char *dhcp_server_timezone;
        char *dhcp_server_domain;
        OrderedHashmap *dhcp_server_send_options;
        OrderedHashmap *dhcp_server_send_vendor_options;
        char *dhcp_server_boot_server_name;
        char *dhcp_server_boot_filename;
        struct in6_addr *router_dns;
        OrderedSet *router_search_domains;
        char *router_uplink_name;
        Set *dhcp_pd_tokens;
        char *dhcp_pd_uplink_name;
        char *dhcp_pd_netlabel;
        Set *ipv6_proxy_ndp_addresses;
        Set *ndisc_deny_listed_router;
        Set *ndisc_allow_listed_router;
        Set *ndisc_deny_listed_prefix;
        Set *ndisc_allow_listed_prefix;
        Set *ndisc_deny_listed_route_prefix;
        Set *ndisc_allow_listed_route_prefix;
        Set *ndisc_tokens;
        char *ndisc_netlabel;
        char *lldp_mudurl;  /* LLDP MUD URL */

        /* Large structs and arrays */
        NetMatch match;
        LIST_HEAD(Condition, conditions);
        struct hw_addr_data hw_addr;
        DUID dhcp_duid;
        NFTSetContext dhcp_nft_set_context;
        DUID dhcp6_duid;
        struct in6_addr dhcp6_pd_prefix_hint;
        NFTSetContext dhcp6_nft_set_context;
        NetworkDHCPServerEmitAddress dhcp_server_emit[_SD_DHCP_LEASE_SERVER_TYPE_MAX];
        struct in6_addr ipv6ll_stable_secret;
        NFTSetContext dhcp_pd_nft_set_context;
        uint32_t bridge_vlan_bitmap[BRIDGE_VLAN_BITMAP_LEN];
        uint32_t bridge_vlan_untagged_bitmap[BRIDGE_VLAN_BITMAP_LEN];
        int ip_forwarding[2];
        NFTSetContext ndisc_nft_set_context;

        /* 64-bit integers */
        usec_t ignore_carrier_loss_usec; /* timespan */
        usec_t ipv4_dad_timeout_usec;
        uint64_t dhcp_max_attempts;
        usec_t dhcp_fallback_lease_lifetime_usec;
        usec_t dhcp_server_default_lease_time_usec, dhcp_server_max_lease_time_usec;
        usec_t dhcp_server_ipv6_only_preferred_usec;
        nsec_t can_time_quanta_ns;
        nsec_t can_data_time_quanta_ns;
        usec_t can_restart_us;
        usec_t ipv6_retransmission_time;
        usec_t router_lifetime_usec;
        usec_t router_reachable_usec;
        usec_t router_retransmit_usec;
        usec_t router_dns_lifetime_usec;
        usec_t home_agent_lifetime_usec;
        int64_t dhcp_pd_subnet_id;

        /* 4-byte integers and enums */
        unsigned n_ref;
        uint32_t mtu;
        int32_t group;
        int arp;
        int multicast;
        int allmulticast;
        int promiscuous;
        int required_for_online; /* Is this network required to be considered online? */
        LinkOperationalStateRange required_operstate_for_online;
        AddressFamily required_family_for_online;
        ActivationPolicy activation_policy;
        KeepConfiguration keep_configuration;
        AddressFamily ip_masquerade;
        UseDomains use_domains;
        UseDomains compat_dhcp_use_domains;
        int compat_dhcp_use_dns;
        int compat_dhcp_use_ntp;
        AddressFamily dhcp;
        struct in_addr dhcp_request_address;
        DHCPClientIdentifier dhcp_client_identifier;
        uint32_t dhcp_iaid;
        uint32_t dhcp_route_metric;
        uint32_t dhcp_route_table;
        uint32_t dhcp_route_mtu;
        int dhcp_critical;
        int dhcp_ip_service_type;
        int dhcp_socket_priority;
        int dhcp_broadcast;
        int dhcp_ipv6_only_mode;
        int dhcp_use_rapid_commit;
        int dhcp_use_dns;
        int dhcp_use_dnr;
        int dhcp_use_ntp;
        int dhcp_use_gateway;
        uint32_t dhcp_initial_congestion_window;
        uint32_t dhcp_advertised_receive_window;
        UseDomains dhcp_use_domains;
        int dhcp6_use_dns;
        int dhcp6_use_dnr;
        int dhcp6_use_ntp;
        UseDomains dhcp6_use_domains;
        uint32_t dhcp6_iaid;
        DHCP6ClientStartMode dhcp6_client_start_mode;
        struct in_addr dhcp_server_address_in_addr;
        int dhcp_server_uplink_index;
        struct in_addr dhcp_server_relay_target;
        struct in_addr dhcp_server_router;
        uint32_t dhcp_server_pool_offset;
        uint32_t dhcp_server_pool_size;
        struct in_addr dhcp_server_boot_server_address;
        DHCPServerPersistLeases dhcp_server_persist_leases;
        char *dhcp_server_local_lease_domain;

        /* link-local addressing support */
        AddressFamily link_local;
        IPv6LinkLocalAddressGenMode ipv6ll_address_gen_mode;
        struct in_addr ipv4ll_start_address;
        RADVPrefixDelegation router_prefix_delegation;
        unsigned n_router_dns;
        int router_uplink_index;
        int dhcp_pd;
        uint32_t dhcp_pd_route_metric;
        int dhcp_pd_uplink_index;
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
        MulticastRouter multicast_router;
        int bridge_locked;
        int bridge_mac_authentication_bypass;
        int bridge_vlan_tunnel;
        uint32_t can_bitrate;
        unsigned can_sample_point;
        uint32_t can_propagation_segment;
        uint32_t can_phase_buffer_segment_1;
        uint32_t can_phase_buffer_segment_2;
        uint32_t can_sync_jump_width;
        uint32_t can_data_bitrate;
        unsigned can_data_sample_point;
        uint32_t can_data_propagation_segment;
        uint32_t can_data_phase_buffer_segment_1;
        uint32_t can_data_phase_buffer_segment_2;
        uint32_t can_data_sync_jump_width;
        uint32_t can_control_mode_mask;
        uint32_t can_control_mode_flags;
        IPoIBMode ipoib_mode;
        int ipoib_umcast;
        int ipv4_accept_local;
        int ipv4_route_localnet;
        int ipv6_dad_transmits;
        int proxy_arp;
        int proxy_arp_pvlan;
        uint32_t ipv6_mtu;
        IPv6PrivacyExtensions ipv6_privacy_extensions;
        IPReversePathFilter ipv4_rp_filter;
        IPv4ForceIgmpVersion ipv4_force_igmp_version;
        int ipv6_proxy_ndp;
        int mpls_input;
        int ndisc;
        int ndisc_use_dnr;
        int ndisc_use_dns;
        UseDomains ndisc_use_domains;
        IPv6AcceptRAStartDHCP6Client ndisc_start_dhcp6_client;
        uint32_t ndisc_route_table;
        uint32_t ndisc_route_metric_high;
        uint32_t ndisc_route_metric_medium;
        uint32_t ndisc_route_metric_low;
        LLDPMode lldp_mode; /* LLDP reception */
        sd_lldp_multicast_mode_t lldp_multicast_mode; /* LLDP transmission */
        unsigned n_dns;
        int dns_default_route;
        ResolveSupport llmnr;
        ResolveSupport mdns;
        DnssecMode dnssec_mode;
        DnsOverTlsMode dns_over_tls_mode;

        /* 2-byte integers */
        uint16_t dhcp_client_port;
        uint16_t dhcp_port;
        uint16_t router_home_agent_preference;
        uint16_t priority;
        uint16_t bridge_vlan_pvid;
        uint16_t can_termination;

        /* 1-byte integers and booleans */
        bool keep_master;
        bool unmanaged;
        bool configure_without_carrier;
        bool default_route_on_device;
        bool dhcp_use_bootp;
        bool dhcp_iaid_set;
        bool dhcp_route_metric_set;
        bool dhcp_route_table_set;
        bool dhcp_socket_priority_set;
        bool dhcp_anonymize;
        bool dhcp_send_hostname;
        bool dhcp_send_hostname_set;
        bool dhcp_routes_to_dns;
        bool dhcp_routes_to_ntp;
        bool dhcp_use_sip;
        bool dhcp_use_captive_portal;
        bool dhcp_use_mtu;
        bool dhcp_use_routes;
        bool dhcp_quickack;
        bool dhcp_use_timezone;
        bool dhcp_use_hostname;
        bool dhcp_use_6rd;
        uint8_t dhcp_6rd_prefix_route_type;
        bool dhcp_send_release;
        bool dhcp_send_decline;
        bool dhcp6_use_address;
        bool dhcp6_use_pd_prefix;
        bool dhcp6_send_hostname;
        bool dhcp6_send_hostname_set;
        bool dhcp6_use_hostname;
        bool dhcp6_use_sip;
        bool dhcp6_use_captive_portal;
        bool dhcp6_use_rapid_commit;
        bool dhcp6_iaid_set;
        bool dhcp6_iaid_set_explicitly;
        uint8_t dhcp6_pd_prefix_length;
        uint8_t dhcp6_pd_prefix_route_type;
        bool dhcp6_send_release;
        bool dhcp_server;
        bool dhcp_server_bind_to_interface;
        unsigned char dhcp_server_address_prefixlen;
        bool dhcp_server_emit_router;
        bool dhcp_server_emit_timezone;
        bool dhcp_server_emit_domain;
        bool dhcp_server_rapid_commit;
        bool ipv4ll_route;
        uint8_t router_preference;
        uint8_t router_hop_limit;
        bool router_managed;
        bool router_other_information;
        bool router_emit_dns;
        bool router_emit_domains;
        bool router_home_agent_information;
        bool dhcp_pd_announce;
        bool dhcp_pd_assign;
        bool dhcp_pd_manage_temporary_address;
        uint8_t ipv6_hop_limit;
        bool ndisc_use_redirect;
        bool ndisc_use_gateway;
        bool ndisc_use_route_prefix;
        bool ndisc_use_autonomous_prefix;
        bool ndisc_use_onlink_prefix;
        bool ndisc_use_mtu;
        bool ndisc_use_hop_limit;
        bool ndisc_use_reachable_time;
        bool ndisc_use_retransmission_time;
        bool ndisc_quickack;
        bool ndisc_use_captive_portal;
        bool ndisc_use_pref64;
        bool active_slave;
        bool primary_slave;
        bool ndisc_route_table_set:1;
        bool ndisc_route_metric_set:1;
        bool can_termination_set:1;
        bool ignore_carrier_loss_set:1;

} Network;

Network *network_ref(Network *network);
Network *network_unref(Network *network);
DEFINE_TRIVIAL_CLEANUP_FUNC(Network*, network_unref);

int network_load(Manager *manager, OrderedHashmap **ret);
int network_reload(Manager *manager);
int network_load_one(Manager *manager, OrderedHashmap **networks, const char *filename);
int network_verify(Network *network);

int manager_build_dhcp_pd_subnet_ids(Manager *manager);

int network_get_by_name(Manager *manager, const char *name, Network **ret);
void network_apply_anonymize_if_set(Network *network);

bool network_has_static_ipv6_configurations(Network *network);

CONFIG_PARSER_PROTOTYPE(config_parse_stacked_netdev);
CONFIG_PARSER_PROTOTYPE(config_parse_tunnel);
CONFIG_PARSER_PROTOTYPE(config_parse_required_for_online);
CONFIG_PARSER_PROTOTYPE(config_parse_required_family_for_online);
CONFIG_PARSER_PROTOTYPE(config_parse_keep_configuration);
CONFIG_PARSER_PROTOTYPE(config_parse_activation_policy);
CONFIG_PARSER_PROTOTYPE(config_parse_link_group);
CONFIG_PARSER_PROTOTYPE(config_parse_ignore_carrier_loss);

const struct ConfigPerfItem* network_network_gperf_lookup(const char *str, GPERF_LEN_TYPE length);

const char* keep_configuration_to_string(KeepConfiguration i) _const_;
KeepConfiguration keep_configuration_from_string(const char *s) _pure_;

const char* activation_policy_to_string(ActivationPolicy i) _const_;
ActivationPolicy activation_policy_from_string(const char *s) _pure_;
