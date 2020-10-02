/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/nl80211.h>

#include "sd-bus.h"
#include "sd-device.h"

#include "bridge.h"
#include "condition.h"
#include "conf-parser.h"
#include "hashmap.h"
#include "net-condition.h"
#include "netdev.h"
#include "networkd-brvlan.h"
#include "networkd-dhcp-common.h"
#include "networkd-dhcp4.h"
#include "networkd-dhcp6.h"
#include "networkd-dhcp-server.h"
#include "networkd-lldp-rx.h"
#include "networkd-lldp-tx.h"
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

typedef enum IPv6LinkLocalAddressGenMode {
       IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_EUI64          = IN6_ADDR_GEN_MODE_EUI64,
       IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_NONE           = IN6_ADDR_GEN_MODE_NONE,
       IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_STABLE_PRIVACY = IN6_ADDR_GEN_MODE_STABLE_PRIVACY,
       IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_RANDOM         = IN6_ADDR_GEN_MODE_RANDOM,
       _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_MAX,
       _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_INVALID        = -EINVAL,
} IPv6LinkLocalAddressGenMode;

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
        usec_t timestamp;
        char *description;

        /* [Match] section */
        NetMatch match;
        LIST_HEAD(Condition, conditions);

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

        /* [Link] section */
        struct ether_addr *mac;
        uint32_t mtu;
        uint32_t group;
        int arp;
        int multicast;
        int allmulticast;
        int promiscuous;
        bool unmanaged;
        bool required_for_online; /* Is this network required to be considered online? */
        LinkOperationalStateRange required_operstate_for_online;
        ActivationPolicy activation_policy;

        /* misc settings */
        bool configure_without_carrier;
        int ignore_carrier_loss;
        KeepConfiguration keep_configuration;
        char **bind_carrier;
        bool default_route_on_device;
        AddressFamily ip_masquerade;

        /* DHCP Client Support */
        AddressFamily dhcp;
        DHCPClientIdentifier dhcp_client_identifier;
        DUID duid;
        uint32_t iaid;
        bool iaid_set;
        char *dhcp_vendor_class_identifier;
        char *dhcp_mudurl;
        char **dhcp_user_class;
        char *dhcp_hostname;
        uint64_t dhcp_max_attempts;
        uint32_t dhcp_route_metric;
        bool dhcp_route_metric_set;
        uint32_t dhcp_route_table;
        uint32_t dhcp_fallback_lease_lifetime;
        uint32_t dhcp_route_mtu;
        uint16_t dhcp_client_port;
        int dhcp_critical;
        int dhcp_ip_service_type;
        bool dhcp_anonymize;
        bool dhcp_send_hostname;
        bool dhcp_broadcast;
        bool dhcp_use_dns;
        bool dhcp_use_dns_set;
        bool dhcp_routes_to_dns;
        bool dhcp_use_ntp;
        bool dhcp_use_ntp_set;
        bool dhcp_use_sip;
        bool dhcp_use_mtu;
        bool dhcp_use_routes;
        int dhcp_use_gateway;
        bool dhcp_use_timezone;
        bool dhcp_use_hostname;
        bool dhcp_route_table_set;
        bool dhcp_send_release;
        bool dhcp_send_decline;
        DHCPUseDomains dhcp_use_domains;
        Set *dhcp_deny_listed_ip;
        Set *dhcp_allow_listed_ip;
        Set *dhcp_request_options;
        OrderedHashmap *dhcp_client_send_options;
        OrderedHashmap *dhcp_client_send_vendor_options;

        /* DHCPv6 Client support*/
        bool dhcp6_use_address;
        bool dhcp6_use_dns;
        bool dhcp6_use_dns_set;
        bool dhcp6_use_hostname;
        bool dhcp6_use_ntp;
        bool dhcp6_use_ntp_set;
        bool dhcp6_rapid_commit;
        uint8_t dhcp6_pd_length;
        uint32_t dhcp6_route_metric;
        bool dhcp6_route_metric_set;
        char *dhcp6_mudurl;
        char **dhcp6_user_class;
        char **dhcp6_vendor_class;
        struct in6_addr dhcp6_pd_address;
        DHCP6ClientStartMode dhcp6_without_ra;
        OrderedHashmap *dhcp6_client_send_options;
        OrderedHashmap *dhcp6_client_send_vendor_options;
        Set *dhcp6_request_options;
        /* Start DHCPv6 PD also when 'O' RA flag is set, see RFC 7084, WPD-4 */
        bool dhcp6_force_pd_other_information;

        /* DHCP Server Support */
        bool dhcp_server;
        NetworkDHCPServerEmitAddress dhcp_server_emit[_SD_DHCP_LEASE_SERVER_TYPE_MAX];
        bool dhcp_server_emit_router;
        bool dhcp_server_emit_timezone;
        char *dhcp_server_timezone;
        usec_t dhcp_server_default_lease_time_usec, dhcp_server_max_lease_time_usec;
        uint32_t dhcp_server_pool_offset;
        uint32_t dhcp_server_pool_size;
        OrderedHashmap *dhcp_server_send_options;
        OrderedHashmap *dhcp_server_send_vendor_options;

        /* link local addressing support */
        AddressFamily link_local;
        IPv6LinkLocalAddressGenMode ipv6ll_address_gen_mode;
        bool ipv4ll_route;

        /* IPv6 RA support */
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

        /* DHCPv6 Prefix Delegation support */
        int dhcp6_pd;
        bool dhcp6_pd_announce;
        bool dhcp6_pd_assign;
        bool dhcp6_pd_manage_temporary_address;
        int64_t dhcp6_pd_subnet_id;
        union in_addr_union dhcp6_pd_token;

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

        /* Bridge VLAN */
        bool use_br_vlan;
        uint16_t pvid;
        uint32_t br_vid_bitmap[BRIDGE_VLAN_BITMAP_LEN];
        uint32_t br_untagged_bitmap[BRIDGE_VLAN_BITMAP_LEN];

        /* CAN support */
        uint32_t can_bitrate;
        unsigned can_sample_point;
        uint32_t can_data_bitrate;
        unsigned can_data_sample_point;
        usec_t can_restart_us;
        int can_triple_sampling;
        int can_berr_reporting;
        int can_termination;
        int can_listen_only;
        int can_fd_mode;
        int can_non_iso;

        /* sysctl settings */
        AddressFamily ip_forward;
        int ipv4_accept_local;
        int ipv4_route_localnet;
        int ipv6_dad_transmits;
        int ipv6_hop_limit;
        int proxy_arp;
        uint32_t ipv6_mtu;
        IPv6PrivacyExtensions ipv6_privacy_extensions;
        int ipv6_proxy_ndp;
        Set *ipv6_proxy_ndp_addresses;

        /* IPv6 accept RA */
        int ipv6_accept_ra;
        bool ipv6_accept_ra_use_dns;
        bool ipv6_accept_ra_use_autonomous_prefix;
        bool ipv6_accept_ra_use_onlink_prefix;
        bool active_slave;
        bool primary_slave;
        bool ipv6_accept_ra_route_table_set;
        DHCPUseDomains ipv6_accept_ra_use_domains;
        IPv6AcceptRAStartDHCP6Client ipv6_accept_ra_start_dhcp6_client;
        uint32_t ipv6_accept_ra_route_table;
        Set *ndisc_deny_listed_router;
        Set *ndisc_allow_listed_router;
        Set *ndisc_deny_listed_prefix;
        Set *ndisc_allow_listed_prefix;
        Set *ndisc_deny_listed_route_prefix;
        Set *ndisc_allow_listed_route_prefix;
        OrderedSet *ipv6_tokens;

        /* LLDP support */
        LLDPMode lldp_mode; /* LLDP reception */
        LLDPEmit lldp_emit; /* LLDP transmission */
        char *lldp_mud;    /* LLDP MUD URL */

        OrderedHashmap *addresses_by_section;
        Hashmap *routes_by_section;
        Hashmap *nexthops_by_section;
        Hashmap *fdb_entries_by_section;
        Hashmap *mdb_entries_by_section;
        Hashmap *neighbors_by_section;
        Hashmap *address_labels_by_section;
        Hashmap *prefixes_by_section;
        Hashmap *route_prefixes_by_section;
        Hashmap *rules_by_section;
        OrderedHashmap *tc_by_section;
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

int network_get_by_name(Manager *manager, const char *name, Network **ret);
int network_get(Manager *manager, unsigned short iftype, sd_device *device,
                const char *ifname, char * const *alternative_names, const char *driver,
                const struct ether_addr *mac, const struct ether_addr *permanent_mac,
                enum nl80211_iftype wlan_iftype, const char *ssid, const struct ether_addr *bssid,
                Network **ret);
void network_apply_anonymize_if_set(Network *network);

bool network_has_static_ipv6_configurations(Network *network);

CONFIG_PARSER_PROTOTYPE(config_parse_stacked_netdev);
CONFIG_PARSER_PROTOTYPE(config_parse_tunnel);
CONFIG_PARSER_PROTOTYPE(config_parse_domains);
CONFIG_PARSER_PROTOTYPE(config_parse_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_hostname);
CONFIG_PARSER_PROTOTYPE(config_parse_timezone);
CONFIG_PARSER_PROTOTYPE(config_parse_dnssec_negative_trust_anchors);
CONFIG_PARSER_PROTOTYPE(config_parse_ntp);
CONFIG_PARSER_PROTOTYPE(config_parse_required_for_online);
CONFIG_PARSER_PROTOTYPE(config_parse_keep_configuration);
CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_link_local_address_gen_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_activation_policy);

const struct ConfigPerfItem* network_network_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

const char* keep_configuration_to_string(KeepConfiguration i) _const_;
KeepConfiguration keep_configuration_from_string(const char *s) _pure_;

const char* ipv6_link_local_address_gen_mode_to_string(IPv6LinkLocalAddressGenMode s) _const_;
IPv6LinkLocalAddressGenMode ipv6_link_local_address_gen_mode_from_string(const char *s) _pure_;

const char* activation_policy_to_string(ActivationPolicy i) _const_;
ActivationPolicy activation_policy_from_string(const char *s) _pure_;
