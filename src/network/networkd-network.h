/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"
#include "sd-device.h"

#include "condition.h"
#include "conf-parser.h"
#include "dhcp-identifier.h"
#include "hashmap.h"
#include "netdev/netdev.h"
#include "networkd-address-label.h"
#include "networkd-address.h"
#include "networkd-brvlan.h"
#include "networkd-fdb.h"
#include "networkd-ipv6-proxy-ndp.h"
#include "networkd-lldp-tx.h"
#include "networkd-neighbor.h"
#include "networkd-radv.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-util.h"
#include "resolve-util.h"

#define DHCP_ROUTE_METRIC 1024
#define IPV4LL_ROUTE_METRIC 2048

#define BRIDGE_VLAN_BITMAP_MAX 4096
#define BRIDGE_VLAN_BITMAP_LEN (BRIDGE_VLAN_BITMAP_MAX / 32)

typedef enum DHCPClientIdentifier {
        DHCP_CLIENT_ID_MAC,
        DHCP_CLIENT_ID_DUID,
        /* The following option may not be good for RFC regarding DHCP (3315 and 4361).
         * But some setups require this. E.g., Sky Broadband, the second largest provider in the UK
         * requires the client id to be set to a custom string, reported at
         * https://github.com/systemd/systemd/issues/7828 */
        DHCP_CLIENT_ID_DUID_ONLY,
        _DHCP_CLIENT_ID_MAX,
        _DHCP_CLIENT_ID_INVALID = -1,
} DHCPClientIdentifier;

typedef enum IPv6PrivacyExtensions {
        /* The values map to the kernel's /proc/sys/net/ipv6/conf/xxx/use_tempaddr values */
        IPV6_PRIVACY_EXTENSIONS_NO,
        IPV6_PRIVACY_EXTENSIONS_PREFER_PUBLIC,
        IPV6_PRIVACY_EXTENSIONS_YES, /* aka prefer-temporary */
        _IPV6_PRIVACY_EXTENSIONS_MAX,
        _IPV6_PRIVACY_EXTENSIONS_INVALID = -1,
} IPv6PrivacyExtensions;

typedef enum DHCPUseDomains {
        DHCP_USE_DOMAINS_NO,
        DHCP_USE_DOMAINS_YES,
        DHCP_USE_DOMAINS_ROUTE,
        _DHCP_USE_DOMAINS_MAX,
        _DHCP_USE_DOMAINS_INVALID = -1,
} DHCPUseDomains;

typedef enum LLDPMode {
        LLDP_MODE_NO = 0,
        LLDP_MODE_YES = 1,
        LLDP_MODE_ROUTERS_ONLY = 2,
        _LLDP_MODE_MAX,
        _LLDP_MODE_INVALID = -1,
} LLDPMode;

typedef struct DUID {
        /* Value of Type in [DHCP] section */
        DUIDType type;

        uint8_t raw_data_len;
        uint8_t raw_data[MAX_DUID_LEN];
        usec_t llt_time;
} DUID;

typedef enum RADVPrefixDelegation {
        RADV_PREFIX_DELEGATION_NONE,
        RADV_PREFIX_DELEGATION_STATIC,
        RADV_PREFIX_DELEGATION_DHCP6,
        RADV_PREFIX_DELEGATION_BOTH,
        _RADV_PREFIX_DELEGATION_MAX,
        _RADV_PREFIX_DELEGATION_INVALID = -1,
} RADVPrefixDelegation;

typedef struct NetworkConfigSection {
        unsigned line;
        char filename[];
} NetworkConfigSection;

int network_config_section_new(const char *filename, unsigned line, NetworkConfigSection **s);
void network_config_section_free(NetworkConfigSection *network);
DEFINE_TRIVIAL_CLEANUP_FUNC(NetworkConfigSection*, network_config_section_free);
extern const struct hash_ops network_config_hash_ops;

typedef struct Manager Manager;

struct Network {
        Manager *manager;

        char *filename;
        char *name;

        Set *match_mac;
        char **match_path;
        char **match_driver;
        char **match_type;
        char **match_name;

        Condition *match_host;
        Condition *match_virt;
        Condition *match_kernel_cmdline;
        Condition *match_kernel_version;
        Condition *match_arch;

        char *description;

        NetDev *bridge;
        NetDev *bond;
        NetDev *vrf;
        Hashmap *stacked_netdevs;

        /* DHCP Client Support */
        AddressFamilyBoolean dhcp;
        DHCPClientIdentifier dhcp_client_identifier;
        char *dhcp_vendor_class_identifier;
        char **dhcp_user_class;
        char *dhcp_hostname;
        unsigned dhcp_route_metric;
        uint32_t dhcp_route_table;
        uint16_t dhcp_client_port;
        bool dhcp_anonymize;
        bool dhcp_send_hostname;
        bool dhcp_broadcast;
        bool dhcp_critical;
        bool dhcp_use_dns;
        bool dhcp_use_ntp;
        bool dhcp_use_mtu;
        bool dhcp_use_routes;
        bool dhcp_use_timezone;
        bool rapid_commit;
        bool dhcp_use_hostname;
        bool dhcp_route_table_set;
        DHCPUseDomains dhcp_use_domains;

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
        AddressFamilyBoolean link_local;
        bool ipv4ll_route;

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
        char **router_search_domains;
        bool dhcp6_force_pd_other_information; /* Start DHCPv6 PD also when 'O'
                                                  RA flag is set, see RFC 7084,
                                                  WPD-4 */

        /* Bridge Support */
        int use_bpdu;
        int hairpin;
        int fast_leave;
        int allow_port_to_be_root;
        int unicast_flood;
        int multicast_to_unicast;
        uint32_t cost;
        uint16_t priority;

        bool use_br_vlan;
        uint16_t pvid;
        uint32_t br_vid_bitmap[BRIDGE_VLAN_BITMAP_LEN];
        uint32_t br_untagged_bitmap[BRIDGE_VLAN_BITMAP_LEN];

        /* CAN support */
        size_t can_bitrate;
        unsigned can_sample_point;
        usec_t can_restart_us;

        AddressFamilyBoolean ip_forward;
        bool ip_masquerade;

        int ipv6_accept_ra;
        int ipv6_dad_transmits;
        int ipv6_hop_limit;
        int ipv6_proxy_ndp;
        int proxy_arp;
        uint32_t ipv6_mtu;

        bool ipv6_accept_ra_use_dns;
        bool active_slave;
        bool primary_slave;
        DHCPUseDomains ipv6_accept_ra_use_domains;
        uint32_t ipv6_accept_ra_route_table;

        union in_addr_union ipv6_token;
        IPv6PrivacyExtensions ipv6_privacy_extensions;

        struct ether_addr *mac;
        uint32_t mtu;
        int arp;
        int multicast;
        int allmulticast;
        bool unmanaged;
        bool configure_without_carrier;
        uint32_t iaid;
        DUID duid;

        bool required_for_online; /* Is this network required to be considered online? */

        LLDPMode lldp_mode; /* LLDP reception */
        LLDPEmit lldp_emit; /* LLDP transmission */

        LIST_HEAD(Address, static_addresses);
        LIST_HEAD(Route, static_routes);
        LIST_HEAD(FdbEntry, static_fdb_entries);
        LIST_HEAD(IPv6ProxyNDPAddress, ipv6_proxy_ndp_addresses);
        LIST_HEAD(Neighbor, neighbors);
        LIST_HEAD(AddressLabel, address_labels);
        LIST_HEAD(Prefix, static_prefixes);
        LIST_HEAD(RoutingPolicyRule, rules);

        unsigned n_static_addresses;
        unsigned n_static_routes;
        unsigned n_static_fdb_entries;
        unsigned n_ipv6_proxy_ndp_addresses;
        unsigned n_neighbors;
        unsigned n_address_labels;
        unsigned n_static_prefixes;
        unsigned n_rules;

        Hashmap *addresses_by_section;
        Hashmap *routes_by_section;
        Hashmap *fdb_entries_by_section;
        Hashmap *neighbors_by_section;
        Hashmap *address_labels_by_section;
        Hashmap *prefixes_by_section;
        Hashmap *rules_by_section;

        struct in_addr_data *dns;
        unsigned n_dns;

        char **search_domains, **route_domains, **ntp, **bind_carrier;

        ResolveSupport llmnr;
        ResolveSupport mdns;
        DnssecMode dnssec_mode;
        DnsOverTlsMode dns_over_tls_mode;
        Set *dnssec_negative_trust_anchors;

        LIST_FIELDS(Network, networks);
};

void network_free(Network *network);

DEFINE_TRIVIAL_CLEANUP_FUNC(Network*, network_free);

int network_load(Manager *manager);
int network_load_one(Manager *manager, const char *filename);

int network_get_by_name(Manager *manager, const char *name, Network **ret);
int network_get(Manager *manager, sd_device *device, const char *ifname, const struct ether_addr *mac, Network **ret);
int network_apply(Network *network, Link *link);
void network_apply_anonymize_if_set(Network *network);

bool network_has_static_ipv6_addresses(Network *network);

CONFIG_PARSER_PROTOTYPE(config_parse_netdev);
CONFIG_PARSER_PROTOTYPE(config_parse_domains);
CONFIG_PARSER_PROTOTYPE(config_parse_tunnel);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp);
CONFIG_PARSER_PROTOTYPE(config_parse_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_client_identifier);
CONFIG_PARSER_PROTOTYPE(config_parse_ipv6token);
CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_privacy_extensions);
CONFIG_PARSER_PROTOTYPE(config_parse_hostname);
CONFIG_PARSER_PROTOTYPE(config_parse_timezone);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_radv_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_radv_search_domains);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_ntp);
CONFIG_PARSER_PROTOTYPE(config_parse_dnssec_negative_trust_anchors);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_use_domains);
CONFIG_PARSER_PROTOTYPE(config_parse_lldp_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_route_table);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_user_class);
CONFIG_PARSER_PROTOTYPE(config_parse_ntp);
/* Legacy IPv4LL support */
CONFIG_PARSER_PROTOTYPE(config_parse_ipv4ll);

const struct ConfigPerfItem* network_network_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

extern const sd_bus_vtable network_vtable[];

int network_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);
int network_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);

const char* ipv6_privacy_extensions_to_string(IPv6PrivacyExtensions i) _const_;
IPv6PrivacyExtensions ipv6_privacy_extensions_from_string(const char *s) _pure_;

const char* dhcp_use_domains_to_string(DHCPUseDomains p) _const_;
DHCPUseDomains dhcp_use_domains_from_string(const char *s) _pure_;

const char* lldp_mode_to_string(LLDPMode m) _const_;
LLDPMode lldp_mode_from_string(const char *s) _pure_;

const char* radv_prefix_delegation_to_string(RADVPrefixDelegation i) _const_;
RADVPrefixDelegation radv_prefix_delegation_from_string(const char *s) _pure_;
