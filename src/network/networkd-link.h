/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <endian.h>
#include <linux/nl80211.h>

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-dhcp-client.h"
#include "sd-dhcp-server.h"
#include "sd-dhcp6-client.h"
#include "sd-ipv4acd.h"
#include "sd-ipv4ll.h"
#include "sd-lldp-rx.h"
#include "sd-lldp-tx.h"
#include "sd-ndisc.h"
#include "sd-radv.h"
#include "sd-netlink.h"

#include "ether-addr-util.h"
#include "log-link.h"
#include "netif-util.h"
#include "network-util.h"
#include "networkd-bridge-vlan.h"
#include "networkd-ipv6ll.h"
#include "networkd-util.h"
#include "ordered-set.h"
#include "resolve-util.h"
#include "set.h"

typedef enum LinkState {
        LINK_STATE_PENDING,     /* udev has not initialized the link */
        LINK_STATE_INITIALIZED, /* udev has initialized the link */
        LINK_STATE_CONFIGURING, /* configuring addresses, routes, etc. */
        LINK_STATE_CONFIGURED,  /* everything is configured */
        LINK_STATE_UNMANAGED,   /* Unmanaged=yes is set */
        LINK_STATE_FAILED,      /* at least one configuration process failed */
        LINK_STATE_LINGER,      /* RTM_DELLINK for the link has been received */
        _LINK_STATE_MAX,
        _LINK_STATE_INVALID = -EINVAL,
} LinkState;

typedef struct Manager Manager;
typedef struct Network Network;
typedef struct NetDev NetDev;
typedef struct DUID DUID;

typedef struct Link {
        Manager *manager;

        unsigned n_ref;

        int ifindex;
        int master_ifindex;
        int dsa_master_ifindex;
        int sr_iov_phys_port_ifindex;
        Set *sr_iov_virt_port_ifindices;

        char *ifname;
        char **alternative_names;
        char *kind;
        unsigned short iftype;
        char *state_file;
        struct hw_addr_data hw_addr;
        struct hw_addr_data bcast_addr;
        struct hw_addr_data permanent_hw_addr;
        struct hw_addr_data requested_hw_addr;
        struct in6_addr ipv6ll_address;
        uint32_t mtu;
        uint32_t min_mtu;
        uint32_t max_mtu;
        uint32_t original_mtu;
        sd_device *dev;
        char *driver;

        /* bridge vlan */
        uint16_t bridge_vlan_pvid;
        bool bridge_vlan_pvid_is_untagged;
        uint32_t bridge_vlan_bitmap[BRIDGE_VLAN_BITMAP_LEN];

        /* to prevent multiple ethtool calls */
        bool ethtool_driver_read;
        bool ethtool_permanent_hw_addr_read;

        /* link-local addressing */
        IPv6LinkLocalAddressGenMode ipv6ll_address_gen_mode;

        /* wlan */
        enum nl80211_iftype wlan_iftype;
        char *ssid;
        char *previous_ssid;
        struct ether_addr bssid;

        unsigned flags;
        uint8_t kernel_operstate;

        sd_event_source *carrier_lost_timer;

        Network *network;
        NetDev *netdev;

        LinkState state;
        LinkOperationalState operstate;
        LinkCarrierState carrier_state;
        LinkAddressState address_state;
        LinkAddressState ipv4_address_state;
        LinkAddressState ipv6_address_state;
        LinkOnlineState online_state;

        unsigned static_address_messages;
        unsigned static_address_label_messages;
        unsigned static_bridge_fdb_messages;
        unsigned static_bridge_mdb_messages;
        unsigned static_ipv6_proxy_ndp_messages;
        unsigned static_neighbor_messages;
        unsigned static_nexthop_messages;
        unsigned static_route_messages;
        unsigned static_routing_policy_rule_messages;
        unsigned tc_messages;
        unsigned sr_iov_messages;
        unsigned set_link_messages;
        unsigned set_flags_messages;
        unsigned create_stacked_netdev_messages;

        Set *addresses;
        Set *neighbors;
        Set *routes;
        Set *qdiscs;
        Set *tclasses;

        sd_dhcp_client *dhcp_client;
        sd_dhcp_lease *dhcp_lease;
        char *lease_file;
        unsigned dhcp4_messages;
        bool dhcp4_configured;
        char *dhcp4_6rd_tunnel_name;

        Hashmap *ipv4acd_by_address;

        sd_ipv4ll *ipv4ll;
        bool ipv4ll_address_configured:1;

        bool static_addresses_configured:1;
        bool static_address_labels_configured:1;
        bool static_bridge_fdb_configured:1;
        bool static_bridge_mdb_configured:1;
        bool static_ipv6_proxy_ndp_configured:1;
        bool static_neighbors_configured:1;
        bool static_nexthops_configured:1;
        bool static_routes_configured:1;
        bool static_routing_policy_rules_configured:1;
        bool tc_configured:1;
        bool sr_iov_configured:1;
        bool activated:1;
        bool master_set:1;
        bool stacked_netdevs_created:1;
        bool bridge_vlan_set:1;

        sd_dhcp_server *dhcp_server;

        sd_ndisc *ndisc;
        sd_event_source *ndisc_expire;
        Set *ndisc_rdnss;
        Set *ndisc_dnssl;
        Set *ndisc_captive_portals;
        Set *ndisc_pref64;
        unsigned ndisc_messages;
        bool ndisc_configured:1;

        sd_radv *radv;

        sd_dhcp6_client *dhcp6_client;
        sd_dhcp6_lease *dhcp6_lease;
        unsigned dhcp6_messages;
        bool dhcp6_configured;

        Set *dhcp_pd_prefixes;
        unsigned dhcp_pd_messages;
        bool dhcp_pd_configured;

        /* This is about LLDP reception */
        sd_lldp_rx *lldp_rx;
        char *lldp_file;

        /* This is about LLDP transmission */
        sd_lldp_tx *lldp_tx;

        Hashmap *bound_by_links;
        Hashmap *bound_to_links;
        Set *slaves;

        /* For speed meter */
        struct rtnl_link_stats64 stats_old, stats_new;
        bool stats_updated;

        /* All kinds of DNS configuration the user configured via D-Bus */
        struct in_addr_full **dns;
        unsigned n_dns;
        OrderedSet *search_domains, *route_domains;

        int dns_default_route;
        ResolveSupport llmnr;
        ResolveSupport mdns;
        DnssecMode dnssec_mode;
        DnsOverTlsMode dns_over_tls_mode;
        Set *dnssec_negative_trust_anchors;

        /* Similar, but NTP server configuration */
        char **ntp;
} Link;

typedef int (*link_netlink_message_handler_t)(sd_netlink*, sd_netlink_message*, Link*);

bool link_is_ready_to_configure(Link *link, bool allow_unmanaged);

void link_ntp_settings_clear(Link *link);
void link_dns_settings_clear(Link *link);
Link *link_unref(Link *link);
Link *link_ref(Link *link);
DEFINE_TRIVIAL_CLEANUP_FUNC(Link*, link_unref);
DEFINE_TRIVIAL_DESTRUCTOR(link_netlink_destroy_callback, Link, link_unref);

int link_get_by_index(Manager *m, int ifindex, Link **ret);
int link_get_by_name(Manager *m, const char *ifname, Link **ret);
int link_get_by_hw_addr(Manager *m, const struct hw_addr_data *hw_addr, Link **ret);
int link_get_master(Link *link, Link **ret);

int link_getlink_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, const char *error_msg);
int link_call_getlink(Link *link, link_netlink_message_handler_t callback);
int link_handle_bound_to_list(Link *link);

void link_enter_failed(Link *link);
void link_set_state(Link *link, LinkState state);
void link_check_ready(Link *link);

void link_update_operstate(Link *link, bool also_update_bond_master);

static inline bool link_has_carrier(Link *link) {
        assert(link);
        return netif_has_carrier(link->kernel_operstate, link->flags);
}

bool link_ipv6_enabled(Link *link);
int link_ipv6ll_gained(Link *link);
bool link_has_ipv6_connectivity(Link *link);

int link_stop_engines(Link *link, bool may_keep_dhcp);

const char* link_state_to_string(LinkState s) _const_;
LinkState link_state_from_string(const char *s) _pure_;

int link_reconfigure_impl(Link *link, bool force);
int link_reconfigure(Link *link, bool force);

int manager_udev_process_link(Manager *m, sd_device *device, sd_device_action_t action);
int manager_rtnl_process_link(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);

int link_flags_to_string_alloc(uint32_t flags, char **ret);
const char *kernel_operstate_to_string(int t) _const_;
