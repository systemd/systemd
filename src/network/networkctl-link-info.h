/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/nl80211.h>
#include <stdint.h>

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-netlink.h"

#include "ether-addr-util.h"
#include "ethtool-util.h"
#include "in-addr-util.h"

typedef struct VxLanInfo {
        uint32_t vni;
        uint32_t link;

        int local_family;
        int group_family;

        union in_addr_union local;
        union in_addr_union group;

        uint16_t dest_port;

        uint8_t proxy;
        uint8_t learning;
        uint8_t rsc;
        uint8_t l2miss;
        uint8_t l3miss;
        uint8_t tos;
        uint8_t ttl;
} VxLanInfo;

typedef struct LinkInfo {
        char name[IFNAMSIZ+1];
        char *netdev_kind;
        sd_device *sd_device;
        int ifindex;
        unsigned short iftype;
        struct hw_addr_data hw_address;
        struct hw_addr_data permanent_hw_address;
        uint32_t master;
        uint32_t mtu;
        uint32_t min_mtu;
        uint32_t max_mtu;
        uint32_t tx_queues;
        uint32_t rx_queues;
        uint8_t addr_gen_mode;
        char *qdisc;
        char **alternative_names;

        union {
                struct rtnl_link_stats64 stats64;
                struct rtnl_link_stats stats;
        };

        uint64_t tx_bitrate;
        uint64_t rx_bitrate;

        /* bridge info */
        uint32_t forward_delay;
        uint32_t hello_time;
        uint32_t max_age;
        uint32_t ageing_time;
        uint32_t stp_state;
        uint32_t cost;
        uint16_t priority;
        uint8_t mcast_igmp_version;
        uint8_t port_state;
        uint32_t fdb_max_learned;
        uint32_t fdb_n_learned;
        bool has_fdb_learned;

        /* vxlan info */
        VxLanInfo vxlan_info;

        /* vlan info */
        uint16_t vlan_id;

        /* tunnel info */
        uint8_t ttl;
        uint8_t tos;
        uint8_t inherit;
        uint8_t df;
        uint8_t csum;
        uint8_t csum6_tx;
        uint8_t csum6_rx;
        uint16_t tunnel_port;
        uint32_t vni;
        uint32_t label;
        union in_addr_union local;
        union in_addr_union remote;

        /* bonding info */
        uint8_t mode;
        uint32_t miimon;
        uint32_t updelay;
        uint32_t downdelay;

        /* macvlan and macvtap info */
        uint32_t macvlan_mode;

        /* ipvlan info */
        uint16_t ipvlan_mode;
        uint16_t ipvlan_flags;

        /* ethtool info */
        int autonegotiation;
        uint64_t speed;
        Duplex duplex;
        NetDevPort port;

        /* wlan info */
        enum nl80211_iftype wlan_iftype;
        char *ssid;
        struct ether_addr bssid;

        bool has_hw_address:1;
        bool has_permanent_hw_address:1;
        bool has_tx_queues:1;
        bool has_rx_queues:1;
        bool has_stats64:1;
        bool has_stats:1;
        bool has_bitrates:1;
        bool has_ethtool_link_info:1;
        bool has_wlan_link_info:1;
        bool has_tunnel_ipv4:1;
        bool has_ipv6_address_generation_mode:1;

        bool needs_freeing:1;
} LinkInfo;

LinkInfo* link_info_array_free(LinkInfo *array);
DEFINE_TRIVIAL_CLEANUP_FUNC(LinkInfo*, link_info_array_free);

int acquire_link_info(sd_bus *bus, sd_netlink *rtnl, char * const *patterns, LinkInfo **ret);
