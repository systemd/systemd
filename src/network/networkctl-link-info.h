/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/nl80211.h>

#include "ether-addr-util.h"
#include "ethtool-util.h"
#include "shared-forward.h"
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
        /* Pointers and other 8-byte aligned types */
        char *netdev_kind;
        sd_device *sd_device;
        char *qdisc;
        char **alternative_names;
        char *ssid;

        /* Large structs and arrays */
        char name[IFNAMSIZ+1];
        union {
                struct rtnl_link_stats64 stats64;
                struct rtnl_link_stats stats;
        };
        VxLanInfo vxlan_info;
        union in_addr_union local;
        union in_addr_union remote;

        /* 4-byte integers and enums */
        int ifindex;

        struct hw_addr_data hw_address;
        struct hw_addr_data permanent_hw_address;
        struct ether_addr bssid;

        /* 2-byte integers */
        unsigned short iftype;

        /* 64-bit integers */
        uint64_t tx_bitrate;
        uint64_t rx_bitrate;
        uint64_t speed;

        /* 4-byte integers and enums */
        uint32_t master;
        uint32_t mtu;
        uint32_t min_mtu;
        uint32_t max_mtu;
        uint32_t tx_queues;
        uint32_t rx_queues;
        uint32_t forward_delay;
        uint32_t hello_time;
        uint32_t max_age;
        uint32_t ageing_time;
        uint32_t stp_state;
        uint32_t cost;
        uint32_t fdb_max_learned;
        uint32_t fdb_n_learned;
        uint32_t vni;
        uint32_t label;
        uint32_t miimon;
        uint32_t updelay;
        uint32_t downdelay;
        uint32_t macvlan_mode;
        int autonegotiation;
        Duplex duplex;
        NetDevPort port;
        enum nl80211_iftype wlan_iftype;

        /* 2-byte integers */
        uint16_t priority;
        uint16_t vlan_id;
        uint16_t tunnel_port;
        uint16_t ipvlan_mode;
        uint16_t ipvlan_flags;

        /* 1-byte integers and booleans */
        uint8_t addr_gen_mode;
        uint8_t mcast_igmp_version;
        uint8_t port_state;
        uint8_t ttl;
        uint8_t tos;
        uint8_t inherit;
        uint8_t df;
        uint8_t csum;
        uint8_t csum6_tx;
        uint8_t csum6_rx;
        uint8_t mode;

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
        bool has_fdb_learned:1;
        bool needs_freeing:1;
} LinkInfo;

LinkInfo* link_info_array_free(LinkInfo *array);
DEFINE_TRIVIAL_CLEANUP_FUNC(LinkInfo*, link_info_array_free);

int acquire_link_info(sd_bus *bus, sd_netlink *rtnl, char * const *patterns, LinkInfo **ret);
