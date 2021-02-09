/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <macro.h>
#include <net/ethernet.h>
#include <linux/ethtool.h>

#include "conf-parser.h"

#define N_ADVERTISE 3

/* we can't use DUPLEX_ prefix, as it
 * clashes with <linux/ethtool.h> */
typedef enum Duplex {
        DUP_HALF = DUPLEX_HALF,
        DUP_FULL = DUPLEX_FULL,
        _DUP_MAX,
        _DUP_INVALID = -EINVAL,
} Duplex;

typedef enum WakeOnLan {
        WOL_PHY,
        WOL_UCAST,
        WOL_MCAST,
        WOL_BCAST,
        WOL_ARP,
        WOL_MAGIC,
        WOL_MAGICSECURE,
        WOL_OFF,
        _WOL_MAX,
        _WOL_INVALID = -EINVAL,
} WakeOnLan;

typedef enum NetDevFeature {
        NET_DEV_FEAT_RX,
        NET_DEV_FEAT_TX,
        NET_DEV_FEAT_GSO,
        NET_DEV_FEAT_GRO,
        NET_DEV_FEAT_LRO,
        NET_DEV_FEAT_TSO,
        NET_DEV_FEAT_TSO6,
        _NET_DEV_FEAT_MAX,
        _NET_DEV_FEAT_INVALID = -EINVAL,
} NetDevFeature;

typedef enum NetDevPort {
        NET_DEV_PORT_TP     = PORT_TP,
        NET_DEV_PORT_AUI    = PORT_AUI,
        NET_DEV_PORT_MII    = PORT_MII,
        NET_DEV_PORT_FIBRE  = PORT_FIBRE,
        NET_DEV_PORT_BNC    = PORT_BNC,
        NET_DEV_PORT_DA     = PORT_DA,
        NET_DEV_PORT_NONE   = PORT_NONE,
        NET_DEV_PORT_OTHER  = PORT_OTHER,
        _NET_DEV_PORT_MAX,
        _NET_DEV_PORT_INVALID = -EINVAL,
} NetDevPort;

#define ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NU32    (SCHAR_MAX)
#define ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NBYTES  (4 * ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NU32)

/* layout of the struct passed from/to userland */
struct ethtool_link_usettings {
        struct ethtool_link_settings base;

        struct {
                uint32_t supported[ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NU32];
                uint32_t advertising[ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NU32];
                uint32_t lp_advertising[ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NU32];
        } link_modes;
};

typedef struct netdev_channels {
        uint32_t rx_count;
        uint32_t tx_count;
        uint32_t other_count;
        uint32_t combined_count;

        bool rx_count_set;
        bool tx_count_set;
        bool other_count_set;
        bool combined_count_set;
} netdev_channels;

typedef struct netdev_ring_param {
        uint32_t rx_pending;
        uint32_t rx_mini_pending;
        uint32_t rx_jumbo_pending;
        uint32_t tx_pending;

        bool rx_pending_set;
        bool rx_mini_pending_set;
        bool rx_jumbo_pending_set;
        bool tx_pending_set;
} netdev_ring_param;

int ethtool_get_driver(int *ethtool_fd, const char *ifname, char **ret);
int ethtool_get_link_info(int *ethtool_fd, const char *ifname,
                          int *ret_autonegotiation, uint64_t *ret_speed,
                          Duplex *ret_duplex, NetDevPort *ret_port);
int ethtool_get_permanent_macaddr(int *ethtool_fd, const char *ifname, struct ether_addr *ret);
int ethtool_set_speed(int *ethtool_fd, const char *ifname, unsigned speed, Duplex duplex);
int ethtool_set_wol(int *ethtool_fd, const char *ifname, WakeOnLan wol);
int ethtool_set_nic_buffer_size(int *ethtool_fd, const char *ifname, const netdev_ring_param *ring);
int ethtool_set_features(int *ethtool_fd, const char *ifname, const int *features);
int ethtool_set_glinksettings(int *ethtool_fd, const char *ifname,
                              int autonegotiation, const uint32_t advertise[static N_ADVERTISE],
                              uint64_t speed, Duplex duplex, NetDevPort port);
int ethtool_set_channels(int *ethtool_fd, const char *ifname, const netdev_channels *channels);
int ethtool_set_flow_control(int *fd, const char *ifname, int rx, int tx, int autoneg);

const char *duplex_to_string(Duplex d) _const_;
Duplex duplex_from_string(const char *d) _pure_;

const char *wol_to_string(WakeOnLan wol) _const_;
WakeOnLan wol_from_string(const char *wol) _pure_;

const char *port_to_string(NetDevPort port) _const_;
NetDevPort port_from_string(const char *port) _pure_;

const char *ethtool_link_mode_bit_to_string(enum ethtool_link_mode_bit_indices val) _const_;
enum ethtool_link_mode_bit_indices ethtool_link_mode_bit_from_string(const char *str) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_duplex);
CONFIG_PARSER_PROTOTYPE(config_parse_wol);
CONFIG_PARSER_PROTOTYPE(config_parse_port);
CONFIG_PARSER_PROTOTYPE(config_parse_channel);
CONFIG_PARSER_PROTOTYPE(config_parse_advertise);
CONFIG_PARSER_PROTOTYPE(config_parse_nic_buffer_size);
