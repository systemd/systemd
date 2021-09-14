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

typedef enum NetDevFeature {
        NET_DEV_FEAT_RX,
        NET_DEV_FEAT_GSO,
        NET_DEV_FEAT_GRO,
        NET_DEV_FEAT_GRO_HW,
        NET_DEV_FEAT_LRO,
        NET_DEV_FEAT_TSO,
        NET_DEV_FEAT_TSO6,
        _NET_DEV_FEAT_SIMPLE_MAX,

        NET_DEV_FEAT_TX = _NET_DEV_FEAT_SIMPLE_MAX,
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

typedef struct u32_opt {
        uint32_t value; /* a value of 0 indicates the hardware advertised maximum should be used.*/
        bool set;
} u32_opt;

typedef struct netdev_channels {
        u32_opt rx;
        u32_opt tx;
        u32_opt other;
        u32_opt combined;
} netdev_channels;

typedef struct netdev_ring_param {
        u32_opt rx;
        u32_opt rx_mini;
        u32_opt rx_jumbo;
        u32_opt tx;
} netdev_ring_param;

typedef struct netdev_coalesce_param {
        u32_opt rx_coalesce_usecs;
        u32_opt rx_max_coalesced_frames;
        u32_opt rx_coalesce_usecs_irq;
        u32_opt rx_max_coalesced_frames_irq;
        u32_opt tx_coalesce_usecs;
        u32_opt tx_max_coalesced_frames;
        u32_opt tx_coalesce_usecs_irq;
        u32_opt tx_max_coalesced_frames_irq;
        u32_opt stats_block_coalesce_usecs;
        int use_adaptive_rx_coalesce;
        int use_adaptive_tx_coalesce;
        u32_opt pkt_rate_low;
        u32_opt rx_coalesce_usecs_low;
        u32_opt rx_max_coalesced_frames_low;
        u32_opt tx_coalesce_usecs_low;
        u32_opt tx_max_coalesced_frames_low;
        u32_opt pkt_rate_high;
        u32_opt rx_coalesce_usecs_high;
        u32_opt rx_max_coalesced_frames_high;
        u32_opt tx_coalesce_usecs_high;
        u32_opt tx_max_coalesced_frames_high;
        u32_opt rate_sample_interval;
} netdev_coalesce_param;

int ethtool_get_driver(int *ethtool_fd, const char *ifname, char **ret);
int ethtool_get_link_info(int *ethtool_fd, const char *ifname,
                          int *ret_autonegotiation, uint64_t *ret_speed,
                          Duplex *ret_duplex, NetDevPort *ret_port);
int ethtool_get_permanent_macaddr(int *ethtool_fd, const char *ifname, struct ether_addr *ret);
int ethtool_set_wol(int *ethtool_fd, const char *ifname, uint32_t wolopts);
int ethtool_set_nic_buffer_size(int *ethtool_fd, const char *ifname, const netdev_ring_param *ring);
int ethtool_set_features(int *ethtool_fd, const char *ifname, const int features[static _NET_DEV_FEAT_MAX]);
int ethtool_set_glinksettings(int *ethtool_fd, const char *ifname,
                              int autonegotiation, const uint32_t advertise[static N_ADVERTISE],
                              uint64_t speed, Duplex duplex, NetDevPort port);
int ethtool_set_channels(int *ethtool_fd, const char *ifname, const netdev_channels *channels);
int ethtool_set_flow_control(int *fd, const char *ifname, int rx, int tx, int autoneg);
int ethtool_set_nic_coalesce_settings(int *ethtool_fd, const char *ifname, const netdev_coalesce_param *coalesce);

const char *duplex_to_string(Duplex d) _const_;
Duplex duplex_from_string(const char *d) _pure_;

int wol_options_to_string_alloc(uint32_t opts, char **ret);

const char *port_to_string(NetDevPort port) _const_;
NetDevPort port_from_string(const char *port) _pure_;

const char *ethtool_link_mode_bit_to_string(enum ethtool_link_mode_bit_indices val) _const_;
enum ethtool_link_mode_bit_indices ethtool_link_mode_bit_from_string(const char *str) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_duplex);
CONFIG_PARSER_PROTOTYPE(config_parse_wol);
CONFIG_PARSER_PROTOTYPE(config_parse_port);
CONFIG_PARSER_PROTOTYPE(config_parse_advertise);
CONFIG_PARSER_PROTOTYPE(config_parse_ring_buffer_or_channel);
CONFIG_PARSER_PROTOTYPE(config_parse_coalesce_u32);
CONFIG_PARSER_PROTOTYPE(config_parse_coalesce_sec);
CONFIG_PARSER_PROTOTYPE(config_parse_nic_coalesce_setting);
