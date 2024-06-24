/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <macro.h>
#include <net/ethernet.h>
#include <linux/ethtool.h>

#include "conf-parser.h"
#include "ether-addr-util.h"

#define N_ADVERTISE 4

/* we can't use DUPLEX_ prefix, as it
 * clashes with <linux/ethtool.h> */
typedef enum Duplex {
        DUP_HALF = DUPLEX_HALF,
        DUP_FULL = DUPLEX_FULL,
        _DUP_MAX,
        _DUP_INVALID = -EINVAL,
} Duplex;

typedef enum NetDevFeature {
        NET_DEV_FEAT_SG,
        NET_DEV_FEAT_IP_CSUM,
        NET_DEV_FEAT_HW_CSUM,
        NET_DEV_FEAT_IPV6_CSUM,
        NET_DEV_FEAT_HIGHDMA,
        NET_DEV_FEAT_FRAGLIST,
        NET_DEV_FEAT_HW_VLAN_CTAG_TX,
        NET_DEV_FEAT_HW_VLAN_CTAG_RX,
        NET_DEV_FEAT_HW_VLAN_CTAG_FILTER,
        NET_DEV_FEAT_HW_VLAN_STAG_TX,
        NET_DEV_FEAT_HW_VLAN_STAG_RX,
        NET_DEV_FEAT_HW_VLAN_STAG_FILTER,
        NET_DEV_FEAT_VLAN_CHALLENGED,
        NET_DEV_FEAT_GSO,
        NET_DEV_FEAT_LLTX,
        NET_DEV_FEAT_NETNS_LOCAL,
        NET_DEV_FEAT_GRO,
        NET_DEV_FEAT_GRO_HW,
        NET_DEV_FEAT_LRO,
        NET_DEV_FEAT_TSO,
        NET_DEV_FEAT_GSO_ROBUST,
        NET_DEV_FEAT_TSO_ECN,
        NET_DEV_FEAT_TSO_MANGLEID,
        NET_DEV_FEAT_TSO6,
        NET_DEV_FEAT_FSO,
        NET_DEV_FEAT_GSO_GRE,
        NET_DEV_FEAT_GSO_GRE_CSUM,
        NET_DEV_FEAT_GSO_IPXIP4,
        NET_DEV_FEAT_GSO_IPXIP6,
        NET_DEV_FEAT_GSO_UDP_TUNNEL,
        NET_DEV_FEAT_GSO_UDP_TUNNEL_CSUM,
        NET_DEV_FEAT_GSO_PARTIAL,
        NET_DEV_FEAT_GSO_TUNNEL_REMCSUM,
        NET_DEV_FEAT_GSO_SCTP,
        NET_DEV_FEAT_GSO_ESP,
        NET_DEV_FEAT_GSO_UDP_L4,
        NET_DEV_FEAT_GSO_FRAGLIST,
        NET_DEV_FEAT_FCOE_CRC,
        NET_DEV_FEAT_SCTP_CRC,
        NET_DEV_FEAT_FCOE_MTU,
        NET_DEV_FEAT_NTUPLE,
        NET_DEV_FEAT_RXHASH,
        NET_DEV_FEAT_RXCSUM,
        NET_DEV_FEAT_NOCACHE_COPY,
        NET_DEV_FEAT_LOOPBACK,
        NET_DEV_FEAT_RXFCS,
        NET_DEV_FEAT_RXALL,
        NET_DEV_FEAT_HW_L2FW_DOFFLOAD,
        NET_DEV_FEAT_HW_TC,
        NET_DEV_FEAT_HW_ESP,
        NET_DEV_FEAT_HW_ESP_TX_CSUM,
        NET_DEV_FEAT_RX_UDP_TUNNEL_PORT,
        NET_DEV_FEAT_HW_TLS_RECORD,
        NET_DEV_FEAT_HW_TLS_TX,
        NET_DEV_FEAT_HW_TLS_RX,
        NET_DEV_FEAT_GRO_FRAGLIST,
        NET_DEV_FEAT_HW_MACSEC,
        NET_DEV_FEAT_GRO_UDP_FWD,
        NET_DEV_FEAT_HW_HSR_TAG_INS,
        NET_DEV_FEAT_HW_HSR_TAG_RM,
        NET_DEV_FEAT_HW_HSR_FWD,
        NET_DEV_FEAT_HW_HSR_DUP,
        _NET_DEV_FEAT_SIMPLE_MAX,

        NET_DEV_FEAT_TXCSUM = _NET_DEV_FEAT_SIMPLE_MAX,
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
        uint32_t value; /* a value of 0 indicates the hardware advertised maximum should be used. */
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
int ethtool_get_permanent_hw_addr(int *ethtool_fd, const char *ifname, struct hw_addr_data *ret);
int ethtool_set_wol(int *ethtool_fd, const char *ifname, uint32_t wolopts, const uint8_t password[SOPASS_MAX]);
int ethtool_set_nic_buffer_size(int *ethtool_fd, const char *ifname, const netdev_ring_param *ring);
int ethtool_set_features(int *ethtool_fd, const char *ifname, const int features[static _NET_DEV_FEAT_MAX]);
int ethtool_set_glinksettings(
                int *fd,
                const char *ifname,
                int autonegotiation,
                const uint32_t advertise[static N_ADVERTISE],
                uint64_t speed,
                Duplex duplex,
                NetDevPort port,
                uint8_t mdi);
int ethtool_set_channels(int *ethtool_fd, const char *ifname, const netdev_channels *channels);
int ethtool_set_flow_control(int *fd, const char *ifname, int rx, int tx, int autoneg);
int ethtool_set_nic_coalesce_settings(int *ethtool_fd, const char *ifname, const netdev_coalesce_param *coalesce);

const char* duplex_to_string(Duplex d) _const_;
Duplex duplex_from_string(const char *d) _pure_;

int wol_options_to_string_alloc(uint32_t opts, char **ret);

const char* port_to_string(NetDevPort port) _const_;
NetDevPort port_from_string(const char *port) _pure_;

const char* mdi_to_string(int mdi) _const_;

const char* ethtool_link_mode_bit_to_string(enum ethtool_link_mode_bit_indices val) _const_;
enum ethtool_link_mode_bit_indices ethtool_link_mode_bit_from_string(const char *str) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_duplex);
CONFIG_PARSER_PROTOTYPE(config_parse_wol);
CONFIG_PARSER_PROTOTYPE(config_parse_port);
CONFIG_PARSER_PROTOTYPE(config_parse_mdi);
CONFIG_PARSER_PROTOTYPE(config_parse_advertise);
CONFIG_PARSER_PROTOTYPE(config_parse_ring_buffer_or_channel);
CONFIG_PARSER_PROTOTYPE(config_parse_coalesce_u32);
CONFIG_PARSER_PROTOTYPE(config_parse_coalesce_sec);
CONFIG_PARSER_PROTOTYPE(config_parse_nic_coalesce_setting);
