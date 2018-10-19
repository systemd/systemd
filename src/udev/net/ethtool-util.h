/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <macro.h>
#include <linux/ethtool.h>

#include "missing.h"

struct link_config;

/* we can't use DUPLEX_ prefix, as it
 * clashes with <linux/ethtool.h> */
typedef enum Duplex {
        DUP_HALF = DUPLEX_HALF,
        DUP_FULL = DUPLEX_FULL,
        _DUP_MAX,
        _DUP_INVALID = -1
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
        _WOL_INVALID = -1
} WakeOnLan;

typedef enum NetDevFeature {
        NET_DEV_FEAT_GSO,
        NET_DEV_FEAT_GRO,
        NET_DEV_FEAT_LRO,
        NET_DEV_FEAT_TSO,
        NET_DEV_FEAT_TSO6,
        _NET_DEV_FEAT_MAX,
        _NET_DEV_FEAT_INVALID = -1
} NetDevFeature;

typedef enum NetDevPort {
        NET_DEV_PORT_TP     = 0x00,
        NET_DEV_PORT_AUI    = 0x01,
        NET_DEV_PORT_MII    = 0x02,
        NET_DEV_PORT_FIBRE  = 0x03,
        NET_DEV_PORT_BNC    = 0x04,
        NET_DEV_PORT_DA     = 0x05,
        NET_DEV_PORT_NONE   = 0xef,
        NET_DEV_PORT_OTHER  = 0xff,
        _NET_DEV_PORT_MAX,
        _NET_DEV_PORT_INVALID = -1
} NetDevPort;

typedef enum NetDevAdvertise {
        NET_DEV_ADVERTISE_10BASET_HALF        =  1 << ETHTOOL_LINK_MODE_10baseT_Half_BIT,
        NET_DEV_ADVERTISE_10BASET_FULL        =  1 << ETHTOOL_LINK_MODE_10baseT_Full_BIT,
        NET_DEV_ADVERTISE_100BASET_HALF       =  1 << ETHTOOL_LINK_MODE_100baseT_Half_BIT,
        NET_DEV_ADVERTISE_100BASET_FULL       =  1 << ETHTOOL_LINK_MODE_100baseT_Full_BIT,
        NET_DEV_ADVERTISE_1000BASET_HALF      =  1 << ETHTOOL_LINK_MODE_1000baseT_Half_BIT,
        NET_DEV_ADVERTISE_1000BASET_FULL      =  1 << ETHTOOL_LINK_MODE_1000baseT_Full_BIT,
        NET_DEV_ADVERTISE_10000BASET_FULL     =  1 << ETHTOOL_LINK_MODE_10000baseT_Full_BIT,
        NET_DEV_ADVERTISE_2500BASEX_FULL      =  1 << ETHTOOL_LINK_MODE_2500baseX_Full_BIT,
        NET_DEV_ADVERTISE_1000BASEKX_FULL     =  1 << ETHTOOL_LINK_MODE_1000baseKX_Full_BIT,
        NET_DEV_ADVERTISE_10000BASEKX4_FULL   =  1 << ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT,
        NET_DEV_ADVERTISE_10000BASEKR_FULL    =  1 << ETHTOOL_LINK_MODE_10000baseKR_Full_BIT,
        NET_DEV_ADVERTISE_10000BASER_FEC      =  1 << ETHTOOL_LINK_MODE_10000baseR_FEC_BIT,
        NET_DEV_ADVERTISE_20000BASEMLD2_Full  =  1 << ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT,
        NET_DEV_ADVERTISE_20000BASEKR2_Full   =  1 << ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT,
        _NET_DEV_ADVERTISE_MAX,
        _NET_DEV_ADVERTISE_INVALID = -1,
} NetDevAdvertise;

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

int ethtool_connect(int *ret);

int ethtool_get_driver(int *fd, const char *ifname, char **ret);
int ethtool_set_speed(int *fd, const char *ifname, unsigned speed, Duplex duplex);
int ethtool_set_wol(int *fd, const char *ifname, WakeOnLan wol);
int ethtool_set_features(int *fd, const char *ifname, int *features);
int ethtool_set_glinksettings(int *fd, const char *ifname, struct link_config *link);
int ethtool_set_channels(int *fd, const char *ifname, netdev_channels *channels);

const char *duplex_to_string(Duplex d) _const_;
Duplex duplex_from_string(const char *d) _pure_;

const char *wol_to_string(WakeOnLan wol) _const_;
WakeOnLan wol_from_string(const char *wol) _pure_;

const char *port_to_string(NetDevPort port) _const_;
NetDevPort port_from_string(const char *port) _pure_;

const char *advertise_to_string(NetDevAdvertise advertise) _const_;
NetDevAdvertise advertise_from_string(const char *advertise) _pure_;

int config_parse_duplex(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_wol(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_port(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_channel(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_advertise(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
