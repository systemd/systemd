/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/ethtool.h>

#if !HAVE_ETHTOOL_LINK_MODE_10baseT_Half_BIT /* linux@3f1ac7a700d039c61d8d8b99f28d605d489a60cf (4.6) */

#define ETHTOOL_GLINKSETTINGS   0x0000004c /* Get ethtool_link_settings */
#define ETHTOOL_SLINKSETTINGS   0x0000004d /* Set ethtool_link_settings */

struct ethtool_link_settings {
        __u32 cmd;
        __u32 speed;
        __u8  duplex;
        __u8  port;
        __u8  phy_address;
        __u8  autoneg;
        __u8  mdio_support;
        __u8  eth_tp_mdix;
        __u8  eth_tp_mdix_ctrl;
        __s8  link_mode_masks_nwords;
        __u8  transceiver;
        __u8  reserved1[3];
        __u32 reserved[7];
        __u32 link_mode_masks[0];
        /* layout of link_mode_masks fields:
         * __u32 map_supported[link_mode_masks_nwords];
         * __u32 map_advertising[link_mode_masks_nwords];
         * __u32 map_lp_advertising[link_mode_masks_nwords];
         */
};

enum ethtool_link_mode_bit_indices {
        ETHTOOL_LINK_MODE_10baseT_Half_BIT           = 0,
        ETHTOOL_LINK_MODE_10baseT_Full_BIT           = 1,
        ETHTOOL_LINK_MODE_100baseT_Half_BIT          = 2,
        ETHTOOL_LINK_MODE_100baseT_Full_BIT          = 3,
        ETHTOOL_LINK_MODE_1000baseT_Half_BIT         = 4,
        ETHTOOL_LINK_MODE_1000baseT_Full_BIT         = 5,
        ETHTOOL_LINK_MODE_Autoneg_BIT                = 6,
        ETHTOOL_LINK_MODE_TP_BIT                     = 7,
        ETHTOOL_LINK_MODE_AUI_BIT                    = 8,
        ETHTOOL_LINK_MODE_MII_BIT                    = 9,
        ETHTOOL_LINK_MODE_FIBRE_BIT                  = 10,
        ETHTOOL_LINK_MODE_BNC_BIT                    = 11,
        ETHTOOL_LINK_MODE_10000baseT_Full_BIT        = 12,
        ETHTOOL_LINK_MODE_Pause_BIT                  = 13,
        ETHTOOL_LINK_MODE_Asym_Pause_BIT             = 14,
        ETHTOOL_LINK_MODE_2500baseX_Full_BIT         = 15,
        ETHTOOL_LINK_MODE_Backplane_BIT              = 16,
        ETHTOOL_LINK_MODE_1000baseKX_Full_BIT        = 17,
        ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT      = 18,
        ETHTOOL_LINK_MODE_10000baseKR_Full_BIT       = 19,
        ETHTOOL_LINK_MODE_10000baseR_FEC_BIT         = 20,
        ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT     = 21,
        ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT      = 22,
        ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT      = 23,
        ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT      = 24,
        ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT      = 25,
        ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT      = 26,
        ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT      = 27,
        ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT      = 28,
        ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT      = 29,
        ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT      = 30,
        ETHTOOL_LINK_MODE_25000baseCR_Full_BIT       = 31,
        ETHTOOL_LINK_MODE_25000baseKR_Full_BIT       = 32,
        ETHTOOL_LINK_MODE_25000baseSR_Full_BIT       = 33,
        ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT      = 34,
        ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT      = 35,
        ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT     = 36,
        ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT     = 37,
        ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT     = 38,
        ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT = 39,
        ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT      = 40,
        ETHTOOL_LINK_MODE_1000baseX_Full_BIT         = 41,
        ETHTOOL_LINK_MODE_10000baseCR_Full_BIT       = 42,
        ETHTOOL_LINK_MODE_10000baseSR_Full_BIT       = 43,
        ETHTOOL_LINK_MODE_10000baseLR_Full_BIT       = 44,
        ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT      = 45,
        ETHTOOL_LINK_MODE_10000baseER_Full_BIT       = 46,
        ETHTOOL_LINK_MODE_2500baseT_Full_BIT         = 47,
        ETHTOOL_LINK_MODE_5000baseT_Full_BIT         = 48,

        ETHTOOL_LINK_MODE_FEC_NONE_BIT               = 49,
        ETHTOOL_LINK_MODE_FEC_RS_BIT                 = 50,
        ETHTOOL_LINK_MODE_FEC_BASER_BIT              = 51,

        /* Last allowed bit for __ETHTOOL_LINK_MODE_LEGACY_MASK is bit
         * 31. Please do NOT define any SUPPORTED_* or ADVERTISED_*
         * macro for bits > 31. The only way to use indices > 31 is to
         * use the new ETHTOOL_GLINKSETTINGS/ETHTOOL_SLINKSETTINGS API.
         */

        __ETHTOOL_LINK_MODE_LAST
          = ETHTOOL_LINK_MODE_FEC_BASER_BIT,
};
#else
#if !HAVE_ETHTOOL_LINK_MODE_25000baseCR_Full_BIT /* linux@3851112e4737cd52aaeda0ce8d084be9ee128106 (4.7) */
#define ETHTOOL_LINK_MODE_25000baseCR_Full_BIT       31
#define ETHTOOL_LINK_MODE_25000baseKR_Full_BIT       32
#define ETHTOOL_LINK_MODE_25000baseSR_Full_BIT       33
#define ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT      34
#define ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT      35
#define ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT     36
#define ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT     37
#define ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT     38
#define ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT 39
#endif
#if !HAVE_ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT /* linux@89da45b8b5b2187734a11038b8593714f964ffd1 (4.8) */
#define ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT      40
#endif
#if !HAVE_ETHTOOL_LINK_MODE_1000baseX_Full_BIT /* linux@5711a98221443aec54c4c81ee98c6ae46acccb65 (4.9) */
#define ETHTOOL_LINK_MODE_1000baseX_Full_BIT         41
#define ETHTOOL_LINK_MODE_10000baseCR_Full_BIT       42
#define ETHTOOL_LINK_MODE_10000baseSR_Full_BIT       43
#define ETHTOOL_LINK_MODE_10000baseLR_Full_BIT       44
#define ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT      45
#define ETHTOOL_LINK_MODE_10000baseER_Full_BIT       46
#endif
#if !HAVE_ETHTOOL_LINK_MODE_2500baseT_Full_BIT /* linux@94842b4fc4d6b1691cfc86c6f5251f299d27f4ba (4.10) */
#define ETHTOOL_LINK_MODE_2500baseT_Full_BIT         47
#define ETHTOOL_LINK_MODE_5000baseT_Full_BIT         48
#endif
#if !HAVE_ETHTOOL_LINK_MODE_FEC_NONE_BIT /* linux@1a5f3da20bd966220931239fbd31e6ac6ff42251 (4.14) */
#define ETHTOOL_LINK_MODE_FEC_NONE_BIT               49
#define ETHTOOL_LINK_MODE_FEC_RS_BIT                 50
#define ETHTOOL_LINK_MODE_FEC_BASER_BIT              51
#endif
#endif
