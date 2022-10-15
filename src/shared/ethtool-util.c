/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/sockios.h>

#include "conf-parser.h"
#include "ethtool-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "log.h"
#include "memory-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "strv.h"
#include "strxcpyx.h"

static const char* const duplex_table[_DUP_MAX] = {
        [DUP_FULL] = "full",
        [DUP_HALF] = "half"
};

DEFINE_STRING_TABLE_LOOKUP(duplex, Duplex);
DEFINE_CONFIG_PARSE_ENUM(config_parse_duplex, duplex, Duplex, "Failed to parse duplex setting");

static const struct {
        uint32_t opt;
        const char *name;
} wol_option_map[] = {
        { WAKE_PHY,         "phy"        },
        { WAKE_UCAST,       "unicast",   },
        { WAKE_MCAST,       "multicast", },
        { WAKE_BCAST,       "broadcast", },
        { WAKE_ARP,         "arp",       },
        { WAKE_MAGIC,       "magic",     },
        { WAKE_MAGICSECURE, "secureon",  },
};

int wol_options_to_string_alloc(uint32_t opts, char **ret) {
        _cleanup_free_ char *str = NULL;

        assert(ret);

        if (opts == UINT32_MAX) {
                *ret = NULL;
                return 0;
        }

        for (size_t i = 0; i < ELEMENTSOF(wol_option_map); i++)
                if (opts & wol_option_map[i].opt &&
                    !strextend_with_separator(&str, ",", wol_option_map[i].name))
                        return -ENOMEM;

        if (!str) {
                str = strdup("off");
                if (!str)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(str);
        return 1;
}

static const char* const port_table[] = {
        [NET_DEV_PORT_TP]     = "tp",
        [NET_DEV_PORT_AUI]    = "aui",
        [NET_DEV_PORT_MII]    = "mii",
        [NET_DEV_PORT_FIBRE]  = "fibre",
        [NET_DEV_PORT_BNC]    = "bnc",
};

DEFINE_STRING_TABLE_LOOKUP(port, NetDevPort);
DEFINE_CONFIG_PARSE_ENUM(config_parse_port, port, NetDevPort, "Failed to parse Port setting");

static const char* const mdi_table[] = {
        [ETH_TP_MDI_INVALID]  = "unknown",
        [ETH_TP_MDI]          = "mdi",
        [ETH_TP_MDI_X]        = "mdi-x",
        [ETH_TP_MDI_AUTO]     = "auto",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(mdi, int);

static const char* const netdev_feature_table[_NET_DEV_FEAT_MAX] = {
        [NET_DEV_FEAT_SG]                  = "tx-scatter-gather",
        [NET_DEV_FEAT_IP_CSUM]             = "tx-checksum-ipv4",
        [NET_DEV_FEAT_HW_CSUM]             = "tx-checksum-ip-generic",
        [NET_DEV_FEAT_IPV6_CSUM]           = "tx-checksum-ipv6",
        [NET_DEV_FEAT_HIGHDMA]             = "highdma",
        [NET_DEV_FEAT_FRAGLIST]            = "tx-scatter-gather-fraglist",
        [NET_DEV_FEAT_HW_VLAN_CTAG_TX]     = "tx-vlan-hw-insert",
        [NET_DEV_FEAT_HW_VLAN_CTAG_RX]     = "rx-vlan-hw-parse",
        [NET_DEV_FEAT_HW_VLAN_CTAG_FILTER] = "rx-vlan-filter",
        [NET_DEV_FEAT_HW_VLAN_STAG_TX]     = "tx-vlan-stag-hw-insert",
        [NET_DEV_FEAT_HW_VLAN_STAG_RX]     = "rx-vlan-stag-hw-parse",
        [NET_DEV_FEAT_HW_VLAN_STAG_FILTER] = "rx-vlan-stag-filter",
        [NET_DEV_FEAT_VLAN_CHALLENGED]     = "vlan-challenged",
        [NET_DEV_FEAT_GSO]                 = "tx-generic-segmentation",
        [NET_DEV_FEAT_LLTX]                = "tx-lockless",
        [NET_DEV_FEAT_NETNS_LOCAL]         = "netns-local",
        [NET_DEV_FEAT_GRO]                 = "rx-gro",
        [NET_DEV_FEAT_GRO_HW]              = "rx-gro-hw",
        [NET_DEV_FEAT_LRO]                 = "rx-lro",
        [NET_DEV_FEAT_TSO]                 = "tx-tcp-segmentation",
        [NET_DEV_FEAT_GSO_ROBUST]          = "tx-gso-robust",
        [NET_DEV_FEAT_TSO_ECN]             = "tx-tcp-ecn-segmentation",
        [NET_DEV_FEAT_TSO_MANGLEID]        = "tx-tcp-mangleid-segmentation",
        [NET_DEV_FEAT_TSO6]                = "tx-tcp6-segmentation",
        [NET_DEV_FEAT_FSO]                 = "tx-fcoe-segmentation",
        [NET_DEV_FEAT_GSO_GRE]             = "tx-gre-segmentation",
        [NET_DEV_FEAT_GSO_GRE_CSUM]        = "tx-gre-csum-segmentation",
        [NET_DEV_FEAT_GSO_IPXIP4]          = "tx-ipxip4-segmentation",
        [NET_DEV_FEAT_GSO_IPXIP6]          = "tx-ipxip6-segmentation",
        [NET_DEV_FEAT_GSO_UDP_TUNNEL]      = "tx-udp_tnl-segmentation",
        [NET_DEV_FEAT_GSO_UDP_TUNNEL_CSUM] = "tx-udp_tnl-csum-segmentation",
        [NET_DEV_FEAT_GSO_PARTIAL]         = "tx-gso-partial",
        [NET_DEV_FEAT_GSO_TUNNEL_REMCSUM]  = "tx-tunnel-remcsum-segmentation",
        [NET_DEV_FEAT_GSO_SCTP]            = "tx-sctp-segmentation",
        [NET_DEV_FEAT_GSO_ESP]             = "tx-esp-segmentation",
        [NET_DEV_FEAT_GSO_UDP_L4]          = "tx-udp-segmentation",
        [NET_DEV_FEAT_GSO_FRAGLIST]        = "tx-gso-list",
        [NET_DEV_FEAT_FCOE_CRC]            = "tx-checksum-fcoe-crc",
        [NET_DEV_FEAT_SCTP_CRC]            = "tx-checksum-sctp",
        [NET_DEV_FEAT_FCOE_MTU]            = "fcoe-mtu",
        [NET_DEV_FEAT_NTUPLE]              = "rx-ntuple-filter",
        [NET_DEV_FEAT_RXHASH]              = "rx-hashing",
        [NET_DEV_FEAT_RXCSUM]              = "rx-checksum",
        [NET_DEV_FEAT_NOCACHE_COPY]        = "tx-nocache-copy",
        [NET_DEV_FEAT_LOOPBACK]            = "loopback",
        [NET_DEV_FEAT_RXFCS]               = "rx-fcs",
        [NET_DEV_FEAT_RXALL]               = "rx-all",
        [NET_DEV_FEAT_HW_L2FW_DOFFLOAD]    = "l2-fwd-offload",
        [NET_DEV_FEAT_HW_TC]               = "hw-tc-offload",
        [NET_DEV_FEAT_HW_ESP]              = "esp-hw-offload",
        [NET_DEV_FEAT_HW_ESP_TX_CSUM]      = "esp-tx-csum-hw-offload",
        [NET_DEV_FEAT_RX_UDP_TUNNEL_PORT]  = "rx-udp_tunnel-port-offload",
        [NET_DEV_FEAT_HW_TLS_RECORD]       = "tls-hw-record",
        [NET_DEV_FEAT_HW_TLS_TX]           = "tls-hw-tx-offload",
        [NET_DEV_FEAT_HW_TLS_RX]           = "tls-hw-rx-offload",
        [NET_DEV_FEAT_GRO_FRAGLIST]        = "rx-gro-list",
        [NET_DEV_FEAT_HW_MACSEC]           = "macsec-hw-offload",
        [NET_DEV_FEAT_GRO_UDP_FWD]         = "rx-udp-gro-forwarding",
        [NET_DEV_FEAT_HW_HSR_TAG_INS]      = "hsr-tag-ins-offload",
        [NET_DEV_FEAT_HW_HSR_TAG_RM]       = "hsr-tag-rm-offload",
        [NET_DEV_FEAT_HW_HSR_FWD]          = "hsr-fwd-offload",
        [NET_DEV_FEAT_HW_HSR_DUP]          = "hsr-dup-offload",

        [NET_DEV_FEAT_TXCSUM]              = "tx-checksum-", /* The suffix "-" means any feature beginning with "tx-checksum-" */
};

static const char* const ethtool_link_mode_bit_table[] = {
        [ETHTOOL_LINK_MODE_10baseT_Half_BIT]               = "10baset-half",
        [ETHTOOL_LINK_MODE_10baseT_Full_BIT]               = "10baset-full",
        [ETHTOOL_LINK_MODE_100baseT_Half_BIT]              = "100baset-half",
        [ETHTOOL_LINK_MODE_100baseT_Full_BIT]              = "100baset-full",
        [ETHTOOL_LINK_MODE_1000baseT_Half_BIT]             = "1000baset-half",
        [ETHTOOL_LINK_MODE_1000baseT_Full_BIT]             = "1000baset-full",
        [ETHTOOL_LINK_MODE_Autoneg_BIT]                    = "autonegotiation",
        [ETHTOOL_LINK_MODE_TP_BIT]                         = "tp",
        [ETHTOOL_LINK_MODE_AUI_BIT]                        = "aui",
        [ETHTOOL_LINK_MODE_MII_BIT]                        = "mii",
        [ETHTOOL_LINK_MODE_FIBRE_BIT]                      = "fibre",
        [ETHTOOL_LINK_MODE_BNC_BIT]                        = "bnc",
        [ETHTOOL_LINK_MODE_10000baseT_Full_BIT]            = "10000baset-full",
        [ETHTOOL_LINK_MODE_Pause_BIT]                      = "pause",
        [ETHTOOL_LINK_MODE_Asym_Pause_BIT]                 = "asym-pause",
        [ETHTOOL_LINK_MODE_2500baseX_Full_BIT]             = "2500basex-full",
        [ETHTOOL_LINK_MODE_Backplane_BIT]                  = "backplane",
        [ETHTOOL_LINK_MODE_1000baseKX_Full_BIT]            = "1000basekx-full",
        [ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT]          = "10000basekx4-full",
        [ETHTOOL_LINK_MODE_10000baseKR_Full_BIT]           = "10000basekr-full",
        [ETHTOOL_LINK_MODE_10000baseR_FEC_BIT]             = "10000baser-fec",
        [ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT]         = "20000basemld2-full",
        [ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT]          = "20000basekr2-full",
        [ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT]          = "40000basekr4-full",
        [ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT]          = "40000basecr4-full",
        [ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT]          = "40000basesr4-full",
        [ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT]          = "40000baselr4-full",
        [ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT]          = "56000basekr4-full",
        [ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT]          = "56000basecr4-full",
        [ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT]          = "56000basesr4-full",
        [ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT]          = "56000baselr4-full",
        [ETHTOOL_LINK_MODE_25000baseCR_Full_BIT]           = "25000basecr-full",
        [ETHTOOL_LINK_MODE_25000baseKR_Full_BIT]           = "25000basekr-full",
        [ETHTOOL_LINK_MODE_25000baseSR_Full_BIT]           = "25000basesr-full",
        [ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT]          = "50000basecr2-full",
        [ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT]          = "50000basekr2-full",
        [ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT]         = "100000basekr4-full",
        [ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT]         = "100000basesr4-full",
        [ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT]         = "100000basecr4-full",
        [ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT]     = "100000baselr4-er4-full",
        [ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT]          = "50000basesr2-full",
        [ETHTOOL_LINK_MODE_1000baseX_Full_BIT]             = "1000basex-full",
        [ETHTOOL_LINK_MODE_10000baseCR_Full_BIT]           = "10000basecr-full",
        [ETHTOOL_LINK_MODE_10000baseSR_Full_BIT]           = "10000basesr-full",
        [ETHTOOL_LINK_MODE_10000baseLR_Full_BIT]           = "10000baselr-full",
        [ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT]          = "10000baselrm-full",
        [ETHTOOL_LINK_MODE_10000baseER_Full_BIT]           = "10000baseer-full",
        [ETHTOOL_LINK_MODE_2500baseT_Full_BIT]             = "2500baset-full",
        [ETHTOOL_LINK_MODE_5000baseT_Full_BIT]             = "5000baset-full",
        [ETHTOOL_LINK_MODE_FEC_NONE_BIT]                   = "fec-none",
        [ETHTOOL_LINK_MODE_FEC_RS_BIT]                     = "fec-rs",
        [ETHTOOL_LINK_MODE_FEC_BASER_BIT]                  = "fec-baser",
        [ETHTOOL_LINK_MODE_50000baseKR_Full_BIT]           = "50000basekr-full",
        [ETHTOOL_LINK_MODE_50000baseSR_Full_BIT]           = "50000basesr-full",
        [ETHTOOL_LINK_MODE_50000baseCR_Full_BIT]           = "50000basecr-full",
        [ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT]     = "50000baselr-er-fr-full",
        [ETHTOOL_LINK_MODE_50000baseDR_Full_BIT]           = "50000basedr-full",
        [ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT]         = "100000basekr2-full",
        [ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT]         = "100000basesr2-full",
        [ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT]         = "100000basecr2-full",
        [ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT] = "100000baselr2-er2-fr2-full",
        [ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT]         = "100000basedr2-full",
        [ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT]         = "200000basekr4-full",
        [ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT]         = "200000basesr4-full",
        [ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT] = "200000baselr4-er4-fr4-full",
        [ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT]         = "200000basedr4-full",
        [ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT]         = "200000basecr4-full",
        [ETHTOOL_LINK_MODE_100baseT1_Full_BIT]             = "100baset1-full",
        [ETHTOOL_LINK_MODE_1000baseT1_Full_BIT]            = "1000baset1-full",
        [ETHTOOL_LINK_MODE_400000baseKR8_Full_BIT]         = "400000basekr8-full",
        [ETHTOOL_LINK_MODE_400000baseSR8_Full_BIT]         = "400000basesr8-full",
        [ETHTOOL_LINK_MODE_400000baseLR8_ER8_FR8_Full_BIT] = "400000baselr8-er8-fr8-full",
        [ETHTOOL_LINK_MODE_400000baseDR8_Full_BIT]         = "400000basedr8-full",
        [ETHTOOL_LINK_MODE_400000baseCR8_Full_BIT]         = "400000basecr8-full",
        [ETHTOOL_LINK_MODE_FEC_LLRS_BIT]                   = "fec-llrs",
        [ETHTOOL_LINK_MODE_100000baseKR_Full_BIT]          = "100000basekr-full",
        [ETHTOOL_LINK_MODE_100000baseSR_Full_BIT]          = "100000basesr-full",
        [ETHTOOL_LINK_MODE_100000baseLR_ER_FR_Full_BIT]    = "100000baselr-er-fr-full",
        [ETHTOOL_LINK_MODE_100000baseCR_Full_BIT]          = "100000basecr-full",
        [ETHTOOL_LINK_MODE_100000baseDR_Full_BIT]          = "100000basedr-full",
        [ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT]         = "200000basekr2-full",
        [ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT]         = "200000basesr2-full",
        [ETHTOOL_LINK_MODE_200000baseLR2_ER2_FR2_Full_BIT] = "200000baselr2-er2-fr2-full",
        [ETHTOOL_LINK_MODE_200000baseDR2_Full_BIT]         = "200000basedr2-full",
        [ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT]         = "200000basecr2-full",
        [ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT]         = "400000basekr4-full",
        [ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT]         = "400000basesr4-full",
        [ETHTOOL_LINK_MODE_400000baseLR4_ER4_FR4_Full_BIT] = "400000baselr4-er4-fr4-full",
        [ETHTOOL_LINK_MODE_400000baseDR4_Full_BIT]         = "400000basedr4-full",
        [ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT]         = "400000basecr4-full",
        [ETHTOOL_LINK_MODE_100baseFX_Half_BIT]             = "100basefx-half",
        [ETHTOOL_LINK_MODE_100baseFX_Full_BIT]             = "100basefx-full",
};
/* Make sure the array is large enough to fit all bits */
assert_cc((ELEMENTSOF(ethtool_link_mode_bit_table)-1) / 32 < N_ADVERTISE);

DEFINE_STRING_TABLE_LOOKUP(ethtool_link_mode_bit, enum ethtool_link_mode_bit_indices);

static int ethtool_connect(int *ethtool_fd) {
        int fd;

        assert(ethtool_fd);

        /* This does nothing if already connected. */
        if (*ethtool_fd >= 0)
                return 0;

        fd = socket_ioctl_fd();
        if (fd < 0)
                return log_debug_errno(fd, "ethtool: could not create control socket: %m");

        *ethtool_fd = fd;
        return 0;
}

int ethtool_get_driver(int *ethtool_fd, const char *ifname, char **ret) {
        struct ethtool_drvinfo ecmd = {
                .cmd = ETHTOOL_GDRVINFO,
        };
        struct ifreq ifr = {
                .ifr_data = (void*) &ecmd,
        };
        char *d;
        int r;

        assert(ethtool_fd);
        assert(ifname);
        assert(ret);

        r = ethtool_connect(ethtool_fd);
        if (r < 0)
                return r;

        strscpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

        if (ioctl(*ethtool_fd, SIOCETHTOOL, &ifr) < 0)
                return -errno;

        if (isempty(ecmd.driver))
                return -ENODATA;

        d = strdup(ecmd.driver);
        if (!d)
                return -ENOMEM;

        *ret = d;
        return 0;
}

int ethtool_get_link_info(
                int *ethtool_fd,
                const char *ifname,
                int *ret_autonegotiation,
                uint64_t *ret_speed,
                Duplex *ret_duplex,
                NetDevPort *ret_port) {

        struct ethtool_cmd ecmd = {
                .cmd = ETHTOOL_GSET,
        };
        struct ifreq ifr = {
                .ifr_data = (void*) &ecmd,
        };
        int r;

        assert(ethtool_fd);
        assert(ifname);

        r = ethtool_connect(ethtool_fd);
        if (r < 0)
                return r;

        strscpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

        if (ioctl(*ethtool_fd, SIOCETHTOOL, &ifr) < 0)
                return -errno;

        if (ret_autonegotiation)
                *ret_autonegotiation = ecmd.autoneg;

        if (ret_speed) {
                uint32_t speed;

                speed = ethtool_cmd_speed(&ecmd);
                *ret_speed = speed == (uint32_t) SPEED_UNKNOWN ?
                        UINT64_MAX : (uint64_t) speed * 1000 * 1000;
        }

        if (ret_duplex)
                *ret_duplex = ecmd.duplex;

        if (ret_port)
                *ret_port = ecmd.port;

        return 0;
}

int ethtool_get_permanent_hw_addr(int *ethtool_fd, const char *ifname, struct hw_addr_data *ret) {
        _cleanup_close_ int fd = -1;
        struct {
                struct ethtool_perm_addr addr;
                uint8_t space[HW_ADDR_MAX_SIZE];
        } epaddr = {
                .addr.cmd = ETHTOOL_GPERMADDR,
                .addr.size = HW_ADDR_MAX_SIZE,
        };
        struct ifreq ifr = {
                .ifr_data = (caddr_t) &epaddr,
        };
        int r;

        assert(ifname);
        assert(ret);

        if (!ethtool_fd)
                ethtool_fd = &fd;
        r = ethtool_connect(ethtool_fd);
        if (r < 0)
                return r;

        strscpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

        if (ioctl(*ethtool_fd, SIOCETHTOOL, &ifr) < 0)
                return -errno;

        if (epaddr.addr.size == 0)
                return -ENODATA;

        if (epaddr.addr.size > HW_ADDR_MAX_SIZE)
                return -EINVAL;

        ret->length = epaddr.addr.size;
        memcpy(ret->bytes, epaddr.addr.data, epaddr.addr.size);
        return 0;
}

#define UPDATE(dest, val, updated)                     \
        do {                                           \
                typeof(val) _v = (val);                \
                if (dest != _v)                        \
                        updated = true;                \
                dest = _v;                             \
        } while (false)

#define UPDATE_WITH_MAX(dest, max, val, updated)       \
        do {                                           \
                typeof(dest) _v = (val);               \
                typeof(dest) _max = (max);             \
                if (_v == 0 || _v > _max)              \
                        _v = _max;                     \
                if (dest != _v)                        \
                        updated = true;                \
                dest = _v;                             \
        } while (false)

int ethtool_set_wol(
                int *ethtool_fd,
                const char *ifname,
                uint32_t wolopts,
                const uint8_t password[SOPASS_MAX]) {

        struct ethtool_wolinfo ecmd = {
                .cmd = ETHTOOL_GWOL,
        };
        struct ifreq ifr = {
                .ifr_data = (void*) &ecmd,
        };
        bool need_update = false;
        int r;

        assert(ethtool_fd);
        assert(ifname);

        if (wolopts == UINT32_MAX && !password)
                /* Nothing requested. Return earlier. */
                return 0;

        r = ethtool_connect(ethtool_fd);
        if (r < 0)
                return r;

        strscpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

        if (ioctl(*ethtool_fd, SIOCETHTOOL, &ifr) < 0)
                return -errno;

        if (wolopts == UINT32_MAX) {
                /* When password is specified without valid WoL options specified, then enable
                 * WAKE_MAGICSECURE flag if supported. */
                wolopts = ecmd.wolopts;
                if (password && FLAGS_SET(ecmd.supported, WAKE_MAGICSECURE))
                        wolopts |= WAKE_MAGICSECURE;
        }

        if ((wolopts & ~ecmd.supported) != 0) {
                _cleanup_free_ char *str = NULL;

                (void) wol_options_to_string_alloc(wolopts & ~ecmd.supported, &str);
                log_debug("Network interface %s does not support requested Wake on LAN options \"%s\", ignoring.",
                          ifname, strna(str));

                wolopts &= ecmd.supported;
        }

        if (!FLAGS_SET(wolopts, WAKE_MAGICSECURE))
                /* When WAKE_MAGICSECURE flag is not set, then ignore password. */
                password = NULL;

        UPDATE(ecmd.wolopts, wolopts, need_update);
        if (password &&
            memcmp(ecmd.sopass, password, sizeof(ecmd.sopass)) != 0) {
                memcpy(ecmd.sopass, password, sizeof(ecmd.sopass));
                need_update = true;
        }

        if (!need_update) {
                explicit_bzero_safe(&ecmd, sizeof(ecmd));
                return 0;
        }

        ecmd.cmd = ETHTOOL_SWOL;
        r = RET_NERRNO(ioctl(*ethtool_fd, SIOCETHTOOL, &ifr));

        explicit_bzero_safe(&ecmd, sizeof(ecmd));
        return r;
}

int ethtool_set_nic_buffer_size(int *ethtool_fd, const char *ifname, const netdev_ring_param *ring) {
        struct ethtool_ringparam ecmd = {
                .cmd = ETHTOOL_GRINGPARAM,
        };
        struct ifreq ifr = {
                .ifr_data = (void*) &ecmd,
        };
        bool need_update = false;
        int r;

        assert(ethtool_fd);
        assert(ifname);
        assert(ring);

        if (!ring->rx.set &&
            !ring->rx_mini.set &&
            !ring->rx_jumbo.set &&
            !ring->tx.set)
                return 0;

        r = ethtool_connect(ethtool_fd);
        if (r < 0)
                return r;

        strscpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

        if (ioctl(*ethtool_fd, SIOCETHTOOL, &ifr) < 0)
                return -errno;

        if (ring->rx.set)
                UPDATE_WITH_MAX(ecmd.rx_pending, ecmd.rx_max_pending, ring->rx.value, need_update);

        if (ring->rx_mini.set)
                UPDATE_WITH_MAX(ecmd.rx_mini_pending, ecmd.rx_mini_max_pending, ring->rx_mini.value, need_update);

        if (ring->rx_jumbo.set)
                UPDATE_WITH_MAX(ecmd.rx_jumbo_pending, ecmd.rx_jumbo_max_pending, ring->rx_jumbo.value, need_update);

        if (ring->tx.set)
                UPDATE_WITH_MAX(ecmd.tx_pending, ecmd.tx_max_pending, ring->tx.value, need_update);

        if (!need_update)
                return 0;

        ecmd.cmd = ETHTOOL_SRINGPARAM;
        return RET_NERRNO(ioctl(*ethtool_fd, SIOCETHTOOL, &ifr));
}

static int get_stringset(int ethtool_fd, const char *ifname, enum ethtool_stringset stringset_id, struct ethtool_gstrings **ret) {
        _cleanup_free_ struct ethtool_gstrings *strings = NULL;
        struct {
                struct ethtool_sset_info info;
                uint32_t space;
        } buffer = {
                .info.cmd = ETHTOOL_GSSET_INFO,
                .info.sset_mask = UINT64_C(1) << stringset_id,
        };
        struct ifreq ifr = {
                .ifr_data = (void*) &buffer,
        };
        uint32_t len;

        assert(ethtool_fd >= 0);
        assert(ifname);
        assert(ret);

        strscpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

        if (ioctl(ethtool_fd, SIOCETHTOOL, &ifr) < 0)
                return -errno;

        if (buffer.info.sset_mask == 0)
                return -EOPNOTSUPP;

#pragma GCC diagnostic push
#if HAVE_ZERO_LENGTH_BOUNDS
#  pragma GCC diagnostic ignored "-Wzero-length-bounds"
#endif
        len = buffer.info.data[0];
#pragma GCC diagnostic pop
        if (len == 0)
                return -EOPNOTSUPP;

        strings = malloc0(offsetof(struct ethtool_gstrings, data) + len * ETH_GSTRING_LEN);
        if (!strings)
                return -ENOMEM;

        strings->cmd = ETHTOOL_GSTRINGS;
        strings->string_set = stringset_id;
        strings->len = len;

        ifr.ifr_data = (void*) strings;

        if (ioctl(ethtool_fd, SIOCETHTOOL, &ifr) < 0)
                return -errno;

        *ret = TAKE_PTR(strings);
        return 0;
}

static int get_features(int ethtool_fd, const char *ifname, uint32_t n_features, struct ethtool_gfeatures **ret) {
        _cleanup_free_ struct ethtool_gfeatures *gfeatures = NULL;
        struct ifreq ifr;

        assert(ethtool_fd >= 0);
        assert(ifname);
        assert(ret);
        assert(n_features > 0);

        gfeatures = malloc0(offsetof(struct ethtool_gfeatures, features) +
                            DIV_ROUND_UP(n_features, 32U) * sizeof(gfeatures->features[0]));
        if (!gfeatures)
                return -ENOMEM;

        gfeatures->cmd = ETHTOOL_GFEATURES;
        gfeatures->size = DIV_ROUND_UP(n_features, 32U);

        ifr = (struct ifreq) {
                .ifr_data = (void*) gfeatures,
        };
        strscpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

        if (ioctl(ethtool_fd, SIOCETHTOOL, &ifr) < 0)
                return -errno;

        *ret = TAKE_PTR(gfeatures);
        return 0;
}

static int set_features_bit(
                const struct ethtool_gstrings *strings,
                const struct ethtool_gfeatures *gfeatures,
                struct ethtool_sfeatures *sfeatures,
                const char *feature,
                int flag) {

        assert(strings);
        assert(gfeatures);
        assert(sfeatures);
        assert(feature);

        if (flag < 0)
                return 0;

        for (uint32_t i = 0; i < strings->len; i++) {
                uint32_t block, mask;

                if (!strneq((const char*) &strings->data[i * ETH_GSTRING_LEN], feature, ETH_GSTRING_LEN))
                        continue;

                block = i / 32;
                mask = UINT32_C(1) << (i % 32);

                if (!FLAGS_SET(gfeatures->features[block].available, mask) ||
                    FLAGS_SET(gfeatures->features[block].never_changed, mask))
                        return -EOPNOTSUPP;

                sfeatures->features[block].valid |= mask;
                SET_FLAG(sfeatures->features[block].requested, mask, flag);

                return 0;
        }

        return -ENODATA;
}

static int set_features_multiple_bit(
                const struct ethtool_gstrings *strings,
                const struct ethtool_gfeatures *gfeatures,
                struct ethtool_sfeatures *sfeatures,
                const char *feature,
                int flag) {

        bool found = false;
        int r = -ENODATA;

        assert(strings);
        assert(gfeatures);
        assert(sfeatures);
        assert(feature);

        if (flag < 0)
                return 0;

        for (uint32_t i = 0; i < strings->len; i++) {
                uint32_t block, mask;

                if (!startswith((const char*) &strings->data[i * ETH_GSTRING_LEN], feature))
                        continue;

                block = i / 32;
                mask = UINT32_C(1) << (i % 32);

                if (!FLAGS_SET(gfeatures->features[block].available, mask) ||
                    FLAGS_SET(gfeatures->features[block].never_changed, mask)) {
                        r = -EOPNOTSUPP;
                        continue;
                }

                /* The flags is explicitly set by set_features_bit() */
                if (FLAGS_SET(sfeatures->features[block].valid, mask))
                        continue;

                sfeatures->features[block].valid |= mask;
                SET_FLAG(sfeatures->features[block].requested, mask, flag);

                found = true;
        }

        return found ? 0 : r;
}

int ethtool_set_features(int *ethtool_fd, const char *ifname, const int features[static _NET_DEV_FEAT_MAX]) {
        _cleanup_free_ struct ethtool_gstrings *strings = NULL;
        _cleanup_free_ struct ethtool_gfeatures *gfeatures = NULL;
        _cleanup_free_ struct ethtool_sfeatures *sfeatures = NULL;
        struct ifreq ifr;
        bool have = false;
        int r;

        assert(ethtool_fd);
        assert(ifname);
        assert(features);

        for (size_t i = 0; i < _NET_DEV_FEAT_MAX; i++)
                if (features[i] >= 0) {
                        have = true;
                        break;
                }

        if (!have)
                return 0;

        r = ethtool_connect(ethtool_fd);
        if (r < 0)
                return r;

        r = get_stringset(*ethtool_fd, ifname, ETH_SS_FEATURES, &strings);
        if (r < 0)
                return log_debug_errno(r, "ethtool: could not get ethtool feature strings: %m");

        r = get_features(*ethtool_fd, ifname, strings->len, &gfeatures);
        if (r < 0)
                return log_debug_errno(r, "ethtool: could not get ethtool features for %s: %m", ifname);

        sfeatures = malloc0(offsetof(struct ethtool_sfeatures, features) +
                            DIV_ROUND_UP(strings->len, 32U) * sizeof(sfeatures->features[0]));
        if (!sfeatures)
                return log_oom_debug();

        sfeatures->cmd = ETHTOOL_SFEATURES;
        sfeatures->size = DIV_ROUND_UP(strings->len, 32U);

        for (size_t i = 0; i < _NET_DEV_FEAT_SIMPLE_MAX; i++) {
                r = set_features_bit(strings, gfeatures, sfeatures, netdev_feature_table[i], features[i]);
                if (r < 0)
                        log_debug_errno(r, "ethtool: could not set feature %s for %s, ignoring: %m", netdev_feature_table[i], ifname);
        }

        for (size_t i = _NET_DEV_FEAT_SIMPLE_MAX; i < _NET_DEV_FEAT_MAX; i++) {
                r = set_features_multiple_bit(strings, gfeatures, sfeatures, netdev_feature_table[i], features[i]);
                if (r < 0)
                        log_debug_errno(r, "ethtool: could not set feature %s for %s, ignoring: %m", netdev_feature_table[i], ifname);
        }

        ifr = (struct ifreq) {
                .ifr_data = (void*) sfeatures,
        };
        strscpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

        if (ioctl(*ethtool_fd, SIOCETHTOOL, &ifr) < 0)
                return log_debug_errno(errno, "ethtool: could not set ethtool features for %s", ifname);

        return 0;
}

static int get_glinksettings(int fd, struct ifreq *ifr, struct ethtool_link_usettings **ret) {
        struct ecmd {
                struct ethtool_link_settings req;
                uint32_t link_mode_data[3 * ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NU32];
        } ecmd = {
                .req.cmd = ETHTOOL_GLINKSETTINGS,
        };
        struct ethtool_link_usettings *u;
        unsigned offset;

        assert(fd >= 0);
        assert(ifr);
        assert(ret);

        /* The interaction user/kernel via the new API requires a small ETHTOOL_GLINKSETTINGS
           handshake first to agree on the length of the link mode bitmaps. If kernel doesn't
           agree with user, it returns the bitmap length it is expecting from user as a negative
           length (and cmd field is 0). When kernel and user agree, kernel returns valid info in
           all fields (ie. link mode length > 0 and cmd is ETHTOOL_GLINKSETTINGS). Based on
           https://github.com/torvalds/linux/commit/3f1ac7a700d039c61d8d8b99f28d605d489a60cf
        */

        ifr->ifr_data = (void *) &ecmd;

        if (ioctl(fd, SIOCETHTOOL, ifr) < 0)
                return -errno;

        if (ecmd.req.link_mode_masks_nwords >= 0 || ecmd.req.cmd != ETHTOOL_GLINKSETTINGS)
                return -EOPNOTSUPP;

        ecmd.req.link_mode_masks_nwords = -ecmd.req.link_mode_masks_nwords;

        ifr->ifr_data = (void *) &ecmd;

        if (ioctl(fd, SIOCETHTOOL, ifr) < 0)
                return -errno;

        if (ecmd.req.link_mode_masks_nwords <= 0 || ecmd.req.cmd != ETHTOOL_GLINKSETTINGS)
                return -EOPNOTSUPP;

        u = new(struct ethtool_link_usettings, 1);
        if (!u)
                return -ENOMEM;

        *u = (struct ethtool_link_usettings) {
                .base = ecmd.req,
        };

        offset = 0;
        memcpy(u->link_modes.supported, &ecmd.link_mode_data[offset], 4 * ecmd.req.link_mode_masks_nwords);

        offset += ecmd.req.link_mode_masks_nwords;
        memcpy(u->link_modes.advertising, &ecmd.link_mode_data[offset], 4 * ecmd.req.link_mode_masks_nwords);

        offset += ecmd.req.link_mode_masks_nwords;
        memcpy(u->link_modes.lp_advertising, &ecmd.link_mode_data[offset], 4 * ecmd.req.link_mode_masks_nwords);

        *ret = u;

        return 0;
}

static int get_gset(int fd, struct ifreq *ifr, struct ethtool_link_usettings **ret) {
        struct ethtool_link_usettings *e;
        struct ethtool_cmd ecmd = {
                .cmd = ETHTOOL_GSET,
        };

        assert(fd >= 0);
        assert(ifr);
        assert(ret);

        ifr->ifr_data = (void *) &ecmd;

        if (ioctl(fd, SIOCETHTOOL, ifr) < 0)
                return -errno;

        e = new(struct ethtool_link_usettings, 1);
        if (!e)
                return -ENOMEM;

        *e = (struct ethtool_link_usettings) {
                .base.cmd = ETHTOOL_GSET,
                .base.link_mode_masks_nwords = 1,
                .base.speed = ethtool_cmd_speed(&ecmd),
                .base.duplex = ecmd.duplex,
                .base.port = ecmd.port,
                .base.phy_address = ecmd.phy_address,
                .base.autoneg = ecmd.autoneg,
                .base.mdio_support = ecmd.mdio_support,
                .base.eth_tp_mdix = ecmd.eth_tp_mdix,
                .base.eth_tp_mdix_ctrl = ecmd.eth_tp_mdix_ctrl,

                .link_modes.supported[0] = ecmd.supported,
                .link_modes.advertising[0] = ecmd.advertising,
                .link_modes.lp_advertising[0] = ecmd.lp_advertising,
        };

        *ret = e;

        return 0;
}

static int set_slinksettings(int fd, struct ifreq *ifr, const struct ethtool_link_usettings *u) {
        struct {
                struct ethtool_link_settings req;
                uint32_t link_mode_data[3 * ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NU32];
        } ecmd = {};
        unsigned offset;

        assert(fd >= 0);
        assert(ifr);
        assert(u);

        if (u->base.cmd != ETHTOOL_GLINKSETTINGS || u->base.link_mode_masks_nwords <= 0)
                return -EINVAL;

        ecmd.req = u->base;
        ecmd.req.cmd = ETHTOOL_SLINKSETTINGS;
        offset = 0;
        memcpy(&ecmd.link_mode_data[offset], u->link_modes.supported, 4 * ecmd.req.link_mode_masks_nwords);

        offset += ecmd.req.link_mode_masks_nwords;
        memcpy(&ecmd.link_mode_data[offset], u->link_modes.advertising, 4 * ecmd.req.link_mode_masks_nwords);

        offset += ecmd.req.link_mode_masks_nwords;
        memcpy(&ecmd.link_mode_data[offset], u->link_modes.lp_advertising, 4 * ecmd.req.link_mode_masks_nwords);

        ifr->ifr_data = (void *) &ecmd;

        return RET_NERRNO(ioctl(fd, SIOCETHTOOL, ifr));
}

static int set_sset(int fd, struct ifreq *ifr, const struct ethtool_link_usettings *u) {
        struct ethtool_cmd ecmd = {
                .cmd = ETHTOOL_SSET,
        };

        assert(fd >= 0);
        assert(ifr);
        assert(u);

        if (u->base.cmd != ETHTOOL_GSET || u->base.link_mode_masks_nwords <= 0)
                return -EINVAL;

        ecmd.supported = u->link_modes.supported[0];
        ecmd.advertising = u->link_modes.advertising[0];
        ecmd.lp_advertising = u->link_modes.lp_advertising[0];

        ethtool_cmd_speed_set(&ecmd, u->base.speed);

        ecmd.duplex = u->base.duplex;
        ecmd.port = u->base.port;
        ecmd.phy_address = u->base.phy_address;
        ecmd.autoneg = u->base.autoneg;
        ecmd.mdio_support = u->base.mdio_support;
        ecmd.eth_tp_mdix = u->base.eth_tp_mdix;
        ecmd.eth_tp_mdix_ctrl = u->base.eth_tp_mdix_ctrl;

        ifr->ifr_data = (void *) &ecmd;

        return RET_NERRNO(ioctl(fd, SIOCETHTOOL, ifr));
}

int ethtool_set_glinksettings(
                int *fd,
                const char *ifname,
                int autonegotiation,
                const uint32_t advertise[static N_ADVERTISE],
                uint64_t speed,
                Duplex duplex,
                NetDevPort port,
                uint8_t mdi) {

        _cleanup_free_ struct ethtool_link_usettings *u = NULL;
        struct ifreq ifr = {};
        bool changed = false;
        int r;

        assert(fd);
        assert(ifname);
        assert(advertise);

        if (autonegotiation < 0 && memeqzero(advertise, sizeof(uint32_t) * N_ADVERTISE) &&
            speed == 0 && duplex < 0 && port < 0 && mdi == ETH_TP_MDI_INVALID)
                return 0;

        /* If autonegotiation is disabled, the speed and duplex represent the fixed link mode and are
         * writable if the driver supports multiple link modes. If it is enabled then they are
         * read-only. If the link is up they represent the negotiated link mode; if the link is down,
         * the speed is 0, %SPEED_UNKNOWN or the highest enabled speed and @duplex is %DUPLEX_UNKNOWN
         * or the best enabled duplex mode. */

        if (speed > 0 || duplex >= 0 || port >= 0) {
                if (autonegotiation == AUTONEG_ENABLE || !memeqzero(advertise, sizeof(uint32_t) * N_ADVERTISE)) {
                        log_debug("ethtool: autonegotiation is enabled, ignoring speed, duplex, or port settings.");
                        speed = 0;
                        duplex = _DUP_INVALID;
                        port = _NET_DEV_PORT_INVALID;
                } else {
                        log_debug("ethtool: setting speed, duplex, or port, disabling autonegotiation.");
                        autonegotiation = AUTONEG_DISABLE;
                }
        }

        r = ethtool_connect(fd);
        if (r < 0)
                return r;

        strscpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

        r = get_glinksettings(*fd, &ifr, &u);
        if (r < 0) {
                r = get_gset(*fd, &ifr, &u);
                if (r < 0)
                        return log_debug_errno(r, "ethtool: Cannot get device settings for %s: %m", ifname);
        }

        if (speed > 0)
                UPDATE(u->base.speed, DIV_ROUND_UP(speed, 1000000), changed);

        if (duplex >= 0)
                UPDATE(u->base.duplex, duplex, changed);

        if (port >= 0)
                UPDATE(u->base.port, port, changed);

        if (autonegotiation >= 0)
                UPDATE(u->base.autoneg, autonegotiation, changed);

        if (!memeqzero(advertise, sizeof(uint32_t) * N_ADVERTISE)) {
                UPDATE(u->base.autoneg, AUTONEG_ENABLE, changed);

                changed = changed ||
                        memcmp(&u->link_modes.advertising, advertise, sizeof(uint32_t) * N_ADVERTISE) != 0 ||
                        !memeqzero((uint8_t*) &u->link_modes.advertising + sizeof(uint32_t) * N_ADVERTISE,
                                   ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NBYTES - sizeof(uint32_t) * N_ADVERTISE);
                memcpy(&u->link_modes.advertising, advertise, sizeof(uint32_t) * N_ADVERTISE);
                memzero((uint8_t*) &u->link_modes.advertising + sizeof(uint32_t) * N_ADVERTISE,
                        ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NBYTES - sizeof(uint32_t) * N_ADVERTISE);
        }

        if (mdi != ETH_TP_MDI_INVALID) {
                if (u->base.eth_tp_mdix_ctrl == ETH_TP_MDI_INVALID)
                        log_debug("ethtool: setting MDI not supported for %s, ignoring.", ifname);
                else
                        UPDATE(u->base.eth_tp_mdix_ctrl, mdi, changed);
        }

        if (!changed)
                return 0;

        if (u->base.cmd == ETHTOOL_GLINKSETTINGS)
                r = set_slinksettings(*fd, &ifr, u);
        else
                r = set_sset(*fd, &ifr, u);
        if (r < 0)
                return log_debug_errno(r, "ethtool: Cannot set device settings for %s: %m", ifname);

        return r;
}

int ethtool_set_channels(int *fd, const char *ifname, const netdev_channels *channels) {
        struct ethtool_channels ecmd = {
                .cmd = ETHTOOL_GCHANNELS,
        };
        struct ifreq ifr = {
                .ifr_data = (void*) &ecmd,
        };
        bool need_update = false;
        int r;

        assert(fd);
        assert(ifname);
        assert(channels);

        if (!channels->rx.set &&
            !channels->tx.set &&
            !channels->other.set &&
            !channels->combined.set)
                return 0;

        r = ethtool_connect(fd);
        if (r < 0)
                return r;

        strscpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

        if (ioctl(*fd, SIOCETHTOOL, &ifr) < 0)
                return -errno;

        if (channels->rx.set)
                UPDATE_WITH_MAX(ecmd.rx_count, ecmd.max_rx, channels->rx.value, need_update);

        if (channels->tx.set)
                UPDATE_WITH_MAX(ecmd.tx_count, ecmd.max_tx, channels->tx.value, need_update);

        if (channels->other.set)
                UPDATE_WITH_MAX(ecmd.other_count, ecmd.max_other, channels->other.value, need_update);

        if (channels->combined.set)
                UPDATE_WITH_MAX(ecmd.combined_count, ecmd.max_combined, channels->combined.value, need_update);

        if (!need_update)
                return 0;

        ecmd.cmd = ETHTOOL_SCHANNELS;
        return RET_NERRNO(ioctl(*fd, SIOCETHTOOL, &ifr));
}

int ethtool_set_flow_control(int *fd, const char *ifname, int rx, int tx, int autoneg) {
        struct ethtool_pauseparam ecmd = {
                .cmd = ETHTOOL_GPAUSEPARAM,
        };
        struct ifreq ifr = {
                .ifr_data = (void*) &ecmd,
        };
        bool need_update = false;
        int r;

        assert(fd);
        assert(ifname);

        if (rx < 0 && tx < 0 && autoneg < 0)
                return 0;

        r = ethtool_connect(fd);
        if (r < 0)
                return r;

        strscpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

        if (ioctl(*fd, SIOCETHTOOL, &ifr) < 0)
                return -errno;

        if (rx >= 0)
                UPDATE(ecmd.rx_pause, (uint32_t) rx, need_update);

        if (tx >= 0)
                UPDATE(ecmd.tx_pause, (uint32_t) tx, need_update);

        if (autoneg >= 0)
                UPDATE(ecmd.autoneg, (uint32_t) autoneg, need_update);

        if (!need_update)
                return 0;

        ecmd.cmd = ETHTOOL_SPAUSEPARAM;
        return RET_NERRNO(ioctl(*fd, SIOCETHTOOL, &ifr));
}

int ethtool_set_nic_coalesce_settings(int *ethtool_fd, const char *ifname, const netdev_coalesce_param *coalesce) {
        struct ethtool_coalesce ecmd = {
                .cmd = ETHTOOL_GCOALESCE,
        };
        struct ifreq ifr = {
                .ifr_data = (void*) &ecmd,
        };
        bool need_update = false;
        int r;

        assert(ethtool_fd);
        assert(ifname);
        assert(coalesce);

        if (coalesce->use_adaptive_rx_coalesce < 0 &&
            coalesce->use_adaptive_tx_coalesce < 0 &&
            !coalesce->rx_coalesce_usecs.set &&
            !coalesce->rx_max_coalesced_frames.set &&
            !coalesce->rx_coalesce_usecs_irq.set &&
            !coalesce->rx_max_coalesced_frames_irq.set &&
            !coalesce->tx_coalesce_usecs.set &&
            !coalesce->tx_max_coalesced_frames.set &&
            !coalesce->tx_coalesce_usecs_irq.set &&
            !coalesce->tx_max_coalesced_frames_irq.set &&
            !coalesce->stats_block_coalesce_usecs.set &&
            !coalesce->pkt_rate_low.set &&
            !coalesce->rx_coalesce_usecs_low.set &&
            !coalesce->rx_max_coalesced_frames_low.set &&
            !coalesce->tx_coalesce_usecs_low.set &&
            !coalesce->tx_max_coalesced_frames_low.set &&
            !coalesce->pkt_rate_high.set &&
            !coalesce->rx_coalesce_usecs_high.set &&
            !coalesce->rx_max_coalesced_frames_high.set &&
            !coalesce->tx_coalesce_usecs_high.set &&
            !coalesce->tx_max_coalesced_frames_high.set &&
            !coalesce->rate_sample_interval.set)
                return 0;

        r = ethtool_connect(ethtool_fd);
        if (r < 0)
                return r;

        strscpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

        if (ioctl(*ethtool_fd, SIOCETHTOOL, &ifr) < 0)
                return -errno;

        if (coalesce->use_adaptive_rx_coalesce >= 0)
                UPDATE(ecmd.use_adaptive_rx_coalesce, (uint32_t) coalesce->use_adaptive_rx_coalesce, need_update);

        if (coalesce->use_adaptive_tx_coalesce >= 0)
                UPDATE(ecmd.use_adaptive_tx_coalesce, (uint32_t) coalesce->use_adaptive_tx_coalesce, need_update);

        if (coalesce->rx_coalesce_usecs.set)
                UPDATE(ecmd.rx_coalesce_usecs, coalesce->rx_coalesce_usecs.value, need_update);

        if (coalesce->rx_max_coalesced_frames.set)
                UPDATE(ecmd.rx_max_coalesced_frames, coalesce->rx_max_coalesced_frames.value, need_update);

        if (coalesce->rx_coalesce_usecs_irq.set)
                UPDATE(ecmd.rx_coalesce_usecs_irq, coalesce->rx_coalesce_usecs_irq.value, need_update);

        if (coalesce->rx_max_coalesced_frames_irq.set)
                UPDATE(ecmd.rx_max_coalesced_frames_irq, coalesce->rx_max_coalesced_frames_irq.value, need_update);

        if (coalesce->tx_coalesce_usecs.set)
                UPDATE(ecmd.tx_coalesce_usecs, coalesce->tx_coalesce_usecs.value, need_update);

        if (coalesce->tx_max_coalesced_frames.set)
                UPDATE(ecmd.tx_max_coalesced_frames, coalesce->tx_max_coalesced_frames.value, need_update);

        if (coalesce->tx_coalesce_usecs_irq.set)
                UPDATE(ecmd.tx_coalesce_usecs_irq, coalesce->tx_coalesce_usecs_irq.value, need_update);

        if (coalesce->tx_max_coalesced_frames_irq.set)
                UPDATE(ecmd.tx_max_coalesced_frames_irq, coalesce->tx_max_coalesced_frames_irq.value, need_update);

        if (coalesce->stats_block_coalesce_usecs.set)
                UPDATE(ecmd.stats_block_coalesce_usecs, coalesce->stats_block_coalesce_usecs.value, need_update);

        if (coalesce->pkt_rate_low.set)
                UPDATE(ecmd.pkt_rate_low, coalesce->pkt_rate_low.value, need_update);

        if (coalesce->rx_coalesce_usecs_low.set)
                UPDATE(ecmd.rx_coalesce_usecs_low, coalesce->rx_coalesce_usecs_low.value, need_update);

        if (coalesce->rx_max_coalesced_frames_low.set)
                UPDATE(ecmd.rx_max_coalesced_frames_low, coalesce->rx_max_coalesced_frames_low.value, need_update);

        if (coalesce->tx_coalesce_usecs_low.set)
                UPDATE(ecmd.tx_coalesce_usecs_low, coalesce->tx_coalesce_usecs_low.value, need_update);

        if (coalesce->tx_max_coalesced_frames_low.set)
                UPDATE(ecmd.tx_max_coalesced_frames_low, coalesce->tx_max_coalesced_frames_low.value, need_update);

        if (coalesce->pkt_rate_high.set)
                UPDATE(ecmd.pkt_rate_high, coalesce->pkt_rate_high.value, need_update);

        if (coalesce->rx_coalesce_usecs_high.set)
                UPDATE(ecmd.rx_coalesce_usecs_high, coalesce->rx_coalesce_usecs_high.value, need_update);

        if (coalesce->rx_max_coalesced_frames_high.set)
                UPDATE(ecmd.rx_max_coalesced_frames_high, coalesce->rx_max_coalesced_frames_high.value, need_update);

        if (coalesce->tx_coalesce_usecs_high.set)
                UPDATE(ecmd.tx_coalesce_usecs_high, coalesce->tx_coalesce_usecs_high.value, need_update);

        if (coalesce->tx_max_coalesced_frames_high.set)
                UPDATE(ecmd.tx_max_coalesced_frames_high, coalesce->tx_max_coalesced_frames_high.value, need_update);

        if (coalesce->rate_sample_interval.set)
                UPDATE(ecmd.rate_sample_interval, DIV_ROUND_UP(coalesce->rate_sample_interval.value, USEC_PER_SEC), need_update);

        if (!need_update)
                return 0;

        ecmd.cmd = ETHTOOL_SCOALESCE;
        return RET_NERRNO(ioctl(*ethtool_fd, SIOCETHTOOL, &ifr));
}

int config_parse_advertise(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint32_t *advertise = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty string resets the value. */
                memzero(advertise, sizeof(uint32_t) * N_ADVERTISE);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *w = NULL;
                enum ethtool_link_mode_bit_indices mode;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to split advertise modes '%s', ignoring assignment: %m", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                mode = ethtool_link_mode_bit_from_string(w);
                /* We reuse the kernel provided enum which does not contain negative value. So, the cast
                 * below is mandatory. Otherwise, the check below always passes and access an invalid address. */
                if ((int) mode < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, mode,
                                   "Failed to parse advertise mode, ignoring: %s", w);
                        continue;
                }

                advertise[mode / 32] |= 1UL << (mode % 32);
        }
}

int config_parse_mdi(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint8_t *mdi = ASSERT_PTR(data);

        assert(filename);
        assert(rvalue);

        if (isempty(rvalue)) {
                *mdi = ETH_TP_MDI_INVALID;
                return 0;
        }

        if (STR_IN_SET(rvalue, "mdi", "straight")) {
                *mdi = ETH_TP_MDI;
                return 0;
        }

        if (STR_IN_SET(rvalue, "mdi-x", "mdix", "crossover")) {
                *mdi = ETH_TP_MDI_X;
                return 0;
        }

        if (streq(rvalue, "auto")) {
                *mdi = ETH_TP_MDI_AUTO;
                return 0;
        }

        log_syntax(unit, LOG_WARNING, filename, line, 0,
                   "Failed to parse %s= setting, ignoring assignment: %s", lvalue, rvalue);
        return 0;
}

int config_parse_ring_buffer_or_channel(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        u32_opt *dst = ASSERT_PTR(data);
        uint32_t k;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                dst->value = 0;
                dst->set = false;
                return 0;
        }

        if (streq(rvalue, "max")) {
                dst->value = 0;
                dst->set = true;
                return 0;
        }

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }
        if (k < 1) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid %s= value, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        dst->value = k;
        dst->set = true;
        return 0;
}

int config_parse_wol(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint32_t new_opts = 0, *opts = data;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *opts = UINT32_MAX; /* Do not update WOL option. */
                return 0;
        }

        if (streq(rvalue, "off")) {
                *opts = 0; /* Disable WOL. */
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *w = NULL;
                bool found = false;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to split wake-on-lan modes '%s', ignoring assignment: %m", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                for (size_t i = 0; i < ELEMENTSOF(wol_option_map); i++)
                        if (streq(w, wol_option_map[i].name)) {
                                new_opts |= wol_option_map[i].opt;
                                found = true;
                                break;
                        }

                if (!found)
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Unknown wake-on-lan mode '%s', ignoring.", w);
        }

        if (*opts == UINT32_MAX)
                *opts = new_opts;
        else
                *opts |= new_opts;

        return 0;
}

int config_parse_coalesce_u32(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {
        u32_opt *dst = data;
        uint32_t k;
        int r;

        if (isempty(rvalue)) {
                dst->value = 0;
                dst->set = false;
                return 0;
        }

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        dst->value = k;
        dst->set = true;
        return 0;
}

int config_parse_coalesce_sec(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {
        u32_opt *dst = data;
        usec_t usec;
        int r;

        if (isempty(rvalue)) {
                dst->value = 0;
                dst->set = false;
                return 0;
        }

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse coalesce setting value, ignoring: %s", rvalue);
                return 0;
        }

        if (usec > UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Too large %s= value, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (STR_IN_SET(lvalue, "StatisticsBlockCoalesceSec", "CoalescePacketRateSampleIntervalSec") && usec < 1) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid %s= value, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        dst->value = (uint32_t) usec;
        dst->set = true;

        return 0;
}
