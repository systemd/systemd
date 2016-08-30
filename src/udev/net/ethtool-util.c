/***
 This file is part of systemd.

 Copyright (C) 2013 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include "conf-parser.h"
#include "ethtool-util.h"
#include "log.h"
#include "string-table.h"
#include "strxcpyx.h"
#include "util.h"

static const char* const duplex_table[_DUP_MAX] = {
        [DUP_FULL] = "full",
        [DUP_HALF] = "half"
};

DEFINE_STRING_TABLE_LOOKUP(duplex, Duplex);
DEFINE_CONFIG_PARSE_ENUM(config_parse_duplex, duplex, Duplex, "Failed to parse duplex setting");

static const char* const wol_table[_WOL_MAX] = {
        [WOL_PHY] = "phy",
        [WOL_MAGIC] = "magic",
        [WOL_OFF] = "off"
};

DEFINE_STRING_TABLE_LOOKUP(wol, WakeOnLan);
DEFINE_CONFIG_PARSE_ENUM(config_parse_wol, wol, WakeOnLan, "Failed to parse WakeOnLan setting");

static const char* const netdev_feature_table[_NET_DEV_FEAT_MAX] = {
        [NET_DEV_FEAT_GSO] = "tx-generic-segmentation",
        [NET_DEV_FEAT_TSO] = "tx-tcp-segmentation",
        [NET_DEV_FEAT_UFO] = "tx-udp-fragmentation",
};

int ethtool_connect(int *ret) {
        int fd;

        assert_return(ret, -EINVAL);

        fd = socket(PF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
                return -errno;

        *ret = fd;

        return 0;
}

int ethtool_get_driver(int *fd, const char *ifname, char **ret) {
        struct ethtool_drvinfo ecmd = {
                .cmd = ETHTOOL_GDRVINFO
        };
        struct ifreq ifr = {
                .ifr_data = (void*) &ecmd
        };
        char *d;
        int r;

        if (*fd < 0) {
                r = ethtool_connect(fd);
                if (r < 0)
                        return log_warning_errno(r, "link_config: could not connect to ethtool: %m");
        }

        strscpy(ifr.ifr_name, IFNAMSIZ, ifname);

        r = ioctl(*fd, SIOCETHTOOL, &ifr);
        if (r < 0)
                return -errno;

        d = strdup(ecmd.driver);
        if (!d)
                return -ENOMEM;

        *ret = d;
        return 0;
}

int ethtool_set_speed(int *fd, const char *ifname, unsigned int speed, Duplex duplex) {
        struct ethtool_cmd ecmd = {
                .cmd = ETHTOOL_GSET
        };
        struct ifreq ifr = {
                .ifr_data = (void*) &ecmd
        };
        bool need_update = false;
        int r;

        if (speed == 0 && duplex == _DUP_INVALID)
                return 0;

        if (*fd < 0) {
                r = ethtool_connect(fd);
                if (r < 0)
                        return log_warning_errno(r, "link_config: could not connect to ethtool: %m");
        }

        strscpy(ifr.ifr_name, IFNAMSIZ, ifname);

        r = ioctl(*fd, SIOCETHTOOL, &ifr);
        if (r < 0)
                return -errno;

        if (ethtool_cmd_speed(&ecmd) != speed) {
                ethtool_cmd_speed_set(&ecmd, speed);
                need_update = true;
        }

        switch (duplex) {
                case DUP_HALF:
                        if (ecmd.duplex != DUPLEX_HALF) {
                                ecmd.duplex = DUPLEX_HALF;
                                need_update = true;
                        }
                        break;
                case DUP_FULL:
                        if (ecmd.duplex != DUPLEX_FULL) {
                                ecmd.duplex = DUPLEX_FULL;
                                need_update = true;
                        }
                        break;
                default:
                        break;
        }

        if (need_update) {
                ecmd.cmd = ETHTOOL_SSET;

                r = ioctl(*fd, SIOCETHTOOL, &ifr);
                if (r < 0)
                        return -errno;
        }

        return 0;
}

int ethtool_set_wol(int *fd, const char *ifname, WakeOnLan wol) {
        struct ethtool_wolinfo ecmd = {
                .cmd = ETHTOOL_GWOL
        };
        struct ifreq ifr = {
                .ifr_data = (void*) &ecmd
        };
        bool need_update = false;
        int r;

        if (wol == _WOL_INVALID)
                return 0;

        if (*fd < 0) {
                r = ethtool_connect(fd);
                if (r < 0)
                        return log_warning_errno(r, "link_config: could not connect to ethtool: %m");
        }

        strscpy(ifr.ifr_name, IFNAMSIZ, ifname);

        r = ioctl(*fd, SIOCETHTOOL, &ifr);
        if (r < 0)
                return -errno;

        switch (wol) {
                case WOL_PHY:
                        if (ecmd.wolopts != WAKE_PHY) {
                                ecmd.wolopts = WAKE_PHY;
                                need_update = true;
                        }
                        break;
                case WOL_MAGIC:
                        if (ecmd.wolopts != WAKE_MAGIC) {
                                ecmd.wolopts = WAKE_MAGIC;
                                need_update = true;
                        }
                        break;
                case WOL_OFF:
                        if (ecmd.wolopts != 0) {
                                ecmd.wolopts = 0;
                                need_update = true;
                        }
                        break;
                default:
                        break;
        }

        if (need_update) {
                ecmd.cmd = ETHTOOL_SWOL;

                r = ioctl(*fd, SIOCETHTOOL, &ifr);
                if (r < 0)
                        return -errno;
        }

        return 0;
}

static int ethtool_get_stringset(int *fd, struct ifreq *ifr, int stringset_id, struct ethtool_gstrings **gstrings) {
        _cleanup_free_ struct ethtool_gstrings *strings = NULL;
        struct ethtool_sset_info info =  {
                .cmd = ETHTOOL_GSSET_INFO,
                .reserved = 0,
                .sset_mask = 1ULL << stringset_id,
        };
        unsigned len;
        int r;

        ifr->ifr_data = (void *) &info;

        r = ioctl(*fd, SIOCETHTOOL, ifr);
        if (r < 0)
                return -errno;

        if (!info.sset_mask)
                return -EINVAL;

        len = info.data[0];

        strings = malloc0(sizeof(struct ethtool_gstrings) + len * ETH_GSTRING_LEN);
        if (!strings)
                return -ENOMEM;

        strings->cmd = ETHTOOL_GSTRINGS;
        strings->string_set = stringset_id;
        strings->len = len;

        ifr->ifr_data = (void *) strings;

        r = ioctl(*fd, SIOCETHTOOL, ifr);
        if (r < 0)
                return -errno;

        *gstrings = strings;
        strings = NULL;

        return 0;
}

static int find_feature_index(struct ethtool_gstrings *strings, const char *feature) {
        unsigned i;

        for (i = 0; i < strings->len; i++) {
                if (streq((char *) &strings->data[i * ETH_GSTRING_LEN], feature))
                        return i;
        }

        return -1;
}

int ethtool_set_features(int *fd, const char *ifname, NetDevFeature *features) {
        _cleanup_free_ struct ethtool_gstrings *strings = NULL;
        struct ethtool_sfeatures *sfeatures;
        int block, bit, i, r;
        struct ifreq ifr;

        if (*fd < 0) {
                r = ethtool_connect(fd);
                if (r < 0)
                        return log_warning_errno(r, "link_config: could not connect to ethtool: %m");
        }

        strscpy(ifr.ifr_name, IFNAMSIZ, ifname);

        r = ethtool_get_stringset(fd, &ifr, ETH_SS_FEATURES, &strings);
        if (r < 0)
                return log_warning_errno(r, "link_config: could not get ethtool features for %s", ifname);

        sfeatures = alloca0(sizeof(struct ethtool_gstrings) + DIV_ROUND_UP(strings->len, 32U) * sizeof(sfeatures->features[0]));
        sfeatures->cmd = ETHTOOL_SFEATURES;
        sfeatures->size = DIV_ROUND_UP(strings->len, 32U);

        for (i = 0; i < _NET_DEV_FEAT_MAX; i++) {

                if (features[i] != -1) {

                        r = find_feature_index(strings, netdev_feature_table[i]);
                        if (r < 0) {
                                log_warning_errno(r, "link_config: could not find feature: %s", netdev_feature_table[i]);
                                continue;
                        }

                        block = r / 32;
                        bit = r % 32;

                        sfeatures->features[block].valid |= 1 << bit;

                        if (features[i])
                                sfeatures->features[block].requested |= 1 << bit;
                        else
                                sfeatures->features[block].requested &= ~(1 << bit);
                }
        }

        ifr.ifr_data = (void *) sfeatures;

        r = ioctl(*fd, SIOCETHTOOL, &ifr);
        if (r < 0)
                return log_warning_errno(r, "link_config: could not set ethtool features for %s", ifname);

        return 0;
}
