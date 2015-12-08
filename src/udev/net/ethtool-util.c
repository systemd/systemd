/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
