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

#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include "ethtool-util.h"

#include "strxcpyx.h"
#include "util.h"
#include "log.h"

int ethtool_connect(int *ret) {
        int fd;

        assert_return(ret, -EINVAL);

        fd = socket(PF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
                return -errno;
        }

        *ret = fd;

        return 0;
}

int ethtool_set_speed(int fd, const char *ifname, const unsigned int speed, const char *duplex)
{
        struct ifreq ifr;
        struct ethtool_cmd ecmd;
        bool need_update;
        int r;

        if (speed == 0 && !duplex)
                return 0;

        memset(&ecmd, 0x00, sizeof(struct ethtool_cmd));
        ecmd.cmd = ETHTOOL_GSET;
        memset(&ifr, 0x00, sizeof(struct ifreq));
        strscpy(ifr.ifr_name, IFNAMSIZ, ifname);
        ifr.ifr_data = (void *)&ecmd;

        r = ioctl(fd, SIOCETHTOOL, &ifr);
        if (r < 0)
                return -errno;

        if (ethtool_cmd_speed(&ecmd) != speed) {
                ethtool_cmd_speed_set(&ecmd, speed);
                need_update = true;
        }

        if (duplex) {
                if (streq(duplex, "half")) {
                        if (ecmd.duplex != DUPLEX_HALF) {
                                ecmd.duplex = DUPLEX_HALF;
                                need_update = true;
                        }
                } else if (streq(duplex, "full"))
                        if (ecmd.duplex != DUPLEX_FULL) {
                                ecmd.duplex = DUPLEX_FULL;
                                need_update = true;
                        }
        }

        if (need_update) {
                ecmd.cmd = ETHTOOL_SSET;

                r = ioctl(fd, SIOCETHTOOL, &ifr);
                if (r < 0)
                        return -errno;
        }

        return 0;
}

int ethtool_set_wol(int fd, const char *ifname, const char *wol) {
        struct ifreq ifr;
        struct ethtool_wolinfo ecmd;
        bool need_update;
        int r;

        if (!wol)
                return 0;

        memset(&ecmd, 0x00, sizeof(struct ethtool_wolinfo));
        ecmd.cmd = ETHTOOL_GWOL;
        memset(&ifr, 0x00, sizeof(struct ifreq));
        strscpy(ifr.ifr_name, IFNAMSIZ, ifname);
        ifr.ifr_data = (void *)&ecmd;

        r = ioctl(fd, SIOCETHTOOL, &ifr);
        if (r < 0)
                return -errno;

        if (streq(wol, "phy")) {
                if (ecmd.wolopts != WAKE_PHY) {
                        ecmd.wolopts = WAKE_PHY;
                        need_update = true;
                }
        } else if (streq(wol, "magic")) {
                if (ecmd.wolopts != WAKE_MAGIC) {
                        ecmd.wolopts = WAKE_MAGIC;
                        need_update = true;
                }
        } else if (streq(wol, "off")) {
                if (ecmd.wolopts != 0) {
                        ecmd.wolopts = 0;
                        need_update = true;
                }
        } else
                return -EINVAL;

        if (need_update) {
                ecmd.cmd = ETHTOOL_SWOL;

                r = ioctl(fd, SIOCETHTOOL, &ifr);
                if (r < 0)
                        return -errno;
        }

        return 0;
}
