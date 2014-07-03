/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
    This file is part of systemd.

    Copyright 2014 Susant Sahani <susant@redhat.com>

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
#include <linux/if_tun.h>

#include "networkd.h"

#define TUN_DEV "/dev/net/tun"


static int netdev_fill_tuntap_message(NetDev *netdev, struct ifreq *ifr) {

        assert(netdev);
        assert(ifr);

        memset(ifr, 0, sizeof(*ifr));

        if (netdev->kind == NETDEV_KIND_TAP)
                ifr->ifr_flags |= IFF_TAP;
        else
                ifr->ifr_flags |= IFF_TUN;

        if (!netdev->packet_info)
                ifr->ifr_flags |= IFF_NO_PI;

        if (netdev->one_queue)
                ifr->ifr_flags |= IFF_ONE_QUEUE;

        if (netdev->multi_queue)
                ifr->ifr_flags |= IFF_MULTI_QUEUE;

        strncpy(ifr->ifr_name, netdev->ifname, IFNAMSIZ-1);

        return 0;
}

static int netdev_tuntap_add(NetDev *netdev, struct ifreq *ifr) {
        _cleanup_close_ int fd;
        const char *user;
        const char *group;
        uid_t uid;
        gid_t gid;
        int r = 0;

        fd = open(TUN_DEV, O_RDWR);
        if (fd < 0) {
                log_error_netdev(netdev,
                                 "Failed to open tun dev: %s",
                                 strerror(-r));
                return r;
        }

        r = ioctl(fd, TUNSETIFF, ifr);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "TUNSETIFF failed on tun dev: %s",
                                 strerror(-r));
                return r;
        }

        if(netdev->user_name) {

                user = netdev->user_name;

                r = get_user_creds(&user, &uid, NULL, NULL, NULL);
                if (r < 0) {
                        log_error("Cannot resolve user name %s: %s",
                                  netdev->user_name, strerror(-r));
                        return 0;
                }

                r = ioctl(fd, TUNSETOWNER, uid);
                if ( r < 0) {
                        log_error_netdev(netdev,
                                         "TUNSETOWNER failed on tun dev: %s",
                                         strerror(-r));
                }
        }

        if(netdev->group_name) {

                group = netdev->group_name;

                r = get_group_creds(&group, &gid);
                if (r < 0) {
                        log_error("Cannot resolve group name %s: %s",
                                  netdev->group_name, strerror(-r));
                        return 0;
                }

                r = ioctl(fd, TUNSETGROUP, gid);
                if( r < 0) {
                        log_error_netdev(netdev,
                                         "TUNSETGROUP failed on tun dev: %s",
                                         strerror(-r));
                        return r;
                }

        }

        r = ioctl(fd, TUNSETPERSIST, 1);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "TUNSETPERSIST failed on tun dev: %s",
                                 strerror(-r));
                return r;
        }

        return r;
}

int netdev_create_tuntap(NetDev *netdev) {
        struct ifreq ifr;
        int r;

        assert(netdev);
        assert(netdev->ifname);

        switch(netdev->kind) {
        case NETDEV_KIND_TUN:
        case NETDEV_KIND_TAP:
                break;
        default:
                return -ENOTSUP;
        }

        r = netdev_fill_tuntap_message(netdev, &ifr);
        if(r < 0)
                return r;

        log_debug_netdev(netdev, "Creating tuntap netdev: %s",
                         netdev_kind_to_string(netdev->kind));

        return netdev_tuntap_add(netdev, &ifr);
}
