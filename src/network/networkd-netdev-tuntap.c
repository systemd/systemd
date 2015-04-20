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

#include "networkd-netdev-tuntap.h"

#define TUN_DEV "/dev/net/tun"

static int netdev_fill_tuntap_message(NetDev *netdev, struct ifreq *ifr) {
        TunTap *t;

        assert(netdev);
        assert(netdev->ifname);
        assert(ifr);

        if (netdev->kind == NETDEV_KIND_TAP) {
                t = TAP(netdev);
                ifr->ifr_flags |= IFF_TAP;
        } else {
                t = TUN(netdev);
                ifr->ifr_flags |= IFF_TUN;
        }

        if (!t->packet_info)
                ifr->ifr_flags |= IFF_NO_PI;

        if (t->one_queue)
                ifr->ifr_flags |= IFF_ONE_QUEUE;

        if (t->multi_queue)
                ifr->ifr_flags |= IFF_MULTI_QUEUE;

        strncpy(ifr->ifr_name, netdev->ifname, IFNAMSIZ-1);

        return 0;
}

static int netdev_tuntap_add(NetDev *netdev, struct ifreq *ifr) {
        _cleanup_close_ int fd;
        TunTap *t = NULL;
        const char *user;
        const char *group;
        uid_t uid;
        gid_t gid;
        int r;

        assert(netdev);
        assert(ifr);

        fd = open(TUN_DEV, O_RDWR);
        if (fd < 0) {
                log_netdev_error(netdev, "Failed to open tun dev: %m");
                return -errno;
        }

        r = ioctl(fd, TUNSETIFF, ifr);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "TUNSETIFF failed on tun dev: %s",
                                 strerror(-r));
                return r;
        }

        if (netdev->kind == NETDEV_KIND_TAP)
                t = TAP(netdev);
        else
                t = TUN(netdev);

        assert(t);

        if(t->user_name) {

                user = t->user_name;

                r = get_user_creds(&user, &uid, NULL, NULL, NULL);
                if (r < 0) {
                        log_error_errno(r, "Cannot resolve user name %s: %m",
                                        t->user_name);
                        return 0;
                }

                r = ioctl(fd, TUNSETOWNER, uid);
                if ( r < 0) {
                        log_netdev_error(netdev,
                                         "TUNSETOWNER failed on tun dev: %s",
                                         strerror(-r));
                }
        }

        if (t->group_name) {

                group = t->group_name;

                r = get_group_creds(&group, &gid);
                if (r < 0) {
                        log_error_errno(r, "Cannot resolve group name %s: %m",
                                        t->group_name);
                        return 0;
                }

                r = ioctl(fd, TUNSETGROUP, gid);
                if( r < 0) {
                        log_netdev_error(netdev,
                                         "TUNSETGROUP failed on tun dev: %s",
                                         strerror(-r));
                        return r;
                }

        }

        r = ioctl(fd, TUNSETPERSIST, 1);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "TUNSETPERSIST failed on tun dev: %s",
                                 strerror(-r));
                return r;
        }

        return 0;
}

static int netdev_create_tuntap(NetDev *netdev) {
        struct ifreq ifr = {};
        int r;

        r = netdev_fill_tuntap_message(netdev, &ifr);
        if(r < 0)
                return r;

        return netdev_tuntap_add(netdev, &ifr);
}

static void tuntap_done(NetDev *netdev) {
        TunTap *t = NULL;

        assert(netdev);

        if (netdev->kind == NETDEV_KIND_TUN)
                t = TUN(netdev);
        else
                t = TAP(netdev);

        assert(t);

        free(t->user_name);
        t->user_name = NULL;

        free(t->group_name);
        t->group_name = NULL;
}

static int tuntap_verify(NetDev *netdev, const char *filename) {
        assert(netdev);

        if (netdev->mtu)
                log_netdev_warning(netdev, "MTU configured for %s, ignoring", netdev_kind_to_string(netdev->kind));

        if (netdev->mac)
                log_netdev_warning(netdev, "MAC configured for %s, ignoring", netdev_kind_to_string(netdev->kind));

        return 0;
}

const NetDevVTable tun_vtable = {
        .object_size = sizeof(TunTap),
        .sections = "Match\0NetDev\0Tun\0",
        .config_verify = tuntap_verify,
        .done = tuntap_done,
        .create = netdev_create_tuntap,
        .create_type = NETDEV_CREATE_INDEPENDENT,
};

const NetDevVTable tap_vtable = {
        .object_size = sizeof(TunTap),
        .sections = "Match\0NetDev\0Tap\0",
        .config_verify = tuntap_verify,
        .done = tuntap_done,
        .create = netdev_create_tuntap,
        .create_type = NETDEV_CREATE_INDEPENDENT,
};
