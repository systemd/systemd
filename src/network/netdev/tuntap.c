/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/if_tun.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "netdev/tuntap.h"
#include "user-util.h"

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

        if (t->multi_queue)
                ifr->ifr_flags |= IFF_MULTI_QUEUE;

        if (t->vnet_hdr)
                ifr->ifr_flags |= IFF_VNET_HDR;

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

        fd = open(TUN_DEV, O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return log_netdev_error_errno(netdev, -errno,  "Failed to open tun dev: %m");

        if (ioctl(fd, TUNSETIFF, ifr) < 0)
                return log_netdev_error_errno(netdev, -errno, "TUNSETIFF failed on tun dev: %m");

        if (netdev->kind == NETDEV_KIND_TAP)
                t = TAP(netdev);
        else
                t = TUN(netdev);

        assert(t);

        if (t->user_name) {
                user = t->user_name;

                r = get_user_creds(&user, &uid, NULL, NULL, NULL, USER_CREDS_ALLOW_MISSING);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Cannot resolve user name %s: %m", t->user_name);

                if (ioctl(fd, TUNSETOWNER, uid) < 0)
                        return log_netdev_error_errno(netdev, -errno, "TUNSETOWNER failed on tun dev: %m");
        }

        if (t->group_name) {
                group = t->group_name;

                r = get_group_creds(&group, &gid, USER_CREDS_ALLOW_MISSING);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Cannot resolve group name %s: %m", t->group_name);

                if (ioctl(fd, TUNSETGROUP, gid) < 0)
                        return log_netdev_error_errno(netdev, -errno, "TUNSETGROUP failed on tun dev: %m");

        }

        if (ioctl(fd, TUNSETPERSIST, 1) < 0)
                return log_netdev_error_errno(netdev, -errno, "TUNSETPERSIST failed on tun dev: %m");

        return 0;
}

static int netdev_create_tuntap(NetDev *netdev) {
        struct ifreq ifr = {};
        int r;

        r = netdev_fill_tuntap_message(netdev, &ifr);
        if (r < 0)
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

        t->user_name = mfree(t->user_name);
        t->group_name = mfree(t->group_name);
}

static int tuntap_verify(NetDev *netdev, const char *filename) {
        assert(netdev);

        if (netdev->mtu != 0)
                log_netdev_warning(netdev,
                                   "MTUBytes= configured for %s device in %s will be ignored.\n"
                                   "Please set it in the corresponding .network file.",
                                   netdev_kind_to_string(netdev->kind), filename);

        if (netdev->mac)
                log_netdev_warning(netdev,
                                   "MACAddress= configured for %s device in %s will be ignored.\n"
                                   "Please set it in the corresponding .network file.",
                                   netdev_kind_to_string(netdev->kind), filename);

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
