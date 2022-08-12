/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
#include "tuntap.h"
#include "user-util.h"

#define TUN_DEV "/dev/net/tun"

static TunTap* TUNTAP(NetDev *netdev) {
        assert(netdev);

        switch (netdev->kind) {
        case NETDEV_KIND_TAP:
                return TAP(netdev);
        case NETDEV_KIND_TUN:
                return TUN(netdev);
        default:
                return NULL;
        }
}

static int netdev_create_tuntap(NetDev *netdev) {
        _cleanup_close_ int fd = -1;
        struct ifreq ifr = {};
        TunTap *t;
        int r;

        assert(netdev);
        t = TUNTAP(netdev);
        assert(t);

        fd = open(TUN_DEV, O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return log_netdev_error_errno(netdev, errno,  "Failed to open " TUN_DEV ": %m");

        if (netdev->kind == NETDEV_KIND_TAP)
                ifr.ifr_flags |= IFF_TAP;
        else
                ifr.ifr_flags |= IFF_TUN;

        if (!t->packet_info)
                ifr.ifr_flags |= IFF_NO_PI;

        if (t->multi_queue)
                ifr.ifr_flags |= IFF_MULTI_QUEUE;

        if (t->vnet_hdr)
                ifr.ifr_flags |= IFF_VNET_HDR;

        strncpy(ifr.ifr_name, netdev->ifname, IFNAMSIZ-1);

        if (ioctl(fd, TUNSETIFF, &ifr) < 0)
                return log_netdev_error_errno(netdev, errno, "TUNSETIFF failed: %m");

        if (t->user_name) {
                const char *user = t->user_name;
                uid_t uid;

                r = get_user_creds(&user, &uid, NULL, NULL, NULL, USER_CREDS_ALLOW_MISSING);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Cannot resolve user name %s: %m", t->user_name);

                if (ioctl(fd, TUNSETOWNER, uid) < 0)
                        return log_netdev_error_errno(netdev, errno, "TUNSETOWNER failed: %m");
        }

        if (t->group_name) {
                const char *group = t->group_name;
                gid_t gid;

                r = get_group_creds(&group, &gid, USER_CREDS_ALLOW_MISSING);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Cannot resolve group name %s: %m", t->group_name);

                if (ioctl(fd, TUNSETGROUP, gid) < 0)
                        return log_netdev_error_errno(netdev, errno, "TUNSETGROUP failed: %m");

        }

        if (ioctl(fd, TUNSETPERSIST, 1) < 0)
                return log_netdev_error_errno(netdev, errno, "TUNSETPERSIST failed: %m");

        if (t->keep_fd)
                t->fd = TAKE_FD(fd);

        return 0;
}

static void tuntap_init(NetDev *netdev) {
        TunTap *t;

        assert(netdev);
        t = TUNTAP(netdev);
        assert(t);

        t->fd = -1;
}

static void tuntap_done(NetDev *netdev) {
        TunTap *t;

        assert(netdev);
        t = TUNTAP(netdev);
        assert(t);

        t->fd = safe_close(t->fd);
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

        if (netdev->hw_addr.length > 0)
                log_netdev_warning(netdev,
                                   "MACAddress= configured for %s device in %s will be ignored.\n"
                                   "Please set it in the corresponding .network file.",
                                   netdev_kind_to_string(netdev->kind), filename);

        return 0;
}

const NetDevVTable tun_vtable = {
        .object_size = sizeof(TunTap),
        .sections = NETDEV_COMMON_SECTIONS "Tun\0",
        .config_verify = tuntap_verify,
        .init = tuntap_init,
        .done = tuntap_done,
        .create = netdev_create_tuntap,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .iftype = ARPHRD_NONE,
};

const NetDevVTable tap_vtable = {
        .object_size = sizeof(TunTap),
        .sections = NETDEV_COMMON_SECTIONS "Tap\0",
        .config_verify = tuntap_verify,
        .init = tuntap_init,
        .done = tuntap_done,
        .create = netdev_create_tuntap,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .iftype = ARPHRD_ETHER,
};
