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
#include "daemon-util.h"
#include "fd-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "socket-util.h"
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

static void *close_fd_ptr(void *p) {
        safe_close(PTR_TO_FD(p));
        return NULL;
}

DEFINE_PRIVATE_HASH_OPS_FULL(named_fd_hash_ops, char, string_hash_func, string_compare_func, free, void, close_fd_ptr);

int manager_add_tuntap_fd(Manager *m, int fd, const char *name) {
        _cleanup_free_ char *tuntap_name = NULL;
        const char *p;
        int r;

        assert(m);
        assert(fd >= 0);
        assert(name);

        p = startswith(name, "tuntap-");
        if (!p)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Received unknown fd (%s).", name);

        if (!ifname_valid(p))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Received tuntap fd with invalid name (%s).", p);

        tuntap_name = strdup(p);
        if (!tuntap_name)
                return log_oom_debug();

        r = hashmap_ensure_put(&m->tuntap_fds_by_name, &named_fd_hash_ops, tuntap_name, FD_TO_PTR(fd));
        if (r < 0)
                return log_debug_errno(r, "Failed to store tuntap fd: %m");

        TAKE_PTR(tuntap_name);
        return 0;
}

void manager_clear_unmanaged_tuntap_fds(Manager *m) {
        char *name;
        void *p;

        assert(m);

        while ((p = hashmap_steal_first_key_and_value(m->tuntap_fds_by_name, (void**) &name))) {
                close_and_notify_warn(PTR_TO_FD(p), name);
                name = mfree(name);
        }
}

static int tuntap_take_fd(NetDev *netdev) {
        _cleanup_free_ char *name = NULL;
        void *p;
        int r;

        assert(netdev);
        assert(netdev->manager);

        r = link_get_by_name(netdev->manager, netdev->ifname, NULL);
        if (r < 0)
                return r;

        p = hashmap_remove2(netdev->manager->tuntap_fds_by_name, netdev->ifname, (void**) &name);
        if (!p)
                return -ENOENT;

        log_netdev_debug(netdev, "Found file descriptor in fd store.");
        return PTR_TO_FD(p);
}

static int netdev_create_tuntap(NetDev *netdev) {
        _cleanup_close_ int fd = -EBADF;
        struct ifreq ifr = {};
        TunTap *t;
        int r;

        assert(netdev);
        t = TUNTAP(netdev);
        assert(t);

        fd = TAKE_FD(t->fd);
        if (fd < 0)
                fd = tuntap_take_fd(netdev);
        if (fd < 0)
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

        if (t->multi_queue) {
                /* If we don't detach the queue, the kernel will send packets to our queue and they
                 * will be dropped because we never read them, which is especially important in case
                 * of KeepCarrier option which persists open FD. So detach our queue right after
                 * device create/attach to make kernel not send the packets to it. The option is
                 * available for multi-queue devices only.
                 *
                 * See https://github.com/systemd/systemd/pull/30504 for details. */
                struct ifreq detach_request = { .ifr_flags = IFF_DETACH_QUEUE };
                if (ioctl(fd, TUNSETQUEUE, &detach_request) < 0)
                        return log_netdev_error_errno(netdev, errno, "TUNSETQUEUE failed: %m");
        }

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

        if (t->keep_fd) {
                t->fd = TAKE_FD(fd);
                (void) notify_push_fdf(t->fd, "tuntap-%s", netdev->ifname);
        }

        return 0;
}

static void tuntap_init(NetDev *netdev) {
        TunTap *t;

        assert(netdev);
        t = TUNTAP(netdev);
        assert(t);

        t->fd = -EBADF;
}

static void tuntap_drop(NetDev *netdev) {
        TunTap *t;

        assert(netdev);
        t = TUNTAP(netdev);
        assert(t);

        t->fd = close_and_notify_warn(t->fd, netdev->ifname);
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
        .drop = tuntap_drop,
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
        .drop = tuntap_drop,
        .done = tuntap_done,
        .create = netdev_create_tuntap,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .iftype = ARPHRD_ETHER,
};
