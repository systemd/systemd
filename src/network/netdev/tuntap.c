/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

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

DEFINE_PRIVATE_HASH_OPS_FULL(named_fd_hash_ops, char, string_hash_func, string_compare_func, free, void, close_fd_ptr);

static int manager_add_tuntap_fd_impl(Manager *m, int fd, const char *name) {
        _cleanup_free_ char *tuntap_name = NULL;
        int r;

        assert(m);
        assert(fd >= 0);
        assert(name);

        tuntap_name = strdup(name);
        if (!tuntap_name)
                return log_oom_debug();

        r = hashmap_ensure_put(&m->tuntap_fds_by_name, &named_fd_hash_ops, tuntap_name, FD_TO_PTR(fd));
        if (r < 0)
                return log_debug_errno(r, "Failed to store tuntap fd: %m");

        TAKE_PTR(tuntap_name);
        return 0;
}

int manager_add_tuntap_fd(Manager *m, int fd, const char *name) {
        const char *p;

        assert(m);
        assert(fd >= 0);
        assert(name);

        p = startswith(name, "tuntap-");
        if (!p)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Received unknown fd (%s).", name);

        if (!ifname_valid(p))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Received tuntap fd with invalid name (%s).", p);

        return manager_add_tuntap_fd_impl(m, fd, p);
}

static int netdev_take_tuntap_fd(Manager *m, const char *ifname) {
        _unused_ _cleanup_free_ char *name = NULL;
        void *p;

        assert(m);
        assert(ifname);

        p = hashmap_remove2(m->tuntap_fds_by_name, ifname, (void**) &name);
        if (!p)
                return -EBADF;

        return PTR_TO_FD(p);
}

static int netdev_push_tuntap_fd(NetDev *netdev, int fd) {
        _unused_ _cleanup_close_ int fd_old = -EBADF;
        int r;

        assert(netdev->manager);

        fd_old = netdev_take_tuntap_fd(netdev->manager, netdev->ifname);

        if (!TUNTAP(netdev)->keep_fd)
                return 0;

        r = manager_add_tuntap_fd_impl(netdev->manager, fd, netdev->ifname);
        if (r < 0)
                return r;

        (void) notify_push_fdf(fd, "tuntap-%s", netdev->ifname);
        return 1; /* saved */
}

static void manager_close_and_notify_tuntap_fd(Manager *m, const char *ifname) {
        assert(m);
        assert(ifname);

        /* netdev_take_tuntap_fd() may invalidate ifname. Hence, need to create fdname earlier. */
        const char *fdname = strjoina("tuntap-", ifname);
        close_and_notify_warn(netdev_take_tuntap_fd(m, ifname), fdname);
}

void manager_clear_unmanaged_tuntap_fds(Manager *m) {
        const char *name;
        void *p;

        assert(m);

        HASHMAP_FOREACH_KEY(p, name, m->tuntap_fds_by_name) {
                NetDev *netdev;

                if (netdev_get(m, name, &netdev) < 0 ||
                    !IN_SET(netdev->kind, NETDEV_KIND_TAP, NETDEV_KIND_TUN) ||
                    !TUNTAP(netdev)->keep_fd)
                        manager_close_and_notify_tuntap_fd(m, name);
        }
}

static int netdev_create_tuntap(NetDev *netdev) {
        _cleanup_close_ int fd = -EBADF;
        struct ifreq ifr = {};
        TunTap *t = TUNTAP(netdev);
        int r;

        assert(netdev->manager);

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

        r = netdev_push_tuntap_fd(netdev, fd);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to save TUN/TAP fd: %m");
        if (r > 0)
                TAKE_FD(fd);

        netdev_enter_ready(netdev);
        return 0;
}

static void tuntap_drop(NetDev *netdev) {
        assert(netdev);

        manager_close_and_notify_tuntap_fd(netdev->manager, netdev->ifname);
}

static void tuntap_done(NetDev *netdev) {
        TunTap *t = TUNTAP(netdev);

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
        .drop = tuntap_drop,
        .done = tuntap_done,
        .create = netdev_create_tuntap,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .iftype = ARPHRD_ETHER,
};
