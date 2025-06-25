/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>

#include "alloc-util.h"
#include "daemon-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "networkd-manager.h"
#include "socket-util.h"
#include "string-util.h"
#include "tuntap.h"
#include "user-record.h"
#include "user-util.h"
#include "userdb.h"

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

        if (uid_is_valid(t->uid))
                if (ioctl(fd, TUNSETOWNER, t->uid) < 0)
                        return log_netdev_error_errno(netdev, errno, "TUNSETOWNER failed: %m");

        if (gid_is_valid(t->gid))
                if (ioctl(fd, TUNSETGROUP, t->gid) < 0)
                        return log_netdev_error_errno(netdev, errno, "TUNSETGROUP failed: %m");

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

static void tuntap_init(NetDev *netdev) {
        TunTap *t = TUNTAP(netdev);

        t->uid = UID_INVALID;
        t->gid = GID_INVALID;
}

static int tuntap_verify(NetDev *netdev, const char *filename) {
        TunTap *t = TUNTAP(netdev);
        int r;

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

        if (t->user_name) {
                _cleanup_(user_record_unrefp) UserRecord *ur = NULL;

                r = userdb_by_name(t->user_name, &USERDB_MATCH_ROOT_AND_SYSTEM,
                                   USERDB_SUPPRESS_SHADOW | USERDB_PARSE_NUMERIC,
                                   &ur);
                if (r == -ENOEXEC)
                        log_netdev_warning_errno(netdev, r, "User %s is not a system user, ignoring.", t->user_name);
                else if (r < 0)
                        log_netdev_warning_errno(netdev, r, "Cannot resolve user name %s, ignoring: %m", t->user_name);
                else
                        t->uid = ur->uid;
        }

        if (t->group_name) {
                _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;

                r = groupdb_by_name(t->group_name, &USERDB_MATCH_ROOT_AND_SYSTEM,
                                    USERDB_SUPPRESS_SHADOW | USERDB_PARSE_NUMERIC,
                                    &gr);
                if (r == -ENOEXEC)
                        log_netdev_warning_errno(netdev, r, "Group %s is not a system group, ignoring.", t->group_name);
                else if (r < 0)
                        log_netdev_warning_errno(netdev, r, "Cannot resolve group name %s, ignoring: %m", t->group_name);
                else
                        t->gid = gr->gid;
        }

        return 0;
}

const NetDevVTable tun_vtable = {
        .object_size = sizeof(TunTap),
        .sections = NETDEV_COMMON_SECTIONS "Tun\0",
        .init = tuntap_init,
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
        .init = tuntap_init,
        .config_verify = tuntap_verify,
        .drop = tuntap_drop,
        .done = tuntap_done,
        .create = netdev_create_tuntap,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .iftype = ARPHRD_ETHER,
};
