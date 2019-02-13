/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <sys/mount.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/net_namespace.h>

#include "fd-util.h"
#include "mkdir.h"
#include "netns.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "path-util.h"

static int setup_netns(NetDev *netdev, char *ns_path) {
        _cleanup_close_ int netns = -1, fd = -1;
        int r;

        assert(netdev);
        assert(ns_path);

        if (unshare(CLONE_NEWNET) < 0)
                return -errno;

        netns = open("/proc/self/ns/net", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (netns < 0)
                return -errno;

        fd = open(ns_path, O_RDONLY|O_CLOEXEC|O_CREAT|O_EXCL, 0);
        if (fd < 0) {
                if (errno != EEXIST)
                        return -errno;

                return 0;
        }

        r = mount("/proc/self/ns/net", ns_path, NULL, MS_BIND, NULL);
        if (r < 0) {
                log_error_errno(errno, "Failed to bind /proc/self/ns/net: %m");
                return r;
        }

        return 0;
}

/* callback for moving netdev to namespace */
static int move_netdev_namespace_handler(sd_netlink *rtnl, sd_netlink_message *m, NetDev *netdev) {
        int r;

        assert(netdev);
        assert(netdev->state != _NETDEV_STATE_INVALID);

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_netdev_warning_errno(netdev, r, "Netdev could not be moved to namespace : %m");
                return 1;
        }

        log_netdev_debug(netdev, "Moved to namespace");

        return 1;
}

static int netdev_move_namespace(NetDev *netdev, char *ns_path) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        assert(netdev);
        assert(ns_path);

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &m, RTM_NEWLINK, netdev->ifindex);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to allocate generic netlink message: %m");

        r = sd_rtnl_message_link_set_nlmsg_flags(m, NLM_F_REQUEST);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to set netlink message flag: %m");

        fd = open(ns_path, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return log_netdev_error_errno(netdev, errno, "Failed open path: %m");

        r = sd_netlink_message_append_u32(m, IFLA_NET_NS_FD, fd);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_NET_NS_FD attribute: %m");

        r = netlink_call_async(netdev->manager->rtnl, NULL, m, move_netdev_namespace_handler, NULL, netdev);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to send netlink message for namespace: %m");

        netdev_ref(netdev);

        return 0;
}

int netdev_configure_namespace(NetDev *netdev) {
        _cleanup_free_ char *ns_path = NULL;
        int r;

        assert(netdev);

        ns_path = path_join(NETNS_RUN_DIR, netdev->netns);
        if (!ns_path)
                return log_oom();

        r = setup_netns(netdev, ns_path);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not setup namespace: %m");

        r = netdev_move_namespace(netdev, ns_path);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to move netdev to namespace: %m");

        return 0;
}
