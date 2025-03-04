/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <linux/if.h>
#include <linux/nl80211.h>
#include <linux/veth.h>
#include <sys/file.h>
#include <sys/mount.h>

#include "sd-device.h"
#include "sd-id128.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "device-private.h"
#include "device-util.h"
#include "ether-addr-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "lock-util.h"
#include "missing_network.h"
#include "mkdir.h"
#include "mount-util.h"
#include "namespace-util.h"
#include "netif-naming-scheme.h"
#include "netif-util.h"
#include "netlink-util.h"
#include "nspawn-network.h"
#include "parse-util.h"
#include "process-util.h"
#include "siphash24.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "udev-util.h"

#define HOST_HASH_KEY SD_ID128_MAKE(1a,37,6f,c7,46,ec,45,0b,ad,a3,d5,31,06,60,5d,b1)
#define CONTAINER_HASH_KEY SD_ID128_MAKE(c3,c4,f9,19,b5,57,b2,1c,e6,cf,14,27,03,9c,ee,a2)
#define VETH_EXTRA_HOST_HASH_KEY SD_ID128_MAKE(48,c7,f6,b7,ea,9d,4c,9e,b7,28,d4,de,91,d5,bf,66)
#define VETH_EXTRA_CONTAINER_HASH_KEY SD_ID128_MAKE(af,50,17,61,ce,f9,4d,35,84,0d,2b,20,54,be,ce,59)
#define MACVLAN_HASH_KEY SD_ID128_MAKE(00,13,6d,bc,66,83,44,81,bb,0c,f9,51,1f,24,a6,6f)

static int remove_one_link(sd_netlink *rtnl, const char *name) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        if (isempty(name))
                return 0;

        r = sd_rtnl_message_new_link(rtnl, &m, RTM_DELLINK, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate netlink message: %m");

        r = sd_netlink_message_append_string(m, IFLA_IFNAME, name);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink interface name: %m");

        r = sd_netlink_call(rtnl, m, 0, NULL);
        if (r == -ENODEV) /* Already gone */
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to remove interface %s: %m", name);

        return 1;
}

static int set_alternative_ifname(sd_netlink *rtnl, const char *ifname, const char *altifname) {
        int r;

        assert(rtnl);
        assert(ifname);

        if (!altifname)
                return 0;

        if (strlen(altifname) >= ALTIFNAMSIZ)
                return log_warning_errno(SYNTHETIC_ERRNO(ERANGE),
                                         "Alternative interface name '%s' for '%s' is too long, ignoring",
                                         altifname, ifname);

        r = rtnl_set_link_alternative_names_by_ifname(&rtnl, ifname, STRV_MAKE(altifname));
        if (r < 0)
                return log_warning_errno(r,
                                         "Failed to set alternative interface name '%s' to '%s', ignoring: %m",
                                         altifname, ifname);

        return 0;
}

static int add_veth(
                sd_netlink *rtnl,
                pid_t pid,
                const char *ifname_host,
                const char *altifname_host,
                const struct ether_addr *mac_host,
                const char *ifname_container,
                const struct ether_addr *mac_container) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(rtnl);
        assert(ifname_host);
        assert(mac_host);
        assert(ifname_container);
        assert(mac_container);

        r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate netlink message: %m");

        r = sd_netlink_message_append_string(m, IFLA_IFNAME, ifname_host);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink interface name: %m");

        r = sd_netlink_message_append_ether_addr(m, IFLA_ADDRESS, mac_host);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink MAC address: %m");

        r = sd_netlink_message_open_container(m, IFLA_LINKINFO);
        if (r < 0)
                return log_error_errno(r, "Failed to open netlink container: %m");

        r = sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, "veth");
        if (r < 0)
                return log_error_errno(r, "Failed to open netlink container: %m");

        r = sd_netlink_message_open_container(m, VETH_INFO_PEER);
        if (r < 0)
                return log_error_errno(r, "Failed to open netlink container: %m");

        r = sd_netlink_message_append_string(m, IFLA_IFNAME, ifname_container);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink interface name: %m");

        r = sd_netlink_message_append_ether_addr(m, IFLA_ADDRESS, mac_container);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink MAC address: %m");

        r = sd_netlink_message_append_u32(m, IFLA_NET_NS_PID, pid);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink namespace field: %m");

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_error_errno(r, "Failed to close netlink container: %m");

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_error_errno(r, "Failed to close netlink container: %m");

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_error_errno(r, "Failed to close netlink container: %m");

        r = sd_netlink_call(rtnl, m, 0, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add new veth interfaces (%s:%s): %m", ifname_host, ifname_container);

        (void) set_alternative_ifname(rtnl, ifname_host, altifname_host);

        return 0;
}

int setup_veth(const char *machine_name,
               pid_t pid,
               char iface_name[IFNAMSIZ],
               bool bridge,
               const struct ether_addr *provided_mac) {

        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        struct ether_addr mac_host, mac_container;
        unsigned u;
        char *n, *a = NULL;
        int r;

        assert(machine_name);
        assert(pid > 0);
        assert(iface_name);

        /* Use two different interface name prefixes depending whether
         * we are in bridge mode or not. */
        n = strjoina(bridge ? "vb-" : "ve-", machine_name);
        r = net_shorten_ifname(n, /* check_naming_scheme= */ true);
        if (r > 0)
                a = strjoina(bridge ? "vb-" : "ve-", machine_name);

        if (ether_addr_is_null(provided_mac)){
                r = net_generate_mac(machine_name, &mac_container, CONTAINER_HASH_KEY, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate predictable MAC address for container side: %m");
        } else
                mac_container = *provided_mac;

        r = net_generate_mac(machine_name, &mac_host, HOST_HASH_KEY, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to generate predictable MAC address for host side: %m");

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        r = add_veth(rtnl, pid, n, a, &mac_host, "host0", &mac_container);
        if (r < 0)
                return r;

        u = if_nametoindex(n); /* We don't need to use rtnl_resolve_ifname() here because the
                                * name we assigned is always the main name. */
        if (u == 0)
                return log_error_errno(errno, "Failed to resolve interface %s: %m", n);

        strcpy(iface_name, n);
        return (int) u;
}

int setup_veth_extra(
                const char *machine_name,
                pid_t pid,
                char **pairs) {

        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        uint64_t idx = 0;
        int r;

        assert(machine_name);
        assert(pid > 0);

        if (strv_isempty(pairs))
                return 0;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        STRV_FOREACH_PAIR(a, b, pairs) {
                struct ether_addr mac_host, mac_container;

                r = net_generate_mac(machine_name, &mac_container, VETH_EXTRA_CONTAINER_HASH_KEY, idx);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate predictable MAC address for container side of extra veth link: %m");

                r = net_generate_mac(machine_name, &mac_host, VETH_EXTRA_HOST_HASH_KEY, idx);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate predictable MAC address for host side of extra veth link: %m");

                r = add_veth(rtnl, pid, *a, NULL, &mac_host, *b, &mac_container);
                if (r < 0)
                        return r;

                idx++;
        }

        return 0;
}

static int join_bridge(sd_netlink *rtnl, const char *veth_name, const char *bridge_name) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r, bridge_ifi;

        assert(rtnl);
        assert(veth_name);
        assert(bridge_name);

        bridge_ifi = rtnl_resolve_interface(&rtnl, bridge_name);
        if (bridge_ifi < 0)
                return bridge_ifi;

        r = sd_rtnl_message_new_link(rtnl, &m, RTM_SETLINK, 0);
        if (r < 0)
                return r;

        r = sd_rtnl_message_link_set_flags(m, IFF_UP, IFF_UP);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, IFLA_IFNAME, veth_name);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFLA_MASTER, bridge_ifi);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, m, 0, NULL);
        if (r < 0)
                return r;

        return bridge_ifi;
}

static int create_bridge(sd_netlink *rtnl, const char *bridge_name) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, IFLA_IFNAME, bridge_name);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, IFLA_LINKINFO);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, "bridge");
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, m, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

int setup_bridge(const char *veth_name, const char *bridge_name, bool create) {
        _cleanup_(release_lock_file) LockFile bridge_lock = LOCK_FILE_INIT;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int r, bridge_ifi;
        unsigned n = 0;

        assert(veth_name);
        assert(bridge_name);

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        if (create) {
                /* We take a system-wide lock here, so that we can safely check whether there's still a member in the
                 * bridge before removing it, without risking interference from other nspawn instances. */

                r = make_lock_file("/run/systemd/nspawn-network-zone", LOCK_EX, &bridge_lock);
                if (r < 0)
                        return log_error_errno(r, "Failed to take network zone lock: %m");
        }

        for (;;) {
                bridge_ifi = join_bridge(rtnl, veth_name, bridge_name);
                if (bridge_ifi >= 0)
                        return bridge_ifi;
                if (bridge_ifi != -ENODEV || !create || n > 10)
                        return log_error_errno(bridge_ifi, "Failed to add interface %s to bridge %s: %m", veth_name, bridge_name);

                /* Count attempts, so that we don't enter an endless loop here. */
                n++;

                /* The bridge doesn't exist yet. Let's create it */
                r = create_bridge(rtnl, bridge_name);
                if (r < 0)
                        return log_error_errno(r, "Failed to create bridge interface %s: %m", bridge_name);

                /* Try again, now that the bridge exists */
        }
}

int remove_bridge(const char *bridge_name) {
        _cleanup_(release_lock_file) LockFile bridge_lock = LOCK_FILE_INIT;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        const char *path;
        int r;

        /* Removes the specified bridge, but only if it is currently empty */

        if (isempty(bridge_name))
                return 0;

        r = make_lock_file("/run/systemd/nspawn-network-zone", LOCK_EX, &bridge_lock);
        if (r < 0)
                return log_error_errno(r, "Failed to take network zone lock: %m");

        path = strjoina("/sys/class/net/", bridge_name, "/brif");

        r = dir_is_empty(path, /* ignore_hidden_or_backup= */ false);
        if (r == -ENOENT) /* Already gone? */
                return 0;
        if (r < 0)
                return log_error_errno(r, "Can't detect if bridge %s is empty: %m", bridge_name);
        if (r == 0) /* Still populated, leave it around */
                return 0;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        return remove_one_link(rtnl, bridge_name);
}

static int test_network_interface_initialized(const char *name) {
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        int r;

        if (!udev_available())
                return 0;

        /* udev should be around. */

        r = sd_device_new_from_ifname(&d, name);
        if (r < 0)
                return log_error_errno(r, "Failed to get device %s: %m", name);

        r = device_is_processed(d);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether interface %s is initialized: %m", name);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Network interface %s is not initialized yet.", name);

        r = device_is_renaming(d);
        if (r < 0)
                return log_error_errno(r, "Failed to determine the interface %s is being renamed: %m", name);
        if (r > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Interface %s is being renamed.", name);

        return 0;
}

int test_network_interfaces_initialized(char **iface_pairs) {
        int r;
        STRV_FOREACH_PAIR(a, b, iface_pairs) {
                r = test_network_interface_initialized(*a);
                if (r < 0)
                        return r;
        }
        return 0;
}

int resolve_network_interface_names(char **iface_pairs) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int r;

        /* Due to a bug in kernel fixed by 8e15aee621618a3ee3abecaf1fd8c1428098b7ef (v6.6, backported to
         * 6.1.60 and 6.5.9), an interface with alternative names cannot be resolved by the alternative name
         * if the interface is moved to another network namespace. Hence, we need to adjust the provided
         * names before moving interfaces to container namespace. */

        STRV_FOREACH_PAIR(from, to, iface_pairs) {
                _cleanup_free_ char *name = NULL;
                _cleanup_strv_free_ char **altnames = NULL;

                r = rtnl_resolve_ifname_full(&rtnl, _RESOLVE_IFNAME_ALL, *from, &name, &altnames);
                if (r < 0)
                        return r;

                /* Always use the resolved name for 'from'. */
                free_and_replace(*from, name);

                /* If the name 'to' is assigned as an alternative name, we cannot rename the interface.
                 * Hence, use the assigned interface name (including the alternative names) as is, and
                 * use the resolved name for 'to'. */
                if (strv_contains(altnames, *to)) {
                        r = free_and_strdup_warn(to, *from);
                        if (r < 0)
                                return r;
                }
        }
        return 0;
}

static int netns_child_begin(int netns_fd, int *ret_original_netns_fd) {
        _cleanup_close_ int original_netns_fd = -EBADF;
        int r;

        assert(netns_fd >= 0);

        if (ret_original_netns_fd) {
                original_netns_fd = namespace_open_by_type(NAMESPACE_NET);
                if (original_netns_fd < 0)
                        return log_error_errno(original_netns_fd, "Failed to open original network namespace: %m");
        }

        r = namespace_enter(/* pidns_fd = */ -EBADF,
                            /* mntns_fd = */ -EBADF,
                            netns_fd,
                            /* userns_fd = */ -EBADF,
                            /* root_fd = */ -EBADF);
        if (r < 0)
                return log_error_errno(r, "Failed to enter child network namespace: %m");

        r = umount_recursive("/sys/", /* flags = */ 0);
        if (r < 0)
                log_debug_errno(r, "Failed to unmount directories below /sys/, ignoring: %m");

        (void) mkdir_p("/sys/", 0755);

        /* Populate new sysfs instance associated with the client netns, to make sd_device usable. */
        r = mount_nofollow_verbose(LOG_ERR, "sysfs", "/sys/", "sysfs",
                                   MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV, /* opts = */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to mount sysfs on /sys/: %m");

        /* udev_avaliable() might be called previously and the result may be cached.
         * Now, we (re-)mount sysfs. Hence, we need to reset the cache. */
        reset_cached_udev_availability();

        if (ret_original_netns_fd)
                *ret_original_netns_fd = TAKE_FD(original_netns_fd);

        return 0;
}

static int netns_fork_and_wait(int netns_fd, int *ret_original_netns_fd) {
        int r;

        assert(netns_fd >= 0);

        r = safe_fork("(sd-netns)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_WAIT|FORK_LOG|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to fork process (sd-netns): %m");
        if (r == 0) {
                if (netns_child_begin(netns_fd, ret_original_netns_fd) < 0)
                        _exit(EXIT_FAILURE);

                return 0;
        }

        if (ret_original_netns_fd)
                *ret_original_netns_fd = -EBADF;

        return 1;
}

static int move_wlan_interface_impl(sd_netlink **genl, int netns_fd, sd_device *dev) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *our_genl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(netns_fd >= 0);
        assert(dev);

        if (!genl)
                genl = &our_genl;
        if (!*genl) {
                r = sd_genl_socket_open(genl);
                if (r < 0)
                        return log_error_errno(r, "Failed to connect to generic netlink: %m");
        }

        r = sd_genl_message_new(*genl, NL80211_GENL_NAME, NL80211_CMD_SET_WIPHY_NETNS, &m);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to allocate netlink message: %m");

        uint32_t phy_index;
        r = device_get_sysattr_u32(dev, "phy80211/index", &phy_index);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get phy index: %m");

        r = sd_netlink_message_append_u32(m, NL80211_ATTR_WIPHY, phy_index);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to append phy index to netlink message: %m");

        r = sd_netlink_message_append_u32(m, NL80211_ATTR_NETNS_FD, netns_fd);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to append namespace fd to netlink message: %m");

        r = sd_netlink_call(*genl, m, 0, NULL);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to move interface to namespace: %m");

        return 0;
}

static int move_wlan_interface_one(
                        sd_netlink **rtnl,
                        sd_netlink **genl,
                        int *temp_netns_fd,
                        int netns_fd,
                        sd_device *dev,
                        const char *name) {

        int r;

        assert(rtnl);
        assert(genl);
        assert(temp_netns_fd);
        assert(netns_fd >= 0);
        assert(dev);

        if (!name)
                return move_wlan_interface_impl(genl, netns_fd, dev);

        /* The command NL80211_CMD_SET_WIPHY_NETNS takes phy instead of network interface, and does not take
         * an interface name in the passed network namespace. Hence, we need to move the phy and interface to
         * a temporary network namespace, rename the interface in it, and move them to the requested netns. */

        if (*temp_netns_fd < 0) {
                r = netns_acquire();
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire new network namespace: %m");
                *temp_netns_fd = r;
        }

        r = move_wlan_interface_impl(genl, *temp_netns_fd, dev);
        if (r < 0)
                return r;

        const char *sysname;
        r = sd_device_get_sysname(dev, &sysname);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get interface name: %m");

        r = netns_fork_and_wait(*temp_netns_fd, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to fork process (nspawn-rename-wlan): %m");
        if (r == 0) {
                _cleanup_(sd_device_unrefp) sd_device *temp_dev = NULL;

                r = rtnl_rename_link(NULL, sysname, name);
                if (r < 0) {
                        log_error_errno(r, "Failed to rename network interface '%s' to '%s': %m", sysname, name);
                        goto finalize;
                }

                r = sd_device_new_from_ifname(&temp_dev, name);
                if (r < 0) {
                        log_error_errno(r, "Failed to acquire device '%s': %m", name);
                        goto finalize;
                }

                r = move_wlan_interface_impl(NULL, netns_fd, temp_dev);

        finalize:
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        return 0;
}

static int move_network_interface_one(sd_netlink **rtnl, int netns_fd, sd_device *dev, const char *name) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(rtnl);
        assert(netns_fd >= 0);
        assert(dev);

        if (!*rtnl) {
                r = sd_netlink_open(rtnl);
                if (r < 0)
                        return log_error_errno(r, "Failed to connect to rtnetlink: %m");
        }

        int ifindex;
        r = sd_device_get_ifindex(dev, &ifindex);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get ifindex: %m");

        r = sd_rtnl_message_new_link(*rtnl, &m, RTM_SETLINK, ifindex);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to allocate netlink message: %m");

        r = sd_netlink_message_append_u32(m, IFLA_NET_NS_FD, netns_fd);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to append namespace fd to netlink message: %m");

        if (name) {
                r = sd_netlink_message_append_string(m, IFLA_IFNAME, name);
                if (r < 0)
                        return log_device_error_errno(dev, r, "Failed to add netlink interface name: %m");
        }

        r = sd_netlink_call(*rtnl, m, 0, NULL);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to move interface to namespace: %m");

        return 0;
}

int move_network_interfaces(int netns_fd, char **iface_pairs) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL, *genl = NULL;
        _cleanup_close_ int temp_netns_fd = -EBADF;
        int r;

        assert(netns_fd >= 0);

        if (strv_isempty(iface_pairs))
                return 0;

        STRV_FOREACH_PAIR(from, to, iface_pairs) {
                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                const char *name;

                name = streq(*from, *to) ? NULL : *to;

                r = sd_device_new_from_ifname(&dev, *from);
                if (r < 0)
                        return log_error_errno(r, "Unknown interface name %s: %m", *from);

                if (device_is_devtype(dev, "wlan"))
                        r = move_wlan_interface_one(&rtnl, &genl, &temp_netns_fd, netns_fd, dev, name);
                else
                        r = move_network_interface_one(&rtnl, netns_fd, dev, name);
                if (r < 0)
                        return r;
        }

        return 0;
}

int move_back_network_interfaces(int child_netns_fd, char **interface_pairs) {
        _cleanup_close_ int parent_netns_fd = -EBADF;
        int r;

        assert(child_netns_fd >= 0);

        if (strv_isempty(interface_pairs))
                return 0;

        r = netns_fork_and_wait(child_netns_fd, &parent_netns_fd);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Reverse network interfaces pair list so that interfaces get their initial name back.
                 * This is about ensuring interfaces get their old name back when being moved back. */
                interface_pairs = strv_reverse(interface_pairs);

                r = move_network_interfaces(parent_netns_fd, interface_pairs);
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        return 0;
}

int setup_macvlan(const char *machine_name, pid_t pid, char **iface_pairs) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        unsigned idx = 0;
        int r;

        if (strv_isempty(iface_pairs))
                return 0;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        STRV_FOREACH_PAIR(i, b, iface_pairs) {
                _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
                _cleanup_free_ char *n = NULL;
                int shortened, ifi;
                struct ether_addr mac;

                ifi = rtnl_resolve_interface_or_warn(&rtnl, *i);
                if (ifi < 0)
                        return ifi;

                r = net_generate_mac(machine_name, &mac, MACVLAN_HASH_KEY, idx++);
                if (r < 0)
                        return log_error_errno(r, "Failed to create MACVLAN MAC address: %m");

                r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate netlink message: %m");

                r = sd_netlink_message_append_u32(m, IFLA_LINK, ifi);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink interface index: %m");

                n = strdup(*b);
                if (!n)
                        return log_oom();

                shortened = net_shorten_ifname(n, /* check_naming_scheme= */ true);

                r = sd_netlink_message_append_string(m, IFLA_IFNAME, n);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink interface name: %m");

                r = sd_netlink_message_append_ether_addr(m, IFLA_ADDRESS, &mac);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink MAC address: %m");

                r = sd_netlink_message_append_u32(m, IFLA_NET_NS_PID, pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink namespace field: %m");

                r = sd_netlink_message_open_container(m, IFLA_LINKINFO);
                if (r < 0)
                        return log_error_errno(r, "Failed to open netlink container: %m");

                r = sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, "macvlan");
                if (r < 0)
                        return log_error_errno(r, "Failed to open netlink container: %m");

                r = sd_netlink_message_append_u32(m, IFLA_MACVLAN_MODE, MACVLAN_MODE_BRIDGE);
                if (r < 0)
                        return log_error_errno(r, "Failed to append macvlan mode: %m");

                r = sd_netlink_message_close_container(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to close netlink container: %m");

                r = sd_netlink_message_close_container(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to close netlink container: %m");

                r = sd_netlink_call(rtnl, m, 0, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to add new macvlan interfaces: %m");

                if (shortened > 0)
                        (void) set_alternative_ifname(rtnl, n, *b);
        }

        return 0;
}

static int remove_macvlan_impl(char **interface_pairs) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int r;

        assert(interface_pairs);

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        STRV_FOREACH_PAIR(a, b, interface_pairs) {
                _cleanup_free_ char *n = NULL;

                n = strdup(*b);
                if (!n)
                        return log_oom();

                (void) net_shorten_ifname(n, /* check_naming_scheme= */ true);

                r = remove_one_link(rtnl, n);
                if (r < 0)
                        log_warning_errno(r, "Failed to remove macvlan interface %s, ignoring: %m", n);
        }

        return 0;
}

int remove_macvlan(int child_netns_fd, char **interface_pairs) {
        _cleanup_close_ int parent_netns_fd = -EBADF;
        int r;

        /* In some cases the kernel might pin the macvlan links on the container even after the namespace
         * died. Hence, let's better remove them explicitly too. See issue #680. */

        assert(child_netns_fd >= 0);

        if (strv_isempty(interface_pairs))
                return 0;

        r = netns_fork_and_wait(child_netns_fd, &parent_netns_fd);
        if (r < 0)
                return r;
        if (r == 0) {
                r = remove_macvlan_impl(interface_pairs);
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        return 0;
}

int setup_ipvlan(const char *machine_name, pid_t pid, char **iface_pairs) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int r;

        if (strv_isempty(iface_pairs))
                return 0;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        STRV_FOREACH_PAIR(i, b, iface_pairs) {
                _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
                _cleanup_free_ char *n = NULL;
                int shortened, ifi ;

                ifi = rtnl_resolve_interface_or_warn(&rtnl, *i);
                if (ifi < 0)
                        return ifi;

                r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate netlink message: %m");

                r = sd_netlink_message_append_u32(m, IFLA_LINK, ifi);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink interface index: %m");

                n = strdup(*b);
                if (!n)
                        return log_oom();

                shortened = net_shorten_ifname(n, /* check_naming_scheme= */ true);

                r = sd_netlink_message_append_string(m, IFLA_IFNAME, n);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink interface name: %m");

                r = sd_netlink_message_append_u32(m, IFLA_NET_NS_PID, pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink namespace field: %m");

                r = sd_netlink_message_open_container(m, IFLA_LINKINFO);
                if (r < 0)
                        return log_error_errno(r, "Failed to open netlink container: %m");

                r = sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, "ipvlan");
                if (r < 0)
                        return log_error_errno(r, "Failed to open netlink container: %m");

                r = sd_netlink_message_append_u16(m, IFLA_IPVLAN_MODE, IPVLAN_MODE_L2);
                if (r < 0)
                        return log_error_errno(r, "Failed to add ipvlan mode: %m");

                r = sd_netlink_message_close_container(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to close netlink container: %m");

                r = sd_netlink_message_close_container(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to close netlink container: %m");

                r = sd_netlink_call(rtnl, m, 0, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to add new ipvlan interfaces: %m");

                if (shortened > 0)
                        (void) set_alternative_ifname(rtnl, n, *b);
        }

        return 0;
}

int veth_extra_parse(char ***l, const char *p) {
        _cleanup_free_ char *a = NULL, *b = NULL;
        int r;

        r = extract_first_word(&p, &a, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0 || !ifname_valid(a))
                return -EINVAL;

        r = extract_first_word(&p, &b, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0 || !ifname_valid(b)) {
                r = free_and_strdup(&b, a);
                if (r < 0)
                        return r;
        }

        if (p)
                return -EINVAL;

        r = strv_push_pair(l, a, b);
        if (r < 0)
                return -ENOMEM;

        a = b = NULL;
        return 0;
}

int remove_veth_links(const char *primary, char **pairs) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int r;

        /* In some cases the kernel might pin the veth links between host and container even after the namespace
         * died. Hence, let's better remove them explicitly too. */

        if (isempty(primary) && strv_isempty(pairs))
                return 0;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        remove_one_link(rtnl, primary);

        STRV_FOREACH_PAIR(a, b, pairs)
                remove_one_link(rtnl, *a);

        return 0;
}

static int network_iface_pair_parse(const char* iftype, char ***l, const char *p, const char* ifprefix) {
        int r;

        for (;;) {
                _cleanup_free_ char *word = NULL, *a = NULL, *b = NULL;
                const char *interface;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse interface name: %m");
                if (r == 0)
                        break;

                interface = word;
                r = extract_first_word(&interface, &a, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract first word in %s parameter: %m", iftype);
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Short read while reading %s parameter: %m", iftype);
                if (!ifname_valid(a))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "%s, interface name not valid: %s", iftype, a);

                /* Here, we only check the validity of the specified second name. If it is not specified,
                 * the copied or prefixed name should be already valid, except for its length. If it is too
                 * long, then it will be shortened later. */
                if (!isempty(interface)) {
                        if (!ifname_valid(interface))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "%s, interface name not valid: %s", iftype, interface);

                        b = strdup(interface);
                } else if (ifprefix)
                        b = strjoin(ifprefix, a);
                else
                        b = strdup(a);
                if (!b)
                        return log_oom();

                r = strv_consume_pair(l, TAKE_PTR(a), TAKE_PTR(b));
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

int interface_pair_parse(char ***l, const char *p) {
        return network_iface_pair_parse("Network interface", l, p, NULL);
}

int macvlan_pair_parse(char ***l, const char *p) {
        return network_iface_pair_parse("MACVLAN network interface", l, p, "mv-");
}

int ipvlan_pair_parse(char ***l, const char *p) {
        return network_iface_pair_parse("IPVLAN network interface", l, p, "iv-");
}
