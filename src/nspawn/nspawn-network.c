/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include <linux/veth.h>
#include <net/if.h>

#include "sd-id128.h"
#include "sd-netlink.h"
#include "libudev.h"

#include "util.h"
#include "ether-addr-util.h"
#include "siphash24.h"
#include "netlink-util.h"
#include "udev-util.h"

#include "nspawn-network.h"

#define HOST_HASH_KEY SD_ID128_MAKE(1a,37,6f,c7,46,ec,45,0b,ad,a3,d5,31,06,60,5d,b1)
#define CONTAINER_HASH_KEY SD_ID128_MAKE(c3,c4,f9,19,b5,57,b2,1c,e6,cf,14,27,03,9c,ee,a2)
#define MACVLAN_HASH_KEY SD_ID128_MAKE(00,13,6d,bc,66,83,44,81,bb,0c,f9,51,1f,24,a6,6f)

static int generate_mac(
                const char *machine_name,
                struct ether_addr *mac,
                sd_id128_t hash_key,
                uint64_t idx) {

        uint8_t result[8];
        size_t l, sz;
        uint8_t *v, *i;
        int r;

        l = strlen(machine_name);
        sz = sizeof(sd_id128_t) + l;
        if (idx > 0)
                sz += sizeof(idx);

        v = alloca(sz);

        /* fetch some persistent data unique to the host */
        r = sd_id128_get_machine((sd_id128_t*) v);
        if (r < 0)
                return r;

        /* combine with some data unique (on this host) to this
         * container instance */
        i = mempcpy(v + sizeof(sd_id128_t), machine_name, l);
        if (idx > 0) {
                idx = htole64(idx);
                memcpy(i, &idx, sizeof(idx));
        }

        /* Let's hash the host machine ID plus the container name. We
         * use a fixed, but originally randomly created hash key here. */
        siphash24(result, v, sz, hash_key.bytes);

        assert_cc(ETH_ALEN <= sizeof(result));
        memcpy(mac->ether_addr_octet, result, ETH_ALEN);

        /* see eth_random_addr in the kernel */
        mac->ether_addr_octet[0] &= 0xfe;        /* clear multicast bit */
        mac->ether_addr_octet[0] |= 0x02;        /* set local assignment bit (IEEE802) */

        return 0;
}

int setup_veth(const char *machine_name,
               pid_t pid,
               char iface_name[IFNAMSIZ],
               bool bridge) {

        _cleanup_netlink_message_unref_ sd_netlink_message *m = NULL;
        _cleanup_netlink_unref_ sd_netlink *rtnl = NULL;
        struct ether_addr mac_host, mac_container;
        int r, i;

        /* Use two different interface name prefixes depending whether
         * we are in bridge mode or not. */
        snprintf(iface_name, IFNAMSIZ - 1, "%s-%s",
                 bridge ? "vb" : "ve", machine_name);

        r = generate_mac(machine_name, &mac_container, CONTAINER_HASH_KEY, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to generate predictable MAC address for container side: %m");

        r = generate_mac(machine_name, &mac_host, HOST_HASH_KEY, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to generate predictable MAC address for host side: %m");

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate netlink message: %m");

        r = sd_netlink_message_append_string(m, IFLA_IFNAME, iface_name);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink interface name: %m");

        r = sd_netlink_message_append_ether_addr(m, IFLA_ADDRESS, &mac_host);
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

        r = sd_netlink_message_append_string(m, IFLA_IFNAME, "host0");
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink interface name: %m");

        r = sd_netlink_message_append_ether_addr(m, IFLA_ADDRESS, &mac_container);
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
                return log_error_errno(r, "Failed to add new veth interfaces (host0, %s): %m", iface_name);

        i = (int) if_nametoindex(iface_name);
        if (i <= 0)
                return log_error_errno(errno, "Failed to resolve interface %s: %m", iface_name);

        return i;
}

int setup_bridge(const char *veth_name, const char *bridge_name) {
        _cleanup_netlink_message_unref_ sd_netlink_message *m = NULL;
        _cleanup_netlink_unref_ sd_netlink *rtnl = NULL;
        int r, bridge_ifi;

        assert(veth_name);
        assert(bridge_name);

        bridge_ifi = (int) if_nametoindex(bridge_name);
        if (bridge_ifi <= 0)
                return log_error_errno(errno, "Failed to resolve interface %s: %m", bridge_name);

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        r = sd_rtnl_message_new_link(rtnl, &m, RTM_SETLINK, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate netlink message: %m");

        r = sd_rtnl_message_link_set_flags(m, IFF_UP, IFF_UP);
        if (r < 0)
                return log_error_errno(r, "Failed to set IFF_UP flag: %m");

        r = sd_netlink_message_append_string(m, IFLA_IFNAME, veth_name);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink interface name field: %m");

        r = sd_netlink_message_append_u32(m, IFLA_MASTER, bridge_ifi);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink master field: %m");

        r = sd_netlink_call(rtnl, m, 0, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add veth interface to bridge: %m");

        return bridge_ifi;
}

static int parse_interface(struct udev *udev, const char *name) {
        _cleanup_udev_device_unref_ struct udev_device *d = NULL;
        char ifi_str[2 + DECIMAL_STR_MAX(int)];
        int ifi;

        ifi = (int) if_nametoindex(name);
        if (ifi <= 0)
                return log_error_errno(errno, "Failed to resolve interface %s: %m", name);

        sprintf(ifi_str, "n%i", ifi);
        d = udev_device_new_from_device_id(udev, ifi_str);
        if (!d)
                return log_error_errno(errno, "Failed to get udev device for interface %s: %m", name);

        if (udev_device_get_is_initialized(d) <= 0) {
                log_error("Network interface %s is not initialized yet.", name);
                return -EBUSY;
        }

        return ifi;
}

int move_network_interfaces(pid_t pid, char **ifaces) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_netlink_unref_ sd_netlink *rtnl = NULL;
        char **i;
        int r;

        if (strv_isempty(ifaces))
                return 0;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        udev = udev_new();
        if (!udev) {
                log_error("Failed to connect to udev.");
                return -ENOMEM;
        }

        STRV_FOREACH(i, ifaces) {
                _cleanup_netlink_message_unref_ sd_netlink_message *m = NULL;
                int ifi;

                ifi = parse_interface(udev, *i);
                if (ifi < 0)
                        return ifi;

                r = sd_rtnl_message_new_link(rtnl, &m, RTM_SETLINK, ifi);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate netlink message: %m");

                r = sd_netlink_message_append_u32(m, IFLA_NET_NS_PID, pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to append namespace PID to netlink message: %m");

                r = sd_netlink_call(rtnl, m, 0, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to move interface %s to namespace: %m", *i);
        }

        return 0;
}

int setup_macvlan(const char *machine_name, pid_t pid, char **ifaces) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_netlink_unref_ sd_netlink *rtnl = NULL;
        unsigned idx = 0;
        char **i;
        int r;

        if (strv_isempty(ifaces))
                return 0;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        udev = udev_new();
        if (!udev) {
                log_error("Failed to connect to udev.");
                return -ENOMEM;
        }

        STRV_FOREACH(i, ifaces) {
                _cleanup_netlink_message_unref_ sd_netlink_message *m = NULL;
                _cleanup_free_ char *n = NULL;
                struct ether_addr mac;
                int ifi;

                ifi = parse_interface(udev, *i);
                if (ifi < 0)
                        return ifi;

                r = generate_mac(machine_name, &mac, MACVLAN_HASH_KEY, idx++);
                if (r < 0)
                        return log_error_errno(r, "Failed to create MACVLAN MAC address: %m");

                r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate netlink message: %m");

                r = sd_netlink_message_append_u32(m, IFLA_LINK, ifi);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink interface index: %m");

                n = strappend("mv-", *i);
                if (!n)
                        return log_oom();

                strshorten(n, IFNAMSIZ-1);

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
        }

        return 0;
}

int setup_ipvlan(const char *machine_name, pid_t pid, char **ifaces) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_netlink_unref_ sd_netlink *rtnl = NULL;
        char **i;
        int r;

        if (strv_isempty(ifaces))
                return 0;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        udev = udev_new();
        if (!udev) {
                log_error("Failed to connect to udev.");
                return -ENOMEM;
        }

        STRV_FOREACH(i, ifaces) {
                _cleanup_netlink_message_unref_ sd_netlink_message *m = NULL;
                _cleanup_free_ char *n = NULL;
                int ifi;

                ifi = parse_interface(udev, *i);
                if (ifi < 0)
                        return ifi;

                r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate netlink message: %m");

                r = sd_netlink_message_append_u32(m, IFLA_LINK, ifi);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink interface index: %m");

                n = strappend("iv-", *i);
                if (!n)
                        return log_oom();

                strshorten(n, IFNAMSIZ-1);

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
        }

        return 0;
}
