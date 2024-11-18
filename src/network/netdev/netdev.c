/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>
#include <unistd.h>

#include "alloc-util.h"
#include "arphrd-util.h"
#include "bareudp.h"
#include "batadv.h"
#include "bond.h"
#include "bridge.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "dummy.h"
#include "fd-util.h"
#include "fou-tunnel.h"
#include "geneve.h"
#include "ifb.h"
#include "ipoib.h"
#include "ipvlan.h"
#include "l2tp-tunnel.h"
#include "list.h"
#include "macsec.h"
#include "macvlan.h"
#include "netdev.h"
#include "netdevsim.h"
#include "netif-util.h"
#include "netlink-util.h"
#include "network-util.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "networkd-setlink.h"
#include "networkd-sriov.h"
#include "networkd-state-file.h"
#include "nlmon.h"
#include "path-lookup.h"
#include "siphash24.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tunnel.h"
#include "tuntap.h"
#include "vcan.h"
#include "veth.h"
#include "vlan.h"
#include "vrf.h"
#include "vxcan.h"
#include "vxlan.h"
#include "wireguard.h"
#include "wlan.h"
#include "xfrm.h"

const NetDevVTable * const netdev_vtable[_NETDEV_KIND_MAX] = {
        [NETDEV_KIND_BAREUDP]   = &bare_udp_vtable,
        [NETDEV_KIND_BATADV]    = &batadv_vtable,
        [NETDEV_KIND_BOND]      = &bond_vtable,
        [NETDEV_KIND_BRIDGE]    = &bridge_vtable,
        [NETDEV_KIND_DUMMY]     = &dummy_vtable,
        [NETDEV_KIND_ERSPAN]    = &erspan_vtable,
        [NETDEV_KIND_FOU]       = &foutnl_vtable,
        [NETDEV_KIND_GENEVE]    = &geneve_vtable,
        [NETDEV_KIND_GRE]       = &gre_vtable,
        [NETDEV_KIND_GRETAP]    = &gretap_vtable,
        [NETDEV_KIND_IFB]       = &ifb_vtable,
        [NETDEV_KIND_IP6GRE]    = &ip6gre_vtable,
        [NETDEV_KIND_IP6GRETAP] = &ip6gretap_vtable,
        [NETDEV_KIND_IP6TNL]    = &ip6tnl_vtable,
        [NETDEV_KIND_IPIP]      = &ipip_vtable,
        [NETDEV_KIND_IPOIB]     = &ipoib_vtable,
        [NETDEV_KIND_IPVLAN]    = &ipvlan_vtable,
        [NETDEV_KIND_IPVTAP]    = &ipvtap_vtable,
        [NETDEV_KIND_L2TP]      = &l2tptnl_vtable,
        [NETDEV_KIND_MACSEC]    = &macsec_vtable,
        [NETDEV_KIND_MACVLAN]   = &macvlan_vtable,
        [NETDEV_KIND_MACVTAP]   = &macvtap_vtable,
        [NETDEV_KIND_NETDEVSIM] = &netdevsim_vtable,
        [NETDEV_KIND_NLMON]     = &nlmon_vtable,
        [NETDEV_KIND_SIT]       = &sit_vtable,
        [NETDEV_KIND_TAP]       = &tap_vtable,
        [NETDEV_KIND_TUN]       = &tun_vtable,
        [NETDEV_KIND_VCAN]      = &vcan_vtable,
        [NETDEV_KIND_VETH]      = &veth_vtable,
        [NETDEV_KIND_VLAN]      = &vlan_vtable,
        [NETDEV_KIND_VRF]       = &vrf_vtable,
        [NETDEV_KIND_VTI6]      = &vti6_vtable,
        [NETDEV_KIND_VTI]       = &vti_vtable,
        [NETDEV_KIND_VXCAN]     = &vxcan_vtable,
        [NETDEV_KIND_VXLAN]     = &vxlan_vtable,
        [NETDEV_KIND_WIREGUARD] = &wireguard_vtable,
        [NETDEV_KIND_WLAN]      = &wlan_vtable,
        [NETDEV_KIND_XFRM]      = &xfrm_vtable,
};

static const char* const netdev_kind_table[_NETDEV_KIND_MAX] = {
        [NETDEV_KIND_BAREUDP]   = "bareudp",
        [NETDEV_KIND_BATADV]    = "batadv",
        [NETDEV_KIND_BOND]      = "bond",
        [NETDEV_KIND_BRIDGE]    = "bridge",
        [NETDEV_KIND_DUMMY]     = "dummy",
        [NETDEV_KIND_ERSPAN]    = "erspan",
        [NETDEV_KIND_FOU]       = "fou",
        [NETDEV_KIND_GENEVE]    = "geneve",
        [NETDEV_KIND_GRE]       = "gre",
        [NETDEV_KIND_GRETAP]    = "gretap",
        [NETDEV_KIND_IFB]       = "ifb",
        [NETDEV_KIND_IP6GRE]    = "ip6gre",
        [NETDEV_KIND_IP6GRETAP] = "ip6gretap",
        [NETDEV_KIND_IP6TNL]    = "ip6tnl",
        [NETDEV_KIND_IPIP]      = "ipip",
        [NETDEV_KIND_IPOIB]     = "ipoib",
        [NETDEV_KIND_IPVLAN]    = "ipvlan",
        [NETDEV_KIND_IPVTAP]    = "ipvtap",
        [NETDEV_KIND_L2TP]      = "l2tp",
        [NETDEV_KIND_MACSEC]    = "macsec",
        [NETDEV_KIND_MACVLAN]   = "macvlan",
        [NETDEV_KIND_MACVTAP]   = "macvtap",
        [NETDEV_KIND_NETDEVSIM] = "netdevsim",
        [NETDEV_KIND_NLMON]     = "nlmon",
        [NETDEV_KIND_SIT]       = "sit",
        [NETDEV_KIND_TAP]       = "tap",
        [NETDEV_KIND_TUN]       = "tun",
        [NETDEV_KIND_VCAN]      = "vcan",
        [NETDEV_KIND_VETH]      = "veth",
        [NETDEV_KIND_VLAN]      = "vlan",
        [NETDEV_KIND_VRF]       = "vrf",
        [NETDEV_KIND_VTI6]      = "vti6",
        [NETDEV_KIND_VTI]       = "vti",
        [NETDEV_KIND_VXCAN]     = "vxcan",
        [NETDEV_KIND_VXLAN]     = "vxlan",
        [NETDEV_KIND_WIREGUARD] = "wireguard",
        [NETDEV_KIND_WLAN]      = "wlan",
        [NETDEV_KIND_XFRM]      = "xfrm",
};

DEFINE_STRING_TABLE_LOOKUP(netdev_kind, NetDevKind);

bool netdev_is_managed(NetDev *netdev) {
        if (!netdev || !netdev->manager || !netdev->ifname)
                return false;

        return hashmap_get(netdev->manager->netdevs, netdev->ifname) == netdev;
}

static bool netdev_is_stacked_and_independent(NetDev *netdev) {
        assert(netdev);

        if (netdev_get_create_type(netdev) != NETDEV_CREATE_STACKED)
                return false;

        switch (netdev->kind) {
        case NETDEV_KIND_ERSPAN:
                return ERSPAN(netdev)->independent;
        case NETDEV_KIND_GRE:
                return GRE(netdev)->independent;
        case NETDEV_KIND_GRETAP:
                return GRETAP(netdev)->independent;
        case NETDEV_KIND_IP6GRE:
                return IP6GRE(netdev)->independent;
        case NETDEV_KIND_IP6GRETAP:
                return IP6GRETAP(netdev)->independent;
        case NETDEV_KIND_IP6TNL:
                return IP6TNL(netdev)->independent;
        case NETDEV_KIND_IPIP:
                return IPIP(netdev)->independent;
        case NETDEV_KIND_SIT:
                return SIT(netdev)->independent;
        case NETDEV_KIND_VTI:
                return VTI(netdev)->independent;
        case NETDEV_KIND_VTI6:
                return VTI6(netdev)->independent;
        case NETDEV_KIND_VXLAN:
                return VXLAN(netdev)->independent;
        case NETDEV_KIND_XFRM:
                return XFRM(netdev)->independent;
        default:
                return false;
        }
}

static bool netdev_is_stacked(NetDev *netdev) {
        assert(netdev);

        if (netdev_get_create_type(netdev) != NETDEV_CREATE_STACKED)
                return false;

        if (netdev_is_stacked_and_independent(netdev))
                return false;

        return true;
}

NetDev* netdev_detach_name(NetDev *netdev, const char *name) {
        assert(netdev);

        if (!netdev->manager || !name)
                return NULL; /* Already detached or not attached yet. */

        return hashmap_remove_value(netdev->manager->netdevs, name, netdev);
}

static NetDev* netdev_detach_impl(NetDev *netdev) {
        assert(netdev);

        if (netdev->state != _NETDEV_STATE_INVALID &&
            NETDEV_VTABLE(netdev) &&
            NETDEV_VTABLE(netdev)->detach)
                NETDEV_VTABLE(netdev)->detach(netdev);

        NetDev *n = netdev_detach_name(netdev, netdev->ifname);

        netdev->manager = NULL;
        return n; /* Return NULL when it is not attached yet, or already detached. */
}

void netdev_detach(NetDev *netdev) {
        assert(netdev);

        netdev_unref(netdev_detach_impl(netdev));
}

static NetDev* netdev_free(NetDev *netdev) {
        assert(netdev);

        netdev_detach_impl(netdev);

        /* Invoke the per-kind done() destructor, but only if the state field is initialized. We conditionalize that
         * because we parse .netdev files twice: once to determine the kind (with a short, minimal NetDev structure
         * allocation, with no room for per-kind fields), and once to read the kind's properties (with a full,
         * comprehensive NetDev structure allocation with enough space for whatever the specific kind needs). Now, in
         * the first case we shouldn't try to destruct the per-kind NetDev fields on destruction, in the second case we
         * should. We use the state field to discern the two cases: it's _NETDEV_STATE_INVALID on the first "raw"
         * call. */
        if (netdev->state != _NETDEV_STATE_INVALID &&
            NETDEV_VTABLE(netdev) &&
            NETDEV_VTABLE(netdev)->done)
                NETDEV_VTABLE(netdev)->done(netdev);

        condition_free_list(netdev->conditions);
        free(netdev->filename);
        strv_free(netdev->dropins);
        hashmap_free(netdev->stats_by_path);
        free(netdev->description);
        free(netdev->ifname);

        return mfree(netdev);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(NetDev, netdev, netdev_free);

void netdev_drop(NetDev *netdev) {
        if (!netdev)
                return;

        if (netdev_is_stacked(netdev)) {
                /* The netdev may be removed due to the underlying device removal, and the device may
                 * be re-added later. */
                netdev->state = NETDEV_STATE_LOADING;
                netdev->ifindex = 0;

                log_netdev_debug(netdev, "netdev removed");
                return;
        }

        if (NETDEV_VTABLE(netdev) && NETDEV_VTABLE(netdev)->drop)
                NETDEV_VTABLE(netdev)->drop(netdev);

        netdev->state = NETDEV_STATE_LINGER;

        log_netdev_debug(netdev, "netdev removed");

        netdev_detach(netdev);
}

static int netdev_attach_name_full(NetDev *netdev, const char *name, Hashmap **netdevs) {
        int r;

        assert(netdev);
        assert(name);

        r = hashmap_ensure_put(netdevs, &string_hash_ops, name, netdev);
        if (r == -ENOMEM)
                return log_oom();
        if (r == -EEXIST) {
                NetDev *n = hashmap_get(*netdevs, name);

                assert(n);
                if (!streq(netdev->filename, n->filename))
                        log_netdev_warning_errno(netdev, r,
                                                 "Device \"%s\" was already configured by \"%s\", ignoring %s.",
                                                 name, n->filename, netdev->filename);

                return -EEXIST;
        }
        assert(r > 0);

        return 0;
}

int netdev_attach_name(NetDev *netdev, const char *name) {
        assert(netdev);
        assert(netdev->manager);

        return netdev_attach_name_full(netdev, name, &netdev->manager->netdevs);
}

static int netdev_attach(NetDev *netdev) {
        int r;

        assert(netdev);
        assert(netdev->ifname);

        r = netdev_attach_name(netdev, netdev->ifname);
        if (r < 0)
                return r;

        if (NETDEV_VTABLE(netdev)->attach) {
                r = NETDEV_VTABLE(netdev)->attach(netdev);
                if (r < 0)
                        return r;
        }

        return 0;
}

int netdev_get(Manager *manager, const char *name, NetDev **ret) {
        NetDev *netdev;

        assert(manager);
        assert(name);
        assert(ret);

        netdev = hashmap_get(manager->netdevs, name);
        if (!netdev)
                return -ENOENT;

        *ret = netdev;

        return 0;
}

void link_assign_netdev(Link *link) {
        _unused_ _cleanup_(netdev_unrefp) NetDev *old = NULL;
        NetDev *netdev;

        assert(link);
        assert(link->manager);
        assert(link->ifname);

        old = TAKE_PTR(link->netdev);

        if (netdev_get(link->manager, link->ifname, &netdev) < 0)
                goto not_found;

        int ifindex = NETDEV_VTABLE(netdev)->get_ifindex ?
                NETDEV_VTABLE(netdev)->get_ifindex(netdev, link->ifname) :
                netdev->ifindex;
        if (ifindex != link->ifindex)
                goto not_found;

        if (NETDEV_VTABLE(netdev)->iftype != link->iftype)
                goto not_found;

        if (!NETDEV_VTABLE(netdev)->skip_netdev_kind_check) {
                const char *kind;

                if (netdev->kind == NETDEV_KIND_TAP)
                        kind = "tun"; /* the kernel does not distinguish between tun and tap */
                else
                        kind = netdev_kind_to_string(netdev->kind);

                if (!streq_ptr(kind, link->kind))
                        goto not_found;
        }

        link->netdev = netdev_ref(netdev);

        if (netdev == old)
                return; /* The same NetDev found. */

        log_link_debug(link, "Found matching .netdev file: %s", netdev->filename);
        link_dirty(link);
        return;

not_found:

        if (old)
                /* Previously assigned NetDev is detached from Manager? Update the state file. */
                link_dirty(link);
}

void netdev_enter_failed(NetDev *netdev) {
        netdev->state = NETDEV_STATE_FAILED;
}

int netdev_enter_ready(NetDev *netdev) {
        assert(netdev);
        assert(netdev->ifname);

        if (!IN_SET(netdev->state, NETDEV_STATE_LOADING, NETDEV_STATE_CREATING))
                return 0;

        netdev->state = NETDEV_STATE_READY;

        log_netdev_info(netdev, "netdev ready");

        if (NETDEV_VTABLE(netdev)->post_create)
                NETDEV_VTABLE(netdev)->post_create(netdev, NULL);

        return 0;
}

bool netdev_needs_reconfigure(NetDev *netdev, NetDevLocalAddressType type) {
        assert(netdev);
        assert(type < _NETDEV_LOCAL_ADDRESS_TYPE_MAX);

        if (type < 0)
                return true;

        return NETDEV_VTABLE(netdev)->needs_reconfigure &&
                NETDEV_VTABLE(netdev)->needs_reconfigure(netdev, type);
}

/* callback for netdev's created without a backing Link */
static int netdev_create_handler(sd_netlink *rtnl, sd_netlink_message *m, NetDev *netdev) {
        int r;

        assert(netdev);
        assert(netdev->state != _NETDEV_STATE_INVALID);

        r = sd_netlink_message_get_errno(m);
        if (r >= 0)
                log_netdev_debug(netdev, "Created.");
        else if (r == -EEXIST && netdev->ifindex > 0)
                log_netdev_debug(netdev, "Already exists.");
        else {
                log_netdev_warning_errno(netdev, r, "Failed to create netdev: %m");
                netdev_enter_failed(netdev);
                return 0;
        }

        return netdev_enter_ready(netdev);
}

int netdev_set_ifindex_internal(NetDev *netdev, int ifindex) {
        assert(netdev);
        assert(ifindex > 0);

        if (netdev->ifindex == ifindex)
                return 0; /* Already set. */

        if (netdev->ifindex > 0 && netdev->ifindex != ifindex)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EEXIST),
                                                "Could not set ifindex to %i, already set to %i.",
                                                ifindex, netdev->ifindex);

        netdev->ifindex = ifindex;
        log_netdev_debug(netdev, "Gained index %i.", ifindex);
        return 1; /* set new ifindex. */
}

static int netdev_set_ifindex_impl(NetDev *netdev, const char *name, int ifindex) {
        assert(netdev);
        assert(name);
        assert(ifindex > 0);

        if (NETDEV_VTABLE(netdev)->set_ifindex)
                return NETDEV_VTABLE(netdev)->set_ifindex(netdev, name, ifindex);

        if (!streq(netdev->ifname, name))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "Received netlink message with unexpected interface name %s (ifindex=%i).",
                                                name, ifindex);

        return netdev_set_ifindex_internal(netdev, ifindex);
}

int netdev_set_ifindex(NetDev *netdev, sd_netlink_message *message) {
        uint16_t type;
        const char *kind;
        const char *received_kind;
        const char *received_name;
        int r, ifindex, family;

        assert(netdev);
        assert(message);

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Could not get rtnl message type: %m");

        if (type != RTM_NEWLINK)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL), "Cannot set ifindex from unexpected rtnl message type.");

        r = sd_rtnl_message_get_family(message, &family);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to get family from received rtnl message: %m");

        if (family != AF_UNSPEC)
                return 0; /* IFLA_LINKINFO is only contained in the message with AF_UNSPEC. */

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Could not get ifindex: %m");
        if (ifindex <= 0)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL), "Got invalid ifindex: %d", ifindex);

        r = sd_netlink_message_read_string(message, IFLA_IFNAME, &received_name);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Could not get IFNAME: %m");

        if (!NETDEV_VTABLE(netdev)->skip_netdev_kind_check) {

                r = sd_netlink_message_enter_container(message, IFLA_LINKINFO);
                if (r < 0)
                        return log_netdev_warning_errno(netdev, r, "Could not get LINKINFO: %m");

                r = sd_netlink_message_read_string(message, IFLA_INFO_KIND, &received_kind);
                if (r < 0)
                        return log_netdev_warning_errno(netdev, r, "Could not get KIND: %m");

                r = sd_netlink_message_exit_container(message);
                if (r < 0)
                        return log_netdev_warning_errno(netdev, r, "Could not exit container: %m");

                if (netdev->kind == NETDEV_KIND_TAP)
                        /* the kernel does not distinguish between tun and tap */
                        kind = "tun";
                else
                        kind = netdev_kind_to_string(netdev->kind);
                if (!kind)
                        return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL), "Could not get netdev kind.");

                if (!streq(kind, received_kind))
                        return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                        "Received newlink with wrong KIND %s, expected %s",
                                                        received_kind, kind);
        }

        return netdev_set_ifindex_impl(netdev, received_name, ifindex);
}

#define HASH_KEY SD_ID128_MAKE(52,e1,45,bd,00,6f,29,96,21,c6,30,6d,83,71,04,48)

int netdev_generate_hw_addr(
                NetDev *netdev,
                Link *parent,
                const char *name,
                const struct hw_addr_data *hw_addr,
                struct hw_addr_data *ret) {

        struct hw_addr_data a = HW_ADDR_NULL;
        bool is_static = false;
        int r;

        assert(netdev);
        assert(name);
        assert(hw_addr);
        assert(ret);

        if (hw_addr_equal(hw_addr, &HW_ADDR_NONE)) {
                *ret = HW_ADDR_NULL;
                return 0;
        }

        if (hw_addr->length == 0) {
                uint64_t result;

                /* HardwareAddress= is not specified. */

                if (!NETDEV_VTABLE(netdev)->generate_mac)
                        goto finalize;

                if (!IN_SET(NETDEV_VTABLE(netdev)->iftype, ARPHRD_ETHER, ARPHRD_INFINIBAND))
                        goto finalize;

                r = net_get_unique_predictable_data_from_name(name, &HASH_KEY, &result);
                if (r < 0) {
                        log_netdev_warning_errno(netdev, r,
                                                 "Failed to generate persistent MAC address, ignoring: %m");
                        goto finalize;
                }

                a.length = arphrd_to_hw_addr_len(NETDEV_VTABLE(netdev)->iftype);

                switch (NETDEV_VTABLE(netdev)->iftype) {
                case ARPHRD_ETHER:
                        assert(a.length <= sizeof(result));
                        memcpy(a.bytes, &result, a.length);

                        if (ether_addr_is_null(&a.ether) || ether_addr_is_broadcast(&a.ether)) {
                                log_netdev_warning(netdev, "Failed to generate persistent MAC address, ignoring.");
                                a = HW_ADDR_NULL;
                                goto finalize;
                        }

                        break;
                case ARPHRD_INFINIBAND:
                        if (result == 0) {
                                log_netdev_warning(netdev, "Failed to generate persistent MAC address.");
                                goto finalize;
                        }

                        assert(a.length >= sizeof(result));
                        memzero(a.bytes, a.length - sizeof(result));
                        memcpy(a.bytes + a.length - sizeof(result), &result, sizeof(result));
                        break;
                default:
                        assert_not_reached();
                }

        } else {
                a = *hw_addr;
                is_static = true;
        }

        r = net_verify_hardware_address(name, is_static, NETDEV_VTABLE(netdev)->iftype,
                                        parent ? &parent->hw_addr : NULL, &a);
        if (r < 0)
                return r;

finalize:
        *ret = a;
        return 0;
}

static bool netdev_can_set_mac(NetDev *netdev, const struct hw_addr_data *hw_addr) {
        assert(netdev);
        assert(netdev->manager);
        assert(hw_addr);

        if (hw_addr->length <= 0)
                return false;

        Link *link;
        if (link_get_by_index(netdev->manager, netdev->ifindex, &link) < 0)
                return true; /* The netdev does not exist yet. We can set MAC address. */

        if (hw_addr_equal(&link->hw_addr, hw_addr))
                return false; /* Unchanged, not necessary to set. */

        /* Some netdevs refuse to update MAC address even if the interface is not running, e.g. ipvlan.
         * Some other netdevs have the IFF_LIVE_ADDR_CHANGE flag and can update update MAC address even if
         * the interface is running, e.g. dummy. For those cases, use custom checkers. */
        if (NETDEV_VTABLE(netdev)->can_set_mac)
                return NETDEV_VTABLE(netdev)->can_set_mac(netdev, hw_addr);

        /* Before ad72c4a06acc6762e84994ac2f722da7a07df34e and 0ec92a8f56ff07237dbe8af7c7a72aba7f957baf
         * (both in v6.5), the kernel refuse to set MAC address for existing netdevs even if it is unchanged.
         * So, by default, do not update MAC address if the it is running. See eth_prepare_mac_addr_change(),
         * which is called by eth_mac_addr(). Note, the result of netif_running() is mapped to operstate
         * and flags. See rtnl_fill_ifinfo() and dev_get_flags(). */
        return link->kernel_operstate == IF_OPER_DOWN &&
                (link->flags & (IFF_RUNNING | IFF_LOWER_UP | IFF_DORMANT)) == 0;
}

static bool netdev_can_set_mtu(NetDev *netdev, uint32_t mtu) {
        assert(netdev);

        if (mtu <= 0)
                return false;

        Link *link;
        if (link_get_by_index(netdev->manager, netdev->ifindex, &link) < 0)
                return true; /* The netdev does not exist yet. We can set MTU. */

        if (mtu < link->min_mtu || link->max_mtu < mtu)
                return false; /* The MTU is out of range. */

        if (link->mtu == mtu)
                return false; /* Unchanged, not necessary to set. */

        /* Some netdevs cannot change MTU, e.g. vxlan. Let's use the custom checkers in such cases. */
        if (NETDEV_VTABLE(netdev)->can_set_mtu)
                return NETDEV_VTABLE(netdev)->can_set_mtu(netdev, mtu);

        /* By default, allow to update the MTU. */
        return true;
}

static int netdev_create_message(NetDev *netdev, Link *link, sd_netlink_message *m) {
        int r;

        if (netdev->ifindex <= 0) {
                /* Set interface name when it is newly created. Otherwise, the kernel older than
                 * bd039b5ea2a91ea707ee8539df26456bd5be80af (v6.2) will refuse the netlink message even if
                 * the name is unchanged. */
                r = sd_netlink_message_append_string(m, IFLA_IFNAME, netdev->ifname);
                if (r < 0)
                        return r;
        }

        struct hw_addr_data hw_addr;
        r = netdev_generate_hw_addr(netdev, link, netdev->ifname, &netdev->hw_addr, &hw_addr);
        if (r < 0)
                return r;

        if (netdev_can_set_mac(netdev, &hw_addr)) {
                log_netdev_debug(netdev, "Using MAC address: %s", HW_ADDR_TO_STR(&hw_addr));
                r = netlink_message_append_hw_addr(m, IFLA_ADDRESS, &hw_addr);
                if (r < 0)
                        return r;
        }

        if (netdev_can_set_mtu(netdev, netdev->mtu)) {
                r = sd_netlink_message_append_u32(m, IFLA_MTU, netdev->mtu);
                if (r < 0)
                        return r;
        }

        if (link) {
                r = sd_netlink_message_append_u32(m, IFLA_LINK, link->ifindex);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_open_container(m, IFLA_LINKINFO);
        if (r < 0)
                return r;

        if (NETDEV_VTABLE(netdev)->fill_message_create) {
                r = sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, netdev_kind_to_string(netdev->kind));
                if (r < 0)
                        return r;

                r = NETDEV_VTABLE(netdev)->fill_message_create(netdev, link, m);
                if (r < 0)
                        return r;

                r = sd_netlink_message_close_container(m);
                if (r < 0)
                        return r;
        } else {
                r = sd_netlink_message_append_string(m, IFLA_INFO_KIND, netdev_kind_to_string(netdev->kind));
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int independent_netdev_create(NetDev *netdev) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(netdev);
        assert(netdev->manager);

        /* create netdev */
        if (NETDEV_VTABLE(netdev)->create) {
                r = NETDEV_VTABLE(netdev)->create(netdev);
                if (r < 0)
                        return r;

                log_netdev_debug(netdev, "Created");
                return 0;
        }

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &m, RTM_NEWLINK, netdev->ifindex);
        if (r < 0)
                return r;

        r = netdev_create_message(netdev, NULL, m);
        if (r < 0)
                return r;

        r = netlink_call_async(netdev->manager->rtnl, NULL, m, netdev_create_handler,
                               netdev_destroy_callback, netdev);
        if (r < 0)
                return r;

        netdev_ref(netdev);

        netdev->state = NETDEV_STATE_CREATING;
        log_netdev_debug(netdev, "Creating");
        return 0;
}

static int stacked_netdev_create(NetDev *netdev, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(netdev);
        assert(netdev->manager);
        assert(link);
        assert(req);

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &m, RTM_NEWLINK, netdev->ifindex);
        if (r < 0)
                return r;

        r = netdev_create_message(netdev, link, m);
        if (r < 0)
                return r;

        r = request_call_netlink_async(netdev->manager->rtnl, m, req);
        if (r < 0)
                return r;

        netdev->state = NETDEV_STATE_CREATING;
        log_netdev_debug(netdev, "Creating");
        return 0;
}

static bool link_is_ready_to_create_stacked_netdev_one(Link *link, bool allow_unmanaged) {
        assert(link);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED, LINK_STATE_UNMANAGED))
                return false;

        if (!link->network)
                return allow_unmanaged;

        if (link->set_link_messages > 0)
                return false;

        /* If stacked netdevs are created before the underlying interface being activated, then
         * the activation policy for the netdevs are ignored. See issue #22593. */
        if (!link->activated)
                return false;

        return true;
}

static bool link_is_ready_to_create_stacked_netdev(Link *link) {
        return check_ready_for_all_sr_iov_ports(link, /* allow_unmanaged = */ false,
                                                link_is_ready_to_create_stacked_netdev_one);
}

static int netdev_is_ready_to_create(NetDev *netdev, Link *link) {
        assert(netdev);

        if (link && !link_is_ready_to_create_stacked_netdev(link))
                return false;

        if (NETDEV_VTABLE(netdev)->is_ready_to_create)
                return NETDEV_VTABLE(netdev)->is_ready_to_create(netdev, link);

        return true;
}

static int stacked_netdev_process_request(Request *req, Link *link, void *userdata) {
        NetDev *netdev = ASSERT_PTR(userdata);
        int r;

        assert(req);
        assert(link);

        if (!netdev_is_managed(netdev))
                goto cancelled; /* Already detached, due to e.g. reloading .netdev files, cancelling the request. */

        if (NETDEV_VTABLE(netdev)->keep_existing && netdev->ifindex > 0) {
                /* Already exists, and the netdev does not support updating, entering the ready state. */
                r = netdev_enter_ready(netdev);
                if (r < 0)
                        return r;

                goto cancelled;
        }

        r = netdev_is_ready_to_create(netdev, link);
        if (r <= 0)
                return r;

        r = stacked_netdev_create(netdev, link, req);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to create netdev: %m");

        return 1;

cancelled:
        assert_se(TAKE_PTR(req->counter) == &link->create_stacked_netdev_messages);
        link->create_stacked_netdev_messages--;

        if (link->create_stacked_netdev_messages == 0) {
                link->stacked_netdevs_created = true;
                log_link_debug(link, "Stacked netdevs created.");
                link_check_ready(link);
        }

        return 1;
}

static int create_stacked_netdev_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        NetDev *netdev = ASSERT_PTR(userdata);
        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r >= 0)
                log_netdev_debug(netdev, "Created.");
        else if (r == -EEXIST && netdev->ifindex > 0)
                log_netdev_debug(netdev, "Already exists.");
        else {
                log_netdev_warning_errno(netdev, r, "Failed to create netdev: %m");
                netdev_enter_failed(netdev);
                link_enter_failed(link);
                return 0;
        }

        (void) netdev_enter_ready(netdev);

        if (link->create_stacked_netdev_messages == 0) {
                link->stacked_netdevs_created = true;
                log_link_debug(link, "Stacked netdevs created.");
                link_check_ready(link);
        }

        return 0;
}

int link_request_stacked_netdev(Link *link, NetDev *netdev) {
        int r;

        assert(link);
        assert(netdev);

        if (!netdev_is_stacked(netdev))
                return -EINVAL;

        if (!netdev_is_managed(netdev))
                return 0; /* Already detached, due to e.g. reloading .netdev files. */

        link->stacked_netdevs_created = false;
        r = link_queue_request_full(link, REQUEST_TYPE_NETDEV_STACKED,
                                    netdev, (mfree_func_t) netdev_unref,
                                    trivial_hash_func, trivial_compare_func,
                                    stacked_netdev_process_request,
                                    &link->create_stacked_netdev_messages,
                                    create_stacked_netdev_handler, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request stacked netdev '%s': %m",
                                            netdev->ifname);
        if (r == 0)
                return 0;

        netdev_ref(netdev);
        log_link_debug(link, "Requested stacked netdev '%s'", netdev->ifname);
        return 1;
}

static int independent_netdev_process_request(Request *req, Link *link, void *userdata) {
        NetDev *netdev = ASSERT_PTR(userdata);
        int r;

        assert(!link);

        if (!netdev_is_managed(netdev))
                return 1; /* Already detached, due to e.g. reloading .netdev files, cancelling the request. */

        if (NETDEV_VTABLE(netdev)->keep_existing && netdev->ifindex > 0) {
                /* Already exists, and the netdev does not support updating, entering the ready state. */
                r = netdev_enter_ready(netdev);
                if (r < 0)
                        return r;

                return 1; /* Skip this request. */
        }

        r = netdev_is_ready_to_create(netdev, NULL);
        if (r <= 0)
                return r;

        r = independent_netdev_create(netdev);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to create netdev: %m");

        return 1;
}

static int netdev_request_to_create(NetDev *netdev) {
        int r;

        assert(netdev);
        assert(netdev->manager);

        if (netdev->manager->test_mode)
                return 0;

        if (netdev_is_stacked(netdev))
                return 0;

        if (!netdev_is_managed(netdev))
                return 0; /* Already detached, due to e.g. reloading .netdev files. */

        if (netdev->state != NETDEV_STATE_LOADING)
                return 0; /* Already configured (at least tried previously). Not necessary to reconfigure. */

        r = netdev_queue_request(netdev, independent_netdev_process_request, NULL);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to request to create netdev: %m");

        return 0;
}

int netdev_load_one(Manager *manager, const char *filename, NetDev **ret) {
        _cleanup_(netdev_unrefp) NetDev *netdev_raw = NULL, *netdev = NULL;
        const char *dropin_dirname;
        int r;

        assert(manager);
        assert(filename);
        assert(ret);

        r = null_or_empty_path(filename);
        if (r < 0)
                return log_warning_errno(r, "Failed to check if \"%s\" is empty: %m", filename);
        if (r > 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT), "Skipping empty file: %s", filename);

        netdev_raw = new(NetDev, 1);
        if (!netdev_raw)
                return log_oom();

        *netdev_raw = (NetDev) {
                .n_ref = 1,
                .kind = _NETDEV_KIND_INVALID,
                .state = _NETDEV_STATE_INVALID, /* an invalid state means done() of the implementation won't be called on destruction */
        };

        dropin_dirname = strjoina(basename(filename), ".d");
        r = config_parse_many(
                        STRV_MAKE_CONST(filename), NETWORK_DIRS, dropin_dirname, /* root = */ NULL,
                        NETDEV_COMMON_SECTIONS NETDEV_OTHER_SECTIONS,
                        config_item_perf_lookup, network_netdev_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        netdev_raw,
                        NULL,
                        NULL);
        if (r < 0)
                return r; /* config_parse_many() logs internally. */

        /* skip out early if configuration does not match the environment */
        if (!condition_test_list(netdev_raw->conditions, environ, NULL, NULL, NULL))
                return log_debug_errno(SYNTHETIC_ERRNO(ESTALE), "%s: Conditions in the file do not match the system environment, skipping.", filename);

        if (netdev_raw->kind == _NETDEV_KIND_INVALID)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "NetDev has no Kind= configured in \"%s\", ignoring.", filename);

        if (!netdev_raw->ifname)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "NetDev without Name= configured in \"%s\", ignoring.", filename);

        netdev = malloc0(NETDEV_VTABLE(netdev_raw)->object_size);
        if (!netdev)
                return log_oom();

        netdev->n_ref = 1;
        netdev->manager = manager;
        netdev->kind = netdev_raw->kind;
        netdev->state = NETDEV_STATE_LOADING; /* we initialize the state here for the first time,
                                                 so that done() will be called on destruction */

        if (NETDEV_VTABLE(netdev)->init)
                NETDEV_VTABLE(netdev)->init(netdev);

        r = config_parse_many(
                        STRV_MAKE_CONST(filename), NETWORK_DIRS, dropin_dirname, /* root = */ NULL,
                        NETDEV_VTABLE(netdev)->sections,
                        config_item_perf_lookup, network_netdev_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        netdev,
                        &netdev->stats_by_path,
                        &netdev->dropins);
        if (r < 0)
                return r; /* config_parse_many() logs internally. */

        /* verify configuration */
        if (NETDEV_VTABLE(netdev)->config_verify) {
                r = NETDEV_VTABLE(netdev)->config_verify(netdev, filename);
                if (r < 0)
                        return r; /* config_verify() logs internally. */
        }

        netdev->filename = strdup(filename);
        if (!netdev->filename)
                return log_oom();

        log_syntax(/* unit = */ NULL, LOG_DEBUG, filename, /* config_line = */ 0, /* error = */ 0, "Successfully loaded.");

        *ret = TAKE_PTR(netdev);
        return 0;
}

int netdev_load(Manager *manager) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(manager);

        r = conf_files_list_strv(&files, ".netdev", NULL, 0, NETWORK_DIRS);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate netdev files: %m");

        STRV_FOREACH(f, files) {
                _cleanup_(netdev_unrefp) NetDev *netdev = NULL;

                if (netdev_load_one(manager, *f, &netdev) < 0)
                        continue;

                if (netdev_attach(netdev) < 0)
                        continue;

                if (netdev_request_to_create(netdev) < 0)
                        continue;

                TAKE_PTR(netdev);
        }

        return 0;
}

int netdev_reload(Manager *manager) {
        _cleanup_hashmap_free_ Hashmap *new_netdevs = NULL;
        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(manager);

        r = conf_files_list_strv(&files, ".netdev", NULL, 0, NETWORK_DIRS);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate netdev files: %m");

        STRV_FOREACH(f, files) {
                _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
                NetDev *old;

                if (netdev_load_one(manager, *f, &netdev) < 0)
                        continue;

                if (netdev_get(manager, netdev->ifname, &old) < 0) {
                        log_netdev_debug(netdev, "Found new .netdev file: %s", netdev->filename);

                        if (netdev_attach_name_full(netdev, netdev->ifname, &new_netdevs) >= 0)
                                TAKE_PTR(netdev);

                        continue;
                }

                if (!stats_by_path_equal(netdev->stats_by_path, old->stats_by_path)) {
                        log_netdev_debug(netdev, "Found updated .netdev file: %s", netdev->filename);

                        /* Copy ifindex. */
                        netdev->ifindex = old->ifindex;

                        if (netdev_attach_name_full(netdev, netdev->ifname, &new_netdevs) >= 0)
                                TAKE_PTR(netdev);

                        continue;
                }

                /* Keep the original object, and drop the new one. */
                if (netdev_attach_name_full(old, old->ifname, &new_netdevs) >= 0)
                        netdev_ref(old);
        }

        /* Detach old NetDev objects from Manager.
         * Note, the same object may be registered with multiple names, and netdev_detach() may drop multiple
         * entries. Hence, hashmap_free_with_destructor() cannot be used. */
        for (NetDev *n; (n = hashmap_first(manager->netdevs)); )
                netdev_detach(n);

        /* Attach new NetDev objects to Manager. */
        for (;;) {
                _cleanup_(netdev_unrefp) NetDev *netdev = hashmap_steal_first(new_netdevs);
                if (!netdev)
                        break;

                netdev->manager = manager;
                if (netdev_attach(netdev) < 0)
                        continue;

                /* Create a new netdev or update existing netdev, */
                if (netdev_request_to_create(netdev) < 0)
                        continue;

                TAKE_PTR(netdev);
        }

        /* Reassign NetDev objects to Link object. */
        Link *link;
        HASHMAP_FOREACH(link, manager->links_by_index)
                link_assign_netdev(link);

        return 0;
}

int config_parse_netdev_kind(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        NetDevKind k, *kind = ASSERT_PTR(data);

        assert(filename);
        assert(rvalue);

        k = netdev_kind_from_string(rvalue);
        if (k < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, k, "Failed to parse netdev kind, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (*kind != _NETDEV_KIND_INVALID && *kind != k) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified netdev kind is different from the previous value '%s', ignoring assignment: %s",
                           netdev_kind_to_string(*kind), rvalue);
                return 0;
        }

        *kind = k;

        return 0;
}

int config_parse_netdev_hw_addr(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        struct hw_addr_data *hw_addr = ASSERT_PTR(data);

        assert(rvalue);

        if (streq(rvalue, "none")) {
                *hw_addr = HW_ADDR_NONE;
                return 0;
        }

        return config_parse_hw_addr(unit, filename, line, section, section_line, lvalue, ltype, rvalue, data, userdata);
}
