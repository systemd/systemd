/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>

#include "conf-parser.h"
#include "netdev.h"
#include "ovs-port.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

static const char * const ovs_port_type_table[_OVS_PORT_TYPE_MAX] = {
        [OVS_PORT_TYPE_INTERNAL] = "internal",
        [OVS_PORT_TYPE_PATCH]    = "patch",
        [OVS_PORT_TYPE_BOND]     = "bond",
};

DEFINE_STRING_TABLE_LOOKUP(ovs_port_type, OVSPortType);

static void ovs_port_init(NetDev *netdev) {
        OVSPort *p = OVS_PORT(netdev);

        p->type = _OVS_PORT_TYPE_INVALID;
        p->tag = VLANID_INVALID;
        p->bond_updelay = USEC_INFINITY;
        p->bond_downdelay = USEC_INFINITY;
}

static void ovs_port_done(NetDev *netdev) {
        OVSPort *p = OVS_PORT(netdev);

        free(p->bridge);
        free(p->vlan_mode);
        free(p->trunks);
        free(p->peer_port);
        free(p->lacp);
        free(p->bond_mode);
}

static int ovs_port_create(NetDev *netdev) {
#if !ENABLE_OPENVSWITCH
        return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EOPNOTSUPP),
                "Open vSwitch support not compiled in. Rebuild with -Dopenvswitch=enabled.");
#else
        netdev->state = NETDEV_STATE_CREATING;
        log_netdev_debug(netdev, "OVS port queued for reconciliation");
        return 0;
#endif
}

static int ovs_port_verify(NetDev *netdev, const char *filename) {
        OVSPort *p = OVS_PORT(netdev);

        assert(filename);

        if (!p->bridge)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: OVSPort without Bridge= is not valid. Ignoring.",
                                                filename);

        if (p->type == _OVS_PORT_TYPE_INVALID)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: OVSPort without valid Type= is not valid. Ignoring.",
                                                filename);

        if (p->type == OVS_PORT_TYPE_PATCH && !p->peer_port)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: OVSPort of type 'patch' requires PeerPort=. Ignoring.",
                                                filename);

        if (p->type != OVS_PORT_TYPE_PATCH && p->peer_port) {
                log_netdev_warning(netdev, "%s: PeerPort= is only valid for Type=patch, ignoring.",
                                   filename);
                p->peer_port = mfree(p->peer_port);
        }

        if (p->vlan_mode && !STR_IN_SET(p->vlan_mode, "trunk", "access", "native-tagged", "native-untagged", "dot1q-tunnel"))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: invalid VLANMode='%s'. Ignoring.",
                                                filename, p->vlan_mode);

        if (p->lacp && !STR_IN_SET(p->lacp, "off", "active", "passive"))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: invalid LACP='%s'. Ignoring.",
                                                filename, p->lacp);

        if (p->bond_mode && !STR_IN_SET(p->bond_mode, "active-backup", "balance-slb", "balance-tcp"))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: invalid BondMode='%s'. Ignoring.",
                                                filename, p->bond_mode);

        if (p->type != OVS_PORT_TYPE_BOND && (p->lacp || p->bond_mode)) {
                log_netdev_warning(netdev,
                                   "%s: LACP= and BondMode= are only valid for type 'bond', ignoring bond settings.",
                                   filename);
                p->lacp = mfree(p->lacp);
                p->bond_mode = mfree(p->bond_mode);
                p->bond_updelay = USEC_INFINITY;
                p->bond_downdelay = USEC_INFINITY;
        }

        if (p->tag != VLANID_INVALID && p->vlan_mode)
                log_netdev_warning(netdev,
                                   "%s: Both Tag= and VLANMode= set; this may cause unexpected behavior.",
                                   filename);

        return 0;
}

static int ovs_port_set_ifindex(NetDev *netdev, const char *name, int ifindex) {
        OVSPort *p;
        int r;

        assert(netdev);
        assert(name);
        assert(ifindex > 0);

        p = OVS_PORT(netdev);

        /* Only internal ports produce a kernel netdev with the same name.
         * Patch and bond ports are purely virtual in OVS — they have no
         * same-name kernel interface, so we should never be called for them.
         * If we are (shouldn't happen), ignore silently. */
        if (p->type != OVS_PORT_TYPE_INTERNAL)
                return 0;

        if (!streq(netdev->ifname, name))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "Received netlink message with unexpected interface name %s (index=%i).",
                                                name, ifindex);

        r = netdev_set_ifindex_internal(netdev, ifindex);
        if (r <= 0)
                return r;

        /* Kernel has created the internal port interface — we're ready */
        return netdev_enter_ready(netdev);
}

int config_parse_ovs_port_type(
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

        OVSPort *p = OVS_PORT(ASSERT_PTR(userdata));
        OVSPortType t;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                p->type = _OVS_PORT_TYPE_INVALID;
                return 0;
        }

        t = ovs_port_type_from_string(rvalue);
        if (t < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, t,
                           "Invalid OVS port type '%s', ignoring.", rvalue);
                return 0;
        }

        p->type = t;
        return 0;
}

const NetDevVTable ovs_port_vtable = {
        .object_size = sizeof(OVSPort),
        .init = ovs_port_init,
        .done = ovs_port_done,
        .sections = NETDEV_COMMON_SECTIONS "OVSPort\0",
        .create = ovs_port_create,
        .set_ifindex = ovs_port_set_ifindex,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = ovs_port_verify,
        .iftype = ARPHRD_ETHER,
        .skip_netdev_kind_check = true,
};
