/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>

#include "conf-parser.h"
#include "netdev.h"
#include "ovs-port.h"
#include "string-table.h"
#include "string-util.h"
#include "vlan-util.h"

static const char * const ovs_port_type_table[_OVS_PORT_TYPE_MAX] = {
        [OVS_PORT_TYPE_INTERNAL] = "internal",
        [OVS_PORT_TYPE_PATCH]    = "patch",
        [OVS_PORT_TYPE_BOND]     = "bond",
};

DEFINE_STRING_TABLE_LOOKUP(ovs_port_type, OVSPortType);

static const char * const ovs_port_vlan_mode_table[_OVS_PORT_VLAN_MODE_MAX] = {
        [OVS_PORT_VLAN_MODE_TRUNK]           = "trunk",
        [OVS_PORT_VLAN_MODE_ACCESS]          = "access",
        [OVS_PORT_VLAN_MODE_NATIVE_TAGGED]   = "native-tagged",
        [OVS_PORT_VLAN_MODE_NATIVE_UNTAGGED] = "native-untagged",
        [OVS_PORT_VLAN_MODE_DOT1Q_TUNNEL]    = "dot1q-tunnel",
};

DEFINE_STRING_TABLE_LOOKUP(ovs_port_vlan_mode, OVSPortVLANMode);

static const char * const ovs_lacp_table[_OVS_LACP_MAX] = {
        [OVS_LACP_OFF]     = "off",
        [OVS_LACP_ACTIVE]  = "active",
        [OVS_LACP_PASSIVE] = "passive",
};

DEFINE_STRING_TABLE_LOOKUP(ovs_lacp, OVSLACP);

static const char * const ovs_bond_mode_table[_OVS_BOND_MODE_MAX] = {
        [OVS_BOND_MODE_ACTIVE_BACKUP] = "active-backup",
        [OVS_BOND_MODE_BALANCE_SLB]   = "balance-slb",
        [OVS_BOND_MODE_BALANCE_TCP]   = "balance-tcp",
};

DEFINE_STRING_TABLE_LOOKUP(ovs_bond_mode, OVSBondMode);

static void ovs_port_init(NetDev *netdev) {
        OVSPort *p = OVS_PORT(netdev);

        p->type = _OVS_PORT_TYPE_INVALID;
        p->vlan_mode = _OVS_PORT_VLAN_MODE_INVALID;
        p->lacp = _OVS_LACP_INVALID;
        p->bond_mode = _OVS_BOND_MODE_INVALID;
        p->tag = VLANID_INVALID;
        p->bond_updelay = USEC_INFINITY;
        p->bond_downdelay = USEC_INFINITY;
}

static void ovs_port_done(NetDev *netdev) {
        OVSPort *p = OVS_PORT(netdev);

        free(p->bridge);
        free(p->peer_port);
}

static int ovs_port_create(NetDev *netdev) {
        OVSPort *p = OVS_PORT(netdev);

        /* Patch and bond ports are purely virtual in OVS — no kernel netdev is
         * created, so no RTM_NEWLINK will arrive and set_ifindex will never be
         * called. Mark READY immediately; the OVSDB create happens via the reconciler. */
        if (p->type != OVS_PORT_TYPE_INTERNAL) {
                log_netdev_debug(netdev, "OVS port queued for reconciliation");
                return netdev_enter_ready(netdev);
        }

        netdev->state = NETDEV_STATE_CREATING;
        log_netdev_debug(netdev, "OVS port queued for reconciliation");
        return 0;
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

        /* Strip bond-only settings on non-bond ports. Invalid VLANMode=/LACP=/BondMode=
         * values are already rejected at parse time by the enum parsers, so no value
         * validation is needed here. */
        if (p->type != OVS_PORT_TYPE_BOND &&
            (p->lacp >= 0 || p->bond_mode >= 0 ||
             p->bond_updelay != USEC_INFINITY || p->bond_downdelay != USEC_INFINITY)) {
                log_netdev_warning(netdev,
                                   "%s: LACP=, BondMode=, BondUpDelaySec=, BondDownDelaySec= are only valid "
                                   "for type 'bond', ignoring bond settings.",
                                   filename);
                p->lacp = _OVS_LACP_INVALID;
                p->bond_mode = _OVS_BOND_MODE_INVALID;
                p->bond_updelay = USEC_INFINITY;
                p->bond_downdelay = USEC_INFINITY;
        }

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

DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_ovs_port_type, ovs_port_type, OVSPortType, _OVS_PORT_TYPE_INVALID);
DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_ovs_port_vlan_mode, ovs_port_vlan_mode, OVSPortVLANMode, _OVS_PORT_VLAN_MODE_INVALID);
DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_ovs_lacp, ovs_lacp, OVSLACP, _OVS_LACP_INVALID);
DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_ovs_bond_mode, ovs_bond_mode, OVSBondMode, _OVS_BOND_MODE_INVALID);

int config_parse_ovs_port_vlanid(
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

        uint16_t *id = ASSERT_PTR(data);
        uint16_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *id = VLANID_INVALID;
                return 0;
        }

        r = parse_vlanid(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        /* Unlike kernel VLANs (config_parse_vlanid permits 0), an OVS port tag of 0 is not a
         * usable primary VLAN ID: ovs-vswitchd would reject it, rolling back the reconcile
         * transact. Restrict to 1…4094 to match the documented range and fail at parse time. */
        if (v == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s= must be in the range 1…4094, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        *id = v;
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
        .keep_on_drop = true,
};
