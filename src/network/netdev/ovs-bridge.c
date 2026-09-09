/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>

#include "conf-parser.h"
#include "extract-word.h" /* IWYU pragma: keep */
#include "netdev.h"
#include "ovs-bridge.h"
#include "string-table.h"
#include "string-util.h"

static const char * const ovs_bridge_fail_mode_table[_OVS_BRIDGE_FAIL_MODE_MAX] = {
        [OVS_BRIDGE_FAIL_MODE_STANDALONE] = "standalone",
        [OVS_BRIDGE_FAIL_MODE_SECURE]     = "secure",
};

DEFINE_STRING_TABLE_LOOKUP(ovs_bridge_fail_mode, OVSBridgeFailMode);

static const char * const ovs_protocol_table[_OVS_PROTOCOL_MAX] = {
        [OVS_PROTOCOL_OPENFLOW10] = "OpenFlow10",
        [OVS_PROTOCOL_OPENFLOW11] = "OpenFlow11",
        [OVS_PROTOCOL_OPENFLOW12] = "OpenFlow12",
        [OVS_PROTOCOL_OPENFLOW13] = "OpenFlow13",
        [OVS_PROTOCOL_OPENFLOW14] = "OpenFlow14",
        [OVS_PROTOCOL_OPENFLOW15] = "OpenFlow15",
};

DEFINE_STRING_TABLE_LOOKUP(ovs_protocol, OVSProtocol);

static void ovs_bridge_init(NetDev *netdev) {
        OVSBridge *b = OVS_BRIDGE(netdev);

        b->fail_mode = _OVS_BRIDGE_FAIL_MODE_INVALID;
        b->stp = -1;
        b->rstp = -1;
        b->mcast_snooping = -1;
}

static void ovs_bridge_done(NetDev *netdev) {
        OVSBridge *b = OVS_BRIDGE(netdev);

        free(b->datapath_type);
        free(b->protocols);
        free(b->datapath_id);
}

static int ovs_bridge_create(NetDev *netdev) {
        netdev->state = NETDEV_STATE_CREATING;
        log_netdev_debug(netdev, "OVS bridge queued for reconciliation");
        return 0;
}

static int ovs_bridge_set_ifindex(NetDev *netdev, const char *name, int ifindex) {
        int r;

        assert(netdev);
        assert(name);
        assert(ifindex > 0);

        if (!streq(netdev->ifname, name))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "Received netlink message with unexpected interface name %s (index=%i).",
                                                name, ifindex);

        r = netdev_set_ifindex_internal(netdev, ifindex);
        if (r <= 0)
                return r;

        /* Kernel has created the OVS bridge interface --- we're ready */
        return netdev_enter_ready(netdev);
}

static int ovs_bridge_verify(NetDev *netdev, const char *filename) {
        OVSBridge *b = OVS_BRIDGE(netdev);

        assert(filename);

        if (b->stp > 0 && b->rstp > 0)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: STP and RSTP are mutually exclusive, ignoring.",
                                                filename);

        /* Don't reject custom datapath types: OVS supports plug-in datapath providers
         * (e.g. "dummy" in test environments, third-party DPDK variants). The string is
         * passed through to OVSDB; ovs-vswitchd validates it server-side. */

        if (b->datapath_id &&
            (strlen(b->datapath_id) != 16 || !in_charset(b->datapath_id, HEXDIGITS)))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: DatapathID= must be exactly 16 hex characters, ignoring.",
                                                filename);

        /* ovs-vswitchd rejects an all-zero other_config:datapath-id. */
        if (b->datapath_id && streq(b->datapath_id, "0000000000000000"))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: DatapathID= must not be all zeros, ignoring.",
                                                filename);

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_ovs_bridge_fail_mode, ovs_bridge_fail_mode, OVSBridgeFailMode, _OVS_BRIDGE_FAIL_MODE_INVALID);
DEFINE_CONFIG_PARSE_ENUMV(config_parse_ovs_protocols, ovs_protocol, OVSProtocol, _OVS_PROTOCOL_INVALID);

const NetDevVTable ovs_bridge_vtable = {
        .object_size = sizeof(OVSBridge),
        .init = ovs_bridge_init,
        .done = ovs_bridge_done,
        .sections = NETDEV_COMMON_SECTIONS "OVSBridge\0",
        .create = ovs_bridge_create,
        .set_ifindex = ovs_bridge_set_ifindex,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = ovs_bridge_verify,
        .iftype = ARPHRD_ETHER,
        .skip_netdev_kind_check = true,
        .keep_on_drop = true,
};
