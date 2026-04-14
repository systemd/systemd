/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>

#include "netdev.h"
#include "ovs-bridge.h"
#include "string-util.h"
#include "strv.h"

static void ovs_bridge_init(NetDev *netdev) {
        OVSBridge *b = OVS_BRIDGE(netdev);

        b->stp = -1;
        b->rstp = -1;
        b->mcast_snooping = -1;
}

static void ovs_bridge_done(NetDev *netdev) {
        OVSBridge *b = OVS_BRIDGE(netdev);

        free(b->fail_mode);
        free(b->datapath_type);
        strv_free(b->protocols);
        free(b->datapath_id);
}

static int ovs_bridge_create(NetDev *netdev) {
#if !ENABLE_OPENVSWITCH
        return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EOPNOTSUPP),
                "Open vSwitch support not compiled in. Rebuild with -Dopenvswitch=enabled.");
#else
        netdev->state = NETDEV_STATE_CREATING;
        log_netdev_debug(netdev, "OVS bridge queued for reconciliation");
        return 0;
#endif
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
                                                "%s: STP and RSTP are mutually exclusive. Ignoring.",
                                                filename);

        if (b->datapath_type && !STR_IN_SET(b->datapath_type, "system", "netdev"))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: invalid DatapathType='%s', must be 'system' or 'netdev'. Ignoring.",
                                                filename, b->datapath_type);

        if (b->datapath_id &&
            (strlen(b->datapath_id) != 16 || !in_charset(b->datapath_id, HEXDIGITS)))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: DatapathID= must be exactly 16 hex characters, ignoring.",
                                                filename);

        return 0;
}

int config_parse_ovs_bridge_fail_mode(
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

        OVSBridge *b = OVS_BRIDGE(ASSERT_PTR(userdata));

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                b->fail_mode = mfree(b->fail_mode);
                return 0;
        }

        if (!STR_IN_SET(rvalue, "standalone", "secure")) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid OVS bridge fail mode '%s', ignoring.", rvalue);
                return 0;
        }

        return free_and_strdup_warn(&b->fail_mode, rvalue);
}

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
};
