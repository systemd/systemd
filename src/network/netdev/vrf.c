/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>

#include "sd-netlink.h"

#include "networkd-route-util.h"
#include "vrf.h"

int config_parse_vrf_table(
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

        Vrf *vrf = ASSERT_PTR(userdata);
        uint32_t *table = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = manager_get_route_table_from_string(vrf->meta.manager, rvalue, table);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        return 0;
}

static int netdev_vrf_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        assert(!link);
        assert(m);

        Vrf *v = VRF(netdev);
        int r;

        r = sd_netlink_message_append_u32(m, IFLA_VRF_TABLE, v->table);
        if (r < 0)
                return r;

        return 0;
}

static bool vrf_can_set_mac(NetDev *netdev, const struct hw_addr_data *hw_addr) {
        return true;
}

const NetDevVTable vrf_vtable = {
        .object_size = sizeof(Vrf),
        .sections = NETDEV_COMMON_SECTIONS "VRF\0",
        .fill_message_create = netdev_vrf_fill_message_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .can_set_mac = vrf_can_set_mac,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
        .keep_existing = true,
};
