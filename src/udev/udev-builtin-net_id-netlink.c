/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netlink-util.h"
#include "udev-builtin-net_id-netlink.h"

void link_info_clear(LinkInfo *info) {
        if (!info)
                return;

        info->ifname = mfree(info->ifname);
        info->phys_port_name = mfree(info->phys_port_name);
}

int link_info_get(sd_netlink **rtnl, int ifindex, LinkInfo *ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;
        _cleanup_(link_info_clear) LinkInfo info = LINK_INFO_NULL;
        uint16_t nlmsg_type;
        int r;

        assert(rtnl);
        assert(ifindex > 0);
        assert(ret);

        if (!*rtnl) {
                r = sd_netlink_open(rtnl);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_new_link(*rtnl, &message, RTM_GETLINK, ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_call(*rtnl, message, 0, &reply);
        if (r == -EINVAL)
                return -ENODEV; /* The device does not exist */
        if (r < 0)
                return r;

        r = sd_netlink_message_get_type(reply, &nlmsg_type);
        if (r < 0)
                return r;
        if (nlmsg_type != RTM_NEWLINK)
                return -ENXIO;

        r = sd_rtnl_message_link_get_ifindex(reply, &info.ifindex);
        if (r < 0)
                return r;
        if (info.ifindex != ifindex)
                return -ENXIO;

        r = sd_rtnl_message_link_get_type(reply, &info.iftype);
        if (r < 0)
                return r;

        r = netlink_message_read_hw_addr(reply, IFLA_ADDRESS, &info.hw_addr);
        if (r < 0 && r != -ENODATA)
                return r;

        r = sd_netlink_message_read_string_strdup(reply, IFLA_IFNAME, &info.ifname);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_u32(reply, IFLA_LINK, &info.iflink);
        if (r == -ENODATA)
                info.iflink = info.ifindex;
        else if (r < 0)
                return r;

        r = sd_netlink_message_read_string_strdup(reply, IFLA_PHYS_PORT_NAME, &info.phys_port_name);
        if (r == -ENODATA) {
                uint16_t max_attr;

                r = sd_netlink_message_get_max_attribute(reply, &max_attr);
                if (r < 0)
                        return r;

                info.support_phys_port_name = max_attr >= IFLA_PHYS_PORT_NAME;
        } else if (r >= 0)
                info.support_phys_port_name = true;
        else
                return r;

        *ret = info;
        info = LINK_INFO_NULL;
        return 0;
}
