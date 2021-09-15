/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-private.h"
#include "netlink-util.h"
#include "strv.h"
#include "udev-netlink.h"

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

static int cache_unsigned(sd_device *device, const char *attr, uint64_t val) {
        _cleanup_free_ char *str = NULL;
        int r;

        assert(device);
        assert(attr);

        if (device_get_cached_sysattr_value(device, attr, NULL) != -ESTALE)
                return 0;

        if (asprintf(&str, "%"PRIu64, val) < 0)
                return -ENOMEM;

        r = device_cache_sysattr_value(device, attr, str);
        if (r < 0)
                return r;

        TAKE_PTR(str);
        return 0;
}

static int cache_hw_addr(sd_device *device, const char *attr, const struct hw_addr_data *hw_addr) {
        _cleanup_free_ char *str = NULL;
        int r;

        assert(device);
        assert(attr);
        assert(hw_addr);

        if (device_get_cached_sysattr_value(device, attr, NULL) != -ESTALE)
                return 0;

        str = new(char, HW_ADDR_TO_STRING_MAX);
        if (!str)
                return -ENOMEM;

        r = device_cache_sysattr_value(device, attr, hw_addr_to_string(hw_addr, str));
        if (r < 0)
                return r;

        TAKE_PTR(str);
        return 0;
}

static int cache_string(sd_device *device, const char *attr, const char *val) {
        _cleanup_free_ char *str = NULL;
        int r;

        assert(device);
        assert(attr);

        if (device_get_cached_sysattr_value(device, attr, NULL) != -ESTALE)
                return 0;

        if (val) {
                str = strdup(val);
                if (!str)
                        return -ENOMEM;
        }

        r = device_cache_sysattr_value(device, attr, str);
        if (r < 0)
                return r;

        TAKE_PTR(str);
        return 0;
}

int device_cache_sysattr_from_link_info(sd_device *device, LinkInfo *info) {
        int ifindex, r;

        assert(device);
        assert(info);

        r = sd_device_get_ifindex(device, &ifindex);
        if (r < 0)
                return r;

        if (ifindex != info->ifindex)
                return -EINVAL;

        r = cache_unsigned(device, "type", info->iftype);
        if (r < 0)
                return r;

        r = cache_hw_addr(device, "address", &info->hw_addr);
        if (r < 0)
                return r;

        r = cache_unsigned(device, "iflink", info->iflink);
        if (r < 0)
                return r;

        if (info->support_phys_port_name) {
                r = cache_string(device, "phys_port_name", info->phys_port_name);
                if (r < 0)
                        return r;
        }

        return 0;
}

int device_get_sysattr_value_maybe_from_netlink(
                sd_device *device,
                sd_netlink **rtnl,
                const char *sysattr,
                const char **ret_value) {

        _cleanup_(link_info_clear) LinkInfo info = LINK_INFO_NULL;
        int ifindex, r;

        assert(device);
        assert(rtnl);
        assert(sysattr);

        if (sd_device_get_ifindex(device, &ifindex) < 0)
                return sd_device_get_sysattr_value(device, sysattr, ret_value);

        if (!STR_IN_SET(sysattr, "type", "address", "iflink", "phys_port_name"))
                return sd_device_get_sysattr_value(device, sysattr, ret_value);

        r = device_get_cached_sysattr_value(device, sysattr, ret_value);
        if (r != -ESTALE)
                return r;

        r = link_info_get(rtnl, ifindex, &info);
        if (r < 0)
                return r;

        r = device_cache_sysattr_from_link_info(device, &info);
        if (r < 0)
                return r;

        /* Do not use device_get_cached_sysattr_value() here, as kernel may not support
         * IFLA_PHYS_PORT_NAME, and in that case we need to read the value from sysfs. */
        return sd_device_get_sysattr_value(device, sysattr, ret_value);
}
