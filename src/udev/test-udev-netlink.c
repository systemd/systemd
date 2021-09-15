/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "arphrd-list.h"
#include "ether-addr-util.h"
#include "parse-util.h"
#include "tests.h"
#include "udev-netlink.h"

static void test_link_info_one(sd_netlink *rtnl, int ifindex) {
        _cleanup_(link_info_clear) LinkInfo info = LINK_INFO_NULL;
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL, *dev_with_netlink = NULL;
        const char *s, *t;
        unsigned u;

        log_debug("/* %s(ifindex=%i) */", __func__, ifindex);

        assert_se(link_info_get(&rtnl, ifindex, &info) >= 0);
        assert_se(sd_device_new_from_ifindex(&dev, ifindex) >= 0);
        assert_se(sd_device_new_from_ifindex(&dev_with_netlink, ifindex) >= 0);

        /* check iftype */
        log_debug("iftype: %"PRIu16" (%s)", info.iftype, strna(arphrd_to_name(info.iftype)));
        assert_se(sd_device_get_sysattr_value(dev, "type", &s) >= 0);
        assert_se(safe_atou(s, &u) >= 0);
        assert_se(u == info.iftype);
        assert_se(device_get_sysattr_value_maybe_from_netlink(dev_with_netlink, &rtnl, "type", &s) >= 0);
        assert_se(safe_atou(s, &u) >= 0);
        assert_se(u == info.iftype);

        /* check hardware address length */
        log_debug("hardware address length: %zu", info.hw_addr.length);
        assert_se(sd_device_get_sysattr_value(dev, "addr_len", &s) >= 0);
        assert_se(safe_atou(s, &u) >= 0);
        assert_se(u == info.hw_addr.length);
        assert_se(device_get_sysattr_value_maybe_from_netlink(dev_with_netlink, &rtnl, "addr_len", &s) >= 0);
        assert_se(safe_atou(s, &u) >= 0);
        assert_se(u == info.hw_addr.length);

        /* check hardware address */
        log_debug("hardware address: %s", HW_ADDR_TO_STR(&info.hw_addr));
        assert_se(sd_device_get_sysattr_value(dev, "address", &s) >= 0);
        assert_se(streq(s, HW_ADDR_TO_STR(&info.hw_addr)));
        assert_se(device_get_sysattr_value_maybe_from_netlink(dev_with_netlink, &rtnl, "address", &s) >= 0);
        assert_se(streq(s, HW_ADDR_TO_STR(&info.hw_addr)));

        /* check broadcast address */
        log_debug("broadcast address: %s", HW_ADDR_TO_STR(&info.broadcast));
        assert_se(sd_device_get_sysattr_value(dev, "broadcast", &s) >= 0);
        assert_se(streq(s, HW_ADDR_TO_STR(&info.broadcast)));
        assert_se(device_get_sysattr_value_maybe_from_netlink(dev_with_netlink, &rtnl, "broadcast", &s) >= 0);
        assert_se(streq(s, HW_ADDR_TO_STR(&info.broadcast)));

        /* check ifname */
        log_debug("ifname: %s", info.ifname);
        assert_se(sd_device_get_sysname(dev, &s) >= 0);
        assert_se(streq(s, info.ifname));
        assert_se(sd_device_get_sysname(dev_with_netlink, &s) >= 0);
        assert_se(streq(s, info.ifname));

        /* check mtu */
        log_debug("mtu: %"PRIu32, info.mtu);
        assert_se(sd_device_get_sysattr_value(dev, "mtu", &s) >= 0);
        assert_se(safe_atou(s, &u) >= 0);
        assert_se(u == info.mtu);
        assert_se(device_get_sysattr_value_maybe_from_netlink(dev_with_netlink, &rtnl, "mtu", &s) >= 0);
        assert_se(safe_atou(s, &u) >= 0);
        assert_se(u == info.mtu);

        /* check iflink */
        log_debug("iflink: %"PRIu32, info.iflink);
        assert_se(sd_device_get_sysattr_value(dev, "iflink", &s) >= 0);
        assert_se(safe_atou(s, &u) >= 0);
        assert_se(u == info.iflink);
        assert_se(device_get_sysattr_value_maybe_from_netlink(dev_with_netlink, &rtnl, "iflink", &s) >= 0);
        assert_se(safe_atou(s, &u) >= 0);
        assert_se(u == info.iflink);

        /* check link_mode */
        log_debug("link_mode: %"PRIu8, info.link_mode);
        assert_se(sd_device_get_sysattr_value(dev, "link_mode", &s) >= 0);
        assert_se(safe_atou(s, &u) >= 0);
        assert_se(u == info.link_mode);
        assert_se(device_get_sysattr_value_maybe_from_netlink(dev_with_netlink, &rtnl, "link_mode", &s) >= 0);
        assert_se(safe_atou(s, &u) >= 0);
        assert_se(u == info.link_mode);

        /* check ifalias */
        log_debug("ifalias: %s", strna(info.ifalias));
        assert_se(sd_device_get_sysattr_value(dev, "ifalias", &s) >= 0);
        assert_se(streq(s, strempty(info.ifalias)));
        assert_se(device_get_sysattr_value_maybe_from_netlink(dev_with_netlink, &rtnl, "ifalias", &s) >= 0);
        assert_se(streq(s, strempty(info.ifalias)));

        /* check netdev_group */
        log_debug("netdev_group: %"PRIu32, info.group);
        assert_se(sd_device_get_sysattr_value(dev, "netdev_group", &s) >= 0);
        assert_se(safe_atou(s, &u) >= 0);
        assert_se(u == info.group);
        assert_se(device_get_sysattr_value_maybe_from_netlink(dev_with_netlink, &rtnl, "netdev_group", &s) >= 0);
        assert_se(safe_atou(s, &u) >= 0);
        assert_se(u == info.group);

        /* check phys_port_id */
        log_debug("phys_port_id: (%s)",
                  info.phys_port_id_supported ? "supported" : "unsupported");
        s = t = NULL;
        (void) sd_device_get_sysattr_value(dev, "phys_port_id", &s);
        (void) device_get_sysattr_value_maybe_from_netlink(dev_with_netlink, &rtnl, "phys_port_id", &t);
        assert_se(streq_ptr(s, t));

        /* check phys_switch_id */
        log_debug("phys_switch_id: (%s)",
                  info.phys_switch_id_supported ? "supported" : "unsupported");
        s = t = NULL;
        (void) sd_device_get_sysattr_value(dev, "phys_switch_id", &s);
        (void) device_get_sysattr_value_maybe_from_netlink(dev_with_netlink, &rtnl, "phys_switch_id", &t);
        assert_se(streq_ptr(s, t));

        /* check phys_port_name */
        log_debug("phys_port_name: %s (%s)",
                  strna(info.phys_port_name),
                  info.phys_port_name_supported ? "supported" : "unsupported");
        s = t = NULL;
        (void) sd_device_get_sysattr_value(dev, "phys_port_name", &s);
        (void) device_get_sysattr_value_maybe_from_netlink(dev_with_netlink, &rtnl, "phys_port_name", &t);
        assert_se(streq_ptr(s, t));
        if (info.phys_port_name_supported) {
                assert_se(streq_ptr(s, info.phys_port_name));
                assert_se(streq_ptr(t, info.phys_port_name));
        }
}

static void test_link_info_get(void) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;

        log_debug("/* %s */", __func__);

        assert_se(sd_netlink_open(&rtnl) >= 0);

        assert_se(sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, 0) >= 0);
        assert_se(sd_netlink_message_request_dump(req, true) >= 0);
        assert_se(sd_netlink_call(rtnl, req, 0, &reply) >= 0);

        for (sd_netlink_message *reply_one = reply; reply_one; reply_one = sd_netlink_message_next(reply_one)) {
                uint16_t nlmsg_type;
                int ifindex;

                assert_se(sd_netlink_message_get_type(reply_one, &nlmsg_type) >= 0);
                assert_se(nlmsg_type == RTM_NEWLINK);
                assert_se(sd_rtnl_message_link_get_ifindex(reply_one, &ifindex) >= 0);

                test_link_info_one(rtnl, ifindex);
        }
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_link_info_get();

        return 0;
}
