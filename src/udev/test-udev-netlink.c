/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "arphrd-list.h"
#include "ether-addr-util.h"
#include "parse-util.h"
#include "tests.h"
#include "udev-netlink.h"

static void test_link_info_one(sd_netlink *rtnl, int ifindex) {
        _cleanup_(link_info_clear) LinkInfo info = LINK_INFO_NULL;
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        unsigned iftype, iflink;
        const char *s;

        log_debug("/* %s(ifindex=%i) */", __func__, ifindex);

        assert_se(link_info_get(&rtnl, ifindex, &info) >= 0);
        assert_se(sd_device_new_from_ifindex(&dev, ifindex) >= 0);

        /* check iftype */
        log_debug("iftype: %"PRIu16" (%s)", info.iftype, strna(arphrd_to_name(info.iftype)));
        assert_se(sd_device_get_sysattr_value(dev, "type", &s) >= 0);
        assert_se(safe_atou(s, &iftype) >= 0);
        assert_se(iftype == info.iftype);

        /* check hardware address */
        log_debug("hardware address: %s", HW_ADDR_TO_STR(&info.hw_addr));
        assert_se(sd_device_get_sysattr_value(dev, "address", &s) >= 0);
        assert_se(streq(s, HW_ADDR_TO_STR(&info.hw_addr)));

        /* check ifname */
        log_debug("ifname: %s", info.ifname);
        assert_se(sd_device_get_sysname(dev, &s) >= 0);
        assert_se(streq(s, info.ifname));

        /* check iflink */
        log_debug("iflink: %"PRIu32, info.iflink);
        assert_se(sd_device_get_sysattr_value(dev, "iflink", &s) >= 0);
        assert_se(safe_atou(s, &iflink) >= 0);
        assert_se(iflink == info.iflink);

        /* check phys_port_name */
        log_debug("phys_port_name: %s (%s)",
                  strna(info.phys_port_name),
                  info.support_phys_port_name ? "supported" : "unsupported");
        if (info.support_phys_port_name) {
                s = NULL;
                (void) sd_device_get_sysattr_value(dev, "phys_port_name", &s);
                assert_se(streq_ptr(s, info.phys_port_name));
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
