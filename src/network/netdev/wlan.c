/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "sd-netlink.h"

#include "netlink-util.h"
#include "networkd-manager.h"
#include "networkd-wiphy.h"
#include "parse-util.h"
#include "wifi-util.h"
#include "wlan.h"

static void wlan_done(NetDev *netdev) {
        WLan *w = WLAN(netdev);

        w->wiphy_name = mfree(w->wiphy_name);
}

static void wlan_init(NetDev *netdev) {
        WLan *w = WLAN(netdev);

        w->wiphy_index = UINT32_MAX;
        w->wds = -1;
}

static int wlan_get_wiphy(NetDev *netdev, Wiphy **ret) {
        WLan *w = WLAN(netdev);

        if (!netdev_is_managed(netdev))
                return -ENOENT; /* Already detached, due to e.g. reloading .netdev files. */

        if (w->wiphy_name)
                return wiphy_get_by_name(netdev->manager, w->wiphy_name, ret);

        return wiphy_get_by_index(netdev->manager, w->wiphy_index, ret);
}

static int wlan_is_ready_to_create(NetDev *netdev, Link *link) {
        return wlan_get_wiphy(netdev, NULL) >= 0;
}

static int wlan_fill_message(NetDev *netdev, sd_netlink_message *m) {
        WLan *w = WLAN(netdev);
        Wiphy *wiphy;
        int r;

        r = wlan_get_wiphy(netdev, &wiphy);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NL80211_ATTR_WIPHY, wiphy->index);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NL80211_ATTR_IFNAME, netdev->ifname);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NL80211_ATTR_IFTYPE, w->iftype);
        if (r < 0)
                return r;

        if (!hw_addr_is_null(&netdev->hw_addr) && netdev->hw_addr.length == ETH_ALEN) {
                r = sd_netlink_message_append_ether_addr(m, NL80211_ATTR_MAC, &netdev->hw_addr.ether);
                if (r < 0)
                        return r;
        }

        if (w->wds >= 0) {
                r = sd_netlink_message_append_u8(m, NL80211_ATTR_4ADDR, w->wds);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int wlan_create_handler(sd_netlink *genl, sd_netlink_message *m, NetDev *netdev) {
        int r;

        assert(netdev);
        assert(netdev->state != _NETDEV_STATE_INVALID);

        r = sd_netlink_message_get_errno(m);
        if (IN_SET(r, -EEXIST, -ENFILE))
                /* Unlike the other netdevs, the kernel may return -ENFILE. See dev_alloc_name(). */
                log_netdev_info(netdev, "WLAN interface exists, using existing without changing its parameters.");
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r, "WLAN interface could not be created: %m");
                netdev_enter_failed(netdev);

                return 1;
        }

        log_netdev_debug(netdev, "WLAN interface is created.");
        return 1;
}

static int wlan_create(NetDev *netdev) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(netdev);
        assert(netdev->manager);
        assert(netdev->manager->genl);

        r = sd_genl_message_new(netdev->manager->genl, NL80211_GENL_NAME, NL80211_CMD_NEW_INTERFACE, &m);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to allocate netlink message: %m");

        r = wlan_fill_message(netdev, m);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to fill netlink message: %m");

        r = netlink_call_async(netdev->manager->genl, NULL, m, wlan_create_handler,
                               netdev_destroy_callback, netdev);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to send netlink message: %m");

        netdev_ref(netdev);
        return 0;
}

static int wlan_verify(NetDev *netdev, const char *filename) {
        WLan *w = WLAN(netdev);

        assert(filename);

        if (w->iftype == NL80211_IFTYPE_UNSPECIFIED)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: WLAN interface type is not specified, ignoring.",
                                                filename);

        if (w->wiphy_index == UINT32_MAX && isempty(w->wiphy_name))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: physical WLAN device is not specified, ignoring.",
                                                filename);

        return 0;
}

int config_parse_wiphy(
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

        WLan *w = WLAN(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                w->wiphy_name = mfree(w->wiphy_name);
                w->wiphy_index = UINT32_MAX;
                return 0;
        }

        r = safe_atou32(rvalue, &w->wiphy_index);
        if (r >= 0) {
                w->wiphy_name = mfree(w->wiphy_name);
                return 0;
        }

        r = free_and_strdup_warn(&w->wiphy_name, rvalue);
        if (r < 0)
                return r;

        w->wiphy_index = UINT32_MAX;
        return 0;
}

int config_parse_wlan_iftype(
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

        enum nl80211_iftype t, *iftype = ASSERT_PTR(data);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *iftype = NL80211_IFTYPE_UNSPECIFIED;
                return 0;
        }

        t = nl80211_iftype_from_string(rvalue);
        /* We reuse the kernel provided enum which does not contain negative value. So, the cast
         * below is mandatory. Otherwise, the check below always passes. */
        if ((int) t < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, t,
                           "Failed to parse wlan interface type, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        *iftype = t;
        return 0;
}

const NetDevVTable wlan_vtable = {
        .object_size = sizeof(WLan),
        .init = wlan_init,
        .done = wlan_done,
        .sections = NETDEV_COMMON_SECTIONS "WLAN\0",
        .is_ready_to_create = wlan_is_ready_to_create,
        .create = wlan_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = wlan_verify,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
        .skip_netdev_kind_check = true,
};
