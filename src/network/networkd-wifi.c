/* SPDX-License-Identifier: LGPL-2.1+ */

#include <net/ethernet.h>
#include <linux/nl80211.h>

#include "sd-bus.h"

#include "bus-util.h"
#include "netlink-internal.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-wifi.h"
#include "string-util.h"

int wifi_get_ssid(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL, *reply = NULL;
        _cleanup_free_ char *ssid = NULL;
        sd_genl_family family;
        const char *type;
        int r;

        if (!link->sd_device)
                return 0;

        r = sd_device_get_devtype(link->sd_device, &type);
        if (r == -ENOENT)
                return 0;
        else if (r < 0)
                return r;

        if (!streq(type, "wlan"))
                return 0;

        r = sd_genl_message_new(link->manager->genl, SD_GENL_NL80211, NL80211_CMD_GET_INTERFACE, &m);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to create generic netlink message: %m");

        r = sd_netlink_message_append_u32(m, NL80211_ATTR_IFINDEX, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NL80211_ATTR_IFINDEX attribute: %m");

        r = sd_netlink_call(link->manager->genl, m, 0, &reply);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request information about wifi interface: %m");
        if (!reply)
                return 0;

        r = sd_netlink_message_get_errno(reply);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get information about wifi interface: %m");

        r = sd_genl_message_get_family(link->manager->genl, reply, &family);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to determine genl family: %m");
        if (family != SD_GENL_NL80211) {
                log_link_debug(link, "Received message of unexpected genl family %u, ignoring.", family);
                return 0;
        }

        r = sd_netlink_message_read_string_strdup(reply, NL80211_ATTR_SSID, &ssid);
        if (r < 0 && r != -ENODATA)
                return log_link_warning_errno(link, r, "Failed to get NL80211_ATTR_SSID attribute: %m");

        free_and_replace(link->ssid, ssid);
        if (link->ssid)
                log_link_info(link, "Connected SSID: %s", link->ssid);

        return r;
}
