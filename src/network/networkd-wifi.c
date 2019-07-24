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

static int wifi_get_ssid(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL, *reply = NULL;
        _cleanup_free_ char *ssid = NULL;
        sd_genl_family family;
        int r;

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
        return r == -ENODATA ? 0 : 1;
}

static int wifi_get_bssid(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL, *reply = NULL;
        struct ether_addr mac = {};
        sd_genl_family family;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->genl);

        r = sd_genl_message_new(link->manager->genl, SD_GENL_NL80211, NL80211_CMD_GET_STATION, &m);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to create generic netlink message: %m");

        r = sd_netlink_message_set_flags(m, NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set dump flag: %m");

        r = sd_netlink_message_append_u32(m, NL80211_ATTR_IFINDEX, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NL80211_ATTR_IFINDEX attribute: %m");

        r = sd_netlink_call(link->manager->genl, m, 0, &reply);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request information about wifi station: %m");
        if (!reply)
                return 0;

        r = sd_netlink_message_get_errno(reply);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get information about wifi station: %m");

        r = sd_genl_message_get_family(link->manager->genl, reply, &family);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to determine genl family: %m");
        if (family != SD_GENL_NL80211) {
                log_link_debug(link, "Received message of unexpected genl family %u, ignoring.", family);
                return 0;
        }

        r = sd_netlink_message_read_ether_addr(reply, NL80211_ATTR_MAC, &mac);
        if (r < 0 && r != -ENODATA)
                return log_link_warning_errno(link, r, "Failed to get NL80211_ATTR_MAC attribute: %m");

        r = memcmp(&link->bssid, &mac, sizeof(mac));
        if (r == 0)
                return 0;

        memcpy(&link->bssid, &mac, sizeof(mac));
        return 1;
}

int wifi_get_info(Link *link) {
        char buf[ETHER_ADDR_TO_STRING_MAX];
        const char *type;
        int r, s;

        assert(link);

        if (!link->sd_device)
                return 0;

        r = sd_device_get_devtype(link->sd_device, &type);
        if (r == -ENOENT)
                return 0;
        else if (r < 0)
                return r;

        if (!streq(type, "wlan"))
                return 0;

        r = wifi_get_ssid(link);
        if (r < 0)
                return r;

        s = wifi_get_bssid(link);
        if (s < 0)
                return s;

        if (r > 0 || s > 0) {
                if (link->ssid)
                        log_link_info(link, "Connected WiFi access point: %s (%s)",
                                      link->ssid, ether_addr_to_string(&link->bssid, buf));
                return 1;
        }
        return 0;
}
