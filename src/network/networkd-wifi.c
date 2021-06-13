/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/ethernet.h>
#include <linux/nl80211.h>

#include "sd-bus.h"

#include "bus-util.h"
#include "ether-addr-util.h"
#include "netlink-internal.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-wifi.h"
#include "string-util.h"
#include "wifi-util.h"

int wifi_get_info(Link *link) {
        _cleanup_free_ char *ssid = NULL;
        enum nl80211_iftype iftype;
        bool updated = false;
        const char *type;
        int r;

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

        r = wifi_get_interface(link->manager->genl, link->ifindex, &iftype, &ssid);
        if (r < 0)
                return r;
        if (r == 0)
                iftype = link->wlan_iftype; /* Assume iftype is not changed. */

        if (iftype == NL80211_IFTYPE_STATION) {
                struct ether_addr bssid;

                r = wifi_get_station(link->manager->genl, link->ifindex, &bssid);
                if (r < 0)
                        return r;

                updated = !ether_addr_equal(&link->bssid, &bssid);
                link->bssid = bssid;
        }

        updated = updated || link->wlan_iftype != iftype;
        link->wlan_iftype = iftype;
        updated = updated || !streq_ptr(link->ssid, ssid);
        free_and_replace(link->ssid, ssid);

        if (updated) {
                if (link->wlan_iftype == NL80211_IFTYPE_STATION && link->ssid)
                        log_link_info(link, "Connected WiFi access point: %s (%s)",
                                      link->ssid, ETHER_ADDR_TO_STR(&link->bssid));

                return 1; /* Some information is updated. */
        }

        return 0; /* No new information. */
}
