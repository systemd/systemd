/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <linux/if.h>
#include <netinet/ether.h>

#include "alloc-util.h"
#include "condition.h"
#include "ether-addr-util.h"
#include "net-condition.h"
#include "network-util.h"
#include "string-table.h"
#include "strv.h"

static bool net_condition_test_strv(char * const *patterns, const char *string) {
        char * const *p;
        bool match = false, has_positive_rule = false;

        if (strv_isempty(patterns))
                return true;

        STRV_FOREACH(p, patterns) {
                const char *q = *p;
                bool invert;

                invert = *q == '!';
                q += invert;

                if (!invert)
                        has_positive_rule = true;

                if (string && fnmatch(q, string, 0) == 0) {
                        if (invert)
                                return false;
                        else
                                match = true;
                }
        }

        return has_positive_rule ? match : true;
}

static bool net_condition_test_ifname(char * const *patterns, const char *ifname, char * const *alternative_names) {
        if (net_condition_test_strv(patterns, ifname))
                return true;

        char * const *p;
        STRV_FOREACH(p, alternative_names)
                if (net_condition_test_strv(patterns, *p))
                        return true;

        return false;
}

static int net_condition_test_property(char * const *match_property, sd_device *device) {
        char * const *p;

        if (strv_isempty(match_property))
                return true;

        STRV_FOREACH(p, match_property) {
                _cleanup_free_ char *key = NULL;
                const char *val, *dev_val;
                bool invert, v;

                invert = **p == '!';

                val = strchr(*p + invert, '=');
                if (!val)
                        return -EINVAL;

                key = strndup(*p + invert, val - *p - invert);
                if (!key)
                        return -ENOMEM;

                val++;

                v = device &&
                        sd_device_get_property_value(device, key, &dev_val) >= 0 &&
                        fnmatch(val, dev_val, 0) == 0;

                if (invert ? v : !v)
                        return false;
        }

        return true;
}

static const char *const wifi_iftype_table[NL80211_IFTYPE_MAX+1] = {
        [NL80211_IFTYPE_ADHOC] = "ad-hoc",
        [NL80211_IFTYPE_STATION] = "station",
        [NL80211_IFTYPE_AP] = "ap",
        [NL80211_IFTYPE_AP_VLAN] = "ap-vlan",
        [NL80211_IFTYPE_WDS] = "wds",
        [NL80211_IFTYPE_MONITOR] = "monitor",
        [NL80211_IFTYPE_MESH_POINT] = "mesh-point",
        [NL80211_IFTYPE_P2P_CLIENT] = "p2p-client",
        [NL80211_IFTYPE_P2P_GO] = "p2p-go",
        [NL80211_IFTYPE_P2P_DEVICE] = "p2p-device",
        [NL80211_IFTYPE_OCB] = "ocb",
        [NL80211_IFTYPE_NAN] = "nan",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(wifi_iftype, enum nl80211_iftype);

bool net_match_config(Set *match_mac,
                      Set *match_permanent_mac,
                      char * const *match_paths,
                      char * const *match_drivers,
                      char * const *match_iftypes,
                      char * const *match_names,
                      char * const *match_property,
                      char * const *match_wifi_iftype,
                      char * const *match_ssid,
                      Set *match_bssid,
                      sd_device *device,
                      const struct ether_addr *dev_mac,
                      const struct ether_addr *dev_permanent_mac,
                      const char *dev_driver,
                      unsigned short dev_iftype,
                      const char *dev_name,
                      char * const *alternative_names,
                      enum nl80211_iftype dev_wifi_iftype,
                      const char *dev_ssid,
                      const struct ether_addr *dev_bssid) {

        _cleanup_free_ char *dev_iftype_str;
        const char *dev_path = NULL;

        dev_iftype_str = link_get_type_string(dev_iftype, device);

        if (device) {
                const char *mac_str;

                (void) sd_device_get_property_value(device, "ID_PATH", &dev_path);
                if (!dev_driver)
                        (void) sd_device_get_property_value(device, "ID_NET_DRIVER", &dev_driver);
                if (!dev_name)
                        (void) sd_device_get_sysname(device, &dev_name);
                if (!dev_mac &&
                    sd_device_get_sysattr_value(device, "address", &mac_str) >= 0)
                        dev_mac = ether_aton(mac_str);
        }

        if (match_mac && (!dev_mac || !set_contains(match_mac, dev_mac)))
                return false;

        if (match_permanent_mac &&
            (!dev_permanent_mac ||
             ether_addr_is_null(dev_permanent_mac) ||
             !set_contains(match_permanent_mac, dev_permanent_mac)))
                return false;

        if (!net_condition_test_strv(match_paths, dev_path))
                return false;

        if (!net_condition_test_strv(match_drivers, dev_driver))
                return false;

        if (!net_condition_test_strv(match_iftypes, dev_iftype_str))
                return false;

        if (!net_condition_test_ifname(match_names, dev_name, alternative_names))
                return false;

        if (!net_condition_test_property(match_property, device))
                return false;

        if (!net_condition_test_strv(match_wifi_iftype, wifi_iftype_to_string(dev_wifi_iftype)))
                return false;

        if (!net_condition_test_strv(match_ssid, dev_ssid))
                return false;

        if (match_bssid && (!dev_bssid || !set_contains(match_bssid, dev_bssid)))
                return false;

        return true;
}
