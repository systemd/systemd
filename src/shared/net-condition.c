/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/ether.h>

#include "condition.h"
#include "env-util.h"
#include "log.h"
#include "net-condition.h"
#include "network-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "strv.h"

void net_match_clear(NetMatch *match) {
        if (!match)
                return;

        match->mac = set_free_free(match->mac);
        match->permanent_mac = set_free_free(match->permanent_mac);
        match->path = strv_free(match->path);
        match->driver = strv_free(match->driver);
        match->iftype = strv_free(match->iftype);
        match->ifname = strv_free(match->ifname);
        match->property = strv_free(match->property);
        match->wifi_iftype = strv_free(match->wifi_iftype);
        match->ssid = strv_free(match->ssid);
        match->bssid = set_free_free(match->bssid);
}

bool net_match_is_empty(const NetMatch *match) {
        assert(match);

        return
                set_isempty(match->mac) &&
                set_isempty(match->permanent_mac) &&
                strv_isempty(match->path) &&
                strv_isempty(match->driver) &&
                strv_isempty(match->iftype) &&
                strv_isempty(match->ifname) &&
                strv_isempty(match->property) &&
                strv_isempty(match->wifi_iftype) &&
                strv_isempty(match->ssid) &&
                set_isempty(match->bssid);
}

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

bool net_match_config(
                const NetMatch *match,
                sd_device *device,
                const struct ether_addr *mac,
                const struct ether_addr *permanent_mac,
                const char *driver,
                unsigned short iftype,
                const char *ifname,
                char * const *alternative_names,
                enum nl80211_iftype wifi_iftype,
                const char *ssid,
                const struct ether_addr *bssid) {

        _cleanup_free_ char *iftype_str;
        const char *path = NULL;

        assert(match);

        iftype_str = link_get_type_string(device, iftype);

        if (device) {
                const char *mac_str;

                (void) sd_device_get_property_value(device, "ID_PATH", &path);
                if (!driver)
                        (void) sd_device_get_property_value(device, "ID_NET_DRIVER", &driver);
                if (!ifname)
                        (void) sd_device_get_sysname(device, &ifname);
                if (!mac &&
                    sd_device_get_sysattr_value(device, "address", &mac_str) >= 0)
                        mac = ether_aton(mac_str);
        }

        if (match->mac && (!mac || !set_contains(match->mac, mac)))
                return false;

        if (match->permanent_mac &&
            (!permanent_mac ||
             ether_addr_is_null(permanent_mac) ||
             !set_contains(match->permanent_mac, permanent_mac)))
                return false;

        if (!net_condition_test_strv(match->path, path))
                return false;

        if (!net_condition_test_strv(match->driver, driver))
                return false;

        if (!net_condition_test_strv(match->iftype, iftype_str))
                return false;

        if (!net_condition_test_ifname(match->ifname, ifname, alternative_names))
                return false;

        if (!net_condition_test_property(match->property, device))
                return false;

        if (!net_condition_test_strv(match->wifi_iftype, wifi_iftype_to_string(wifi_iftype)))
                return false;

        if (!net_condition_test_strv(match->ssid, ssid))
                return false;

        if (match->bssid && (!bssid || !set_contains(match->bssid, bssid)))
                return false;

        return true;
}

int config_parse_net_condition(
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

        ConditionType cond = ltype;
        Condition **list = data, *c;
        bool negate;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *list = condition_free_list_type(*list, cond);
                return 0;
        }

        negate = rvalue[0] == '!';
        if (negate)
                rvalue++;

        c = condition_new(cond, rvalue, false, negate);
        if (!c)
                return log_oom();

        /* Drop previous assignment. */
        *list = condition_free_list_type(*list, cond);

        LIST_PREPEND(conditions, *list, c);
        return 0;
}

int config_parse_match_strv(
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

        const char *p = rvalue;
        char ***sv = data;
        bool invert;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *sv = strv_free(*sv);
                return 0;
        }

        invert = *p == '!';
        p += invert;

        for (;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                if (invert) {
                        k = strjoin("!", word);
                        if (!k)
                                return log_oom();
                } else
                        k = TAKE_PTR(word);

                r = strv_consume(sv, TAKE_PTR(k));
                if (r < 0)
                        return log_oom();
        }
}

int config_parse_match_ifnames(
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

        const char *p = rvalue;
        char ***sv = data;
        bool invert;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *sv = strv_free(*sv);
                return 0;
        }

        invert = *p == '!';
        p += invert;

        for (;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Failed to parse interface name list, ignoring: %s", rvalue);
                        return 0;
                }

                if (!ifname_valid_full(word, ltype)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Interface name is not valid or too long, ignoring assignment: %s", word);
                        continue;
                }

                if (invert) {
                        k = strjoin("!", word);
                        if (!k)
                                return log_oom();
                } else
                        k = TAKE_PTR(word);

                r = strv_consume(sv, TAKE_PTR(k));
                if (r < 0)
                        return log_oom();
        }
}

int config_parse_match_property(
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

        const char *p = rvalue;
        char ***sv = data;
        bool invert;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *sv = strv_free(*sv);
                return 0;
        }

        invert = *p == '!';
        p += invert;

        for (;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                if (!env_assignment_is_valid(word)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid property or value, ignoring assignment: %s", word);
                        continue;
                }

                if (invert) {
                        k = strjoin("!", word);
                        if (!k)
                                return log_oom();
                } else
                        k = TAKE_PTR(word);

                r = strv_consume(sv, TAKE_PTR(k));
                if (r < 0)
                        return log_oom();
        }
}
