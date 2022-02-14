/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-netlink.h"

#include "device-private.h"
#include "link-wifi.h"
#include "log-link.h"
#include "parse-util.h"
#include "socket-util.h"
#include "wifi-util.h"

WLANInterface *wlan_interface_free(WLANInterface *w) {
        if (!w)
                return NULL;

        if (w->config) {
                assert(w->section);
                hashmap_remove(w->config->wlan_interfaces_by_section, w->section);
        }

        config_section_free(w->section);

        free(w->ifname);

        return mfree(w);
}

static int wlan_interface_new_static(LinkConfig *config, const char *filename, unsigned section_line, WLANInterface **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(wlan_interface_freep) WLANInterface *w = NULL;
        int r;

        assert(config);
        assert(filename);
        assert(section_line > 0);
        assert(ret);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        w = hashmap_get(config->wlan_interfaces_by_section, n);
        if (w) {
                *ret = TAKE_PTR(w);
                return 0;
        }

        w = new(WLANInterface, 1);
        if (!w)
                return -ENOMEM;

        *w = (WLANInterface) {
                .config = config,
                .section = TAKE_PTR(n),
        };

        r = hashmap_ensure_put(&config->wlan_interfaces_by_section, &config_section_hash_ops, w->section, w);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(w);
        return 0;
}

static int wlan_interface_configure(sd_netlink **genl, Link *link, WLANInterface *w) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(genl);
        assert(link);
        assert(link->device);
        assert(w);

        if (!*genl) {
                r = sd_genl_socket_open(genl);
                if (r < 0)
                        return r;
        }

        r = sd_genl_message_new(*genl, NL80211_GENL_NAME, NL80211_CMD_NEW_INTERFACE, &req);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(req, NL80211_ATTR_IFINDEX, link->ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(req, NL80211_ATTR_IFNAME, w->ifname);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(req, NL80211_ATTR_IFTYPE, w->iftype);
        if (r < 0)
                return r;

        if (!ether_addr_is_null(&w->mac)) {
                r = sd_netlink_message_append_ether_addr(req, NL80211_ATTR_MAC, &w->mac);
                if (r < 0)
                        return r;
        }

        if (w->wds >= 0) {
                r = sd_netlink_message_append_u8(req, NL80211_ATTR_4ADDR, w->wds);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_call(*genl, req, 0, NULL);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to create new wlan interface %s, ignoring: %m", w->ifname);

        return 0;
}

int link_apply_wlan_interface_config(Link *link) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *genl = NULL;
        const char *devtype;
        WLANInterface *w;
        int r;

        assert(link);
        assert(link->config);
        assert(link->device);

        if (sd_device_get_devtype(link->device, &devtype) < 0 || !streq(devtype, "wlan")) {
                if (!hashmap_isempty(link->config->wlan_interfaces_by_section))
                        log_link_debug(link, "Not a wlan interface, ignoring [VirtualWLANInterface] sections.");
                return 0;
        }

        if (link->action != SD_DEVICE_ADD) {
                if (!hashmap_isempty(link->config->wlan_interfaces_by_section))
                        log_link_debug(link, "Skipping to apply configs specified in [VirtualWLANInterface] sections on '%s' uevent.",
                                       device_action_to_string(link->action));
                return 0;
        }

        HASHMAP_FOREACH(w, link->config->wlan_interfaces_by_section) {
                r = wlan_interface_configure(&genl, link, w);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to apply wlan interface config: %m");
        }

        return 0;
}

static int wlan_interface_section_verify(WLANInterface *w) {
        assert(w);

        if (section_is_invalid(w->section))
                return -EINVAL;

        if (isempty(w->ifname))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s:%u: [VirtualWLANInterface] section specified without valid interface name, ignoring section.",
                                         w->section->filename, w->section->line);

        if (w->iftype == NL80211_IFTYPE_UNSPECIFIED)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s:%u: [VirtualWLANInterface] section specified without valid interface type, ignoring section.",
                                         w->section->filename, w->section->line);

        return 0;
}

void link_config_drop_invalid_wlan_interfaces(LinkConfig *config) {
        WLANInterface *w;

        assert(config);

        HASHMAP_FOREACH(w, config->wlan_interfaces_by_section)
                if (wlan_interface_section_verify(w) < 0)
                        wlan_interface_free(w);
}

int config_parse_wlan_interface_name(
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

        _cleanup_(wlan_interface_free_or_set_invalidp) WLANInterface *w = NULL;
        LinkConfig *config = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(userdata);

        r = wlan_interface_new_static(config, filename, section_line, &w);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate wlan interface config, ignoring assignment: %s=%s",
                           lvalue, rvalue);
                return 0;
        }

        if (isempty(rvalue)) {
                w->ifname = mfree(w->ifname);
                TAKE_PTR(w);
                return 0;
        }

        if (!ifname_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Interface name is not valid or too long, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = free_and_strdup_warn(&w->ifname, rvalue);
        if (r < 0)
                return r;

        TAKE_PTR(w);
        return 0;
}

int config_parse_wlan_interface_type(
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

        _cleanup_(wlan_interface_free_or_set_invalidp) WLANInterface *w = NULL;
        LinkConfig *config = userdata;
        enum nl80211_iftype t;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(userdata);

        r = wlan_interface_new_static(config, filename, section_line, &w);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate wlan interface config, ignoring assignment: %s=%s",
                           lvalue, rvalue);
                return 0;
        }

        if (isempty(rvalue)) {
                w->iftype = NL80211_IFTYPE_UNSPECIFIED;
                TAKE_PTR(w);
                return 0;
        }

        t = nl80211_iftype_from_string(rvalue);
        /* We reuse the kernel provided enum which does not contain negative value. So, the cast
         * below is mandatory. Otherwise, the check below always passes. */
        if ((int) t < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse wlan interface type, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        w->iftype = t;
        TAKE_PTR(w);
        return 0;
}

int config_parse_wlan_interface_mac(
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

        _cleanup_(wlan_interface_free_or_set_invalidp) WLANInterface *w = NULL;
        LinkConfig *config = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(userdata);

        r = wlan_interface_new_static(config, filename, section_line, &w);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate wlan interface config, ignoring assignment: %s=%s",
                           lvalue, rvalue);
                return 0;
        }

        if (isempty(rvalue)) {
                w->mac = ETHER_ADDR_NULL;
                TAKE_PTR(w);
                return 0;
        }

        r = parse_ether_addr(rvalue, &w->mac);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse wlan MAC address, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        TAKE_PTR(w);
        return 0;
}

int config_parse_wlan_interface_wds(
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

        _cleanup_(wlan_interface_free_or_set_invalidp) WLANInterface *w = NULL;
        LinkConfig *config = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(userdata);

        r = wlan_interface_new_static(config, filename, section_line, &w);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate wlan interface config, ignoring assignment: %s=%s",
                           lvalue, rvalue);
                return 0;
        }

        if (isempty(rvalue)) {
                w->wds = -1;
                TAKE_PTR(w);
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse wlan WDS mode, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        w->wds = r;
        TAKE_PTR(w);
        return 0;
}
