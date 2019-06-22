/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-bus.h"

#include "bus-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-wifi-iwd.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"

static int iwd_get_ssid_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        const sd_bus_error *e;
        Link *link = userdata;
        const char *ssid;
        int r;

        assert(m);
        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        e = sd_bus_message_get_error(m);
        if (e) {
                log_link_full(link,
                              sd_bus_error_has_name(e, "org.freedesktop.DBus.Error.UnknownMethod") ? LOG_DEBUG : LOG_ERR,
                              sd_bus_error_get_errno(e),
                              "Failed to get current wifi SSID: %s",
                              e->message);
                return 0;
        }

        r = sd_bus_message_read(m, "v", "s", &ssid);
        if (r < 0)
                return bus_log_parse_error(r);

        r = free_and_strdup(&link->ssid, ssid);
        if (r < 0)
                return log_oom();
        if (r > 0)
                log_link_info(link, "Connected to %s", ssid);

        (void) link_reconfigure(link);
        return 0;
}

static int iwd_get_ssid(Link *link) {
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        int r;

        assert(link);

        if (isempty(link->iwd_station_network_path))
                return -EINVAL;

        r = sd_bus_call_method_async(
                        link->manager->bus,
                        &slot,
                        "net.connman.iwd",
                        link->iwd_station_network_path,
                        "org.freedesktop.DBus.Properties",
                        "Get",
                        iwd_get_ssid_handler,
                        link,
                        "ss",
                        "net.connman.iwd.Network",
                        "Name");
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get current wifi SSID: %m");

        assert_se(sd_bus_slot_set_destroy_callback(slot, (sd_bus_destroy_t) link_netlink_destroy_callback) >= 0);
        assert_se(sd_bus_slot_set_floating(slot, true) >= 0);
        link_ref(link);

        return 0;
}

static int iwd_get_current_network_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        const sd_bus_error *e;
        Link *link = userdata;
        const char *path;
        int r;

        assert(m);
        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        e = sd_bus_message_get_error(m);
        if (e) {
                if (sd_bus_error_has_name(e, "org.freedesktop.DBus.Error.ServiceUnknown"))
                        log_link_debug_errno(link, sd_bus_error_get_errno(e),
                                             "IWD seems not running, ignoring: %s",
                                             e->message);
                else if (sd_bus_error_has_name(e, "org.freedesktop.DBus.Error.AccessDenied"))
                        log_link_warning_errno(link, sd_bus_error_get_errno(e),
                                               "The DBus API of IWD seems not to be usable by the user 'systemd-network'. "
                                               "Please update the DBus policy for IWD: %s",
                                               e->message);
                else {
                        bool ignore =
                                sd_bus_error_has_name(e, "org.freedesktop.DBus.Error.Failed") ||
                                sd_bus_error_has_name(e, "org.freedesktop.DBus.Error.IOError");

                        log_link_full(link,
                                      ignore ? LOG_DEBUG : LOG_ERR,
                                      sd_bus_error_get_errno(e),
                                      "Failed to get current wifi network%s: %s",
                                      ignore ? ", ignoring" : "", e->message);
                }
                return 0;
        }

        r = sd_bus_message_read(m, "v", "o", &path);
        if (r < 0)
                return bus_log_parse_error(r);

        r = free_and_strdup(&link->iwd_station_network_path, path);
        if (r < 0)
                return log_oom();

        (void) iwd_get_ssid(link);

        return 0;
}

static int iwd_get_current_network(Link *link) {
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        int r;

        r = sd_bus_call_method_async(
                        link->manager->bus,
                        &slot,
                        "net.connman.iwd",
                        link->iwd_path,
                        "org.freedesktop.DBus.Properties",
                        "Get",
                        iwd_get_current_network_handler,
                        link,
                        "ss",
                        "net.connman.iwd.Station",
                        "ConnectedNetwork");
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get current wifi network: %m");

        assert_se(sd_bus_slot_set_destroy_callback(slot, (sd_bus_destroy_t) link_netlink_destroy_callback) >= 0);
        assert_se(sd_bus_slot_set_floating(slot, true) >= 0);
        link_ref(link);

        return 0;
}

typedef struct IWDProperties {
        const char *state;
        const char *network;
} IWDProperties;

static int on_iwd_properties_changed(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        static const struct bus_properties_map map[] = {
                { "State",            "s", NULL, offsetof(IWDProperties, state)   },
                { "ConnectedNetwork", "o", NULL, offsetof(IWDProperties, network) },
                {}
        };
        IWDProperties prop = {};
        Link *link = userdata;
        const char *interface;
        int r;

        assert(m);
        assert(link);

        r = sd_bus_message_read(m, "s", &interface);
        if (r < 0)
                return bus_log_parse_error(r);

        if (!STR_IN_SET(interface, "net.connman.iwd.Station"))
                return 0;

        r = bus_message_map_all_properties(m, map, 0, NULL, &prop);
        if (r < 0)
                return bus_log_parse_error(r);

        if (streq_ptr(prop.state, "connected"))
                (void) iwd_get_ssid(link);
        else {
                link->ssid = mfree(link->ssid);
                r = free_and_strdup(&link->iwd_station_network_path, prop.network);
                if (r < 0)
                        return log_oom();

                (void) link_reconfigure(link);
        }

        return 0;
}

int iwd_get_ssid_async(Link *link) {
        _cleanup_(sd_device_unrefp) sd_device *phy_dev = NULL;
        const char *type, *syspath, *phy_syspath, *phy_name, *p;
        _cleanup_free_ char *path = NULL;
        unsigned phy_id;
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

        r = sd_device_get_syspath(link->sd_device, &syspath);
        if (r < 0)
                return r;

        phy_syspath = prefix_roota(syspath, "phy80211");
        r = sd_device_new_from_syspath(&phy_dev, phy_syspath);
        if (r < 0)
                return r;

        r = sd_device_get_sysname(phy_dev, &phy_name);
        if (r < 0)
                return r;

        p = startswith(phy_name, "phy");
        if (!p)
                return -EINVAL;

        r = safe_atou(p, &phy_id);
        if (r < 0)
                return r;

        if (asprintf(&path, "/%u/%d", phy_id, link->ifindex) < 0)
                return -ENOMEM;

        free_and_replace(link->iwd_path, path);

        r = sd_bus_match_signal_async(
                        link->manager->bus,
                        &link->iwd_slot,
                        "net.connman.iwd",
                        link->iwd_path,
                        "org.freedesktop.DBus.Properties",
                        "PropertiesChanged",
                        on_iwd_properties_changed, NULL, link);
        if (r < 0)
                log_link_error_errno(link, r, "Failed to install match signal for wifi interface: %m");

        return iwd_get_current_network(link);
}
