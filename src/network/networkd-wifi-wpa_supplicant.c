/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-bus.h"

#include "bus-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-wifi-wpa_supplicant.h"
#include "string-util.h"

static int wpa_supplicant_update_ssid(Link *link, const char *ssid) {
        assert(link);
        assert(ssid);

        /* It seems that ssid provided by wpa_supplicant is quoted... */
        if (*ssid == '"')
                return free_and_strndup(&link->ssid, ssid + 1, strlen(ssid) - 2);

        return free_and_strdup(&link->ssid, ssid);
}

static int wpa_supplicant_get_network_properties_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        const char *name, *ssid = NULL;
        const sd_bus_error *e;
        Link *link = userdata;
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
                              "Failed to get current wifi properties: %s",
                              e->message);
                return 0;
        }

        r = sd_bus_message_enter_container(m, 'v', "a{sv}");
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_enter_container(m, 'a', "{sv}");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;)
                if (ssid) {
                        r = sd_bus_message_skip(m, "{sv}");
                        if (r < 0)
                                return bus_log_parse_error(r);
                        if (r == 0)
                                break;
                } else {
                        r = sd_bus_message_enter_container(m, 'e', "sv");
                        if (r < 0)
                                return bus_log_parse_error(r);
                        if (r == 0)
                                break;

                        r = sd_bus_message_read(m, "s", &name);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        if (streq(name, "ssid"))
                                r = sd_bus_message_read(m, "v", "s", &ssid);
                        else
                                r = sd_bus_message_skip(m, "v");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);
                }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return bus_log_parse_error(r);

        r = wpa_supplicant_update_ssid(link, ssid);
        if (r < 0)
                return log_oom();
        if (r == 0)
                return 0;

        log_link_info(link, "Connected to %s", ssid);

        (void) link_reconfigure(link);
        return 0;
}

static int wpa_supplicant_get_network_properties(Link *link) {
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        int r;

        assert(link);
        assert(link->wpa_supplicant_network_path);

        r = sd_bus_call_method_async(
                        link->manager->bus,
                        &slot,
                        "fi.w1.wpa_supplicant1",
                        link->wpa_supplicant_network_path,
                        "org.freedesktop.DBus.Properties",
                        "Get",
                        wpa_supplicant_get_network_properties_handler,
                        link,
                        "ss",
                        "fi.w1.wpa_supplicant1.Network",
                        "Properties");
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get wifi network properties: %m");

        assert_se(sd_bus_slot_set_destroy_callback(slot, (sd_bus_destroy_t) link_netlink_destroy_callback) >= 0);
        assert_se(sd_bus_slot_set_floating(slot, true) >= 0);
        link_ref(link);

        return 0;
}

static int on_wpa_supplicant_network_properties_changed(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Link *link = userdata;

        assert(message);
        assert(link);

        (void) wpa_supplicant_get_network_properties(link);
        return 0;
}

static int wpa_supplicant_get_network_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
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
                log_link_full(link,
                              sd_bus_error_has_name(e, "org.freedesktop.DBus.Error.NoReply") ? LOG_DEBUG : LOG_ERR,
                              sd_bus_error_get_errno(e),
                              "Failed to get current wifi network: %s",
                              e->message);
                return 0;
        }

        r = sd_bus_message_read(m, "v", "o", &path);
        if (r < 0)
                return bus_log_parse_error(r);

        if (streq_ptr(path, "/")) {
                /* When no connection is established, wpa_supplicant returns "/". */
                link->wpa_supplicant_network_path = mfree(link->wpa_supplicant_network_path);
                link->wpa_supplicant_network_slot = sd_bus_slot_unref(link->wpa_supplicant_network_slot);
                return 0;
        }

        if (streq_ptr(link->wpa_supplicant_network_path, path))
                return 0;

        r = free_and_strdup(&link->wpa_supplicant_network_path, path);
        if (r < 0)
                return log_oom();

        link->wpa_supplicant_network_slot = sd_bus_slot_unref(link->wpa_supplicant_network_slot);

        r = sd_bus_match_signal_async(
                        link->manager->bus,
                        &link->wpa_supplicant_network_slot,
                        "fi.w1.wpa_supplicant1",
                        path,
                        "fi.w1.wpa_supplicant1.Network",
                        "PropertiesChanged",
                        on_wpa_supplicant_network_properties_changed, NULL, link);
        if (r < 0)
                log_link_error_errno(link, r, "Failed to install match signal for wifi network: %m");

        (void) wpa_supplicant_get_network_properties(link);
        return 0;
}

static int wpa_supplicant_get_network(Link *link) {
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        int r;

        assert(link);
        assert(link->wpa_supplicant_interface_path);

        r = sd_bus_call_method_async(
                        link->manager->bus,
                        &slot,
                        "fi.w1.wpa_supplicant1",
                        link->wpa_supplicant_interface_path,
                        "org.freedesktop.DBus.Properties",
                        "Get",
                        wpa_supplicant_get_network_handler,
                        link,
                        "ss",
                        "fi.w1.wpa_supplicant1.Interface",
                        "CurrentNetwork");
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get wifi network: %m");;

        assert_se(sd_bus_slot_set_destroy_callback(slot, (sd_bus_destroy_t) link_netlink_destroy_callback) >= 0);
        assert_se(sd_bus_slot_set_floating(slot, true) >= 0);
        link_ref(link);

        return 0;
}

static int on_wpa_supplicant_interface_properties_changed(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Link *link = userdata;

        assert(message);
        assert(link);

        (void) wpa_supplicant_get_network(link);
        return 0;
}

static int wpa_supplicant_get_interface_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
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
                                             "wpa_supplicant seems not running, ignoring: %s",
                                             e->message);
                else if (sd_bus_error_has_name(e, "org.freedesktop.DBus.Error.AccessDenied"))
                        log_link_warning_errno(link, sd_bus_error_get_errno(e),
                                               "The DBus API of wpa_supplicant seems not to be usable by the user 'systemd-network'. "
                                               "Please update the DBus policy for wpa_supplicant: %s",
                                               e->message);
                else if (sd_bus_error_has_name(e, "fi.w1.wpa_supplicant1.InterfaceUnknown"))
                        log_link_debug_errno(link, sd_bus_error_get_errno(e),
                                             "wpa_supplicant seems not configured, ignoring: %s",
                                             e->message);
                else
                        log_link_error_errno(link, sd_bus_error_get_errno(e),
                                             "Failed to get DBus path to interface: %m: %s",
                                             e->message);

                link->manager->wpa_supplicant_support = false;
                return 0;
        }

        r = sd_bus_message_read(m, "o", &path);
        if (r < 0)
                return bus_log_parse_error(r);

        if (streq_ptr(link->wpa_supplicant_interface_path, path))
                return 0;

        r = free_and_strdup(&link->wpa_supplicant_interface_path, path);
        if (r < 0)
                return log_oom();

        link->wpa_supplicant_interface_slot = sd_bus_slot_unref(link->wpa_supplicant_interface_slot);

        r = sd_bus_match_signal_async(
                        link->manager->bus,
                        &link->wpa_supplicant_interface_slot,
                        "fi.w1.wpa_supplicant1",
                        path,
                        "fi.w1.wpa_supplicant1.Interface",
                        "PropertiesChanged",
                        on_wpa_supplicant_interface_properties_changed, NULL, link);
        if (r < 0)
                log_link_error_errno(link, r, "Failed to install match signal for wifi interface: %m");

        (void) wpa_supplicant_get_network(link);
        return 0;
}

int wpa_supplicant_get_interface(Link *link) {
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        const char *type;
        int r;

        if (!link->manager->wpa_supplicant_support)
                return 0;

        if (!link->sd_device)
                return 0;

        r = sd_device_get_devtype(link->sd_device, &type);
        if (r == -ENOENT)
                return 0;
        else if (r < 0)
                return r;

        if (!streq(type, "wlan"))
                return 0;

        r = sd_bus_call_method_async(
                        link->manager->bus,
                        &slot,
                        "fi.w1.wpa_supplicant1",
                        "/fi/w1/wpa_supplicant1",
                        "fi.w1.wpa_supplicant1",
                        "GetInterface",
                        wpa_supplicant_get_interface_handler,
                        link,
                        "s",
                        link->ifname);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get DBus path to interface: %m");

        assert_se(sd_bus_slot_set_destroy_callback(slot, (sd_bus_destroy_t) link_netlink_destroy_callback) >= 0);
        assert_se(sd_bus_slot_set_floating(slot, true) >= 0);
        link_ref(link);

        return 0;
}

int on_wpa_supplicant_properties_changed(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Manager *manager = userdata;
        Iterator i;
        Link *link;

        assert(message);
        assert(manager);

        HASHMAP_FOREACH(link, manager->links, i)
                (void) wpa_supplicant_get_interface(link);

        return 0;
}
