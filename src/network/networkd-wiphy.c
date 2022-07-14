/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>
#include <linux/nl80211.h>

#include "device-private.h"
#include "device-util.h"
#include "networkd-manager.h"
#include "networkd-wiphy.h"
#include "parse-util.h"
#include "wifi-util.h"

Wiphy *wiphy_free(Wiphy *w) {
        if (!w)
                return NULL;

        if (w->manager) {
                hashmap_remove_value(w->manager->wiphy_by_index, UINT32_TO_PTR(w->index), w);
                if (w->name)
                        hashmap_remove_value(w->manager->wiphy_by_name, w->name, w);
        }

        sd_device_unref(w->dev);
        free(w->name);
        return mfree(w);
}

static int wiphy_new(Manager *manager, uint32_t index, Wiphy **ret) {
        _cleanup_(wiphy_freep) Wiphy *w = NULL;
        int r;

        assert(manager);

        w = new(Wiphy, 1);
        if (!w)
                return -ENOMEM;

        *w = (Wiphy) {
                .index = index,
        };

        r = hashmap_ensure_put(&manager->wiphy_by_index, NULL, UINT32_TO_PTR(w->index), w);
        if (r < 0)
                return r;

        w->manager = manager;

        if (ret)
                *ret = w;

        TAKE_PTR(w);
        return 0;
}

int wiphy_get_by_index(Manager *manager, uint32_t index, Wiphy **ret) {
        Wiphy *w;

        assert(manager);

        w = hashmap_get(manager->wiphy_by_index, UINT32_TO_PTR(index));
        if (!w)
                return -ENODEV;

        if (ret)
                *ret = w;

        return 0;
}

int wiphy_get_by_name(Manager *manager, const char *name, Wiphy **ret) {
        Wiphy *w;

        assert(manager);
        assert(name);

        w = hashmap_get(manager->wiphy_by_name, name);
        if (!w)
                return -ENODEV;

        if (ret)
                *ret = w;

        return 0;
}

static int link_get_wiphy(Link *link, Wiphy **ret) {
        _cleanup_(sd_device_unrefp) sd_device *phy = NULL;
        const char *s;
        Wiphy *w;
        int r;

        assert(link);
        assert(link->manager);

        if (link->iftype != ARPHRD_ETHER)
                return -EOPNOTSUPP;

        if (!link->sd_device)
                return -EOPNOTSUPP;

        r = sd_device_get_devtype(link->sd_device, &s);
        if (r < 0)
                return r;

        if (!streq_ptr(s, "wlan"))
                return -EOPNOTSUPP;

        r = sd_device_get_syspath(link->sd_device, &s);
        if (r < 0)
                return r;

        s = strjoina(s, "/phy80211");
        r = sd_device_new_from_syspath(&phy, s);
        if (r < 0)
                return r;

        r = sd_device_get_sysname(phy, &s);
        if (r < 0)
                return r;

        r = wiphy_get_by_name(link->manager, s, &w);
        if (r < 0)
                return r;

        /* Optionally assign the sd-device object to the Wiphy object. */
        if (!w->dev)
                w->dev = TAKE_PTR(phy);

        /* TODO:
         * Maybe, it is better to cache the found Wiphy object in the Link object.
         * To support that, we need to investigate what happens when the _phy_ is renamed. */

        if (ret)
                *ret = w;

        return 0;
}

static int wiphy_get_rfkill_device(Wiphy *w, sd_device **ret) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *rfkill;
        const char *s;
        int r;

        assert(w);
        assert(w->name);

        if (w->rfkill) {
                if (ret)
                        *ret = w->rfkill;

                return 0;
        }

        if (!w->dev) {
                r = sd_device_new_from_subsystem_sysname(&w->dev, "ieee80211", w->name);
                if (r < 0)
                        return r;
        }

        r = sd_device_get_syspath(w->dev, &s);
        if (r < 0)
                return r;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "rfkill", true);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_parent(e, w->dev);
        if (r < 0)
                return r;

        rfkill = sd_device_enumerator_get_device_first(e);
        if (!rfkill)
                return log_wiphy_debug_errno(w, SYNTHETIC_ERRNO(ENODEV), "No rfkill device found.");

        if (sd_device_enumerator_get_device_next(e))
                return log_wiphy_debug_errno(w, SYNTHETIC_ERRNO(EEXIST), "Multiple rfkill devices found.");

        w->rfkill = sd_device_ref(rfkill);
        log_wiphy_debug(w, "rfkill device found: %s", sd_device_get_syspath(rfkill, &s) >= 0 ? s : "n/a");

        if (ret)
                *ret = w->rfkill;

        return 0;
}

static int wiphy_get_rfkill_state(Wiphy *w) {
        sd_device *dev;
        int r;

        assert(w);

        r = wiphy_get_rfkill_device(w, &dev);
        if (r < 0)
                return r;

        /* The previous values may be outdated. Let's clear cache and re-read the values. */
        device_clear_sysattr_cache(dev);

        r = device_get_sysattr_bool(dev, "soft");
        if (r < 0 && r != -ENOENT)
                return r;
        if (r > 0)
                return RFKILL_SOFT;

        r = device_get_sysattr_bool(dev, "hard");
        if (r < 0 && r != -ENOENT)
                return r;
        if (r > 0)
                return RFKILL_HARD;

        return RFKILL_UNBLOCKED;
}

int link_rfkilled(Link *link) {
        Wiphy *w;
        int r;

        assert(link);

        r = link_get_wiphy(link, &w);
        if (IN_SET(r, -EOPNOTSUPP, -ENODEV))
                return false; /* Typically, non-wifi interface. */
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not get phy: %m");

        r = wiphy_get_rfkill_state(w);
        if (r == -ENODEV) {
                log_link_debug_errno(link, r, "Could not get rfkill state, assuming the radio transmitter is unblocked, ignoring: %m");
                return false;
        }
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not get rfkill state: %m");

        if (link->rfkill_state != r)
                switch (r) {
                case RFKILL_UNBLOCKED:
                        log_link_debug(link, "The radio transmitter is unblocked.");
                        break;
                case RFKILL_SOFT:
                        log_link_debug(link,
                                       "The radio transmitter is turned off by software. "
                                       "Waiting for the transmitter to be unblocked.");
                        break;
                case RFKILL_HARD:
                        log_link_debug(link,
                                       "The radio transmitter is forced off by something outside of the driver's control. "
                                       "Waiting for the transmitter to be turned on.");
                        break;
                default:
                        assert_not_reached();
                }

        link->rfkill_state = r; /* Cache the state to suppress the above log messages. */
        return r != RFKILL_UNBLOCKED;
}

static int wiphy_update_name(Wiphy *w, sd_netlink_message *message) {
        const char *name;
        int r;

        assert(w);
        assert(w->manager);
        assert(message);

        r = sd_netlink_message_read_string(message, NL80211_ATTR_WIPHY_NAME, &name);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        if (streq_ptr(w->name, name))
                return 0;

        if (w->name)
                hashmap_remove_value(w->manager->wiphy_by_name, w->name, w);

        r = free_and_strdup(&w->name, name);
        if (r < 0)
                return r;

        return hashmap_ensure_put(&w->manager->wiphy_by_name, &string_hash_ops, w->name, w);
}

static int wiphy_update(Wiphy *w, sd_netlink_message *message) {
        int r;

        assert(w);
        assert(message);

        r = wiphy_update_name(w, message);
        if (r < 0)
                return log_wiphy_debug_errno(w, r, "Failed to update wiphy name: %m");

        return 0;
}

int manager_genl_process_nl80211_wiphy(sd_netlink *genl, sd_netlink_message *message, Manager *manager) {
        const char *family;
        uint32_t index;
        uint8_t cmd;
        Wiphy *w = NULL;
        int r;

        assert(genl);
        assert(message);
        assert(manager);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "nl80211: received error message, ignoring");

                return 0;
        }

        r = sd_genl_message_get_family_name(genl, message, &family);
        if (r < 0) {
                log_debug_errno(r, "nl80211: failed to determine genl family, ignoring: %m");
                return 0;
        }
        if (!streq(family, NL80211_GENL_NAME)) {
                log_debug("nl80211: Received message of unexpected genl family '%s', ignoring.", family);
                return 0;
        }

        r = sd_genl_message_get_command(genl, message, &cmd);
        if (r < 0) {
                log_debug_errno(r, "nl80211: failed to determine genl message command, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u32(message, NL80211_ATTR_WIPHY, &index);
        if (r < 0) {
                log_debug_errno(r, "nl80211: received %s(%u) message without valid index, ignoring: %m",
                                strna(nl80211_cmd_to_string(cmd)), cmd);
                return 0;
        }

        (void) wiphy_get_by_index(manager, index, &w);

        switch (cmd) {
        case NL80211_CMD_NEW_WIPHY: {
                bool is_new = !w;

                if (!w) {
                        r = wiphy_new(manager, index, &w);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to allocate wiphy, ignoring: %m");
                                return 0;
                        }
                }

                r = wiphy_update(w, message);
                if (r < 0) {
                        log_wiphy_warning_errno(w, r, "Failed to update wiphy, ignoring: %m");
                        return 0;
                }

                log_wiphy_debug(w, "Received %s phy.", is_new ? "new" : "updated");
                break;
        }
        case NL80211_CMD_DEL_WIPHY:

                if (!w) {
                        log_debug("The kernel removes wiphy we do not know, ignoring: %m");
                        return 0;
                }

                log_wiphy_debug(w, "Removed.");
                wiphy_free(w);
                break;

        default:
                log_wiphy_debug(w, "nl80211: received %s(%u) message.",
                                strna(nl80211_cmd_to_string(cmd)), cmd);
        }

        return 0;
}
