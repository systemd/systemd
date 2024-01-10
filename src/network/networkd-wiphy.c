/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>
#include <linux/nl80211.h>

#include "device-private.h"
#include "device-util.h"
#include "networkd-manager.h"
#include "networkd-wiphy.h"
#include "parse-util.h"
#include "path-util.h"
#include "udev-util.h"
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
        sd_device_unref(w->rfkill);

        free(w->name);
        return mfree(w);
}

static int wiphy_new(Manager *manager, sd_netlink_message *message, Wiphy **ret) {
        _cleanup_(wiphy_freep) Wiphy *w = NULL;
        _cleanup_free_ char *name = NULL;
        uint32_t index;
        int r;

        assert(manager);
        assert(message);

        r = sd_netlink_message_read_u32(message, NL80211_ATTR_WIPHY, &index);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_string_strdup(message, NL80211_ATTR_WIPHY_NAME, &name);
        if (r < 0)
                return r;

        w = new(Wiphy, 1);
        if (!w)
                return -ENOMEM;

        *w = (Wiphy) {
                .manager = manager,
                .index = index,
                .name = TAKE_PTR(name),
        };

        r = hashmap_ensure_put(&manager->wiphy_by_index, NULL, UINT32_TO_PTR(w->index), w);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&w->manager->wiphy_by_name, &string_hash_ops, w->name, w);
        if (r < 0)
                return r;

        log_wiphy_debug(w, "Saved new wiphy: index=%"PRIu32, w->index);

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
        int r;

        assert(link);
        assert(link->manager);

        if (link->iftype != ARPHRD_ETHER)
                return -EOPNOTSUPP;

        if (!link->dev)
                return -ENODEV;

        if (!device_is_devtype(link->dev, "wlan"))
                return -EOPNOTSUPP;

        r = sd_device_new_child(&phy, link->dev, "phy80211");
        if (r < 0)
                return r;

        r = sd_device_get_sysname(phy, &s);
        if (r < 0)
                return r;

        /* TODO:
         * Maybe, it is better to cache the found Wiphy object in the Link object.
         * To support that, we need to investigate what happens when the _phy_ is renamed. */

        return wiphy_get_by_name(link->manager, s, ret);
}

static int rfkill_get_state(sd_device *dev) {
        int r;

        assert(dev);

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

static int wiphy_rfkilled(Wiphy *w) {
        int r;

        assert(w);

        if (!udev_available()) {
                if (w->rfkill_state != RFKILL_UNBLOCKED) {
                        log_wiphy_debug(w, "Running in container, assuming the radio transmitter is unblocked.");
                        w->rfkill_state = RFKILL_UNBLOCKED; /* To suppress the above log message, cache the state. */
                }
                return false;
        }

        if (!w->rfkill) {
                if (w->rfkill_state != RFKILL_UNBLOCKED) {
                        log_wiphy_debug(w, "No rfkill device found, assuming the radio transmitter is unblocked.");
                        w->rfkill_state = RFKILL_UNBLOCKED; /* To suppress the above log message, cache the state. */
                }
                return false;
        }

        r = rfkill_get_state(w->rfkill);
        if (r < 0)
                return log_wiphy_debug_errno(w, r, "Could not get rfkill state: %m");

        if (w->rfkill_state != r)
                switch (r) {
                case RFKILL_UNBLOCKED:
                        log_wiphy_debug(w, "The radio transmitter is unblocked.");
                        break;
                case RFKILL_SOFT:
                        log_wiphy_debug(w, "The radio transmitter is turned off by software.");
                        break;
                case RFKILL_HARD:
                        log_wiphy_debug(w, "The radio transmitter is forced off by something outside of the driver's control.");
                        break;
                default:
                        assert_not_reached();
                }

        w->rfkill_state = r; /* Cache the state to suppress the above log messages. */
        return r != RFKILL_UNBLOCKED;
}

int link_rfkilled(Link *link) {
        Wiphy *w;
        int r;

        assert(link);

        r = link_get_wiphy(link, &w);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r) || ERRNO_IS_NEG_DEVICE_ABSENT(r))
                return false; /* Typically, non-wifi interface or running in container */
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not get phy: %m");

        return wiphy_rfkilled(w);
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

        if (streq(w->name, name))
                return 0;

        log_wiphy_debug(w, "Wiphy name change detected, renamed to %s.", name);

        hashmap_remove_value(w->manager->wiphy_by_name, w->name, w);

        r = free_and_strdup(&w->name, name);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&w->manager->wiphy_by_name, &string_hash_ops, w->name, w);
        if (r < 0)
                return r;

        return 1; /* updated */
}

static int wiphy_update_device(Wiphy *w) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        int r;

        assert(w);
        assert(w->name);

        if (!udev_available())
                return 0;

        w->dev = sd_device_unref(w->dev);

        r = sd_device_new_from_subsystem_sysname(&dev, "ieee80211", w->name);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING) {
                const char *s = NULL;

                (void) sd_device_get_syspath(dev, &s);
                log_wiphy_debug(w, "Found device: %s", strna(s));
        }

        w->dev = TAKE_PTR(dev);
        return 0;
}

static int wiphy_update_rfkill(Wiphy *w) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *rfkill;
        int r;

        assert(w);

        if (!udev_available())
                return 0;

        w->rfkill = sd_device_unref(w->rfkill);

        if (!w->dev)
                return 0;

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
                /* rfkill device may not detected by the kernel yet, and may appear later. */
                return -ENODEV;

        if (sd_device_enumerator_get_device_next(e))
                return -ENXIO; /* multiple devices found */

        w->rfkill = sd_device_ref(rfkill);

        if (DEBUG_LOGGING) {
                const char *s = NULL;

                (void) sd_device_get_syspath(rfkill, &s);
                log_wiphy_debug(w, "Found rfkill device: %s", strna(s));
        }

        return 0;
}

static int wiphy_update(Wiphy *w) {
        int r;

        assert(w);

        r = wiphy_update_device(w);
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r))
                log_wiphy_debug_errno(w, r, "Failed to update wiphy device, ignoring: %m");
        else if (r < 0)
                return log_wiphy_warning_errno(w, r, "Failed to update wiphy device: %m");

        r = wiphy_update_rfkill(w);
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r))
                log_wiphy_debug_errno(w, r, "Failed to update rfkill device, ignoring: %m");
        else if (r < 0)
                return log_wiphy_warning_errno(w, r, "Failed to update rfkill device: %m");

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

                if (!w) {
                        r = wiphy_new(manager, message, &w);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to save new wiphy, ignoring: %m");
                                return 0;
                        }
                } else {
                        r = wiphy_update_name(w, message);
                        if (r < 0) {
                                log_wiphy_warning_errno(w, r, "Failed to update wiphy name, ignoring: %m");
                                return 0;
                        }
                        if (r == 0)
                                return 0;
                }

                r = wiphy_update(w);
                if (r < 0)
                        log_wiphy_warning_errno(w, r, "Failed to update wiphy, ignoring: %m");

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

int manager_udev_process_wiphy(Manager *m, sd_device *device, sd_device_action_t action) {
        const char *name;
        Wiphy *w;
        int r;

        assert(m);
        assert(device);

        r = sd_device_get_sysname(device, &name);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to get sysname: %m");

        r = wiphy_get_by_name(m, name, &w);
        if (r < 0) {
                /* This error is not critical, as the corresponding genl message may be received later. */
                log_device_debug_errno(device, r, "Failed to get Wiphy object, ignoring: %m");
                return 0;
        }

        return device_unref_and_replace(w->dev, action == SD_DEVICE_REMOVE ? NULL : device);
}

int manager_udev_process_rfkill(Manager *m, sd_device *device, sd_device_action_t action) {
        _cleanup_free_ char *parent_path = NULL, *parent_name = NULL;
        const char *s;
        Wiphy *w;
        int r;

        assert(m);
        assert(device);

        r = sd_device_get_syspath(device, &s);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to get syspath: %m");

        /* Do not use sd_device_get_parent() here, as this might be a 'remove' uevent. */
        r = path_extract_directory(s, &parent_path);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to get parent syspath: %m");

        r = path_extract_filename(parent_path, &parent_name);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to get parent name: %m");

        r = wiphy_get_by_name(m, parent_name, &w);
        if (r < 0) {
                /* This error is not critical, as the corresponding genl message may be received later. */
                log_device_debug_errno(device, r, "Failed to get Wiphy object: %m");
                return 0;
        }

        return device_unref_and_replace(w->rfkill, action == SD_DEVICE_REMOVE ? NULL : device);
}
