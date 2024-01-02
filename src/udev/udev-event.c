/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "alloc-util.h"
#include "device-internal.h"
#include "device-private.h"
#include "device-util.h"
#include "fs-util.h"
#include "netif-naming-scheme.h"
#include "netlink-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "udev-event.h"
#include "udev-node.h"
#include "udev-trace.h"
#include "udev-util.h"
#include "user-util.h"

UdevEvent *udev_event_new(sd_device *dev, UdevWorker *worker) {
        int log_level = worker ? worker->log_level : log_get_max_level();
        UdevEvent *event;

        assert(dev);

        event = new(UdevEvent, 1);
        if (!event)
                return NULL;

        *event = (UdevEvent) {
                .worker = worker,
                .rtnl = worker ? sd_netlink_ref(worker->rtnl) : NULL,
                .dev = sd_device_ref(dev),
                .birth_usec = now(CLOCK_MONOTONIC),
                .uid = UID_INVALID,
                .gid = GID_INVALID,
                .mode = MODE_INVALID,
                .log_level_was_debug = log_level == LOG_DEBUG,
                .default_log_level = log_level,
        };

        return event;
}

UdevEvent *udev_event_free(UdevEvent *event) {
        if (!event)
                return NULL;

        sd_device_unref(event->dev);
        sd_device_unref(event->dev_db_clone);
        sd_netlink_unref(event->rtnl);
        ordered_hashmap_free_free_key(event->run_list);
        ordered_hashmap_free_free_free(event->seclabel_list);
        free(event->program_result);
        free(event->name);
        strv_free(event->altnames);

        return mfree(event);
}

static int device_rename(sd_device *device, const char *name) {
        _cleanup_free_ char *new_syspath = NULL;
        const char *s;
        int r;

        assert(device);
        assert(name);

        if (!filename_is_valid(name))
                return -EINVAL;

        r = sd_device_get_syspath(device, &s);
        if (r < 0)
                return r;

        r = path_extract_directory(s, &new_syspath);
        if (r < 0)
                return r;

        if (!path_extend(&new_syspath, name))
                return -ENOMEM;

        if (!path_is_safe(new_syspath))
                return -EINVAL;

        /* At the time this is called, the renamed device may not exist yet. Hence, we cannot validate
         * the new syspath. */
        r = device_set_syspath(device, new_syspath, /* verify = */ false);
        if (r < 0)
                return r;

        r = sd_device_get_property_value(device, "INTERFACE", &s);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        /* like DEVPATH_OLD, INTERFACE_OLD is not saved to the db, but only stays around for the current event */
        r = device_add_property_internal(device, "INTERFACE_OLD", s);
        if (r < 0)
                return r;

        return device_add_property_internal(device, "INTERFACE", name);
}

static int rename_netif(UdevEvent *event) {
        _cleanup_free_ char *old_syspath = NULL, *old_sysname = NULL;
        const char *s;
        sd_device *dev;
        int ifindex, r;

        assert(event);

        if (!event->name)
                return 0; /* No new name is requested. */

        dev = ASSERT_PTR(event->dev);

        r = sd_device_get_ifindex(dev, &ifindex);
        if (r == -ENOENT)
                return 0; /* Device is not a network interface. */
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get ifindex: %m");

        if (naming_scheme_has(NAMING_REPLACE_STRICTLY) &&
            !ifname_valid(event->name)) {
                log_device_warning(dev, "Invalid network interface name, ignoring: %s", event->name);
                return 0;
        }

        r = sd_device_get_sysname(dev, &s);
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get sysname: %m");

        if (streq(event->name, s))
                return 0; /* The interface name is already requested name. */

        old_sysname = strdup(s);
        if (!old_sysname)
                return -ENOMEM;

        r = sd_device_get_syspath(dev, &s);
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get syspath: %m");

        old_syspath = strdup(s);
        if (!old_syspath)
                return -ENOMEM;

        r = device_rename(dev, event->name);
        if (r < 0) {
                /* Here and below, use dev_db_clone for logging, otherwise, logged message is prefixed with
                 * the new interface name, and e.g. 'networkctl status INTERFACE' does not show the message. */
                log_device_warning_errno(event->dev_db_clone, r,
                                         "Failed to update properties with new name '%s': %m", event->name);
                goto revert;
        }

        /* Set ID_RENAMING boolean property here. It will be dropped when the corresponding move uevent is processed. */
        r = device_add_property(dev, "ID_RENAMING", "1");
        if (r < 0) {
                log_device_warning_errno(event->dev_db_clone, r, "Failed to add 'ID_RENAMING' property: %m");
                goto revert;
        }

        /* Also set ID_RENAMING boolean property to cloned sd_device object and save it to database
         * before calling rtnl_set_link_name(). Otherwise, clients (e.g., systemd-networkd) may receive
         * RTM_NEWLINK netlink message before the database is updated. */
        r = device_add_property(event->dev_db_clone, "ID_RENAMING", "1");
        if (r < 0) {
                log_device_warning_errno(event->dev_db_clone, r, "Failed to add 'ID_RENAMING' property: %m");
                goto revert;
        }

        r = device_add_property(event->dev_db_clone, "ID_PROCESSING", "1");
        if (r < 0) {
                log_device_warning_errno(event->dev_db_clone, r, "Failed to add 'ID_PROCESSING' property: %m");
                goto revert;
        }

        r = device_update_db(event->dev_db_clone);
        if (r < 0) {
                log_device_debug_errno(event->dev_db_clone, r, "Failed to update database under /run/udev/data/: %m");
                goto revert;
        }

        r = rtnl_set_link_name(&event->rtnl, ifindex, event->name, event->altnames);
        if (r < 0) {
                if (r == -EBUSY) {
                        log_device_info(event->dev_db_clone,
                                        "Network interface '%s' is already up, cannot rename to '%s'.",
                                        old_sysname, event->name);
                        r = 0;
                } else
                        log_device_error_errno(event->dev_db_clone, r,
                                               "Failed to rename network interface %i from '%s' to '%s': %m",
                                               ifindex, old_sysname, event->name);
                goto revert;
        }

        log_device_debug(dev, "Network interface %i is renamed from '%s' to '%s'", ifindex, old_sysname, event->name);
        return 1;

revert:
        /* Restore 'dev_db_clone' */
        (void) device_add_property(event->dev_db_clone, "ID_RENAMING", NULL);
        (void) device_add_property(event->dev_db_clone, "ID_PROCESSING", NULL);
        (void) device_update_db(event->dev_db_clone);

        /* Restore 'dev' */
        (void) device_set_syspath(dev, old_syspath, /* verify = */ false);
        if (sd_device_get_property_value(dev, "INTERFACE_OLD", &s) >= 0) {
                (void) device_add_property_internal(dev, "INTERFACE", s);
                (void) device_add_property_internal(dev, "INTERFACE_OLD", NULL);
        }
        (void) device_add_property(dev, "ID_RENAMING", NULL);

        return r;
}

static int assign_altnames(UdevEvent *event) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        int ifindex, r;
        const char *s;

        if (strv_isempty(event->altnames))
                return 0;

        r = sd_device_get_ifindex(dev, &ifindex);
        if (r == -ENOENT)
                return 0; /* Device is not a network interface. */
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get ifindex: %m");

        r = sd_device_get_sysname(dev, &s);
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get sysname: %m");

        /* Filter out the current interface name. */
        strv_remove(event->altnames, s);

        r = rtnl_append_link_alternative_names(&event->rtnl, ifindex, event->altnames);
        if (r < 0)
                log_device_full_errno(dev, r == -EOPNOTSUPP ? LOG_DEBUG : LOG_WARNING, r,
                                      "Could not set AlternativeName= or apply AlternativeNamesPolicy=, ignoring: %m");

        return 0;
}

static int update_devnode(UdevEvent *event) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        int r;

        r = sd_device_get_devnum(dev, NULL);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get devnum: %m");

        if (!uid_is_valid(event->uid)) {
                r = device_get_devnode_uid(dev, &event->uid);
                if (r < 0 && r != -ENOENT)
                        return log_device_error_errno(dev, r, "Failed to get devnode UID: %m");
        }

        if (!gid_is_valid(event->gid)) {
                r = device_get_devnode_gid(dev, &event->gid);
                if (r < 0 && r != -ENOENT)
                        return log_device_error_errno(dev, r, "Failed to get devnode GID: %m");
        }

        if (event->mode == MODE_INVALID) {
                r = device_get_devnode_mode(dev, &event->mode);
                if (r < 0 && r != -ENOENT)
                        return log_device_error_errno(dev, r, "Failed to get devnode mode: %m");
        }

        bool apply_mac = device_for_action(dev, SD_DEVICE_ADD);

        r = udev_node_apply_permissions(dev, apply_mac, event->mode, event->uid, event->gid, event->seclabel_list);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to apply devnode permissions: %m");

        return udev_node_update(dev, event->dev_db_clone);
}

static int event_execute_rules_on_remove(UdevEvent *event, UdevRules *rules) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        int r;

        r = device_read_db_internal(dev, true);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to read database under /run/udev/data/: %m");

        r = device_tag_index(dev, NULL, false);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to remove corresponding tag files under /run/udev/tag/, ignoring: %m");

        r = device_delete_db(dev);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to delete database under /run/udev/data/, ignoring: %m");

        r = udev_rules_apply_to_event(rules, event);

        if (sd_device_get_devnum(dev, NULL) >= 0)
                (void) udev_node_remove(dev);

        return r;
}

static int copy_all_tags(sd_device *d, sd_device *s) {
        int r;

        assert(d);

        if (!s)
                return 0;

        FOREACH_DEVICE_TAG(s, tag) {
                r = device_add_tag(d, tag, false);
                if (r < 0)
                        return r;
        }

        return 0;
}

int udev_event_execute_rules(UdevEvent *event, UdevRules *rules) {
        sd_device_action_t action;
        sd_device *dev;
        int r;

        dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        assert(rules);

        r = sd_device_get_action(dev, &action);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get ACTION: %m");

        if (action == SD_DEVICE_REMOVE)
                return event_execute_rules_on_remove(event, rules);

        r = device_clone_with_db(dev, &event->dev_db_clone);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to clone sd_device object: %m");

        r = copy_all_tags(dev, event->dev_db_clone);
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to copy all tags from old database entry, ignoring: %m");

        /* Drop previously added property for safety to make IMPORT{db}="ID_RENAMING" not work. This is
         * mostly for 'move' uevent, but let's do unconditionally. Why? If a network interface is renamed in
         * initrd, then udevd may lose the 'move' uevent during switching root. Usually, we do not set the
         * persistent flag for network interfaces, but user may set it. Just for safety. */
        r = device_add_property(event->dev_db_clone, "ID_RENAMING", NULL);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to remove 'ID_RENAMING' property: %m");

        /* If the database file already exists, append ID_PROCESSING property to the existing database,
         * to indicate that the device is being processed by udevd. */
        if (device_has_db(event->dev_db_clone) > 0) {
                r = device_add_property(event->dev_db_clone, "ID_PROCESSING", "1");
                if (r < 0)
                        return log_device_warning_errno(event->dev_db_clone, r, "Failed to add 'ID_PROCESSING' property: %m");

                r = device_update_db(event->dev_db_clone);
                if (r < 0)
                        return log_device_warning_errno(event->dev_db_clone, r, "Failed to update database under /run/udev/data/: %m");
        }

        DEVICE_TRACE_POINT(rules_start, dev);

        r = udev_rules_apply_to_event(rules, event);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to apply udev rules: %m");

        DEVICE_TRACE_POINT(rules_finished, dev);

        if (action == SD_DEVICE_ADD) {
                r = rename_netif(event);
                if (r < 0)
                        return r;
                if (r == 0)
                        (void) assign_altnames(event);
        }

        r = update_devnode(event);
        if (r < 0)
                return r;

        /* preserve old, or get new initialization timestamp */
        r = device_ensure_usec_initialized(dev, event->dev_db_clone);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to set initialization timestamp: %m");

        /* (re)write database file */
        r = device_tag_index(dev, event->dev_db_clone, true);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to update tags under /run/udev/tag/: %m");

        /* If the database file for the device will be created below, add ID_PROCESSING=1 to indicate that
         * the device is still being processed by udevd, as commands specified in RUN are invoked after
         * the database is created. See issue #30056. */
        if (device_should_have_db(dev) && !ordered_hashmap_isempty(event->run_list)) {
                r = device_add_property(dev, "ID_PROCESSING", "1");
                if (r < 0)
                        return log_device_warning_errno(dev, r, "Failed to add 'ID_PROCESSING' property: %m");
        }

        r = device_update_db(dev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to update database under /run/udev/data/: %m");

        device_set_is_initialized(dev);

        return 0;
}
