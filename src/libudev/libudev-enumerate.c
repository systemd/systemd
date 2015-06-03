/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>
  Copyright 2015 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fnmatch.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-device-internal.h"
#include "sd-device.h"
#include "device-util.h"
#include "device-enumerator-private.h"


/**
 * SECTION:libudev-enumerate
 * @short_description: lookup and sort sys devices
 *
 * Lookup devices in the sys filesystem, filter devices by properties,
 * and return a sorted list of devices.
 */

/**
 * udev_enumerate:
 *
 * Opaque object representing one device lookup/sort context.
 */
struct udev_enumerate {
        struct udev *udev;
        int refcount;
        struct udev_list devices_list;
        bool devices_uptodate:1;

        sd_device_enumerator *enumerator;
};

/**
 * udev_enumerate_new:
 * @udev: udev library context
 *
 * Create an enumeration context to scan /sys.
 *
 * Returns: an enumeration context.
 **/
_public_ struct udev_enumerate *udev_enumerate_new(struct udev *udev) {
        _cleanup_free_ struct udev_enumerate *udev_enumerate = NULL;
        struct udev_enumerate *ret;
        int r;

        assert_return_errno(udev, NULL, EINVAL);

        udev_enumerate = new0(struct udev_enumerate, 1);
        if (!udev_enumerate) {
                errno = ENOMEM;
                return NULL;
        }

        r = sd_device_enumerator_new(&udev_enumerate->enumerator);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        r = sd_device_enumerator_allow_uninitialized(udev_enumerate->enumerator);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        udev_enumerate->refcount = 1;
        udev_enumerate->udev = udev;

        udev_list_init(udev, &udev_enumerate->devices_list, false);

        ret = udev_enumerate;
        udev_enumerate = NULL;

        return ret;
}

/**
 * udev_enumerate_ref:
 * @udev_enumerate: context
 *
 * Take a reference of a enumeration context.
 *
 * Returns: the passed enumeration context
 **/
_public_ struct udev_enumerate *udev_enumerate_ref(struct udev_enumerate *udev_enumerate) {
        if (udev_enumerate)
                udev_enumerate->refcount ++;

        return udev_enumerate;
}

/**
 * udev_enumerate_unref:
 * @udev_enumerate: context
 *
 * Drop a reference of an enumeration context. If the refcount reaches zero,
 * all resources of the enumeration context will be released.
 *
 * Returns: #NULL
 **/
_public_ struct udev_enumerate *udev_enumerate_unref(struct udev_enumerate *udev_enumerate) {
        if (udev_enumerate && (-- udev_enumerate->refcount) == 0) {
                udev_list_cleanup(&udev_enumerate->devices_list);
                sd_device_enumerator_unref(udev_enumerate->enumerator);
                free(udev_enumerate);
        }

        return NULL;
}

/**
 * udev_enumerate_get_udev:
 * @udev_enumerate: context
 *
 * Get the udev library context.
 *
 * Returns: a pointer to the context.
 */
_public_ struct udev *udev_enumerate_get_udev(struct udev_enumerate *udev_enumerate) {
        assert_return_errno(udev_enumerate, NULL, EINVAL);

        return udev_enumerate->udev;
}

/**
 * udev_enumerate_get_list_entry:
 * @udev_enumerate: context
 *
 * Get the first entry of the sorted list of device paths.
 *
 * Returns: a udev_list_entry.
 */
_public_ struct udev_list_entry *udev_enumerate_get_list_entry(struct udev_enumerate *udev_enumerate) {
        assert_return_errno(udev_enumerate, NULL, EINVAL);

        if (!udev_enumerate->devices_uptodate) {
                sd_device *device;

                udev_list_cleanup(&udev_enumerate->devices_list);

                FOREACH_DEVICE_AND_SUBSYSTEM(udev_enumerate->enumerator, device) {
                        const char *syspath;
                        int r;

                        r = sd_device_get_syspath(device, &syspath);
                        if (r < 0) {
                                errno = -r;
                                return NULL;
                        }

                        udev_list_entry_add(&udev_enumerate->devices_list, syspath, NULL);
                }

                udev_enumerate->devices_uptodate = true;
        }

        return udev_list_get_entry(&udev_enumerate->devices_list);
}

/**
 * udev_enumerate_add_match_subsystem:
 * @udev_enumerate: context
 * @subsystem: filter for a subsystem of the device to include in the list
 *
 * Match only devices belonging to a certain kernel subsystem.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_enumerate_add_match_subsystem(struct udev_enumerate *udev_enumerate, const char *subsystem) {
        assert_return(udev_enumerate, -EINVAL);

        if (!subsystem)
                return 0;

        return sd_device_enumerator_add_match_subsystem(udev_enumerate->enumerator, subsystem, true);
}

/**
 * udev_enumerate_add_nomatch_subsystem:
 * @udev_enumerate: context
 * @subsystem: filter for a subsystem of the device to exclude from the list
 *
 * Match only devices not belonging to a certain kernel subsystem.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_enumerate_add_nomatch_subsystem(struct udev_enumerate *udev_enumerate, const char *subsystem) {
        assert_return(udev_enumerate, -EINVAL);

        if (!subsystem)
                return 0;

        return sd_device_enumerator_add_match_subsystem(udev_enumerate->enumerator, subsystem, false);
}

/**
 * udev_enumerate_add_match_sysattr:
 * @udev_enumerate: context
 * @sysattr: filter for a sys attribute at the device to include in the list
 * @value: optional value of the sys attribute
 *
 * Match only devices with a certain /sys device attribute.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_enumerate_add_match_sysattr(struct udev_enumerate *udev_enumerate, const char *sysattr, const char *value) {
        assert_return(udev_enumerate, -EINVAL);

        if (!sysattr)
                return 0;

        return sd_device_enumerator_add_match_sysattr(udev_enumerate->enumerator, sysattr, value, true);
}

/**
 * udev_enumerate_add_nomatch_sysattr:
 * @udev_enumerate: context
 * @sysattr: filter for a sys attribute at the device to exclude from the list
 * @value: optional value of the sys attribute
 *
 * Match only devices not having a certain /sys device attribute.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_enumerate_add_nomatch_sysattr(struct udev_enumerate *udev_enumerate, const char *sysattr, const char *value) {
        assert_return(udev_enumerate, -EINVAL);

        if (!sysattr)
                return 0;

        return sd_device_enumerator_add_match_sysattr(udev_enumerate->enumerator, sysattr, value, false);
}

/**
 * udev_enumerate_add_match_property:
 * @udev_enumerate: context
 * @property: filter for a property of the device to include in the list
 * @value: value of the property
 *
 * Match only devices with a certain property.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_enumerate_add_match_property(struct udev_enumerate *udev_enumerate, const char *property, const char *value) {
        assert_return(udev_enumerate, -EINVAL);

        if (!property)
                return 0;

        return sd_device_enumerator_add_match_property(udev_enumerate->enumerator, property, value);
}

/**
 * udev_enumerate_add_match_tag:
 * @udev_enumerate: context
 * @tag: filter for a tag of the device to include in the list
 *
 * Match only devices with a certain tag.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_enumerate_add_match_tag(struct udev_enumerate *udev_enumerate, const char *tag) {
        assert_return(udev_enumerate, -EINVAL);

        if (!tag)
                return 0;

        return sd_device_enumerator_add_match_tag(udev_enumerate->enumerator, tag);
}

/**
 * udev_enumerate_add_match_parent:
 * @udev_enumerate: context
 * @parent: parent device where to start searching
 *
 * Return the devices on the subtree of one given device. The parent
 * itself is included in the list.
 *
 * A reference for the device is held until the udev_enumerate context
 * is cleaned up.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_enumerate_add_match_parent(struct udev_enumerate *udev_enumerate, struct udev_device *parent) {
        assert_return(udev_enumerate, -EINVAL);

        if (!parent)
                return 0;

        return sd_device_enumerator_add_match_parent(udev_enumerate->enumerator, parent->device);
}

/**
 * udev_enumerate_add_match_is_initialized:
 * @udev_enumerate: context
 *
 * Match only devices which udev has set up already. This makes
 * sure, that the device node permissions and context are properly set
 * and that network devices are fully renamed.
 *
 * Usually, devices which are found in the kernel but not already
 * handled by udev, have still pending events. Services should subscribe
 * to monitor events and wait for these devices to become ready, instead
 * of using uninitialized devices.
 *
 * For now, this will not affect devices which do not have a device node
 * and are not network interfaces.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_enumerate_add_match_is_initialized(struct udev_enumerate *udev_enumerate) {
        assert_return(udev_enumerate, -EINVAL);

        return device_enumerator_add_match_is_initialized(udev_enumerate->enumerator);
}

/**
 * udev_enumerate_add_match_sysname:
 * @udev_enumerate: context
 * @sysname: filter for the name of the device to include in the list
 *
 * Match only devices with a given /sys device name.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_enumerate_add_match_sysname(struct udev_enumerate *udev_enumerate, const char *sysname) {
        assert_return(udev_enumerate, -EINVAL);

        if (!sysname)
                return 0;

        return sd_device_enumerator_add_match_sysname(udev_enumerate->enumerator, sysname);
}

/**
 * udev_enumerate_add_syspath:
 * @udev_enumerate: context
 * @syspath: path of a device
 *
 * Add a device to the list of devices, to retrieve it back sorted in dependency order.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_enumerate_add_syspath(struct udev_enumerate *udev_enumerate, const char *syspath) {
        _cleanup_device_unref_ sd_device *device = NULL;
        int r;

        assert_return(udev_enumerate, -EINVAL);

        if (!syspath)
                return 0;

        r = sd_device_new_from_syspath(&device, syspath);
        if (r < 0)
                return r;

        r = device_enumerator_add_device(udev_enumerate->enumerator, device);
        if (r < 0)
                return r;

        return 0;
}

/**
 * udev_enumerate_scan_devices:
 * @udev_enumerate: udev enumeration context
 *
 * Scan /sys for all devices which match the given filters. No matches
 * will return all currently available devices.
 *
 * Returns: 0 on success, otherwise a negative error value.
 **/
_public_ int udev_enumerate_scan_devices(struct udev_enumerate *udev_enumerate) {
        assert_return(udev_enumerate, -EINVAL);

        return device_enumerator_scan_devices(udev_enumerate->enumerator);
}

/**
 * udev_enumerate_scan_subsystems:
 * @udev_enumerate: udev enumeration context
 *
 * Scan /sys for all kernel subsystems, including buses, classes, drivers.
 *
 * Returns: 0 on success, otherwise a negative error value.
 **/
_public_ int udev_enumerate_scan_subsystems(struct udev_enumerate *udev_enumerate) {
        assert_return(udev_enumerate, -EINVAL);

        return device_enumerator_scan_subsystems(udev_enumerate->enumerator);
}
