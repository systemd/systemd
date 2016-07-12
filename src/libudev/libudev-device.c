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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libudev.h"
#include "sd-device.h"

#include "alloc-util.h"
#include "device-private.h"
#include "device-util.h"
#include "libudev-device-internal.h"
#include "libudev-private.h"
#include "parse-util.h"

/**
 * SECTION:libudev-device
 * @short_description: kernel sys devices
 *
 * Representation of kernel sys devices. Devices are uniquely identified
 * by their syspath, every device has exactly one path in the kernel sys
 * filesystem. Devices usually belong to a kernel subsystem, and have
 * a unique name inside that subsystem.
 */

/**
 * udev_device_get_seqnum:
 * @udev_device: udev device
 *
 * This is only valid if the device was received through a monitor. Devices read from
 * sys do not have a sequence number.
 *
 * Returns: the kernel event sequence number, or 0 if there is no sequence number available.
 **/
_public_ unsigned long long int udev_device_get_seqnum(struct udev_device *udev_device)
{
        const char *seqnum;
        unsigned long long ret;
        int r;

        assert_return_errno(udev_device, 0, EINVAL);

        r = sd_device_get_property_value(udev_device->device, "SEQNUM", &seqnum);
        if (r == -ENOENT)
                return 0;
        else if (r < 0) {
                errno = -r;
                return 0;
        }

        r = safe_atollu(seqnum, &ret);
        if (r < 0) {
                errno = -r;
                return 0;
        }

        return ret;
}

/**
 * udev_device_get_devnum:
 * @udev_device: udev device
 *
 * Get the device major/minor number.
 *
 * Returns: the dev_t number.
 **/
_public_ dev_t udev_device_get_devnum(struct udev_device *udev_device)
{
        dev_t devnum;
        int r;

        assert_return_errno(udev_device, makedev(0, 0), EINVAL);

        r = sd_device_get_devnum(udev_device->device, &devnum);
        if (r < 0) {
                errno = -r;
                return makedev(0, 0);
        }

        return devnum;
}

/**
 * udev_device_get_driver:
 * @udev_device: udev device
 *
 * Get the kernel driver name.
 *
 * Returns: the driver name string, or #NULL if there is no driver attached.
 **/
_public_ const char *udev_device_get_driver(struct udev_device *udev_device)
{
        const char *driver;
        int r;

        assert_return_errno(udev_device, NULL, EINVAL);

        r = sd_device_get_driver(udev_device->device, &driver);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        return driver;
}

/**
 * udev_device_get_devtype:
 * @udev_device: udev device
 *
 * Retrieve the devtype string of the udev device.
 *
 * Returns: the devtype name of the udev device, or #NULL if it can not be determined
 **/
_public_ const char *udev_device_get_devtype(struct udev_device *udev_device)
{
        const char *devtype;
        int r;

        assert_return_errno(udev_device, NULL, EINVAL);

        r = sd_device_get_devtype(udev_device->device, &devtype);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        return devtype;
}

/**
 * udev_device_get_subsystem:
 * @udev_device: udev device
 *
 * Retrieve the subsystem string of the udev device. The string does not
 * contain any "/".
 *
 * Returns: the subsystem name of the udev device, or #NULL if it can not be determined
 **/
_public_ const char *udev_device_get_subsystem(struct udev_device *udev_device)
{
        const char *subsystem;
        int r;

        assert_return_errno(udev_device, NULL, EINVAL);

        r = sd_device_get_subsystem(udev_device->device, &subsystem);
        if (r < 0) {
                errno = -r;
                return NULL;
        } else if (!subsystem)
                errno = ENODATA;

        return subsystem;
}

/**
 * udev_device_get_property_value:
 * @udev_device: udev device
 * @key: property name
 *
 * Get the value of a given property.
 *
 * Returns: the property string, or #NULL if there is no such property.
 **/
_public_ const char *udev_device_get_property_value(struct udev_device *udev_device, const char *key)
{
        const char *value = NULL;
        int r;

        assert_return_errno(udev_device && key, NULL, EINVAL);

        r = sd_device_get_property_value(udev_device->device, key, &value);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        return value;
}

struct udev_device *udev_device_new(struct udev *udev) {
        struct udev_device *udev_device;

        assert_return_errno(udev, NULL, EINVAL);

        udev_device = new0(struct udev_device, 1);
        if (!udev_device) {
                errno = ENOMEM;
                return NULL;
        }
        udev_device->refcount = 1;
        udev_device->udev = udev;
        udev_list_init(udev, &udev_device->properties, true);
        udev_list_init(udev, &udev_device->tags, true);
        udev_list_init(udev, &udev_device->sysattrs, true);
        udev_list_init(udev, &udev_device->devlinks, true);

        return udev_device;
}

/**
 * udev_device_new_from_syspath:
 * @udev: udev library context
 * @syspath: sys device path including sys directory
 *
 * Create new udev device, and fill in information from the sys
 * device and the udev database entry. The syspath is the absolute
 * path to the device, including the sys mount point.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_syspath(struct udev *udev, const char *syspath) {
        struct udev_device *udev_device;
        int r;

        udev_device = udev_device_new(udev);
        if (!udev_device)
                return NULL;

        r = sd_device_new_from_syspath(&udev_device->device, syspath);
        if (r < 0) {
                errno = -r;
                udev_device_unref(udev_device);
                return NULL;
        }

        return udev_device;
}

/**
 * udev_device_new_from_devnum:
 * @udev: udev library context
 * @type: char or block device
 * @devnum: device major/minor number
 *
 * Create new udev device, and fill in information from the sys
 * device and the udev database entry. The device is looked-up
 * by its major/minor number and type. Character and block device
 * numbers are not unique across the two types.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_devnum(struct udev *udev, char type, dev_t devnum)
{
        struct udev_device *udev_device;
        int r;

        udev_device = udev_device_new(udev);
        if (!udev_device)
                return NULL;

        r = sd_device_new_from_devnum(&udev_device->device, type, devnum);
        if (r < 0) {
                errno = -r;
                udev_device_unref(udev_device);
                return NULL;
        }

        return udev_device;
}

/**
 * udev_device_new_from_device_id:
 * @udev: udev library context
 * @id: text string identifying a kernel device
 *
 * Create new udev device, and fill in information from the sys
 * device and the udev database entry. The device is looked-up
 * by a special string:
 *   b8:2          - block device major:minor
 *   c128:1        - char device major:minor
 *   n3            - network device ifindex
 *   +sound:card29 - kernel driver core subsystem:device name
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_device_id(struct udev *udev, const char *id)
{
        struct udev_device *udev_device;
        int r;

        udev_device = udev_device_new(udev);
        if (!udev_device)
                return NULL;

        r = sd_device_new_from_device_id(&udev_device->device, id);
        if (r < 0) {
                errno = -r;
                udev_device_unref(udev_device);
                return NULL;
        }

        return udev_device;
}

/**
 * udev_device_new_from_subsystem_sysname:
 * @udev: udev library context
 * @subsystem: the subsystem of the device
 * @sysname: the name of the device
 *
 * Create new udev device, and fill in information from the sys device
 * and the udev database entry. The device is looked up by the subsystem
 * and name string of the device, like "mem" / "zero", or "block" / "sda".
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_subsystem_sysname(struct udev *udev, const char *subsystem, const char *sysname)
{
        struct udev_device *udev_device;
        int r;

        udev_device = udev_device_new(udev);
        if (!udev_device)
                return NULL;

        r = sd_device_new_from_subsystem_sysname(&udev_device->device, subsystem, sysname);
        if (r < 0) {
                errno = -r;
                udev_device_unref(udev_device);
                return NULL;
        }

        return udev_device;
}

/**
 * udev_device_new_from_environment
 * @udev: udev library context
 *
 * Create new udev device, and fill in information from the
 * current process environment. This only works reliable if
 * the process is called from a udev rule. It is usually used
 * for tools executed from IMPORT= rules.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, if it does not exist
 **/
_public_ struct udev_device *udev_device_new_from_environment(struct udev *udev)
{
        struct udev_device *udev_device;
        int r;

        udev_device = udev_device_new(udev);
        if (!udev_device)
                return NULL;

        r = device_new_from_strv(&udev_device->device, environ);
        if (r < 0) {
                errno = -r;
                udev_device_unref(udev_device);
                return NULL;
        }

        return udev_device;
}

static struct udev_device *device_new_from_parent(struct udev_device *child)
{
        struct udev_device *parent;
        int r;

        assert_return_errno(child, NULL, EINVAL);

        parent = udev_device_new(child->udev);
        if (!parent)
                return NULL;

        r = sd_device_get_parent(child->device, &parent->device);
        if (r < 0) {
                errno = -r;
                udev_device_unref(parent);
                return NULL;
        }

        /* the parent is unref'ed with the child, so take a ref from libudev as well */
        sd_device_ref(parent->device);

        return parent;
}

/**
 * udev_device_get_parent:
 * @udev_device: the device to start searching from
 *
 * Find the next parent device, and fill in information from the sys
 * device and the udev database entry.
 *
 * Returned device is not referenced. It is attached to the child
 * device, and will be cleaned up when the child device is cleaned up.
 *
 * It is not necessarily just the upper level directory, empty or not
 * recognized sys directories are ignored.
 *
 * It can be called as many times as needed, without caring about
 * references.
 *
 * Returns: a new udev device, or #NULL, if it no parent exist.
 **/
_public_ struct udev_device *udev_device_get_parent(struct udev_device *udev_device)
{
        assert_return_errno(udev_device, NULL, EINVAL);

        if (!udev_device->parent_set) {
                udev_device->parent_set = true;
                udev_device->parent = device_new_from_parent(udev_device);
        }

        /* TODO: errno will differ here in case parent == NULL */
        return udev_device->parent;
}

/**
 * udev_device_get_parent_with_subsystem_devtype:
 * @udev_device: udev device to start searching from
 * @subsystem: the subsystem of the device
 * @devtype: the type (DEVTYPE) of the device
 *
 * Find the next parent device, with a matching subsystem and devtype
 * value, and fill in information from the sys device and the udev
 * database entry.
 *
 * If devtype is #NULL, only subsystem is checked, and any devtype will
 * match.
 *
 * Returned device is not referenced. It is attached to the child
 * device, and will be cleaned up when the child device is cleaned up.
 *
 * It can be called as many times as needed, without caring about
 * references.
 *
 * Returns: a new udev device, or #NULL if no matching parent exists.
 **/
_public_ struct udev_device *udev_device_get_parent_with_subsystem_devtype(struct udev_device *udev_device, const char *subsystem, const char *devtype)
{
        sd_device *parent;
        int r;

        assert_return_errno(udev_device, NULL, EINVAL);

        /* this relies on the fact that finding the subdevice of a parent or the
           parent of a subdevice commute */

        /* first find the correct sd_device */
        r = sd_device_get_parent_with_subsystem_devtype(udev_device->device, subsystem, devtype, &parent);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        /* then walk the chain of udev_device parents until the correspanding
           one is found */
        while ((udev_device = udev_device_get_parent(udev_device))) {
                if (udev_device->device == parent)
                        return udev_device;
        }

        errno = ENOENT;
        return NULL;
}

/**
 * udev_device_get_udev:
 * @udev_device: udev device
 *
 * Retrieve the udev library context the device was created with.
 *
 * Returns: the udev library context
 **/
_public_ struct udev *udev_device_get_udev(struct udev_device *udev_device)
{
        assert_return_errno(udev_device, NULL, EINVAL);

        return udev_device->udev;
}

/**
 * udev_device_ref:
 * @udev_device: udev device
 *
 * Take a reference of a udev device.
 *
 * Returns: the passed udev device
 **/
_public_ struct udev_device *udev_device_ref(struct udev_device *udev_device)
{
        if (udev_device)
                udev_device->refcount++;

        return udev_device;
}

/**
 * udev_device_unref:
 * @udev_device: udev device
 *
 * Drop a reference of a udev device. If the refcount reaches zero,
 * the resources of the device will be released.
 *
 * Returns: #NULL
 **/
_public_ struct udev_device *udev_device_unref(struct udev_device *udev_device)
{
        if (udev_device && (-- udev_device->refcount) == 0) {
                sd_device_unref(udev_device->device);
                udev_device_unref(udev_device->parent);

                udev_list_cleanup(&udev_device->properties);
                udev_list_cleanup(&udev_device->sysattrs);
                udev_list_cleanup(&udev_device->tags);
                udev_list_cleanup(&udev_device->devlinks);

                free(udev_device);
        }

        return NULL;
}

/**
 * udev_device_get_devpath:
 * @udev_device: udev device
 *
 * Retrieve the kernel devpath value of the udev device. The path
 * does not contain the sys mount point, and starts with a '/'.
 *
 * Returns: the devpath of the udev device
 **/
_public_ const char *udev_device_get_devpath(struct udev_device *udev_device)
{
        const char *devpath;
        int r;

        assert_return_errno(udev_device, NULL, EINVAL);

        r = sd_device_get_devpath(udev_device->device, &devpath);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        return devpath;
}

/**
 * udev_device_get_syspath:
 * @udev_device: udev device
 *
 * Retrieve the sys path of the udev device. The path is an
 * absolute path and starts with the sys mount point.
 *
 * Returns: the sys path of the udev device
 **/
_public_ const char *udev_device_get_syspath(struct udev_device *udev_device)
{
        const char *syspath;
        int r;

        assert_return_errno(udev_device, NULL, EINVAL);

        r = sd_device_get_syspath(udev_device->device, &syspath);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        return syspath;
}

/**
 * udev_device_get_sysname:
 * @udev_device: udev device
 *
 * Get the kernel device name in /sys.
 *
 * Returns: the name string of the device
 **/
_public_ const char *udev_device_get_sysname(struct udev_device *udev_device)
{
        const char *sysname;
        int r;

        assert_return_errno(udev_device, NULL, EINVAL);

        r = sd_device_get_sysname(udev_device->device, &sysname);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        return sysname;
}

/**
 * udev_device_get_sysnum:
 * @udev_device: udev device
 *
 * Get the instance number of the device.
 *
 * Returns: the trailing number string of the device name
 **/
_public_ const char *udev_device_get_sysnum(struct udev_device *udev_device)
{
        const char *sysnum;
        int r;

        assert_return_errno(udev_device, NULL, EINVAL);

        r = sd_device_get_sysnum(udev_device->device, &sysnum);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        return sysnum;
}

/**
 * udev_device_get_devnode:
 * @udev_device: udev device
 *
 * Retrieve the device node file name belonging to the udev device.
 * The path is an absolute path, and starts with the device directory.
 *
 * Returns: the device node file name of the udev device, or #NULL if no device node exists
 **/
_public_ const char *udev_device_get_devnode(struct udev_device *udev_device)
{
        const char *devnode;
        int r;

        assert_return_errno(udev_device, NULL, EINVAL);

        r = sd_device_get_devname(udev_device->device, &devnode);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        return devnode;
}

/**
 * udev_device_get_devlinks_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of device links pointing to the device file of
 * the udev device. The next list entry can be retrieved with
 * udev_list_entry_get_next(), which returns #NULL if no more entries exist.
 * The devlink path can be retrieved from the list entry by
 * udev_list_entry_get_name(). The path is an absolute path, and starts with
 * the device directory.
 *
 * Returns: the first entry of the device node link list
 **/
_public_ struct udev_list_entry *udev_device_get_devlinks_list_entry(struct udev_device *udev_device)
{
        assert_return_errno(udev_device, NULL, EINVAL);

        if (device_get_devlinks_generation(udev_device->device) != udev_device->devlinks_generation ||
            !udev_device->devlinks_read) {
                const char *devlink;

                udev_list_cleanup(&udev_device->devlinks);

                FOREACH_DEVICE_DEVLINK(udev_device->device, devlink)
                        udev_list_entry_add(&udev_device->devlinks, devlink, NULL);

                udev_device->devlinks_read = true;
                udev_device->devlinks_generation = device_get_devlinks_generation(udev_device->device);
        }

        return udev_list_get_entry(&udev_device->devlinks);
}

/**
 * udev_device_get_event_properties_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of key/value device properties of the udev
 * device. The next list entry can be retrieved with udev_list_entry_get_next(),
 * which returns #NULL if no more entries exist. The property name
 * can be retrieved from the list entry by udev_list_entry_get_name(),
 * the property value by udev_list_entry_get_value().
 *
 * Returns: the first entry of the property list
 **/
_public_ struct udev_list_entry *udev_device_get_properties_list_entry(struct udev_device *udev_device)
{
        assert_return_errno(udev_device, NULL, EINVAL);

        if (device_get_properties_generation(udev_device->device) != udev_device->properties_generation ||
            !udev_device->properties_read) {
                const char *key, *value;

                udev_list_cleanup(&udev_device->properties);

                FOREACH_DEVICE_PROPERTY(udev_device->device, key, value)
                        udev_list_entry_add(&udev_device->properties, key, value);

                udev_device->properties_read = true;
                udev_device->properties_generation = device_get_properties_generation(udev_device->device);
        }

        return udev_list_get_entry(&udev_device->properties);
}

/**
 * udev_device_get_action:
 * @udev_device: udev device
 *
 * This is only valid if the device was received through a monitor. Devices read from
 * sys do not have an action string. Usual actions are: add, remove, change, online,
 * offline.
 *
 * Returns: the kernel action value, or #NULL if there is no action value available.
 **/
_public_ const char *udev_device_get_action(struct udev_device *udev_device) {
        const char *action = NULL;
        int r;

        assert_return_errno(udev_device, NULL, EINVAL);

        r = sd_device_get_property_value(udev_device->device, "ACTION", &action);
        if (r < 0 && r != -ENOENT) {
                errno = -r;
                return NULL;
        }

        return action;
}

/**
 * udev_device_get_usec_since_initialized:
 * @udev_device: udev device
 *
 * Return the number of microseconds passed since udev set up the
 * device for the first time.
 *
 * This is only implemented for devices with need to store properties
 * in the udev database. All other devices return 0 here.
 *
 * Returns: the number of microseconds since the device was first seen.
 **/
_public_ unsigned long long int udev_device_get_usec_since_initialized(struct udev_device *udev_device)
{
        usec_t ts;
        int r;

        assert_return(udev_device, -EINVAL);

        r = sd_device_get_usec_since_initialized(udev_device->device, &ts);
        if (r < 0) {
                errno = EINVAL;
                return 0;
        }

        return ts;
}

/**
 * udev_device_get_sysattr_value:
 * @udev_device: udev device
 * @sysattr: attribute name
 *
 * The retrieved value is cached in the device. Repeated calls will return the same
 * value and not open the attribute again.
 *
 * Returns: the content of a sys attribute file, or #NULL if there is no sys attribute value.
 **/
_public_ const char *udev_device_get_sysattr_value(struct udev_device *udev_device, const char *sysattr)
{
        const char *value;
        int r;

        assert_return_errno(udev_device, NULL, EINVAL);

        r = sd_device_get_sysattr_value(udev_device->device, sysattr, &value);
        if (r < 0) {
                errno = -r;
                return NULL;
        }

        return value;
}

/**
 * udev_device_set_sysattr_value:
 * @udev_device: udev device
 * @sysattr: attribute name
 * @value: new value to be set
 *
 * Update the contents of the sys attribute and the cached value of the device.
 *
 * Returns: Negative error code on failure or 0 on success.
 **/
_public_ int udev_device_set_sysattr_value(struct udev_device *udev_device, const char *sysattr, char *value)
{
        int r;

        assert_return(udev_device, -EINVAL);

        r = sd_device_set_sysattr_value(udev_device->device, sysattr, value);
        if (r < 0)
                return r;

        return 0;
}

/**
 * udev_device_get_sysattr_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of available sysattrs, with value being empty;
 * This just return all available sysfs attributes for a particular
 * device without reading their values.
 *
 * Returns: the first entry of the property list
 **/
_public_ struct udev_list_entry *udev_device_get_sysattr_list_entry(struct udev_device *udev_device)
{
        assert_return_errno(udev_device, NULL, EINVAL);

        if (!udev_device->sysattrs_read) {
                const char *sysattr;

                udev_list_cleanup(&udev_device->sysattrs);

                FOREACH_DEVICE_SYSATTR(udev_device->device, sysattr)
                        udev_list_entry_add(&udev_device->sysattrs, sysattr, NULL);

                udev_device->sysattrs_read = true;
        }

        return udev_list_get_entry(&udev_device->sysattrs);
}

/**
 * udev_device_get_is_initialized:
 * @udev_device: udev device
 *
 * Check if udev has already handled the device and has set up
 * device node permissions and context, or has renamed a network
 * device.
 *
 * This is only implemented for devices with a device node
 * or network interfaces. All other devices return 1 here.
 *
 * Returns: 1 if the device is set up. 0 otherwise.
 **/
_public_ int udev_device_get_is_initialized(struct udev_device *udev_device)
{
        int r, initialized;

        assert_return(udev_device, -EINVAL);

        r = sd_device_get_is_initialized(udev_device->device, &initialized);
        if (r < 0) {
                errno = -r;

                return 0;
        }

        return initialized;
}

/**
 * udev_device_get_tags_list_entry:
 * @udev_device: udev device
 *
 * Retrieve the list of tags attached to the udev device. The next
 * list entry can be retrieved with udev_list_entry_get_next(),
 * which returns #NULL if no more entries exist. The tag string
 * can be retrieved from the list entry by udev_list_entry_get_name().
 *
 * Returns: the first entry of the tag list
 **/
_public_ struct udev_list_entry *udev_device_get_tags_list_entry(struct udev_device *udev_device)
{
        assert_return_errno(udev_device, NULL, EINVAL);

        if (device_get_tags_generation(udev_device->device) != udev_device->tags_generation ||
            !udev_device->tags_read) {
                const char *tag;

                udev_list_cleanup(&udev_device->tags);

                FOREACH_DEVICE_TAG(udev_device->device, tag)
                        udev_list_entry_add(&udev_device->tags, tag, NULL);

                udev_device->tags_read = true;
                udev_device->tags_generation = device_get_tags_generation(udev_device->device);
        }

        return udev_list_get_entry(&udev_device->tags);
}

/**
 * udev_device_has_tag:
 * @udev_device: udev device
 * @tag: tag name
 *
 * Check if a given device has a certain tag associated.
 *
 * Returns: 1 if the tag is found. 0 otherwise.
 **/
_public_ int udev_device_has_tag(struct udev_device *udev_device, const char *tag)
{
        assert_return(udev_device, 0);

        return sd_device_has_tag(udev_device->device, tag);
}
