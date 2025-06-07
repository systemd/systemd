/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libudev.h"
#include "sd-device.h"

#include "alloc-util.h"
#include "device-enumerator-private.h"
#include "errno-util.h"
#include "libudev-device-internal.h"
#include "libudev-list-internal.h"

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
        unsigned n_ref;
        struct udev_list *devices_list;
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
_public_ struct udev_enumerate* udev_enumerate_new(struct udev *udev) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(udev_list_freep) struct udev_list *list = NULL;
        struct udev_enumerate *udev_enumerate;
        int r;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return_with_errno(NULL, r);

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return_with_errno(NULL, r);

        list = udev_list_new(false);
        if (!list)
                return_with_errno(NULL, ENOMEM);

        udev_enumerate = new(struct udev_enumerate, 1);
        if (!udev_enumerate)
                return_with_errno(NULL, ENOMEM);

        *udev_enumerate = (struct udev_enumerate) {
                .udev = udev,
                .n_ref = 1,
                .enumerator = TAKE_PTR(e),
                .devices_list = TAKE_PTR(list),
        };

        return udev_enumerate;
}

static struct udev_enumerate* udev_enumerate_free(struct udev_enumerate *udev_enumerate) {
        assert(udev_enumerate);

        udev_list_free(udev_enumerate->devices_list);
        sd_device_enumerator_unref(udev_enumerate->enumerator);
        return mfree(udev_enumerate);
}

/**
 * udev_enumerate_ref:
 * @udev_enumerate: context
 *
 * Take a reference of an enumeration context.
 *
 * Returns: the passed enumeration context
 **/

/**
 * udev_enumerate_unref:
 * @udev_enumerate: context
 *
 * Drop a reference of an enumeration context. If the refcount reaches zero,
 * all resources of the enumeration context will be released.
 *
 * Returns: #NULL
 **/
DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(struct udev_enumerate, udev_enumerate, udev_enumerate_free);

/**
 * udev_enumerate_get_udev:
 * @udev_enumerate: context
 *
 * Get the udev library context.
 *
 * Returns: a pointer to the context.
 */
_public_ struct udev* udev_enumerate_get_udev(struct udev_enumerate *udev_enumerate) {
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
_public_ struct udev_list_entry* udev_enumerate_get_list_entry(struct udev_enumerate *udev_enumerate) {
        struct udev_list_entry *e;

        assert_return_errno(udev_enumerate, NULL, EINVAL);

        if (!udev_enumerate->devices_uptodate) {
                sd_device *device;

                udev_list_cleanup(udev_enumerate->devices_list);

                FOREACH_DEVICE_AND_SUBSYSTEM(udev_enumerate->enumerator, device) {
                        const char *syspath;
                        int r;

                        r = sd_device_get_syspath(device, &syspath);
                        if (r < 0)
                                return_with_errno(NULL, r);

                        if (!udev_list_entry_add(udev_enumerate->devices_list, syspath, NULL))
                                return_with_errno(NULL, ENOMEM);
                }

                udev_enumerate->devices_uptodate = true;
        }

        e = udev_list_get_entry(udev_enumerate->devices_list);
        if (!e)
                return_with_errno(NULL, ENODATA);

        return e;
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
        int r;

        assert_return(udev_enumerate, -EINVAL);

        if (!subsystem)
                return 0;

        r = sd_device_enumerator_add_match_subsystem(udev_enumerate->enumerator, subsystem, true);
        if (r < 0)
                return r;

        udev_enumerate->devices_uptodate = false;
        return 0;
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
        int r;

        assert_return(udev_enumerate, -EINVAL);

        if (!subsystem)
                return 0;

        r = sd_device_enumerator_add_match_subsystem(udev_enumerate->enumerator, subsystem, false);
        if (r < 0)
                return r;

        udev_enumerate->devices_uptodate = false;
        return 0;
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
        int r;

        assert_return(udev_enumerate, -EINVAL);

        if (!sysattr)
                return 0;

        r = sd_device_enumerator_add_match_sysattr(udev_enumerate->enumerator, sysattr, value, true);
        if (r < 0)
                return r;

        udev_enumerate->devices_uptodate = false;
        return 0;
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
        int r;

        assert_return(udev_enumerate, -EINVAL);

        if (!sysattr)
                return 0;

        r = sd_device_enumerator_add_match_sysattr(udev_enumerate->enumerator, sysattr, value, false);
        if (r < 0)
                return r;

        udev_enumerate->devices_uptodate = false;
        return 0;
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
        int r;

        assert_return(udev_enumerate, -EINVAL);

        if (!property)
                return 0;

        r = sd_device_enumerator_add_match_property(udev_enumerate->enumerator, property, value);
        if (r < 0)
                return r;

        udev_enumerate->devices_uptodate = false;
        return 0;
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
        int r;

        assert_return(udev_enumerate, -EINVAL);

        if (!tag)
                return 0;

        r = sd_device_enumerator_add_match_tag(udev_enumerate->enumerator, tag);
        if (r < 0)
                return r;

        udev_enumerate->devices_uptodate = false;
        return 0;
}

/**
 * udev_enumerate_add_match_parent:
 * @udev_enumerate: context
 * @parent: parent device where to start searching
 *
 * Return the devices on the subtree of one given device. The parent
 * itself is included in the list.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
_public_ int udev_enumerate_add_match_parent(struct udev_enumerate *udev_enumerate, struct udev_device *parent) {
        int r;

        assert_return(udev_enumerate, -EINVAL);

        if (!parent)
                return 0;

        r = sd_device_enumerator_add_match_parent(udev_enumerate->enumerator, udev_device_get_sd_device(parent));
        if (r < 0)
                return r;

        udev_enumerate->devices_uptodate = false;
        return 0;
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
        int r;

        assert_return(udev_enumerate, -EINVAL);

        r = device_enumerator_add_match_is_initialized(udev_enumerate->enumerator, MATCH_INITIALIZED_COMPAT);
        if (r < 0)
                return r;

        udev_enumerate->devices_uptodate = false;
        return 0;
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
        int r;

        assert_return(udev_enumerate, -EINVAL);

        if (!sysname)
                return 0;

        r = sd_device_enumerator_add_match_sysname(udev_enumerate->enumerator, sysname);
        if (r < 0)
                return r;

        udev_enumerate->devices_uptodate = false;
        return 0;
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
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
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

        udev_enumerate->devices_uptodate = false;
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
