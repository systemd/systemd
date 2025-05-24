/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-hwdb.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "libudev-list-internal.h"

/**
 * SECTION:libudev-hwdb
 * @short_description: retrieve properties from the hardware database
 *
 * Libudev hardware database interface.
 */

/**
 * udev_hwdb:
 *
 * Opaque object representing the hardware database.
 */
struct udev_hwdb {
        unsigned n_ref;
        sd_hwdb *hwdb;
        struct udev_list *properties_list;
};

/**
 * udev_hwdb_new:
 * @udev: udev library context (unused)
 *
 * Create a hardware database context to query properties for devices.
 *
 * Returns: a hwdb context.
 **/
_public_ struct udev_hwdb* udev_hwdb_new(struct udev *udev) {
        _cleanup_(udev_list_freep) struct udev_list *list = NULL;
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb_internal = NULL;
        struct udev_hwdb *hwdb;
        int r;

        r = sd_hwdb_new(&hwdb_internal);
        if (r < 0)
                return_with_errno(NULL, r);

        list = udev_list_new(true);
        if (!list)
                return_with_errno(NULL, ENOMEM);

        hwdb = new(struct udev_hwdb, 1);
        if (!hwdb)
                return_with_errno(NULL, ENOMEM);

        *hwdb = (struct udev_hwdb) {
                .n_ref = 1,
                .hwdb = TAKE_PTR(hwdb_internal),
                .properties_list = TAKE_PTR(list),
        };

        return hwdb;
}

static struct udev_hwdb* udev_hwdb_free(struct udev_hwdb *hwdb) {
        assert(hwdb);

        sd_hwdb_unref(hwdb->hwdb);
        udev_list_free(hwdb->properties_list);
        return mfree(hwdb);
}

/**
 * udev_hwdb_ref:
 * @hwdb: context
 *
 * Take a reference of a hwdb context.
 *
 * Returns: the passed enumeration context
 **/

/**
 * udev_hwdb_unref:
 * @hwdb: context
 *
 * Drop a reference of a hwdb context. If the refcount reaches zero,
 * all resources of the hwdb context will be released.
 *
 * Returns: #NULL
 **/
DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(struct udev_hwdb, udev_hwdb, udev_hwdb_free);

/**
 * udev_hwdb_get_properties_list_entry:
 * @hwdb: context
 * @modalias: modalias string
 * @flags: (unused)
 *
 * Lookup a matching device in the hardware database. The lookup key is a
 * modalias string, whose formats are defined for the Linux kernel modules.
 * Examples are: pci:v00008086d00001C2D*, usb:v04F2pB221*. The first entry
 * of a list of retrieved properties is returned.
 *
 * Returns: a udev_list_entry.
 */
_public_ struct udev_list_entry* udev_hwdb_get_properties_list_entry(struct udev_hwdb *hwdb, const char *modalias, unsigned flags) {
        const char *key, *value;
        struct udev_list_entry *e;

        assert_return_errno(hwdb, NULL, EINVAL);
        assert_return_errno(modalias, NULL, EINVAL);

        udev_list_cleanup(hwdb->properties_list);

        SD_HWDB_FOREACH_PROPERTY(hwdb->hwdb, modalias, key, value)
                if (!udev_list_entry_add(hwdb->properties_list, key, value))
                        return_with_errno(NULL, ENOMEM);

        e = udev_list_get_entry(hwdb->properties_list);
        if (!e)
                return_with_errno(NULL, ENODATA);

        return e;
}
