/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "libudev.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "log.h"

/**
 * SECTION:libudev
 * @short_description: libudev context
 */

/**
 * udev:
 *
 * Opaque object representing the library context.
 */
struct udev {
        unsigned n_ref;
        void *userdata;
};

/**
 * udev_get_userdata:
 * @udev: udev library context
 *
 * Retrieve stored data pointer from library context. This might be useful
 * to access from callbacks.
 *
 * Returns: stored userdata
 **/
_public_ void* udev_get_userdata(struct udev *udev) {
        assert_return(udev, NULL);

        return udev->userdata;
}

/**
 * udev_set_userdata:
 * @udev: udev library context
 * @userdata: data pointer
 *
 * Store custom @userdata in the library context.
 **/
_public_ void udev_set_userdata(struct udev *udev, void *userdata) {
        if (!udev)
                return;

        udev->userdata = userdata;
}

/**
 * udev_new:
 *
 * Create udev library context. This only allocates the basic data structure.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev library context.
 *
 * Returns: a new udev library context
 **/
_public_ struct udev* udev_new(void) {
        struct udev *udev;

        udev = new(struct udev, 1);
        if (!udev)
                return_with_errno(NULL, ENOMEM);

        *udev = (struct udev) {
                .n_ref = 1,
        };

        return udev;
}

/**
 * udev_ref:
 * @udev: udev library context
 *
 * Take a reference of the udev library context.
 *
 * Returns: the passed udev library context
 **/
DEFINE_PUBLIC_TRIVIAL_REF_FUNC(struct udev, udev);

/**
 * udev_unref:
 * @udev: udev library context
 *
 * Drop a reference of the udev library context. If the refcount
 * reaches zero, the resources of the context will be released.
 *
 * Returns: the passed udev library context if it has still an active reference, or #NULL otherwise.
 **/
_public_ struct udev* udev_unref(struct udev *udev) {
        if (!udev)
                return NULL;

        assert(udev->n_ref > 0);
        udev->n_ref--;
        if (udev->n_ref > 0)
                /* This is different from our convention, but let's keep backward
                 * compatibility. So, do not use DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC()
                 * macro to define this function. */
                return udev;

        return mfree(udev);
}

/**
 * udev_set_log_fn:
 * @udev: udev library context
 * @log_fn: function to be called for log messages
 *
 * This function is deprecated.
 *
 **/
_public_ void udev_set_log_fn(
                struct udev *udev,
                void (*log_fn)(struct udev *udev,
                               int priority,
                               const char *file,
                               int line,
                               const char *fn,
                               const char *format,
                               va_list args)) {
        return;
}

/**
 * udev_get_log_priority:
 * @udev: udev library context
 *
 * This function is deprecated.
 *
 **/
_public_ int udev_get_log_priority(struct udev *udev) {
        return log_get_max_level();
}

/**
 * udev_set_log_priority:
 * @udev: udev library context
 * @priority: the new log priority
 *
 * This function is deprecated.
 *
 **/
_public_ void udev_set_log_priority(struct udev *udev, int priority) {
        log_set_max_level(priority);
}
