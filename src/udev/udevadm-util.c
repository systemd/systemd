/* SPDX-License-Identifier: GPL-2.0+ */

#include <errno.h>

#include "alloc-util.h"
#include "device-private.h"
#include "path-util.h"
#include "udevadm-util.h"
#include "unit-name.h"

int find_device(const char *id, const char *prefix, sd_device **ret) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(id);
        assert(ret);

        if (prefix) {
                if (!path_startswith(id, prefix)) {
                        id = path = path_join(prefix, id);
                        if (!path)
                                return -ENOMEM;
                }
        } else {
                /* In cases where the argument is generic (no prefix specified),
                 * check if the argument looks like a device unit name. */
                if (unit_name_is_valid(id, UNIT_NAME_PLAIN) && unit_name_to_type(id) == UNIT_DEVICE) {
                        r = unit_name_to_path(id, &path);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to convert \"%s\" to a device path: %m", id);
                        id = path;
                }
        }

        if (path_startswith(id, "/sys/"))
                return sd_device_new_from_syspath(ret, id);

        if (path_startswith(id, "/dev/")) {
                struct stat st;

                if (stat(id, &st) < 0)
                        return -errno;

                return device_new_from_stat_rdev(ret, &st);
        }

        return -EINVAL;
}
