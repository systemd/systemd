/* SPDX-License-Identifier: GPL-2.0+ */

#include <errno.h>

#include "alloc-util.h"
#include "device-private.h"
#include "path-util.h"
#include "udevadm-util.h"

int find_device(const char *id, const char *prefix, sd_device **ret) {
        _cleanup_free_ char *buf = NULL;

        assert(id);
        assert(ret);

        if (prefix && !path_startswith(id, prefix)) {
                buf = path_join(prefix, id);
                if (!buf)
                        return -ENOMEM;
                id = buf;
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
