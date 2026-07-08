/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "clonesetup-util.h"
#include "log.h"
#include "path-util.h"
#include "string-util.h"

int validate_dev_path(const char *what, const char *path) {
        if (!string_is_safe(path, 0) || !path_is_normalized(path) ||
            !path_is_absolute(path) || !path_startswith(path, "/dev/"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid %s device path '%s'.", what, path);
        return 0;
}

int validate_fields(const char *name, const char *src, const char *dst,
                    const char *meta, const char *options) {
        int r;

        if (!filename_is_valid(name))
                return -EINVAL;

        r = validate_dev_path("source", src);
        if (r < 0)
                return r;
        r = validate_dev_path("destination", dst);
        if (r < 0)
                return r;
        r = validate_dev_path("metadata", meta);
        if (r < 0)
                return r;

        if (options && !string_is_safe(options, 0))
                return -EINVAL;

        return 0;
}
