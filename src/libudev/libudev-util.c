/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <errno.h>

#include "sd-device.h"

#include "device-nodes.h"
#include "libudev-util.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "utf8.h"

/**
 * SECTION:libudev-util
 * @short_description: utils
 *
 * Utilities useful when dealing with devices and device node names.
 */

/* handle "[<SUBSYSTEM>/<KERNEL>]<attribute>" format */
int util_resolve_subsys_kernel(const char *string, char *result, size_t maxsize, bool read_value) {
        char temp[UTIL_PATH_SIZE], *subsys, *sysname, *attr;
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        const char *val;
        int r;

        if (string[0] != '[')
                return -EINVAL;

        strscpy(temp, sizeof(temp), string);

        subsys = &temp[1];

        sysname = strchr(subsys, '/');
        if (!sysname)
                return -EINVAL;
        sysname[0] = '\0';
        sysname = &sysname[1];

        attr = strchr(sysname, ']');
        if (!attr)
                return -EINVAL;
        attr[0] = '\0';
        attr = &attr[1];
        if (attr[0] == '/')
                attr = &attr[1];
        if (attr[0] == '\0')
                attr = NULL;

        if (read_value && !attr)
                return -EINVAL;

        r = sd_device_new_from_subsystem_sysname(&dev, subsys, sysname);
        if (r < 0)
                return r;

        if (read_value) {
                r = sd_device_get_sysattr_value(dev, attr, &val);
                if (r < 0 && r != -ENOENT)
                        return r;
                if (r == -ENOENT)
                        result[0] = '\0';
                else
                        strscpy(result, maxsize, val);
                log_debug("value '[%s/%s]%s' is '%s'", subsys, sysname, attr, result);
        } else {
                r = sd_device_get_syspath(dev, &val);
                if (r < 0)
                        return r;

                strscpyl(result, maxsize, val, attr ? "/" : NULL, attr ?: NULL, NULL);
                log_debug("path '[%s/%s]%s' is '%s'", subsys, sysname, strempty(attr), result);
        }
        return 0;
}

/**
 * udev_util_encode_string:
 * @str: input string to be encoded
 * @str_enc: output string to store the encoded input string
 * @len: maximum size of the output string, which may be
 *       four times as long as the input string
 *
 * Encode all potentially unsafe characters of a string to the
 * corresponding 2 char hex value prefixed by '\x'.
 *
 * Returns: 0 if the entire string was copied, non-zero otherwise.
 **/
_public_ int udev_util_encode_string(const char *str, char *str_enc, size_t len) {
        return encode_devnode_name(str, str_enc, len);
}
