/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>

#include "device-util.h"

static bool device_match_sysattr_value(sd_device *device, const char *sysattr, const char *match_value) {
        const char *value;

        assert(device);
        assert(sysattr);

        if (sd_device_get_sysattr_value(device, sysattr, &value) < 0)
                return false;

        if (!match_value)
                return true;

        if (fnmatch(match_value, value, 0) == 0)
                return true;

        return false;
}

bool device_match_sysattr(sd_device *device, Hashmap *match_sysattr, Hashmap *nomatch_sysattr) {
        const char *sysattr;
        const char *value;

        assert(device);

        HASHMAP_FOREACH_KEY(value, sysattr, match_sysattr)
                if (!device_match_sysattr_value(device, sysattr, value))
                        return false;

        HASHMAP_FOREACH_KEY(value, sysattr, nomatch_sysattr)
                if (device_match_sysattr_value(device, sysattr, value))
                        return false;

        return true;
}
