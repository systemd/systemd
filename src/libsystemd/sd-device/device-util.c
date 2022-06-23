/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>

#include "device-util.h"
#include "path-util.h"
#include "string-table.h"
#include "string-util.h"

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

bool device_match_parent(sd_device *device, Set *match_parent, Set *nomatch_parent) {
        const char *syspath_parent, *syspath;

        assert(device);

        if (sd_device_get_syspath(device, &syspath) < 0)
                return false;

        SET_FOREACH(syspath_parent, nomatch_parent)
                if (path_startswith(syspath, syspath_parent))
                        return false;

        if (set_isempty(match_parent))
                return true;

        SET_FOREACH(syspath_parent, match_parent)
                if (path_startswith(syspath, syspath_parent))
                        return true;

        return false;
}

static const char* const device_action_table[_SD_DEVICE_ACTION_MAX] = {
        [SD_DEVICE_ADD]     = "add",
        [SD_DEVICE_REMOVE]  = "remove",
        [SD_DEVICE_CHANGE]  = "change",
        [SD_DEVICE_MOVE]    = "move",
        [SD_DEVICE_ONLINE]  = "online",
        [SD_DEVICE_OFFLINE] = "offline",
        [SD_DEVICE_BIND]    = "bind",
        [SD_DEVICE_UNBIND]  = "unbind",
};

DEFINE_STRING_TABLE_LOOKUP(device_action, sd_device_action_t);

void dump_device_action_table(void) {
        DUMP_STRING_TABLE(device_action, sd_device_action_t, _SD_DEVICE_ACTION_MAX);
}
