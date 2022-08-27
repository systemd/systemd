/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>

#include "device-filter.h"
#include "path-util.h"

int update_match_strv(Hashmap **match_strv, const char *key, const char *value, bool clear_on_null) {
        char **strv;
        int r;

        assert(match_strv);
        assert(key);

        strv = hashmap_get(*match_strv, key);
        if (strv) {
                if (!value) {
                        char **v;

                        if (strv_isempty(strv) || !clear_on_null)
                                return 0;

                        /* Accept all value. Clear previous assignment. */

                        v = new0(char*, 1);
                        if (!v)
                                return -ENOMEM;

                        strv_free_and_replace(strv, v);
                } else {
                        if (strv_contains(strv, value))
                                return 0;

                        r = strv_extend(&strv, value);
                        if (r < 0)
                                return r;
                }

                r = hashmap_update(*match_strv, key, strv);
                if (r < 0)
                        return r;

        } else {
                _cleanup_strv_free_ char **strv_alloc = NULL;
                _cleanup_free_ char *key_alloc = NULL;

                key_alloc = strdup(key);
                if (!key_alloc)
                        return -ENOMEM;

                strv_alloc = strv_new(value);
                if (!strv_alloc)
                        return -ENOMEM;

                r = hashmap_ensure_put(match_strv, &string_hash_ops_free_strv_free, key_alloc, strv_alloc);
                if (r < 0)
                        return r;

                TAKE_PTR(key_alloc);
                TAKE_PTR(strv_alloc);
        }

        return 1;
}

static bool device_match_sysattr_value(sd_device *device, const char *sysattr, char * const *patterns) {
        const char *value;

        assert(device);
        assert(sysattr);

        if (sd_device_get_sysattr_value(device, sysattr, &value) < 0)
                return false;

        return strv_fnmatch_or_empty(patterns, value, 0);
}

bool device_match_sysattr(sd_device *device, Hashmap *match_sysattr, Hashmap *nomatch_sysattr) {
        char * const *patterns;
        const char *sysattr;

        assert(device);

        HASHMAP_FOREACH_KEY(patterns, sysattr, match_sysattr)
                if (!device_match_sysattr_value(device, sysattr, patterns))
                        return false;

        HASHMAP_FOREACH_KEY(patterns, sysattr, nomatch_sysattr)
                if (device_match_sysattr_value(device, sysattr, patterns))
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
