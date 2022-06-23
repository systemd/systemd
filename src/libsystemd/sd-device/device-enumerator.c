/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "device-internal.h"
#include "device-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "set.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"

_public_ int sd_device_enumerator_new(sd_device_enumerator **ret) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *enumerator = NULL;

        assert(ret);

        enumerator = new(sd_device_enumerator, 1);
        if (!enumerator)
                return -ENOMEM;

        *enumerator = (sd_device_enumerator) {
                .n_ref = 1,
                .type = _DEVICE_ENUMERATION_TYPE_INVALID,
                .match_initialized = MATCH_INITIALIZED_COMPAT,
        };

        *ret = TAKE_PTR(enumerator);

        return 0;
}

static sd_device_enumerator *device_enumerator_free(sd_device_enumerator *enumerator) {
        assert(enumerator);

        device_enumerator_unref_devices(enumerator);

        hashmap_free(enumerator->devices_by_syspath);
        strv_free(enumerator->prioritized_subsystems);
        set_free(enumerator->match_subsystem);
        set_free(enumerator->nomatch_subsystem);
        hashmap_free(enumerator->match_sysattr);
        hashmap_free(enumerator->nomatch_sysattr);
        hashmap_free(enumerator->match_property);
        set_free(enumerator->match_sysname);
        set_free(enumerator->nomatch_sysname);
        set_free(enumerator->match_tag);
        set_free(enumerator->match_parent);

        return mfree(enumerator);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_device_enumerator, sd_device_enumerator, device_enumerator_free);

_public_ int sd_device_enumerator_add_match_subsystem(sd_device_enumerator *enumerator, const char *subsystem, int match) {
        Set **set;
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(subsystem, -EINVAL);

        if (match)
                set = &enumerator->match_subsystem;
        else
                set = &enumerator->nomatch_subsystem;

        r = set_put_strdup(set, subsystem);
        if (r <= 0)
                return r;

        enumerator->scan_uptodate = false;

        return 1;
}

_public_ int sd_device_enumerator_add_match_sysattr(sd_device_enumerator *enumerator, const char *sysattr, const char *value, int match) {
        Hashmap **hashmap;
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(sysattr, -EINVAL);

        if (match)
                hashmap = &enumerator->match_sysattr;
        else
                hashmap = &enumerator->nomatch_sysattr;

        /* Do not use string_has_ops_free_free or hashmap_put_strdup() here, as this may be called
         * multiple times with the same sysattr but different value. */
        r = hashmap_put_strdup_full(hashmap, &trivial_hash_ops_free_free, sysattr, value);
        if (r <= 0)
                return r;

        enumerator->scan_uptodate = false;

        return 1;
}

_public_ int sd_device_enumerator_add_match_property(sd_device_enumerator *enumerator, const char *property, const char *value) {
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(property, -EINVAL);

        /* Do not use string_has_ops_free_free or hashmap_put_strdup() here, as this may be called
         * multiple times with the same property but different value. */
        r = hashmap_put_strdup_full(&enumerator->match_property, &trivial_hash_ops_free_free, property, value);
        if (r <= 0)
                return r;

        enumerator->scan_uptodate = false;

        return 1;
}

static int device_enumerator_add_match_sysname(sd_device_enumerator *enumerator, const char *sysname, bool match) {
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(sysname, -EINVAL);

        r = set_put_strdup(match ? &enumerator->match_sysname : &enumerator->nomatch_sysname, sysname);
        if (r <= 0)
                return r;

        enumerator->scan_uptodate = false;

        return 1;
}

_public_ int sd_device_enumerator_add_match_sysname(sd_device_enumerator *enumerator, const char *sysname) {
        return device_enumerator_add_match_sysname(enumerator, sysname, true);
}

_public_ int sd_device_enumerator_add_nomatch_sysname(sd_device_enumerator *enumerator, const char *sysname) {
        return device_enumerator_add_match_sysname(enumerator, sysname, false);
}

_public_ int sd_device_enumerator_add_match_tag(sd_device_enumerator *enumerator, const char *tag) {
        int r;

        assert_return(enumerator, -EINVAL);
        assert_return(tag, -EINVAL);

        r = set_put_strdup(&enumerator->match_tag, tag);
        if (r <= 0)
                return r;

        enumerator->scan_uptodate = false;

        return 1;
}

_public_ int sd_device_enumerator_add_match_parent(sd_device_enumerator *enumerator, sd_device *parent) {
        assert_return(enumerator, -EINVAL);
        assert_return(parent, -EINVAL);

        set_clear(enumerator->match_parent);

        return device_enumerator_add_match_parent_incremental(enumerator, parent);
}

_public_ int sd_device_enumerator_allow_uninitialized(sd_device_enumerator *enumerator) {
        assert_return(enumerator, -EINVAL);

        enumerator->match_initialized = MATCH_INITIALIZED_ALL;

        enumerator->scan_uptodate = false;

        return 1;
}

_public_ sd_device *sd_device_enumerator_get_device_first(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (device_enumerator_scan_devices(enumerator) < 0)
                return NULL;

        if (device_enumerator_sort_devices(enumerator) < 0)
                return NULL;

        enumerator->current_device_index = 0;

        if (enumerator->n_devices == 0)
                return NULL;

        return enumerator->devices[0];
}

_public_ sd_device *sd_device_enumerator_get_device_next(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (!enumerator->scan_uptodate ||
            !enumerator->sorted ||
            enumerator->type != DEVICE_ENUMERATION_TYPE_DEVICES ||
            enumerator->current_device_index + 1 >= enumerator->n_devices)
                return NULL;

        return enumerator->devices[++enumerator->current_device_index];
}

_public_ sd_device *sd_device_enumerator_get_subsystem_first(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (device_enumerator_scan_subsystems(enumerator) < 0)
                return NULL;

        if (device_enumerator_sort_devices(enumerator) < 0)
                return NULL;

        enumerator->current_device_index = 0;

        if (enumerator->n_devices == 0)
                return NULL;

        return enumerator->devices[0];
}

_public_ sd_device *sd_device_enumerator_get_subsystem_next(sd_device_enumerator *enumerator) {
        assert_return(enumerator, NULL);

        if (!enumerator->scan_uptodate ||
            !enumerator->sorted ||
            enumerator->type != DEVICE_ENUMERATION_TYPE_SUBSYSTEMS ||
            enumerator->current_device_index + 1 >= enumerator->n_devices)
                return NULL;

        return enumerator->devices[++enumerator->current_device_index];
}
