/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cpu-set-util.h"
#include "json-util.h"
#include "rlimit-util.h"
#include "varlink-common.h"

int rlimit_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        const struct rlimit *rl = userdata;
        struct rlimit buf = {};

        assert(ret);
        assert(name);

        if (!rl) {
                int z = rlimit_from_string(name);
                if (z < 0)
                        return log_debug_errno(z, "Failed to get rlimit for '%s': %m", name);

                if (getrlimit(z, &buf) < 0) {
                        log_debug_errno(errno, "Failed to getrlimit(%s), ignoring: %m", name);
                        *ret = NULL;
                        return 0;
                }

                rl = &buf;
        }

        if (rl->rlim_cur == RLIM_INFINITY && rl->rlim_max == RLIM_INFINITY) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(ret,
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("soft", rl->rlim_cur, RLIM_INFINITY),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("hard", rl->rlim_max, RLIM_INFINITY));
}

int rlimit_table_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        struct rlimit **rl = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (int i = 0; i < _RLIMIT_MAX; i++) {
                r = sd_json_variant_merge_objectbo(
                        ret,
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL(rlimit_to_string(i), rlimit_build_json, rl[i]));
                if (r < 0)
                        return r;
        }

        return 0;
}

int cpuset_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_free_ uint8_t *array = NULL;
        CPUSet *cpuset = ASSERT_PTR(userdata);
        size_t allocated;
        int r;

        assert(ret);

        if (!cpuset->set)
                goto empty;

        r = cpu_set_to_dbus(cpuset, &array, &allocated);
        if (r < 0)
                return log_debug_errno(r, "Failed to call cpu_set_to_dbus(): %m");

        if (allocated == 0)
                goto empty;

        return sd_json_variant_new_array_bytes(ret, array, allocated);

empty:
        *ret = NULL;
        return 0;
}
