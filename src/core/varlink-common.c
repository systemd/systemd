/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cpu-set-util.h"
#include "execute.h"
#include "json-util.h"
#include "rlimit-util.h"
#include "strv.h"
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
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        struct rlimit **rl = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        for (int i = 0; i < _RLIMIT_MAX; i++) {
                r = sd_json_variant_merge_objectbo(
                        &v,
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL(rlimit_to_string(i), rlimit_build_json, rl[i]));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);

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
                return log_debug_errno(r, "Failed to serialize cpu set to dbus: %m");

        if (allocated == 0)
                goto empty;

        return sd_json_variant_new_array_bytes(ret, array, allocated);

empty:
        *ret = NULL;
        return 0;
}

int exec_command_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecCommand *cmd = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **flags = NULL;
        int r;

        assert(ret);

        if (isempty(cmd->path)) {
                *ret = NULL;
                return 0;
        }

        r = exec_command_flags_to_strv(cmd->flags, &flags);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert exec command flags to strv: %m");

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("path", cmd->path),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("arguments", cmd->argv),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("flags", flags));
}
