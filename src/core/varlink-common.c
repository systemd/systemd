/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-common-errors.h"
#include "cpu-set-util.h"
#include "json-util.h"
#include "rlimit-util.h"
#include "varlink-common.h"
#include "varlink-unit.h"

const char* varlink_error_id_from_bus_error(const sd_bus_error *e) {
        static const struct {
                const char *bus_error;
                const char *varlink_error;
        } map[] = {
                { BUS_ERROR_NO_SUCH_UNIT,       VARLINK_ERROR_UNIT_NO_SUCH_UNIT       },
                { BUS_ERROR_ONLY_BY_DEPENDENCY, VARLINK_ERROR_UNIT_ONLY_BY_DEPENDENCY },
                { BUS_ERROR_SHUTTING_DOWN,      VARLINK_ERROR_UNIT_DBUS_SHUTTING_DOWN },
        };

        if (!sd_bus_error_is_set(e))
                return NULL;

        FOREACH_ELEMENT(i, map)
                if (sd_bus_error_has_name(e, i->bus_error))
                        return i->varlink_error;

        return NULL;
}

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
