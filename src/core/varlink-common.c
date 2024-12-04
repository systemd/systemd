/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "json-util.h"
#include "rlimit-util.h"
#include "unit.h"
#include "varlink-common.h"

int rlimit_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        const struct rlimit *rl = userdata;
        struct rlimit buf = {};
        int r;

        assert(ret);
        assert(name);

        if (!rl) {
                const char *p;
                int z;

                /* Skip over any prefix, such as "Default" */
                assert_se(p = strstrafter(name, "Limit"));

                z = rlimit_from_string(p);
                assert(z >= 0 && z < _RLIMIT_MAX);

                r = getrlimit(z, &buf);
                if (r < 0) {
                        log_debug_errno(errno, "Failed to getrlimit(%s), ignoring: %m", name);
                        return 0;
                }

                rl = &buf;
        }

        if (rl->rlim_cur == RLIM_INFINITY && rl->rlim_max == RLIM_INFINITY)
                return 0;

        /* rlim_t might have different sizes, let's map RLIMIT_INFINITY to UINT64_MAX, so that it is the same
         * on all archs */
        return sd_json_buildo(ret,
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("soft", rl->rlim_cur, RLIM_INFINITY),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("hard", rl->rlim_max, RLIM_INFINITY));
}

int activation_details_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_strv_free_ char **pairs = NULL;
        ActivationDetails *activation_details = userdata;
        int r;

        assert(ret);

        r = activation_details_append_pair(activation_details, &pairs);
        if (r < 0)
                return r;

        STRV_FOREACH_PAIR(key, value, pairs) {
                r = sd_json_variant_set_field_string(&v, *key, *value);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}
