/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "json-util.h"
#include "path.h"
#include "varlink-path.h"

static int path_specs_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        PathSpec *specs = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(spec, k, specs) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                JSON_BUILD_PAIR_ENUM("type", path_type_to_string(k->type)),
                                SD_JSON_BUILD_PAIR_STRING("path", k->path));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int path_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Path *p = ASSERT_PTR(PATH(userdata));
        Unit *trigger = UNIT_TRIGGER(UNIT(p));

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("Paths", path_specs_build_json, p->specs),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Unit", trigger ? trigger->id : NULL),
                        SD_JSON_BUILD_PAIR_BOOLEAN("MakeDirectory", p->make_directory),
                        SD_JSON_BUILD_PAIR_UNSIGNED("DirectoryMode", p->directory_mode),
                        JSON_BUILD_PAIR_RATELIMIT("TriggerLimit", &p->trigger_limit));
}

int path_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Path *p = ASSERT_PTR(PATH(userdata));

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_ENUM("Result", path_result_to_string(p->result)));
}
