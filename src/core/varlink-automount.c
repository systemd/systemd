/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "automount.h"
#include "json-util.h"
#include "varlink-automount.h"

int automount_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Automount *a = ASSERT_PTR(AUTOMOUNT(userdata));
        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Where", a->where),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("ExtraOptions", a->extra_options),
                        SD_JSON_BUILD_PAIR_UNSIGNED("DirectoryMode", a->directory_mode),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutIdleUSec", a->timeout_idle_usec));
}

int automount_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Automount *a = ASSERT_PTR(AUTOMOUNT(userdata));
        return sd_json_buildo(ASSERT_PTR(ret), SD_JSON_BUILD_PAIR_STRING("Result", automount_result_to_string(a->result)));
}
