/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "json-util.h"
#include "swap.h"
#include "user-util.h"
#include "varlink-common.h"
#include "varlink-swap.h"

int swap_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Swap *s = ASSERT_PTR(SWAP(userdata));

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_STRING("What", s->what),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("Priority", swap_get_priority(s)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Options", swap_get_options(s)),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutUSec", s->timeout_usec),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecActivate", exec_command_build_json, &s->exec_command[SWAP_EXEC_ACTIVATE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecDeactivate", exec_command_build_json, &s->exec_command[SWAP_EXEC_DEACTIVATE]));
}

int swap_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        Swap *s = ASSERT_PTR(SWAP(u));

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_CONDITION(pidref_is_set(&s->control_pid), "ControlPID", JSON_BUILD_PIDREF(&s->control_pid)),
                        JSON_BUILD_PAIR_ENUM("Result", swap_result_to_string(s->result)),
                        JSON_BUILD_PAIR_ENUM("CleanResult", swap_result_to_string(s->clean_result)),
                        SD_JSON_BUILD_PAIR_CONDITION(uid_is_valid(u->ref_uid), "UID", SD_JSON_BUILD_UNSIGNED(u->ref_uid)),
                        SD_JSON_BUILD_PAIR_CONDITION(gid_is_valid(u->ref_gid), "GID", SD_JSON_BUILD_UNSIGNED(u->ref_gid)));
}
