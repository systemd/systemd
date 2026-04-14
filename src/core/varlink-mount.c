/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "json-util.h"
#include "mount.h"
#include "user-util.h"
#include "varlink-common.h"
#include "varlink-mount.h"

int mount_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Mount *m = ASSERT_PTR(MOUNT(userdata));
        _cleanup_free_ char *what = NULL, *where = NULL, *options = NULL;

        what = mount_get_what_escaped(m);
        if (!what)
                return -ENOMEM;

        where = mount_get_where_escaped(m);
        if (!where)
                return -ENOMEM;

        options = mount_get_options_escaped(m);
        if (!options)
                return -ENOMEM;

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("What", what),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Where", where),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Type", mount_get_fstype(m)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Options", options),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SloppyOptions", m->sloppy_options),
                        SD_JSON_BUILD_PAIR_BOOLEAN("LazyUnmount", m->lazy_unmount),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ReadWriteOnly", m->read_write_only),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ForceUnmount", m->force_unmount),
                        SD_JSON_BUILD_PAIR_UNSIGNED("DirectoryMode", m->directory_mode),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutUSec", m->timeout_usec),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecMount", exec_command_build_json, &m->exec_command[MOUNT_EXEC_MOUNT]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecUnmount", exec_command_build_json, &m->exec_command[MOUNT_EXEC_UNMOUNT]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecRemount", exec_command_build_json, &m->exec_command[MOUNT_EXEC_REMOUNT]));
}

int mount_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        Mount *m = ASSERT_PTR(MOUNT(u));
        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_CONDITION(pidref_is_set(&m->control_pid), "ControlPID", JSON_BUILD_PIDREF(&m->control_pid)),
                        SD_JSON_BUILD_PAIR_STRING("Result", mount_result_to_string(m->result)),
                        SD_JSON_BUILD_PAIR_STRING("ReloadResult", mount_result_to_string(m->reload_result)),
                        SD_JSON_BUILD_PAIR_STRING("CleanResult", mount_result_to_string(m->clean_result)),
                        SD_JSON_BUILD_PAIR_CONDITION(uid_is_valid(u->ref_uid), "UID", SD_JSON_BUILD_UNSIGNED(u->ref_uid)),
                        SD_JSON_BUILD_PAIR_CONDITION(gid_is_valid(u->ref_gid), "GID", SD_JSON_BUILD_UNSIGNED(u->ref_gid)));
}
