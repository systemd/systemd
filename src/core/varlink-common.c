/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "cpu-set-util.h"
#include "execute.h"
#include "json-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "unit.h"
#include "varlink-common.h"
#include "varlink-unit.h"

const char* varlink_error_id_from_bus_error(const sd_bus_error *e) {
        static const struct {
                const char *bus_error;
                const char *varlink_error;
        } map[] = {
                { BUS_ERROR_NO_SUCH_UNIT,               VARLINK_ERROR_UNIT_NO_SUCH_UNIT       },
                { BUS_ERROR_ONLY_BY_DEPENDENCY,         VARLINK_ERROR_UNIT_ONLY_BY_DEPENDENCY },
                { BUS_ERROR_SHUTTING_DOWN,              VARLINK_ERROR_UNIT_DBUS_SHUTTING_DOWN },
                { BUS_ERROR_UNIT_EXISTS,                VARLINK_ERROR_UNIT_UNIT_EXISTS        },
                { BUS_ERROR_BAD_UNIT_SETTING,           VARLINK_ERROR_UNIT_BAD_SETTING        },
                { SD_BUS_ERROR_UNIX_PROCESS_ID_UNKNOWN, VARLINK_ERROR_UNIT_PID_UNKNOWN        }
        };

        if (!sd_bus_error_is_set(e))
                return NULL;

        FOREACH_ELEMENT(i, map)
                if (sd_bus_error_has_name(e, i->bus_error))
                        return i->varlink_error;

        return NULL;
}

int varlink_reply_bus_error(sd_varlink *link, int r, const sd_bus_error *e) {
        const char *error_id = varlink_error_id_from_bus_error(e);
        if (error_id)
                return sd_varlink_error(link, error_id, NULL);
        return sd_varlink_error_errno(link, r);
}

void varlink_propagate_bad_field(const char *bad_field, const char *child_bad_field, char **reterr_bad_field) {
        assert(bad_field);

        if (!reterr_bad_field)
                return;

        char *bad_field_path = child_bad_field ?
                strjoin(bad_field, ".", child_bad_field) :
                strdup(bad_field);

        free_and_replace(*reterr_bad_field, bad_field_path);
}

int varlink_propagate_bad_field_errno(int errnum, const char *bad_field, const char *child_bad_field, char **reterr_bad_field) {
        assert(errnum < 0);

        /* don't allocate more mem if ENOMEM */
        if (errnum == -ENOMEM)
                return errnum;

        varlink_propagate_bad_field(bad_field, child_bad_field, reterr_bad_field);
        return errnum;
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

int exec_command_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecCommand *cmd = ASSERT_PTR(userdata);

        assert(ret);

        if (isempty(cmd->path)) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("path", cmd->path),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("arguments", cmd->argv),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ignoreFailure", FLAGS_SET(cmd->flags, EXEC_COMMAND_IGNORE_FAILURE)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("privileged", FLAGS_SET(cmd->flags, EXEC_COMMAND_FULLY_PRIVILEGED)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("noSetuid", FLAGS_SET(cmd->flags, EXEC_COMMAND_NO_SETUID)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("noEnvExpand", FLAGS_SET(cmd->flags, EXEC_COMMAND_NO_ENV_EXPAND)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("viaShell", FLAGS_SET(cmd->flags, EXEC_COMMAND_VIA_SHELL)));
}

int exec_command_list_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecCommand *list = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(command, c, list) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;

                r = exec_command_build_json(&entry, /* name= */ NULL, c);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&v, entry);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int exec_command_status_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecStatus *status = ASSERT_PTR(userdata);

        assert(ret);

        if (!pid_is_valid(status->pid)) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ret,
                        /* TODO: replace with a real PidRef once ExecStatus carries one */
                        SD_JSON_BUILD_PAIR("PID", JSON_BUILD_PIDREF(&PIDREF_MAKE_FROM_PID(status->pid))),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("StartTimestamp", &status->start_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("ExitTimestamp", &status->exit_timestamp),
                        JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL("HandoffTimestamp", &status->handoff_timestamp),
                        SD_JSON_BUILD_PAIR_CONDITION(status->code > 0, "Code", SD_JSON_BUILD_INTEGER(status->code)),
                        SD_JSON_BUILD_PAIR_CONDITION(status->code > 0, "Status", SD_JSON_BUILD_INTEGER(status->status)));
}

/* exec_command_status_list_build_json() is the runtime counterpart of exec_command_list_build_json().
 * The two arrays are positionally aligned: index N in the status array corresponds to index N in the
 * command array. Commands that have not yet run produce null entries to preserve alignment. */
int exec_command_status_list_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecCommand *list = userdata;
        bool any_ran = false;
        int r;

        assert(ret);

        LIST_FOREACH(command, c, list) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;

                r = exec_command_status_build_json(&entry, /* name= */ NULL, &c->exec_status);
                if (r < 0)
                        return r;

                if (entry) {
                        any_ran = true;
                        r = sd_json_variant_append_array(&v, entry);
                } else
                        r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_NULL);
                if (r < 0)
                        return r;
        }

        if (!any_ran) {
                *ret = NULL;
                return 0;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int varlink_apply_tristate_bool(Unit *u, const char *name, bool *p, int value, UnitWriteFlags flags) {
        assert(u);
        assert(name);
        assert(p);

        if (value < 0)
                return 0;

        *p = value;
        unit_write_settingf(u, flags, name, "%s=%s", name, yes_no(value));
        return 1;
}

int varlink_apply_string(Unit *u, const char *name, char **p, const char *value, UnitWriteFlags flags) {
        assert(name);
        assert(p);

        if (!value)
                return 0;

        int r;
        r = free_and_strdup(p, value);
        if (r < 0)
                return r;

        unit_write_settingf(u, flags, name, "%s=%s", name, *p);
        return 1;
}

int varlink_apply_string_escaped(Unit *u, const char *name, char **p, const char *value, UnitWriteFlags flags) {
        return varlink_apply_string(u, name, p, value, flags|UNIT_ESCAPE_SPECIFIERS);
}

int varlink_apply_absolute_path(Unit *u, const char *name, char **p, const char *value, UnitWriteFlags flags) {
        assert(name);
        assert(p);

        if (!value)
                return 0;

        if (!path_is_absolute(value))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "%s: expects an absolute path", name);

        return varlink_apply_string_escaped(u, name, p, value, flags);
}

int varlink_apply_strv(Unit *u, const char *name, char ***p, char **value, UnitWriteFlags flags) {
        _cleanup_free_ char *joined = NULL;
        int r;

        assert(name);
        assert(p);

        /* NULL means absent; an allocated empty vector explicitly clears all configured entries.
         * varlink_dispatch_strv_preserve_empty() preserves this distinction when parsing JSON. */
        if (!value)
                return 0;

        if (strv_isempty(value)) {
                *p = strv_free(*p);
                unit_write_settingf(u, flags, name, "%s=", name);
                return 1;
        }

        r = strv_extend_strv(p, value, /* filter_duplicates= */ true);
        if (r < 0)
                return r;

        joined = strv_join(*p, " ");
        if (!joined)
                return -ENOMEM;

        unit_write_settingf(u, flags, name, "%s=%s", name, joined);
        return 1;
}

int varlink_apply_strv_escaped(Unit *u, const char *name, char ***p, char **value, UnitWriteFlags flags) {
        return varlink_apply_strv(u, name, p, value, flags|UNIT_ESCAPE_SPECIFIERS);
}

int varlink_apply_uint64_limit(Unit *u, const char *name, uint64_t *p, uint64_t value, uint64_t minimum, UnitWriteFlags flags) {
        assert(name);
        assert(p);

        if (value < minimum)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "%s= value out of range.", name);

        *p = value;
        if (value == UINT64_MAX)
                unit_write_settingf(u, flags, name, "%s=infinity", name);
        else
                unit_write_settingf(u, flags, name, "%s=%" PRIu64, name, value);
        return 1;
}

static inline void assert_usec_name(const char *name) {
        assert(name);
        assert(endswith(name, "Sec"));
        assert(!endswith(name, "USec"));
}

int varlink_apply_usec_per_msec(Unit *u, const char *name, usec_t *p, usec_t value, UnitWriteFlags flags) {
        assert_usec_name(name);
        assert(p);

        *p = value;
        unit_write_settingf(u, flags, name, "%s=%s", name, FORMAT_TIMESPAN(value, USEC_PER_MSEC));
        return 1;
}

int varlink_apply_usec_empty_on_infinity(Unit *u, const char *name, usec_t *p, usec_t value, UnitWriteFlags flags) {
        assert_usec_name(name);
        assert(p);

        *p = value;
        unit_write_settingf(u, flags, name, "%s=%s", name, value == USEC_INFINITY ? "" : FORMAT_TIMESPAN(value, 1));
        return 1;
}

int varlink_dispatch_strv_preserve_empty(
                const char *name,
                sd_json_variant *variant,
                sd_json_dispatch_flags_t flags,
                void *userdata) {

        char ***p = ASSERT_PTR(userdata);

        assert(name);
        assert(variant);

        if (sd_json_variant_is_array(variant) && sd_json_variant_elements(variant) == 0) {
                char **empty = new0(char*, 1);
                if (!empty)
                        return -ENOMEM;

                strv_free_and_replace(*p, empty);
                return 0;
        }

        return sd_json_dispatch_strv(name, variant, flags, p);
}
