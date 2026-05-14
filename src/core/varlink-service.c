/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "exit-status.h"
#include "json-util.h"
#include "open-file.h"
#include "service.h"
#include "signal-util.h"
#include "strv.h"
#include "user-util.h"
#include "varlink-common.h"
#include "varlink-service.h"

static int exit_status_set_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *statuses = NULL, *signals = NULL;
        ExitStatusSet *set = ASSERT_PTR(userdata);
        unsigned n;
        int r;

        assert(ret);

        if (exit_status_set_is_empty(set)) {
                *ret = NULL;
                return 0;
        }

        BITMAP_FOREACH(n, &set->status) {
                assert(n < 256);

                r = sd_json_variant_append_arrayb(&statuses, SD_JSON_BUILD_UNSIGNED(n));
                if (r < 0)
                        return r;
        }

        BITMAP_FOREACH(n, &set->signal) {
                const char *str = signal_to_string(n);
                if (!str)
                        continue;

                r = sd_json_variant_append_arrayb(&signals, SD_JSON_BUILD_STRING(str));
                if (r < 0)
                        return r;
        }

        return sd_json_buildo(ret,
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("statuses", statuses),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("signals", signals));
}

static int open_files_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        OpenFile *open_files = userdata;
        int r;

        assert(ret);

        LIST_FOREACH(open_files, of, open_files) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("path", of->path),
                                SD_JSON_BUILD_PAIR_STRING("fileDescriptorName", of->fdname),
                                JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("flags", of->flags));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int extra_fd_names_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Service *s = ASSERT_PTR(userdata);
        int r;

        assert(ret);

        FOREACH_ARRAY(i, s->extra_fds, s->n_extra_fds) {
                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_STRING(i->fdname));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int refresh_on_reload_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Service *s = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(ret);

        r = service_refresh_on_reload_to_strv(s->refresh_on_reload_flags, &l);
        if (r < 0)
                return r;

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_array_strv(ret, l);
}

int service_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Service *s = ASSERT_PTR(SERVICE(userdata));

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        JSON_BUILD_PAIR_ENUM("Type", service_type_to_string(s->type)),
                        JSON_BUILD_PAIR_ENUM("ExitType", service_exit_type_to_string(s->exit_type)),
                        JSON_BUILD_PAIR_ENUM("Restart", service_restart_to_string(s->restart)),
                        JSON_BUILD_PAIR_ENUM("RestartMode", service_restart_mode_to_string(s->restart_mode)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("PIDFile", s->pid_file),
                        JSON_BUILD_PAIR_FINITE_USEC("RestartUSec", s->restart_usec),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("RestartSteps", s->restart_steps),
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("RestartMaxDelayUSec", s->restart_max_delay_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutStartUSec", s->timeout_start_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutStopUSec", s->timeout_stop_usec),
                        JSON_BUILD_PAIR_ENUM("TimeoutStartFailureMode", service_timeout_failure_mode_to_string(s->timeout_start_failure_mode)),
                        JSON_BUILD_PAIR_ENUM("TimeoutStopFailureMode", service_timeout_failure_mode_to_string(s->timeout_stop_failure_mode)),
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("RuntimeMaxUSec", s->runtime_max_usec),
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("RuntimeRandomizedExtraUSec", s->runtime_rand_extra_usec),
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("WatchdogUSec", s->watchdog_usec),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RemainAfterExit", s->remain_after_exit),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RootDirectoryStartOnly", s->root_directory_start_only),
                        SD_JSON_BUILD_PAIR_BOOLEAN("GuessMainPID", s->guess_main_pid),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SuccessExitStatus", exit_status_set_build_json, &s->success_status),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RestartPreventExitStatus", exit_status_set_build_json, &s->restart_prevent_status),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RestartForceExitStatus", exit_status_set_build_json, &s->restart_force_status),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("BusName", s->bus_name),
                        JSON_BUILD_PAIR_ENUM("NotifyAccess", notify_access_to_string(service_get_notify_access(s))),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("FileDescriptorStoreMax", s->n_fd_store_max),
                        JSON_BUILD_PAIR_ENUM("FileDescriptorStorePreserve", exec_preserve_mode_to_string(s->fd_store_preserve_mode)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("USBFunctionDescriptors", s->usb_function_descriptors),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("USBFunctionStrings", s->usb_function_strings),
                        JSON_BUILD_PAIR_ENUM("OOMPolicy", oom_policy_to_string(s->oom_policy)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("OpenFile", open_files_build_json, s->open_files),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExtraFileDescriptorNames", extra_fd_names_build_json, s),
                        SD_JSON_BUILD_PAIR_STRING("ReloadSignal", signal_to_string(s->reload_signal)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RefreshOnReload", refresh_on_reload_build_json, s),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecCondition", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_CONDITION]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStart", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_START]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStartPre", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_START_PRE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStartPost", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_START_POST]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecReload", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_RELOAD]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecReloadPost", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_RELOAD_POST]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStop", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_STOP]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStopPost", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_STOP_POST]));
}

int service_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        Service *s = ASSERT_PTR(SERVICE(u));

        return sd_json_buildo(
                        ASSERT_PTR(ret),
                        SD_JSON_BUILD_PAIR_CONDITION(pidref_is_set(&s->main_pid), "MainPID", JSON_BUILD_PIDREF(&s->main_pid)),
                        SD_JSON_BUILD_PAIR_CONDITION(pidref_is_set(&s->control_pid), "ControlPID", JSON_BUILD_PIDREF(&s->control_pid)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("StatusText", s->status_text),
                        JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE("StatusErrno", s->status_errno),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("StatusBusError", s->status_bus_error),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("StatusVarlinkError", s->status_varlink_error),
                        JSON_BUILD_PAIR_ENUM("Result", service_result_to_string(s->result)),
                        JSON_BUILD_PAIR_ENUM("ReloadResult", service_result_to_string(s->reload_result)),
                        JSON_BUILD_PAIR_ENUM("CleanResult", service_result_to_string(s->clean_result)),
                        JSON_BUILD_PAIR_ENUM("LiveMountResult", service_result_to_string(s->live_mount_result)),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("NFileDescriptorStore", s->n_fd_store),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("NRestarts", s->n_restarts),
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("RestartUSecNext", service_restart_usec_next(s)),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutAbortUSec", service_timeout_abort_usec(s)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecMain", exec_command_status_build_json, &s->main_exec_status),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecConditionStatus", exec_command_status_list_build_json, s->exec_command[SERVICE_EXEC_CONDITION]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStartPreStatus", exec_command_status_list_build_json, s->exec_command[SERVICE_EXEC_START_PRE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStartStatus", exec_command_status_list_build_json, s->exec_command[SERVICE_EXEC_START]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStartPostStatus", exec_command_status_list_build_json, s->exec_command[SERVICE_EXEC_START_POST]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecReloadStatus", exec_command_status_list_build_json, s->exec_command[SERVICE_EXEC_RELOAD]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecReloadPostStatus", exec_command_status_list_build_json, s->exec_command[SERVICE_EXEC_RELOAD_POST]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStopStatus", exec_command_status_list_build_json, s->exec_command[SERVICE_EXEC_STOP]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStopPostStatus", exec_command_status_list_build_json, s->exec_command[SERVICE_EXEC_STOP_POST]),
                        SD_JSON_BUILD_PAIR_CONDITION(uid_is_valid(u->ref_uid), "UID", SD_JSON_BUILD_UNSIGNED(u->ref_uid)),
                        SD_JSON_BUILD_PAIR_CONDITION(gid_is_valid(u->ref_gid), "GID", SD_JSON_BUILD_UNSIGNED(u->ref_gid)));
}
