/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "async.h"
#include "exit-status.h"
#include "fd-util.h"
#include "json-util.h"
#include "open-file.h"
#include "path-util.h"
#include "service.h"
#include "signal-util.h"
#include "strv.h"
#include "user-util.h"
#include "varlink-common.h"
#include "varlink-service.h"

/* Read side of the Service context and runtime for List. */

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
                        JSON_BUILD_PAIR_FINITE_USEC_NON_ZERO("RestartRandomizedDelayUSec", s->restart_randomized_delay_usec),
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

/* Write side of the Service context for StartTransient. */

typedef struct TransientExecCommandItem {
        const char *path;
        char **arguments;
        bool ignore_failure;
        bool privileged;
        bool no_setuid;
        bool no_env_expand;
        bool via_shell;
} TransientExecCommandItem;

struct TransientServiceParameters {
        ServiceType type;
        TransientExecCommandItem *exec_commands[_SERVICE_EXEC_COMMAND_MAX];
        size_t n_exec_commands[_SERVICE_EXEC_COMMAND_MAX];
        int remain_after_exit;
        /* Indices of stdio fds attached to the method call (SCM_RIGHTS), UINT_MAX if unset. Resolved into
         * the owned fds below by transient_service_resolve_stdio_fds(). */
        unsigned stdin_fd_index;
        unsigned stdout_fd_index;
        unsigned stderr_fd_index;
        int stdin_fd;
        int stdout_fd;
        int stderr_fd;
};

static void transient_exec_command_item_done(TransientExecCommandItem *i) {
        assert(i);
        strv_free(i->arguments);
}

static JSON_DISPATCH_ENUM_DEFINE(dispatch_service_type, ServiceType, service_type_from_string);

TransientServiceParameters* transient_service_parameters_free(TransientServiceParameters *p) {
        if (!p)
                return NULL;

        for (ServiceExecCommand c = 0; c < _SERVICE_EXEC_COMMAND_MAX; c++) {
                FOREACH_ARRAY(i, p->exec_commands[c], p->n_exec_commands[c])
                        transient_exec_command_item_done(i);
                free(p->exec_commands[c]);
        }

        safe_close(p->stdin_fd);
        safe_close(p->stdout_fd);
        safe_close(p->stderr_fd);
        return mfree(p);
}

static int dispatch_transient_exec_command(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field exec_command_dispatch[] = {
                { "path",          SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, offsetof(TransientExecCommandItem, path),           SD_JSON_MANDATORY },
                { "arguments",     SD_JSON_VARIANT_ARRAY,   sd_json_dispatch_strv,         offsetof(TransientExecCommandItem, arguments),      0                 },
                { "ignoreFailure", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(TransientExecCommandItem, ignore_failure), 0                 },
                { "privileged",    SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(TransientExecCommandItem, privileged),     0                 },
                { "noSetuid",      SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(TransientExecCommandItem, no_setuid),      0                 },
                { "noEnvExpand",   SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(TransientExecCommandItem, no_env_expand),  0                 },
                { "viaShell",      SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(TransientExecCommandItem, via_shell),      0                 },
                {}
        };

        ServiceExecCommand c = service_exec_command_from_string(name);
        TransientServiceParameters *p = ASSERT_PTR(userdata);
        size_t n;
        int r;

        assert(c >= 0);

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Expected JSON array for %s.", name);

        n = sd_json_variant_elements(variant);
        if (n == 0)
                return 0;

        p->exec_commands[c] = new0(TransientExecCommandItem, n);
        if (!p->exec_commands[c])
                return -ENOMEM;
        p->n_exec_commands[c] = n;

        for (size_t i = 0; i < n; i++) {
                sd_json_variant *element = sd_json_variant_by_index(variant, i);

                r = sd_json_dispatch(element, exec_command_dispatch, /* flags= */ 0, &p->exec_commands[c][i]);
                if (r < 0)
                        return r;
        }

        return 0;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(TransientServiceParameters*, transient_service_parameters_free);

int transient_service_dispatch(
                sd_json_variant *variant,
                TransientServiceParameters **ret,
                const char **reterr_field) {

        static const sd_json_dispatch_field service_dispatch[] = {
                { "Type",                         SD_JSON_VARIANT_STRING,        dispatch_service_type,           offsetof(TransientServiceParameters, type),              0 },
                { "ExecCondition",                SD_JSON_VARIANT_ARRAY,         dispatch_transient_exec_command, 0,                                                       0 },
                { "ExecStartPre",                 SD_JSON_VARIANT_ARRAY,         dispatch_transient_exec_command, 0,                                                       0 },
                { "ExecStart",                    SD_JSON_VARIANT_ARRAY,         dispatch_transient_exec_command, 0,                                                       0 },
                { "ExecStartPost",                SD_JSON_VARIANT_ARRAY,         dispatch_transient_exec_command, 0,                                                       0 },
                { "ExecReload",                   SD_JSON_VARIANT_ARRAY,         dispatch_transient_exec_command, 0,                                                       0 },
                { "ExecReloadPost",               SD_JSON_VARIANT_ARRAY,         dispatch_transient_exec_command, 0,                                                       0 },
                { "ExecStop",                     SD_JSON_VARIANT_ARRAY,         dispatch_transient_exec_command, 0,                                                       0 },
                { "ExecStopPost",                 SD_JSON_VARIANT_ARRAY,         dispatch_transient_exec_command, 0,                                                       0 },
                { "RemainAfterExit",              SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,       offsetof(TransientServiceParameters, remain_after_exit), 0 },
                { "StandardInputFileDescriptor",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,           offsetof(TransientServiceParameters, stdin_fd_index),    0 },
                { "StandardOutputFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,           offsetof(TransientServiceParameters, stdout_fd_index),   0 },
                { "StandardErrorFileDescriptor",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,           offsetof(TransientServiceParameters, stderr_fd_index),   0 },
                {}
        };

        int r;

        assert(ret);

        _cleanup_(transient_service_parameters_freep) TransientServiceParameters *p = NULL;
        p = new(TransientServiceParameters, 1);
        if (!p)
                return -ENOMEM;

        *p = (TransientServiceParameters) {
                .type = _SERVICE_TYPE_INVALID,
                .remain_after_exit = -1,
                .stdin_fd_index = UINT_MAX,
                .stdout_fd_index = UINT_MAX,
                .stderr_fd_index = UINT_MAX,
                .stdin_fd = -EBADF,
                .stdout_fd = -EBADF,
                .stderr_fd = -EBADF,
        };

        r = sd_json_dispatch_full(variant, service_dispatch, /* bad= */ NULL, /* flags= */ 0, p, reterr_field);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(p);
        return r;
}

static int transient_service_resolve_one_stdio_fd(
                sd_varlink *link,
                unsigned idx,
                int accmode,
                int *ret_fd) {

        int r;

        assert(link);
        assert(ret_fd);

        if (idx == UINT_MAX) /* not specified */
                return 0;

        /* Dup non-destructively off the connection, so that a re-dispatch of the method (e.g. after a
         * deferred polkit authorization) can resolve the same index again. */
        _cleanup_close_ int fd = sd_varlink_peek_dup_fd(link, (size_t) idx);
        if (fd < 0)
                return fd;

        r = fd_vet_accmode(fd, accmode);
        if (r < 0)
                return r;

        *ret_fd = TAKE_FD(fd);
        return 1;
}

/* Resolve stdio fd indices to fds attached to the method call. Ownership of the resolved fds lands in
 * the parameters and is released by transient_service_parameters_free(). */
int transient_service_resolve_stdio_fds(sd_varlink *link, TransientServiceParameters *sp, const char **reterr_field) {
        int r;

        assert(link);

        if (!sp)
                return 0;

        r = transient_service_resolve_one_stdio_fd(link, sp->stdin_fd_index, O_RDONLY, &sp->stdin_fd);
        if (r < 0) {
                if (reterr_field)
                        *reterr_field = "Service.StandardInputFileDescriptor";
                return r;
        }

        r = transient_service_resolve_one_stdio_fd(link, sp->stdout_fd_index, O_WRONLY, &sp->stdout_fd);
        if (r < 0) {
                if (reterr_field)
                        *reterr_field = "Service.StandardOutputFileDescriptor";
                return r;
        }

        r = transient_service_resolve_one_stdio_fd(link, sp->stderr_fd_index, O_WRONLY, &sp->stderr_fd);
        if (r < 0) {
                if (reterr_field)
                        *reterr_field = "Service.StandardErrorFileDescriptor";
                return r;
        }

        return 0;
}

/* Consumes command argument vectors and stdio fds from sp as they are applied, including on failure. */
int transient_service_apply_properties(Service *s, TransientServiceParameters *sp, const char **reterr_field) {
        static const char* const exec_fields[_SERVICE_EXEC_COMMAND_MAX] = {
                [SERVICE_EXEC_CONDITION]   = "Service.ExecCondition",
                [SERVICE_EXEC_START_PRE]   = "Service.ExecStartPre",
                [SERVICE_EXEC_START]       = "Service.ExecStart",
                [SERVICE_EXEC_START_POST]  = "Service.ExecStartPost",
                [SERVICE_EXEC_RELOAD]      = "Service.ExecReload",
                [SERVICE_EXEC_RELOAD_POST] = "Service.ExecReloadPost",
                [SERVICE_EXEC_STOP]        = "Service.ExecStop",
                [SERVICE_EXEC_STOP_POST]   = "Service.ExecStopPost",
        };
        Unit *u = UNIT(ASSERT_PTR(s));
        int r;

        assert(sp);

        if (sp->type >= 0) {
                s->type = sp->type;
                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "Type", "Type=%s", service_type_to_string(sp->type));
        }

        /* Passed stdio fds, resolved earlier by transient_service_resolve_stdio_fds(): store them on the
         * Service and flag the exec context. Not written as a text setting; fd serialization across
         * reexec is handled by service_serialize(). */
        if (sp->stdin_fd >= 0) {
                asynchronous_close(s->stdin_fd);
                s->stdin_fd = TAKE_FD(sp->stdin_fd);
                s->exec_context.stdio_as_fds = true;
        }
        if (sp->stdout_fd >= 0) {
                asynchronous_close(s->stdout_fd);
                s->stdout_fd = TAKE_FD(sp->stdout_fd);
                s->exec_context.stdio_as_fds = true;
        }
        if (sp->stderr_fd >= 0) {
                asynchronous_close(s->stderr_fd);
                s->stderr_fd = TAKE_FD(sp->stderr_fd);
                s->exec_context.stdio_as_fds = true;
        }

        if (sp->remain_after_exit >= 0) {
                s->remain_after_exit = sp->remain_after_exit;
                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "RemainAfterExit", "RemainAfterExit=%s", yes_no(sp->remain_after_exit));
        }

        for (ServiceExecCommand cmd = 0; cmd < _SERVICE_EXEC_COMMAND_MAX; cmd++) {
                const char *name = service_exec_command_to_string(cmd);

                FOREACH_ARRAY(item, sp->exec_commands[cmd], sp->n_exec_commands[cmd]) {
                        _cleanup_(exec_command_freep) ExecCommand *c = NULL;
                        ExecCommandFlags command_flags;

                        if (item->privileged && item->no_setuid) {
                                if (reterr_field)
                                        *reterr_field = exec_fields[cmd];
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "%s 'privileged' and 'noSetuid' flags may not be combined.", name);
                        }

                        if (!item->via_shell && !filename_or_absolute_path_is_valid(item->path)) {
                                if (reterr_field)
                                        *reterr_field = exec_fields[cmd];
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid %s path: %s", name, item->path);
                        }

                        command_flags =
                                (item->ignore_failure ? EXEC_COMMAND_IGNORE_FAILURE : 0) |
                                (item->privileged ? EXEC_COMMAND_FULLY_PRIVILEGED : 0) |
                                (item->no_setuid ? EXEC_COMMAND_NO_SETUID : 0) |
                                (item->no_env_expand ? EXEC_COMMAND_NO_ENV_EXPAND : 0) |
                                (item->via_shell ? EXEC_COMMAND_VIA_SHELL : 0);

                        r = exec_command_new(item->path, TAKE_PTR(item->arguments), command_flags, &c);
                        if (r < 0)
                                return r;

                        exec_command_append_list(&s->exec_command[cmd], TAKE_PTR(c));
                }

                LIST_FOREACH(command, c, s->exec_command[cmd]) {
                        _cleanup_free_ char *a = NULL;

                        r = exec_command_to_setting(c, &a);
                        if (r < 0)
                                return r;

                        unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, name, "%s=%s", name, a);
                }
        }

        return 0;
}
