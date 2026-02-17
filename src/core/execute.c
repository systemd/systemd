/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "af-list.h"
#include "alloc-util.h"
#include "async.h"
#include "bitfield.h"
#include "capability-list.h"
#include "capability-util.h"
#include "cgroup-setup.h"
#include "coredump-util.h"
#include "cpu-set-util.h"
#include "dissect-image.h"
#include "dynamic-user.h"
#include "env-file.h"
#include "env-util.h"
#include "escape.h"
#include "execute.h"
#include "execute-serialize.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "glob-util.h"
#include "hexdecoct.h"
#include "image-policy.h"
#include "io-util.h"
#include "ioprio-util.h"
#include "log.h"
#include "manager.h"
#include "mkdir.h"
#include "namespace-util.h"
#include "namespace.h"
#include "nsflags.h"
#include "open-file.h"
#include "ordered-set.h"
#include "osc-context.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "rm-rf.h"
#include "seccomp-util.h"
#include "securebits-util.h"
#include "serialize.h"
#include "set.h"
#include "sort-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "utmp-wtmp.h"
#include "vpick.h"

const char* exec_context_tty_path(const ExecContext *context) {
        assert(context);

        if (context->stdio_as_fds)
                return NULL;

        if (context->tty_path)
                return context->tty_path;

        return "/dev/console";
}

int exec_context_apply_tty_size(
                const ExecContext *context,
                int input_fd,
                int output_fd,
                const char *tty_path) {

        unsigned rows, cols;
        int r;

        assert(context);
        assert(input_fd >= 0);
        assert(output_fd >= 0);

        if (!isatty_safe(output_fd))
                return 0;

        if (!tty_path)
                tty_path = exec_context_tty_path(context);

        /* Preferably use explicitly configured data */
        rows = context->tty_rows;
        cols = context->tty_cols;

        /* Fill in data from kernel command line if anything is unspecified */
        if (tty_path && (rows == UINT_MAX || cols == UINT_MAX))
                (void) proc_cmdline_tty_size(
                                tty_path,
                                rows == UINT_MAX ? &rows : NULL,
                                cols == UINT_MAX ? &cols : NULL);

        /* If we got nothing so far and we are talking to a physical device, then let's query dimensions from
         * the ANSI terminal driver. Note that we will not bother with this in case terminal reset via ansi
         * sequences is not enabled, as the DSR logic relies on ANSI sequences after all, and if we shall not
         * use those during initialization we need to skip it. */
        if (rows == UINT_MAX && cols == UINT_MAX &&
            exec_context_shall_ansi_seq_reset(context) &&
            isatty_safe(input_fd)) {
                r = terminal_get_size_by_dsr(input_fd, output_fd, &rows, &cols);
                if (r < 0)
                        log_debug_errno(r, "Failed to get terminal size by DSR, ignoring: %m");
        }

        return terminal_set_size_fd(output_fd, tty_path, rows, cols);
}

void exec_context_tty_reset(const ExecContext *context, const ExecParameters *parameters, sd_id128_t invocation_id) {
        _cleanup_close_ int _fd = -EBADF, lock_fd = -EBADF;
        int fd, r;

        assert(context);

        /* Note that this is potentially a "destructive" reset of a TTY device. It's about getting rid of the
         * remains of previous uses of the TTY. It's *not* about getting things set up for coming uses. We'll
         * potentially invalidate the TTY here through hangups or VT disallocations, and hence do not keep a
         * continuous fd open. */

        const char *path = exec_context_tty_path(context);

        if (parameters && parameters->stdout_fd >= 0 && isatty_safe(parameters->stdout_fd))
                fd = parameters->stdout_fd;
        else if (path && exec_context_has_tty(context)) {
                fd = _fd = open_terminal(path, O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
                if (fd < 0)
                        return (void) log_debug_errno(fd, "Failed to open terminal '%s', ignoring: %m", path);
        } else
                return;   /* nothing to do */

        /* Take a synchronization lock for the duration of the setup that we do here.
         * systemd-vconsole-setup.service also takes the lock to avoid being interrupted. We open a new fd
         * that will be closed automatically, and operate on it for convenience. */
        lock_fd = lock_dev_console();
        if (ERRNO_IS_NEG_PRIVILEGE(lock_fd))
                log_debug_errno(lock_fd, "No privileges to lock /dev/console, proceeding without lock: %m");
        else if (ERRNO_IS_NEG_DEVICE_ABSENT(lock_fd))
                log_debug_errno(lock_fd, "Device /dev/console does not exist, proceeding without lock: %m");
        else if (lock_fd < 0)
                log_warning_errno(lock_fd, "Failed to lock /dev/console, proceeding without lock: %m");

        if (context->tty_reset)
                (void) terminal_reset_defensive(
                                fd,
                                TERMINAL_RESET_SWITCH_TO_TEXT |
                                (exec_context_shall_ansi_seq_reset(context) ? TERMINAL_RESET_FORCE_ANSI_SEQ : TERMINAL_RESET_AVOID_ANSI_SEQ));

        r = exec_context_apply_tty_size(context, fd, fd, path);
        if (r < 0)
                log_debug_errno(r, "Failed to configure TTY dimensions, ignoring: %m");

        if (!sd_id128_is_null(invocation_id) && exec_context_shall_ansi_seq_reset(context)) {
                sd_id128_t context_id;

                r = osc_context_id_from_invocation_id(invocation_id, &context_id);
                if (r < 0)
                        log_debug_errno(r, "Failed to derive context ID from invocation ID, ignoring: %m");
                else {
                        _cleanup_free_ char *seq = NULL;

                        r = osc_context_close(context_id, &seq);
                        if (r < 0)
                                log_debug_errno(r, "Failed to acquire OSC close sequence, ignoring: %m");
                        else
                                (void) loop_write(fd, seq, SIZE_MAX);
                }
        }

        if (context->tty_vhangup)
                (void) terminal_vhangup_fd(fd);

        /* We don't need the fd anymore now, and it potentially points to a hungup TTY anyway, let's close it
         * hence. */
        _fd = safe_close(_fd);

        if (context->tty_vt_disallocate && path)
                (void) vt_disallocate(path);
}

bool exec_needs_network_namespace(const ExecContext *context) {
        assert(context);

        return context->private_network || context->network_namespace_path;
}

static bool exec_needs_ephemeral(const ExecContext *context) {
        return (context->root_image || context->root_directory) && context->root_ephemeral;
}

bool exec_needs_ipc_namespace(const ExecContext *context) {
        assert(context);

        return context->private_ipc || context->ipc_namespace_path;
}

static bool needs_cgroup_namespace(ProtectControlGroups i) {
        return IN_SET(i, PROTECT_CONTROL_GROUPS_PRIVATE, PROTECT_CONTROL_GROUPS_STRICT);
}

ProtectControlGroups exec_get_protect_control_groups(const ExecContext *context) {
        assert(context);

        /* If cgroup namespace is configured via ProtectControlGroups=private or strict but we can't actually
         * use cgroup namespace, we ignore the setting and do not unshare the namespace.
         * ProtectControlGroups=private and strict get downgraded to no and yes respectively. This ensures
         * that strict always gets a read-only mount of /sys/fs/cgroup/. */
        if (needs_cgroup_namespace(context->protect_control_groups) && !namespace_type_supported(NAMESPACE_CGROUP)) {
                if (context->protect_control_groups == PROTECT_CONTROL_GROUPS_PRIVATE)
                        return PROTECT_CONTROL_GROUPS_NO;
                if (context->protect_control_groups == PROTECT_CONTROL_GROUPS_STRICT)
                        return PROTECT_CONTROL_GROUPS_YES;
        }
        return context->protect_control_groups;
}

bool exec_needs_cgroup_namespace(const ExecContext *context) {
        assert(context);

        return needs_cgroup_namespace(exec_get_protect_control_groups(context));
}

bool exec_needs_cgroup_mount(const ExecContext *context) {
        assert(context);

        return exec_get_protect_control_groups(context) != PROTECT_CONTROL_GROUPS_NO;
}

bool exec_is_cgroup_mount_read_only(const ExecContext *context) {
        assert(context);

        return IN_SET(exec_get_protect_control_groups(context), PROTECT_CONTROL_GROUPS_YES, PROTECT_CONTROL_GROUPS_STRICT);
}

bool exec_needs_pid_namespace(const ExecContext *context, const ExecParameters *params) {
        assert(context);

        /* PID namespaces don't really make sense for control processes so let's not use them for those. */
        if (params && FLAGS_SET(params->flags, EXEC_IS_CONTROL))
                return false;

        return context->private_pids != PRIVATE_PIDS_NO && namespace_type_supported(NAMESPACE_PID);
}

bool exec_needs_mount_namespace(
                const ExecContext *context,
                const ExecParameters *params,
                const ExecRuntime *runtime) {

        assert(context);

        if (context->root_image)
                return true;

        if (context->root_directory_as_fd)
                return true;

        if (!strv_isempty(context->read_write_paths) ||
            !strv_isempty(context->read_only_paths) ||
            !strv_isempty(context->inaccessible_paths) ||
            !strv_isempty(context->exec_paths) ||
            !strv_isempty(context->no_exec_paths))
                return true;

        if (context->n_bind_mounts > 0)
                return true;

        if (context->n_temporary_filesystems > 0)
                return true;

        if (context->n_mount_images > 0)
                return true;

        if (context->n_extension_images > 0)
                return true;

        if (!strv_isempty(context->extension_directories))
                return true;

        if (!IN_SET(context->mount_propagation_flag, 0, MS_SHARED))
                return true;

        if (context->private_tmp == PRIVATE_TMP_DISCONNECTED)
                return true;

        if (context->private_tmp == PRIVATE_TMP_CONNECTED && runtime && runtime->shared && (runtime->shared->tmp_dir || runtime->shared->var_tmp_dir))
                return true;

        if (context->private_devices ||
            context->private_mounts > 0 ||
            (context->private_mounts < 0 && exec_needs_network_namespace(context)) ||
            context->protect_system != PROTECT_SYSTEM_NO ||
            context->protect_home != PROTECT_HOME_NO ||
            context->protect_kernel_tunables ||
            context->protect_kernel_modules ||
            context->protect_kernel_logs ||
            exec_needs_cgroup_mount(context) ||
            context->protect_proc != PROTECT_PROC_DEFAULT ||
            context->proc_subset != PROC_SUBSET_ALL ||
            context->private_bpf != PRIVATE_BPF_NO ||
            exec_needs_ipc_namespace(context) ||
            exec_needs_pid_namespace(context, params))
                return true;

        if (context->root_directory) {
                if (exec_context_get_effective_mount_apivfs(context))
                        return true;

                for (ExecDirectoryType t = 0; t < _EXEC_DIRECTORY_TYPE_MAX; t++) {
                        if (params && !params->prefix[t])
                                continue;

                        if (context->directories[t].n_items > 0)
                                return true;
                }
        }

        if (context->dynamic_user &&
            (context->directories[EXEC_DIRECTORY_STATE].n_items > 0 ||
             context->directories[EXEC_DIRECTORY_CACHE].n_items > 0 ||
             context->directories[EXEC_DIRECTORY_LOGS].n_items > 0))
                return true;

        if (exec_context_get_effective_bind_log_sockets(context))
                return true;

        for (ExecDirectoryType t = 0; t < _EXEC_DIRECTORY_TYPE_MAX; t++)
                FOREACH_ARRAY(i, context->directories[t].items, context->directories[t].n_items)
                        if (FLAGS_SET(i->flags, EXEC_DIRECTORY_READ_ONLY))
                                return true;

        return false;
}

const char* exec_get_private_notify_socket_path(const ExecContext *context, const ExecParameters *params, bool needs_sandboxing) {
        assert(context);
        assert(params);

        if (!params->notify_socket)
                return NULL;

        if (!needs_sandboxing)
                return NULL;

        if (!exec_context_with_rootfs(context))
                return NULL;

        if (!exec_context_get_effective_mount_apivfs(context))
                return NULL;

        if (!FLAGS_SET(params->flags, EXEC_APPLY_CHROOT))
                return NULL;

        return "/run/host/notify";
}

int exec_log_level_max_with_exec_params(const ExecContext *context, const ExecParameters *params) {
        assert(params);

        if (params->debug_invocation)
                return LOG_DEBUG;

        return exec_log_level_max(context);
}

int exec_log_level_max(const ExecContext *context) {
        assert(context);
        return context->log_level_max < 0 ? log_get_max_level() : context->log_level_max;
}

bool exec_directory_is_private(const ExecContext *context, ExecDirectoryType type) {
        assert(context);

        if (!context->dynamic_user)
                return false;

        if (!EXEC_DIRECTORY_TYPE_SHALL_CHOWN(type))
                return false;

        if (type == EXEC_DIRECTORY_RUNTIME && context->runtime_directory_preserve_mode == EXEC_PRESERVE_NO)
                return false;

        return true;
}

int exec_params_needs_control_subcgroup(const ExecParameters *params) {
        /* Keep this in sync with exec_params_get_cgroup_path(). */
        return FLAGS_SET(params->flags, EXEC_CGROUP_DELEGATE|EXEC_CONTROL_CGROUP|EXEC_IS_CONTROL);
}

int exec_params_get_cgroup_path(
                const ExecParameters *params,
                const CGroupContext *c,
                const char *prefix,
                char **ret) {

        const char *subgroup = NULL;
        char *p;

        assert(params);
        assert(c);
        assert(ret);

        /* If we are called for a unit where cgroup delegation is on, and the payload created its own populated
         * subcgroup (which we expect it to do, after all it asked for delegation), then we cannot place the control
         * processes started after the main unit's process in the unit's main cgroup because it is now an inner one,
         * and inner cgroups may not contain processes. Hence, if delegation is on, and this is a control process,
         * let's use ".control" as subcgroup instead. Note that we do so only for ExecStartPost=, ExecReload=,
         * ExecStop=, ExecStopPost=, i.e. for the commands where the main process is already forked. For ExecStartPre=
         * this is not necessary, the cgroup is still empty. We distinguish these cases with the EXEC_CONTROL_CGROUP
         * flag, which is only passed for the former statements, not for the latter. */

        /* Keep this in sync with exec_params_needs_control_subcgroup(). */
        if (FLAGS_SET(params->flags, EXEC_CGROUP_DELEGATE) && (FLAGS_SET(params->flags, EXEC_CONTROL_CGROUP) || c->delegate_subgroup)) {
                if (FLAGS_SET(params->flags, EXEC_IS_CONTROL))
                        subgroup = ".control";
                else
                        subgroup = c->delegate_subgroup;
        }

        if (subgroup)
                p = path_join(prefix, subgroup);
        else
                p = strdup(strempty(prefix));
        if (!p)
                return -ENOMEM;

        *ret = p;
        return !!subgroup;
}

bool exec_context_get_cpu_affinity_from_numa(const ExecContext *c) {
        assert(c);

        return c->cpu_affinity_from_numa;
}

static void log_command_line(Unit *unit, const char *msg, const char *executable, char **argv) {
        assert(unit);
        assert(msg);
        assert(executable);

        if (!DEBUG_LOGGING)
                return;

        _cleanup_free_ char *cmdline = quote_command_line(argv, SHELL_ESCAPE_EMPTY);

        log_unit_struct(unit, LOG_DEBUG,
                        LOG_ITEM("EXECUTABLE=%s", executable),
                        LOG_UNIT_MESSAGE(unit, "%s: %s", msg, strnull(cmdline)),
                        LOG_UNIT_INVOCATION_ID(unit));
}

static int exec_context_load_environment(const Unit *unit, const ExecContext *c, char ***ret);

int exec_spawn(
                Unit *unit,
                ExecCommand *command,
                const ExecContext *context,
                ExecParameters *params,
                ExecRuntime *runtime,
                const CGroupContext *cgroup_context,
                PidRef *ret) {

        _cleanup_free_ char *subcgroup_path = NULL, *max_log_levels = NULL;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(unit);
        assert(unit->manager);
        assert(unit->manager->executor_fd >= 0);
        assert(unit->manager->executor_path);
        assert(command);
        assert(context);
        assert(params);
        assert(params->fds || (params->n_socket_fds + params->n_stashed_fds == 0 && !params->fd_names));
        assert(params->n_stashed_fds == 0 || FLAGS_SET(params->flags, EXEC_PASS_FDS));
        assert(!params->files_env); /* We fill this field, ensure it comes NULL-initialized to us */
        assert(ret);

        LOG_CONTEXT_PUSH_UNIT(unit);

        r = exec_context_load_environment(unit, context, &params->files_env);
        if (r < 0)
                return log_unit_error_errno(unit, r, "Failed to load environment files: %m");

        /* We won't know the real executable path until we create the mount namespace in the child, but we
           want to log from the parent, so we use the possibly inaccurate path here. */
        log_command_line(unit, "About to execute", command->path, command->argv);

        /* We cannot spawn the main service process into the subcgroup as it might need to unshare the cgroup
         * namespace first if one is configured to make sure the root of the cgroup namespace is the service
         * cgroup and not the subcgroup. However, when running control commands on a live service, the
         * commands have to be spawned inside a subcgroup, otherwise we violate the no inner processes rule
         * of cgroupv2 as the main service process might already have enabled controllers by writing to
         * cgroup.subtree_control. */

        const char *cgtarget;
        if (exec_params_needs_control_subcgroup(params)) {
                r = exec_params_get_cgroup_path(params, cgroup_context, params->cgroup_path, &subcgroup_path);
                if (r < 0)
                        return log_unit_error_errno(unit, r, "Failed to acquire subcgroup path: %m");
                if (r > 0) {
                        /* If there's a subcgroup, then let's create it here now (the main cgroup was already
                         * realized by the unit logic) */

                        r = cg_create(subcgroup_path);
                        if (r < 0)
                                return log_unit_error_errno(unit, r, "Failed to create subcgroup '%s': %m", subcgroup_path);
                }

                cgtarget = subcgroup_path;
        } else
                cgtarget = params->cgroup_path;

        /* In order to avoid copy-on-write traps and OOM-kills when pid1's memory.current is above the
         * child's memory.max, serialize all the state needed to start the unit, and pass it to the
         * systemd-executor binary. clone() with CLONE_VM + CLONE_VFORK will pause the parent until the exec
         * and ensure all memory is shared. The child immediately execs the new binary so the delay should
         * be minimal. If glibc 2.39 is available pidfd_spawn() is used in order to get a race-free pid fd
         * and to clone directly into the target cgroup (if we booted with cgroupv2). */

        r = open_serialization_file("sd-executor-state", &f);
        if (r < 0)
                return log_unit_error_errno(unit, r, "Failed to open serialization stream: %m");

        fdset = fdset_new();
        if (!fdset)
                return log_oom();

        r = exec_serialize_invocation(f, fdset, context, command, params, runtime, cgroup_context);
        if (r < 0)
                return log_unit_error_errno(unit, r, "Failed to serialize parameters: %m");

        r = finish_serialization_file(f);
        if (r < 0)
                return log_unit_error_errno(unit, r, "Failed to finish serialization stream: %m");

        r = fd_cloexec(fileno(f), false);
        if (r < 0)
                return log_unit_error_errno(unit, r, "Failed to set O_CLOEXEC on serialization fd: %m");

        r = fdset_cloexec(fdset, false);
        if (r < 0)
                return log_unit_error_errno(unit, r, "Failed to set O_CLOEXEC on serialized fds: %m");

        /* If LogLevelMax= is specified, then let's use the specified log level at the beginning of the
         * executor process. To achieve that the specified log level is passed as an argument, rather than
         * the one for the manager process. */
        r = log_max_levels_to_string(context->log_level_max >= 0 ? context->log_level_max : log_get_max_level(), &max_log_levels);
        if (r < 0)
                return log_unit_error_errno(unit, r, "Failed to convert max log levels to string: %m");

        char serialization_fd_number[DECIMAL_STR_MAX(int)];
        xsprintf(serialization_fd_number, "%i", fileno(f));

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        dual_timestamp start_timestamp;

        /* Restore the original ambient capability set the manager was started with to pass it to
         * sd-executor. */
        r = capability_ambient_set_apply(unit->manager->saved_ambient_set, /* also_inherit= */ false);
        if (r < 0)
                return log_unit_error_errno(unit, r, "Failed to apply the starting ambient set: %m");

        /* Record the start timestamp before we fork so that it is guaranteed to be earlier than the
         * handoff timestamp. */
        dual_timestamp_now(&start_timestamp);

        /* The executor binary is pinned, to avoid compatibility problems during upgrades. */
        r = posix_spawn_wrapper(
                        FORMAT_PROC_FD_PATH(unit->manager->executor_fd),
                        STRV_MAKE(unit->manager->executor_path,
                                  "--deserialize", serialization_fd_number,
                                  "--log-level", max_log_levels,
                                  "--log-target", log_target_to_string(manager_get_executor_log_target(unit->manager))),
                        environ,
                        cgtarget,
                        &pidref);

        /* Drop the ambient set again, so no processes other than sd-executore spawned from the manager inherit it. */
        (void) capability_ambient_set_apply(0, /* also_inherit= */ false);

        if (r == -EUCLEAN && cgtarget)
                return log_unit_error_errno(unit, r,
                                            "Failed to spawn process into cgroup '%s', because the cgroup "
                                            "or one of its parents or siblings is in the threaded mode.",
                                            cgtarget);
        if (r < 0)
                return log_unit_error_errno(unit, r, "Failed to spawn executor: %m");
        /* We add the new process to the cgroup both in the child (so that we can be sure that no user code is ever
         * executed outside of the cgroup) and in the parent (so that we can be sure that when we kill the cgroup the
         * process will be killed too). */
        if (r == 0 && cgtarget)
                (void) cg_attach(cgtarget, pidref.pid);
        /* r > 0: Already in the right cgroup thanks to CLONE_INTO_CGROUP */

        log_unit_debug(unit, "Forked %s as " PID_FMT " (%s CLONE_INTO_CGROUP)",
                       command->path, pidref.pid, r > 0 ? "via" : "without");

        exec_status_start(&command->exec_status, pidref.pid, &start_timestamp);

        *ret = TAKE_PIDREF(pidref);
        return 0;
}

void exec_context_init(ExecContext *c) {
        assert(c);

        /* When initializing a bool member to 'true', make sure to serialize in execute-serialize.c using
         * serialize_bool() instead of serialize_bool_elide(). */

        *c = (ExecContext) {
                .umask = 0022,
                .ioprio = IOPRIO_DEFAULT_CLASS_AND_PRIO,
                .cpu_sched_policy = SCHED_OTHER,
                .syslog_priority = LOG_DAEMON|LOG_INFO,
                .syslog_level_prefix = true,
                .ignore_sigpipe = true,
                .timer_slack_nsec = NSEC_INFINITY,
                .personality = PERSONALITY_INVALID,
                .timeout_clean_usec = USEC_INFINITY,
                .capability_bounding_set = CAP_MASK_ALL,
                .restrict_namespaces = NAMESPACE_FLAGS_INITIAL,
                .delegate_namespaces = NAMESPACE_FLAGS_INITIAL,
                .log_level_max = -1,
#if HAVE_SECCOMP
                .syscall_errno = SECCOMP_ERROR_NUMBER_KILL,
#endif
                .tty_rows = UINT_MAX,
                .tty_cols = UINT_MAX,
                .private_mounts = -1,
                .mount_apivfs = -1,
                .bind_log_sockets = -1,
                .memory_ksm = -1,
                .private_var_tmp = _PRIVATE_TMP_INVALID,
                .set_login_environment = -1,
        };

        FOREACH_ARRAY(d, c->directories, _EXEC_DIRECTORY_TYPE_MAX)
                d->mode = 0755;

        numa_policy_reset(&c->numa_policy);

        assert_cc(NAMESPACE_FLAGS_INITIAL != NAMESPACE_FLAGS_ALL);
}

void exec_context_done(ExecContext *c) {
        assert(c);

        c->environment = strv_free(c->environment);
        c->environment_files = strv_free(c->environment_files);
        c->pass_environment = strv_free(c->pass_environment);
        c->unset_environment = strv_free(c->unset_environment);

        rlimit_free_all(c->rlimit);

        for (size_t l = 0; l < 3; l++) {
                c->stdio_fdname[l] = mfree(c->stdio_fdname[l]);
                c->stdio_file[l] = mfree(c->stdio_file[l]);
        }

        c->working_directory = mfree(c->working_directory);
        c->root_directory = mfree(c->root_directory);
        c->root_image = mfree(c->root_image);
        c->root_image_options = mount_options_free_all(c->root_image_options);
        iovec_done(&c->root_hash);
        c->root_hash_path = mfree(c->root_hash_path);
        iovec_done(&c->root_hash_sig);
        c->root_hash_sig_path = mfree(c->root_hash_sig_path);
        c->root_verity = mfree(c->root_verity);
        c->tty_path = mfree(c->tty_path);
        c->syslog_identifier = mfree(c->syslog_identifier);
        c->user = mfree(c->user);
        c->group = mfree(c->group);

        c->supplementary_groups = strv_free(c->supplementary_groups);

        c->pam_name = mfree(c->pam_name);

        c->read_only_paths = strv_free(c->read_only_paths);
        c->read_write_paths = strv_free(c->read_write_paths);
        c->inaccessible_paths = strv_free(c->inaccessible_paths);
        c->exec_paths = strv_free(c->exec_paths);
        c->no_exec_paths = strv_free(c->no_exec_paths);
        c->exec_search_path = strv_free(c->exec_search_path);

        bind_mount_free_many(c->bind_mounts, c->n_bind_mounts);
        c->bind_mounts = NULL;
        c->n_bind_mounts = 0;
        mount_image_free_many(c->mount_images, c->n_mount_images);
        c->mount_images = NULL;
        c->n_mount_images = 0;
        mount_image_free_many(c->extension_images, c->n_extension_images);
        c->extension_images = NULL;
        c->n_extension_images = 0;
        c->extension_directories = strv_free(c->extension_directories);
        temporary_filesystem_free_many(c->temporary_filesystems, c->n_temporary_filesystems);
        c->temporary_filesystems = NULL;
        c->n_temporary_filesystems = 0;

        cpu_set_done(&c->cpu_set);
        numa_policy_reset(&c->numa_policy);

        c->utmp_id = mfree(c->utmp_id);
        c->selinux_context = mfree(c->selinux_context);
        c->apparmor_profile = mfree(c->apparmor_profile);
        c->smack_process_label = mfree(c->smack_process_label);

        c->restrict_filesystems = set_free(c->restrict_filesystems);

        c->syscall_filter = hashmap_free(c->syscall_filter);
        c->syscall_archs = set_free(c->syscall_archs);
        c->syscall_log = hashmap_free(c->syscall_log);
        c->address_families = set_free(c->address_families);

        FOREACH_ARRAY(d, c->directories, _EXEC_DIRECTORY_TYPE_MAX)
                exec_directory_done(d);

        c->log_level_max = -1;

        exec_context_free_log_extra_fields(c);
        c->log_filter_allowed_patterns = set_free(c->log_filter_allowed_patterns);
        c->log_filter_denied_patterns = set_free(c->log_filter_denied_patterns);

        c->log_ratelimit = (RateLimit) {};

        c->stdin_data = mfree(c->stdin_data);
        c->stdin_data_size = 0;

        c->user_namespace_path = mfree(c->user_namespace_path);
        c->network_namespace_path = mfree(c->network_namespace_path);
        c->ipc_namespace_path = mfree(c->ipc_namespace_path);

        c->log_namespace = mfree(c->log_namespace);

        c->load_credentials = hashmap_free(c->load_credentials);
        c->set_credentials = hashmap_free(c->set_credentials);
        c->import_credentials = ordered_set_free(c->import_credentials);

        c->root_image_policy = image_policy_free(c->root_image_policy);
        c->mount_image_policy = image_policy_free(c->mount_image_policy);
        c->extension_image_policy = image_policy_free(c->extension_image_policy);

        c->private_hostname = mfree(c->private_hostname);
}

int exec_context_destroy_runtime_directory(const ExecContext *c, const char *runtime_prefix) {
        assert(c);

        if (!runtime_prefix)
                return 0;

        FOREACH_ARRAY(i, c->directories[EXEC_DIRECTORY_RUNTIME].items, c->directories[EXEC_DIRECTORY_RUNTIME].n_items) {
                _cleanup_free_ char *p = NULL;

                if (exec_directory_is_private(c, EXEC_DIRECTORY_RUNTIME))
                        p = path_join(runtime_prefix, "private", i->path);
                else
                        p = path_join(runtime_prefix, i->path);
                if (!p)
                        return -ENOMEM;

                /* We execute this synchronously, since we need to be sure this is gone when we start the
                 * service next. */
                (void) rm_rf(p, REMOVE_ROOT);

                STRV_FOREACH(symlink, i->symlinks) {
                        _cleanup_free_ char *symlink_abs = NULL;

                        if (exec_directory_is_private(c, EXEC_DIRECTORY_RUNTIME))
                                symlink_abs = path_join(runtime_prefix, "private", *symlink);
                        else
                                symlink_abs = path_join(runtime_prefix, *symlink);
                        if (!symlink_abs)
                                return -ENOMEM;

                        (void) unlink(symlink_abs);
                }
        }

        return 0;
}

int exec_context_destroy_mount_ns_dir(Unit *u) {
        _cleanup_free_ char *p = NULL;

        if (!u || !MANAGER_IS_SYSTEM(u->manager))
                return 0;

        p = path_join("/run/systemd/propagate/", u->id);
        if (!p)
                return -ENOMEM;

        /* This is only filled transiently (see mount_in_namespace()), should be empty or even non-existent. */
        if (rmdir(p) < 0 && errno != ENOENT)
                log_unit_debug_errno(u, errno, "Unable to remove propagation dir '%s', ignoring: %m", p);

        return 0;
}

void exec_command_done(ExecCommand *c) {
        assert(c);

        c->path = mfree(c->path);
        c->argv = strv_free(c->argv);
}

void exec_command_done_array(ExecCommand *c, size_t n) {
        FOREACH_ARRAY(i, c, n)
                exec_command_done(i);
}

ExecCommand* exec_command_free(ExecCommand *c) {
        if (!c)
                return NULL;

        exec_command_done(c);
        return mfree(c);
}

ExecCommand* exec_command_free_list(ExecCommand *c) {
        ExecCommand *i;

        while ((i = LIST_POP(command, c)))
                exec_command_free(i);

        return NULL;
}

void exec_command_free_array(ExecCommand **c, size_t n) {
        FOREACH_ARRAY(i, c, n)
                *i = exec_command_free_list(*i);
}

void exec_command_reset_status_array(ExecCommand *c, size_t n) {
        FOREACH_ARRAY(i, c, n)
                exec_status_reset(&i->exec_status);
}

void exec_command_reset_status_list_array(ExecCommand **c, size_t n) {
        FOREACH_ARRAY(i, c, n)
                LIST_FOREACH(command, z, *i)
                        exec_status_reset(&z->exec_status);
}

typedef struct InvalidEnvInfo {
        const Unit *unit;
        const char *path;
} InvalidEnvInfo;

static void invalid_env(const char *p, void *userdata) {
        InvalidEnvInfo *info = userdata;

        log_unit_error(info->unit, "Ignoring invalid environment assignment '%s': %s", p, info->path);
}

const char* exec_context_fdname(const ExecContext *c, int fd_index) {
        assert(c);

        switch (fd_index) {

        case STDIN_FILENO:
                if (c->std_input != EXEC_INPUT_NAMED_FD)
                        return NULL;

                return c->stdio_fdname[STDIN_FILENO] ?: "stdin";

        case STDOUT_FILENO:
                if (c->std_output != EXEC_OUTPUT_NAMED_FD)
                        return NULL;

                return c->stdio_fdname[STDOUT_FILENO] ?: "stdout";

        case STDERR_FILENO:
                if (c->std_error != EXEC_OUTPUT_NAMED_FD)
                        return NULL;

                return c->stdio_fdname[STDERR_FILENO] ?: "stderr";

        default:
                return NULL;
        }
}

static int exec_context_load_environment(const Unit *unit, const ExecContext *c, char ***ret) {
        _cleanup_strv_free_ char **v = NULL;
        int r;

        assert(c);
        assert(ret);

        STRV_FOREACH(i, c->environment_files) {
                _cleanup_strv_free_ char **paths = NULL;
                bool ignore = false;
                char *fn = *i;

                if (fn[0] == '-') {
                        ignore = true;
                        fn++;
                }

                if (!path_is_absolute(fn)) {
                        if (ignore)
                                continue;
                        return -EINVAL;
                }

                /* Filename supports globbing, take all matching files */
                r = safe_glob(fn, /* flags= */ 0, &paths);
                if (r < 0) {
                        if (ignore)
                                continue;
                        return r;
                }

                /* When we don't match anything, -ENOENT should be returned */
                assert(!strv_isempty(paths));

                STRV_FOREACH(path, paths) {
                        _cleanup_strv_free_ char **p = NULL;

                        r = load_env_file(NULL, *path, &p);
                        if (r < 0) {
                                if (ignore)
                                        continue;
                                return r;
                        }

                        /* Log invalid environment variables with filename */
                        if (p) {
                                InvalidEnvInfo info = {
                                        .unit = unit,
                                        .path = *path,
                                };

                                strv_env_clean_with_callback(p, invalid_env, &info);
                        }

                        if (!v)
                                v = TAKE_PTR(p);
                        else {
                                char **m = strv_env_merge(v, p);
                                if (!m)
                                        return -ENOMEM;

                                strv_free_and_replace(v, m);
                        }
                }
        }

        *ret = TAKE_PTR(v);

        return 0;
}

static bool tty_may_match_dev_console(const char *tty) {
        _cleanup_free_ char *resolved = NULL;

        if (!tty)
                return true;

        tty = skip_dev_prefix(tty);

        /* trivial identity? */
        if (streq(tty, "console"))
                return true;

        if (resolve_dev_console(&resolved) < 0)
                return true; /* if we could not resolve, assume it may */

        /* "tty0" means the active VC, so it may be the same sometimes */
        return path_equal(skip_dev_prefix(resolved), tty) || (streq(skip_dev_prefix(resolved), "tty0") && tty_is_vc(tty));
}

static bool exec_context_may_touch_tty(const ExecContext *ec) {
        assert(ec);

        return ec->tty_reset ||
                ec->tty_vhangup ||
                ec->tty_vt_disallocate ||
                exec_input_is_terminal(ec->std_input) ||
                ec->std_output == EXEC_OUTPUT_TTY ||
                ec->std_error == EXEC_OUTPUT_TTY;
}

bool exec_context_may_touch_console(const ExecContext *ec) {

        return exec_context_may_touch_tty(ec) &&
               tty_may_match_dev_console(exec_context_tty_path(ec));
}

bool exec_context_shall_ansi_seq_reset(const ExecContext *c) {
        assert(c);

        /* Determines whether ANSI sequences shall be used during any terminal initialisation:
         *
         * 1. If the reset logic is enabled at all, this is an immediate no.
         *
         * 2. If $TERM is set to anything other than "dumb", it's a yes.
         */

        if (!c->tty_reset)
                return false;

        /* FIXME:
         * On invocation, we generate $TERM based on settings for StandardOutput= and friends and the kernel
         * command line options, or propagate $TERM from the service manager. See setup_term_environment(). */
        return !streq_ptr(strv_env_get(c->environment, "TERM"), "dumb");
}

static void strv_fprintf(FILE *f, char **l) {
        assert(f);

        STRV_FOREACH(g, l)
                fprintf(f, " %s", *g);
}

static void strv_dump(FILE* f, const char *prefix, const char *name, char **strv) {
        assert(f);
        assert(prefix);
        assert(name);

        if (!strv_isempty(strv)) {
                fprintf(f, "%s%s:", prefix, name);
                strv_fprintf(f, strv);
                fputs("\n", f);
        }
}

void exec_params_dump(const ExecParameters *p, FILE* f, const char *prefix) {
        assert(p);
        assert(f);

        prefix = strempty(prefix);

        fprintf(f,
                "%sRuntimeScope: %s\n"
                "%sExecFlags: %u\n"
                "%sSELinuxContextNetwork: %s\n"
                "%sCgroupPath: %s\n"
                "%sCrededentialsDirectory: %s\n"
                "%sEncryptedCredentialsDirectory: %s\n"
                "%sConfirmSpawn: %s\n"
                "%sShallConfirmSpawn: %s\n"
                "%sWatchdogUSec: " USEC_FMT "\n"
                "%sNotifySocket: %s\n"
                "%sDebugInvocation: %s\n"
                "%sFallbackSmackProcessLabel: %s\n",
                prefix, runtime_scope_to_string(p->runtime_scope),
                prefix, p->flags,
                prefix, yes_no(p->selinux_context_net),
                prefix, p->cgroup_path,
                prefix, strempty(p->received_credentials_directory),
                prefix, strempty(p->received_encrypted_credentials_directory),
                prefix, strempty(p->confirm_spawn),
                prefix, yes_no(p->shall_confirm_spawn),
                prefix, p->watchdog_usec,
                prefix, strempty(p->notify_socket),
                prefix, yes_no(p->debug_invocation),
                prefix, strempty(p->fallback_smack_process_label));

        strv_dump(f, prefix, "FdNames", p->fd_names);
        strv_dump(f, prefix, "Environment", p->environment);
        strv_dump(f, prefix, "Prefix", p->prefix);

        LIST_FOREACH(open_files, file, p->open_files)
                fprintf(f, "%sOpenFile: %s %s", prefix, file->path, open_file_flags_to_string(file->flags));

        strv_dump(f, prefix, "FilesEnv", p->files_env);
}

void exec_context_dump(const ExecContext *c, FILE* f, const char *prefix) {
        int r;

        assert(c);
        assert(f);

        prefix = strempty(prefix);

        fprintf(f,
                "%sUMask: %04o\n"
                "%sWorkingDirectory: %s\n"
                "%sRootDirectory: %s\n"
                "%sRootEphemeral: %s\n"
                "%sNonBlocking: %s\n"
                "%sPrivateTmp: %s\n"
                "%sPrivateDevices: %s\n"
                "%sProtectKernelTunables: %s\n"
                "%sProtectKernelModules: %s\n"
                "%sProtectKernelLogs: %s\n"
                "%sProtectClock: %s\n"
                "%sProtectControlGroups: %s\n"
                "%sPrivateNetwork: %s\n"
                "%sPrivateUsers: %s\n"
                "%sPrivatePIDs: %s\n"
                "%sProtectHome: %s\n"
                "%sProtectSystem: %s\n"
                "%sMountAPIVFS: %s\n"
                "%sBindLogSockets: %s\n"
                "%sIgnoreSIGPIPE: %s\n"
                "%sMemoryDenyWriteExecute: %s\n"
                "%sRestrictRealtime: %s\n"
                "%sRestrictSUIDSGID: %s\n"
                "%sKeyringMode: %s\n"
                "%sProtectHostname: %s%s%s\n"
                "%sProtectProc: %s\n"
                "%sProcSubset: %s\n"
                "%sMemoryTHP: %s\n"
                "%sPrivateBPF: %s\n",
                prefix, c->umask,
                prefix, empty_to_root(c->working_directory),
                prefix, empty_to_root(c->root_directory),
                prefix, yes_no(c->root_ephemeral),
                prefix, yes_no(c->non_blocking),
                prefix, private_tmp_to_string(c->private_tmp),
                prefix, yes_no(c->private_devices),
                prefix, yes_no(c->protect_kernel_tunables),
                prefix, yes_no(c->protect_kernel_modules),
                prefix, yes_no(c->protect_kernel_logs),
                prefix, yes_no(c->protect_clock),
                prefix, protect_control_groups_to_string(c->protect_control_groups),
                prefix, yes_no(c->private_network),
                prefix, private_users_to_string(c->private_users),
                prefix, private_pids_to_string(c->private_pids),
                prefix, protect_home_to_string(c->protect_home),
                prefix, protect_system_to_string(c->protect_system),
                prefix, yes_no(exec_context_get_effective_mount_apivfs(c)),
                prefix, yes_no(exec_context_get_effective_bind_log_sockets(c)),
                prefix, yes_no(c->ignore_sigpipe),
                prefix, yes_no(c->memory_deny_write_execute),
                prefix, yes_no(c->restrict_realtime),
                prefix, yes_no(c->restrict_suid_sgid),
                prefix, exec_keyring_mode_to_string(c->keyring_mode),
                prefix, protect_hostname_to_string(c->protect_hostname), c->private_hostname ? ":" : "", strempty(c->private_hostname),
                prefix, protect_proc_to_string(c->protect_proc),
                prefix, proc_subset_to_string(c->proc_subset),
                prefix, memory_thp_to_string(c->memory_thp),
                prefix, private_bpf_to_string(c->private_bpf));

        if (c->private_bpf == PRIVATE_BPF_YES) {
                _cleanup_free_ char
                        *commands = bpf_delegate_commands_to_string(c->bpf_delegate_commands),
                        *maps = bpf_delegate_maps_to_string(c->bpf_delegate_maps),
                        *programs = bpf_delegate_programs_to_string(c->bpf_delegate_programs),
                        *attachments = bpf_delegate_attachments_to_string(c->bpf_delegate_attachments);

                fprintf(f, "%sBPFDelegateCommands: %s\n", prefix, strna(commands));
                fprintf(f, "%sBPFDelegateMaps: %s\n", prefix, strna(maps));
                fprintf(f, "%sBPFDelegatePrograms: %s\n", prefix, strna(programs));
                fprintf(f, "%sBPFDelegateAttachments: %s\n", prefix, strna(attachments));
        }

        if (c->set_login_environment >= 0)
                fprintf(f, "%sSetLoginEnvironment: %s\n", prefix, yes_no(c->set_login_environment > 0));

        if (c->root_image)
                fprintf(f, "%sRootImage: %s\n", prefix, c->root_image);

        if (c->root_image_options) {
                _cleanup_free_ char *opts_str = NULL;

                if (mount_options_to_string(c->root_image_options, &opts_str) >= 0 && !isempty(opts_str))
                        fprintf(f, "%sRootImageOptions: %s\n", prefix, opts_str);
        }

        if (iovec_is_set(&c->root_hash)) {
                _cleanup_free_ char *encoded = NULL;
                encoded = hexmem(c->root_hash.iov_base, c->root_hash.iov_len);
                if (encoded)
                        fprintf(f, "%sRootHash: %s\n", prefix, encoded);
        }

        if (c->root_hash_path)
                fprintf(f, "%sRootHash: %s\n", prefix, c->root_hash_path);

        if (iovec_is_set(&c->root_hash_sig)) {
                _cleanup_free_ char *encoded = NULL;
                ssize_t len;
                len = base64mem(c->root_hash_sig.iov_base, c->root_hash_sig.iov_len, &encoded);
                if (len)
                        fprintf(f, "%sRootHashSignature: base64:%s\n", prefix, encoded);
        }

        if (c->root_hash_sig_path)
                fprintf(f, "%sRootHashSignature: %s\n", prefix, c->root_hash_sig_path);

        if (c->root_verity)
                fprintf(f, "%sRootVerity: %s\n", prefix, c->root_verity);

        STRV_FOREACH(e, c->environment)
                fprintf(f, "%sEnvironment: %s\n", prefix, *e);

        STRV_FOREACH(e, c->environment_files)
                fprintf(f, "%sEnvironmentFile: %s\n", prefix, *e);

        STRV_FOREACH(e, c->pass_environment)
                fprintf(f, "%sPassEnvironment: %s\n", prefix, *e);

        STRV_FOREACH(e, c->unset_environment)
                fprintf(f, "%sUnsetEnvironment: %s\n", prefix, *e);

        fprintf(f, "%sRuntimeDirectoryPreserve: %s\n", prefix, exec_preserve_mode_to_string(c->runtime_directory_preserve_mode));

        for (ExecDirectoryType dt = 0; dt < _EXEC_DIRECTORY_TYPE_MAX; dt++) {
                fprintf(f, "%s%sMode: %04o\n", prefix, exec_directory_type_to_string(dt), c->directories[dt].mode);

                for (size_t i = 0; i < c->directories[dt].n_items; i++) {
                        fprintf(f,
                                "%s%s: %s%s\n",
                                prefix,
                                exec_directory_type_to_string(dt),
                                c->directories[dt].items[i].path,
                                FLAGS_SET(c->directories[dt].items[i].flags, EXEC_DIRECTORY_READ_ONLY) ? " (ro)" : "");

                        STRV_FOREACH(d, c->directories[dt].items[i].symlinks)
                                fprintf(f, "%s%s: %s:%s\n", prefix, exec_directory_type_symlink_to_string(dt), c->directories[dt].items[i].path, *d);
                }
        }

        fprintf(f, "%sTimeoutCleanSec: %s\n", prefix, FORMAT_TIMESPAN(c->timeout_clean_usec, USEC_PER_SEC));

        if (c->memory_ksm >= 0)
                fprintf(f, "%sMemoryKSM: %s\n", prefix, yes_no(c->memory_ksm > 0));

        if (c->nice_set)
                fprintf(f, "%sNice: %i\n", prefix, c->nice);

        if (c->oom_score_adjust_set)
                fprintf(f, "%sOOMScoreAdjust: %i\n", prefix, c->oom_score_adjust);

        if (c->coredump_filter_set)
                fprintf(f, "%sCoredumpFilter: 0x%"PRIx64"\n", prefix, c->coredump_filter);

        for (unsigned i = 0; i < RLIM_NLIMITS; i++)
                if (c->rlimit[i]) {
                        fprintf(f, "%sLimit%s: " RLIM_FMT "\n",
                                prefix, rlimit_to_string(i), c->rlimit[i]->rlim_max);
                        fprintf(f, "%sLimit%sSoft: " RLIM_FMT "\n",
                                prefix, rlimit_to_string(i), c->rlimit[i]->rlim_cur);
                }

        if (c->ioprio_is_set) {
                _cleanup_free_ char *class_str = NULL;

                r = ioprio_class_to_string_alloc(ioprio_prio_class(c->ioprio), &class_str);
                if (r >= 0)
                        fprintf(f, "%sIOSchedulingClass: %s\n", prefix, class_str);

                fprintf(f, "%sIOPriority: %d\n", prefix, ioprio_prio_data(c->ioprio));
        }

        if (c->cpu_sched_set) {
                _cleanup_free_ char *policy_str = NULL;

                r = sched_policy_to_string_alloc(c->cpu_sched_policy, &policy_str);
                if (r >= 0)
                        fprintf(f, "%sCPUSchedulingPolicy: %s\n", prefix, policy_str);

                fprintf(f,
                        "%sCPUSchedulingPriority: %i\n"
                        "%sCPUSchedulingResetOnFork: %s\n",
                        prefix, c->cpu_sched_priority,
                        prefix, yes_no(c->cpu_sched_reset_on_fork));
        }

        if (c->cpu_set.set) {
                _cleanup_free_ char *affinity = NULL;

                affinity = cpu_set_to_range_string(&c->cpu_set);
                fprintf(f, "%sCPUAffinity: %s\n", prefix, affinity);
        }

        if (mpol_is_valid(numa_policy_get_type(&c->numa_policy))) {
                _cleanup_free_ char *nodes = NULL;

                nodes = cpu_set_to_range_string(&c->numa_policy.nodes);
                fprintf(f, "%sNUMAPolicy: %s\n", prefix, mpol_to_string(numa_policy_get_type(&c->numa_policy)));
                fprintf(f, "%sNUMAMask: %s\n", prefix, strnull(nodes));
        }

        if (c->timer_slack_nsec != NSEC_INFINITY)
                fprintf(f, "%sTimerSlackNSec: "NSEC_FMT "\n", prefix, c->timer_slack_nsec);

        fprintf(f,
                "%sStandardInput: %s\n"
                "%sStandardOutput: %s\n"
                "%sStandardError: %s\n",
                prefix, exec_input_to_string(c->std_input),
                prefix, exec_output_to_string(c->std_output),
                prefix, exec_output_to_string(c->std_error));

        if (c->std_input == EXEC_INPUT_NAMED_FD)
                fprintf(f, "%sStandardInputFileDescriptorName: %s\n", prefix, c->stdio_fdname[STDIN_FILENO]);
        if (c->std_output == EXEC_OUTPUT_NAMED_FD)
                fprintf(f, "%sStandardOutputFileDescriptorName: %s\n", prefix, c->stdio_fdname[STDOUT_FILENO]);
        if (c->std_error == EXEC_OUTPUT_NAMED_FD)
                fprintf(f, "%sStandardErrorFileDescriptorName: %s\n", prefix, c->stdio_fdname[STDERR_FILENO]);

        if (c->std_input == EXEC_INPUT_FILE)
                fprintf(f, "%sStandardInputFile: %s\n", prefix, c->stdio_file[STDIN_FILENO]);
        if (c->std_output == EXEC_OUTPUT_FILE)
                fprintf(f, "%sStandardOutputFile: %s\n", prefix, c->stdio_file[STDOUT_FILENO]);
        if (c->std_output == EXEC_OUTPUT_FILE_APPEND)
                fprintf(f, "%sStandardOutputFileToAppend: %s\n", prefix, c->stdio_file[STDOUT_FILENO]);
        if (c->std_output == EXEC_OUTPUT_FILE_TRUNCATE)
                fprintf(f, "%sStandardOutputFileToTruncate: %s\n", prefix, c->stdio_file[STDOUT_FILENO]);
        if (c->std_error == EXEC_OUTPUT_FILE)
                fprintf(f, "%sStandardErrorFile: %s\n", prefix, c->stdio_file[STDERR_FILENO]);
        if (c->std_error == EXEC_OUTPUT_FILE_APPEND)
                fprintf(f, "%sStandardErrorFileToAppend: %s\n", prefix, c->stdio_file[STDERR_FILENO]);
        if (c->std_error == EXEC_OUTPUT_FILE_TRUNCATE)
                fprintf(f, "%sStandardErrorFileToTruncate: %s\n", prefix, c->stdio_file[STDERR_FILENO]);

        if (c->tty_path)
                fprintf(f,
                        "%sTTYPath: %s\n"
                        "%sTTYReset: %s\n"
                        "%sTTYVHangup: %s\n"
                        "%sTTYVTDisallocate: %s\n"
                        "%sTTYRows: %u\n"
                        "%sTTYColumns: %u\n",
                        prefix, c->tty_path,
                        prefix, yes_no(c->tty_reset),
                        prefix, yes_no(c->tty_vhangup),
                        prefix, yes_no(c->tty_vt_disallocate),
                        prefix, c->tty_rows,
                        prefix, c->tty_cols);

        if (IN_SET(c->std_output,
                   EXEC_OUTPUT_KMSG,
                   EXEC_OUTPUT_JOURNAL,
                   EXEC_OUTPUT_KMSG_AND_CONSOLE,
                   EXEC_OUTPUT_JOURNAL_AND_CONSOLE) ||
            IN_SET(c->std_error,
                   EXEC_OUTPUT_KMSG,
                   EXEC_OUTPUT_JOURNAL,
                   EXEC_OUTPUT_KMSG_AND_CONSOLE,
                   EXEC_OUTPUT_JOURNAL_AND_CONSOLE)) {

                _cleanup_free_ char *fac_str = NULL, *lvl_str = NULL;

                r = log_facility_unshifted_to_string_alloc(c->syslog_priority >> 3, &fac_str);
                if (r >= 0)
                        fprintf(f, "%sSyslogFacility: %s\n", prefix, fac_str);

                r = log_level_to_string_alloc(LOG_PRI(c->syslog_priority), &lvl_str);
                if (r >= 0)
                        fprintf(f, "%sSyslogLevel: %s\n", prefix, lvl_str);
        }

        if (c->log_level_max >= 0) {
                _cleanup_free_ char *t = NULL;

                (void) log_level_to_string_alloc(c->log_level_max, &t);

                fprintf(f, "%sLogLevelMax: %s\n", prefix, strna(t));
        }

        if (c->log_ratelimit.interval > 0)
                fprintf(f,
                        "%sLogRateLimitIntervalSec: %s\n",
                        prefix, FORMAT_TIMESPAN(c->log_ratelimit.interval, USEC_PER_SEC));

        if (c->log_ratelimit.burst > 0)
                fprintf(f, "%sLogRateLimitBurst: %u\n", prefix, c->log_ratelimit.burst);

        if (!set_isempty(c->log_filter_allowed_patterns) || !set_isempty(c->log_filter_denied_patterns)) {
                fprintf(f, "%sLogFilterPatterns:", prefix);

                char *pattern;
                SET_FOREACH(pattern, c->log_filter_allowed_patterns)
                        fprintf(f, " %s", pattern);
                SET_FOREACH(pattern, c->log_filter_denied_patterns)
                        fprintf(f, " ~%s", pattern);
                fputc('\n', f);
        }

        FOREACH_ARRAY(field, c->log_extra_fields, c->n_log_extra_fields) {
                fprintf(f, "%sLogExtraFields: ", prefix);
                fwrite(field->iov_base, 1, field->iov_len, f);
                fputc('\n', f);
        }

        if (c->log_namespace)
                fprintf(f, "%sLogNamespace: %s\n", prefix, c->log_namespace);

        if (c->secure_bits) {
                _cleanup_free_ char *str = NULL;

                r = secure_bits_to_string_alloc(c->secure_bits, &str);
                if (r >= 0)
                        fprintf(f, "%sSecure Bits: %s\n", prefix, str);
        }

        if (c->capability_bounding_set != CAP_MASK_UNSET) {
                _cleanup_free_ char *str = NULL;

                r = capability_set_to_string(c->capability_bounding_set, &str);
                if (r >= 0)
                        fprintf(f, "%sCapabilityBoundingSet: %s\n", prefix, str);
        }

        if (c->capability_ambient_set != 0) {
                _cleanup_free_ char *str = NULL;

                r = capability_set_to_string(c->capability_ambient_set, &str);
                if (r >= 0)
                        fprintf(f, "%sAmbientCapabilities: %s\n", prefix, str);
        }

        if (c->user)
                fprintf(f, "%sUser: %s\n", prefix, c->user);
        if (c->group)
                fprintf(f, "%sGroup: %s\n", prefix, c->group);

        fprintf(f, "%sDynamicUser: %s\n", prefix, yes_no(c->dynamic_user));

        strv_dump(f, prefix, "SupplementaryGroups", c->supplementary_groups);

        if (c->pam_name)
                fprintf(f, "%sPAMName: %s\n", prefix, c->pam_name);

        strv_dump(f, prefix, "ReadWritePaths", c->read_write_paths);
        strv_dump(f, prefix, "ReadOnlyPaths", c->read_only_paths);
        strv_dump(f, prefix, "InaccessiblePaths", c->inaccessible_paths);
        strv_dump(f, prefix, "ExecPaths", c->exec_paths);
        strv_dump(f, prefix, "NoExecPaths", c->no_exec_paths);
        strv_dump(f, prefix, "ExecSearchPath", c->exec_search_path);

        FOREACH_ARRAY(mount, c->bind_mounts, c->n_bind_mounts)
                fprintf(f, "%s%s: %s%s:%s:%s\n", prefix,
                        mount->read_only ? "BindReadOnlyPaths" : "BindPaths",
                        mount->ignore_enoent ? "-": "",
                        mount->source,
                        mount->destination,
                        mount->recursive ? "rbind" : "norbind");

        FOREACH_ARRAY(tmpfs, c->temporary_filesystems, c->n_temporary_filesystems)
                fprintf(f, "%sTemporaryFileSystem: %s%s%s\n", prefix,
                        tmpfs->path,
                        isempty(tmpfs->options) ? "" : ":",
                        strempty(tmpfs->options));

        if (c->utmp_id)
                fprintf(f,
                        "%sUtmpIdentifier: %s\n",
                        prefix, c->utmp_id);

        if (c->selinux_context)
                fprintf(f,
                        "%sSELinuxContext: %s%s\n",
                        prefix, c->selinux_context_ignore ? "-" : "", c->selinux_context);

        if (c->apparmor_profile)
                fprintf(f,
                        "%sAppArmorProfile: %s%s\n",
                        prefix, c->apparmor_profile_ignore ? "-" : "", c->apparmor_profile);

        if (c->smack_process_label)
                fprintf(f,
                        "%sSmackProcessLabel: %s%s\n",
                        prefix, c->smack_process_label_ignore ? "-" : "", c->smack_process_label);

        if (c->personality != PERSONALITY_INVALID)
                fprintf(f,
                        "%sPersonality: %s\n",
                        prefix, strna(personality_to_string(c->personality)));

        fprintf(f,
                "%sLockPersonality: %s\n",
                prefix, yes_no(c->lock_personality));

        if (c->syscall_filter) {
                fprintf(f,
                        "%sSystemCallFilter: ",
                        prefix);

                if (!c->syscall_allow_list)
                        fputc('~', f);

#if HAVE_SECCOMP
                if (dlopen_libseccomp() >= 0) {
                        void *id, *val;
                        bool first = true;
                        HASHMAP_FOREACH_KEY(val, id, c->syscall_filter) {
                                _cleanup_free_ char *name = NULL;
                                const char *errno_name = NULL;
                                int num = PTR_TO_INT(val);

                                if (first)
                                        first = false;
                                else
                                        fputc(' ', f);

                                name = sym_seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, PTR_TO_INT(id) - 1);
                                fputs(strna(name), f);

                                if (num >= 0) {
                                        errno_name = seccomp_errno_or_action_to_string(num);
                                        if (errno_name)
                                                fprintf(f, ":%s", errno_name);
                                        else
                                                fprintf(f, ":%d", num);
                                }
                        }
                }
#endif

                fputc('\n', f);
        }

        if (c->syscall_archs) {
                fprintf(f,
                        "%sSystemCallArchitectures:",
                        prefix);

#if HAVE_SECCOMP
                void *id;
                SET_FOREACH(id, c->syscall_archs)
                        fprintf(f, " %s", strna(seccomp_arch_to_string(PTR_TO_UINT32(id) - 1)));
#endif
                fputc('\n', f);
        }

        if (exec_context_restrict_namespaces_set(c)) {
                _cleanup_free_ char *s = NULL;

                r = namespace_flags_to_string(c->restrict_namespaces, &s);
                if (r >= 0)
                        fprintf(f, "%sRestrictNamespaces: %s\n",
                                prefix, strna(s));
        }

#if HAVE_LIBBPF
        if (exec_context_restrict_filesystems_set(c)) {
                char *fs;
                SET_FOREACH(fs, c->restrict_filesystems)
                        fprintf(f, "%sRestrictFileSystems: %s\n", prefix, fs);
        }
#endif

        if (c->user_namespace_path)
                fprintf(f,
                        "%sUserNamespacePath: %s\n",
                        prefix, c->user_namespace_path);

        if (c->network_namespace_path)
                fprintf(f,
                        "%sNetworkNamespacePath: %s\n",
                        prefix, c->network_namespace_path);

        if (c->syscall_errno > 0) {
                fprintf(f, "%sSystemCallErrorNumber: ", prefix);

#if HAVE_SECCOMP
                const char *errno_name = seccomp_errno_or_action_to_string(c->syscall_errno);
                if (errno_name)
                        fputs(errno_name, f);
                else
                        fprintf(f, "%d", c->syscall_errno);
#endif
                fputc('\n', f);
        }

        FOREACH_ARRAY(mount, c->mount_images, c->n_mount_images) {
                fprintf(f, "%sMountImages: %s%s:%s", prefix,
                        mount->ignore_enoent ? "-": "",
                        mount->source,
                        mount->destination);
                if (mount->mount_options) {
                        _cleanup_free_ char *opts = NULL;

                        if (mount_options_to_string(mount->mount_options, &opts) >= 0 && !isempty(opts))
                                fprintf(f, " %s", opts);
                }
                fprintf(f, "\n");
        }

        FOREACH_ARRAY(mount, c->extension_images, c->n_extension_images) {
                fprintf(f, "%sExtensionImages: %s%s", prefix,
                        mount->ignore_enoent ? "-": "",
                        mount->source);
                if (mount->mount_options) {
                        _cleanup_free_ char *opts = NULL;

                        if (mount_options_to_string(mount->mount_options, &opts) >= 0 && !isempty(opts))
                                fprintf(f, " %s", opts);
                }
                fprintf(f, "\n");
        }

        strv_dump(f, prefix, "ExtensionDirectories", c->extension_directories);
}

bool exec_context_maintains_privileges(const ExecContext *c) {
        assert(c);

        /* Returns true if the process forked off would run under
         * an unchanged UID or as root. */

        if (!c->user)
                return true;

        if (STR_IN_SET(c->user, "root", "0"))
                return true;

        return false;
}

int exec_context_get_effective_ioprio(const ExecContext *c) {
        int p;

        assert(c);

        if (c->ioprio_is_set)
                return c->ioprio;

        p = ioprio_get(IOPRIO_WHO_PROCESS, 0);
        if (p < 0)
                return IOPRIO_DEFAULT_CLASS_AND_PRIO;

        return ioprio_normalize(p);
}

bool exec_context_get_effective_mount_apivfs(const ExecContext *c) {
        assert(c);

        /* Explicit setting wins */
        if (c->mount_apivfs >= 0)
                return c->mount_apivfs > 0;

        /* Default to "yes" if root directory or image are specified */
        if (exec_context_with_rootfs(c))
                return true;

        return false;
}

bool exec_context_get_effective_bind_log_sockets(const ExecContext *c) {
        assert(c);

        /* If log namespace is specified, "/run/systemd/journal.namespace/" would be bind mounted to
         * "/run/systemd/journal/", which effectively means BindLogSockets=yes */
        if (c->log_namespace)
                return true;

        if (c->bind_log_sockets >= 0)
                return c->bind_log_sockets > 0;

        if (exec_context_get_effective_mount_apivfs(c))
                return true;

        /* When PrivateDevices=yes, /dev/log gets symlinked to /run/systemd/journal/dev-log */
        if (exec_context_with_rootfs(c) && c->private_devices)
                return true;

        return false;
}

void exec_context_free_log_extra_fields(ExecContext *c) {
        assert(c);

        FOREACH_ARRAY(field, c->log_extra_fields, c->n_log_extra_fields)
                free(field->iov_base);

        c->log_extra_fields = mfree(c->log_extra_fields);
        c->n_log_extra_fields = 0;
}

void exec_context_revert_tty(ExecContext *c, sd_id128_t invocation_id) {
        _cleanup_close_ int fd = -EBADF;
        const char *path;
        struct stat st;
        int r;

        assert(c);

        /* First, reset the TTY (possibly kicking everybody else from the TTY) */
        exec_context_tty_reset(c, /* parameters= */ NULL, invocation_id);

        /* And then undo what chown_terminal() did earlier. Note that we only do this if we have a path
         * configured. If the TTY was passed to us as file descriptor we assume the TTY is opened and managed
         * by whoever passed it to us and thus knows better when and how to chmod()/chown() it back. */
        if (!exec_context_may_touch_tty(c))
                return;

        path = exec_context_tty_path(c);
        if (!path)
                return;

        fd = open(path, O_PATH|O_CLOEXEC); /* Pin the inode */
        if (fd < 0)
                return (void) log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                                             "Failed to open TTY inode of '%s' to adjust ownership/access mode, ignoring: %m",
                                             path);

        if (fstat(fd, &st) < 0)
                return (void) log_warning_errno(errno, "Failed to stat TTY '%s', ignoring: %m", path);

        /* Let's add a superficial check that we only do this for stuff that looks like a TTY. We only check
         * if things are a character device, since a proper check either means we'd have to open the TTY and
         * use isatty(), but we'd rather not do that since opening TTYs comes with all kinds of side-effects
         * and is slow. Or we'd have to hardcode dev_t major information, which we'd rather avoid. Why bother
         * with this at all? → https://github.com/systemd/systemd/issues/19213 */
        if (!S_ISCHR(st.st_mode))
                return log_warning("Configured TTY '%s' is not actually a character device, ignoring.", path);

        r = fchmod_and_chown(fd, TTY_MODE, 0, TTY_GID);
        if (r < 0)
                log_warning_errno(r, "Failed to reset TTY ownership/access mode of %s to " UID_FMT ":" GID_FMT ", ignoring: %m", path, (uid_t) 0, (gid_t) TTY_GID);
}

int exec_context_get_clean_directories(
                ExecContext *c,
                char **prefix,
                ExecCleanMask mask,
                char ***ret) {

        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(c);
        assert(prefix);
        assert(ret);

        for (ExecDirectoryType t = 0; t < _EXEC_DIRECTORY_TYPE_MAX; t++) {
                if (!BIT_SET(mask, t))
                        continue;

                if (!prefix[t])
                        continue;

                FOREACH_ARRAY(i, c->directories[t].items, c->directories[t].n_items) {
                        char *j;

                        j = path_join(prefix[t], i->path);
                        if (!j)
                                return -ENOMEM;

                        r = strv_consume(&l, j);
                        if (r < 0)
                                return r;

                        /* Also remove private directories unconditionally. */
                        if (EXEC_DIRECTORY_TYPE_SHALL_CHOWN(t)) {
                                j = path_join(prefix[t], "private", i->path);
                                if (!j)
                                        return -ENOMEM;

                                r = strv_consume(&l, j);
                                if (r < 0)
                                        return r;
                        }

                        STRV_FOREACH(symlink, i->symlinks) {
                                j = path_join(prefix[t], *symlink);
                                if (!j)
                                        return -ENOMEM;

                                r = strv_consume(&l, j);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        *ret = TAKE_PTR(l);
        return 0;
}

int exec_context_get_clean_mask(ExecContext *c, ExecCleanMask *ret) {
        ExecCleanMask mask = 0;

        assert(c);
        assert(ret);

        for (ExecDirectoryType t = 0; t < _EXEC_DIRECTORY_TYPE_MAX; t++)
                if (c->directories[t].n_items > 0)
                        mask |= 1U << t;

        *ret = mask;
        return 0;
}

int exec_context_get_oom_score_adjust(const ExecContext *c) {
        int n = 0, r;

        assert(c);

        if (c->oom_score_adjust_set)
                return c->oom_score_adjust;

        r = get_oom_score_adjust(&n);
        if (r < 0)
                log_debug_errno(r, "Failed to read /proc/self/oom_score_adj, ignoring: %m");

        return n;
}

uint64_t exec_context_get_coredump_filter(const ExecContext *c) {
        _cleanup_free_ char *t = NULL;
        uint64_t n = COREDUMP_FILTER_MASK_DEFAULT;
        int r;

        assert(c);

        if (c->coredump_filter_set)
                return c->coredump_filter;

        r = read_one_line_file("/proc/self/coredump_filter", &t);
        if (r < 0)
                log_debug_errno(r, "Failed to read /proc/self/coredump_filter, ignoring: %m");
        else {
                r = safe_atoux64(t, &n);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse \"%s\" from /proc/self/coredump_filter, ignoring: %m", t);
        }

        return n;
}

int exec_context_get_nice(const ExecContext *c) {
        int n;

        assert(c);

        if (c->nice_set)
                return c->nice;

        errno = 0;
        n = getpriority(PRIO_PROCESS, 0);
        if (errno > 0) {
                log_debug_errno(errno, "Failed to get process nice value, ignoring: %m");
                n = 0;
        }

        return n;
}

int exec_context_get_cpu_sched_policy(const ExecContext *c) {
        int n;

        assert(c);

        if (c->cpu_sched_set)
                return c->cpu_sched_policy;

        n = sched_getscheduler(0);
        if (n < 0)
                log_debug_errno(errno, "Failed to get scheduler policy, ignoring: %m");

        return n < 0 ? SCHED_OTHER : n;
}

int exec_context_get_cpu_sched_priority(const ExecContext *c) {
        struct sched_param p = {};
        int r;

        assert(c);

        if (c->cpu_sched_set)
                return c->cpu_sched_priority;

        r = sched_getparam(0, &p);
        if (r < 0)
                log_debug_errno(errno, "Failed to get scheduler priority, ignoring: %m");

        return r >= 0 ? p.sched_priority : 0;
}

uint64_t exec_context_get_timer_slack_nsec(const ExecContext *c) {
        int r;

        assert(c);

        if (c->timer_slack_nsec != NSEC_INFINITY)
                return c->timer_slack_nsec;

        r = prctl(PR_GET_TIMERSLACK);
        if (r < 0)
                log_debug_errno(r, "Failed to get timer slack, ignoring: %m");

        return (uint64_t) MAX(r, 0);
}

bool exec_context_get_set_login_environment(const ExecContext *c) {
        assert(c);

        if (c->set_login_environment >= 0)
                return c->set_login_environment;

        return c->user || c->dynamic_user || c->pam_name;
}

char** exec_context_get_syscall_filter(const ExecContext *c) {
        _cleanup_strv_free_ char **l = NULL;

        assert(c);

#if HAVE_SECCOMP
        if (dlopen_libseccomp() < 0)
                return strv_new(NULL);

        void *id, *val;
        HASHMAP_FOREACH_KEY(val, id, c->syscall_filter) {
                _cleanup_free_ char *name = NULL;
                const char *e = NULL;
                char *s;
                int num = PTR_TO_INT(val);

                if (c->syscall_allow_list && num >= 0)
                        /* syscall with num >= 0 in allow-list is denied. */
                        continue;

                name = sym_seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, PTR_TO_INT(id) - 1);
                if (!name)
                        continue;

                if (num >= 0) {
                        e = seccomp_errno_or_action_to_string(num);
                        if (e) {
                                s = strjoin(name, ":", e);
                                if (!s)
                                        return NULL;
                        } else {
                                if (asprintf(&s, "%s:%d", name, num) < 0)
                                        return NULL;
                        }
                } else
                        s = TAKE_PTR(name);

                if (strv_consume(&l, s) < 0)
                        return NULL;
        }

        strv_sort(l);
#endif

        return l ? TAKE_PTR(l) : strv_new(NULL);
}

char** exec_context_get_syscall_archs(const ExecContext *c) {
        _cleanup_strv_free_ char **l = NULL;

        assert(c);

#if HAVE_SECCOMP
        void *id;
        SET_FOREACH(id, c->syscall_archs) {
                const char *name;

                name = seccomp_arch_to_string(PTR_TO_UINT32(id) - 1);
                if (!name)
                        continue;

                if (strv_extend(&l, name) < 0)
                        return NULL;
        }

        strv_sort(l);
#endif

        return l ? TAKE_PTR(l) : strv_new(NULL);
}

char** exec_context_get_syscall_log(const ExecContext *c) {
        _cleanup_strv_free_ char **l = NULL;

        assert(c);

#if HAVE_SECCOMP
        if (dlopen_libseccomp() < 0)
                return strv_new(NULL);

        void *id, *val;
        HASHMAP_FOREACH_KEY(val, id, c->syscall_log) {
                char *name = NULL;

                name = sym_seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, PTR_TO_INT(id) - 1);
                if (!name)
                        continue;

                if (strv_consume(&l, name) < 0)
                        return NULL;
        }

        strv_sort(l);
#endif

        return l ? TAKE_PTR(l) : strv_new(NULL);
}

char** exec_context_get_address_families(const ExecContext *c) {
        _cleanup_strv_free_ char **l = NULL;
        void *af;

        assert(c);

        SET_FOREACH(af, c->address_families) {
                const char *name;

                name = af_to_name(PTR_TO_INT(af));
                if (!name)
                        continue;

                if (strv_extend(&l, name) < 0)
                        return NULL;
        }

        strv_sort(l);

        return l ? TAKE_PTR(l) : strv_new(NULL);
}

char** exec_context_get_restrict_filesystems(const ExecContext *c) {
        assert(c);

#if HAVE_LIBBPF
        char **l = set_get_strv(c->restrict_filesystems);
        if (!l)
                return NULL;

        return strv_sort(l);
#else
        return strv_new(NULL);
#endif
}

bool exec_context_restrict_namespaces_set(const ExecContext *c) {
        assert(c);

        return (c->restrict_namespaces & NAMESPACE_FLAGS_ALL) != NAMESPACE_FLAGS_ALL;
}

bool exec_context_restrict_filesystems_set(const ExecContext *c) {
        assert(c);

        return c->restrict_filesystems_allow_list ||
          !set_isempty(c->restrict_filesystems);
}

bool exec_context_with_rootfs(const ExecContext *c) {
        assert(c);

        /* Checks if RootDirectory=, RootImage= or RootDirectoryFileDescriptor= are used */

        return !empty_or_root(c->root_directory) || c->root_image || c->root_directory_as_fd;
}

int exec_context_has_vpicked_extensions(const ExecContext *context) {
        int r;

        assert(context);

        FOREACH_ARRAY(mi, context->extension_images, context->n_extension_images) {
                r = path_uses_vpick(mi->source);
                if (r != 0)
                        return r;
        }
        STRV_FOREACH(ed, context->extension_directories) {
                r = path_uses_vpick(*ed);
                if (r != 0)
                        return r;
        }

        return 0;
}

void exec_status_start(ExecStatus *s, pid_t pid, const dual_timestamp *ts) {
        assert(s);

        *s = (ExecStatus) {
                .pid = pid,
        };

        if (ts)
                s->start_timestamp = *ts;
        else
                dual_timestamp_now(&s->start_timestamp);
}

void exec_status_exit(ExecStatus *s, const ExecContext *context, pid_t pid, int code, int status) {
        assert(s);

        if (s->pid != pid)
                *s = (ExecStatus) {
                        .pid = pid,
                };

        dual_timestamp_now(&s->exit_timestamp);

        s->code = code;
        s->status = status;

        if (context && context->utmp_id)
                (void) utmp_put_dead_process(context->utmp_id, pid, code, status);
}

void exec_status_handoff(ExecStatus *s, const struct ucred *ucred, const dual_timestamp *ts) {
        assert(s);
        assert(ucred);
        assert(ts);

        if (ucred->pid != s->pid)
                *s = (ExecStatus) {
                        .pid = ucred->pid,
                };

        s->handoff_timestamp = *ts;
}

void exec_status_reset(ExecStatus *s) {
        assert(s);

        *s = (ExecStatus) {};
}

void exec_status_dump(const ExecStatus *s, FILE *f, const char *prefix) {
        assert(s);
        assert(f);

        if (s->pid <= 0)
                return;

        prefix = strempty(prefix);

        fprintf(f,
                "%sPID: "PID_FMT"\n",
                prefix, s->pid);

        if (dual_timestamp_is_set(&s->start_timestamp))
                fprintf(f,
                        "%sStart Timestamp: %s\n",
                        prefix, FORMAT_TIMESTAMP_STYLE(s->start_timestamp.realtime, TIMESTAMP_US));

        if (dual_timestamp_is_set(&s->handoff_timestamp) && dual_timestamp_is_set(&s->start_timestamp) &&
            s->handoff_timestamp.monotonic > s->start_timestamp.monotonic)
                fprintf(f,
                        "%sHandoff Timestamp: %s since start\n",
                        prefix,
                        FORMAT_TIMESPAN(usec_sub_unsigned(s->handoff_timestamp.monotonic, s->start_timestamp.monotonic), 1));
        else
                fprintf(f,
                        "%sHandoff Timestamp: %s\n",
                        prefix, FORMAT_TIMESTAMP_STYLE(s->handoff_timestamp.realtime, TIMESTAMP_US));

        if (dual_timestamp_is_set(&s->exit_timestamp)) {

                if (dual_timestamp_is_set(&s->handoff_timestamp) && s->exit_timestamp.monotonic > s->handoff_timestamp.monotonic)
                        fprintf(f,
                                "%sExit Timestamp: %s since handoff\n",
                                prefix,
                                FORMAT_TIMESPAN(usec_sub_unsigned(s->exit_timestamp.monotonic, s->handoff_timestamp.monotonic), 1));
                else if (dual_timestamp_is_set(&s->start_timestamp) && s->exit_timestamp.monotonic > s->start_timestamp.monotonic)
                        fprintf(f,
                                "%sExit Timestamp: %s since start\n",
                                prefix,
                                FORMAT_TIMESPAN(usec_sub_unsigned(s->exit_timestamp.monotonic, s->start_timestamp.monotonic), 1));
                else
                        fprintf(f,
                                "%sExit Timestamp: %s\n",
                                prefix, FORMAT_TIMESTAMP_STYLE(s->exit_timestamp.realtime, TIMESTAMP_US));

                fprintf(f,
                        "%sExit Code: %s\n"
                        "%sExit Status: %i\n",
                        prefix, sigchld_code_to_string(s->code),
                        prefix, s->status);
        }
}

void exec_command_dump(ExecCommand *c, FILE *f, const char *prefix) {
        _cleanup_free_ char *cmd = NULL;
        const char *prefix2;

        assert(c);
        assert(f);

        prefix = strempty(prefix);
        prefix2 = strjoina(prefix, "\t");

        cmd = quote_command_line(c->argv, SHELL_ESCAPE_EMPTY);

        fprintf(f,
                "%sCommand Line: %s\n",
                prefix, strnull(cmd));

        exec_status_dump(&c->exec_status, f, prefix2);
}

void exec_command_dump_list(ExecCommand *c, FILE *f, const char *prefix) {
        assert(f);

        prefix = strempty(prefix);

        LIST_FOREACH(command, i, c)
                exec_command_dump(i, f, prefix);
}

void exec_command_append_list(ExecCommand **l, ExecCommand *e) {
        ExecCommand *end;

        assert(l);
        assert(e);

        if (*l) {
                /* It's kind of important, that we keep the order here */
                end = LIST_FIND_TAIL(command, *l);
                LIST_INSERT_AFTER(command, *l, end, e);
        } else
                *l = e;
}

int exec_command_set(ExecCommand *c, const char *path, ...) {
        va_list ap;
        char **l, *p;

        assert(c);
        assert(path);

        va_start(ap, path);
        l = strv_new_ap(path, ap);
        va_end(ap);

        if (!l)
                return -ENOMEM;

        p = strdup(path);
        if (!p) {
                strv_free(l);
                return -ENOMEM;
        }

        free_and_replace(c->path, p);

        return strv_free_and_replace(c->argv, l);
}

int exec_command_append(ExecCommand *c, const char *path, ...) {
        char **l;
        va_list ap;
        int r;

        assert(c);
        assert(path);

        va_start(ap, path);
        l = strv_new_ap(path, ap);
        va_end(ap);

        if (!l)
                return -ENOMEM;

        r = strv_extend_strv_consume(&c->argv, l, /* filter_duplicates= */ false);
        if (r < 0)
                return r;

        return 0;
}

static char *destroy_tree(char *path) {
        if (!path)
                return NULL;

        if (!path_equal(path, RUN_SYSTEMD_EMPTY)) {
                log_debug("Spawning process to nuke '%s'", path);

                (void) asynchronous_rm_rf(path, REMOVE_ROOT|REMOVE_SUBVOLUME|REMOVE_PHYSICAL);
        }

        return mfree(path);
}

void exec_shared_runtime_done(ExecSharedRuntime *rt) {
        assert(rt);

        if (rt->manager)
                (void) hashmap_remove(rt->manager->exec_shared_runtime_by_id, rt->id);

        rt->id = mfree(rt->id);
        rt->tmp_dir = mfree(rt->tmp_dir);
        rt->var_tmp_dir = mfree(rt->var_tmp_dir);
        safe_close_pair(rt->userns_storage_socket);
        safe_close_pair(rt->netns_storage_socket);
        safe_close_pair(rt->ipcns_storage_socket);
}

static ExecSharedRuntime* exec_shared_runtime_free(ExecSharedRuntime *rt) {
        if (!rt)
                return NULL;

        exec_shared_runtime_done(rt);
        return mfree(rt);
}

DEFINE_TRIVIAL_UNREF_FUNC(ExecSharedRuntime, exec_shared_runtime, exec_shared_runtime_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(ExecSharedRuntime*, exec_shared_runtime_free);

ExecSharedRuntime* exec_shared_runtime_destroy(ExecSharedRuntime *rt) {
        if (!rt)
                return NULL;

        assert(rt->n_ref > 0);
        rt->n_ref--;

        if (rt->n_ref > 0)
                return NULL;

        rt->tmp_dir = destroy_tree(rt->tmp_dir);
        rt->var_tmp_dir = destroy_tree(rt->var_tmp_dir);

        return exec_shared_runtime_free(rt);
}

static int exec_shared_runtime_allocate(ExecSharedRuntime **ret, const char *id) {
        _cleanup_free_ char *id_copy = NULL;
        ExecSharedRuntime *n;

        assert(ret);

        id_copy = strdup(id);
        if (!id_copy)
                return -ENOMEM;

        n = new(ExecSharedRuntime, 1);
        if (!n)
                return -ENOMEM;

        *n = (ExecSharedRuntime) {
                .id = TAKE_PTR(id_copy),
                .userns_storage_socket = EBADF_PAIR,
                .netns_storage_socket = EBADF_PAIR,
                .ipcns_storage_socket = EBADF_PAIR,
        };

        *ret = n;
        return 0;
}

static int exec_shared_runtime_add(
                Manager *m,
                const char *id,
                char **tmp_dir,
                char **var_tmp_dir,
                int userns_storage_socket[2],
                int netns_storage_socket[2],
                int ipcns_storage_socket[2],
                ExecSharedRuntime **ret) {

        _cleanup_(exec_shared_runtime_freep) ExecSharedRuntime *rt = NULL;
        int r;

        assert(m);
        assert(id);

        /* tmp_dir, var_tmp_dir, {net,ipc}ns_storage_socket fds are donated on success */

        r = exec_shared_runtime_allocate(&rt, id);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&m->exec_shared_runtime_by_id, &string_hash_ops, rt->id, rt);
        if (r < 0)
                return r;

        assert(!!rt->tmp_dir == !!rt->var_tmp_dir); /* We require both to be set together */
        rt->tmp_dir = TAKE_PTR(*tmp_dir);
        rt->var_tmp_dir = TAKE_PTR(*var_tmp_dir);

        if (userns_storage_socket) {
                rt->userns_storage_socket[0] = TAKE_FD(userns_storage_socket[0]);
                rt->userns_storage_socket[1] = TAKE_FD(userns_storage_socket[1]);
        }

        if (netns_storage_socket) {
                rt->netns_storage_socket[0] = TAKE_FD(netns_storage_socket[0]);
                rt->netns_storage_socket[1] = TAKE_FD(netns_storage_socket[1]);
        }

        if (ipcns_storage_socket) {
                rt->ipcns_storage_socket[0] = TAKE_FD(ipcns_storage_socket[0]);
                rt->ipcns_storage_socket[1] = TAKE_FD(ipcns_storage_socket[1]);
        }

        rt->manager = m;

        if (ret)
                *ret = rt;
        /* do not remove created ExecSharedRuntime object when the operation succeeds. */
        TAKE_PTR(rt);
        return 0;
}

static int exec_shared_runtime_make(
                Manager *m,
                const ExecContext *c,
                const char *id,
                ExecSharedRuntime **ret) {

        _cleanup_(namespace_cleanup_tmpdirp) char *tmp_dir = NULL, *var_tmp_dir = NULL;
        _cleanup_close_pair_ int userns_storage_socket[2] = EBADF_PAIR, netns_storage_socket[2] = EBADF_PAIR, ipcns_storage_socket[2] = EBADF_PAIR;
        int r;

        assert(m);
        assert(c);
        assert(id);

        /* It is not necessary to create ExecSharedRuntime object. */
        if (!exec_needs_network_namespace(c) && !exec_needs_ipc_namespace(c) && c->private_tmp != PRIVATE_TMP_CONNECTED) {
                *ret = NULL;
                return 0;
        }

        if (c->private_tmp == PRIVATE_TMP_CONNECTED &&
            !(prefixed_path_strv_contains(c->inaccessible_paths, "/tmp") &&
              (prefixed_path_strv_contains(c->inaccessible_paths, "/var/tmp") ||
               prefixed_path_strv_contains(c->inaccessible_paths, "/var")))) {
                r = setup_tmp_dirs(id, &tmp_dir, &var_tmp_dir);
                if (r < 0)
                        return r;
        }

        if (c->user_namespace_path)
                if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, userns_storage_socket) < 0)
                        return -errno;

        if (exec_needs_network_namespace(c))
                if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, netns_storage_socket) < 0)
                        return -errno;

        if (exec_needs_ipc_namespace(c))
                if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, ipcns_storage_socket) < 0)
                        return -errno;

        r = exec_shared_runtime_add(m, id, &tmp_dir, &var_tmp_dir, userns_storage_socket, netns_storage_socket, ipcns_storage_socket, ret);
        if (r < 0)
                return r;

        return 1;
}

int exec_shared_runtime_acquire(Manager *m, const ExecContext *c, const char *id, bool create, ExecSharedRuntime **ret) {
        ExecSharedRuntime *rt;
        int r;

        assert(m);
        assert(id);
        assert(ret);

        rt = hashmap_get(m->exec_shared_runtime_by_id, id);
        if (rt)
                /* We already have an ExecSharedRuntime object, let's increase the ref count and reuse it */
                goto ref;

        if (!create) {
                *ret = NULL;
                return 0;
        }

        /* If not found, then create a new object. */
        r = exec_shared_runtime_make(m, c, id, &rt);
        if (r < 0)
                return r;
        if (r == 0) {
                /* When r == 0, it is not necessary to create ExecSharedRuntime object. */
                *ret = NULL;
                return 0;
        }

ref:
        /* increment reference counter. */
        rt->n_ref++;
        *ret = rt;
        return 1;
}

int exec_shared_runtime_serialize(const Manager *m, FILE *f, FDSet *fds) {
        ExecSharedRuntime *rt;

        assert(m);
        assert(f);
        assert(fds);

        HASHMAP_FOREACH(rt, m->exec_shared_runtime_by_id) {
                fprintf(f, "exec-runtime=%s", rt->id);

                if (rt->tmp_dir)
                        fprintf(f, " tmp-dir=%s", rt->tmp_dir);

                if (rt->var_tmp_dir)
                        fprintf(f, " var-tmp-dir=%s", rt->var_tmp_dir);

                if (rt->userns_storage_socket[0] >= 0) {
                        int copy;

                        copy = fdset_put_dup(fds, rt->userns_storage_socket[0]);
                        if (copy < 0)
                                return copy;

                        fprintf(f, " userns-socket-0=%i", copy);
                }

                if (rt->userns_storage_socket[1] >= 0) {
                        int copy;

                        copy = fdset_put_dup(fds, rt->userns_storage_socket[1]);
                        if (copy < 0)
                                return copy;

                        fprintf(f, " userns-socket-1=%i", copy);
                }

                if (rt->netns_storage_socket[0] >= 0) {
                        int copy;

                        copy = fdset_put_dup(fds, rt->netns_storage_socket[0]);
                        if (copy < 0)
                                return copy;

                        fprintf(f, " netns-socket-0=%i", copy);
                }

                if (rt->netns_storage_socket[1] >= 0) {
                        int copy;

                        copy = fdset_put_dup(fds, rt->netns_storage_socket[1]);
                        if (copy < 0)
                                return copy;

                        fprintf(f, " netns-socket-1=%i", copy);
                }

                if (rt->ipcns_storage_socket[0] >= 0) {
                        int copy;

                        copy = fdset_put_dup(fds, rt->ipcns_storage_socket[0]);
                        if (copy < 0)
                                return copy;

                        fprintf(f, " ipcns-socket-0=%i", copy);
                }

                if (rt->ipcns_storage_socket[1] >= 0) {
                        int copy;

                        copy = fdset_put_dup(fds, rt->ipcns_storage_socket[1]);
                        if (copy < 0)
                                return copy;

                        fprintf(f, " ipcns-socket-1=%i", copy);
                }

                fputc('\n', f);
        }

        return 0;
}

int exec_shared_runtime_deserialize_compat(Unit *u, const char *key, const char *value, FDSet *fds) {
        _cleanup_(exec_shared_runtime_freep) ExecSharedRuntime *rt_create = NULL;
        ExecSharedRuntime *rt = NULL;
        int r;

        /* This is for the migration from old (v237 or earlier) deserialization text.
         * Due to the bug #7790, this may not work with the units that use JoinsNamespaceOf=.
         * Even if the ExecSharedRuntime object originally created by the other unit, we cannot judge
         * so or not from the serialized text, then we always creates a new object owned by this. */

        assert(u);
        assert(key);
        assert(value);

        /* Manager manages ExecSharedRuntime objects by the unit id.
         * So, we omit the serialized text when the unit does not have id (yet?)... */
        if (isempty(u->id)) {
                log_unit_debug(u, "Invocation ID not found. Dropping runtime parameter.");
                return 0;
        }

        if (u->manager) {
                if (hashmap_ensure_allocated(&u->manager->exec_shared_runtime_by_id, &string_hash_ops) < 0)
                        return log_oom();

                rt = hashmap_get(u->manager->exec_shared_runtime_by_id, u->id);
        }
        if (!rt) {
                if (exec_shared_runtime_allocate(&rt_create, u->id) < 0)
                        return log_oom();

                rt = rt_create;
        }

        if (streq(key, "tmp-dir")) {
                if (free_and_strdup_warn(&rt->tmp_dir, value) < 0)
                        return -ENOMEM;

        } else if (streq(key, "var-tmp-dir")) {
                if (free_and_strdup_warn(&rt->var_tmp_dir, value) < 0)
                        return -ENOMEM;

        } else if (streq(key, "netns-socket-0")) {

                safe_close(rt->netns_storage_socket[0]);
                rt->netns_storage_socket[0] = deserialize_fd(fds, value);
                if (rt->netns_storage_socket[0] < 0)
                        return 0;

        } else if (streq(key, "netns-socket-1")) {

                safe_close(rt->netns_storage_socket[1]);
                rt->netns_storage_socket[1] = deserialize_fd(fds, value);
                if (rt->netns_storage_socket[1] < 0)
                        return 0;
        } else
                return 0;

        /* If the object is newly created, then put it to the hashmap which manages ExecSharedRuntime objects. */
        if (rt_create && u->manager) {
                r = hashmap_put(u->manager->exec_shared_runtime_by_id, rt_create->id, rt_create);
                if (r < 0) {
                        log_unit_debug_errno(u, r, "Failed to put runtime parameter to manager's storage: %m");
                        return 0;
                }

                rt_create->manager = u->manager;

                /* Avoid cleanup */
                TAKE_PTR(rt_create);
        }

        return 1;
}

int exec_shared_runtime_deserialize_one(Manager *m, const char *value, FDSet *fds) {
        _cleanup_free_ char *tmp_dir = NULL, *var_tmp_dir = NULL;
        char *id = NULL;
        int r, userns_fdpair[] = {-1, -1}, netns_fdpair[] = {-1, -1}, ipcns_fdpair[] = {-1, -1};
        const char *p, *v = ASSERT_PTR(value);
        size_t n;

        assert(m);
        assert(fds);

        n = strcspn(v, " ");
        id = strndupa_safe(v, n);
        if (v[n] != ' ')
                goto finalize;
        p = v + n + 1;

        v = startswith(p, "tmp-dir=");
        if (v) {
                n = strcspn(v, " ");
                tmp_dir = strndup(v, n);
                if (!tmp_dir)
                        return log_oom();
                if (v[n] != ' ')
                        goto finalize;
                p = v + n + 1;
        }

        v = startswith(p, "var-tmp-dir=");
        if (v) {
                n = strcspn(v, " ");
                var_tmp_dir = strndup(v, n);
                if (!var_tmp_dir)
                        return log_oom();
                if (v[n] != ' ')
                        goto finalize;
                p = v + n + 1;
        }

        v = startswith(p, "userns-socket-0=");
        if (v) {
                char *buf;

                n = strcspn(v, " ");
                buf = strndupa_safe(v, n);

                userns_fdpair[0] = deserialize_fd(fds, buf);
                if (userns_fdpair[0] < 0)
                        return userns_fdpair[0];
                if (v[n] != ' ')
                        goto finalize;
                p = v + n + 1;
        }

        v = startswith(p, "userns-socket-1=");
        if (v) {
                char *buf;

                n = strcspn(v, " ");
                buf = strndupa_safe(v, n);

                userns_fdpair[1] = deserialize_fd(fds, buf);
                if (userns_fdpair[1] < 0)
                        return userns_fdpair[1];
                if (v[n] != ' ')
                        goto finalize;
                p = v + n + 1;
        }

        v = startswith(p, "netns-socket-0=");
        if (v) {
                char *buf;

                n = strcspn(v, " ");
                buf = strndupa_safe(v, n);

                netns_fdpair[0] = deserialize_fd(fds, buf);
                if (netns_fdpair[0] < 0)
                        return netns_fdpair[0];
                if (v[n] != ' ')
                        goto finalize;
                p = v + n + 1;
        }

        v = startswith(p, "netns-socket-1=");
        if (v) {
                char *buf;

                n = strcspn(v, " ");
                buf = strndupa_safe(v, n);

                netns_fdpair[1] = deserialize_fd(fds, buf);
                if (netns_fdpair[1] < 0)
                        return netns_fdpair[1];
                if (v[n] != ' ')
                        goto finalize;
                p = v + n + 1;
        }

        v = startswith(p, "ipcns-socket-0=");
        if (v) {
                char *buf;

                n = strcspn(v, " ");
                buf = strndupa_safe(v, n);

                ipcns_fdpair[0] = deserialize_fd(fds, buf);
                if (ipcns_fdpair[0] < 0)
                        return ipcns_fdpair[0];
                if (v[n] != ' ')
                        goto finalize;
                p = v + n + 1;
        }

        v = startswith(p, "ipcns-socket-1=");
        if (v) {
                char *buf;

                n = strcspn(v, " ");
                buf = strndupa_safe(v, n);

                ipcns_fdpair[1] = deserialize_fd(fds, buf);
                if (ipcns_fdpair[1] < 0)
                        return ipcns_fdpair[1];
        }

finalize:
        r = exec_shared_runtime_add(m, id, &tmp_dir, &var_tmp_dir, userns_fdpair, netns_fdpair, ipcns_fdpair, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to add exec-runtime: %m");
        return 0;
}

void exec_shared_runtime_vacuum(Manager *m) {
        ExecSharedRuntime *rt;

        assert(m);

        /* Free unreferenced ExecSharedRuntime objects. This is used after manager deserialization process. */

        HASHMAP_FOREACH(rt, m->exec_shared_runtime_by_id) {
                if (rt->n_ref > 0)
                        continue;

                (void) exec_shared_runtime_free(rt);
        }
}

int exec_runtime_make(
                const Unit *unit,
                const ExecContext *context,
                ExecSharedRuntime *shared,
                DynamicCreds *creds,
                ExecRuntime **ret) {
        _cleanup_close_pair_ int ephemeral_storage_socket[2] = EBADF_PAIR;
        _cleanup_free_ char *ephemeral = NULL;
        _cleanup_(exec_runtime_freep) ExecRuntime *rt = NULL;
        int r;

        assert(unit);
        assert(context);
        assert(ret);

        if (!shared && !creds && !exec_needs_ephemeral(context)) {
                *ret = NULL;
                return 0;
        }

        if (exec_needs_ephemeral(context)) {
                r = mkdir_p("/var/lib/systemd/ephemeral-trees", 0755);
                if (r < 0)
                        return r;

                r = tempfn_random_child("/var/lib/systemd/ephemeral-trees", unit->id, &ephemeral);
                if (r < 0)
                        return r;

                if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, ephemeral_storage_socket) < 0)
                        return -errno;
        }

        rt = new(ExecRuntime, 1);
        if (!rt)
                return -ENOMEM;

        *rt = (ExecRuntime) {
                .shared = shared,
                .dynamic_creds = creds,
                .ephemeral_copy = TAKE_PTR(ephemeral),
                .ephemeral_storage_socket[0] = TAKE_FD(ephemeral_storage_socket[0]),
                .ephemeral_storage_socket[1] = TAKE_FD(ephemeral_storage_socket[1]),
        };

        *ret = TAKE_PTR(rt);
        return 1;
}

ExecRuntime* exec_runtime_free(ExecRuntime *rt) {
        if (!rt)
                return NULL;

        exec_shared_runtime_unref(rt->shared);
        dynamic_creds_unref(rt->dynamic_creds);

        rt->ephemeral_copy = destroy_tree(rt->ephemeral_copy);

        safe_close_pair(rt->ephemeral_storage_socket);
        return mfree(rt);
}

ExecRuntime* exec_runtime_destroy(ExecRuntime *rt) {
        if (!rt)
                return NULL;

        rt->shared = exec_shared_runtime_destroy(rt->shared);
        rt->dynamic_creds = dynamic_creds_destroy(rt->dynamic_creds);
        return exec_runtime_free(rt);
}

void exec_runtime_clear(ExecRuntime *rt) {
        if (!rt)
                return;

        safe_close_pair(rt->ephemeral_storage_socket);
        rt->ephemeral_copy = mfree(rt->ephemeral_copy);
}

void exec_params_shallow_clear(ExecParameters *p) {
        if (!p)
                return;

        /* This is called on the PID1 side, as many of the struct's FDs are only borrowed, and actually
         * owned by the manager or other objects, and reused across multiple units. */

        p->environment = strv_free(p->environment);
        p->fd_names = strv_free(p->fd_names);
        p->files_env = strv_free(p->files_env);
        p->fds = mfree(p->fds);
        p->root_directory_fd = safe_close(p->root_directory_fd);
        p->exec_fd = safe_close(p->exec_fd);
        p->user_lookup_fd = -EBADF;
        p->bpf_restrict_fs_map_fd = -EBADF;
        p->unit_id = mfree(p->unit_id);
        p->invocation_id = SD_ID128_NULL;
        p->invocation_id_string[0] = '\0';
        p->confirm_spawn = mfree(p->confirm_spawn);
}

void exec_params_deep_clear(ExecParameters *p) {
        if (!p)
                return;

        /* This is called on the sd-executor side, where everything received is owned by the process and has
         * to be fully cleaned up to make sanitizers and analyzers happy, as opposed as the shallow clean
         * function above. */

        close_many_unset(p->fds, p->n_socket_fds + p->n_stashed_fds);

        p->cgroup_path = mfree(p->cgroup_path);

        if (p->prefix) {
                free_many_charp(p->prefix, _EXEC_DIRECTORY_TYPE_MAX);
                p->prefix = mfree(p->prefix);
        }

        p->received_credentials_directory = mfree(p->received_credentials_directory);
        p->received_encrypted_credentials_directory = mfree(p->received_encrypted_credentials_directory);

        if (p->idle_pipe) {
                close_many_and_free(p->idle_pipe, 4);
                p->idle_pipe = NULL;
        }

        p->stdin_fd = safe_close(p->stdin_fd);
        p->stdout_fd = safe_close(p->stdout_fd);
        p->stderr_fd = safe_close(p->stderr_fd);
        p->root_directory_fd = safe_close(p->root_directory_fd);

        p->notify_socket = mfree(p->notify_socket);

        open_file_free_many(&p->open_files);

        p->fallback_smack_process_label = mfree(p->fallback_smack_process_label);

        exec_params_shallow_clear(p);
}

void exec_directory_done(ExecDirectory *d) {
        if (!d)
                return;

        FOREACH_ARRAY(i, d->items, d->n_items) {
                free(i->path);
                strv_free(i->symlinks);
        }

        d->items = mfree(d->items);
        d->n_items = 0;
        d->mode = 0755;
}

static ExecDirectoryItem *exec_directory_find(ExecDirectory *d, const char *path) {
        assert(d);
        assert(path);

        FOREACH_ARRAY(i, d->items, d->n_items)
                if (path_equal(i->path, path))
                        return i;

        return NULL;
}

int exec_directory_add(ExecDirectory *d, const char *path, const char *symlink, ExecDirectoryFlags flags) {
        _cleanup_strv_free_ char **s = NULL;
        _cleanup_free_ char *p = NULL;
        ExecDirectoryItem *existing;
        int r;

        assert(d);
        assert(path);

        existing = exec_directory_find(d, path);
        if (existing) {
                r = strv_extend(&existing->symlinks, symlink);
                if (r < 0)
                        return r;

                existing->flags |= flags;

                return 0; /* existing item is updated */
        }

        p = strdup(path);
        if (!p)
                return -ENOMEM;

        if (symlink) {
                s = strv_new(symlink);
                if (!s)
                        return -ENOMEM;
        }

        if (!GREEDY_REALLOC(d->items, d->n_items + 1))
                return -ENOMEM;

        d->items[d->n_items++] = (ExecDirectoryItem) {
                .path = TAKE_PTR(p),
                .symlinks = TAKE_PTR(s),
                .flags = flags,
        };

        return 1; /* new item is added */
}

static int exec_directory_item_compare_func(const ExecDirectoryItem *a, const ExecDirectoryItem *b) {
        assert(a);
        assert(b);

        return path_compare(a->path, b->path);
}

void exec_directory_sort(ExecDirectory *d) {
        assert(d);

        /* Sort the exec directories to make always parent directories processed at first in
         * setup_exec_directory(), e.g., even if StateDirectory=foo/bar foo, we need to create foo at first,
         * then foo/bar. Also, set the ONLY_CREATE flag if one of the parent directories is contained in the
         * list. See also comments in setup_exec_directory() and issue #24783. */

        if (d->n_items <= 1)
                return;

        typesafe_qsort(d->items, d->n_items, exec_directory_item_compare_func);

        for (size_t i = 1; i < d->n_items; i++)
                for (size_t j = 0; j < i; j++)
                        if (path_startswith(d->items[i].path, d->items[j].path)) {
                                d->items[i].flags |= EXEC_DIRECTORY_ONLY_CREATE;
                                break;
                        }
}

ExecCleanMask exec_clean_mask_from_string(const char *s) {
        ExecDirectoryType t;

        assert(s);

        if (streq(s, "all"))
                return EXEC_CLEAN_ALL;
        if (streq(s, "fdstore"))
                return EXEC_CLEAN_FDSTORE;

        t = exec_resource_type_from_string(s);
        if (t < 0)
                return (ExecCleanMask) t;

        return 1U << t;
}

static const char* const exec_input_table[_EXEC_INPUT_MAX] = {
        [EXEC_INPUT_NULL]      = "null",
        [EXEC_INPUT_TTY]       = "tty",
        [EXEC_INPUT_TTY_FORCE] = "tty-force",
        [EXEC_INPUT_TTY_FAIL]  = "tty-fail",
        [EXEC_INPUT_SOCKET]    = "socket",
        [EXEC_INPUT_NAMED_FD]  = "fd",
        [EXEC_INPUT_DATA]      = "data",
        [EXEC_INPUT_FILE]      = "file",
};

DEFINE_STRING_TABLE_LOOKUP(exec_input, ExecInput);

static const char* const exec_output_table[_EXEC_OUTPUT_MAX] = {
        [EXEC_OUTPUT_INHERIT]             = "inherit",
        [EXEC_OUTPUT_NULL]                = "null",
        [EXEC_OUTPUT_TTY]                 = "tty",
        [EXEC_OUTPUT_KMSG]                = "kmsg",
        [EXEC_OUTPUT_KMSG_AND_CONSOLE]    = "kmsg+console",
        [EXEC_OUTPUT_JOURNAL]             = "journal",
        [EXEC_OUTPUT_JOURNAL_AND_CONSOLE] = "journal+console",
        [EXEC_OUTPUT_SOCKET]              = "socket",
        [EXEC_OUTPUT_NAMED_FD]            = "fd",
        [EXEC_OUTPUT_FILE]                = "file",
        [EXEC_OUTPUT_FILE_APPEND]         = "append",
        [EXEC_OUTPUT_FILE_TRUNCATE]       = "truncate",
};

DEFINE_STRING_TABLE_LOOKUP(exec_output, ExecOutput);

static const char* const exec_utmp_mode_table[_EXEC_UTMP_MODE_MAX] = {
        [EXEC_UTMP_INIT]  = "init",
        [EXEC_UTMP_LOGIN] = "login",
        [EXEC_UTMP_USER]  = "user",
};

DEFINE_STRING_TABLE_LOOKUP(exec_utmp_mode, ExecUtmpMode);

static const char* const exec_preserve_mode_table[_EXEC_PRESERVE_MODE_MAX] = {
        [EXEC_PRESERVE_NO]      = "no",
        [EXEC_PRESERVE_YES]     = "yes",
        [EXEC_PRESERVE_RESTART] = "restart",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(exec_preserve_mode, ExecPreserveMode, EXEC_PRESERVE_YES);

/* This table maps ExecDirectoryType to the symlink setting it is configured with in the unit */
static const char* const exec_directory_type_symlink_table[_EXEC_DIRECTORY_TYPE_MAX] = {
        [EXEC_DIRECTORY_RUNTIME]       = "RuntimeDirectorySymlink",
        [EXEC_DIRECTORY_STATE]         = "StateDirectorySymlink",
        [EXEC_DIRECTORY_CACHE]         = "CacheDirectorySymlink",
        [EXEC_DIRECTORY_LOGS]          = "LogsDirectorySymlink",
        [EXEC_DIRECTORY_CONFIGURATION] = "ConfigurationDirectorySymlink",
};

DEFINE_STRING_TABLE_LOOKUP(exec_directory_type_symlink, ExecDirectoryType);

static const char* const exec_directory_type_mode_table[_EXEC_DIRECTORY_TYPE_MAX] = {
        [EXEC_DIRECTORY_RUNTIME]       = "RuntimeDirectoryMode",
        [EXEC_DIRECTORY_STATE]         = "StateDirectoryMode",
        [EXEC_DIRECTORY_CACHE]         = "CacheDirectoryMode",
        [EXEC_DIRECTORY_LOGS]          = "LogsDirectoryMode",
        [EXEC_DIRECTORY_CONFIGURATION] = "ConfigurationDirectoryMode",
};

DEFINE_STRING_TABLE_LOOKUP(exec_directory_type_mode, ExecDirectoryType);

/* And this table maps ExecDirectoryType too, but to a generic term identifying the type of resource. This
 * one is supposed to be generic enough to be used for unit types that don't use ExecContext and per-unit
 * directories, specifically .timer units with their timestamp touch file. */
static const char* const exec_resource_type_table[_EXEC_DIRECTORY_TYPE_MAX] = {
        [EXEC_DIRECTORY_RUNTIME]       = "runtime",
        [EXEC_DIRECTORY_STATE]         = "state",
        [EXEC_DIRECTORY_CACHE]         = "cache",
        [EXEC_DIRECTORY_LOGS]          = "logs",
        [EXEC_DIRECTORY_CONFIGURATION] = "configuration",
};

DEFINE_STRING_TABLE_LOOKUP(exec_resource_type, ExecDirectoryType);

static const char* const exec_keyring_mode_table[_EXEC_KEYRING_MODE_MAX] = {
        [EXEC_KEYRING_INHERIT] = "inherit",
        [EXEC_KEYRING_PRIVATE] = "private",
        [EXEC_KEYRING_SHARED]  = "shared",
};

DEFINE_STRING_TABLE_LOOKUP(exec_keyring_mode, ExecKeyringMode);

static const char* const memory_thp_table[_MEMORY_THP_MAX] = {
        [MEMORY_THP_INHERIT] = "inherit",
        [MEMORY_THP_DISABLE] = "disable",
        [MEMORY_THP_MADVISE] = "madvise",
        [MEMORY_THP_SYSTEM]  = "system",
};

DEFINE_STRING_TABLE_LOOKUP(memory_thp, MemoryTHP);
