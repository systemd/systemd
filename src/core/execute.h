/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "sd-id128.h"

#include "bus-unit-util.h"
#include "core-forward.h"
#include "cpu-set-util.h"
#include "exec-util.h"
#include "list.h"
#include "log-context.h"
#include "namespace.h"
#include "numa-util.h"
#include "ratelimit.h"
#include "rlimit-util.h"
#include "time-util.h"

#define EXEC_STDIN_DATA_MAX (64U*1024U*1024U)

typedef enum ExecUtmpMode {
        EXEC_UTMP_INIT,
        EXEC_UTMP_LOGIN,
        EXEC_UTMP_USER,
        _EXEC_UTMP_MODE_MAX,
        _EXEC_UTMP_MODE_INVALID = -EINVAL,
} ExecUtmpMode;

typedef enum ExecInput {
        EXEC_INPUT_NULL,
        EXEC_INPUT_TTY,
        EXEC_INPUT_TTY_FORCE,
        EXEC_INPUT_TTY_FAIL,
        EXEC_INPUT_SOCKET,
        EXEC_INPUT_NAMED_FD,
        EXEC_INPUT_DATA,
        EXEC_INPUT_FILE,
        _EXEC_INPUT_MAX,
        _EXEC_INPUT_INVALID = -EINVAL,
} ExecInput;

typedef enum ExecOutput {
        EXEC_OUTPUT_INHERIT,
        EXEC_OUTPUT_NULL,
        EXEC_OUTPUT_TTY,
        EXEC_OUTPUT_KMSG,
        EXEC_OUTPUT_KMSG_AND_CONSOLE,
        EXEC_OUTPUT_JOURNAL,
        EXEC_OUTPUT_JOURNAL_AND_CONSOLE,
        EXEC_OUTPUT_SOCKET,
        EXEC_OUTPUT_NAMED_FD,
        EXEC_OUTPUT_FILE,
        EXEC_OUTPUT_FILE_APPEND,
        EXEC_OUTPUT_FILE_TRUNCATE,
        _EXEC_OUTPUT_MAX,
        _EXEC_OUTPUT_INVALID = -EINVAL,
} ExecOutput;

typedef enum ExecPreserveMode {
        EXEC_PRESERVE_NO,
        EXEC_PRESERVE_YES,
        EXEC_PRESERVE_RESTART,
        _EXEC_PRESERVE_MODE_MAX,
        _EXEC_PRESERVE_MODE_INVALID = -EINVAL,
} ExecPreserveMode;

typedef enum ExecKeyringMode {
        EXEC_KEYRING_INHERIT,
        EXEC_KEYRING_PRIVATE,
        EXEC_KEYRING_SHARED,
        _EXEC_KEYRING_MODE_MAX,
        _EXEC_KEYRING_MODE_INVALID = -EINVAL,
} ExecKeyringMode;

typedef enum MemoryTHP {
        /*
         * Inherit default from process that starts systemd, i.e. do not make
         * any PR_SET_THP_DISABLE call.
         */
        MEMORY_THP_INHERIT,
        MEMORY_THP_DISABLE, /* Disable THPs completely for the process */
        MEMORY_THP_MADVISE, /* Disable THPs for the process except when madvised */
        /*
         * Use system default THP setting. this can be used when the process that
         * starts systemd has already disabled THPs via PR_SET_THP_DISABLE, and we
         * want to restore the system default THP setting at process invocation time.
         */
        MEMORY_THP_SYSTEM,
        _MEMORY_THP_MAX,
        _MEMORY_THP_INVALID = -EINVAL,
} MemoryTHP;

/* Contains start and exit information about an executed command.  */
typedef struct ExecStatus {
        dual_timestamp start_timestamp;
        dual_timestamp exit_timestamp;
        dual_timestamp handoff_timestamp;
        pid_t pid;
        int code;     /* as in siginfo_t::si_code */
        int status;   /* as in siginfo_t::si_status */
} ExecStatus;

/* Stores information about commands we execute. Covers both configuration settings as well as runtime data. */
typedef struct ExecCommand {
        char *path;
        char **argv;
        ExecStatus exec_status; /* Note that this is not serialized to sd-executor */
        ExecCommandFlags flags;
        LIST_FIELDS(ExecCommand, command); /* useful for chaining commands */
} ExecCommand;

/* Encapsulates certain aspects of the runtime environment that is to be shared between multiple otherwise separate
 * invocations of commands. Specifically, this allows sharing of /tmp and /var/tmp data as well as network namespaces
 * between invocations of commands. This is a reference counted object, with one reference taken by each currently
 * active command invocation that wants to share this runtime. */
typedef struct ExecSharedRuntime {
        unsigned n_ref;

        Manager *manager;

        char *id; /* Unit id of the owner */

        char *tmp_dir;
        char *var_tmp_dir;

        /* An AF_UNIX socket pair, that contains a datagram containing a file descriptor referring to the network
         * namespace. */
        int netns_storage_socket[2];

        /* Like netns_storage_socket, but the file descriptor is referring to the IPC namespace. */
        int ipcns_storage_socket[2];

        /* Like netns_storage_socket, but the file descriptor is referring to the user namespace. */
        int userns_storage_socket[2];
} ExecSharedRuntime;

typedef struct ExecRuntime {
        ExecSharedRuntime *shared;
        DynamicCreds *dynamic_creds;

        /* The path to the ephemeral snapshot of the root directory or root image if one was requested. */
        char *ephemeral_copy;

        /* An AF_UNIX socket pair that receives the locked file descriptor referring to the ephemeral copy of
         * the root directory or root image. The lock prevents tmpfiles from removing the ephemeral snapshot
         * until we're done using it. */
        int ephemeral_storage_socket[2];
} ExecRuntime;

static inline bool EXEC_DIRECTORY_TYPE_SHALL_CHOWN(ExecDirectoryType t) {
        /* Returns true for the ExecDirectoryTypes that we shall chown()ing for the user to. We do this for
         * all of them, except for configuration */
        return t >= 0 && t < _EXEC_DIRECTORY_TYPE_MAX && t != EXEC_DIRECTORY_CONFIGURATION;
}

typedef struct QuotaLimit {
        uint64_t quota_absolute; /* absolute quota in bytes; if UINT64_MAX relative quota configured, see below */
        uint32_t quota_scale;    /* relative quota to backend size, scaled to 0…UINT32_MAX */
        bool quota_enforce;
        bool quota_accounting;
} QuotaLimit;

typedef struct ExecDirectoryItem {
        char *path;
        char **symlinks;
        ExecDirectoryFlags flags;
        bool idmapped;
} ExecDirectoryItem;

typedef struct ExecDirectory {
        mode_t mode;
        size_t n_items;
        ExecDirectoryItem *items;
        QuotaLimit exec_quota;
} ExecDirectory;

typedef enum ExecCleanMask {
        /* In case you wonder why the bitmask below doesn't use "directory" in its name: we want to keep this
         * generic so that .timer timestamp files can nicely be covered by this too, and similar. */
        EXEC_CLEAN_RUNTIME       = 1U << EXEC_DIRECTORY_RUNTIME,
        EXEC_CLEAN_STATE         = 1U << EXEC_DIRECTORY_STATE,
        EXEC_CLEAN_CACHE         = 1U << EXEC_DIRECTORY_CACHE,
        EXEC_CLEAN_LOGS          = 1U << EXEC_DIRECTORY_LOGS,
        EXEC_CLEAN_CONFIGURATION = 1U << EXEC_DIRECTORY_CONFIGURATION,
        EXEC_CLEAN_FDSTORE       = 1U << _EXEC_DIRECTORY_TYPE_MAX,
        EXEC_CLEAN_NONE          = 0,
        EXEC_CLEAN_ALL           = (1U << (_EXEC_DIRECTORY_TYPE_MAX+1)) - 1,
        _EXEC_CLEAN_MASK_INVALID = -EINVAL,
} ExecCleanMask;

/* Encodes configuration parameters applied to invoked commands. Does not carry runtime data, but only configuration
 * changes sourced from unit files and suchlike. ExecContext objects are usually embedded into Unit objects, and do not
 * change after being loaded. */
typedef struct ExecContext {
        char **environment;
        char **environment_files;
        char **pass_environment;
        char **unset_environment;

        struct rlimit *rlimit[_RLIMIT_MAX];
        char *working_directory, *root_directory, *root_image, *root_verity, *root_hash_path, *root_hash_sig_path;
        struct iovec root_hash, root_hash_sig;
        MountOptions *root_image_options;
        bool root_ephemeral;
        bool working_directory_missing_ok:1;
        bool working_directory_home:1;

        bool oom_score_adjust_set:1;
        bool coredump_filter_set:1;
        bool nice_set:1;
        bool ioprio_is_set:1;
        bool cpu_sched_set:1;

        /* This is not exposed to the user but available internally. We need it to make sure that whenever we
         * spawn /usr/bin/mount it is run in the same process group as us so that the autofs logic detects
         * that it belongs to us and we don't enter a trigger loop. */
        bool same_pgrp;

        bool cpu_sched_reset_on_fork;
        bool non_blocking;

        mode_t umask;
        int oom_score_adjust;
        int nice;
        int ioprio;
        int cpu_sched_policy;
        int cpu_sched_priority;
        uint64_t coredump_filter;

        CPUSet cpu_set;
        NUMAPolicy numa_policy;
        bool cpu_affinity_from_numa;

        ExecInput std_input;
        ExecOutput std_output;
        ExecOutput std_error;

        /* At least one of stdin/stdout/stderr was initialized from an fd passed in. This boolean survives
         * the fds being closed. This only makes sense for transient units. */
        bool stdio_as_fds;
        bool root_directory_as_fd;

        char *stdio_fdname[3];
        char *stdio_file[3];

        void *stdin_data;
        size_t stdin_data_size;

        nsec_t timer_slack_nsec;

        char *tty_path;

        bool tty_reset;
        bool tty_vhangup;
        bool tty_vt_disallocate;

        unsigned tty_rows;
        unsigned tty_cols;

        bool ignore_sigpipe;

        ExecKeyringMode keyring_mode;

        /* Since resolving these names might involve socket
         * connections and we don't want to deadlock ourselves these
         * names are resolved on execution only and in the child
         * process. */
        char *user;
        char *group;
        char **supplementary_groups;

        int set_login_environment;

        char *pam_name;

        char *utmp_id;
        ExecUtmpMode utmp_mode;

        bool no_new_privileges;

        bool selinux_context_ignore;
        bool apparmor_profile_ignore;
        bool smack_process_label_ignore;

        char *selinux_context;
        char *apparmor_profile;
        char *smack_process_label;

        char **read_write_paths, **read_only_paths, **inaccessible_paths, **exec_paths, **no_exec_paths;
        char **exec_search_path;
        unsigned long mount_propagation_flag;
        BindMount *bind_mounts;
        size_t n_bind_mounts;
        TemporaryFileSystem *temporary_filesystems;
        size_t n_temporary_filesystems;
        MountImage *mount_images;
        size_t n_mount_images;
        MountImage *extension_images;
        size_t n_extension_images;
        char **extension_directories;

        uint64_t capability_bounding_set;
        uint64_t capability_ambient_set;
        int secure_bits;

        int syslog_priority;
        bool syslog_level_prefix;
        char *syslog_identifier;

        struct iovec* log_extra_fields;
        size_t n_log_extra_fields;
        Set *log_filter_allowed_patterns;
        Set *log_filter_denied_patterns;

        RateLimit log_ratelimit;

        int log_level_max;

        char *log_namespace;

        ProtectProc protect_proc;  /* hidepid= */
        ProcSubset proc_subset;    /* subset= */

        PrivateBPF private_bpf;
        uint64_t bpf_delegate_commands, bpf_delegate_maps, bpf_delegate_programs, bpf_delegate_attachments;

        int private_mounts;
        int mount_apivfs;
        int bind_log_sockets;
        int memory_ksm;
        MemoryTHP memory_thp;
        PrivateTmp private_tmp;
        PrivateTmp private_var_tmp; /* This is not an independent parameter, but calculated from other
                                     * parameters in unit_patch_contexts(). */
        bool private_network;
        bool private_devices;
        PrivateUsers private_users;
        bool private_ipc;
        bool protect_kernel_tunables;
        bool protect_kernel_modules;
        bool protect_kernel_logs;
        bool protect_clock;
        ProtectControlGroups protect_control_groups;
        ProtectSystem protect_system;
        ProtectHome protect_home;
        PrivatePIDs private_pids;
        ProtectHostname protect_hostname;
        char *private_hostname;

        bool dynamic_user;
        bool remove_ipc;

        bool memory_deny_write_execute;
        bool restrict_realtime;
        bool restrict_suid_sgid;

        bool lock_personality;
        unsigned long personality;

        unsigned long restrict_namespaces; /* The CLONE_NEWxyz flags permitted to the unit's processes */
        unsigned long delegate_namespaces; /* The CLONE_NEWxyz flags delegated to the unit's processes */

        Set *restrict_filesystems;
        bool restrict_filesystems_allow_list:1;

        Hashmap *syscall_filter;
        Set *syscall_archs;
        int syscall_errno;
        bool syscall_allow_list:1;

        Hashmap *syscall_log;
        bool syscall_log_allow_list:1; /* Log listed system calls */

        bool address_families_allow_list:1;
        Set *address_families;

        char *user_namespace_path;
        char *network_namespace_path;
        char *ipc_namespace_path;

        ExecDirectory directories[_EXEC_DIRECTORY_TYPE_MAX];
        ExecPreserveMode runtime_directory_preserve_mode;
        usec_t timeout_clean_usec;

        Hashmap *set_credentials; /* output id → ExecSetCredential */
        Hashmap *load_credentials; /* output id → ExecLoadCredential */
        OrderedSet *import_credentials; /* ExecImportCredential */

        ImagePolicy *root_image_policy, *mount_image_policy, *extension_image_policy;
} ExecContext;

typedef enum ExecFlags {
        EXEC_APPLY_SANDBOXING        = 1 << 0,
        EXEC_APPLY_CHROOT            = 1 << 1,
        EXEC_APPLY_TTY_STDIN         = 1 << 2,
        EXEC_PASS_LOG_UNIT           = 1 << 3,  /* Whether to pass the unit name to the service's journal stream connection */
        EXEC_CHOWN_DIRECTORIES       = 1 << 4,  /* chown() the runtime/state/cache/log directories to the user we run as, under all conditions */
        EXEC_NSS_DYNAMIC_BYPASS      = 1 << 5,  /* Set the SYSTEMD_NSS_DYNAMIC_BYPASS environment variable, to disable nss-systemd blocking on PID 1, for use by dbus-daemon */
        EXEC_CGROUP_DELEGATE         = 1 << 6,
        EXEC_IS_CONTROL              = 1 << 7,
        EXEC_CONTROL_CGROUP          = 1 << 8,  /* Place the process not in the indicated cgroup but in a subcgroup '/.control', but only EXEC_CGROUP_DELEGATE and EXEC_IS_CONTROL is set, too */
        EXEC_SETUP_CREDENTIALS       = 1 << 9,  /* Set up the credential store logic */
        EXEC_SETUP_CREDENTIALS_FRESH = 1 << 10, /* Set up a new credential store (disable reuse) */

        /* The following are not used by execute.c, but by consumers internally */
        EXEC_PASS_FDS                = 1 << 11,
        EXEC_SETENV_RESULT           = 1 << 12,
        EXEC_SET_WATCHDOG            = 1 << 13,
        EXEC_SETENV_MONITOR_RESULT   = 1 << 14, /* Pass exit status to OnFailure= and OnSuccess= dependencies. */
} ExecFlags;

/* Parameters for a specific invocation of a command. This structure is put together right before a command is
 * executed. */
typedef struct ExecParameters {
        RuntimeScope runtime_scope;

        ExecFlags flags;

        char **environment;
        char **files_env;

        int *fds;
        char **fd_names;
        size_t n_socket_fds;
        size_t n_stashed_fds;

        char *cgroup_path;
        uint64_t cgroup_id;

        char **prefix;
        char *received_credentials_directory;
        char *received_encrypted_credentials_directory;

        char *confirm_spawn;
        bool shall_confirm_spawn;

        usec_t watchdog_usec;

        int *idle_pipe;

        int stdin_fd;
        int stdout_fd;
        int stderr_fd;
        int root_directory_fd;

        /* An fd that is closed by the execve(), and thus will result in EOF when the execve() is done. */
        int exec_fd;

        char *notify_socket;

        LIST_HEAD(OpenFile, open_files);

        char *fallback_smack_process_label;

        int user_lookup_fd;
        int handoff_timestamp_fd;
        int pidref_transport_fd;

        int bpf_restrict_fs_map_fd;

        /* Used for logging in the executor functions */
        char *unit_id;
        sd_id128_t invocation_id;
        char invocation_id_string[SD_ID128_STRING_MAX];

        bool debug_invocation;
        bool selinux_context_net;
} ExecParameters;

#define EXEC_PARAMETERS_INIT(_flags)              \
        (ExecParameters) {                        \
                .flags = (_flags),                \
                .stdin_fd               = -EBADF, \
                .stdout_fd              = -EBADF, \
                .stderr_fd              = -EBADF, \
                .root_directory_fd      = -EBADF, \
                .exec_fd                = -EBADF, \
                .bpf_restrict_fs_map_fd = -EBADF, \
                .user_lookup_fd         = -EBADF, \
                .handoff_timestamp_fd   = -EBADF, \
                .pidref_transport_fd    = -EBADF, \
        }

static inline bool exec_input_is_terminal(ExecInput i) {
        return IN_SET(i,
                      EXEC_INPUT_TTY,
                      EXEC_INPUT_TTY_FORCE,
                      EXEC_INPUT_TTY_FAIL);
}

static inline bool exec_context_has_tty(const ExecContext *context) {
        assert(context);

        return
                context->tty_path ||
                exec_input_is_terminal(context->std_input) ||
                context->std_output == EXEC_OUTPUT_TTY ||
                context->std_error == EXEC_OUTPUT_TTY;
}

static inline bool exec_input_is_inheritable(ExecInput i) {
        /* We assume these listed inputs refer to bidirectional streams, and hence duplicating them from
         * stdin to stdout/stderr makes sense and hence allowing EXEC_OUTPUT_INHERIT makes sense, too.
         * Outputs such as regular files or sealed data memfds otoh don't really make sense to be
         * duplicated for both input and output at the same time (since they then would cause a feedback
         * loop). */

        return exec_input_is_terminal(i) || IN_SET(i, EXEC_INPUT_SOCKET, EXEC_INPUT_NAMED_FD);
}

int exec_spawn(
                Unit *unit,
                ExecCommand *command,
                const ExecContext *context,
                ExecParameters *exec_params,
                ExecRuntime *runtime,
                const CGroupContext *cgroup_context,
                PidRef *ret);

void exec_command_done(ExecCommand *c);
void exec_command_done_array(ExecCommand *c, size_t n);
ExecCommand* exec_command_free(ExecCommand *c);
DEFINE_TRIVIAL_CLEANUP_FUNC(ExecCommand*, exec_command_free);
ExecCommand* exec_command_free_list(ExecCommand *c);
void exec_command_free_array(ExecCommand **c, size_t n);
void exec_command_reset_status_array(ExecCommand *c, size_t n);
void exec_command_reset_status_list_array(ExecCommand **c, size_t n);

void exec_command_dump(ExecCommand *c, FILE *f, const char *prefix);
void exec_command_dump_list(ExecCommand *c, FILE *f, const char *prefix);
void exec_command_append_list(ExecCommand **l, ExecCommand *e);
int exec_command_set(ExecCommand *c, const char *path, ...) _sentinel_;
int exec_command_append(ExecCommand *c, const char *path, ...) _sentinel_;

void exec_context_init(ExecContext *c);
void exec_context_done(ExecContext *c);
void exec_context_dump(const ExecContext *c, FILE* f, const char *prefix);

int exec_context_destroy_runtime_directory(const ExecContext *c, const char *runtime_prefix);
int exec_context_destroy_mount_ns_dir(Unit *u);

const char* exec_context_fdname(const ExecContext *c, int fd_index) _pure_;

bool exec_context_may_touch_console(const ExecContext *c);
bool exec_context_maintains_privileges(const ExecContext *c);
bool exec_context_shall_ansi_seq_reset(const ExecContext *c);

int exec_context_get_effective_ioprio(const ExecContext *c);
bool exec_context_get_effective_mount_apivfs(const ExecContext *c);
bool exec_context_get_effective_bind_log_sockets(const ExecContext *c);

void exec_context_free_log_extra_fields(ExecContext *c);

void exec_context_revert_tty(ExecContext *c, sd_id128_t invocation_id);

int exec_context_get_clean_directories(ExecContext *c, char **prefix, ExecCleanMask mask, char ***ret);
int exec_context_get_clean_mask(ExecContext *c, ExecCleanMask *ret);

const char* exec_context_tty_path(const ExecContext *context);
int exec_context_apply_tty_size(const ExecContext *context, int input_fd, int output_fd, const char *tty_path);
void exec_context_tty_reset(const ExecContext *context, const ExecParameters *parameters, sd_id128_t invocation_id);

uint64_t exec_context_get_rlimit(const ExecContext *c, const char *name);
int exec_context_get_oom_score_adjust(const ExecContext *c);
uint64_t exec_context_get_coredump_filter(const ExecContext *c);
int exec_context_get_nice(const ExecContext *c);
int exec_context_get_cpu_sched_policy(const ExecContext *c);
int exec_context_get_cpu_sched_priority(const ExecContext *c);
uint64_t exec_context_get_timer_slack_nsec(const ExecContext *c);
bool exec_context_get_set_login_environment(const ExecContext *c);
char** exec_context_get_syscall_filter(const ExecContext *c);
char** exec_context_get_syscall_archs(const ExecContext *c);
char** exec_context_get_syscall_log(const ExecContext *c);
char** exec_context_get_address_families(const ExecContext *c);
char** exec_context_get_restrict_filesystems(const ExecContext *c);
bool exec_context_restrict_namespaces_set(const ExecContext *c);
bool exec_context_restrict_filesystems_set(const ExecContext *c);
bool exec_context_with_rootfs(const ExecContext *c);
bool exec_context_with_rootfs_strict(const ExecContext *c);

int exec_context_has_vpicked_extensions(const ExecContext *context);

void exec_status_start(ExecStatus *s, pid_t pid, const dual_timestamp *ts);
void exec_status_exit(ExecStatus *s, const ExecContext *context, pid_t pid, int code, int status);
void exec_status_handoff(ExecStatus *s, const struct ucred *ucred, const dual_timestamp *ts);
void exec_status_dump(const ExecStatus *s, FILE *f, const char *prefix);
void exec_status_reset(ExecStatus *s);

int exec_shared_runtime_acquire(Manager *m, const ExecContext *c, const char *id, bool create, ExecSharedRuntime **ret);
ExecSharedRuntime *exec_shared_runtime_destroy(ExecSharedRuntime *r);
DECLARE_TRIVIAL_UNREF_FUNC(ExecSharedRuntime, exec_shared_runtime);
DEFINE_TRIVIAL_CLEANUP_FUNC(ExecSharedRuntime*, exec_shared_runtime_unref);

int exec_shared_runtime_serialize(const Manager *m, FILE *f, FDSet *fds);
int exec_shared_runtime_deserialize_compat(Unit *u, const char *key, const char *value, FDSet *fds);
int exec_shared_runtime_deserialize_one(Manager *m, const char *value, FDSet *fds);
void exec_shared_runtime_done(ExecSharedRuntime *rt);
void exec_shared_runtime_vacuum(Manager *m);

int exec_runtime_make(const Unit *unit, const ExecContext *context, ExecSharedRuntime *shared, DynamicCreds *creds, ExecRuntime **ret);
ExecRuntime* exec_runtime_free(ExecRuntime *rt);
DEFINE_TRIVIAL_CLEANUP_FUNC(ExecRuntime*, exec_runtime_free);
ExecRuntime* exec_runtime_destroy(ExecRuntime *rt);
void exec_runtime_clear(ExecRuntime *rt);

int exec_params_needs_control_subcgroup(const ExecParameters *params);
int exec_params_get_cgroup_path(const ExecParameters *params, const CGroupContext *c, const char *prefix, char **ret);
void exec_params_shallow_clear(ExecParameters *p);
void exec_params_deep_clear(ExecParameters *p);
void exec_params_dump(const ExecParameters *p, FILE* f, const char *prefix);

bool exec_context_get_cpu_affinity_from_numa(const ExecContext *c);

void exec_directory_done(ExecDirectory *d);
int exec_directory_add(ExecDirectory *d, const char *path, const char *symlink, ExecDirectoryFlags flags);
void exec_directory_sort(ExecDirectory *d);
bool exec_directory_is_private(const ExecContext *context, ExecDirectoryType type);

DECLARE_STRING_TABLE_LOOKUP_FROM_STRING(exec_clean_mask, ExecCleanMask);

DECLARE_STRING_TABLE_LOOKUP(exec_input, ExecInput);
DECLARE_STRING_TABLE_LOOKUP(exec_output, ExecOutput);

DECLARE_STRING_TABLE_LOOKUP(exec_utmp_mode, ExecUtmpMode);

DECLARE_STRING_TABLE_LOOKUP(exec_preserve_mode, ExecPreserveMode);

DECLARE_STRING_TABLE_LOOKUP(exec_keyring_mode, ExecKeyringMode);

DECLARE_STRING_TABLE_LOOKUP(exec_directory_type_symlink, ExecDirectoryType);
DECLARE_STRING_TABLE_LOOKUP(exec_directory_type_mode, ExecDirectoryType);

DECLARE_STRING_TABLE_LOOKUP(exec_resource_type, ExecDirectoryType);

DECLARE_STRING_TABLE_LOOKUP(memory_thp, MemoryTHP);

bool exec_needs_mount_namespace(const ExecContext *context, const ExecParameters *params, const ExecRuntime *runtime);
bool exec_needs_network_namespace(const ExecContext *context);
bool exec_needs_ipc_namespace(const ExecContext *context);
bool exec_needs_pid_namespace(const ExecContext *context, const ExecParameters *params);

ProtectControlGroups exec_get_protect_control_groups(const ExecContext *context);
bool exec_needs_cgroup_namespace(const ExecContext *context);
bool exec_needs_cgroup_mount(const ExecContext *context);
bool exec_is_cgroup_mount_read_only(const ExecContext *context);

const char* exec_get_private_notify_socket_path(const ExecContext *context, const ExecParameters *params, bool needs_sandboxing);

int exec_log_level_max_with_exec_params(const ExecContext *context, const ExecParameters *params);
int exec_log_level_max(const ExecContext *context);

/* These logging macros do the same logging as those in unit.h, but using ExecContext and ExecParameters
 * instead of the unit object, so that it can be used in the sd-executor context (where the unit object is
 * not available). */

#define LOG_EXEC_ID_FIELD(ep) \
        ((ep)->runtime_scope == RUNTIME_SCOPE_USER ? "USER_UNIT=" : "UNIT=")
#define LOG_EXEC_INVOCATION_ID_FIELD(ep) \
        ((ep)->runtime_scope == RUNTIME_SCOPE_USER ? "USER_INVOCATION_ID=" : "INVOCATION_ID=")

/* Like LOG_MESSAGE(), but with the unit name prefixed. */
#define LOG_EXEC_MESSAGE(ep, fmt, ...) LOG_MESSAGE("%s: " fmt, (ep)->unit_id, ##__VA_ARGS__)
#define LOG_EXEC_ID(ep) LOG_ITEM("%s%s", LOG_EXEC_ID_FIELD(ep), (ep)->unit_id)
#define LOG_EXEC_INVOCATION_ID(ep) LOG_ITEM("%s%s", LOG_EXEC_INVOCATION_ID_FIELD(ep), (ep)->invocation_id_string)

#define _LOG_CONTEXT_PUSH_EXEC(ec, ep, p, c)                                                       \
        const ExecContext *c = (ec);                                                               \
        const ExecParameters *p = (ep);                                                            \
        LOG_CONTEXT_PUSH_KEY_VALUE(LOG_EXEC_ID_FIELD(p), p->unit_id);                              \
        LOG_CONTEXT_PUSH_KEY_VALUE(LOG_EXEC_INVOCATION_ID_FIELD(p), p->invocation_id_string);      \
        LOG_CONTEXT_PUSH_IOV(c->log_extra_fields, c->n_log_extra_fields)                           \
        LOG_CONTEXT_SET_LOG_LEVEL(exec_log_level_max_with_exec_params(c, p))                       \
        LOG_SET_PREFIX(p->unit_id);

#define LOG_CONTEXT_PUSH_EXEC(ec, ep) \
        _LOG_CONTEXT_PUSH_EXEC(ec, ep, UNIQ_T(p, UNIQ), UNIQ_T(c, UNIQ))
