/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct ExecStatus ExecStatus;
typedef struct ExecCommand ExecCommand;
typedef struct ExecContext ExecContext;
typedef struct ExecRuntime ExecRuntime;
typedef struct ExecParameters ExecParameters;
typedef struct Manager Manager;

#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/capability.h>

#include "cgroup-util.h"
#include "coredump-util.h"
#include "cpu-set-util.h"
#include "exec-util.h"
#include "fdset.h"
#include "list.h"
#include "missing_resource.h"
#include "namespace.h"
#include "nsflags.h"
#include "numa-util.h"
#include "path-util.h"
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

/* Contains start and exit information about an executed command.  */
struct ExecStatus {
        dual_timestamp start_timestamp;
        dual_timestamp exit_timestamp;
        pid_t pid;
        int code;     /* as in siginfo_t::si_code */
        int status;   /* as in siginfo_t::si_status */
};

/* Stores information about commands we execute. Covers both configuration settings as well as runtime data. */
struct ExecCommand {
        char *path;
        char **argv;
        ExecStatus exec_status;
        ExecCommandFlags flags;
        LIST_FIELDS(ExecCommand, command); /* useful for chaining commands */
};

/* Encapsulates certain aspects of the runtime environment that is to be shared between multiple otherwise separate
 * invocations of commands. Specifically, this allows sharing of /tmp and /var/tmp data as well as network namespaces
 * between invocations of commands. This is a reference counted object, with one reference taken by each currently
 * active command invocation that wants to share this runtime. */
struct ExecRuntime {
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
};

typedef enum ExecDirectoryType {
        EXEC_DIRECTORY_RUNTIME = 0,
        EXEC_DIRECTORY_STATE,
        EXEC_DIRECTORY_CACHE,
        EXEC_DIRECTORY_LOGS,
        EXEC_DIRECTORY_CONFIGURATION,
        _EXEC_DIRECTORY_TYPE_MAX,
        _EXEC_DIRECTORY_TYPE_INVALID = -EINVAL,
} ExecDirectoryType;

typedef struct ExecDirectoryItem {
        char *path;
        char **symlinks;
        bool only_create;
} ExecDirectoryItem;

typedef struct ExecDirectory {
        mode_t mode;
        size_t n_items;
        ExecDirectoryItem *items;
} ExecDirectory;

typedef enum ExecCleanMask {
        /* In case you wonder why the bitmask below doesn't use "directory" in its name: we want to keep this
         * generic so that .timer timestamp files can nicely be covered by this too, and similar. */
        EXEC_CLEAN_RUNTIME       = 1U << EXEC_DIRECTORY_RUNTIME,
        EXEC_CLEAN_STATE         = 1U << EXEC_DIRECTORY_STATE,
        EXEC_CLEAN_CACHE         = 1U << EXEC_DIRECTORY_CACHE,
        EXEC_CLEAN_LOGS          = 1U << EXEC_DIRECTORY_LOGS,
        EXEC_CLEAN_CONFIGURATION = 1U << EXEC_DIRECTORY_CONFIGURATION,
        EXEC_CLEAN_NONE          = 0,
        EXEC_CLEAN_ALL           = (1U << _EXEC_DIRECTORY_TYPE_MAX) - 1,
        _EXEC_CLEAN_MASK_INVALID = -EINVAL,
} ExecCleanMask;

/* A credential configured with LoadCredential= */
typedef struct ExecLoadCredential {
        char *id, *path;
        bool encrypted;
} ExecLoadCredential;

/* A credential configured with SetCredential= */
typedef struct ExecSetCredential {
        char *id;
        bool encrypted;
        void *data;
        size_t size;
} ExecSetCredential;

/* Encodes configuration parameters applied to invoked commands. Does not carry runtime data, but only configuration
 * changes sourced from unit files and suchlike. ExecContext objects are usually embedded into Unit objects, and do not
 * change after being loaded. */
struct ExecContext {
        char **environment;
        char **environment_files;
        char **pass_environment;
        char **unset_environment;

        struct rlimit *rlimit[_RLIMIT_MAX];
        char *working_directory, *root_directory, *root_image, *root_verity, *root_hash_path, *root_hash_sig_path;
        void *root_hash, *root_hash_sig;
        size_t root_hash_size, root_hash_sig_size;
        LIST_HEAD(MountOptions, root_image_options);
        bool working_directory_missing_ok:1;
        bool working_directory_home:1;

        bool oom_score_adjust_set:1;
        bool coredump_filter_set:1;
        bool nice_set:1;
        bool ioprio_set:1;
        bool cpu_sched_set:1;
        bool mount_apivfs_set:1;

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
        bool stdio_as_fds;
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
        unsigned long mount_flags;
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

        usec_t log_ratelimit_interval_usec;
        unsigned log_ratelimit_burst;

        int log_level_max;

        char *log_namespace;

        ProtectProc protect_proc;  /* hidepid= */
        ProcSubset proc_subset;    /* subset= */

        bool private_tmp;
        bool private_network;
        bool private_devices;
        bool private_users;
        bool private_mounts;
        bool private_ipc;
        bool protect_kernel_tunables;
        bool protect_kernel_modules;
        bool protect_kernel_logs;
        bool protect_clock;
        bool protect_control_groups;
        ProtectSystem protect_system;
        ProtectHome protect_home;
        bool protect_hostname;
        bool mount_apivfs;

        bool dynamic_user;
        bool remove_ipc;

        bool memory_deny_write_execute;
        bool restrict_realtime;
        bool restrict_suid_sgid;

        bool lock_personality;
        unsigned long personality;

        unsigned long restrict_namespaces; /* The CLONE_NEWxyz flags permitted to the unit's processes */

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

        char *network_namespace_path;
        char *ipc_namespace_path;

        ExecDirectory directories[_EXEC_DIRECTORY_TYPE_MAX];
        ExecPreserveMode runtime_directory_preserve_mode;
        usec_t timeout_clean_usec;

        Hashmap *set_credentials; /* output id → ExecSetCredential */
        Hashmap *load_credentials; /* output id → ExecLoadCredential */
};

static inline bool exec_context_restrict_namespaces_set(const ExecContext *c) {
        assert(c);

        return (c->restrict_namespaces & NAMESPACE_FLAGS_ALL) != NAMESPACE_FLAGS_ALL;
}

static inline bool exec_context_restrict_filesystems_set(const ExecContext *c) {
        assert(c);

        return c->restrict_filesystems_allow_list ||
          !set_isempty(c->restrict_filesystems);
}

static inline bool exec_context_with_rootfs(const ExecContext *c) {
        assert(c);

        /* Checks if RootDirectory= or RootImage= are used */

        return !empty_or_root(c->root_directory) || c->root_image;
}

typedef enum ExecFlags {
        EXEC_APPLY_SANDBOXING      = 1 << 0,
        EXEC_APPLY_CHROOT          = 1 << 1,
        EXEC_APPLY_TTY_STDIN       = 1 << 2,
        EXEC_PASS_LOG_UNIT         = 1 << 3, /* Whether to pass the unit name to the service's journal stream connection */
        EXEC_CHOWN_DIRECTORIES     = 1 << 4, /* chown() the runtime/state/cache/log directories to the user we run as, under all conditions */
        EXEC_NSS_DYNAMIC_BYPASS    = 1 << 5, /* Set the SYSTEMD_NSS_DYNAMIC_BYPASS environment variable, to disable nss-systemd blocking on PID 1, for use by dbus-daemon */
        EXEC_CGROUP_DELEGATE       = 1 << 6,
        EXEC_IS_CONTROL            = 1 << 7,
        EXEC_CONTROL_CGROUP        = 1 << 8, /* Place the process not in the indicated cgroup but in a subcgroup '/.control', but only EXEC_CGROUP_DELEGATE and EXEC_IS_CONTROL is set, too */
        EXEC_WRITE_CREDENTIALS     = 1 << 9, /* Set up the credential store logic */

        /* The following are not used by execute.c, but by consumers internally */
        EXEC_PASS_FDS              = 1 << 10,
        EXEC_SETENV_RESULT         = 1 << 11,
        EXEC_SET_WATCHDOG          = 1 << 12,
        EXEC_SETENV_MONITOR_RESULT = 1 << 13, /* Pass exit status to OnFailure= and OnSuccess= dependencies. */
} ExecFlags;

/* Parameters for a specific invocation of a command. This structure is put together right before a command is
 * executed. */
struct ExecParameters {
        char **environment;

        int *fds;
        char **fd_names;
        size_t n_socket_fds;
        size_t n_storage_fds;

        ExecFlags flags;
        bool selinux_context_net:1;

        CGroupMask cgroup_supported;
        const char *cgroup_path;

        char **prefix;
        const char *received_credentials_directory;
        const char *received_encrypted_credentials_directory;

        const char *confirm_spawn;

        usec_t watchdog_usec;

        int *idle_pipe;

        int stdin_fd;
        int stdout_fd;
        int stderr_fd;

        /* An fd that is closed by the execve(), and thus will result in EOF when the execve() is done */
        int exec_fd;

        const char *notify_socket;
};

#include "unit.h"
#include "dynamic-user.h"

int exec_spawn(Unit *unit,
               ExecCommand *command,
               const ExecContext *context,
               const ExecParameters *exec_params,
               ExecRuntime *runtime,
               DynamicCreds *dynamic_creds,
               pid_t *ret);

void exec_command_done_array(ExecCommand *c, size_t n);
ExecCommand* exec_command_free_list(ExecCommand *c);
void exec_command_free_array(ExecCommand **c, size_t n);
void exec_command_reset_status_array(ExecCommand *c, size_t n);
void exec_command_reset_status_list_array(ExecCommand **c, size_t n);
void exec_command_dump_list(ExecCommand *c, FILE *f, const char *prefix);
void exec_command_append_list(ExecCommand **l, ExecCommand *e);
int exec_command_set(ExecCommand *c, const char *path, ...) _sentinel_;
int exec_command_append(ExecCommand *c, const char *path, ...) _sentinel_;

void exec_context_init(ExecContext *c);
void exec_context_done(ExecContext *c);
void exec_context_dump(const ExecContext *c, FILE* f, const char *prefix);

int exec_context_destroy_runtime_directory(const ExecContext *c, const char *runtime_root);
int exec_context_destroy_credentials(const ExecContext *c, const char *runtime_root, const char *unit);

const char* exec_context_fdname(const ExecContext *c, int fd_index);

bool exec_context_may_touch_console(const ExecContext *c);
bool exec_context_maintains_privileges(const ExecContext *c);

int exec_context_get_effective_ioprio(const ExecContext *c);
bool exec_context_get_effective_mount_apivfs(const ExecContext *c);

void exec_context_free_log_extra_fields(ExecContext *c);

void exec_context_revert_tty(ExecContext *c);

int exec_context_get_clean_directories(ExecContext *c, char **prefix, ExecCleanMask mask, char ***ret);
int exec_context_get_clean_mask(ExecContext *c, ExecCleanMask *ret);

void exec_status_start(ExecStatus *s, pid_t pid);
void exec_status_exit(ExecStatus *s, const ExecContext *context, pid_t pid, int code, int status);
void exec_status_dump(const ExecStatus *s, FILE *f, const char *prefix);
void exec_status_reset(ExecStatus *s);

int exec_runtime_acquire(Manager *m, const ExecContext *c, const char *name, bool create, ExecRuntime **ret);
ExecRuntime *exec_runtime_unref(ExecRuntime *r, bool destroy);

int exec_runtime_serialize(const Manager *m, FILE *f, FDSet *fds);
int exec_runtime_deserialize_compat(Unit *u, const char *key, const char *value, FDSet *fds);
int exec_runtime_deserialize_one(Manager *m, const char *value, FDSet *fds);
void exec_runtime_vacuum(Manager *m);

void exec_params_clear(ExecParameters *p);

bool exec_context_get_cpu_affinity_from_numa(const ExecContext *c);

ExecSetCredential *exec_set_credential_free(ExecSetCredential *sc);
DEFINE_TRIVIAL_CLEANUP_FUNC(ExecSetCredential*, exec_set_credential_free);

ExecLoadCredential *exec_load_credential_free(ExecLoadCredential *lc);
DEFINE_TRIVIAL_CLEANUP_FUNC(ExecLoadCredential*, exec_load_credential_free);

void exec_directory_done(ExecDirectory *d);
int exec_directory_add(ExecDirectory *d, const char *path, const char *symlink);
void exec_directory_sort(ExecDirectory *d);

extern const struct hash_ops exec_set_credential_hash_ops;
extern const struct hash_ops exec_load_credential_hash_ops;

const char* exec_output_to_string(ExecOutput i) _const_;
ExecOutput exec_output_from_string(const char *s) _pure_;

const char* exec_input_to_string(ExecInput i) _const_;
ExecInput exec_input_from_string(const char *s) _pure_;

const char* exec_utmp_mode_to_string(ExecUtmpMode i) _const_;
ExecUtmpMode exec_utmp_mode_from_string(const char *s) _pure_;

const char* exec_preserve_mode_to_string(ExecPreserveMode i) _const_;
ExecPreserveMode exec_preserve_mode_from_string(const char *s) _pure_;

const char* exec_keyring_mode_to_string(ExecKeyringMode i) _const_;
ExecKeyringMode exec_keyring_mode_from_string(const char *s) _pure_;

const char* exec_directory_type_to_string(ExecDirectoryType i) _const_;
ExecDirectoryType exec_directory_type_from_string(const char *s) _pure_;

const char* exec_directory_type_symlink_to_string(ExecDirectoryType i) _const_;
ExecDirectoryType exec_directory_type_symlink_from_string(const char *s) _pure_;

const char* exec_resource_type_to_string(ExecDirectoryType i) _const_;
ExecDirectoryType exec_resource_type_from_string(const char *s) _pure_;

bool exec_needs_mount_namespace(const ExecContext *context, const ExecParameters *params, const ExecRuntime *runtime);
