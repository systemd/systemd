/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* An enum of well known cgroup controllers */
typedef enum CGroupController {
        /* Original cgroup controllers */
        CGROUP_CONTROLLER_CPU,
        CGROUP_CONTROLLER_CPUACCT,    /* v1 only */
        CGROUP_CONTROLLER_CPUSET,     /* v2 only */
        CGROUP_CONTROLLER_IO,         /* v2 only */
        CGROUP_CONTROLLER_BLKIO,      /* v1 only */
        CGROUP_CONTROLLER_MEMORY,
        CGROUP_CONTROLLER_DEVICES,    /* v1 only */
        CGROUP_CONTROLLER_PIDS,

        /* BPF-based pseudo-controllers, v2 only */
        CGROUP_CONTROLLER_BPF_FIREWALL,
        CGROUP_CONTROLLER_BPF_DEVICES,
        CGROUP_CONTROLLER_BPF_FOREIGN,
        CGROUP_CONTROLLER_BPF_SOCKET_BIND,
        CGROUP_CONTROLLER_BPF_RESTRICT_NETWORK_INTERFACES,
        /* The BPF hook implementing RestrictFileSystems= is not defined here.
         * It's applied as late as possible in exec_invoke() so we don't block
         * our own unit setup code. */

        _CGROUP_CONTROLLER_MAX,
        _CGROUP_CONTROLLER_INVALID = -EINVAL,
} CGroupController;

#define CGROUP_CONTROLLER_TO_MASK(c) (1U << (c))

/* A bit mask of well known cgroup controllers */
typedef enum CGroupMask {
        CGROUP_MASK_CPU = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_CPU),
        CGROUP_MASK_CPUACCT = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_CPUACCT),
        CGROUP_MASK_CPUSET = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_CPUSET),
        CGROUP_MASK_IO = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_IO),
        CGROUP_MASK_BLKIO = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_BLKIO),
        CGROUP_MASK_MEMORY = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_MEMORY),
        CGROUP_MASK_DEVICES = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_DEVICES),
        CGROUP_MASK_PIDS = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_PIDS),
        CGROUP_MASK_BPF_FIREWALL = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_BPF_FIREWALL),
        CGROUP_MASK_BPF_DEVICES = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_BPF_DEVICES),
        CGROUP_MASK_BPF_FOREIGN = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_BPF_FOREIGN),
        CGROUP_MASK_BPF_SOCKET_BIND = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_BPF_SOCKET_BIND),
        CGROUP_MASK_BPF_RESTRICT_NETWORK_INTERFACES = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_BPF_RESTRICT_NETWORK_INTERFACES),

        /* All real cgroup v1 controllers */
        CGROUP_MASK_V1 = CGROUP_MASK_CPU|CGROUP_MASK_CPUACCT|CGROUP_MASK_BLKIO|CGROUP_MASK_MEMORY|CGROUP_MASK_DEVICES|CGROUP_MASK_PIDS,

        /* All real cgroup v2 controllers */
        CGROUP_MASK_V2 = CGROUP_MASK_CPU|CGROUP_MASK_CPUSET|CGROUP_MASK_IO|CGROUP_MASK_MEMORY|CGROUP_MASK_PIDS,

        /* All controllers we want to delegate in case of Delegate=yes. Which are pretty much the v2 controllers only, as delegation on v1 is not safe, and bpf stuff isn't a real controller */
        CGROUP_MASK_DELEGATE = CGROUP_MASK_V2,

        /* All cgroup v2 BPF pseudo-controllers */
        CGROUP_MASK_BPF = CGROUP_MASK_BPF_FIREWALL|CGROUP_MASK_BPF_DEVICES|CGROUP_MASK_BPF_FOREIGN|CGROUP_MASK_BPF_SOCKET_BIND|CGROUP_MASK_BPF_RESTRICT_NETWORK_INTERFACES,

        _CGROUP_MASK_ALL = CGROUP_CONTROLLER_TO_MASK(_CGROUP_CONTROLLER_MAX) - 1,
} CGroupMask;

/* Special values for all weight knobs on unified hierarchy */
#define CGROUP_WEIGHT_INVALID UINT64_MAX
#define CGROUP_WEIGHT_IDLE UINT64_C(0)
#define CGROUP_WEIGHT_MIN UINT64_C(1)
#define CGROUP_WEIGHT_MAX UINT64_C(10000)
#define CGROUP_WEIGHT_DEFAULT UINT64_C(100)

#define CGROUP_LIMIT_MIN UINT64_C(0)
#define CGROUP_LIMIT_MAX UINT64_MAX

static inline bool CGROUP_WEIGHT_IS_OK(uint64_t x) {
        return
            x == CGROUP_WEIGHT_INVALID ||
            (x >= CGROUP_WEIGHT_MIN && x <= CGROUP_WEIGHT_MAX);
}

/* IO limits on unified hierarchy */
typedef enum CGroupIOLimitType {
        CGROUP_IO_RBPS_MAX,
        CGROUP_IO_WBPS_MAX,
        CGROUP_IO_RIOPS_MAX,
        CGROUP_IO_WIOPS_MAX,

        _CGROUP_IO_LIMIT_TYPE_MAX,
        _CGROUP_IO_LIMIT_TYPE_INVALID = -EINVAL,
} CGroupIOLimitType;

extern const uint64_t cgroup_io_limit_defaults[_CGROUP_IO_LIMIT_TYPE_MAX];

const char* cgroup_io_limit_type_to_string(CGroupIOLimitType t) _const_;
CGroupIOLimitType cgroup_io_limit_type_from_string(const char *s) _pure_;
void cgroup_io_limits_list(void);

/* Special values for the io.bfq.weight attribute */
#define CGROUP_BFQ_WEIGHT_INVALID UINT64_MAX
#define CGROUP_BFQ_WEIGHT_MIN UINT64_C(1)
#define CGROUP_BFQ_WEIGHT_MAX UINT64_C(1000)
#define CGROUP_BFQ_WEIGHT_DEFAULT UINT64_C(100)

/* Convert the normal io.weight value to io.bfq.weight */
static inline uint64_t BFQ_WEIGHT(uint64_t io_weight) {
        return
            io_weight <= CGROUP_WEIGHT_DEFAULT ?
            CGROUP_BFQ_WEIGHT_DEFAULT - (CGROUP_WEIGHT_DEFAULT - io_weight) * (CGROUP_BFQ_WEIGHT_DEFAULT - CGROUP_BFQ_WEIGHT_MIN) / (CGROUP_WEIGHT_DEFAULT - CGROUP_WEIGHT_MIN) :
            CGROUP_BFQ_WEIGHT_DEFAULT + (io_weight - CGROUP_WEIGHT_DEFAULT) * (CGROUP_BFQ_WEIGHT_MAX - CGROUP_BFQ_WEIGHT_DEFAULT) / (CGROUP_WEIGHT_MAX - CGROUP_WEIGHT_DEFAULT);
}

/*
 * General rules:
 *
 * We accept named hierarchies in the syntax "foo" and "name=foo".
 *
 * We expect that named hierarchies do not conflict in name with a
 * kernel hierarchy, modulo the "name=" prefix.
 *
 * We always generate "normalized" controller names, i.e. without the
 * "name=" prefix.
 *
 * We require absolute cgroup paths. When returning, we will always
 * generate paths with multiple adjacent / removed.
 */

int cg_path_open(const char *path);
int cg_cgroupid_open(int cgroupfs_fd, uint64_t id);

int cg_path_from_cgroupid(int cgroupfs_fd, uint64_t id, char **ret);
int cg_get_cgroupid_at(int dfd, const char *path, uint64_t *ret);
static inline int cg_path_get_cgroupid(const char *path, uint64_t *ret) {
        return cg_get_cgroupid_at(AT_FDCWD, path, ret);
}
static inline int cg_fd_get_cgroupid(int fd, uint64_t *ret) {
        return cg_get_cgroupid_at(fd, NULL, ret);
}

typedef enum CGroupFlags {
        CGROUP_SIGCONT            = 1 << 0,
        CGROUP_IGNORE_SELF        = 1 << 1,
        CGROUP_DONT_SKIP_UNMAPPED = 1 << 2,
} CGroupFlags;

int cg_enumerate_processes(const char *path, FILE **ret);
int cg_read_pid(FILE *f, pid_t *ret, CGroupFlags flags);
int cg_read_pidref(FILE *f, PidRef *ret, CGroupFlags flags);

int cg_enumerate_subgroups(const char *path, DIR **ret);
int cg_read_subgroup(DIR *d, char **ret);

typedef int (*cg_kill_log_func_t)(const PidRef *pid, int sig, void *userdata);

int cg_kill(const char *path, int sig, CGroupFlags flags, Set *killed_pids, cg_kill_log_func_t log_kill, void *userdata);
int cg_kill_kernel_sigkill(const char *path);
int cg_kill_recursive(const char *path, int sig, CGroupFlags flags, Set *killed_pids, cg_kill_log_func_t log_kill, void *userdata);

int cg_get_path(const char *path, const char *suffix, char **ret);

int cg_pid_get_path(pid_t pid, char **ret);
int cg_pidref_get_path(const PidRef *pidref, char **ret);

int cg_is_threaded(const char *path);

int cg_is_delegated(const char *path);
int cg_is_delegated_fd(int fd);

int cg_has_coredump_receive(const char *path);

int cg_set_attribute(const char *path, const char *attribute, const char *value);
int cg_get_attribute(const char *path, const char *attribute, char **ret);
int cg_get_attribute_as_uint64(const char *path, const char *attribute, uint64_t *ret);
int cg_get_attribute_as_bool(const char *path, const char *attribute);

int cg_get_keyed_attribute(const char *path, const char *attribute, char * const *keys, char **values);

int cg_get_owner(const char *path, uid_t *ret_uid);

int cg_set_xattr(const char *path, const char *name, const void *value, size_t size, int flags);
int cg_get_xattr(const char *path, const char *name, char **ret, size_t *ret_size);
/* Returns negative on error, and 0 or 1 on success for the bool value */
int cg_get_xattr_bool(const char *path, const char *name);
int cg_remove_xattr(const char *path, const char *name);

int cg_is_empty(const char *path);

int cg_get_root_path(char **path);

int cg_path_get_session(const char *path, char **ret_session);
int cg_path_get_owner_uid(const char *path, uid_t *ret_uid);
int cg_path_get_unit_full(const char *path, char **ret_unit, char **ret_subgroup);
static inline int cg_path_get_unit(const char *path, char **ret_unit) {
        return cg_path_get_unit_full(path, ret_unit, NULL);
}
int cg_path_get_unit_path(const char *path, char **ret_unit);
int cg_path_get_user_unit_full(const char *path, char **ret_unit, char **ret_subgroup);
static inline int cg_path_get_user_unit(const char *path, char **ret_unit) {
        return cg_path_get_user_unit_full(path, ret_unit, NULL);
}
int cg_path_get_machine_name(const char *path, char **ret_machine);
int cg_path_get_slice(const char *path, char **ret_slice);
int cg_path_get_user_slice(const char *path, char **ret_slice);

int cg_shift_path(const char *cgroup, const char *cached_root, const char **ret_shifted);
int cg_pid_get_path_shifted(pid_t pid, const char *cached_root, char **ret_cgroup);

int cg_pid_get_session(pid_t pid, char **ret_session);
int cg_pidref_get_session(const PidRef *pidref, char **ret);
int cg_pid_get_owner_uid(pid_t pid, uid_t *ret_uid);
int cg_pidref_get_owner_uid(const PidRef *pidref, uid_t *ret);
int cg_pid_get_unit_full(pid_t pid, char **ret_unit, char **ret_subgroup);
static inline int cg_pid_get_unit(pid_t pid, char **ret_unit) {
        return cg_pid_get_unit_full(pid, ret_unit, NULL);
}
int cg_pidref_get_unit_full(const PidRef *pidref, char **ret_unit, char **ret_subgroup);
static inline int cg_pidref_get_unit(const PidRef *pidref, char **ret_unit) {
        return cg_pidref_get_unit_full(pidref, ret_unit, NULL);
}
int cg_pid_get_user_unit_full(pid_t pid, char **ret_unit, char **ret_subgroup);
static inline int cg_pid_get_user_unit(pid_t pid, char **ret_unit) {
        return cg_pid_get_unit_full(pid, ret_unit, NULL);
}
int cg_pidref_get_user_unit_full(const PidRef *pidref, char **ret_unit, char **ret_subgroup);
static inline int cg_pidref_get_user_unit(const PidRef *pidref, char **ret_unit) {
        return cg_pidref_get_user_unit_full(pidref, ret_unit, NULL);
}
int cg_pid_get_machine_name(pid_t pid, char **ret_machine);
int cg_pid_get_slice(pid_t pid, char **ret_slice);
int cg_pid_get_user_slice(pid_t pid, char **ret_slice);

int cg_path_decode_unit(const char *cgroup, char **ret_unit);

bool cg_needs_escape(const char *p) _pure_;
int cg_escape(const char *p, char **ret);
char* cg_unescape(const char *p) _pure_;

int cg_slice_to_path(const char *unit, char **ret);

int cg_mask_supported(CGroupMask *ret);
int cg_mask_supported_subtree(const char *root, CGroupMask *ret);
int cg_mask_from_string(const char *s, CGroupMask *ret);
int cg_mask_to_string(CGroupMask mask, char **ret);

bool cg_kill_supported(void);

const char* cgroup_controller_to_string(CGroupController c) _const_;
CGroupController cgroup_controller_from_string(const char *s) _pure_;

typedef enum ManagedOOMMode {
        MANAGED_OOM_AUTO,
        MANAGED_OOM_KILL,
        _MANAGED_OOM_MODE_MAX,
        _MANAGED_OOM_MODE_INVALID = -EINVAL,
} ManagedOOMMode;

const char* managed_oom_mode_to_string(ManagedOOMMode m) _const_;
ManagedOOMMode managed_oom_mode_from_string(const char *s) _pure_;

typedef enum ManagedOOMPreference {
        MANAGED_OOM_PREFERENCE_NONE = 0,
        MANAGED_OOM_PREFERENCE_AVOID = 1,
        MANAGED_OOM_PREFERENCE_OMIT = 2,
        _MANAGED_OOM_PREFERENCE_MAX,
        _MANAGED_OOM_PREFERENCE_INVALID = -EINVAL,
} ManagedOOMPreference;

const char* managed_oom_preference_to_string(ManagedOOMPreference a) _const_;
ManagedOOMPreference managed_oom_preference_from_string(const char *s) _pure_;
