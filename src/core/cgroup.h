/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-event.h"

#include "bpf-program.h"
#include "bpf-restrict-fs.h"
#include "cgroup-util.h"
#include "cpu-set-util.h"
#include "firewall-util.h"
#include "list.h"
#include "pidref.h"
#include "time-util.h"

typedef struct CGroupTasksMax {
        /* If scale == 0, just use value; otherwise, value / scale.
         * See tasks_max_resolve(). */
        uint64_t value;
        uint64_t scale;
} CGroupTasksMax;

#define CGROUP_TASKS_MAX_UNSET ((CGroupTasksMax) { .value = UINT64_MAX, .scale = 0 })

static inline bool cgroup_tasks_max_isset(const CGroupTasksMax *tasks_max) {
        return tasks_max->value != UINT64_MAX || tasks_max->scale != 0;
}

uint64_t cgroup_tasks_max_resolve(const CGroupTasksMax *tasks_max);

typedef struct CGroupContext CGroupContext;
typedef struct CGroupDeviceAllow CGroupDeviceAllow;
typedef struct CGroupIODeviceWeight CGroupIODeviceWeight;
typedef struct CGroupIODeviceLimit CGroupIODeviceLimit;
typedef struct CGroupIODeviceLatency CGroupIODeviceLatency;
typedef struct CGroupBlockIODeviceWeight CGroupBlockIODeviceWeight;
typedef struct CGroupBlockIODeviceBandwidth CGroupBlockIODeviceBandwidth;
typedef struct CGroupBPFForeignProgram CGroupBPFForeignProgram;
typedef struct CGroupSocketBindItem CGroupSocketBindItem;
typedef struct CGroupRuntime CGroupRuntime;

typedef enum CGroupDevicePolicy {
        /* When devices listed, will allow those, plus built-in ones, if none are listed will allow
         * everything. */
        CGROUP_DEVICE_POLICY_AUTO,

        /* Everything forbidden, except built-in ones and listed ones. */
        CGROUP_DEVICE_POLICY_CLOSED,

        /* Everything forbidden, except for the listed devices */
        CGROUP_DEVICE_POLICY_STRICT,

        _CGROUP_DEVICE_POLICY_MAX,
        _CGROUP_DEVICE_POLICY_INVALID = -EINVAL,
} CGroupDevicePolicy;

typedef enum FreezerAction {
        FREEZER_FREEZE,
        FREEZER_PARENT_FREEZE,
        FREEZER_THAW,
        FREEZER_PARENT_THAW,
        _FREEZER_ACTION_MAX,
        _FREEZER_ACTION_INVALID = -EINVAL,
} FreezerAction;

typedef enum CGroupDevicePermissions {
        /* We reuse the same bit meanings the kernel's BPF_DEVCG_ACC_xyz definitions use */
        CGROUP_DEVICE_MKNOD                = 1 << 0,
        CGROUP_DEVICE_READ                 = 1 << 1,
        CGROUP_DEVICE_WRITE                = 1 << 2,
        _CGROUP_DEVICE_PERMISSIONS_MAX     = 1 << 3,
        _CGROUP_DEVICE_PERMISSIONS_ALL     = _CGROUP_DEVICE_PERMISSIONS_MAX - 1,
        _CGROUP_DEVICE_PERMISSIONS_INVALID = -EINVAL,
} CGroupDevicePermissions;

struct CGroupDeviceAllow {
        LIST_FIELDS(CGroupDeviceAllow, device_allow);
        char *path;
        CGroupDevicePermissions permissions;
};

struct CGroupIODeviceWeight {
        LIST_FIELDS(CGroupIODeviceWeight, device_weights);
        char *path;
        uint64_t weight;
};

struct CGroupIODeviceLimit {
        LIST_FIELDS(CGroupIODeviceLimit, device_limits);
        char *path;
        uint64_t limits[_CGROUP_IO_LIMIT_TYPE_MAX];
};

struct CGroupIODeviceLatency {
        LIST_FIELDS(CGroupIODeviceLatency, device_latencies);
        char *path;
        usec_t target_usec;
};

struct CGroupBlockIODeviceWeight {
        LIST_FIELDS(CGroupBlockIODeviceWeight, device_weights);
        char *path;
        uint64_t weight;
};

struct CGroupBlockIODeviceBandwidth {
        LIST_FIELDS(CGroupBlockIODeviceBandwidth, device_bandwidths);
        char *path;
        uint64_t rbps;
        uint64_t wbps;
};

struct CGroupBPFForeignProgram {
        LIST_FIELDS(CGroupBPFForeignProgram, programs);
        uint32_t attach_type;
        char *bpffs_path;
};

struct CGroupSocketBindItem {
        LIST_FIELDS(CGroupSocketBindItem, socket_bind_items);
        int address_family;
        int ip_protocol;
        uint16_t nr_ports;
        uint16_t port_min;
};

typedef enum CGroupPressureWatch {
        CGROUP_PRESSURE_WATCH_NO,       /* → tells the service payload explicitly not to watch for memory pressure */
        CGROUP_PRESSURE_WATCH_YES,
        CGROUP_PRESSURE_WATCH_AUTO,     /* → on if memory account is on anyway for the unit, otherwise off */
        CGROUP_PRESSURE_WATCH_SKIP,     /* → doesn't set up memory pressure watch, but also doesn't explicitly tell payload to avoid it */
        _CGROUP_PRESSURE_WATCH_MAX,
        _CGROUP_PRESSURE_WATCH_INVALID = -EINVAL,
} CGroupPressureWatch;

/* The user-supplied cgroup-related configuration options. This remains mostly immutable while the service
 * manager is running (except for an occasional SetProperty() configuration change), outside of reload
 * cycles. When adding members make sure to update cgroup_context_copy() accordingly. */
struct CGroupContext {
        bool cpu_accounting;
        bool io_accounting;
        bool blockio_accounting;
        bool memory_accounting;
        bool tasks_accounting;
        bool ip_accounting;

        /* Configures the memory.oom.group attribute (on unified) */
        bool memory_oom_group;

        bool delegate;
        CGroupMask delegate_controllers;
        CGroupMask disable_controllers;
        char *delegate_subgroup;

        /* For unified hierarchy */
        uint64_t cpu_weight;
        uint64_t startup_cpu_weight;
        usec_t cpu_quota_per_sec_usec;
        usec_t cpu_quota_period_usec;

        CPUSet cpuset_cpus;
        CPUSet startup_cpuset_cpus;
        CPUSet cpuset_mems;
        CPUSet startup_cpuset_mems;

        uint64_t io_weight;
        uint64_t startup_io_weight;
        LIST_HEAD(CGroupIODeviceWeight, io_device_weights);
        LIST_HEAD(CGroupIODeviceLimit, io_device_limits);
        LIST_HEAD(CGroupIODeviceLatency, io_device_latencies);

        uint64_t default_memory_min;
        uint64_t default_memory_low;
        uint64_t default_startup_memory_low;
        uint64_t memory_min;
        uint64_t memory_low;
        uint64_t startup_memory_low;
        uint64_t memory_high;
        uint64_t startup_memory_high;
        uint64_t memory_max;
        uint64_t startup_memory_max;
        uint64_t memory_swap_max;
        uint64_t startup_memory_swap_max;
        uint64_t memory_zswap_max;
        uint64_t startup_memory_zswap_max;

        bool default_memory_min_set:1;
        bool default_memory_low_set:1;
        bool default_startup_memory_low_set:1;
        bool memory_min_set:1;
        bool memory_low_set:1;
        bool startup_memory_low_set:1;
        bool startup_memory_high_set:1;
        bool startup_memory_max_set:1;
        bool startup_memory_swap_max_set:1;
        bool startup_memory_zswap_max_set:1;

        bool memory_zswap_writeback;

        Set *ip_address_allow;
        Set *ip_address_deny;
        /* These two flags indicate that redundant entries have been removed from
         * ip_address_allow/ip_address_deny, i.e. in_addr_prefixes_reduce() has already been called. */
        bool ip_address_allow_reduced;
        bool ip_address_deny_reduced;

        char **ip_filters_ingress;
        char **ip_filters_egress;
        LIST_HEAD(CGroupBPFForeignProgram, bpf_foreign_programs);

        Set *restrict_network_interfaces;
        bool restrict_network_interfaces_is_allow_list;

        /* For legacy hierarchies */
        uint64_t cpu_shares;
        uint64_t startup_cpu_shares;

        uint64_t blockio_weight;
        uint64_t startup_blockio_weight;
        LIST_HEAD(CGroupBlockIODeviceWeight, blockio_device_weights);
        LIST_HEAD(CGroupBlockIODeviceBandwidth, blockio_device_bandwidths);

        uint64_t memory_limit;

        CGroupDevicePolicy device_policy;
        LIST_HEAD(CGroupDeviceAllow, device_allow);

        LIST_HEAD(CGroupSocketBindItem, socket_bind_allow);
        LIST_HEAD(CGroupSocketBindItem, socket_bind_deny);

        /* Common */
        CGroupTasksMax tasks_max;

        /* Settings for systemd-oomd */
        ManagedOOMMode moom_swap;
        ManagedOOMMode moom_mem_pressure;
        uint32_t moom_mem_pressure_limit; /* Normalized to 2^32-1 == 100% */
        usec_t moom_mem_pressure_duration_usec;
        ManagedOOMPreference moom_preference;

        /* Memory pressure logic */
        CGroupPressureWatch memory_pressure_watch;
        usec_t memory_pressure_threshold_usec;
        /* NB: For now we don't make the period configurable, not the type, nor do we allow multiple
         * triggers, nor triggers for non-memory pressure. We might add that later. */

        NFTSetContext nft_set_context;

        /* Forward coredumps for processes that crash within this cgroup.
         * Requires 'delegate' to also be true. */
        bool coredump_receive;
};

/* Used when querying IP accounting data */
typedef enum CGroupIPAccountingMetric {
        CGROUP_IP_INGRESS_BYTES,
        CGROUP_IP_INGRESS_PACKETS,
        CGROUP_IP_EGRESS_BYTES,
        CGROUP_IP_EGRESS_PACKETS,
        _CGROUP_IP_ACCOUNTING_METRIC_MAX,
        _CGROUP_IP_ACCOUNTING_METRIC_INVALID = -EINVAL,
} CGroupIPAccountingMetric;

/* Used when querying IO accounting data */
typedef enum CGroupIOAccountingMetric {
        CGROUP_IO_READ_BYTES,
        CGROUP_IO_WRITE_BYTES,
        CGROUP_IO_READ_OPERATIONS,
        CGROUP_IO_WRITE_OPERATIONS,
        _CGROUP_IO_ACCOUNTING_METRIC_MAX,
        _CGROUP_IO_ACCOUNTING_METRIC_INVALID = -EINVAL,
} CGroupIOAccountingMetric;

typedef enum CGroupMemoryAccountingMetric {
        CGROUP_MEMORY_PEAK,
        CGROUP_MEMORY_SWAP_PEAK,
        /* We cache the above attributes, so that they can be fetched even after the cgroup is gone, e.g.
         * when systemd-run exits. */
        _CGROUP_MEMORY_ACCOUNTING_METRIC_CACHED_LAST = CGROUP_MEMORY_SWAP_PEAK,

        /* These attributes are transient, so no need for caching. */
        CGROUP_MEMORY_SWAP_CURRENT,
        CGROUP_MEMORY_ZSWAP_CURRENT,

        _CGROUP_MEMORY_ACCOUNTING_METRIC_MAX,
        _CGROUP_MEMORY_ACCOUNTING_METRIC_INVALID = -EINVAL,
} CGroupMemoryAccountingMetric;

/* Used for limits whose value sets have infimum */
typedef enum CGroupLimitType {
        CGROUP_LIMIT_MEMORY_MAX,
        CGROUP_LIMIT_MEMORY_HIGH,
        CGROUP_LIMIT_TASKS_MAX,
        _CGROUP_LIMIT_TYPE_MAX,
        _CGROUP_LIMIT_INVALID = -EINVAL,
} CGroupLimitType;

/* The dynamic, regular updated information about a unit that as a realized cgroup. This is only allocated when a unit is first realized */
typedef struct CGroupRuntime {
        /* Where the cpu.stat or cpuacct.usage was at the time the unit was started */
        nsec_t cpu_usage_base;
        nsec_t cpu_usage_last; /* the most recently read value */

        /* Most recently read value of memory accounting metrics */
        uint64_t memory_accounting_last[_CGROUP_MEMORY_ACCOUNTING_METRIC_CACHED_LAST + 1];

        /* The current counter of OOM kills initiated by systemd-oomd */
        uint64_t managed_oom_kill_last;

        /* The current counter of the oom_kill field in the memory.events cgroup attribute */
        uint64_t oom_kill_last;

        /* Where the io.stat data was at the time the unit was started */
        uint64_t io_accounting_base[_CGROUP_IO_ACCOUNTING_METRIC_MAX];
        uint64_t io_accounting_last[_CGROUP_IO_ACCOUNTING_METRIC_MAX]; /* the most recently read value */

        /* Counterparts in the cgroup filesystem */
        char *cgroup_path;
        uint64_t cgroup_id;
        CGroupMask cgroup_realized_mask;           /* In which hierarchies does this unit's cgroup exist? (only relevant on cgroup v1) */
        CGroupMask cgroup_enabled_mask;            /* Which controllers are enabled (or more correctly: enabled for the children) for this unit's cgroup? (only relevant on cgroup v2) */
        CGroupMask cgroup_invalidated_mask;        /* A mask specifying controllers which shall be considered invalidated, and require re-realization */
        CGroupMask cgroup_members_mask;            /* A cache for the controllers required by all children of this cgroup (only relevant for slice units) */

        /* Inotify watch descriptors for watching cgroup.events and memory.events on cgroupv2 */
        int cgroup_control_inotify_wd;
        int cgroup_memory_inotify_wd;

        /* Device Controller BPF program */
        BPFProgram *bpf_device_control_installed;

        /* IP BPF Firewalling/accounting */
        int ip_accounting_ingress_map_fd;
        int ip_accounting_egress_map_fd;
        uint64_t ip_accounting_extra[_CGROUP_IP_ACCOUNTING_METRIC_MAX];

        int ipv4_allow_map_fd;
        int ipv6_allow_map_fd;
        int ipv4_deny_map_fd;
        int ipv6_deny_map_fd;
        BPFProgram *ip_bpf_ingress, *ip_bpf_ingress_installed;
        BPFProgram *ip_bpf_egress, *ip_bpf_egress_installed;

        Set *ip_bpf_custom_ingress;
        Set *ip_bpf_custom_ingress_installed;
        Set *ip_bpf_custom_egress;
        Set *ip_bpf_custom_egress_installed;

        /* BPF programs managed (e.g. loaded to kernel) by an entity external to systemd,
         * attached to unit cgroup by provided program fd and attach type. */
        Hashmap *bpf_foreign_by_key;

        FDSet *initial_socket_bind_link_fds;
#if BPF_FRAMEWORK
        /* BPF links to BPF programs attached to cgroup/bind{4|6} hooks and
         * responsible for allowing or denying a unit to bind(2) to a socket
         * address. */
        struct bpf_link *ipv4_socket_bind_link;
        struct bpf_link *ipv6_socket_bind_link;
#endif

        FDSet *initial_restrict_ifaces_link_fds;
#if BPF_FRAMEWORK
        struct bpf_link *restrict_ifaces_ingress_bpf_link;
        struct bpf_link *restrict_ifaces_egress_bpf_link;
#endif

        bool cgroup_realized:1;
        bool cgroup_members_mask_valid:1;

        /* Reset cgroup accounting next time we fork something off */
        bool reset_accounting:1;

        /* Whether we warned about clamping the CPU quota period */
        bool warned_clamping_cpu_quota_period:1;
} CGroupRuntime;

typedef struct Unit Unit;
typedef struct Manager Manager;
typedef enum ManagerState ManagerState;

uint64_t cgroup_context_cpu_weight(CGroupContext *c, ManagerState state);

usec_t cgroup_cpu_adjust_period(usec_t period, usec_t quota, usec_t resolution, usec_t max_period);

void cgroup_context_init(CGroupContext *c);
int cgroup_context_copy(CGroupContext *dst, const CGroupContext *src);
void cgroup_context_done(CGroupContext *c);
void cgroup_context_dump(Unit *u, FILE* f, const char *prefix);
void cgroup_context_dump_socket_bind_item(const CGroupSocketBindItem *item, FILE *f);
void cgroup_context_dump_socket_bind_items(const CGroupSocketBindItem *items, FILE *f);

void cgroup_context_free_device_allow(CGroupContext *c, CGroupDeviceAllow *a);
void cgroup_context_free_io_device_weight(CGroupContext *c, CGroupIODeviceWeight *w);
void cgroup_context_free_io_device_limit(CGroupContext *c, CGroupIODeviceLimit *l);
void cgroup_context_free_io_device_latency(CGroupContext *c, CGroupIODeviceLatency *l);
void cgroup_context_free_blockio_device_weight(CGroupContext *c, CGroupBlockIODeviceWeight *w);
void cgroup_context_free_blockio_device_bandwidth(CGroupContext *c, CGroupBlockIODeviceBandwidth *b);
void cgroup_context_remove_bpf_foreign_program(CGroupContext *c, CGroupBPFForeignProgram *p);
void cgroup_context_remove_socket_bind(CGroupSocketBindItem **head);

static inline bool cgroup_context_want_memory_pressure(const CGroupContext *c) {
        assert(c);

        return c->memory_pressure_watch == CGROUP_PRESSURE_WATCH_YES ||
                (c->memory_pressure_watch == CGROUP_PRESSURE_WATCH_AUTO && c->memory_accounting);
}

int cgroup_context_add_device_allow(CGroupContext *c, const char *dev, CGroupDevicePermissions p);
int cgroup_context_add_or_update_device_allow(CGroupContext *c, const char *dev, CGroupDevicePermissions p);
int cgroup_context_add_bpf_foreign_program(CGroupContext *c, uint32_t attach_type, const char *path);
static inline int cgroup_context_add_bpf_foreign_program_dup(CGroupContext *c, const CGroupBPFForeignProgram *p) {
        return cgroup_context_add_bpf_foreign_program(c, p->attach_type, p->bpffs_path);
}
int cgroup_context_add_io_device_limit_dup(CGroupContext *c, const CGroupIODeviceLimit *l);
int cgroup_context_add_io_device_weight_dup(CGroupContext *c, const CGroupIODeviceWeight *w);
int cgroup_context_add_io_device_latency_dup(CGroupContext *c, const CGroupIODeviceLatency *l);
int cgroup_context_add_block_io_device_weight_dup(CGroupContext *c, const CGroupBlockIODeviceWeight *w);
int cgroup_context_add_block_io_device_bandwidth_dup(CGroupContext *c, const CGroupBlockIODeviceBandwidth *b);
int cgroup_context_add_device_allow_dup(CGroupContext *c, const CGroupDeviceAllow *a);
int cgroup_context_add_socket_bind_item_allow_dup(CGroupContext *c, const CGroupSocketBindItem *i);
int cgroup_context_add_socket_bind_item_deny_dup(CGroupContext *c, const CGroupSocketBindItem *i);

void unit_modify_nft_set(Unit *u, bool add);

CGroupMask unit_get_own_mask(Unit *u);
CGroupMask unit_get_delegate_mask(Unit *u);
CGroupMask unit_get_members_mask(Unit *u);
CGroupMask unit_get_siblings_mask(Unit *u);
CGroupMask unit_get_ancestor_disable_mask(Unit *u);

CGroupMask unit_get_target_mask(Unit *u);
CGroupMask unit_get_enable_mask(Unit *u);

void unit_invalidate_cgroup_members_masks(Unit *u);

void unit_add_family_to_cgroup_realize_queue(Unit *u);

const char* unit_get_realized_cgroup_path(Unit *u, CGroupMask mask);
int unit_default_cgroup_path(const Unit *u, char **ret);
int unit_set_cgroup_path(Unit *u, const char *path);
int unit_pick_cgroup_path(Unit *u);

int unit_realize_cgroup(Unit *u);
void unit_prune_cgroup(Unit *u);
int unit_watch_cgroup(Unit *u);
int unit_watch_cgroup_memory(Unit *u);
void unit_add_to_cgroup_realize_queue(Unit *u);

int unit_cgroup_is_empty(Unit *u);
void unit_release_cgroup(Unit *u, bool drop_cgroup_runtime);

void unit_add_to_cgroup_empty_queue(Unit *u);
int unit_check_oomd_kill(Unit *u);
int unit_check_oom(Unit *u);

int unit_attach_pids_to_cgroup(Unit *u, Set *pids, const char *suffix_path);
int unit_remove_subcgroup(Unit *u, const char *suffix_path);

int manager_setup_cgroup(Manager *m);
void manager_shutdown_cgroup(Manager *m, bool delete);

unsigned manager_dispatch_cgroup_realize_queue(Manager *m);

Unit *manager_get_unit_by_cgroup(Manager *m, const char *cgroup);
Unit *manager_get_unit_by_pidref_cgroup(Manager *m, const PidRef *pid);
Unit *manager_get_unit_by_pidref_watching(Manager *m, const PidRef *pid);
Unit* manager_get_unit_by_pidref(Manager *m, PidRef *pid);
Unit* manager_get_unit_by_pid(Manager *m, pid_t pid);

uint64_t unit_get_ancestor_memory_min(Unit *u);
uint64_t unit_get_ancestor_memory_low(Unit *u);
uint64_t unit_get_ancestor_startup_memory_low(Unit *u);

int unit_search_main_pid(Unit *u, PidRef *ret);
int unit_watch_all_pids(Unit *u);

int unit_synthesize_cgroup_empty_event(Unit *u);

int unit_get_memory_available(Unit *u, uint64_t *ret);
int unit_get_memory_current(Unit *u, uint64_t *ret);
int unit_get_memory_accounting(Unit *u, CGroupMemoryAccountingMetric metric, uint64_t *ret);
int unit_get_tasks_current(Unit *u, uint64_t *ret);
int unit_get_cpu_usage(Unit *u, nsec_t *ret);
int unit_get_io_accounting(Unit *u, CGroupIOAccountingMetric metric, uint64_t *ret);
int unit_get_ip_accounting(Unit *u, CGroupIPAccountingMetric metric, uint64_t *ret);
int unit_get_effective_limit(Unit *u, CGroupLimitType type, uint64_t *ret);

int unit_reset_accounting(Unit *u);

#define UNIT_CGROUP_BOOL(u, name)                               \
        ({                                                      \
                CGroupContext *cc = unit_get_cgroup_context(u); \
                cc ? cc->name : false;                          \
        })

bool manager_owns_host_root_cgroup(Manager *m);
bool unit_has_host_root_cgroup(const Unit *u);

bool unit_has_startup_cgroup_constraints(Unit *u);

int manager_notify_cgroup_empty(Manager *m, const char *group);

void unit_invalidate_cgroup(Unit *u, CGroupMask m);
void unit_invalidate_cgroup_bpf(Unit *u);

void manager_invalidate_startup_units(Manager *m);

const char* cgroup_device_policy_to_string(CGroupDevicePolicy i) _const_;
CGroupDevicePolicy cgroup_device_policy_from_string(const char *s) _pure_;

void unit_cgroup_catchup(Unit *u);

bool unit_cgroup_delegate(Unit *u);

int unit_get_cpuset(Unit *u, CPUSet *cpus, const char *name);

int unit_cgroup_freezer_action(Unit *u, FreezerAction action);

const char* freezer_action_to_string(FreezerAction a) _const_;
FreezerAction freezer_action_from_string(const char *s) _pure_;

CGroupRuntime* cgroup_runtime_new(void);
CGroupRuntime* cgroup_runtime_free(CGroupRuntime *crt);
DEFINE_TRIVIAL_CLEANUP_FUNC(CGroupRuntime*, cgroup_runtime_free);

int cgroup_runtime_serialize(Unit *u, FILE *f, FDSet *fds);
int cgroup_runtime_deserialize_one(Unit *u, const char *key, const char *value, FDSet *fds);

const char* cgroup_pressure_watch_to_string(CGroupPressureWatch a) _const_;
CGroupPressureWatch cgroup_pressure_watch_from_string(const char *s) _pure_;

const char* cgroup_device_permissions_to_string(CGroupDevicePermissions p) _const_;
CGroupDevicePermissions cgroup_device_permissions_from_string(const char *s) _pure_;

const char* cgroup_ip_accounting_metric_to_string(CGroupIPAccountingMetric m) _const_;
CGroupIPAccountingMetric cgroup_ip_accounting_metric_from_string(const char *s) _pure_;

const char* cgroup_io_accounting_metric_to_string(CGroupIOAccountingMetric m) _const_;
CGroupIOAccountingMetric cgroup_io_accounting_metric_from_string(const char *s) _pure_;

const char* cgroup_effective_limit_type_to_string(CGroupLimitType m) _const_;
CGroupLimitType cgroup_effective_limit_type_from_string(const char *s) _pure_;

const char* cgroup_memory_accounting_metric_to_string(CGroupMemoryAccountingMetric m) _const_;
CGroupMemoryAccountingMetric cgroup_memory_accounting_metric_from_string(const char *s) _pure_;
