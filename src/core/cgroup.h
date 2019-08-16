/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "cgroup-util.h"
#include "ip-address-access.h"
#include "list.h"
#include "time-util.h"

typedef struct CGroupContext CGroupContext;
typedef struct CGroupDeviceAllow CGroupDeviceAllow;
typedef struct CGroupIODeviceWeight CGroupIODeviceWeight;
typedef struct CGroupIODeviceLimit CGroupIODeviceLimit;
typedef struct CGroupIODeviceLatency CGroupIODeviceLatency;
typedef struct CGroupBlockIODeviceWeight CGroupBlockIODeviceWeight;
typedef struct CGroupBlockIODeviceBandwidth CGroupBlockIODeviceBandwidth;

typedef enum CGroupDevicePolicy {

        /* When devices listed, will allow those, plus built-in ones,
        if none are listed will allow everything. */
        CGROUP_AUTO,

        /* Everything forbidden, except built-in ones and listed ones. */
        CGROUP_CLOSED,

        /* Everything forbidden, except for the listed devices */
        CGROUP_STRICT,

        _CGROUP_DEVICE_POLICY_MAX,
        _CGROUP_DEVICE_POLICY_INVALID = -1
} CGroupDevicePolicy;

struct CGroupDeviceAllow {
        LIST_FIELDS(CGroupDeviceAllow, device_allow);
        char *path;
        bool r:1;
        bool w:1;
        bool m:1;
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

        /* For unified hierarchy */
        uint64_t cpu_weight;
        uint64_t startup_cpu_weight;
        usec_t cpu_quota_per_sec_usec;
        usec_t cpu_quota_period_usec;

        uint64_t io_weight;
        uint64_t startup_io_weight;
        LIST_HEAD(CGroupIODeviceWeight, io_device_weights);
        LIST_HEAD(CGroupIODeviceLimit, io_device_limits);
        LIST_HEAD(CGroupIODeviceLatency, io_device_latencies);

        uint64_t default_memory_min;
        uint64_t default_memory_low;
        uint64_t memory_min;
        uint64_t memory_low;
        uint64_t memory_high;
        uint64_t memory_max;
        uint64_t memory_swap_max;

        bool default_memory_min_set;
        bool default_memory_low_set;
        bool memory_min_set;
        bool memory_low_set;

        LIST_HEAD(IPAddressAccessItem, ip_address_allow);
        LIST_HEAD(IPAddressAccessItem, ip_address_deny);

        char **ip_filters_ingress;
        char **ip_filters_egress;

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

        /* Common */
        uint64_t tasks_max;
};

/* Used when querying IP accounting data */
typedef enum CGroupIPAccountingMetric {
        CGROUP_IP_INGRESS_BYTES,
        CGROUP_IP_INGRESS_PACKETS,
        CGROUP_IP_EGRESS_BYTES,
        CGROUP_IP_EGRESS_PACKETS,
        _CGROUP_IP_ACCOUNTING_METRIC_MAX,
        _CGROUP_IP_ACCOUNTING_METRIC_INVALID = -1,
} CGroupIPAccountingMetric;

/* Used when querying IO accounting data */
typedef enum CGroupIOAccountingMetric {
        CGROUP_IO_READ_BYTES,
        CGROUP_IO_WRITE_BYTES,
        CGROUP_IO_READ_OPERATIONS,
        CGROUP_IO_WRITE_OPERATIONS,
        _CGROUP_IO_ACCOUNTING_METRIC_MAX,
        _CGROUP_IO_ACCOUNTING_METRIC_INVALID = -1,
} CGroupIOAccountingMetric;

typedef struct Unit Unit;
typedef struct Manager Manager;

usec_t cgroup_cpu_adjust_period(usec_t period, usec_t quota, usec_t resolution, usec_t max_period);

void cgroup_context_init(CGroupContext *c);
void cgroup_context_done(CGroupContext *c);
void cgroup_context_dump(CGroupContext *c, FILE* f, const char *prefix);

void cgroup_context_free_device_allow(CGroupContext *c, CGroupDeviceAllow *a);
void cgroup_context_free_io_device_weight(CGroupContext *c, CGroupIODeviceWeight *w);
void cgroup_context_free_io_device_limit(CGroupContext *c, CGroupIODeviceLimit *l);
void cgroup_context_free_io_device_latency(CGroupContext *c, CGroupIODeviceLatency *l);
void cgroup_context_free_blockio_device_weight(CGroupContext *c, CGroupBlockIODeviceWeight *w);
void cgroup_context_free_blockio_device_bandwidth(CGroupContext *c, CGroupBlockIODeviceBandwidth *b);

int cgroup_add_device_allow(CGroupContext *c, const char *dev, const char *mode);

CGroupMask unit_get_own_mask(Unit *u);
CGroupMask unit_get_delegate_mask(Unit *u);
CGroupMask unit_get_members_mask(Unit *u);
CGroupMask unit_get_siblings_mask(Unit *u);
CGroupMask unit_get_subtree_mask(Unit *u);
CGroupMask unit_get_disable_mask(Unit *u);
CGroupMask unit_get_ancestor_disable_mask(Unit *u);

CGroupMask unit_get_target_mask(Unit *u);
CGroupMask unit_get_enable_mask(Unit *u);

void unit_invalidate_cgroup_members_masks(Unit *u);

void unit_add_to_cgroup_realize_queue(Unit *u);

const char *unit_get_realized_cgroup_path(Unit *u, CGroupMask mask);
char *unit_default_cgroup_path(const Unit *u);
int unit_set_cgroup_path(Unit *u, const char *path);
int unit_pick_cgroup_path(Unit *u);

int unit_realize_cgroup(Unit *u);
void unit_release_cgroup(Unit *u);
void unit_prune_cgroup(Unit *u);
int unit_watch_cgroup(Unit *u);
int unit_watch_cgroup_memory(Unit *u);

void unit_add_to_cgroup_empty_queue(Unit *u);
int unit_check_oom(Unit *u);

int unit_attach_pids_to_cgroup(Unit *u, Set *pids, const char *suffix_path);

int manager_setup_cgroup(Manager *m);
void manager_shutdown_cgroup(Manager *m, bool delete);

unsigned manager_dispatch_cgroup_realize_queue(Manager *m);

Unit *manager_get_unit_by_cgroup(Manager *m, const char *cgroup);
Unit *manager_get_unit_by_pid_cgroup(Manager *m, pid_t pid);
Unit* manager_get_unit_by_pid(Manager *m, pid_t pid);

uint64_t unit_get_ancestor_memory_min(Unit *u);
uint64_t unit_get_ancestor_memory_low(Unit *u);

int unit_search_main_pid(Unit *u, pid_t *ret);
int unit_watch_all_pids(Unit *u);

int unit_synthesize_cgroup_empty_event(Unit *u);

int unit_get_memory_current(Unit *u, uint64_t *ret);
int unit_get_tasks_current(Unit *u, uint64_t *ret);
int unit_get_cpu_usage(Unit *u, nsec_t *ret);
int unit_get_io_accounting(Unit *u, CGroupIOAccountingMetric metric, bool allow_cache, uint64_t *ret);
int unit_get_ip_accounting(Unit *u, CGroupIPAccountingMetric metric, uint64_t *ret);

int unit_reset_cpu_accounting(Unit *u);
int unit_reset_ip_accounting(Unit *u);
int unit_reset_io_accounting(Unit *u);
int unit_reset_accounting(Unit *u);

#define UNIT_CGROUP_BOOL(u, name)                       \
        ({                                              \
        CGroupContext *cc = unit_get_cgroup_context(u); \
        cc ? cc->name : false;                          \
        })

bool manager_owns_host_root_cgroup(Manager *m);
bool unit_has_host_root_cgroup(Unit *u);

int manager_notify_cgroup_empty(Manager *m, const char *group);

void unit_invalidate_cgroup(Unit *u, CGroupMask m);
void unit_invalidate_cgroup_bpf(Unit *u);

void manager_invalidate_startup_units(Manager *m);

const char* cgroup_device_policy_to_string(CGroupDevicePolicy i) _const_;
CGroupDevicePolicy cgroup_device_policy_from_string(const char *s) _pure_;

bool unit_cgroup_delegate(Unit *u);

int compare_job_priority(const void *a, const void *b);
