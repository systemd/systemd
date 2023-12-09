/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "sd-messages.h"

#include "af-list.h"
#include "alloc-util.h"
#include "blockdev-util.h"
#include "bpf-devices.h"
#include "bpf-firewall.h"
#include "bpf-foreign.h"
#include "bpf-socket-bind.h"
#include "btrfs-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "cgroup.h"
#include "devnum-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "firewall-util.h"
#include "in-addr-prefix-util.h"
#include "inotify-util.h"
#include "io-util.h"
#include "ip-protocol-list.h"
#include "limits-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "percent-util.h"
#include "process-util.h"
#include "procfs-util.h"
#include "restrict-ifaces.h"
#include "special.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "virt.h"

#if BPF_FRAMEWORK
#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "bpf/restrict_fs/restrict-fs-skel.h"
#endif

#define CGROUP_CPU_QUOTA_DEFAULT_PERIOD_USEC ((usec_t) 100 * USEC_PER_MSEC)

/* Returns the log level to use when cgroup attribute writes fail. When an attribute is missing or we have access
 * problems we downgrade to LOG_DEBUG. This is supposed to be nice to container managers and kernels which want to mask
 * out specific attributes from us. */
#define LOG_LEVEL_CGROUP_WRITE(r) (IN_SET(abs(r), ENOENT, EROFS, EACCES, EPERM) ? LOG_DEBUG : LOG_WARNING)

uint64_t cgroup_tasks_max_resolve(const CGroupTasksMax *tasks_max) {
        if (tasks_max->scale == 0)
                return tasks_max->value;

        return system_tasks_max_scale(tasks_max->value, tasks_max->scale);
}

bool manager_owns_host_root_cgroup(Manager *m) {
        assert(m);

        /* Returns true if we are managing the root cgroup. Note that it isn't sufficient to just check whether the
         * group root path equals "/" since that will also be the case if CLONE_NEWCGROUP is in the mix. Since there's
         * appears to be no nice way to detect whether we are in a CLONE_NEWCGROUP namespace we instead just check if
         * we run in any kind of container virtualization. */

        if (MANAGER_IS_USER(m))
                return false;

        if (detect_container() > 0)
                return false;

        return empty_or_root(m->cgroup_root);
}

bool unit_has_startup_cgroup_constraints(Unit *u) {
        assert(u);

        /* Returns true if this unit has any directives which apply during
         * startup/shutdown phases. */

        CGroupContext *c;

        c = unit_get_cgroup_context(u);
        if (!c)
                return false;

        return c->startup_cpu_shares != CGROUP_CPU_SHARES_INVALID ||
               c->startup_io_weight != CGROUP_WEIGHT_INVALID ||
               c->startup_blockio_weight != CGROUP_BLKIO_WEIGHT_INVALID ||
               c->startup_cpuset_cpus.set ||
               c->startup_cpuset_mems.set ||
               c->startup_memory_high_set ||
               c->startup_memory_max_set ||
               c->startup_memory_swap_max_set||
               c->startup_memory_zswap_max_set ||
               c->startup_memory_low_set;
}

bool unit_has_host_root_cgroup(Unit *u) {
        assert(u);

        /* Returns whether this unit manages the root cgroup. This will return true if this unit is the root slice and
         * the manager manages the root cgroup. */

        if (!manager_owns_host_root_cgroup(u->manager))
                return false;

        return unit_has_name(u, SPECIAL_ROOT_SLICE);
}

static int set_attribute_and_warn(Unit *u, const char *controller, const char *attribute, const char *value) {
        int r;

        r = cg_set_attribute(controller, u->cgroup_path, attribute, value);
        if (r < 0)
                log_unit_full_errno(u, LOG_LEVEL_CGROUP_WRITE(r), r, "Failed to set '%s' attribute on '%s' to '%.*s': %m",
                                    strna(attribute), empty_to_root(u->cgroup_path), (int) strcspn(value, NEWLINE), value);

        return r;
}

static void cgroup_compat_warn(void) {
        static bool cgroup_compat_warned = false;

        if (cgroup_compat_warned)
                return;

        log_warning("cgroup compatibility translation between legacy and unified hierarchy settings activated. "
                    "See cgroup-compat debug messages for details.");

        cgroup_compat_warned = true;
}

#define log_cgroup_compat(unit, fmt, ...) do {                                  \
                cgroup_compat_warn();                                           \
                log_unit_debug(unit, "cgroup-compat: " fmt, ##__VA_ARGS__);     \
        } while (false)

void cgroup_context_init(CGroupContext *c) {
        assert(c);

        /* Initialize everything to the kernel defaults. When initializing a bool member to 'true', make
         * sure to serialize in execute-serialize.c using serialize_bool() instead of
         * serialize_bool_elide(), as sd-executor will initialize here to 'true', but serialize_bool_elide()
         * skips serialization if the value is 'false' (as that's the common default), so if the value at
         * runtime is zero it would be lost after deserialization. Same when initializing uint64_t and other
         * values, update/add a conditional serialization check. This is to minimize the amount of
         * serialized data that is sent to the sd-executor, so that there is less work to do on the default
         * cases. */

        *c = (CGroupContext) {
                .cpu_weight = CGROUP_WEIGHT_INVALID,
                .startup_cpu_weight = CGROUP_WEIGHT_INVALID,
                .cpu_quota_per_sec_usec = USEC_INFINITY,
                .cpu_quota_period_usec = USEC_INFINITY,

                .cpu_shares = CGROUP_CPU_SHARES_INVALID,
                .startup_cpu_shares = CGROUP_CPU_SHARES_INVALID,

                .memory_high = CGROUP_LIMIT_MAX,
                .startup_memory_high = CGROUP_LIMIT_MAX,
                .memory_max = CGROUP_LIMIT_MAX,
                .startup_memory_max = CGROUP_LIMIT_MAX,
                .memory_swap_max = CGROUP_LIMIT_MAX,
                .startup_memory_swap_max = CGROUP_LIMIT_MAX,
                .memory_zswap_max = CGROUP_LIMIT_MAX,
                .startup_memory_zswap_max = CGROUP_LIMIT_MAX,

                .memory_limit = CGROUP_LIMIT_MAX,

                .io_weight = CGROUP_WEIGHT_INVALID,
                .startup_io_weight = CGROUP_WEIGHT_INVALID,

                .blockio_weight = CGROUP_BLKIO_WEIGHT_INVALID,
                .startup_blockio_weight = CGROUP_BLKIO_WEIGHT_INVALID,

                .tasks_max = CGROUP_TASKS_MAX_UNSET,

                .moom_swap = MANAGED_OOM_AUTO,
                .moom_mem_pressure = MANAGED_OOM_AUTO,
                .moom_preference = MANAGED_OOM_PREFERENCE_NONE,

                .memory_pressure_watch = _CGROUP_PRESSURE_WATCH_INVALID,
                .memory_pressure_threshold_usec = USEC_INFINITY,
        };
}

void cgroup_context_free_device_allow(CGroupContext *c, CGroupDeviceAllow *a) {
        assert(c);
        assert(a);

        LIST_REMOVE(device_allow, c->device_allow, a);
        free(a->path);
        free(a);
}

void cgroup_context_free_io_device_weight(CGroupContext *c, CGroupIODeviceWeight *w) {
        assert(c);
        assert(w);

        LIST_REMOVE(device_weights, c->io_device_weights, w);
        free(w->path);
        free(w);
}

void cgroup_context_free_io_device_latency(CGroupContext *c, CGroupIODeviceLatency *l) {
        assert(c);
        assert(l);

        LIST_REMOVE(device_latencies, c->io_device_latencies, l);
        free(l->path);
        free(l);
}

void cgroup_context_free_io_device_limit(CGroupContext *c, CGroupIODeviceLimit *l) {
        assert(c);
        assert(l);

        LIST_REMOVE(device_limits, c->io_device_limits, l);
        free(l->path);
        free(l);
}

void cgroup_context_free_blockio_device_weight(CGroupContext *c, CGroupBlockIODeviceWeight *w) {
        assert(c);
        assert(w);

        LIST_REMOVE(device_weights, c->blockio_device_weights, w);
        free(w->path);
        free(w);
}

void cgroup_context_free_blockio_device_bandwidth(CGroupContext *c, CGroupBlockIODeviceBandwidth *b) {
        assert(c);
        assert(b);

        LIST_REMOVE(device_bandwidths, c->blockio_device_bandwidths, b);
        free(b->path);
        free(b);
}

void cgroup_context_remove_bpf_foreign_program(CGroupContext *c, CGroupBPFForeignProgram *p) {
        assert(c);
        assert(p);

        LIST_REMOVE(programs, c->bpf_foreign_programs, p);
        free(p->bpffs_path);
        free(p);
}

void cgroup_context_remove_socket_bind(CGroupSocketBindItem **head) {
        assert(head);

        LIST_CLEAR(socket_bind_items, *head, free);
}

void cgroup_context_done(CGroupContext *c) {
        assert(c);

        while (c->io_device_weights)
                cgroup_context_free_io_device_weight(c, c->io_device_weights);

        while (c->io_device_latencies)
                cgroup_context_free_io_device_latency(c, c->io_device_latencies);

        while (c->io_device_limits)
                cgroup_context_free_io_device_limit(c, c->io_device_limits);

        while (c->blockio_device_weights)
                cgroup_context_free_blockio_device_weight(c, c->blockio_device_weights);

        while (c->blockio_device_bandwidths)
                cgroup_context_free_blockio_device_bandwidth(c, c->blockio_device_bandwidths);

        while (c->device_allow)
                cgroup_context_free_device_allow(c, c->device_allow);

        cgroup_context_remove_socket_bind(&c->socket_bind_allow);
        cgroup_context_remove_socket_bind(&c->socket_bind_deny);

        c->ip_address_allow = set_free(c->ip_address_allow);
        c->ip_address_deny = set_free(c->ip_address_deny);

        c->ip_filters_ingress = strv_free(c->ip_filters_ingress);
        c->ip_filters_egress = strv_free(c->ip_filters_egress);

        while (c->bpf_foreign_programs)
                cgroup_context_remove_bpf_foreign_program(c, c->bpf_foreign_programs);

        c->restrict_network_interfaces = set_free_free(c->restrict_network_interfaces);

        cpu_set_reset(&c->cpuset_cpus);
        cpu_set_reset(&c->startup_cpuset_cpus);
        cpu_set_reset(&c->cpuset_mems);
        cpu_set_reset(&c->startup_cpuset_mems);

        c->delegate_subgroup = mfree(c->delegate_subgroup);

        nft_set_context_clear(&c->nft_set_context);
}

static int unit_get_kernel_memory_limit(Unit *u, const char *file, uint64_t *ret) {
        assert(u);

        if (!u->cgroup_realized)
                return -EOWNERDEAD;

        return cg_get_attribute_as_uint64("memory", u->cgroup_path, file, ret);
}

static int unit_compare_memory_limit(Unit *u, const char *property_name, uint64_t *ret_unit_value, uint64_t *ret_kernel_value) {
        CGroupContext *c;
        CGroupMask m;
        const char *file;
        uint64_t unit_value;
        int r;

        /* Compare kernel memcg configuration against our internal systemd state. Unsupported (and will
         * return -ENODATA) on cgroup v1.
         *
         * Returns:
         *
         * <0: On error.
         *  0: If the kernel memory setting doesn't match our configuration.
         * >0: If the kernel memory setting matches our configuration.
         *
         * The following values are only guaranteed to be populated on return >=0:
         *
         * - ret_unit_value will contain our internal expected value for the unit, page-aligned.
         * - ret_kernel_value will contain the actual value presented by the kernel. */

        assert(u);

        r = cg_all_unified();
        if (r < 0)
                return log_debug_errno(r, "Failed to determine cgroup hierarchy version: %m");

        /* Unsupported on v1.
         *
         * We don't return ENOENT, since that could actually mask a genuine problem where somebody else has
         * silently masked the controller. */
        if (r == 0)
                return -ENODATA;

        /* The root slice doesn't have any controller files, so we can't compare anything. */
        if (unit_has_name(u, SPECIAL_ROOT_SLICE))
                return -ENODATA;

        /* It's possible to have MemoryFoo set without systemd wanting to have the memory controller enabled,
         * for example, in the case of DisableControllers= or cgroup_disable on the kernel command line. To
         * avoid specious errors in these scenarios, check that we even expect the memory controller to be
         * enabled at all. */
        m = unit_get_target_mask(u);
        if (!FLAGS_SET(m, CGROUP_MASK_MEMORY))
                return -ENODATA;

        assert_se(c = unit_get_cgroup_context(u));

        bool startup = u->manager && IN_SET(manager_state(u->manager), MANAGER_STARTING, MANAGER_INITIALIZING, MANAGER_STOPPING);

        if (streq(property_name, "MemoryLow")) {
                unit_value = unit_get_ancestor_memory_low(u);
                file = "memory.low";
        } else if (startup && streq(property_name, "StartupMemoryLow")) {
                unit_value = unit_get_ancestor_startup_memory_low(u);
                file = "memory.low";
        } else if (streq(property_name, "MemoryMin")) {
                unit_value = unit_get_ancestor_memory_min(u);
                file = "memory.min";
        } else if (streq(property_name, "MemoryHigh")) {
                unit_value = c->memory_high;
                file = "memory.high";
        } else if (startup && streq(property_name, "StartupMemoryHigh")) {
                unit_value = c->startup_memory_high;
                file = "memory.high";
        } else if (streq(property_name, "MemoryMax")) {
                unit_value = c->memory_max;
                file = "memory.max";
        } else if (startup && streq(property_name, "StartupMemoryMax")) {
                unit_value = c->startup_memory_max;
                file = "memory.max";
        } else if (streq(property_name, "MemorySwapMax")) {
                unit_value = c->memory_swap_max;
                file = "memory.swap.max";
        } else if (startup && streq(property_name, "StartupMemorySwapMax")) {
                unit_value = c->startup_memory_swap_max;
                file = "memory.swap.max";
        } else if (streq(property_name, "MemoryZSwapMax")) {
                unit_value = c->memory_zswap_max;
                file = "memory.zswap.max";
        } else if (startup && streq(property_name, "StartupMemoryZSwapMax")) {
                unit_value = c->startup_memory_zswap_max;
                file = "memory.zswap.max";
        } else
                return -EINVAL;

        r = unit_get_kernel_memory_limit(u, file, ret_kernel_value);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to parse %s: %m", file);

        /* It's intended (soon) in a future kernel to not expose cgroup memory limits rounded to page
         * boundaries, but instead separate the user-exposed limit, which is whatever userspace told us, from
         * our internal page-counting. To support those future kernels, just check the value itself first
         * without any page-alignment. */
        if (*ret_kernel_value == unit_value) {
                *ret_unit_value = unit_value;
                return 1;
        }

        /* The current kernel behaviour, by comparison, is that even if you write a particular number of
         * bytes into a cgroup memory file, it always returns that number page-aligned down (since the kernel
         * internally stores cgroup limits in pages). As such, so long as it aligns properly, everything is
         * cricket. */
        if (unit_value != CGROUP_LIMIT_MAX)
                unit_value = PAGE_ALIGN_DOWN(unit_value);

        *ret_unit_value = unit_value;

        return *ret_kernel_value == *ret_unit_value;
}

#define FORMAT_CGROUP_DIFF_MAX 128

static char *format_cgroup_memory_limit_comparison(char *buf, size_t l, Unit *u, const char *property_name) {
        uint64_t kval, sval;
        int r;

        assert(u);
        assert(buf);
        assert(l > 0);

        r = unit_compare_memory_limit(u, property_name, &sval, &kval);

        /* memory.swap.max is special in that it relies on CONFIG_MEMCG_SWAP (and the default swapaccount=1).
         * In the absence of reliably being able to detect whether memcg swap support is available or not,
         * only complain if the error is not ENOENT. This is similarly the case for memory.zswap.max relying
         * on CONFIG_ZSWAP. */
        if (r > 0 || IN_SET(r, -ENODATA, -EOWNERDEAD) ||
            (r == -ENOENT && STR_IN_SET(property_name,
                                        "MemorySwapMax",
                                        "StartupMemorySwapMax",
                                        "MemoryZSwapMax",
                                        "StartupMemoryZSwapMax")))
                buf[0] = 0;
        else if (r < 0) {
                errno = -r;
                (void) snprintf(buf, l, " (error getting kernel value: %m)");
        } else
                (void) snprintf(buf, l, " (different value in kernel: %" PRIu64 ")", kval);

        return buf;
}

const char *cgroup_device_permissions_to_string(CGroupDevicePermissions p) {
        static const char *table[_CGROUP_DEVICE_PERMISSIONS_MAX] = {
                /* Lets simply define a table with every possible combination. As long as those are just 8 we
                 * can get away with it. If this ever grows to more we need to revisit this logic though. */
                [0]                                                          = "",
                [CGROUP_DEVICE_READ]                                         = "r",
                [CGROUP_DEVICE_WRITE]                                        = "w",
                [CGROUP_DEVICE_MKNOD]                                        = "m",
                [CGROUP_DEVICE_READ|CGROUP_DEVICE_WRITE]                     = "rw",
                [CGROUP_DEVICE_READ|CGROUP_DEVICE_MKNOD]                     = "rm",
                [CGROUP_DEVICE_WRITE|CGROUP_DEVICE_MKNOD]                    = "wm",
                [CGROUP_DEVICE_READ|CGROUP_DEVICE_WRITE|CGROUP_DEVICE_MKNOD] = "rwm",
        };

        if (p < 0 || p >= _CGROUP_DEVICE_PERMISSIONS_MAX)
                return NULL;

        return table[p];
}

CGroupDevicePermissions cgroup_device_permissions_from_string(const char *s) {
        CGroupDevicePermissions p = 0;

        if (!s)
                return _CGROUP_DEVICE_PERMISSIONS_INVALID;

        for (const char *c = s; *c; c++) {
                if (*c == 'r')
                        p |= CGROUP_DEVICE_READ;
                else if (*c == 'w')
                        p |= CGROUP_DEVICE_WRITE;
                else if (*c == 'm')
                        p |= CGROUP_DEVICE_MKNOD;
                else
                        return _CGROUP_DEVICE_PERMISSIONS_INVALID;
        }

        return p;
}

void cgroup_context_dump(Unit *u, FILE* f, const char *prefix) {
        _cleanup_free_ char *disable_controllers_str = NULL, *delegate_controllers_str = NULL, *cpuset_cpus = NULL, *cpuset_mems = NULL, *startup_cpuset_cpus = NULL, *startup_cpuset_mems = NULL;
        CGroupContext *c;
        struct in_addr_prefix *iaai;

        char cda[FORMAT_CGROUP_DIFF_MAX];
        char cdb[FORMAT_CGROUP_DIFF_MAX];
        char cdc[FORMAT_CGROUP_DIFF_MAX];
        char cdd[FORMAT_CGROUP_DIFF_MAX];
        char cde[FORMAT_CGROUP_DIFF_MAX];
        char cdf[FORMAT_CGROUP_DIFF_MAX];
        char cdg[FORMAT_CGROUP_DIFF_MAX];
        char cdh[FORMAT_CGROUP_DIFF_MAX];
        char cdi[FORMAT_CGROUP_DIFF_MAX];
        char cdj[FORMAT_CGROUP_DIFF_MAX];
        char cdk[FORMAT_CGROUP_DIFF_MAX];

        assert(u);
        assert(f);

        assert_se(c = unit_get_cgroup_context(u));

        prefix = strempty(prefix);

        (void) cg_mask_to_string(c->disable_controllers, &disable_controllers_str);
        (void) cg_mask_to_string(c->delegate_controllers, &delegate_controllers_str);

        /* "Delegate=" means "yes, but no controllers". Show this as "(none)". */
        const char *delegate_str = delegate_controllers_str ?: c->delegate ? "(none)" : "no";

        cpuset_cpus = cpu_set_to_range_string(&c->cpuset_cpus);
        startup_cpuset_cpus = cpu_set_to_range_string(&c->startup_cpuset_cpus);
        cpuset_mems = cpu_set_to_range_string(&c->cpuset_mems);
        startup_cpuset_mems = cpu_set_to_range_string(&c->startup_cpuset_mems);

        fprintf(f,
                "%sCPUAccounting: %s\n"
                "%sIOAccounting: %s\n"
                "%sBlockIOAccounting: %s\n"
                "%sMemoryAccounting: %s\n"
                "%sTasksAccounting: %s\n"
                "%sIPAccounting: %s\n"
                "%sCPUWeight: %" PRIu64 "\n"
                "%sStartupCPUWeight: %" PRIu64 "\n"
                "%sCPUShares: %" PRIu64 "\n"
                "%sStartupCPUShares: %" PRIu64 "\n"
                "%sCPUQuotaPerSecSec: %s\n"
                "%sCPUQuotaPeriodSec: %s\n"
                "%sAllowedCPUs: %s\n"
                "%sStartupAllowedCPUs: %s\n"
                "%sAllowedMemoryNodes: %s\n"
                "%sStartupAllowedMemoryNodes: %s\n"
                "%sIOWeight: %" PRIu64 "\n"
                "%sStartupIOWeight: %" PRIu64 "\n"
                "%sBlockIOWeight: %" PRIu64 "\n"
                "%sStartupBlockIOWeight: %" PRIu64 "\n"
                "%sDefaultMemoryMin: %" PRIu64 "\n"
                "%sDefaultMemoryLow: %" PRIu64 "\n"
                "%sMemoryMin: %" PRIu64 "%s\n"
                "%sMemoryLow: %" PRIu64 "%s\n"
                "%sStartupMemoryLow: %" PRIu64 "%s\n"
                "%sMemoryHigh: %" PRIu64 "%s\n"
                "%sStartupMemoryHigh: %" PRIu64 "%s\n"
                "%sMemoryMax: %" PRIu64 "%s\n"
                "%sStartupMemoryMax: %" PRIu64 "%s\n"
                "%sMemorySwapMax: %" PRIu64 "%s\n"
                "%sStartupMemorySwapMax: %" PRIu64 "%s\n"
                "%sMemoryZSwapMax: %" PRIu64 "%s\n"
                "%sStartupMemoryZSwapMax: %" PRIu64 "%s\n"
                "%sMemoryLimit: %" PRIu64 "\n"
                "%sTasksMax: %" PRIu64 "\n"
                "%sDevicePolicy: %s\n"
                "%sDisableControllers: %s\n"
                "%sDelegate: %s\n"
                "%sManagedOOMSwap: %s\n"
                "%sManagedOOMMemoryPressure: %s\n"
                "%sManagedOOMMemoryPressureLimit: " PERMYRIAD_AS_PERCENT_FORMAT_STR "\n"
                "%sManagedOOMPreference: %s\n"
                "%sMemoryPressureWatch: %s\n"
                "%sCoredumpReceive: %s\n",
                prefix, yes_no(c->cpu_accounting),
                prefix, yes_no(c->io_accounting),
                prefix, yes_no(c->blockio_accounting),
                prefix, yes_no(c->memory_accounting),
                prefix, yes_no(c->tasks_accounting),
                prefix, yes_no(c->ip_accounting),
                prefix, c->cpu_weight,
                prefix, c->startup_cpu_weight,
                prefix, c->cpu_shares,
                prefix, c->startup_cpu_shares,
                prefix, FORMAT_TIMESPAN(c->cpu_quota_per_sec_usec, 1),
                prefix, FORMAT_TIMESPAN(c->cpu_quota_period_usec, 1),
                prefix, strempty(cpuset_cpus),
                prefix, strempty(startup_cpuset_cpus),
                prefix, strempty(cpuset_mems),
                prefix, strempty(startup_cpuset_mems),
                prefix, c->io_weight,
                prefix, c->startup_io_weight,
                prefix, c->blockio_weight,
                prefix, c->startup_blockio_weight,
                prefix, c->default_memory_min,
                prefix, c->default_memory_low,
                prefix, c->memory_min, format_cgroup_memory_limit_comparison(cda, sizeof(cda), u, "MemoryMin"),
                prefix, c->memory_low, format_cgroup_memory_limit_comparison(cdb, sizeof(cdb), u, "MemoryLow"),
                prefix, c->startup_memory_low, format_cgroup_memory_limit_comparison(cdc, sizeof(cdc), u, "StartupMemoryLow"),
                prefix, c->memory_high, format_cgroup_memory_limit_comparison(cdd, sizeof(cdd), u, "MemoryHigh"),
                prefix, c->startup_memory_high, format_cgroup_memory_limit_comparison(cde, sizeof(cde), u, "StartupMemoryHigh"),
                prefix, c->memory_max, format_cgroup_memory_limit_comparison(cdf, sizeof(cdf), u, "MemoryMax"),
                prefix, c->startup_memory_max, format_cgroup_memory_limit_comparison(cdg, sizeof(cdg), u, "StartupMemoryMax"),
                prefix, c->memory_swap_max, format_cgroup_memory_limit_comparison(cdh, sizeof(cdh), u, "MemorySwapMax"),
                prefix, c->startup_memory_swap_max, format_cgroup_memory_limit_comparison(cdi, sizeof(cdi), u, "StartupMemorySwapMax"),
                prefix, c->memory_zswap_max, format_cgroup_memory_limit_comparison(cdj, sizeof(cdj), u, "MemoryZSwapMax"),
                prefix, c->startup_memory_zswap_max, format_cgroup_memory_limit_comparison(cdk, sizeof(cdk), u, "StartupMemoryZSwapMax"),
                prefix, c->memory_limit,
                prefix, cgroup_tasks_max_resolve(&c->tasks_max),
                prefix, cgroup_device_policy_to_string(c->device_policy),
                prefix, strempty(disable_controllers_str),
                prefix, delegate_str,
                prefix, managed_oom_mode_to_string(c->moom_swap),
                prefix, managed_oom_mode_to_string(c->moom_mem_pressure),
                prefix, PERMYRIAD_AS_PERCENT_FORMAT_VAL(UINT32_SCALE_TO_PERMYRIAD(c->moom_mem_pressure_limit)),
                prefix, managed_oom_preference_to_string(c->moom_preference),
                prefix, cgroup_pressure_watch_to_string(c->memory_pressure_watch),
                prefix, yes_no(c->coredump_receive));

        if (c->delegate_subgroup)
                fprintf(f, "%sDelegateSubgroup: %s\n",
                        prefix, c->delegate_subgroup);

        if (c->memory_pressure_threshold_usec != USEC_INFINITY)
                fprintf(f, "%sMemoryPressureThresholdSec: %s\n",
                        prefix, FORMAT_TIMESPAN(c->memory_pressure_threshold_usec, 1));

        LIST_FOREACH(device_allow, a, c->device_allow)
                /* strna() below should be redundant, for avoiding -Werror=format-overflow= error. See #30223. */
                fprintf(f,
                        "%sDeviceAllow: %s %s\n",
                        prefix,
                        a->path,
                        strna(cgroup_device_permissions_to_string(a->permissions)));

        LIST_FOREACH(device_weights, iw, c->io_device_weights)
                fprintf(f,
                        "%sIODeviceWeight: %s %" PRIu64 "\n",
                        prefix,
                        iw->path,
                        iw->weight);

        LIST_FOREACH(device_latencies, l, c->io_device_latencies)
                fprintf(f,
                        "%sIODeviceLatencyTargetSec: %s %s\n",
                        prefix,
                        l->path,
                        FORMAT_TIMESPAN(l->target_usec, 1));

        LIST_FOREACH(device_limits, il, c->io_device_limits)
                for (CGroupIOLimitType type = 0; type < _CGROUP_IO_LIMIT_TYPE_MAX; type++)
                        if (il->limits[type] != cgroup_io_limit_defaults[type])
                                fprintf(f,
                                        "%s%s: %s %s\n",
                                        prefix,
                                        cgroup_io_limit_type_to_string(type),
                                        il->path,
                                        FORMAT_BYTES(il->limits[type]));

        LIST_FOREACH(device_weights, w, c->blockio_device_weights)
                fprintf(f,
                        "%sBlockIODeviceWeight: %s %" PRIu64,
                        prefix,
                        w->path,
                        w->weight);

        LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths) {
                if (b->rbps != CGROUP_LIMIT_MAX)
                        fprintf(f,
                                "%sBlockIOReadBandwidth: %s %s\n",
                                prefix,
                                b->path,
                                FORMAT_BYTES(b->rbps));
                if (b->wbps != CGROUP_LIMIT_MAX)
                        fprintf(f,
                                "%sBlockIOWriteBandwidth: %s %s\n",
                                prefix,
                                b->path,
                                FORMAT_BYTES(b->wbps));
        }

        SET_FOREACH(iaai, c->ip_address_allow)
                fprintf(f, "%sIPAddressAllow: %s\n", prefix,
                        IN_ADDR_PREFIX_TO_STRING(iaai->family, &iaai->address, iaai->prefixlen));
        SET_FOREACH(iaai, c->ip_address_deny)
                fprintf(f, "%sIPAddressDeny: %s\n", prefix,
                        IN_ADDR_PREFIX_TO_STRING(iaai->family, &iaai->address, iaai->prefixlen));

        STRV_FOREACH(path, c->ip_filters_ingress)
                fprintf(f, "%sIPIngressFilterPath: %s\n", prefix, *path);
        STRV_FOREACH(path, c->ip_filters_egress)
                fprintf(f, "%sIPEgressFilterPath: %s\n", prefix, *path);

        LIST_FOREACH(programs, p, c->bpf_foreign_programs)
                fprintf(f, "%sBPFProgram: %s:%s",
                        prefix, bpf_cgroup_attach_type_to_string(p->attach_type), p->bpffs_path);

        if (c->socket_bind_allow) {
                fprintf(f, "%sSocketBindAllow: ", prefix);
                cgroup_context_dump_socket_bind_items(c->socket_bind_allow, f);
                fputc('\n', f);
        }

        if (c->socket_bind_deny) {
                fprintf(f, "%sSocketBindDeny: ", prefix);
                cgroup_context_dump_socket_bind_items(c->socket_bind_deny, f);
                fputc('\n', f);
        }

        if (c->restrict_network_interfaces) {
                char *iface;
                SET_FOREACH(iface, c->restrict_network_interfaces)
                        fprintf(f, "%sRestrictNetworkInterfaces: %s\n", prefix, iface);
        }

        FOREACH_ARRAY(nft_set, c->nft_set_context.sets, c->nft_set_context.n_sets)
                fprintf(f, "%sNFTSet: %s:%s:%s:%s\n", prefix, nft_set_source_to_string(nft_set->source),
                        nfproto_to_string(nft_set->nfproto), nft_set->table, nft_set->set);
}

void cgroup_context_dump_socket_bind_item(const CGroupSocketBindItem *item, FILE *f) {
        const char *family, *colon1, *protocol = "", *colon2 = "";

        family = strempty(af_to_ipv4_ipv6(item->address_family));
        colon1 = isempty(family) ? "" : ":";

        if (item->ip_protocol != 0) {
                protocol = ip_protocol_to_tcp_udp(item->ip_protocol);
                colon2 = ":";
        }

        if (item->nr_ports == 0)
                fprintf(f, "%s%s%s%sany", family, colon1, protocol, colon2);
        else if (item->nr_ports == 1)
                fprintf(f, "%s%s%s%s%" PRIu16, family, colon1, protocol, colon2, item->port_min);
        else {
                uint16_t port_max = item->port_min + item->nr_ports - 1;
                fprintf(f, "%s%s%s%s%" PRIu16 "-%" PRIu16, family, colon1, protocol, colon2,
                        item->port_min, port_max);
        }
}

void cgroup_context_dump_socket_bind_items(const CGroupSocketBindItem *items, FILE *f) {
        bool first = true;

        LIST_FOREACH(socket_bind_items, bi, items) {
                if (first)
                        first = false;
                else
                        fputc(' ', f);

                cgroup_context_dump_socket_bind_item(bi, f);
        }
}

int cgroup_context_add_device_allow(CGroupContext *c, const char *dev, CGroupDevicePermissions p) {
        _cleanup_free_ CGroupDeviceAllow *a = NULL;
        _cleanup_free_ char *d = NULL;

        assert(c);
        assert(dev);
        assert(p >= 0 && p < _CGROUP_DEVICE_PERMISSIONS_MAX);

        if (p == 0)
                p = _CGROUP_DEVICE_PERMISSIONS_ALL;

        a = new(CGroupDeviceAllow, 1);
        if (!a)
                return -ENOMEM;

        d = strdup(dev);
        if (!d)
                return -ENOMEM;

        *a = (CGroupDeviceAllow) {
                .path = TAKE_PTR(d),
                .permissions = p,
        };

        LIST_PREPEND(device_allow, c->device_allow, a);
        TAKE_PTR(a);

        return 0;
}

int cgroup_context_add_or_update_device_allow(CGroupContext *c, const char *dev, CGroupDevicePermissions p) {
        assert(c);
        assert(dev);
        assert(p >= 0 && p < _CGROUP_DEVICE_PERMISSIONS_MAX);

        if (p == 0)
                p = _CGROUP_DEVICE_PERMISSIONS_ALL;

        LIST_FOREACH(device_allow, b, c->device_allow)
                if (path_equal(b->path, dev)) {
                        b->permissions = p;
                        return 0;
                }

        return cgroup_context_add_device_allow(c, dev, p);
}

int cgroup_context_add_bpf_foreign_program(CGroupContext *c, uint32_t attach_type, const char *bpffs_path) {
        CGroupBPFForeignProgram *p;
        _cleanup_free_ char *d = NULL;

        assert(c);
        assert(bpffs_path);

        if (!path_is_normalized(bpffs_path) || !path_is_absolute(bpffs_path))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Path is not normalized: %m");

        d = strdup(bpffs_path);
        if (!d)
                return log_oom();

        p = new(CGroupBPFForeignProgram, 1);
        if (!p)
                return log_oom();

        *p = (CGroupBPFForeignProgram) {
                .attach_type = attach_type,
                .bpffs_path = TAKE_PTR(d),
        };

        LIST_PREPEND(programs, c->bpf_foreign_programs, TAKE_PTR(p));

        return 0;
}

#define UNIT_DEFINE_ANCESTOR_MEMORY_LOOKUP(entry)                       \
        uint64_t unit_get_ancestor_##entry(Unit *u) {                   \
                CGroupContext *c;                                       \
                                                                        \
                /* 1. Is entry set in this unit? If so, use that.       \
                 * 2. Is the default for this entry set in any          \
                 *    ancestor? If so, use that.                        \
                 * 3. Otherwise, return CGROUP_LIMIT_MIN. */            \
                                                                        \
                assert(u);                                              \
                                                                        \
                c = unit_get_cgroup_context(u);                         \
                if (c && c->entry##_set)                                \
                        return c->entry;                                \
                                                                        \
                while ((u = UNIT_GET_SLICE(u))) {                       \
                        c = unit_get_cgroup_context(u);                 \
                        if (c && c->default_##entry##_set)              \
                                return c->default_##entry;              \
                }                                                       \
                                                                        \
                /* We've reached the root, but nobody had default for   \
                 * this entry set, so set it to the kernel default. */  \
                return CGROUP_LIMIT_MIN;                                \
}

UNIT_DEFINE_ANCESTOR_MEMORY_LOOKUP(memory_low);
UNIT_DEFINE_ANCESTOR_MEMORY_LOOKUP(startup_memory_low);
UNIT_DEFINE_ANCESTOR_MEMORY_LOOKUP(memory_min);

static void unit_set_xattr_graceful(Unit *u, const char *name, const void *data, size_t size) {
        int r;

        assert(u);
        assert(name);

        if (!u->cgroup_path)
                return;

        r = cg_set_xattr(u->cgroup_path, name, data, size, 0);
        if (r < 0)
                log_unit_debug_errno(u, r, "Failed to set '%s' xattr on control group %s, ignoring: %m", name, empty_to_root(u->cgroup_path));
}

static void unit_remove_xattr_graceful(Unit *u, const char *name) {
        int r;

        assert(u);
        assert(name);

        if (!u->cgroup_path)
                return;

        r = cg_remove_xattr(u->cgroup_path, name);
        if (r < 0 && !ERRNO_IS_XATTR_ABSENT(r))
                log_unit_debug_errno(u, r, "Failed to remove '%s' xattr flag on control group %s, ignoring: %m", name, empty_to_root(u->cgroup_path));
}

static void cgroup_oomd_xattr_apply(Unit *u) {
        CGroupContext *c;

        assert(u);

        c = unit_get_cgroup_context(u);
        if (!c)
                return;

        if (c->moom_preference == MANAGED_OOM_PREFERENCE_OMIT)
                unit_set_xattr_graceful(u, "user.oomd_omit", "1", 1);

        if (c->moom_preference == MANAGED_OOM_PREFERENCE_AVOID)
                unit_set_xattr_graceful(u, "user.oomd_avoid", "1", 1);

        if (c->moom_preference != MANAGED_OOM_PREFERENCE_AVOID)
                unit_remove_xattr_graceful(u, "user.oomd_avoid");

        if (c->moom_preference != MANAGED_OOM_PREFERENCE_OMIT)
                unit_remove_xattr_graceful(u, "user.oomd_omit");
}

static int cgroup_log_xattr_apply(Unit *u) {
        ExecContext *c;
        size_t len, allowed_patterns_len, denied_patterns_len;
        _cleanup_free_ char *patterns = NULL, *allowed_patterns = NULL, *denied_patterns = NULL;
        char *last;
        int r;

        assert(u);

        c = unit_get_exec_context(u);
        if (!c)
                /* Some unit types have a cgroup context but no exec context, so we do not log
                 * any error here to avoid confusion. */
                return 0;

        if (set_isempty(c->log_filter_allowed_patterns) && set_isempty(c->log_filter_denied_patterns)) {
                unit_remove_xattr_graceful(u, "user.journald_log_filter_patterns");
                return 0;
        }

        r = set_make_nulstr(c->log_filter_allowed_patterns, &allowed_patterns, &allowed_patterns_len);
        if (r < 0)
                return log_debug_errno(r, "Failed to make nulstr from set: %m");

        r = set_make_nulstr(c->log_filter_denied_patterns, &denied_patterns, &denied_patterns_len);
        if (r < 0)
                return log_debug_errno(r, "Failed to make nulstr from set: %m");

        /* Use nul character separated strings without trailing nul */
        allowed_patterns_len = LESS_BY(allowed_patterns_len, 1u);
        denied_patterns_len = LESS_BY(denied_patterns_len, 1u);

        len = allowed_patterns_len + 1 + denied_patterns_len;
        patterns = new(char, len);
        if (!patterns)
                return log_oom_debug();

        last = mempcpy_safe(patterns, allowed_patterns, allowed_patterns_len);
        *(last++) = '\xff';
        memcpy_safe(last, denied_patterns, denied_patterns_len);

        unit_set_xattr_graceful(u, "user.journald_log_filter_patterns", patterns, len);

        return 0;
}

static void cgroup_invocation_id_xattr_apply(Unit *u) {
        bool b;

        assert(u);

        b = !sd_id128_is_null(u->invocation_id);
        FOREACH_STRING(xn, "trusted.invocation_id", "user.invocation_id") {
                if (b)
                        unit_set_xattr_graceful(u, xn, SD_ID128_TO_STRING(u->invocation_id), 32);
                else
                        unit_remove_xattr_graceful(u, xn);
        }
}

static void cgroup_coredump_xattr_apply(Unit *u) {
        CGroupContext *c;

        assert(u);

        c = unit_get_cgroup_context(u);
        if (!c)
                return;

        if (unit_cgroup_delegate(u) && c->coredump_receive)
                unit_set_xattr_graceful(u, "user.coredump_receive", "1", 1);
        else
                unit_remove_xattr_graceful(u, "user.coredump_receive");
}

static void cgroup_delegate_xattr_apply(Unit *u) {
        bool b;

        assert(u);

        /* Indicate on the cgroup whether delegation is on, via an xattr. This is best-effort, as old kernels
         * didn't support xattrs on cgroups at all. Later they got support for setting 'trusted.*' xattrs,
         * and even later 'user.*' xattrs. We started setting this field when 'trusted.*' was added, and
         * given this is now pretty much API, let's continue to support that. But also set 'user.*' as well,
         * since it is readable by any user, not just CAP_SYS_ADMIN. This hence comes with slightly weaker
         * security (as users who got delegated cgroups could turn it off if they like), but this shouldn't
         * be a big problem given this communicates delegation state to clients, but the manager never reads
         * it. */
        b = unit_cgroup_delegate(u);
        FOREACH_STRING(xn, "trusted.delegate", "user.delegate") {
                if (b)
                        unit_set_xattr_graceful(u, xn, "1", 1);
                else
                        unit_remove_xattr_graceful(u, xn);
        }
}

static void cgroup_survive_xattr_apply(Unit *u) {
        int r;

        assert(u);

        if (u->survive_final_kill_signal) {
                r = cg_set_xattr(
                                u->cgroup_path,
                                "user.survive_final_kill_signal",
                                "1",
                                1,
                                /* flags= */ 0);
                /* user xattr support was added in kernel v5.7 */
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        r = cg_set_xattr(
                                        u->cgroup_path,
                                        "trusted.survive_final_kill_signal",
                                        "1",
                                        1,
                                        /* flags= */ 0);
                if (r < 0)
                        log_unit_debug_errno(u,
                                             r,
                                             "Failed to set 'survive_final_kill_signal' xattr on control "
                                             "group %s, ignoring: %m",
                                             empty_to_root(u->cgroup_path));
        } else {
                unit_remove_xattr_graceful(u, "user.survive_final_kill_signal");
                unit_remove_xattr_graceful(u, "trusted.survive_final_kill_signal");
        }
}

static void cgroup_xattr_apply(Unit *u) {
        assert(u);

        /* The 'user.*' xattrs can be set from a user manager. */
        cgroup_oomd_xattr_apply(u);
        cgroup_log_xattr_apply(u);
        cgroup_coredump_xattr_apply(u);

        if (!MANAGER_IS_SYSTEM(u->manager))
                return;

        cgroup_invocation_id_xattr_apply(u);
        cgroup_delegate_xattr_apply(u);
        cgroup_survive_xattr_apply(u);
}

static int lookup_block_device(const char *p, dev_t *ret) {
        dev_t rdev, dev = 0;
        mode_t mode;
        int r;

        assert(p);
        assert(ret);

        r = device_path_parse_major_minor(p, &mode, &rdev);
        if (r == -ENODEV) { /* not a parsable device node, need to go to disk */
                struct stat st;

                if (stat(p, &st) < 0)
                        return log_warning_errno(errno, "Couldn't stat device '%s': %m", p);

                mode = st.st_mode;
                rdev = st.st_rdev;
                dev = st.st_dev;
        } else if (r < 0)
                return log_warning_errno(r, "Failed to parse major/minor from path '%s': %m", p);

        if (S_ISCHR(mode))
                return log_warning_errno(SYNTHETIC_ERRNO(ENOTBLK),
                                         "Device node '%s' is a character device, but block device needed.", p);
        if (S_ISBLK(mode))
                *ret = rdev;
        else if (major(dev) != 0)
                *ret = dev; /* If this is not a device node then use the block device this file is stored on */
        else {
                /* If this is btrfs, getting the backing block device is a bit harder */
                r = btrfs_get_block_device(p, ret);
                if (r == -ENOTTY)
                        return log_warning_errno(SYNTHETIC_ERRNO(ENODEV),
                                                 "'%s' is not a block device node, and file system block device cannot be determined or is not local.", p);
                if (r < 0)
                        return log_warning_errno(r, "Failed to determine block device backing btrfs file system '%s': %m", p);
        }

        /* If this is a LUKS/DM device, recursively try to get the originating block device */
        while (block_get_originating(*ret, ret) > 0);

        /* If this is a partition, try to get the originating block device */
        (void) block_get_whole_disk(*ret, ret);
        return 0;
}

static bool cgroup_context_has_cpu_weight(CGroupContext *c) {
        return c->cpu_weight != CGROUP_WEIGHT_INVALID ||
                c->startup_cpu_weight != CGROUP_WEIGHT_INVALID;
}

static bool cgroup_context_has_cpu_shares(CGroupContext *c) {
        return c->cpu_shares != CGROUP_CPU_SHARES_INVALID ||
                c->startup_cpu_shares != CGROUP_CPU_SHARES_INVALID;
}

static bool cgroup_context_has_allowed_cpus(CGroupContext *c) {
        return c->cpuset_cpus.set || c->startup_cpuset_cpus.set;
}

static bool cgroup_context_has_allowed_mems(CGroupContext *c) {
        return c->cpuset_mems.set || c->startup_cpuset_mems.set;
}

uint64_t cgroup_context_cpu_weight(CGroupContext *c, ManagerState state) {
        assert(c);

        if (IN_SET(state, MANAGER_STARTING, MANAGER_INITIALIZING, MANAGER_STOPPING) &&
            c->startup_cpu_weight != CGROUP_WEIGHT_INVALID)
                return c->startup_cpu_weight;
        else if (c->cpu_weight != CGROUP_WEIGHT_INVALID)
                return c->cpu_weight;
        else
                return CGROUP_WEIGHT_DEFAULT;
}

static uint64_t cgroup_context_cpu_shares(CGroupContext *c, ManagerState state) {
        if (IN_SET(state, MANAGER_STARTING, MANAGER_INITIALIZING, MANAGER_STOPPING) &&
            c->startup_cpu_shares != CGROUP_CPU_SHARES_INVALID)
                return c->startup_cpu_shares;
        else if (c->cpu_shares != CGROUP_CPU_SHARES_INVALID)
                return c->cpu_shares;
        else
                return CGROUP_CPU_SHARES_DEFAULT;
}

static CPUSet *cgroup_context_allowed_cpus(CGroupContext *c, ManagerState state) {
        if (IN_SET(state, MANAGER_STARTING, MANAGER_INITIALIZING, MANAGER_STOPPING) &&
            c->startup_cpuset_cpus.set)
                return &c->startup_cpuset_cpus;
        else
                return &c->cpuset_cpus;
}

static CPUSet *cgroup_context_allowed_mems(CGroupContext *c, ManagerState state) {
        if (IN_SET(state, MANAGER_STARTING, MANAGER_INITIALIZING, MANAGER_STOPPING) &&
            c->startup_cpuset_mems.set)
                return &c->startup_cpuset_mems;
        else
                return &c->cpuset_mems;
}

usec_t cgroup_cpu_adjust_period(usec_t period, usec_t quota, usec_t resolution, usec_t max_period) {
        /* kernel uses a minimum resolution of 1ms, so both period and (quota * period)
         * need to be higher than that boundary. quota is specified in USecPerSec.
         * Additionally, period must be at most max_period. */
        assert(quota > 0);

        return MIN(MAX3(period, resolution, resolution * USEC_PER_SEC / quota), max_period);
}

static usec_t cgroup_cpu_adjust_period_and_log(Unit *u, usec_t period, usec_t quota) {
        usec_t new_period;

        if (quota == USEC_INFINITY)
                /* Always use default period for infinity quota. */
                return CGROUP_CPU_QUOTA_DEFAULT_PERIOD_USEC;

        if (period == USEC_INFINITY)
                /* Default period was requested. */
                period = CGROUP_CPU_QUOTA_DEFAULT_PERIOD_USEC;

        /* Clamp to interval [1ms, 1s] */
        new_period = cgroup_cpu_adjust_period(period, quota, USEC_PER_MSEC, USEC_PER_SEC);

        if (new_period != period) {
                log_unit_full(u, u->warned_clamping_cpu_quota_period ? LOG_DEBUG : LOG_WARNING,
                              "Clamping CPU interval for cpu.max: period is now %s",
                              FORMAT_TIMESPAN(new_period, 1));
                u->warned_clamping_cpu_quota_period = true;
        }

        return new_period;
}

static void cgroup_apply_unified_cpu_weight(Unit *u, uint64_t weight) {
        char buf[DECIMAL_STR_MAX(uint64_t) + 2];

        if (weight == CGROUP_WEIGHT_IDLE)
                return;
        xsprintf(buf, "%" PRIu64 "\n", weight);
        (void) set_attribute_and_warn(u, "cpu", "cpu.weight", buf);
}

static void cgroup_apply_unified_cpu_idle(Unit *u, uint64_t weight) {
        int r;
        bool is_idle;
        const char *idle_val;

        is_idle = weight == CGROUP_WEIGHT_IDLE;
        idle_val = one_zero(is_idle);
        r = cg_set_attribute("cpu", u->cgroup_path, "cpu.idle", idle_val);
        if (r < 0 && (r != -ENOENT || is_idle))
                log_unit_full_errno(u, LOG_LEVEL_CGROUP_WRITE(r), r, "Failed to set '%s' attribute on '%s' to '%s': %m",
                                    "cpu.idle", empty_to_root(u->cgroup_path), idle_val);
}

static void cgroup_apply_unified_cpu_quota(Unit *u, usec_t quota, usec_t period) {
        char buf[(DECIMAL_STR_MAX(usec_t) + 1) * 2 + 1];

        period = cgroup_cpu_adjust_period_and_log(u, period, quota);
        if (quota != USEC_INFINITY)
                xsprintf(buf, USEC_FMT " " USEC_FMT "\n",
                         MAX(quota * period / USEC_PER_SEC, USEC_PER_MSEC), period);
        else
                xsprintf(buf, "max " USEC_FMT "\n", period);
        (void) set_attribute_and_warn(u, "cpu", "cpu.max", buf);
}

static void cgroup_apply_legacy_cpu_shares(Unit *u, uint64_t shares) {
        char buf[DECIMAL_STR_MAX(uint64_t) + 2];

        xsprintf(buf, "%" PRIu64 "\n", shares);
        (void) set_attribute_and_warn(u, "cpu", "cpu.shares", buf);
}

static void cgroup_apply_legacy_cpu_quota(Unit *u, usec_t quota, usec_t period) {
        char buf[DECIMAL_STR_MAX(usec_t) + 2];

        period = cgroup_cpu_adjust_period_and_log(u, period, quota);

        xsprintf(buf, USEC_FMT "\n", period);
        (void) set_attribute_and_warn(u, "cpu", "cpu.cfs_period_us", buf);

        if (quota != USEC_INFINITY) {
                xsprintf(buf, USEC_FMT "\n", MAX(quota * period / USEC_PER_SEC, USEC_PER_MSEC));
                (void) set_attribute_and_warn(u, "cpu", "cpu.cfs_quota_us", buf);
        } else
                (void) set_attribute_and_warn(u, "cpu", "cpu.cfs_quota_us", "-1\n");
}

static uint64_t cgroup_cpu_shares_to_weight(uint64_t shares) {
        return CLAMP(shares * CGROUP_WEIGHT_DEFAULT / CGROUP_CPU_SHARES_DEFAULT,
                     CGROUP_WEIGHT_MIN, CGROUP_WEIGHT_MAX);
}

static uint64_t cgroup_cpu_weight_to_shares(uint64_t weight) {
        /* we don't support idle in cgroupv1 */
        if (weight == CGROUP_WEIGHT_IDLE)
                return CGROUP_CPU_SHARES_MIN;

        return CLAMP(weight * CGROUP_CPU_SHARES_DEFAULT / CGROUP_WEIGHT_DEFAULT,
                     CGROUP_CPU_SHARES_MIN, CGROUP_CPU_SHARES_MAX);
}

static void cgroup_apply_unified_cpuset(Unit *u, const CPUSet *cpus, const char *name) {
        _cleanup_free_ char *buf = NULL;

        buf = cpu_set_to_range_string(cpus);
        if (!buf) {
                log_oom();
                return;
        }

        (void) set_attribute_and_warn(u, "cpuset", name, buf);
}

static bool cgroup_context_has_io_config(CGroupContext *c) {
        return c->io_accounting ||
                c->io_weight != CGROUP_WEIGHT_INVALID ||
                c->startup_io_weight != CGROUP_WEIGHT_INVALID ||
                c->io_device_weights ||
                c->io_device_latencies ||
                c->io_device_limits;
}

static bool cgroup_context_has_blockio_config(CGroupContext *c) {
        return c->blockio_accounting ||
                c->blockio_weight != CGROUP_BLKIO_WEIGHT_INVALID ||
                c->startup_blockio_weight != CGROUP_BLKIO_WEIGHT_INVALID ||
                c->blockio_device_weights ||
                c->blockio_device_bandwidths;
}

static uint64_t cgroup_context_io_weight(CGroupContext *c, ManagerState state) {
        if (IN_SET(state, MANAGER_STARTING, MANAGER_INITIALIZING, MANAGER_STOPPING) &&
            c->startup_io_weight != CGROUP_WEIGHT_INVALID)
                return c->startup_io_weight;
        if (c->io_weight != CGROUP_WEIGHT_INVALID)
                return c->io_weight;
        return CGROUP_WEIGHT_DEFAULT;
}

static uint64_t cgroup_context_blkio_weight(CGroupContext *c, ManagerState state) {
        if (IN_SET(state, MANAGER_STARTING, MANAGER_INITIALIZING, MANAGER_STOPPING) &&
            c->startup_blockio_weight != CGROUP_BLKIO_WEIGHT_INVALID)
                return c->startup_blockio_weight;
        if (c->blockio_weight != CGROUP_BLKIO_WEIGHT_INVALID)
                return c->blockio_weight;
        return CGROUP_BLKIO_WEIGHT_DEFAULT;
}

static uint64_t cgroup_weight_blkio_to_io(uint64_t blkio_weight) {
        return CLAMP(blkio_weight * CGROUP_WEIGHT_DEFAULT / CGROUP_BLKIO_WEIGHT_DEFAULT,
                     CGROUP_WEIGHT_MIN, CGROUP_WEIGHT_MAX);
}

static uint64_t cgroup_weight_io_to_blkio(uint64_t io_weight) {
        return CLAMP(io_weight * CGROUP_BLKIO_WEIGHT_DEFAULT / CGROUP_WEIGHT_DEFAULT,
                     CGROUP_BLKIO_WEIGHT_MIN, CGROUP_BLKIO_WEIGHT_MAX);
}

static int set_bfq_weight(Unit *u, const char *controller, dev_t dev, uint64_t io_weight) {
        static const char * const prop_names[] = {
                "IOWeight",
                "BlockIOWeight",
                "IODeviceWeight",
                "BlockIODeviceWeight",
        };
        static bool warned = false;
        char buf[DECIMAL_STR_MAX(dev_t)*2+2+DECIMAL_STR_MAX(uint64_t)+STRLEN("\n")];
        const char *p;
        uint64_t bfq_weight;
        int r;

        /* FIXME: drop this function when distro kernels properly support BFQ through "io.weight"
         * See also: https://github.com/systemd/systemd/pull/13335 and
         * https://github.com/torvalds/linux/commit/65752aef0a407e1ef17ec78a7fc31ba4e0b360f9. */
        p = strjoina(controller, ".bfq.weight");
        /* Adjust to kernel range is 1..1000, the default is 100. */
        bfq_weight = BFQ_WEIGHT(io_weight);

        if (major(dev) > 0)
                xsprintf(buf, DEVNUM_FORMAT_STR " %" PRIu64 "\n", DEVNUM_FORMAT_VAL(dev), bfq_weight);
        else
                xsprintf(buf, "%" PRIu64 "\n", bfq_weight);

        r = cg_set_attribute(controller, u->cgroup_path, p, buf);

        /* FIXME: drop this when kernels prior
         * 795fe54c2a82 ("bfq: Add per-device weight") v5.4
         * are not interesting anymore. Old kernels will fail with EINVAL, while new kernels won't return
         * EINVAL on properly formatted input by us. Treat EINVAL accordingly. */
        if (r == -EINVAL && major(dev) > 0) {
               if (!warned) {
                        log_unit_warning(u, "Kernel version does not accept per-device setting in %s.", p);
                        warned = true;
               }
               r = -EOPNOTSUPP; /* mask as unconfigured device */
        } else if (r >= 0 && io_weight != bfq_weight)
                log_unit_debug(u, "%s=%" PRIu64 " scaled to %s=%" PRIu64,
                               prop_names[2*(major(dev) > 0) + streq(controller, "blkio")],
                               io_weight, p, bfq_weight);
        return r;
}

static void cgroup_apply_io_device_weight(Unit *u, const char *dev_path, uint64_t io_weight) {
        char buf[DECIMAL_STR_MAX(dev_t)*2+2+DECIMAL_STR_MAX(uint64_t)+1];
        dev_t dev;
        int r, r1, r2;

        if (lookup_block_device(dev_path, &dev) < 0)
                return;

        r1 = set_bfq_weight(u, "io", dev, io_weight);

        xsprintf(buf, DEVNUM_FORMAT_STR " %" PRIu64 "\n", DEVNUM_FORMAT_VAL(dev), io_weight);
        r2 = cg_set_attribute("io", u->cgroup_path, "io.weight", buf);

        /* Look at the configured device, when both fail, prefer io.weight errno. */
        r = r2 == -EOPNOTSUPP ? r1 : r2;

        if (r < 0)
                log_unit_full_errno(u, LOG_LEVEL_CGROUP_WRITE(r),
                                    r, "Failed to set 'io[.bfq].weight' attribute on '%s' to '%.*s': %m",
                                    empty_to_root(u->cgroup_path), (int) strcspn(buf, NEWLINE), buf);
}

static void cgroup_apply_blkio_device_weight(Unit *u, const char *dev_path, uint64_t blkio_weight) {
        char buf[DECIMAL_STR_MAX(dev_t)*2+2+DECIMAL_STR_MAX(uint64_t)+1];
        dev_t dev;
        int r;

        r = lookup_block_device(dev_path, &dev);
        if (r < 0)
                return;

        xsprintf(buf, DEVNUM_FORMAT_STR " %" PRIu64 "\n", DEVNUM_FORMAT_VAL(dev), blkio_weight);
        (void) set_attribute_and_warn(u, "blkio", "blkio.weight_device", buf);
}

static void cgroup_apply_io_device_latency(Unit *u, const char *dev_path, usec_t target) {
        char buf[DECIMAL_STR_MAX(dev_t)*2+2+7+DECIMAL_STR_MAX(uint64_t)+1];
        dev_t dev;
        int r;

        r = lookup_block_device(dev_path, &dev);
        if (r < 0)
                return;

        if (target != USEC_INFINITY)
                xsprintf(buf, DEVNUM_FORMAT_STR " target=%" PRIu64 "\n", DEVNUM_FORMAT_VAL(dev), target);
        else
                xsprintf(buf, DEVNUM_FORMAT_STR " target=max\n", DEVNUM_FORMAT_VAL(dev));

        (void) set_attribute_and_warn(u, "io", "io.latency", buf);
}

static void cgroup_apply_io_device_limit(Unit *u, const char *dev_path, uint64_t *limits) {
        char limit_bufs[_CGROUP_IO_LIMIT_TYPE_MAX][DECIMAL_STR_MAX(uint64_t)],
             buf[DECIMAL_STR_MAX(dev_t)*2+2+(6+DECIMAL_STR_MAX(uint64_t)+1)*4];
        dev_t dev;

        if (lookup_block_device(dev_path, &dev) < 0)
                return;

        for (CGroupIOLimitType type = 0; type < _CGROUP_IO_LIMIT_TYPE_MAX; type++)
                if (limits[type] != cgroup_io_limit_defaults[type])
                        xsprintf(limit_bufs[type], "%" PRIu64, limits[type]);
                else
                        xsprintf(limit_bufs[type], "%s", limits[type] == CGROUP_LIMIT_MAX ? "max" : "0");

        xsprintf(buf, DEVNUM_FORMAT_STR " rbps=%s wbps=%s riops=%s wiops=%s\n", DEVNUM_FORMAT_VAL(dev),
                 limit_bufs[CGROUP_IO_RBPS_MAX], limit_bufs[CGROUP_IO_WBPS_MAX],
                 limit_bufs[CGROUP_IO_RIOPS_MAX], limit_bufs[CGROUP_IO_WIOPS_MAX]);
        (void) set_attribute_and_warn(u, "io", "io.max", buf);
}

static void cgroup_apply_blkio_device_limit(Unit *u, const char *dev_path, uint64_t rbps, uint64_t wbps) {
        char buf[DECIMAL_STR_MAX(dev_t)*2+2+DECIMAL_STR_MAX(uint64_t)+1];
        dev_t dev;

        if (lookup_block_device(dev_path, &dev) < 0)
                return;

        sprintf(buf, DEVNUM_FORMAT_STR " %" PRIu64 "\n", DEVNUM_FORMAT_VAL(dev), rbps);
        (void) set_attribute_and_warn(u, "blkio", "blkio.throttle.read_bps_device", buf);

        sprintf(buf, DEVNUM_FORMAT_STR " %" PRIu64 "\n", DEVNUM_FORMAT_VAL(dev), wbps);
        (void) set_attribute_and_warn(u, "blkio", "blkio.throttle.write_bps_device", buf);
}

static bool unit_has_unified_memory_config(Unit *u) {
        CGroupContext *c;

        assert(u);

        assert_se(c = unit_get_cgroup_context(u));

        return unit_get_ancestor_memory_min(u) > 0 ||
               unit_get_ancestor_memory_low(u) > 0 || unit_get_ancestor_startup_memory_low(u) > 0 ||
               c->memory_high != CGROUP_LIMIT_MAX || c->startup_memory_high_set ||
               c->memory_max != CGROUP_LIMIT_MAX || c->startup_memory_max_set ||
               c->memory_swap_max != CGROUP_LIMIT_MAX || c->startup_memory_swap_max_set ||
               c->memory_zswap_max != CGROUP_LIMIT_MAX || c->startup_memory_zswap_max_set;
}

static void cgroup_apply_unified_memory_limit(Unit *u, const char *file, uint64_t v) {
        char buf[DECIMAL_STR_MAX(uint64_t) + 1] = "max\n";

        if (v != CGROUP_LIMIT_MAX)
                xsprintf(buf, "%" PRIu64 "\n", v);

        (void) set_attribute_and_warn(u, "memory", file, buf);
}

static void cgroup_apply_firewall(Unit *u) {
        assert(u);

        /* Best-effort: let's apply IP firewalling and/or accounting if that's enabled */

        if (bpf_firewall_compile(u) < 0)
                return;

        (void) bpf_firewall_load_custom(u);
        (void) bpf_firewall_install(u);
}

void unit_modify_nft_set(Unit *u, bool add) {
        int r;

        assert(u);

        if (!MANAGER_IS_SYSTEM(u->manager))
                return;

        if (!UNIT_HAS_CGROUP_CONTEXT(u))
                return;

        if (cg_all_unified() <= 0)
                return;

        if (u->cgroup_id == 0)
                return;

        if (!u->manager->fw_ctx) {
                r = fw_ctx_new_full(&u->manager->fw_ctx, /* init_tables= */ false);
                if (r < 0)
                        return;

                assert(u->manager->fw_ctx);
        }

        CGroupContext *c = ASSERT_PTR(unit_get_cgroup_context(u));

        FOREACH_ARRAY(nft_set, c->nft_set_context.sets, c->nft_set_context.n_sets) {
                if (nft_set->source != NFT_SET_SOURCE_CGROUP)
                        continue;

                uint64_t element = u->cgroup_id;

                r = nft_set_element_modify_any(u->manager->fw_ctx, add, nft_set->nfproto, nft_set->table, nft_set->set, &element, sizeof(element));
                if (r < 0)
                        log_warning_errno(r, "Failed to %s NFT set: family %s, table %s, set %s, cgroup %" PRIu64 ", ignoring: %m",
                                          add? "add" : "delete", nfproto_to_string(nft_set->nfproto), nft_set->table, nft_set->set, u->cgroup_id);
                else
                        log_debug("%s NFT set: family %s, table %s, set %s, cgroup %" PRIu64,
                                  add? "Added" : "Deleted", nfproto_to_string(nft_set->nfproto), nft_set->table, nft_set->set, u->cgroup_id);
        }
}

static void cgroup_apply_socket_bind(Unit *u) {
        assert(u);

        (void) bpf_socket_bind_install(u);
}

static void cgroup_apply_restrict_network_interfaces(Unit *u) {
        assert(u);

        (void) restrict_network_interfaces_install(u);
}

static int cgroup_apply_devices(Unit *u) {
        _cleanup_(bpf_program_freep) BPFProgram *prog = NULL;
        const char *path;
        CGroupContext *c;
        CGroupDevicePolicy policy;
        int r;

        assert_se(c = unit_get_cgroup_context(u));
        assert_se(path = u->cgroup_path);

        policy = c->device_policy;

        if (cg_all_unified() > 0) {
                r = bpf_devices_cgroup_init(&prog, policy, c->device_allow);
                if (r < 0)
                        return log_unit_warning_errno(u, r, "Failed to initialize device control bpf program: %m");

        } else {
                /* Changing the devices list of a populated cgroup might result in EINVAL, hence ignore
                 * EINVAL here. */

                if (c->device_allow || policy != CGROUP_DEVICE_POLICY_AUTO)
                        r = cg_set_attribute("devices", path, "devices.deny", "a");
                else
                        r = cg_set_attribute("devices", path, "devices.allow", "a");
                if (r < 0)
                        log_unit_full_errno(u, IN_SET(r, -ENOENT, -EROFS, -EINVAL, -EACCES, -EPERM) ? LOG_DEBUG : LOG_WARNING, r,
                                            "Failed to reset devices.allow/devices.deny: %m");
        }

        bool allow_list_static = policy == CGROUP_DEVICE_POLICY_CLOSED ||
                (policy == CGROUP_DEVICE_POLICY_AUTO && c->device_allow);
        if (allow_list_static)
                (void) bpf_devices_allow_list_static(prog, path);

        bool any = allow_list_static;
        LIST_FOREACH(device_allow, a, c->device_allow) {
                const char *val;

                if (a->permissions == 0)
                        continue;

                if (path_startswith(a->path, "/dev/"))
                        r = bpf_devices_allow_list_device(prog, path, a->path, a->permissions);
                else if ((val = startswith(a->path, "block-")))
                        r = bpf_devices_allow_list_major(prog, path, val, 'b', a->permissions);
                else if ((val = startswith(a->path, "char-")))
                        r = bpf_devices_allow_list_major(prog, path, val, 'c', a->permissions);
                else {
                        log_unit_debug(u, "Ignoring device '%s' while writing cgroup attribute.", a->path);
                        continue;
                }

                if (r >= 0)
                        any = true;
        }

        if (prog && !any) {
                log_unit_warning_errno(u, SYNTHETIC_ERRNO(ENODEV), "No devices matched by device filter.");

                /* The kernel verifier would reject a program we would build with the normal intro and outro
                   but no allow-listing rules (outro would contain an unreachable instruction for successful
                   return). */
                policy = CGROUP_DEVICE_POLICY_STRICT;
        }

        r = bpf_devices_apply_policy(&prog, policy, any, path, &u->bpf_device_control_installed);
        if (r < 0) {
                static bool warned = false;

                log_full_errno(warned ? LOG_DEBUG : LOG_WARNING, r,
                               "Unit %s configures device ACL, but the local system doesn't seem to support the BPF-based device controller.\n"
                               "Proceeding WITHOUT applying ACL (all devices will be accessible)!\n"
                               "(This warning is only shown for the first loaded unit using device ACL.)", u->id);

                warned = true;
        }
        return r;
}

static void set_io_weight(Unit *u, uint64_t weight) {
        char buf[STRLEN("default \n")+DECIMAL_STR_MAX(uint64_t)];

        assert(u);

        (void) set_bfq_weight(u, "io", makedev(0, 0), weight);

        xsprintf(buf, "default %" PRIu64 "\n", weight);
        (void) set_attribute_and_warn(u, "io", "io.weight", buf);
}

static void set_blkio_weight(Unit *u, uint64_t weight) {
        char buf[STRLEN("\n")+DECIMAL_STR_MAX(uint64_t)];

        assert(u);

        (void) set_bfq_weight(u, "blkio", makedev(0, 0), weight);

        xsprintf(buf, "%" PRIu64 "\n", weight);
        (void) set_attribute_and_warn(u, "blkio", "blkio.weight", buf);
}

static void cgroup_apply_bpf_foreign_program(Unit *u) {
        assert(u);

        (void) bpf_foreign_install(u);
}

static void cgroup_context_apply(
                Unit *u,
                CGroupMask apply_mask,
                ManagerState state) {

        const char *path;
        CGroupContext *c;
        bool is_host_root, is_local_root;
        int r;

        assert(u);

        /* Nothing to do? Exit early! */
        if (apply_mask == 0)
                return;

        /* Some cgroup attributes are not supported on the host root cgroup, hence silently ignore them here. And other
         * attributes should only be managed for cgroups further down the tree. */
        is_local_root = unit_has_name(u, SPECIAL_ROOT_SLICE);
        is_host_root = unit_has_host_root_cgroup(u);

        assert_se(c = unit_get_cgroup_context(u));
        assert_se(path = u->cgroup_path);

        if (is_local_root) /* Make sure we don't try to display messages with an empty path. */
                path = "/";

        /* We generally ignore errors caused by read-only mounted cgroup trees (assuming we are running in a container
         * then), and missing cgroups, i.e. EROFS and ENOENT. */

        /* In fully unified mode these attributes don't exist on the host cgroup root. On legacy the weights exist, but
         * setting the weight makes very little sense on the host root cgroup, as there are no other cgroups at this
         * level. The quota exists there too, but any attempt to write to it is refused with EINVAL. Inside of
         * containers we want to leave control of these to the container manager (and if cgroup v2 delegation is used
         * we couldn't even write to them if we wanted to). */
        if ((apply_mask & CGROUP_MASK_CPU) && !is_local_root) {

                if (cg_all_unified() > 0) {
                        uint64_t weight;

                        if (cgroup_context_has_cpu_weight(c))
                                weight = cgroup_context_cpu_weight(c, state);
                        else if (cgroup_context_has_cpu_shares(c)) {
                                uint64_t shares;

                                shares = cgroup_context_cpu_shares(c, state);
                                weight = cgroup_cpu_shares_to_weight(shares);

                                log_cgroup_compat(u, "Applying [Startup]CPUShares=%" PRIu64 " as [Startup]CPUWeight=%" PRIu64 " on %s",
                                                  shares, weight, path);
                        } else
                                weight = CGROUP_WEIGHT_DEFAULT;

                        cgroup_apply_unified_cpu_idle(u, weight);
                        cgroup_apply_unified_cpu_weight(u, weight);
                        cgroup_apply_unified_cpu_quota(u, c->cpu_quota_per_sec_usec, c->cpu_quota_period_usec);

                } else {
                        uint64_t shares;

                        if (cgroup_context_has_cpu_weight(c)) {
                                uint64_t weight;

                                weight = cgroup_context_cpu_weight(c, state);
                                shares = cgroup_cpu_weight_to_shares(weight);

                                log_cgroup_compat(u, "Applying [Startup]CPUWeight=%" PRIu64 " as [Startup]CPUShares=%" PRIu64 " on %s",
                                                  weight, shares, path);
                        } else if (cgroup_context_has_cpu_shares(c))
                                shares = cgroup_context_cpu_shares(c, state);
                        else
                                shares = CGROUP_CPU_SHARES_DEFAULT;

                        cgroup_apply_legacy_cpu_shares(u, shares);
                        cgroup_apply_legacy_cpu_quota(u, c->cpu_quota_per_sec_usec, c->cpu_quota_period_usec);
                }
        }

        if ((apply_mask & CGROUP_MASK_CPUSET) && !is_local_root) {
                cgroup_apply_unified_cpuset(u, cgroup_context_allowed_cpus(c, state), "cpuset.cpus");
                cgroup_apply_unified_cpuset(u, cgroup_context_allowed_mems(c, state), "cpuset.mems");
        }

        /* The 'io' controller attributes are not exported on the host's root cgroup (being a pure cgroup v2
         * controller), and in case of containers we want to leave control of these attributes to the container manager
         * (and we couldn't access that stuff anyway, even if we tried if proper delegation is used). */
        if ((apply_mask & CGROUP_MASK_IO) && !is_local_root) {
                bool has_io, has_blockio;
                uint64_t weight;

                has_io = cgroup_context_has_io_config(c);
                has_blockio = cgroup_context_has_blockio_config(c);

                if (has_io)
                        weight = cgroup_context_io_weight(c, state);
                else if (has_blockio) {
                        uint64_t blkio_weight;

                        blkio_weight = cgroup_context_blkio_weight(c, state);
                        weight = cgroup_weight_blkio_to_io(blkio_weight);

                        log_cgroup_compat(u, "Applying [Startup]BlockIOWeight=%" PRIu64 " as [Startup]IOWeight=%" PRIu64,
                                          blkio_weight, weight);
                } else
                        weight = CGROUP_WEIGHT_DEFAULT;

                set_io_weight(u, weight);

                if (has_io) {
                        LIST_FOREACH(device_weights, w, c->io_device_weights)
                                cgroup_apply_io_device_weight(u, w->path, w->weight);

                        LIST_FOREACH(device_limits, limit, c->io_device_limits)
                                cgroup_apply_io_device_limit(u, limit->path, limit->limits);

                        LIST_FOREACH(device_latencies, latency, c->io_device_latencies)
                                cgroup_apply_io_device_latency(u, latency->path, latency->target_usec);

                } else if (has_blockio) {
                        LIST_FOREACH(device_weights, w, c->blockio_device_weights) {
                                weight = cgroup_weight_blkio_to_io(w->weight);

                                log_cgroup_compat(u, "Applying BlockIODeviceWeight=%" PRIu64 " as IODeviceWeight=%" PRIu64 " for %s",
                                                  w->weight, weight, w->path);

                                cgroup_apply_io_device_weight(u, w->path, weight);
                        }

                        LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths) {
                                uint64_t limits[_CGROUP_IO_LIMIT_TYPE_MAX];

                                for (CGroupIOLimitType type = 0; type < _CGROUP_IO_LIMIT_TYPE_MAX; type++)
                                        limits[type] = cgroup_io_limit_defaults[type];

                                limits[CGROUP_IO_RBPS_MAX] = b->rbps;
                                limits[CGROUP_IO_WBPS_MAX] = b->wbps;

                                log_cgroup_compat(u, "Applying BlockIO{Read|Write}Bandwidth=%" PRIu64 " %" PRIu64 " as IO{Read|Write}BandwidthMax= for %s",
                                                  b->rbps, b->wbps, b->path);

                                cgroup_apply_io_device_limit(u, b->path, limits);
                        }
                }
        }

        if (apply_mask & CGROUP_MASK_BLKIO) {
                bool has_io, has_blockio;

                has_io = cgroup_context_has_io_config(c);
                has_blockio = cgroup_context_has_blockio_config(c);

                /* Applying a 'weight' never makes sense for the host root cgroup, and for containers this should be
                 * left to our container manager, too. */
                if (!is_local_root) {
                        uint64_t weight;

                        if (has_io) {
                                uint64_t io_weight;

                                io_weight = cgroup_context_io_weight(c, state);
                                weight = cgroup_weight_io_to_blkio(cgroup_context_io_weight(c, state));

                                log_cgroup_compat(u, "Applying [Startup]IOWeight=%" PRIu64 " as [Startup]BlockIOWeight=%" PRIu64,
                                                  io_weight, weight);
                        } else if (has_blockio)
                                weight = cgroup_context_blkio_weight(c, state);
                        else
                                weight = CGROUP_BLKIO_WEIGHT_DEFAULT;

                        set_blkio_weight(u, weight);

                        if (has_io)
                                LIST_FOREACH(device_weights, w, c->io_device_weights) {
                                        weight = cgroup_weight_io_to_blkio(w->weight);

                                        log_cgroup_compat(u, "Applying IODeviceWeight=%" PRIu64 " as BlockIODeviceWeight=%" PRIu64 " for %s",
                                                          w->weight, weight, w->path);

                                        cgroup_apply_blkio_device_weight(u, w->path, weight);
                                }
                        else if (has_blockio)
                                LIST_FOREACH(device_weights, w, c->blockio_device_weights)
                                        cgroup_apply_blkio_device_weight(u, w->path, w->weight);
                }

                /* The bandwidth limits are something that make sense to be applied to the host's root but not container
                 * roots, as there we want the container manager to handle it */
                if (is_host_root || !is_local_root) {
                        if (has_io)
                                LIST_FOREACH(device_limits, l, c->io_device_limits) {
                                        log_cgroup_compat(u, "Applying IO{Read|Write}Bandwidth=%" PRIu64 " %" PRIu64 " as BlockIO{Read|Write}BandwidthMax= for %s",
                                                          l->limits[CGROUP_IO_RBPS_MAX], l->limits[CGROUP_IO_WBPS_MAX], l->path);

                                        cgroup_apply_blkio_device_limit(u, l->path, l->limits[CGROUP_IO_RBPS_MAX], l->limits[CGROUP_IO_WBPS_MAX]);
                                }
                        else if (has_blockio)
                                LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths)
                                        cgroup_apply_blkio_device_limit(u, b->path, b->rbps, b->wbps);
                }
        }

        /* In unified mode 'memory' attributes do not exist on the root cgroup. In legacy mode 'memory.limit_in_bytes'
         * exists on the root cgroup, but any writes to it are refused with EINVAL. And if we run in a container we
         * want to leave control to the container manager (and if proper cgroup v2 delegation is used we couldn't even
         * write to this if we wanted to.) */
        if ((apply_mask & CGROUP_MASK_MEMORY) && !is_local_root) {

                if (cg_all_unified() > 0) {
                        uint64_t max, swap_max = CGROUP_LIMIT_MAX, zswap_max = CGROUP_LIMIT_MAX, high = CGROUP_LIMIT_MAX;

                        if (unit_has_unified_memory_config(u)) {
                                bool startup = IN_SET(state, MANAGER_STARTING, MANAGER_INITIALIZING, MANAGER_STOPPING);

                                high = startup && c->startup_memory_high_set ? c->startup_memory_high : c->memory_high;
                                max = startup && c->startup_memory_max_set ? c->startup_memory_max : c->memory_max;
                                swap_max = startup && c->startup_memory_swap_max_set ? c->startup_memory_swap_max : c->memory_swap_max;
                                zswap_max = startup && c->startup_memory_zswap_max_set ? c->startup_memory_zswap_max : c->memory_zswap_max;
                        } else {
                                max = c->memory_limit;

                                if (max != CGROUP_LIMIT_MAX)
                                        log_cgroup_compat(u, "Applying MemoryLimit=%" PRIu64 " as MemoryMax=", max);
                        }

                        cgroup_apply_unified_memory_limit(u, "memory.min", unit_get_ancestor_memory_min(u));
                        cgroup_apply_unified_memory_limit(u, "memory.low", unit_get_ancestor_memory_low(u));
                        cgroup_apply_unified_memory_limit(u, "memory.high", high);
                        cgroup_apply_unified_memory_limit(u, "memory.max", max);
                        cgroup_apply_unified_memory_limit(u, "memory.swap.max", swap_max);
                        cgroup_apply_unified_memory_limit(u, "memory.zswap.max", zswap_max);

                        (void) set_attribute_and_warn(u, "memory", "memory.oom.group", one_zero(c->memory_oom_group));

                } else {
                        char buf[DECIMAL_STR_MAX(uint64_t) + 1];
                        uint64_t val;

                        if (unit_has_unified_memory_config(u)) {
                                val = c->memory_max;
                                if (val != CGROUP_LIMIT_MAX)
                                        log_cgroup_compat(u, "Applying MemoryMax=%" PRIu64 " as MemoryLimit=", val);
                        } else
                                val = c->memory_limit;

                        if (val == CGROUP_LIMIT_MAX)
                                strncpy(buf, "-1\n", sizeof(buf));
                        else
                                xsprintf(buf, "%" PRIu64 "\n", val);

                        (void) set_attribute_and_warn(u, "memory", "memory.limit_in_bytes", buf);
                }
        }

        /* On cgroup v2 we can apply BPF everywhere. On cgroup v1 we apply it everywhere except for the root of
         * containers, where we leave this to the manager */
        if ((apply_mask & (CGROUP_MASK_DEVICES | CGROUP_MASK_BPF_DEVICES)) &&
            (is_host_root || cg_all_unified() > 0 || !is_local_root))
                (void) cgroup_apply_devices(u);

        if (apply_mask & CGROUP_MASK_PIDS) {

                if (is_host_root) {
                        /* So, the "pids" controller does not expose anything on the root cgroup, in order not to
                         * replicate knobs exposed elsewhere needlessly. We abstract this away here however, and when
                         * the knobs of the root cgroup are modified propagate this to the relevant sysctls. There's a
                         * non-obvious asymmetry however: unlike the cgroup properties we don't really want to take
                         * exclusive ownership of the sysctls, but we still want to honour things if the user sets
                         * limits. Hence we employ sort of a one-way strategy: when the user sets a bounded limit
                         * through us it counts. When the user afterwards unsets it again (i.e. sets it to unbounded)
                         * it also counts. But if the user never set a limit through us (i.e. we are the default of
                         * "unbounded") we leave things unmodified. For this we manage a global boolean that we turn on
                         * the first time we set a limit. Note that this boolean is flushed out on manager reload,
                         * which is desirable so that there's an official way to release control of the sysctl from
                         * systemd: set the limit to unbounded and reload. */

                        if (cgroup_tasks_max_isset(&c->tasks_max)) {
                                u->manager->sysctl_pid_max_changed = true;
                                r = procfs_tasks_set_limit(cgroup_tasks_max_resolve(&c->tasks_max));
                        } else if (u->manager->sysctl_pid_max_changed)
                                r = procfs_tasks_set_limit(TASKS_MAX);
                        else
                                r = 0;
                        if (r < 0)
                                log_unit_full_errno(u, LOG_LEVEL_CGROUP_WRITE(r), r,
                                                    "Failed to write to tasks limit sysctls: %m");
                }

                /* The attribute itself is not available on the host root cgroup, and in the container case we want to
                 * leave it for the container manager. */
                if (!is_local_root) {
                        if (cgroup_tasks_max_isset(&c->tasks_max)) {
                                char buf[DECIMAL_STR_MAX(uint64_t) + 1];

                                xsprintf(buf, "%" PRIu64 "\n", cgroup_tasks_max_resolve(&c->tasks_max));
                                (void) set_attribute_and_warn(u, "pids", "pids.max", buf);
                        } else
                                (void) set_attribute_and_warn(u, "pids", "pids.max", "max\n");
                }
        }

        if (apply_mask & CGROUP_MASK_BPF_FIREWALL)
                cgroup_apply_firewall(u);

        if (apply_mask & CGROUP_MASK_BPF_FOREIGN)
                cgroup_apply_bpf_foreign_program(u);

        if (apply_mask & CGROUP_MASK_BPF_SOCKET_BIND)
                cgroup_apply_socket_bind(u);

        if (apply_mask & CGROUP_MASK_BPF_RESTRICT_NETWORK_INTERFACES)
                cgroup_apply_restrict_network_interfaces(u);

        unit_modify_nft_set(u, /* add = */ true);
}

static bool unit_get_needs_bpf_firewall(Unit *u) {
        CGroupContext *c;
        assert(u);

        c = unit_get_cgroup_context(u);
        if (!c)
                return false;

        if (c->ip_accounting ||
            !set_isempty(c->ip_address_allow) ||
            !set_isempty(c->ip_address_deny) ||
            c->ip_filters_ingress ||
            c->ip_filters_egress)
                return true;

        /* If any parent slice has an IP access list defined, it applies too */
        for (Unit *p = UNIT_GET_SLICE(u); p; p = UNIT_GET_SLICE(p)) {
                c = unit_get_cgroup_context(p);
                if (!c)
                        return false;

                if (!set_isempty(c->ip_address_allow) ||
                    !set_isempty(c->ip_address_deny))
                        return true;
        }

        return false;
}

static bool unit_get_needs_bpf_foreign_program(Unit *u) {
        CGroupContext *c;
        assert(u);

        c = unit_get_cgroup_context(u);
        if (!c)
                return false;

        return !!c->bpf_foreign_programs;
}

static bool unit_get_needs_socket_bind(Unit *u) {
        CGroupContext *c;
        assert(u);

        c = unit_get_cgroup_context(u);
        if (!c)
                return false;

        return c->socket_bind_allow || c->socket_bind_deny;
}

static bool unit_get_needs_restrict_network_interfaces(Unit *u) {
        CGroupContext *c;
        assert(u);

        c = unit_get_cgroup_context(u);
        if (!c)
                return false;

        return !set_isempty(c->restrict_network_interfaces);
}

static CGroupMask unit_get_cgroup_mask(Unit *u) {
        CGroupMask mask = 0;
        CGroupContext *c;

        assert(u);

        assert_se(c = unit_get_cgroup_context(u));

        /* Figure out which controllers we need, based on the cgroup context object */

        if (c->cpu_accounting)
                mask |= get_cpu_accounting_mask();

        if (cgroup_context_has_cpu_weight(c) ||
            cgroup_context_has_cpu_shares(c) ||
            c->cpu_quota_per_sec_usec != USEC_INFINITY)
                mask |= CGROUP_MASK_CPU;

        if (cgroup_context_has_allowed_cpus(c) || cgroup_context_has_allowed_mems(c))
                mask |= CGROUP_MASK_CPUSET;

        if (cgroup_context_has_io_config(c) || cgroup_context_has_blockio_config(c))
                mask |= CGROUP_MASK_IO | CGROUP_MASK_BLKIO;

        if (c->memory_accounting ||
            c->memory_limit != CGROUP_LIMIT_MAX ||
            unit_has_unified_memory_config(u))
                mask |= CGROUP_MASK_MEMORY;

        if (c->device_allow ||
            c->device_policy != CGROUP_DEVICE_POLICY_AUTO)
                mask |= CGROUP_MASK_DEVICES | CGROUP_MASK_BPF_DEVICES;

        if (c->tasks_accounting ||
            cgroup_tasks_max_isset(&c->tasks_max))
                mask |= CGROUP_MASK_PIDS;

        return CGROUP_MASK_EXTEND_JOINED(mask);
}

static CGroupMask unit_get_bpf_mask(Unit *u) {
        CGroupMask mask = 0;

        /* Figure out which controllers we need, based on the cgroup context, possibly taking into account children
         * too. */

        if (unit_get_needs_bpf_firewall(u))
                mask |= CGROUP_MASK_BPF_FIREWALL;

        if (unit_get_needs_bpf_foreign_program(u))
                mask |= CGROUP_MASK_BPF_FOREIGN;

        if (unit_get_needs_socket_bind(u))
                mask |= CGROUP_MASK_BPF_SOCKET_BIND;

        if (unit_get_needs_restrict_network_interfaces(u))
                mask |= CGROUP_MASK_BPF_RESTRICT_NETWORK_INTERFACES;

        return mask;
}

CGroupMask unit_get_own_mask(Unit *u) {
        CGroupContext *c;

        /* Returns the mask of controllers the unit needs for itself. If a unit is not properly loaded, return an empty
         * mask, as we shouldn't reflect it in the cgroup hierarchy then. */

        if (u->load_state != UNIT_LOADED)
                return 0;

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        return unit_get_cgroup_mask(u) | unit_get_bpf_mask(u) | unit_get_delegate_mask(u);
}

CGroupMask unit_get_delegate_mask(Unit *u) {
        CGroupContext *c;

        /* If delegation is turned on, then turn on selected controllers, unless we are on the legacy hierarchy and the
         * process we fork into is known to drop privileges, and hence shouldn't get access to the controllers.
         *
         * Note that on the unified hierarchy it is safe to delegate controllers to unprivileged services. */

        if (!unit_cgroup_delegate(u))
                return 0;

        if (cg_all_unified() <= 0) {
                ExecContext *e;

                e = unit_get_exec_context(u);
                if (e && !exec_context_maintains_privileges(e))
                        return 0;
        }

        assert_se(c = unit_get_cgroup_context(u));
        return CGROUP_MASK_EXTEND_JOINED(c->delegate_controllers);
}

static CGroupMask unit_get_subtree_mask(Unit *u) {

        /* Returns the mask of this subtree, meaning of the group
         * itself and its children. */

        return unit_get_own_mask(u) | unit_get_members_mask(u);
}

CGroupMask unit_get_members_mask(Unit *u) {
        assert(u);

        /* Returns the mask of controllers all of the unit's children require, merged */

        if (u->cgroup_members_mask_valid)
                return u->cgroup_members_mask; /* Use cached value if possible */

        u->cgroup_members_mask = 0;

        if (u->type == UNIT_SLICE) {
                Unit *member;

                UNIT_FOREACH_DEPENDENCY(member, u, UNIT_ATOM_SLICE_OF)
                        u->cgroup_members_mask |= unit_get_subtree_mask(member); /* note that this calls ourselves again, for the children */
        }

        u->cgroup_members_mask_valid = true;
        return u->cgroup_members_mask;
}

CGroupMask unit_get_siblings_mask(Unit *u) {
        Unit *slice;
        assert(u);

        /* Returns the mask of controllers all of the unit's siblings
         * require, i.e. the members mask of the unit's parent slice
         * if there is one. */

        slice = UNIT_GET_SLICE(u);
        if (slice)
                return unit_get_members_mask(slice);

        return unit_get_subtree_mask(u); /* we are the top-level slice */
}

static CGroupMask unit_get_disable_mask(Unit *u) {
        CGroupContext *c;

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        return c->disable_controllers;
}

CGroupMask unit_get_ancestor_disable_mask(Unit *u) {
        CGroupMask mask;
        Unit *slice;

        assert(u);
        mask = unit_get_disable_mask(u);

        /* Returns the mask of controllers which are marked as forcibly
         * disabled in any ancestor unit or the unit in question. */

        slice = UNIT_GET_SLICE(u);
        if (slice)
                mask |= unit_get_ancestor_disable_mask(slice);

        return mask;
}

CGroupMask unit_get_target_mask(Unit *u) {
        CGroupMask own_mask, mask;

        /* This returns the cgroup mask of all controllers to enable for a specific cgroup, i.e. everything
         * it needs itself, plus all that its children need, plus all that its siblings need. This is
         * primarily useful on the legacy cgroup hierarchy, where we need to duplicate each cgroup in each
         * hierarchy that shall be enabled for it. */

        own_mask = unit_get_own_mask(u);

        if (own_mask & CGROUP_MASK_BPF_FIREWALL & ~u->manager->cgroup_supported)
                emit_bpf_firewall_warning(u);

        mask = own_mask | unit_get_members_mask(u) | unit_get_siblings_mask(u);

        mask &= u->manager->cgroup_supported;
        mask &= ~unit_get_ancestor_disable_mask(u);

        return mask;
}

CGroupMask unit_get_enable_mask(Unit *u) {
        CGroupMask mask;

        /* This returns the cgroup mask of all controllers to enable
         * for the children of a specific cgroup. This is primarily
         * useful for the unified cgroup hierarchy, where each cgroup
         * controls which controllers are enabled for its children. */

        mask = unit_get_members_mask(u);
        mask &= u->manager->cgroup_supported;
        mask &= ~unit_get_ancestor_disable_mask(u);

        return mask;
}

void unit_invalidate_cgroup_members_masks(Unit *u) {
        Unit *slice;

        assert(u);

        /* Recurse invalidate the member masks cache all the way up the tree */
        u->cgroup_members_mask_valid = false;

        slice = UNIT_GET_SLICE(u);
        if (slice)
                unit_invalidate_cgroup_members_masks(slice);
}

const char *unit_get_realized_cgroup_path(Unit *u, CGroupMask mask) {

        /* Returns the realized cgroup path of the specified unit where all specified controllers are available. */

        while (u) {

                if (u->cgroup_path &&
                    u->cgroup_realized &&
                    FLAGS_SET(u->cgroup_realized_mask, mask))
                        return u->cgroup_path;

                u = UNIT_GET_SLICE(u);
        }

        return NULL;
}

static const char *migrate_callback(CGroupMask mask, void *userdata) {
        /* If not realized at all, migrate to root ("").
         * It may happen if we're upgrading from older version that didn't clean up.
         */
        return strempty(unit_get_realized_cgroup_path(userdata, mask));
}

int unit_default_cgroup_path(const Unit *u, char **ret) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(u);
        assert(ret);

        if (unit_has_name(u, SPECIAL_ROOT_SLICE))
                p = strdup(u->manager->cgroup_root);
        else {
                _cleanup_free_ char *escaped = NULL, *slice_path = NULL;
                Unit *slice;

                slice = UNIT_GET_SLICE(u);
                if (slice && !unit_has_name(slice, SPECIAL_ROOT_SLICE)) {
                        r = cg_slice_to_path(slice->id, &slice_path);
                        if (r < 0)
                                return r;
                }

                r = cg_escape(u->id, &escaped);
                if (r < 0)
                        return r;

                p = path_join(empty_to_root(u->manager->cgroup_root), slice_path, escaped);
        }
        if (!p)
                return -ENOMEM;

        *ret = TAKE_PTR(p);
        return 0;
}

int unit_set_cgroup_path(Unit *u, const char *path) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(u);

        if (streq_ptr(u->cgroup_path, path))
                return 0;

        if (path) {
                p = strdup(path);
                if (!p)
                        return -ENOMEM;
        }

        if (p) {
                r = hashmap_put(u->manager->cgroup_unit, p, u);
                if (r < 0)
                        return r;
        }

        unit_release_cgroup(u);
        u->cgroup_path = TAKE_PTR(p);

        return 1;
}

int unit_watch_cgroup(Unit *u) {
        _cleanup_free_ char *events = NULL;
        int r;

        assert(u);

        /* Watches the "cgroups.events" attribute of this unit's cgroup for "empty" events, but only if
         * cgroupv2 is available. */

        if (!u->cgroup_path)
                return 0;

        if (u->cgroup_control_inotify_wd >= 0)
                return 0;

        /* Only applies to the unified hierarchy */
        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether the name=systemd hierarchy is unified: %m");
        if (r == 0)
                return 0;

        /* No point in watch the top-level slice, it's never going to run empty. */
        if (unit_has_name(u, SPECIAL_ROOT_SLICE))
                return 0;

        r = hashmap_ensure_allocated(&u->manager->cgroup_control_inotify_wd_unit, &trivial_hash_ops);
        if (r < 0)
                return log_oom();

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, "cgroup.events", &events);
        if (r < 0)
                return log_oom();

        u->cgroup_control_inotify_wd = inotify_add_watch(u->manager->cgroup_inotify_fd, events, IN_MODIFY);
        if (u->cgroup_control_inotify_wd < 0) {

                if (errno == ENOENT) /* If the directory is already gone we don't need to track it, so this
                                      * is not an error */
                        return 0;

                return log_unit_error_errno(u, errno, "Failed to add control inotify watch descriptor for control group %s: %m", empty_to_root(u->cgroup_path));
        }

        r = hashmap_put(u->manager->cgroup_control_inotify_wd_unit, INT_TO_PTR(u->cgroup_control_inotify_wd), u);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to add control inotify watch descriptor for control group %s to hash map: %m", empty_to_root(u->cgroup_path));

        return 0;
}

int unit_watch_cgroup_memory(Unit *u) {
        _cleanup_free_ char *events = NULL;
        CGroupContext *c;
        int r;

        assert(u);

        /* Watches the "memory.events" attribute of this unit's cgroup for "oom_kill" events, but only if
         * cgroupv2 is available. */

        if (!u->cgroup_path)
                return 0;

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        /* The "memory.events" attribute is only available if the memory controller is on. Let's hence tie
         * this to memory accounting, in a way watching for OOM kills is a form of memory accounting after
         * all. */
        if (!c->memory_accounting)
                return 0;

        /* Don't watch inner nodes, as the kernel doesn't report oom_kill events recursively currently, and
         * we also don't want to generate a log message for each parent cgroup of a process. */
        if (u->type == UNIT_SLICE)
                return 0;

        if (u->cgroup_memory_inotify_wd >= 0)
                return 0;

        /* Only applies to the unified hierarchy */
        r = cg_all_unified();
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether the memory controller is unified: %m");
        if (r == 0)
                return 0;

        r = hashmap_ensure_allocated(&u->manager->cgroup_memory_inotify_wd_unit, &trivial_hash_ops);
        if (r < 0)
                return log_oom();

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, "memory.events", &events);
        if (r < 0)
                return log_oom();

        u->cgroup_memory_inotify_wd = inotify_add_watch(u->manager->cgroup_inotify_fd, events, IN_MODIFY);
        if (u->cgroup_memory_inotify_wd < 0) {

                if (errno == ENOENT) /* If the directory is already gone we don't need to track it, so this
                                      * is not an error */
                        return 0;

                return log_unit_error_errno(u, errno, "Failed to add memory inotify watch descriptor for control group %s: %m", empty_to_root(u->cgroup_path));
        }

        r = hashmap_put(u->manager->cgroup_memory_inotify_wd_unit, INT_TO_PTR(u->cgroup_memory_inotify_wd), u);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to add memory inotify watch descriptor for control group %s to hash map: %m", empty_to_root(u->cgroup_path));

        return 0;
}

int unit_pick_cgroup_path(Unit *u) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(u);

        if (u->cgroup_path)
                return 0;

        if (!UNIT_HAS_CGROUP_CONTEXT(u))
                return -EINVAL;

        r = unit_default_cgroup_path(u, &path);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to generate default cgroup path: %m");

        r = unit_set_cgroup_path(u, path);
        if (r == -EEXIST)
                return log_unit_error_errno(u, r, "Control group %s exists already.", empty_to_root(path));
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to set unit's control group path to %s: %m", empty_to_root(path));

        return 0;
}

static int unit_update_cgroup(
                Unit *u,
                CGroupMask target_mask,
                CGroupMask enable_mask,
                ManagerState state) {

        bool created, is_root_slice;
        CGroupMask migrate_mask = 0;
        _cleanup_free_ char *cgroup_full_path = NULL;
        int r;

        assert(u);

        if (!UNIT_HAS_CGROUP_CONTEXT(u))
                return 0;

        /* Figure out our cgroup path */
        r = unit_pick_cgroup_path(u);
        if (r < 0)
                return r;

        /* First, create our own group */
        r = cg_create_everywhere(u->manager->cgroup_supported, target_mask, u->cgroup_path);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to create cgroup %s: %m", empty_to_root(u->cgroup_path));
        created = r;

        if (cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER) > 0) {
                uint64_t cgroup_id = 0;

                r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, NULL, &cgroup_full_path);
                if (r == 0) {
                        r = cg_path_get_cgroupid(cgroup_full_path, &cgroup_id);
                        if (r < 0)
                                log_unit_full_errno(u, ERRNO_IS_NOT_SUPPORTED(r) ? LOG_DEBUG : LOG_WARNING, r,
                                                    "Failed to get cgroup ID of cgroup %s, ignoring: %m", cgroup_full_path);
                } else
                        log_unit_warning_errno(u, r, "Failed to get full cgroup path on cgroup %s, ignoring: %m", empty_to_root(u->cgroup_path));

                u->cgroup_id = cgroup_id;
        }

        /* Start watching it */
        (void) unit_watch_cgroup(u);
        (void) unit_watch_cgroup_memory(u);

        /* For v2 we preserve enabled controllers in delegated units, adjust others,
         * for v1 we figure out which controller hierarchies need migration. */
        if (created || !u->cgroup_realized || !unit_cgroup_delegate(u)) {
                CGroupMask result_mask = 0;

                /* Enable all controllers we need */
                r = cg_enable_everywhere(u->manager->cgroup_supported, enable_mask, u->cgroup_path, &result_mask);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to enable/disable controllers on cgroup %s, ignoring: %m", empty_to_root(u->cgroup_path));

                /* Remember what's actually enabled now */
                u->cgroup_enabled_mask = result_mask;

                migrate_mask = u->cgroup_realized_mask ^ target_mask;
        }

        /* Keep track that this is now realized */
        u->cgroup_realized = true;
        u->cgroup_realized_mask = target_mask;

        /* Migrate processes in controller hierarchies both downwards (enabling) and upwards (disabling).
         *
         * Unnecessary controller cgroups are trimmed (after emptied by upward migration).
         * We perform migration also with whole slices for cases when users don't care about leave
         * granularity. Since delegated_mask is subset of target mask, we won't trim slice subtree containing
         * delegated units.
         */
        if (cg_all_unified() == 0) {
                r = cg_migrate_v1_controllers(u->manager->cgroup_supported, migrate_mask, u->cgroup_path, migrate_callback, u);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to migrate controller cgroups from %s, ignoring: %m", empty_to_root(u->cgroup_path));

                is_root_slice = unit_has_name(u, SPECIAL_ROOT_SLICE);
                r = cg_trim_v1_controllers(u->manager->cgroup_supported, ~target_mask, u->cgroup_path, !is_root_slice);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to delete controller cgroups %s, ignoring: %m", empty_to_root(u->cgroup_path));
        }

        /* Set attributes */
        cgroup_context_apply(u, target_mask, state);
        cgroup_xattr_apply(u);

        /* For most units we expect that memory monitoring is set up before the unit is started and we won't
         * touch it after. For PID 1 this is different though, because we couldn't possibly do that given
         * that PID 1 runs before init.scope is even set up. Hence, whenever init.scope is realized, let's
         * try to open the memory pressure interface anew. */
        if (unit_has_name(u, SPECIAL_INIT_SCOPE))
                (void) manager_setup_memory_pressure_event_source(u->manager);

        return 0;
}

static int unit_attach_pid_to_cgroup_via_bus(Unit *u, pid_t pid, const char *suffix_path) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        char *pp;
        int r;

        assert(u);

        if (MANAGER_IS_SYSTEM(u->manager))
                return -EINVAL;

        if (!u->manager->system_bus)
                return -EIO;

        if (!u->cgroup_path)
                return -EINVAL;

        /* Determine this unit's cgroup path relative to our cgroup root */
        pp = path_startswith(u->cgroup_path, u->manager->cgroup_root);
        if (!pp)
                return -EINVAL;

        pp = strjoina("/", pp, suffix_path);
        path_simplify(pp);

        r = bus_call_method(u->manager->system_bus,
                            bus_systemd_mgr,
                            "AttachProcessesToUnit",
                            &error, NULL,
                            "ssau",
                            NULL /* empty unit name means client's unit, i.e. us */, pp, 1, (uint32_t) pid);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to attach unit process " PID_FMT " via the bus: %s", pid, bus_error_message(&error, r));

        return 0;
}

int unit_attach_pids_to_cgroup(Unit *u, Set *pids, const char *suffix_path) {
        _cleanup_free_ char *joined = NULL;
        CGroupMask delegated_mask;
        const char *p;
        PidRef *pid;
        int ret, r;

        assert(u);

        if (!UNIT_HAS_CGROUP_CONTEXT(u))
                return -EINVAL;

        if (set_isempty(pids))
                return 0;

        /* Load any custom firewall BPF programs here once to test if they are existing and actually loadable.
         * Fail here early since later errors in the call chain unit_realize_cgroup to cgroup_context_apply are ignored. */
        r = bpf_firewall_load_custom(u);
        if (r < 0)
                return r;

        r = unit_realize_cgroup(u);
        if (r < 0)
                return r;

        if (isempty(suffix_path))
                p = u->cgroup_path;
        else {
                joined = path_join(u->cgroup_path, suffix_path);
                if (!joined)
                        return -ENOMEM;

                p = joined;
        }

        delegated_mask = unit_get_delegate_mask(u);

        ret = 0;
        SET_FOREACH(pid, pids) {

                /* Unfortunately we cannot add pids by pidfd to a cgroup. Hence we have to use PIDs instead,
                 * which of course is racy. Let's shorten the race a bit though, and re-validate the PID
                 * before we use it */
                r = pidref_verify(pid);
                if (r < 0) {
                        log_unit_info_errno(u, r, "PID " PID_FMT " vanished before we could move it to target cgroup '%s', skipping: %m", pid->pid, empty_to_root(p));
                        continue;
                }

                /* First, attach the PID to the main cgroup hierarchy */
                r = cg_attach(SYSTEMD_CGROUP_CONTROLLER, p, pid->pid);
                if (r < 0) {
                        bool again = MANAGER_IS_USER(u->manager) && ERRNO_IS_PRIVILEGE(r);

                        log_unit_full_errno(u, again ? LOG_DEBUG : LOG_INFO,  r,
                                            "Couldn't move process "PID_FMT" to%s requested cgroup '%s': %m",
                                            pid->pid, again ? " directly" : "", empty_to_root(p));

                        if (again) {
                                int z;

                                /* If we are in a user instance, and we can't move the process ourselves due
                                 * to permission problems, let's ask the system instance about it instead.
                                 * Since it's more privileged it might be able to move the process across the
                                 * leaves of a subtree whose top node is not owned by us. */

                                z = unit_attach_pid_to_cgroup_via_bus(u, pid->pid, suffix_path);
                                if (z < 0)
                                        log_unit_info_errno(u, z, "Couldn't move process "PID_FMT" to requested cgroup '%s' (directly or via the system bus): %m", pid->pid, empty_to_root(p));
                                else {
                                        if (ret >= 0)
                                                ret++; /* Count successful additions */
                                        continue; /* When the bus thing worked via the bus we are fully done for this PID. */
                                }
                        }

                        if (ret >= 0)
                                ret = r; /* Remember first error */

                        continue;
                } else if (ret >= 0)
                        ret++; /* Count successful additions */

                r = cg_all_unified();
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                /* In the legacy hierarchy, attach the process to the request cgroup if possible, and if not to the
                 * innermost realized one */

                for (CGroupController c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                        CGroupMask bit = CGROUP_CONTROLLER_TO_MASK(c);
                        const char *realized;

                        if (!(u->manager->cgroup_supported & bit))
                                continue;

                        /* If this controller is delegated and realized, honour the caller's request for the cgroup suffix. */
                        if (delegated_mask & u->cgroup_realized_mask & bit) {
                                r = cg_attach(cgroup_controller_to_string(c), p, pid->pid);
                                if (r >= 0)
                                        continue; /* Success! */

                                log_unit_debug_errno(u, r, "Failed to attach PID " PID_FMT " to requested cgroup %s in controller %s, falling back to unit's cgroup: %m",
                                                     pid->pid, empty_to_root(p), cgroup_controller_to_string(c));
                        }

                        /* So this controller is either not delegate or realized, or something else weird happened. In
                         * that case let's attach the PID at least to the closest cgroup up the tree that is
                         * realized. */
                        realized = unit_get_realized_cgroup_path(u, bit);
                        if (!realized)
                                continue; /* Not even realized in the root slice? Then let's not bother */

                        r = cg_attach(cgroup_controller_to_string(c), realized, pid->pid);
                        if (r < 0)
                                log_unit_debug_errno(u, r, "Failed to attach PID " PID_FMT " to realized cgroup %s in controller %s, ignoring: %m",
                                                     pid->pid, realized, cgroup_controller_to_string(c));
                }
        }

        return ret;
}

static bool unit_has_mask_realized(
                Unit *u,
                CGroupMask target_mask,
                CGroupMask enable_mask) {

        assert(u);

        /* Returns true if this unit is fully realized. We check four things:
         *
         * 1. Whether the cgroup was created at all
         * 2. Whether the cgroup was created in all the hierarchies we need it to be created in (in case of cgroup v1)
         * 3. Whether the cgroup has all the right controllers enabled (in case of cgroup v2)
         * 4. Whether the invalidation mask is currently zero
         *
         * If you wonder why we mask the target realization and enable mask with CGROUP_MASK_V1/CGROUP_MASK_V2: note
         * that there are three sets of bitmasks: CGROUP_MASK_V1 (for real cgroup v1 controllers), CGROUP_MASK_V2 (for
         * real cgroup v2 controllers) and CGROUP_MASK_BPF (for BPF-based pseudo-controllers). Now, cgroup_realized_mask
         * is only matters for cgroup v1 controllers, and cgroup_enabled_mask only used for cgroup v2, and if they
         * differ in the others, we don't really care. (After all, the cgroup_enabled_mask tracks with controllers are
         * enabled through cgroup.subtree_control, and since the BPF pseudo-controllers don't show up there, they
         * simply don't matter. */

        return u->cgroup_realized &&
                ((u->cgroup_realized_mask ^ target_mask) & CGROUP_MASK_V1) == 0 &&
                ((u->cgroup_enabled_mask ^ enable_mask) & CGROUP_MASK_V2) == 0 &&
                u->cgroup_invalidated_mask == 0;
}

static bool unit_has_mask_disables_realized(
                Unit *u,
                CGroupMask target_mask,
                CGroupMask enable_mask) {

        assert(u);

        /* Returns true if all controllers which should be disabled are indeed disabled.
         *
         * Unlike unit_has_mask_realized, we don't care what was enabled, only that anything we want to remove is
         * already removed. */

        return !u->cgroup_realized ||
                (FLAGS_SET(u->cgroup_realized_mask, target_mask & CGROUP_MASK_V1) &&
                 FLAGS_SET(u->cgroup_enabled_mask, enable_mask & CGROUP_MASK_V2));
}

static bool unit_has_mask_enables_realized(
                Unit *u,
                CGroupMask target_mask,
                CGroupMask enable_mask) {

        assert(u);

        /* Returns true if all controllers which should be enabled are indeed enabled.
         *
         * Unlike unit_has_mask_realized, we don't care about the controllers that are not present, only that anything
         * we want to add is already added. */

        return u->cgroup_realized &&
                ((u->cgroup_realized_mask | target_mask) & CGROUP_MASK_V1) == (u->cgroup_realized_mask & CGROUP_MASK_V1) &&
                ((u->cgroup_enabled_mask | enable_mask) & CGROUP_MASK_V2) == (u->cgroup_enabled_mask & CGROUP_MASK_V2);
}

void unit_add_to_cgroup_realize_queue(Unit *u) {
        assert(u);

        if (u->in_cgroup_realize_queue)
                return;

        LIST_APPEND(cgroup_realize_queue, u->manager->cgroup_realize_queue, u);
        u->in_cgroup_realize_queue = true;
}

static void unit_remove_from_cgroup_realize_queue(Unit *u) {
        assert(u);

        if (!u->in_cgroup_realize_queue)
                return;

        LIST_REMOVE(cgroup_realize_queue, u->manager->cgroup_realize_queue, u);
        u->in_cgroup_realize_queue = false;
}

/* Controllers can only be enabled breadth-first, from the root of the
 * hierarchy downwards to the unit in question. */
static int unit_realize_cgroup_now_enable(Unit *u, ManagerState state) {
        CGroupMask target_mask, enable_mask, new_target_mask, new_enable_mask;
        Unit *slice;
        int r;

        assert(u);

        /* First go deal with this unit's parent, or we won't be able to enable
         * any new controllers at this layer. */
        slice = UNIT_GET_SLICE(u);
        if (slice) {
                r = unit_realize_cgroup_now_enable(slice, state);
                if (r < 0)
                        return r;
        }

        target_mask = unit_get_target_mask(u);
        enable_mask = unit_get_enable_mask(u);

        /* We can only enable in this direction, don't try to disable anything.
         */
        if (unit_has_mask_enables_realized(u, target_mask, enable_mask))
                return 0;

        new_target_mask = u->cgroup_realized_mask | target_mask;
        new_enable_mask = u->cgroup_enabled_mask | enable_mask;

        return unit_update_cgroup(u, new_target_mask, new_enable_mask, state);
}

/* Controllers can only be disabled depth-first, from the leaves of the
 * hierarchy upwards to the unit in question. */
static int unit_realize_cgroup_now_disable(Unit *u, ManagerState state) {
        Unit *m;

        assert(u);

        if (u->type != UNIT_SLICE)
                return 0;

        UNIT_FOREACH_DEPENDENCY(m, u, UNIT_ATOM_SLICE_OF) {
                CGroupMask target_mask, enable_mask, new_target_mask, new_enable_mask;
                int r;

                /* The cgroup for this unit might not actually be fully realised yet, in which case it isn't
                 * holding any controllers open anyway. */
                if (!m->cgroup_realized)
                        continue;

                /* We must disable those below us first in order to release the controller. */
                if (m->type == UNIT_SLICE)
                        (void) unit_realize_cgroup_now_disable(m, state);

                target_mask = unit_get_target_mask(m);
                enable_mask = unit_get_enable_mask(m);

                /* We can only disable in this direction, don't try to enable anything. */
                if (unit_has_mask_disables_realized(m, target_mask, enable_mask))
                        continue;

                new_target_mask = m->cgroup_realized_mask & target_mask;
                new_enable_mask = m->cgroup_enabled_mask & enable_mask;

                r = unit_update_cgroup(m, new_target_mask, new_enable_mask, state);
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Check if necessary controllers and attributes for a unit are in place.
 *
 * - If so, do nothing.
 * - If not, create paths, move processes over, and set attributes.
 *
 * Controllers can only be *enabled* in a breadth-first way, and *disabled* in
 * a depth-first way. As such the process looks like this:
 *
 * Suppose we have a cgroup hierarchy which looks like this:
 *
 *             root
 *            /    \
 *           /      \
 *          /        \
 *         a          b
 *        / \        / \
 *       /   \      /   \
 *      c     d    e     f
 *     / \   / \  / \   / \
 *     h i   j k  l m   n o
 *
 * 1. We want to realise cgroup "d" now.
 * 2. cgroup "a" has DisableControllers=cpu in the associated unit.
 * 3. cgroup "k" just started requesting the memory controller.
 *
 * To make this work we must do the following in order:
 *
 * 1. Disable CPU controller in k, j
 * 2. Disable CPU controller in d
 * 3. Enable memory controller in root
 * 4. Enable memory controller in a
 * 5. Enable memory controller in d
 * 6. Enable memory controller in k
 *
 * Notice that we need to touch j in one direction, but not the other. We also
 * don't go beyond d when disabling -- it's up to "a" to get realized if it
 * wants to disable further. The basic rules are therefore:
 *
 * - If you're disabling something, you need to realise all of the cgroups from
 *   your recursive descendants to the root. This starts from the leaves.
 * - If you're enabling something, you need to realise from the root cgroup
 *   downwards, but you don't need to iterate your recursive descendants.
 *
 * Returns 0 on success and < 0 on failure. */
static int unit_realize_cgroup_now(Unit *u, ManagerState state) {
        CGroupMask target_mask, enable_mask;
        Unit *slice;
        int r;

        assert(u);

        unit_remove_from_cgroup_realize_queue(u);

        target_mask = unit_get_target_mask(u);
        enable_mask = unit_get_enable_mask(u);

        if (unit_has_mask_realized(u, target_mask, enable_mask))
                return 0;

        /* Disable controllers below us, if there are any */
        r = unit_realize_cgroup_now_disable(u, state);
        if (r < 0)
                return r;

        /* Enable controllers above us, if there are any */
        slice = UNIT_GET_SLICE(u);
        if (slice) {
                r = unit_realize_cgroup_now_enable(slice, state);
                if (r < 0)
                        return r;
        }

        /* Now actually deal with the cgroup we were trying to realise and set attributes */
        r = unit_update_cgroup(u, target_mask, enable_mask, state);
        if (r < 0)
                return r;

        /* Now, reset the invalidation mask */
        u->cgroup_invalidated_mask = 0;
        return 0;
}

unsigned manager_dispatch_cgroup_realize_queue(Manager *m) {
        ManagerState state;
        unsigned n = 0;
        Unit *i;
        int r;

        assert(m);

        state = manager_state(m);

        while ((i = m->cgroup_realize_queue)) {
                assert(i->in_cgroup_realize_queue);

                if (UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(i))) {
                        /* Maybe things changed, and the unit is not actually active anymore? */
                        unit_remove_from_cgroup_realize_queue(i);
                        continue;
                }

                r = unit_realize_cgroup_now(i, state);
                if (r < 0)
                        log_warning_errno(r, "Failed to realize cgroups for queued unit %s, ignoring: %m", i->id);

                n++;
        }

        return n;
}

void unit_add_family_to_cgroup_realize_queue(Unit *u) {
        assert(u);
        assert(u->type == UNIT_SLICE);

        /* Family of a unit for is defined as (immediate) children of the unit and immediate children of all
         * its ancestors.
         *
         * Ideally we would enqueue ancestor path only (bottom up). However, on cgroup-v1 scheduling becomes
         * very weird if two units that own processes reside in the same slice, but one is realized in the
         * "cpu" hierarchy and one is not (for example because one has CPUWeight= set and the other does
         * not), because that means individual processes need to be scheduled against whole cgroups. Let's
         * avoid this asymmetry by always ensuring that siblings of a unit are always realized in their v1
         * controller hierarchies too (if unit requires the controller to be realized).
         *
         * The function must invalidate cgroup_members_mask of all ancestors in order to calculate up to date
         * masks. */

        do {
                Unit *m;

                /* Children of u likely changed when we're called */
                u->cgroup_members_mask_valid = false;

                UNIT_FOREACH_DEPENDENCY(m, u, UNIT_ATOM_SLICE_OF) {

                        /* No point in doing cgroup application for units without active processes. */
                        if (UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(m)))
                                continue;

                        /* We only enqueue siblings if they were realized once at least, in the main
                         * hierarchy. */
                        if (!m->cgroup_realized)
                                continue;

                        /* If the unit doesn't need any new controllers and has current ones
                         * realized, it doesn't need any changes. */
                        if (unit_has_mask_realized(m,
                                                   unit_get_target_mask(m),
                                                   unit_get_enable_mask(m)))
                                continue;

                        unit_add_to_cgroup_realize_queue(m);
                }

                /* Parent comes after children */
                unit_add_to_cgroup_realize_queue(u);

                u = UNIT_GET_SLICE(u);
        } while (u);
}

int unit_realize_cgroup(Unit *u) {
        Unit *slice;

        assert(u);

        if (!UNIT_HAS_CGROUP_CONTEXT(u))
                return 0;

        /* So, here's the deal: when realizing the cgroups for this unit, we need to first create all
         * parents, but there's more actually: for the weight-based controllers we also need to make sure
         * that all our siblings (i.e. units that are in the same slice as we are) have cgroups, too.  On the
         * other hand, when a controller is removed from realized set, it may become unnecessary in siblings
         * and ancestors and they should be (de)realized too.
         *
         * This call will defer work on the siblings and derealized ancestors to the next event loop
         * iteration and synchronously creates the parent cgroups (unit_realize_cgroup_now). */

        slice = UNIT_GET_SLICE(u);
        if (slice)
                unit_add_family_to_cgroup_realize_queue(slice);

        /* And realize this one now (and apply the values) */
        return unit_realize_cgroup_now(u, manager_state(u->manager));
}

void unit_release_cgroup(Unit *u) {
        assert(u);

        /* Forgets all cgroup details for this cgroup — but does *not* destroy the cgroup. This is hence OK to call
         * when we close down everything for reexecution, where we really want to leave the cgroup in place. */

        if (u->cgroup_path) {
                (void) hashmap_remove(u->manager->cgroup_unit, u->cgroup_path);
                u->cgroup_path = mfree(u->cgroup_path);
        }

        if (u->cgroup_control_inotify_wd >= 0) {
                if (inotify_rm_watch(u->manager->cgroup_inotify_fd, u->cgroup_control_inotify_wd) < 0)
                        log_unit_debug_errno(u, errno, "Failed to remove cgroup control inotify watch %i for %s, ignoring: %m", u->cgroup_control_inotify_wd, u->id);

                (void) hashmap_remove(u->manager->cgroup_control_inotify_wd_unit, INT_TO_PTR(u->cgroup_control_inotify_wd));
                u->cgroup_control_inotify_wd = -1;
        }

        if (u->cgroup_memory_inotify_wd >= 0) {
                if (inotify_rm_watch(u->manager->cgroup_inotify_fd, u->cgroup_memory_inotify_wd) < 0)
                        log_unit_debug_errno(u, errno, "Failed to remove cgroup memory inotify watch %i for %s, ignoring: %m", u->cgroup_memory_inotify_wd, u->id);

                (void) hashmap_remove(u->manager->cgroup_memory_inotify_wd_unit, INT_TO_PTR(u->cgroup_memory_inotify_wd));
                u->cgroup_memory_inotify_wd = -1;
        }
}

bool unit_maybe_release_cgroup(Unit *u) {
        int r;

        assert(u);

        if (!u->cgroup_path)
                return true;

        /* Don't release the cgroup if there are still processes under it. If we get notified later when all the
         * processes exit (e.g. the processes were in D-state and exited after the unit was marked as failed)
         * we need the cgroup paths to continue to be tracked by the manager so they can be looked up and cleaned
         * up later. */
        r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path);
        if (r < 0)
                log_unit_debug_errno(u, r, "Error checking if the cgroup is recursively empty, ignoring: %m");
        else if (r == 1) {
                unit_release_cgroup(u);
                return true;
        }

        return false;
}

void unit_prune_cgroup(Unit *u) {
        int r;
        bool is_root_slice;

        assert(u);

        /* Removes the cgroup, if empty and possible, and stops watching it. */

        if (!u->cgroup_path)
                return;

        /* Cache the last CPU and memory usage values before we destroy the cgroup */
        (void) unit_get_cpu_usage(u, /* ret = */ NULL);

        for (CGroupMemoryAccountingMetric metric = 0; metric <= _CGROUP_MEMORY_ACCOUNTING_METRIC_CACHED_LAST; metric++)
                (void) unit_get_memory_accounting(u, metric, /* ret = */ NULL);

#if BPF_FRAMEWORK
        (void) lsm_bpf_cleanup(u); /* Remove cgroup from the global LSM BPF map */
#endif

        unit_modify_nft_set(u, /* add = */ false);

        is_root_slice = unit_has_name(u, SPECIAL_ROOT_SLICE);

        r = cg_trim_everywhere(u->manager->cgroup_supported, u->cgroup_path, !is_root_slice);
        if (r < 0)
                /* One reason we could have failed here is, that the cgroup still contains a process.
                 * However, if the cgroup becomes removable at a later time, it might be removed when
                 * the containing slice is stopped. So even if we failed now, this unit shouldn't assume
                 * that the cgroup is still realized the next time it is started. Do not return early
                 * on error, continue cleanup. */
                log_unit_full_errno(u, r == -EBUSY ? LOG_DEBUG : LOG_WARNING, r, "Failed to destroy cgroup %s, ignoring: %m", empty_to_root(u->cgroup_path));

        if (is_root_slice)
                return;

        if (!unit_maybe_release_cgroup(u)) /* Returns true if the cgroup was released */
                return;

        u->cgroup_realized = false;
        u->cgroup_realized_mask = 0;
        u->cgroup_enabled_mask = 0;

        u->bpf_device_control_installed = bpf_program_free(u->bpf_device_control_installed);
}

int unit_search_main_pid(Unit *u, PidRef *ret) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(u);
        assert(ret);

        if (!u->cgroup_path)
                return -ENXIO;

        r = cg_enumerate_processes(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, &f);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_(pidref_done) PidRef npidref = PIDREF_NULL;

                r = cg_read_pidref(f, &npidref);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (pidref_equal(&pidref, &npidref)) /* seen already, cgroupfs reports duplicates! */
                        continue;

                if (pidref_is_my_child(&npidref) <= 0) /* ignore processes further down the tree */
                        continue;

                if (pidref_is_set(&pidref) != 0)
                        /* Dang, there's more than one daemonized PID in this group, so we don't know what
                         * process is the main process. */
                        return -ENODATA;

                pidref = TAKE_PIDREF(npidref);
        }

        if (!pidref_is_set(&pidref))
                return -ENODATA;

        *ret = TAKE_PIDREF(pidref);
        return 0;
}

static int unit_watch_pids_in_path(Unit *u, const char *path) {
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int ret = 0, r;

        assert(u);
        assert(path);

        r = cg_enumerate_processes(SYSTEMD_CGROUP_CONTROLLER, path, &f);
        if (r < 0)
                RET_GATHER(ret, r);
        else {
                for (;;) {
                        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;

                        r = cg_read_pidref(f, &pid);
                        if (r == 0)
                                break;
                        if (r < 0) {
                                RET_GATHER(ret, r);
                                break;
                        }

                        RET_GATHER(ret, unit_watch_pidref(u, &pid, /* exclusive= */ false));
                }
        }

        r = cg_enumerate_subgroups(SYSTEMD_CGROUP_CONTROLLER, path, &d);
        if (r < 0)
                RET_GATHER(ret, r);
        else {
                for (;;) {
                        _cleanup_free_ char *fn = NULL, *p = NULL;

                        r = cg_read_subgroup(d, &fn);
                        if (r == 0)
                                break;
                        if (r < 0) {
                                RET_GATHER(ret, r);
                                break;
                        }

                        p = path_join(empty_to_root(path), fn);
                        if (!p)
                                return -ENOMEM;

                        RET_GATHER(ret, unit_watch_pids_in_path(u, p));
                }
        }

        return ret;
}

int unit_synthesize_cgroup_empty_event(Unit *u) {
        int r;

        assert(u);

        /* Enqueue a synthetic cgroup empty event if this unit doesn't watch any PIDs anymore. This is compatibility
         * support for non-unified systems where notifications aren't reliable, and hence need to take whatever we can
         * get as notification source as soon as we stopped having any useful PIDs to watch for. */

        if (!u->cgroup_path)
                return -ENOENT;

        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0)
                return r;
        if (r > 0) /* On unified we have reliable notifications, and don't need this */
                return 0;

        if (!set_isempty(u->pids))
                return 0;

        unit_add_to_cgroup_empty_queue(u);
        return 0;
}

int unit_watch_all_pids(Unit *u) {
        int r;

        assert(u);

        /* Adds all PIDs from our cgroup to the set of PIDs we
         * watch. This is a fallback logic for cases where we do not
         * get reliable cgroup empty notifications: we try to use
         * SIGCHLD as replacement. */

        if (!u->cgroup_path)
                return -ENOENT;

        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0)
                return r;
        if (r > 0) /* On unified we can use proper notifications */
                return 0;

        return unit_watch_pids_in_path(u, u->cgroup_path);
}

static int on_cgroup_empty_event(sd_event_source *s, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        Unit *u;
        int r;

        assert(s);

        u = m->cgroup_empty_queue;
        if (!u)
                return 0;

        assert(u->in_cgroup_empty_queue);
        u->in_cgroup_empty_queue = false;
        LIST_REMOVE(cgroup_empty_queue, m->cgroup_empty_queue, u);

        if (m->cgroup_empty_queue) {
                /* More stuff queued, let's make sure we remain enabled */
                r = sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
                if (r < 0)
                        log_debug_errno(r, "Failed to reenable cgroup empty event source, ignoring: %m");
        }

        /* Update state based on OOM kills before we notify about cgroup empty event */
        (void) unit_check_oom(u);
        (void) unit_check_oomd_kill(u);

        unit_add_to_gc_queue(u);

        if (IN_SET(unit_active_state(u), UNIT_INACTIVE, UNIT_FAILED))
                unit_prune_cgroup(u);
        else if (UNIT_VTABLE(u)->notify_cgroup_empty)
                UNIT_VTABLE(u)->notify_cgroup_empty(u);

        return 0;
}

void unit_add_to_cgroup_empty_queue(Unit *u) {
        int r;

        assert(u);

        /* Note that there are four different ways how cgroup empty events reach us:
         *
         * 1. On the unified hierarchy we get an inotify event on the cgroup
         *
         * 2. On the legacy hierarchy, when running in system mode, we get a datagram on the cgroup agent socket
         *
         * 3. On the legacy hierarchy, when running in user mode, we get a D-Bus signal on the system bus
         *
         * 4. On the legacy hierarchy, in service units we start watching all processes of the cgroup for SIGCHLD as
         *    soon as we get one SIGCHLD, to deal with unreliable cgroup notifications.
         *
         * Regardless which way we got the notification, we'll verify it here, and then add it to a separate
         * queue. This queue will be dispatched at a lower priority than the SIGCHLD handler, so that we always use
         * SIGCHLD if we can get it first, and only use the cgroup empty notifications if there's no SIGCHLD pending
         * (which might happen if the cgroup doesn't contain processes that are our own child, which is typically the
         * case for scope units). */

        if (u->in_cgroup_empty_queue)
                return;

        /* Let's verify that the cgroup is really empty */
        if (!u->cgroup_path)
                return;

        r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path);
        if (r < 0) {
                log_unit_debug_errno(u, r, "Failed to determine whether cgroup %s is empty: %m", empty_to_root(u->cgroup_path));
                return;
        }
        if (r == 0)
                return;

        LIST_PREPEND(cgroup_empty_queue, u->manager->cgroup_empty_queue, u);
        u->in_cgroup_empty_queue = true;

        /* Trigger the defer event */
        r = sd_event_source_set_enabled(u->manager->cgroup_empty_event_source, SD_EVENT_ONESHOT);
        if (r < 0)
                log_debug_errno(r, "Failed to enable cgroup empty event source: %m");
}

static void unit_remove_from_cgroup_empty_queue(Unit *u) {
        assert(u);

        if (!u->in_cgroup_empty_queue)
                return;

        LIST_REMOVE(cgroup_empty_queue, u->manager->cgroup_empty_queue, u);
        u->in_cgroup_empty_queue = false;
}

int unit_check_oomd_kill(Unit *u) {
        _cleanup_free_ char *value = NULL;
        bool increased;
        uint64_t n = 0;
        int r;

        if (!u->cgroup_path)
                return 0;

        r = cg_all_unified();
        if (r < 0)
                return log_unit_debug_errno(u, r, "Couldn't determine whether we are in all unified mode: %m");
        else if (r == 0)
                return 0;

        r = cg_get_xattr_malloc(u->cgroup_path, "user.oomd_ooms", &value);
        if (r < 0 && !ERRNO_IS_XATTR_ABSENT(r))
                return r;

        if (!isempty(value)) {
                 r = safe_atou64(value, &n);
                 if (r < 0)
                         return r;
        }

        increased = n > u->managed_oom_kill_last;
        u->managed_oom_kill_last = n;

        if (!increased)
                return 0;

        n = 0;
        value = mfree(value);
        r = cg_get_xattr_malloc(u->cgroup_path, "user.oomd_kill", &value);
        if (r >= 0 && !isempty(value))
                (void) safe_atou64(value, &n);

        if (n > 0)
                log_unit_struct(u, LOG_NOTICE,
                                "MESSAGE_ID=" SD_MESSAGE_UNIT_OOMD_KILL_STR,
                                LOG_UNIT_INVOCATION_ID(u),
                                LOG_UNIT_MESSAGE(u, "systemd-oomd killed %"PRIu64" process(es) in this unit.", n),
                                "N_PROCESSES=%" PRIu64, n);
        else
                log_unit_struct(u, LOG_NOTICE,
                                "MESSAGE_ID=" SD_MESSAGE_UNIT_OOMD_KILL_STR,
                                LOG_UNIT_INVOCATION_ID(u),
                                LOG_UNIT_MESSAGE(u, "systemd-oomd killed some process(es) in this unit."));

        unit_notify_cgroup_oom(u, /* ManagedOOM= */ true);

        return 1;
}

int unit_check_oom(Unit *u) {
        _cleanup_free_ char *oom_kill = NULL;
        bool increased;
        uint64_t c;
        int r;

        if (!u->cgroup_path)
                return 0;

        r = cg_get_keyed_attribute("memory", u->cgroup_path, "memory.events", STRV_MAKE("oom_kill"), &oom_kill);
        if (IN_SET(r, -ENOENT, -ENXIO)) /* Handle gracefully if cgroup or oom_kill attribute don't exist */
                c = 0;
        else if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to read oom_kill field of memory.events cgroup attribute: %m");
        else {
                r = safe_atou64(oom_kill, &c);
                if (r < 0)
                        return log_unit_debug_errno(u, r, "Failed to parse oom_kill field: %m");
        }

        increased = c > u->oom_kill_last;
        u->oom_kill_last = c;

        if (!increased)
                return 0;

        log_unit_struct(u, LOG_NOTICE,
                        "MESSAGE_ID=" SD_MESSAGE_UNIT_OUT_OF_MEMORY_STR,
                        LOG_UNIT_INVOCATION_ID(u),
                        LOG_UNIT_MESSAGE(u, "A process of this unit has been killed by the OOM killer."));

        unit_notify_cgroup_oom(u, /* ManagedOOM= */ false);

        return 1;
}

static int on_cgroup_oom_event(sd_event_source *s, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        Unit *u;
        int r;

        assert(s);

        u = m->cgroup_oom_queue;
        if (!u)
                return 0;

        assert(u->in_cgroup_oom_queue);
        u->in_cgroup_oom_queue = false;
        LIST_REMOVE(cgroup_oom_queue, m->cgroup_oom_queue, u);

        if (m->cgroup_oom_queue) {
                /* More stuff queued, let's make sure we remain enabled */
                r = sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
                if (r < 0)
                        log_debug_errno(r, "Failed to reenable cgroup oom event source, ignoring: %m");
        }

        (void) unit_check_oom(u);
        unit_add_to_gc_queue(u);

        return 0;
}

static void unit_add_to_cgroup_oom_queue(Unit *u) {
        int r;

        assert(u);

        if (u->in_cgroup_oom_queue)
                return;
        if (!u->cgroup_path)
                return;

        LIST_PREPEND(cgroup_oom_queue, u->manager->cgroup_oom_queue, u);
        u->in_cgroup_oom_queue = true;

        /* Trigger the defer event */
        if (!u->manager->cgroup_oom_event_source) {
                _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;

                r = sd_event_add_defer(u->manager->event, &s, on_cgroup_oom_event, u->manager);
                if (r < 0) {
                        log_error_errno(r, "Failed to create cgroup oom event source: %m");
                        return;
                }

                r = sd_event_source_set_priority(s, SD_EVENT_PRIORITY_NORMAL-8);
                if (r < 0) {
                        log_error_errno(r, "Failed to set priority of cgroup oom event source: %m");
                        return;
                }

                (void) sd_event_source_set_description(s, "cgroup-oom");
                u->manager->cgroup_oom_event_source = TAKE_PTR(s);
        }

        r = sd_event_source_set_enabled(u->manager->cgroup_oom_event_source, SD_EVENT_ONESHOT);
        if (r < 0)
                log_error_errno(r, "Failed to enable cgroup oom event source: %m");
}

static int unit_check_cgroup_events(Unit *u) {
        char *values[2] = {};
        int r;

        assert(u);

        if (!u->cgroup_path)
                return 0;

        r = cg_get_keyed_attribute_graceful(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, "cgroup.events",
                                            STRV_MAKE("populated", "frozen"), values);
        if (r < 0)
                return r;

        /* The cgroup.events notifications can be merged together so act as we saw the given state for the
         * first time. The functions we call to handle given state are idempotent, which makes them
         * effectively remember the previous state. */
        if (values[0]) {
                if (streq(values[0], "1"))
                        unit_remove_from_cgroup_empty_queue(u);
                else
                        unit_add_to_cgroup_empty_queue(u);
        }

        /* Disregard freezer state changes due to operations not initiated by us */
        if (values[1] && IN_SET(u->freezer_state, FREEZER_FREEZING, FREEZER_THAWING)) {
                if (streq(values[1], "0"))
                        unit_thawed(u);
                else
                        unit_frozen(u);
        }

        free(values[0]);
        free(values[1]);

        return 0;
}

static int on_cgroup_inotify_event(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);
        assert(fd >= 0);

        for (;;) {
                union inotify_event_buffer buffer;
                ssize_t l;

                l = read(fd, &buffer, sizeof(buffer));
                if (l < 0) {
                        if (ERRNO_IS_TRANSIENT(errno))
                                return 0;

                        return log_error_errno(errno, "Failed to read control group inotify events: %m");
                }

                FOREACH_INOTIFY_EVENT_WARN(e, buffer, l) {
                        Unit *u;

                        if (e->wd < 0)
                                /* Queue overflow has no watch descriptor */
                                continue;

                        if (e->mask & IN_IGNORED)
                                /* The watch was just removed */
                                continue;

                        /* Note that inotify might deliver events for a watch even after it was removed,
                         * because it was queued before the removal. Let's ignore this here safely. */

                        u = hashmap_get(m->cgroup_control_inotify_wd_unit, INT_TO_PTR(e->wd));
                        if (u)
                                unit_check_cgroup_events(u);

                        u = hashmap_get(m->cgroup_memory_inotify_wd_unit, INT_TO_PTR(e->wd));
                        if (u)
                                unit_add_to_cgroup_oom_queue(u);
                }
        }
}

static int cg_bpf_mask_supported(CGroupMask *ret) {
        CGroupMask mask = 0;
        int r;

        /* BPF-based firewall */
        r = bpf_firewall_supported();
        if (r < 0)
                return r;
        if (r > 0)
                mask |= CGROUP_MASK_BPF_FIREWALL;

        /* BPF-based device access control */
        r = bpf_devices_supported();
        if (r < 0)
                return r;
        if (r > 0)
                mask |= CGROUP_MASK_BPF_DEVICES;

        /* BPF pinned prog */
        r = bpf_foreign_supported();
        if (r < 0)
                return r;
        if (r > 0)
                mask |= CGROUP_MASK_BPF_FOREIGN;

        /* BPF-based bind{4|6} hooks */
        r = bpf_socket_bind_supported();
        if (r < 0)
                return r;
        if (r > 0)
                mask |= CGROUP_MASK_BPF_SOCKET_BIND;

        /* BPF-based cgroup_skb/{egress|ingress} hooks */
        r = restrict_network_interfaces_supported();
        if (r < 0)
                return r;
        if (r > 0)
                mask |= CGROUP_MASK_BPF_RESTRICT_NETWORK_INTERFACES;

        *ret = mask;
        return 0;
}

int manager_setup_cgroup(Manager *m) {
        _cleanup_free_ char *path = NULL;
        const char *scope_path;
        int r, all_unified;
        CGroupMask mask;
        char *e;

        assert(m);

        /* 1. Determine hierarchy */
        m->cgroup_root = mfree(m->cgroup_root);
        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 0, &m->cgroup_root);
        if (r < 0)
                return log_error_errno(r, "Cannot determine cgroup we are running in: %m");

        /* Chop off the init scope, if we are already located in it */
        e = endswith(m->cgroup_root, "/" SPECIAL_INIT_SCOPE);

        /* LEGACY: Also chop off the system slice if we are in
         * it. This is to support live upgrades from older systemd
         * versions where PID 1 was moved there. Also see
         * cg_get_root_path(). */
        if (!e && MANAGER_IS_SYSTEM(m)) {
                e = endswith(m->cgroup_root, "/" SPECIAL_SYSTEM_SLICE);
                if (!e)
                        e = endswith(m->cgroup_root, "/system"); /* even more legacy */
        }
        if (e)
                *e = 0;

        /* And make sure to store away the root value without trailing slash, even for the root dir, so that we can
         * easily prepend it everywhere. */
        delete_trailing_chars(m->cgroup_root, "/");

        /* 2. Show data */
        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_root, NULL, &path);
        if (r < 0)
                return log_error_errno(r, "Cannot find cgroup mount point: %m");

        r = cg_unified();
        if (r < 0)
                return log_error_errno(r, "Couldn't determine if we are running in the unified hierarchy: %m");

        all_unified = cg_all_unified();
        if (all_unified < 0)
                return log_error_errno(all_unified, "Couldn't determine whether we are in all unified mode: %m");
        if (all_unified > 0)
                log_debug("Unified cgroup hierarchy is located at %s.", path);
        else {
                r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether systemd's own controller is in unified mode: %m");
                if (r > 0)
                        log_debug("Unified cgroup hierarchy is located at %s. Controllers are on legacy hierarchies.", path);
                else
                        log_debug("Using cgroup controller " SYSTEMD_CGROUP_CONTROLLER_LEGACY ". File system hierarchy is at %s.", path);
        }

        /* 3. Allocate cgroup empty defer event source */
        m->cgroup_empty_event_source = sd_event_source_disable_unref(m->cgroup_empty_event_source);
        r = sd_event_add_defer(m->event, &m->cgroup_empty_event_source, on_cgroup_empty_event, m);
        if (r < 0)
                return log_error_errno(r, "Failed to create cgroup empty event source: %m");

        /* Schedule cgroup empty checks early, but after having processed service notification messages or
         * SIGCHLD signals, so that a cgroup running empty is always just the last safety net of
         * notification, and we collected the metadata the notification and SIGCHLD stuff offers first. */
        r = sd_event_source_set_priority(m->cgroup_empty_event_source, SD_EVENT_PRIORITY_NORMAL-5);
        if (r < 0)
                return log_error_errno(r, "Failed to set priority of cgroup empty event source: %m");

        r = sd_event_source_set_enabled(m->cgroup_empty_event_source, SD_EVENT_OFF);
        if (r < 0)
                return log_error_errno(r, "Failed to disable cgroup empty event source: %m");

        (void) sd_event_source_set_description(m->cgroup_empty_event_source, "cgroup-empty");

        /* 4. Install notifier inotify object, or agent */
        if (cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER) > 0) {

                /* In the unified hierarchy we can get cgroup empty notifications via inotify. */

                m->cgroup_inotify_event_source = sd_event_source_disable_unref(m->cgroup_inotify_event_source);
                safe_close(m->cgroup_inotify_fd);

                m->cgroup_inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
                if (m->cgroup_inotify_fd < 0)
                        return log_error_errno(errno, "Failed to create control group inotify object: %m");

                r = sd_event_add_io(m->event, &m->cgroup_inotify_event_source, m->cgroup_inotify_fd, EPOLLIN, on_cgroup_inotify_event, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to watch control group inotify object: %m");

                /* Process cgroup empty notifications early. Note that when this event is dispatched it'll
                 * just add the unit to a cgroup empty queue, hence let's run earlier than that. Also see
                 * handling of cgroup agent notifications, for the classic cgroup hierarchy support. */
                r = sd_event_source_set_priority(m->cgroup_inotify_event_source, SD_EVENT_PRIORITY_NORMAL-9);
                if (r < 0)
                        return log_error_errno(r, "Failed to set priority of inotify event source: %m");

                (void) sd_event_source_set_description(m->cgroup_inotify_event_source, "cgroup-inotify");

        } else if (MANAGER_IS_SYSTEM(m) && manager_owns_host_root_cgroup(m) && !MANAGER_IS_TEST_RUN(m)) {

                /* On the legacy hierarchy we only get notifications via cgroup agents. (Which isn't really reliable,
                 * since it does not generate events when control groups with children run empty. */

                r = cg_install_release_agent(SYSTEMD_CGROUP_CONTROLLER, SYSTEMD_CGROUPS_AGENT_PATH);
                if (r < 0)
                        log_warning_errno(r, "Failed to install release agent, ignoring: %m");
                else if (r > 0)
                        log_debug("Installed release agent.");
                else if (r == 0)
                        log_debug("Release agent already installed.");
        }

        /* 5. Make sure we are in the special "init.scope" unit in the root slice. */
        scope_path = strjoina(m->cgroup_root, "/" SPECIAL_INIT_SCOPE);
        r = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, scope_path, 0);
        if (r >= 0) {
                /* Also, move all other userspace processes remaining in the root cgroup into that scope. */
                r = cg_migrate(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_root, SYSTEMD_CGROUP_CONTROLLER, scope_path, 0);
                if (r < 0)
                        log_warning_errno(r, "Couldn't move remaining userspace processes, ignoring: %m");

                /* 6. And pin it, so that it cannot be unmounted */
                safe_close(m->pin_cgroupfs_fd);
                m->pin_cgroupfs_fd = open(path, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOCTTY|O_NONBLOCK);
                if (m->pin_cgroupfs_fd < 0)
                        return log_error_errno(errno, "Failed to open pin file: %m");

        } else if (!MANAGER_IS_TEST_RUN(m))
                return log_error_errno(r, "Failed to create %s control group: %m", scope_path);

        /* 7. Always enable hierarchical support if it exists... */
        if (!all_unified && !MANAGER_IS_TEST_RUN(m))
                (void) cg_set_attribute("memory", "/", "memory.use_hierarchy", "1");

        /* 8. Figure out which controllers are supported */
        r = cg_mask_supported_subtree(m->cgroup_root, &m->cgroup_supported);
        if (r < 0)
                return log_error_errno(r, "Failed to determine supported controllers: %m");

        /* 9. Figure out which bpf-based pseudo-controllers are supported */
        r = cg_bpf_mask_supported(&mask);
        if (r < 0)
                return log_error_errno(r, "Failed to determine supported bpf-based pseudo-controllers: %m");
        m->cgroup_supported |= mask;

        /* 10. Log which controllers are supported */
        for (CGroupController c = 0; c < _CGROUP_CONTROLLER_MAX; c++)
                log_debug("Controller '%s' supported: %s", cgroup_controller_to_string(c),
                          yes_no(m->cgroup_supported & CGROUP_CONTROLLER_TO_MASK(c)));

        return 0;
}

void manager_shutdown_cgroup(Manager *m, bool delete) {
        assert(m);

        /* We can't really delete the group, since we are in it. But
         * let's trim it. */
        if (delete && m->cgroup_root && !FLAGS_SET(m->test_run_flags, MANAGER_TEST_RUN_MINIMAL))
                (void) cg_trim(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_root, false);

        m->cgroup_empty_event_source = sd_event_source_disable_unref(m->cgroup_empty_event_source);

        m->cgroup_control_inotify_wd_unit = hashmap_free(m->cgroup_control_inotify_wd_unit);
        m->cgroup_memory_inotify_wd_unit = hashmap_free(m->cgroup_memory_inotify_wd_unit);

        m->cgroup_inotify_event_source = sd_event_source_disable_unref(m->cgroup_inotify_event_source);
        m->cgroup_inotify_fd = safe_close(m->cgroup_inotify_fd);

        m->pin_cgroupfs_fd = safe_close(m->pin_cgroupfs_fd);

        m->cgroup_root = mfree(m->cgroup_root);
}

Unit* manager_get_unit_by_cgroup(Manager *m, const char *cgroup) {
        char *p;
        Unit *u;

        assert(m);
        assert(cgroup);

        u = hashmap_get(m->cgroup_unit, cgroup);
        if (u)
                return u;

        p = strdupa_safe(cgroup);
        for (;;) {
                char *e;

                e = strrchr(p, '/');
                if (!e || e == p)
                        return hashmap_get(m->cgroup_unit, SPECIAL_ROOT_SLICE);

                *e = 0;

                u = hashmap_get(m->cgroup_unit, p);
                if (u)
                        return u;
        }
}

Unit *manager_get_unit_by_pidref_cgroup(Manager *m, PidRef *pid) {
        _cleanup_free_ char *cgroup = NULL;

        assert(m);

        if (cg_pidref_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &cgroup) < 0)
                return NULL;

        return manager_get_unit_by_cgroup(m, cgroup);
}

Unit *manager_get_unit_by_pidref_watching(Manager *m, PidRef *pid) {
        Unit *u, **array;

        assert(m);

        if (!pidref_is_set(pid))
                return NULL;

        u = hashmap_get(m->watch_pids, pid);
        if (u)
                return u;

        array = hashmap_get(m->watch_pids_more, pid);
        if (array)
                return array[0];

        return NULL;
}

Unit *manager_get_unit_by_pidref(Manager *m, PidRef *pid) {
        Unit *u;

        assert(m);

        /* Note that a process might be owned by multiple units, we return only one here, which is good
         * enough for most cases, though not strictly correct. We prefer the one reported by cgroup
         * membership, as that's the most relevant one as children of the process will be assigned to that
         * one, too, before all else. */

        if (!pidref_is_set(pid))
                return NULL;

        if (pidref_is_self(pid))
                return hashmap_get(m->units, SPECIAL_INIT_SCOPE);
        if (pid->pid == 1)
                return NULL;

        u = manager_get_unit_by_pidref_cgroup(m, pid);
        if (u)
                return u;

        u = manager_get_unit_by_pidref_watching(m, pid);
        if (u)
                return u;

        return NULL;
}

Unit *manager_get_unit_by_pid(Manager *m, pid_t pid) {
        assert(m);

        if (!pid_is_valid(pid))
                return NULL;

        return manager_get_unit_by_pidref(m, &PIDREF_MAKE_FROM_PID(pid));
}

int manager_notify_cgroup_empty(Manager *m, const char *cgroup) {
        Unit *u;

        assert(m);
        assert(cgroup);

        /* Called on the legacy hierarchy whenever we get an explicit cgroup notification from the cgroup agent process
         * or from the --system instance */

        log_debug("Got cgroup empty notification for: %s", cgroup);

        u = manager_get_unit_by_cgroup(m, cgroup);
        if (!u)
                return 0;

        unit_add_to_cgroup_empty_queue(u);
        return 1;
}

int unit_get_memory_available(Unit *u, uint64_t *ret) {
        uint64_t available = UINT64_MAX, current = 0;

        assert(u);
        assert(ret);

        /* If data from cgroups can be accessed, try to find out how much more memory a unit can
         * claim before hitting the configured cgroup limits (if any). Consider both MemoryHigh
         * and MemoryMax, and also any slice the unit might be nested below. */

        do {
                uint64_t unit_available, unit_limit = UINT64_MAX;
                CGroupContext *unit_context;

                /* No point in continuing if we can't go any lower */
                if (available == 0)
                        break;

                unit_context = unit_get_cgroup_context(u);
                if (!unit_context)
                        return -ENODATA;

                if (!u->cgroup_path)
                        continue;

                (void) unit_get_memory_current(u, &current);
                /* in case of error, previous current propagates as lower bound */

                if (unit_has_name(u, SPECIAL_ROOT_SLICE))
                        unit_limit = physical_memory();
                else if (unit_context->memory_max == UINT64_MAX && unit_context->memory_high == UINT64_MAX)
                        continue;
                unit_limit = MIN3(unit_limit, unit_context->memory_max, unit_context->memory_high);

                unit_available = LESS_BY(unit_limit, current);
                available = MIN(unit_available, available);
        } while ((u = UNIT_GET_SLICE(u)));

        *ret = available;

        return 0;
}

int unit_get_memory_current(Unit *u, uint64_t *ret) {
        int r;

        // FIXME: Merge this into unit_get_memory_accounting after support for cgroup v1 is dropped

        assert(u);
        assert(ret);

        if (!UNIT_CGROUP_BOOL(u, memory_accounting))
                return -ENODATA;

        if (!u->cgroup_path)
                return -ENODATA;

        /* The root cgroup doesn't expose this information, let's get it from /proc instead */
        if (unit_has_host_root_cgroup(u))
                return procfs_memory_get_used(ret);

        if ((u->cgroup_realized_mask & CGROUP_MASK_MEMORY) == 0)
                return -ENODATA;

        r = cg_all_unified();
        if (r < 0)
                return r;

        return cg_get_attribute_as_uint64("memory", u->cgroup_path, r > 0 ? "memory.current" : "memory.usage_in_bytes", ret);
}

int unit_get_memory_accounting(Unit *u, CGroupMemoryAccountingMetric metric, uint64_t *ret) {

        static const char* const attributes_table[_CGROUP_MEMORY_ACCOUNTING_METRIC_MAX] = {
                [CGROUP_MEMORY_PEAK]          = "memory.peak",
                [CGROUP_MEMORY_SWAP_CURRENT]  = "memory.swap.current",
                [CGROUP_MEMORY_SWAP_PEAK]     = "memory.swap.peak",
                [CGROUP_MEMORY_ZSWAP_CURRENT] = "memory.zswap.current",
        };

        uint64_t bytes;
        bool updated = false;
        int r;

        assert(u);
        assert(metric >= 0);
        assert(metric < _CGROUP_MEMORY_ACCOUNTING_METRIC_MAX);

        if (!UNIT_CGROUP_BOOL(u, memory_accounting))
                return -ENODATA;

        if (!u->cgroup_path)
                /* If the cgroup is already gone, we try to find the last cached value. */
                goto finish;

        /* The root cgroup doesn't expose this information. */
        if (unit_has_host_root_cgroup(u))
                return -ENODATA;

        if (!FLAGS_SET(u->cgroup_realized_mask, CGROUP_MASK_MEMORY))
                return -ENODATA;

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r == 0)
                return -ENODATA;

        r = cg_get_attribute_as_uint64("memory", u->cgroup_path, attributes_table[metric], &bytes);
        if (r < 0 && r != -ENODATA)
                return r;
        updated = r >= 0;

finish:
        if (metric <= _CGROUP_MEMORY_ACCOUNTING_METRIC_CACHED_LAST) {
                uint64_t *last = &u->memory_accounting_last[metric];

                if (updated)
                        *last = bytes;
                else if (*last != UINT64_MAX)
                        bytes = *last;
                else
                        return -ENODATA;

        } else if (!updated)
                return -ENODATA;

        if (ret)
                *ret = bytes;

        return 0;
}

int unit_get_tasks_current(Unit *u, uint64_t *ret) {
        assert(u);
        assert(ret);

        if (!UNIT_CGROUP_BOOL(u, tasks_accounting))
                return -ENODATA;

        if (!u->cgroup_path)
                return -ENODATA;

        /* The root cgroup doesn't expose this information, let's get it from /proc instead */
        if (unit_has_host_root_cgroup(u))
                return procfs_tasks_get_current(ret);

        if ((u->cgroup_realized_mask & CGROUP_MASK_PIDS) == 0)
                return -ENODATA;

        return cg_get_attribute_as_uint64("pids", u->cgroup_path, "pids.current", ret);
}

static int unit_get_cpu_usage_raw(Unit *u, nsec_t *ret) {
        uint64_t ns;
        int r;

        assert(u);
        assert(ret);

        if (!u->cgroup_path)
                return -ENODATA;

        /* The root cgroup doesn't expose this information, let's get it from /proc instead */
        if (unit_has_host_root_cgroup(u))
                return procfs_cpu_get_usage(ret);

        /* Requisite controllers for CPU accounting are not enabled */
        if ((get_cpu_accounting_mask() & ~u->cgroup_realized_mask) != 0)
                return -ENODATA;

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r > 0) {
                _cleanup_free_ char *val = NULL;
                uint64_t us;

                r = cg_get_keyed_attribute("cpu", u->cgroup_path, "cpu.stat", STRV_MAKE("usage_usec"), &val);
                if (IN_SET(r, -ENOENT, -ENXIO))
                        return -ENODATA;
                if (r < 0)
                        return r;

                r = safe_atou64(val, &us);
                if (r < 0)
                        return r;

                ns = us * NSEC_PER_USEC;
        } else
                return cg_get_attribute_as_uint64("cpuacct", u->cgroup_path, "cpuacct.usage", ret);

        *ret = ns;
        return 0;
}

int unit_get_cpu_usage(Unit *u, nsec_t *ret) {
        nsec_t ns;
        int r;

        assert(u);

        /* Retrieve the current CPU usage counter. This will subtract the CPU counter taken when the unit was
         * started. If the cgroup has been removed already, returns the last cached value. To cache the value, simply
         * call this function with a NULL return value. */

        if (!UNIT_CGROUP_BOOL(u, cpu_accounting))
                return -ENODATA;

        r = unit_get_cpu_usage_raw(u, &ns);
        if (r == -ENODATA && u->cpu_usage_last != NSEC_INFINITY) {
                /* If we can't get the CPU usage anymore (because the cgroup was already removed, for example), use our
                 * cached value. */

                if (ret)
                        *ret = u->cpu_usage_last;
                return 0;
        }
        if (r < 0)
                return r;

        if (ns > u->cpu_usage_base)
                ns -= u->cpu_usage_base;
        else
                ns = 0;

        u->cpu_usage_last = ns;
        if (ret)
                *ret = ns;

        return 0;
}

int unit_get_ip_accounting(
                Unit *u,
                CGroupIPAccountingMetric metric,
                uint64_t *ret) {

        uint64_t value;
        int fd, r;

        assert(u);
        assert(metric >= 0);
        assert(metric < _CGROUP_IP_ACCOUNTING_METRIC_MAX);
        assert(ret);

        if (!UNIT_CGROUP_BOOL(u, ip_accounting))
                return -ENODATA;

        fd = IN_SET(metric, CGROUP_IP_INGRESS_BYTES, CGROUP_IP_INGRESS_PACKETS) ?
                u->ip_accounting_ingress_map_fd :
                u->ip_accounting_egress_map_fd;
        if (fd < 0)
                return -ENODATA;

        if (IN_SET(metric, CGROUP_IP_INGRESS_BYTES, CGROUP_IP_EGRESS_BYTES))
                r = bpf_firewall_read_accounting(fd, &value, NULL);
        else
                r = bpf_firewall_read_accounting(fd, NULL, &value);
        if (r < 0)
                return r;

        /* Add in additional metrics from a previous runtime. Note that when reexecing/reloading the daemon we compile
         * all BPF programs and maps anew, but serialize the old counters. When deserializing we store them in the
         * ip_accounting_extra[] field, and add them in here transparently. */

        *ret = value + u->ip_accounting_extra[metric];

        return r;
}

static int unit_get_io_accounting_raw(Unit *u, uint64_t ret[static _CGROUP_IO_ACCOUNTING_METRIC_MAX]) {
        static const char *const field_names[_CGROUP_IO_ACCOUNTING_METRIC_MAX] = {
                [CGROUP_IO_READ_BYTES]       = "rbytes=",
                [CGROUP_IO_WRITE_BYTES]      = "wbytes=",
                [CGROUP_IO_READ_OPERATIONS]  = "rios=",
                [CGROUP_IO_WRITE_OPERATIONS] = "wios=",
        };
        uint64_t acc[_CGROUP_IO_ACCOUNTING_METRIC_MAX] = {};
        _cleanup_free_ char *path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(u);

        if (!u->cgroup_path)
                return -ENODATA;

        if (unit_has_host_root_cgroup(u))
                return -ENODATA; /* TODO: return useful data for the top-level cgroup */

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r == 0) /* TODO: support cgroupv1 */
                return -ENODATA;

        if (!FLAGS_SET(u->cgroup_realized_mask, CGROUP_MASK_IO))
                return -ENODATA;

        r = cg_get_path("io", u->cgroup_path, "io.stat", &path);
        if (r < 0)
                return r;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *p;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                p = line;
                p += strcspn(p, WHITESPACE); /* Skip over device major/minor */
                p += strspn(p, WHITESPACE);  /* Skip over following whitespace */

                for (;;) {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&p, &word, NULL, EXTRACT_RETAIN_ESCAPE);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        for (CGroupIOAccountingMetric i = 0; i < _CGROUP_IO_ACCOUNTING_METRIC_MAX; i++) {
                                const char *x;

                                x = startswith(word, field_names[i]);
                                if (x) {
                                        uint64_t w;

                                        r = safe_atou64(x, &w);
                                        if (r < 0)
                                                return r;

                                        /* Sum up the stats of all devices */
                                        acc[i] += w;
                                        break;
                                }
                        }
                }
        }

        memcpy(ret, acc, sizeof(acc));
        return 0;
}

int unit_get_io_accounting(
                Unit *u,
                CGroupIOAccountingMetric metric,
                bool allow_cache,
                uint64_t *ret) {

        uint64_t raw[_CGROUP_IO_ACCOUNTING_METRIC_MAX];
        int r;

        /* Retrieve an IO account parameter. This will subtract the counter when the unit was started. */

        if (!UNIT_CGROUP_BOOL(u, io_accounting))
                return -ENODATA;

        if (allow_cache && u->io_accounting_last[metric] != UINT64_MAX)
                goto done;

        r = unit_get_io_accounting_raw(u, raw);
        if (r == -ENODATA && u->io_accounting_last[metric] != UINT64_MAX)
                goto done;
        if (r < 0)
                return r;

        for (CGroupIOAccountingMetric i = 0; i < _CGROUP_IO_ACCOUNTING_METRIC_MAX; i++) {
                /* Saturated subtraction */
                if (raw[i] > u->io_accounting_base[i])
                        u->io_accounting_last[i] = raw[i] - u->io_accounting_base[i];
                else
                        u->io_accounting_last[i] = 0;
        }

done:
        if (ret)
                *ret = u->io_accounting_last[metric];

        return 0;
}

int unit_reset_cpu_accounting(Unit *u) {
        int r;

        assert(u);

        u->cpu_usage_last = NSEC_INFINITY;

        r = unit_get_cpu_usage_raw(u, &u->cpu_usage_base);
        if (r < 0) {
                u->cpu_usage_base = 0;
                return r;
        }

        return 0;
}

void unit_reset_memory_accounting_last(Unit *u) {
        assert(u);

        FOREACH_ARRAY(i, u->memory_accounting_last, ELEMENTSOF(u->memory_accounting_last))
                *i = UINT64_MAX;
}

int unit_reset_ip_accounting(Unit *u) {
        int r = 0;

        assert(u);

        if (u->ip_accounting_ingress_map_fd >= 0)
                RET_GATHER(r, bpf_firewall_reset_accounting(u->ip_accounting_ingress_map_fd));

        if (u->ip_accounting_egress_map_fd >= 0)
                RET_GATHER(r, bpf_firewall_reset_accounting(u->ip_accounting_egress_map_fd));

        zero(u->ip_accounting_extra);

        return r;
}

void unit_reset_io_accounting_last(Unit *u) {
        assert(u);

        FOREACH_ARRAY(i, u->io_accounting_last, _CGROUP_IO_ACCOUNTING_METRIC_MAX)
                *i = UINT64_MAX;
}

int unit_reset_io_accounting(Unit *u) {
        int r;

        assert(u);

        unit_reset_io_accounting_last(u);

        r = unit_get_io_accounting_raw(u, u->io_accounting_base);
        if (r < 0) {
                zero(u->io_accounting_base);
                return r;
        }

        return 0;
}

int unit_reset_accounting(Unit *u) {
        int r = 0;

        assert(u);

        RET_GATHER(r, unit_reset_cpu_accounting(u));
        RET_GATHER(r, unit_reset_io_accounting(u));
        RET_GATHER(r, unit_reset_ip_accounting(u));
        unit_reset_memory_accounting_last(u);

        return r;
}

void unit_invalidate_cgroup(Unit *u, CGroupMask m) {
        assert(u);

        if (!UNIT_HAS_CGROUP_CONTEXT(u))
                return;

        if (m == 0)
                return;

        /* always invalidate compat pairs together */
        if (m & (CGROUP_MASK_IO | CGROUP_MASK_BLKIO))
                m |= CGROUP_MASK_IO | CGROUP_MASK_BLKIO;

        if (m & (CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT))
                m |= CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT;

        if (FLAGS_SET(u->cgroup_invalidated_mask, m)) /* NOP? */
                return;

        u->cgroup_invalidated_mask |= m;
        unit_add_to_cgroup_realize_queue(u);
}

void unit_invalidate_cgroup_bpf(Unit *u) {
        assert(u);

        if (!UNIT_HAS_CGROUP_CONTEXT(u))
                return;

        if (u->cgroup_invalidated_mask & CGROUP_MASK_BPF_FIREWALL) /* NOP? */
                return;

        u->cgroup_invalidated_mask |= CGROUP_MASK_BPF_FIREWALL;
        unit_add_to_cgroup_realize_queue(u);

        /* If we are a slice unit, we also need to put compile a new BPF program for all our children, as the IP access
         * list of our children includes our own. */
        if (u->type == UNIT_SLICE) {
                Unit *member;

                UNIT_FOREACH_DEPENDENCY(member, u, UNIT_ATOM_SLICE_OF)
                        unit_invalidate_cgroup_bpf(member);
        }
}

void unit_cgroup_catchup(Unit *u) {
        assert(u);

        if (!UNIT_HAS_CGROUP_CONTEXT(u))
                return;

        /* We dropped the inotify watch during reexec/reload, so we need to
         * check these as they may have changed.
         * Note that (currently) the kernel doesn't actually update cgroup
         * file modification times, so we can't just serialize and then check
         * the mtime for file(s) we are interested in. */
        (void) unit_check_cgroup_events(u);
        unit_add_to_cgroup_oom_queue(u);
}

bool unit_cgroup_delegate(Unit *u) {
        CGroupContext *c;

        assert(u);

        if (!UNIT_VTABLE(u)->can_delegate)
                return false;

        c = unit_get_cgroup_context(u);
        if (!c)
                return false;

        return c->delegate;
}

void manager_invalidate_startup_units(Manager *m) {
        Unit *u;

        assert(m);

        SET_FOREACH(u, m->startup_units)
                unit_invalidate_cgroup(u, CGROUP_MASK_CPU|CGROUP_MASK_IO|CGROUP_MASK_BLKIO|CGROUP_MASK_CPUSET);
}

int unit_cgroup_freezer_action(Unit *u, FreezerAction action) {
        _cleanup_free_ char *path = NULL;
        FreezerState target, kernel = _FREEZER_STATE_INVALID;
        int r, ret;

        assert(u);
        assert(IN_SET(action, FREEZER_FREEZE, FREEZER_THAW));

        if (!cg_freezer_supported())
                return 0;

        /* Ignore all requests to thaw init.scope or -.slice and reject all requests to freeze them */
        if (unit_has_name(u, SPECIAL_ROOT_SLICE) || unit_has_name(u, SPECIAL_INIT_SCOPE))
                return action == FREEZER_FREEZE ? -EPERM : 0;

        if (!u->cgroup_realized)
                return -EBUSY;

        if (action == FREEZER_THAW) {
                Unit *slice = UNIT_GET_SLICE(u);

                if (slice) {
                        r = unit_cgroup_freezer_action(slice, FREEZER_THAW);
                        if (r < 0)
                                return log_unit_error_errno(u, r, "Failed to thaw slice %s of unit: %m", slice->id);
                }
        }

        target = action == FREEZER_FREEZE ? FREEZER_FROZEN : FREEZER_RUNNING;

        r = unit_freezer_state_kernel(u, &kernel);
        if (r < 0)
                log_unit_debug_errno(u, r, "Failed to obtain cgroup freezer state: %m");

        if (target == kernel) {
                u->freezer_state = target;
                if (action == FREEZER_FREEZE)
                        return 0;
                ret = 0;
        } else
                ret = 1;

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, "cgroup.freeze", &path);
        if (r < 0)
                return r;

        log_unit_debug(u, "%s unit.", action == FREEZER_FREEZE ? "Freezing" : "Thawing");

        if (target != kernel) {
                if (action == FREEZER_FREEZE)
                        u->freezer_state = FREEZER_FREEZING;
                else
                        u->freezer_state = FREEZER_THAWING;
        }

        r = write_string_file(path, one_zero(action == FREEZER_FREEZE), WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return r;

        return ret;
}

int unit_get_cpuset(Unit *u, CPUSet *cpus, const char *name) {
        _cleanup_free_ char *v = NULL;
        int r;

        assert(u);
        assert(cpus);

        if (!u->cgroup_path)
                return -ENODATA;

        if ((u->cgroup_realized_mask & CGROUP_MASK_CPUSET) == 0)
                return -ENODATA;

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r == 0)
                return -ENODATA;

        r = cg_get_attribute("cpuset", u->cgroup_path, name, &v);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;

        return parse_cpu_set_full(v, cpus, false, NULL, NULL, 0, NULL);
}

static const char* const cgroup_device_policy_table[_CGROUP_DEVICE_POLICY_MAX] = {
        [CGROUP_DEVICE_POLICY_AUTO]   = "auto",
        [CGROUP_DEVICE_POLICY_CLOSED] = "closed",
        [CGROUP_DEVICE_POLICY_STRICT] = "strict",
};

DEFINE_STRING_TABLE_LOOKUP(cgroup_device_policy, CGroupDevicePolicy);

static const char* const freezer_action_table[_FREEZER_ACTION_MAX] = {
        [FREEZER_FREEZE] = "freeze",
        [FREEZER_THAW] = "thaw",
};

DEFINE_STRING_TABLE_LOOKUP(freezer_action, FreezerAction);

static const char* const cgroup_pressure_watch_table[_CGROUP_PRESSURE_WATCH_MAX] = {
        [CGROUP_PRESSURE_WATCH_OFF] = "off",
        [CGROUP_PRESSURE_WATCH_AUTO] = "auto",
        [CGROUP_PRESSURE_WATCH_ON] = "on",
        [CGROUP_PRESSURE_WATCH_SKIP] = "skip",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(cgroup_pressure_watch, CGroupPressureWatch, CGROUP_PRESSURE_WATCH_ON);

static const char* const cgroup_ip_accounting_metric_table[_CGROUP_IP_ACCOUNTING_METRIC_MAX] = {
        [CGROUP_IP_INGRESS_BYTES]   = "IPIngressBytes",
        [CGROUP_IP_EGRESS_BYTES]    = "IPEgressBytes",
        [CGROUP_IP_INGRESS_PACKETS] = "IPIngressPackets",
        [CGROUP_IP_EGRESS_PACKETS]  = "IPEgressPackets",
};

DEFINE_STRING_TABLE_LOOKUP(cgroup_ip_accounting_metric, CGroupIPAccountingMetric);

static const char* const cgroup_io_accounting_metric_table[_CGROUP_IO_ACCOUNTING_METRIC_MAX] = {
        [CGROUP_IO_READ_BYTES]       = "IOReadBytes",
        [CGROUP_IO_WRITE_BYTES]      = "IOWriteBytes",
        [CGROUP_IO_READ_OPERATIONS]  = "IOReadOperations",
        [CGROUP_IO_WRITE_OPERATIONS] = "IOWriteOperations",
};

DEFINE_STRING_TABLE_LOOKUP(cgroup_io_accounting_metric, CGroupIOAccountingMetric);

static const char* const cgroup_memory_accounting_metric_table[_CGROUP_MEMORY_ACCOUNTING_METRIC_MAX] = {
        [CGROUP_MEMORY_PEAK]          = "MemoryPeak",
        [CGROUP_MEMORY_SWAP_CURRENT]  = "MemorySwapCurrent",
        [CGROUP_MEMORY_SWAP_PEAK]     = "MemorySwapPeak",
        [CGROUP_MEMORY_ZSWAP_CURRENT] = "MemoryZSwapCurrent",
};

DEFINE_STRING_TABLE_LOOKUP(cgroup_memory_accounting_metric, CGroupMemoryAccountingMetric);
