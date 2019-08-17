/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <fnmatch.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "bpf-devices.h"
#include "bpf-firewall.h"
#include "btrfs-util.h"
#include "bus-error.h"
#include "cgroup-util.h"
#include "cgroup.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "procfs-util.h"
#include "special.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "virt.h"

#define CGROUP_CPU_QUOTA_DEFAULT_PERIOD_USEC ((usec_t) 100 * USEC_PER_MSEC)

/* Returns the log level to use when cgroup attribute writes fail. When an attribute is missing or we have access
 * problems we downgrade to LOG_DEBUG. This is supposed to be nice to container managers and kernels which want to mask
 * out specific attributes from us. */
#define LOG_LEVEL_CGROUP_WRITE(r) (IN_SET(abs(r), ENOENT, EROFS, EACCES, EPERM) ? LOG_DEBUG : LOG_WARNING)

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
                log_unit_full(u, LOG_LEVEL_CGROUP_WRITE(r), r, "Failed to set '%s' attribute on '%s' to '%.*s': %m",
                              strna(attribute), isempty(u->cgroup_path) ? "/" : u->cgroup_path, (int) strcspn(value, NEWLINE), value);

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

        /* Initialize everything to the kernel defaults. */

        *c = (CGroupContext) {
                .cpu_weight = CGROUP_WEIGHT_INVALID,
                .startup_cpu_weight = CGROUP_WEIGHT_INVALID,
                .cpu_quota_per_sec_usec = USEC_INFINITY,
                .cpu_quota_period_usec = USEC_INFINITY,

                .cpu_shares = CGROUP_CPU_SHARES_INVALID,
                .startup_cpu_shares = CGROUP_CPU_SHARES_INVALID,

                .memory_high = CGROUP_LIMIT_MAX,
                .memory_max = CGROUP_LIMIT_MAX,
                .memory_swap_max = CGROUP_LIMIT_MAX,

                .memory_limit = CGROUP_LIMIT_MAX,

                .io_weight = CGROUP_WEIGHT_INVALID,
                .startup_io_weight = CGROUP_WEIGHT_INVALID,

                .blockio_weight = CGROUP_BLKIO_WEIGHT_INVALID,
                .startup_blockio_weight = CGROUP_BLKIO_WEIGHT_INVALID,

                .tasks_max = CGROUP_LIMIT_MAX,
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

        c->ip_address_allow = ip_address_access_free_all(c->ip_address_allow);
        c->ip_address_deny = ip_address_access_free_all(c->ip_address_deny);

        c->ip_filters_ingress = strv_free(c->ip_filters_ingress);
        c->ip_filters_egress = strv_free(c->ip_filters_egress);
}

void cgroup_context_dump(CGroupContext *c, FILE* f, const char *prefix) {
        _cleanup_free_ char *disable_controllers_str = NULL;
        CGroupIODeviceLimit *il;
        CGroupIODeviceWeight *iw;
        CGroupIODeviceLatency *l;
        CGroupBlockIODeviceBandwidth *b;
        CGroupBlockIODeviceWeight *w;
        CGroupDeviceAllow *a;
        IPAddressAccessItem *iaai;
        char **path;
        char u[FORMAT_TIMESPAN_MAX];
        char v[FORMAT_TIMESPAN_MAX];

        assert(c);
        assert(f);

        prefix = strempty(prefix);

        (void) cg_mask_to_string(c->disable_controllers, &disable_controllers_str);

        fprintf(f,
                "%sCPUAccounting=%s\n"
                "%sIOAccounting=%s\n"
                "%sBlockIOAccounting=%s\n"
                "%sMemoryAccounting=%s\n"
                "%sTasksAccounting=%s\n"
                "%sIPAccounting=%s\n"
                "%sCPUWeight=%" PRIu64 "\n"
                "%sStartupCPUWeight=%" PRIu64 "\n"
                "%sCPUShares=%" PRIu64 "\n"
                "%sStartupCPUShares=%" PRIu64 "\n"
                "%sCPUQuotaPerSecSec=%s\n"
                "%sCPUQuotaPeriodSec=%s\n"
                "%sIOWeight=%" PRIu64 "\n"
                "%sStartupIOWeight=%" PRIu64 "\n"
                "%sBlockIOWeight=%" PRIu64 "\n"
                "%sStartupBlockIOWeight=%" PRIu64 "\n"
                "%sDefaultMemoryMin=%" PRIu64 "\n"
                "%sDefaultMemoryLow=%" PRIu64 "\n"
                "%sMemoryMin=%" PRIu64 "\n"
                "%sMemoryLow=%" PRIu64 "\n"
                "%sMemoryHigh=%" PRIu64 "\n"
                "%sMemoryMax=%" PRIu64 "\n"
                "%sMemorySwapMax=%" PRIu64 "\n"
                "%sMemoryLimit=%" PRIu64 "\n"
                "%sTasksMax=%" PRIu64 "\n"
                "%sDevicePolicy=%s\n"
                "%sDisableControllers=%s\n"
                "%sDelegate=%s\n",
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
                prefix, format_timespan(u, sizeof(u), c->cpu_quota_per_sec_usec, 1),
                prefix, format_timespan(v, sizeof(v), c->cpu_quota_period_usec, 1),
                prefix, c->io_weight,
                prefix, c->startup_io_weight,
                prefix, c->blockio_weight,
                prefix, c->startup_blockio_weight,
                prefix, c->default_memory_min,
                prefix, c->default_memory_low,
                prefix, c->memory_min,
                prefix, c->memory_low,
                prefix, c->memory_high,
                prefix, c->memory_max,
                prefix, c->memory_swap_max,
                prefix, c->memory_limit,
                prefix, c->tasks_max,
                prefix, cgroup_device_policy_to_string(c->device_policy),
                prefix, strempty(disable_controllers_str),
                prefix, yes_no(c->delegate));

        if (c->delegate) {
                _cleanup_free_ char *t = NULL;

                (void) cg_mask_to_string(c->delegate_controllers, &t);

                fprintf(f, "%sDelegateControllers=%s\n",
                        prefix,
                        strempty(t));
        }

        LIST_FOREACH(device_allow, a, c->device_allow)
                fprintf(f,
                        "%sDeviceAllow=%s %s%s%s\n",
                        prefix,
                        a->path,
                        a->r ? "r" : "", a->w ? "w" : "", a->m ? "m" : "");

        LIST_FOREACH(device_weights, iw, c->io_device_weights)
                fprintf(f,
                        "%sIODeviceWeight=%s %" PRIu64 "\n",
                        prefix,
                        iw->path,
                        iw->weight);

        LIST_FOREACH(device_latencies, l, c->io_device_latencies)
                fprintf(f,
                        "%sIODeviceLatencyTargetSec=%s %s\n",
                        prefix,
                        l->path,
                        format_timespan(u, sizeof(u), l->target_usec, 1));

        LIST_FOREACH(device_limits, il, c->io_device_limits) {
                char buf[FORMAT_BYTES_MAX];
                CGroupIOLimitType type;

                for (type = 0; type < _CGROUP_IO_LIMIT_TYPE_MAX; type++)
                        if (il->limits[type] != cgroup_io_limit_defaults[type])
                                fprintf(f,
                                        "%s%s=%s %s\n",
                                        prefix,
                                        cgroup_io_limit_type_to_string(type),
                                        il->path,
                                        format_bytes(buf, sizeof(buf), il->limits[type]));
        }

        LIST_FOREACH(device_weights, w, c->blockio_device_weights)
                fprintf(f,
                        "%sBlockIODeviceWeight=%s %" PRIu64,
                        prefix,
                        w->path,
                        w->weight);

        LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths) {
                char buf[FORMAT_BYTES_MAX];

                if (b->rbps != CGROUP_LIMIT_MAX)
                        fprintf(f,
                                "%sBlockIOReadBandwidth=%s %s\n",
                                prefix,
                                b->path,
                                format_bytes(buf, sizeof(buf), b->rbps));
                if (b->wbps != CGROUP_LIMIT_MAX)
                        fprintf(f,
                                "%sBlockIOWriteBandwidth=%s %s\n",
                                prefix,
                                b->path,
                                format_bytes(buf, sizeof(buf), b->wbps));
        }

        LIST_FOREACH(items, iaai, c->ip_address_allow) {
                _cleanup_free_ char *k = NULL;

                (void) in_addr_to_string(iaai->family, &iaai->address, &k);
                fprintf(f, "%sIPAddressAllow=%s/%u\n", prefix, strnull(k), iaai->prefixlen);
        }

        LIST_FOREACH(items, iaai, c->ip_address_deny) {
                _cleanup_free_ char *k = NULL;

                (void) in_addr_to_string(iaai->family, &iaai->address, &k);
                fprintf(f, "%sIPAddressDeny=%s/%u\n", prefix, strnull(k), iaai->prefixlen);
        }

        STRV_FOREACH(path, c->ip_filters_ingress)
                fprintf(f, "%sIPIngressFilterPath=%s\n", prefix, *path);

        STRV_FOREACH(path, c->ip_filters_egress)
                fprintf(f, "%sIPEgressFilterPath=%s\n", prefix, *path);
}

int cgroup_add_device_allow(CGroupContext *c, const char *dev, const char *mode) {
        _cleanup_free_ CGroupDeviceAllow *a = NULL;
        _cleanup_free_ char *d = NULL;

        assert(c);
        assert(dev);
        assert(isempty(mode) || in_charset(mode, "rwm"));

        a = new(CGroupDeviceAllow, 1);
        if (!a)
                return -ENOMEM;

        d = strdup(dev);
        if (!d)
                return -ENOMEM;

        *a = (CGroupDeviceAllow) {
                .path = TAKE_PTR(d),
                .r = isempty(mode) || strchr(mode, 'r'),
                .w = isempty(mode) || strchr(mode, 'w'),
                .m = isempty(mode) || strchr(mode, 'm'),
        };

        LIST_PREPEND(device_allow, c->device_allow, a);
        TAKE_PTR(a);

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
                while ((u = UNIT_DEREF(u->slice))) {                    \
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
UNIT_DEFINE_ANCESTOR_MEMORY_LOOKUP(memory_min);

static void cgroup_xattr_apply(Unit *u) {
        char ids[SD_ID128_STRING_MAX];
        int r;

        assert(u);

        if (!MANAGER_IS_SYSTEM(u->manager))
                return;

        if (sd_id128_is_null(u->invocation_id))
                return;

        r = cg_set_xattr(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path,
                         "trusted.invocation_id",
                         sd_id128_to_string(u->invocation_id, ids), 32,
                         0);
        if (r < 0)
                log_unit_debug_errno(u, r, "Failed to set invocation ID on control group %s, ignoring: %m", u->cgroup_path);
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
                rdev = (dev_t)st.st_rdev;
                dev = (dev_t)st.st_dev;
                mode = st.st_mode;
        } else if (r < 0)
                return log_warning_errno(r, "Failed to parse major/minor from path '%s': %m", p);

        if (S_ISCHR(mode)) {
                log_warning("Device node '%s' is a character device, but block device needed.", p);
                return -ENOTBLK;
        } else if (S_ISBLK(mode))
                *ret = rdev;
        else if (major(dev) != 0)
                *ret = dev; /* If this is not a device node then use the block device this file is stored on */
        else {
                /* If this is btrfs, getting the backing block device is a bit harder */
                r = btrfs_get_block_device(p, ret);
                if (r < 0 && r != -ENOTTY)
                        return log_warning_errno(r, "Failed to determine block device backing btrfs file system '%s': %m", p);
                if (r == -ENOTTY) {
                        log_warning("'%s' is not a block device node, and file system block device cannot be determined or is not local.", p);
                        return -ENODEV;
                }
        }

        /* If this is a LUKS device, try to get the originating block device */
        (void) block_get_originating(*ret, ret);

        /* If this is a partition, try to get the originating block device */
        (void) block_get_whole_disk(*ret, ret);
        return 0;
}

static int whitelist_device(BPFProgram *prog, const char *path, const char *node, const char *acc) {
        dev_t rdev;
        mode_t mode;
        int r;

        assert(path);
        assert(acc);

        /* Some special handling for /dev/block/%u:%u, /dev/char/%u:%u, /run/systemd/inaccessible/chr and
         * /run/systemd/inaccessible/blk paths. Instead of stat()ing these we parse out the major/minor directly. This
         * means clients can use these path without the device node actually around */
        r = device_path_parse_major_minor(node, &mode, &rdev);
        if (r < 0) {
                if (r != -ENODEV)
                        return log_warning_errno(r, "Couldn't parse major/minor from device path '%s': %m", node);

                struct stat st;
                if (stat(node, &st) < 0)
                        return log_warning_errno(errno, "Couldn't stat device %s: %m", node);

                if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode)) {
                        log_warning("%s is not a device.", node);
                        return -ENODEV;
                }
                rdev = (dev_t) st.st_rdev;
                mode = st.st_mode;
        }

        if (cg_all_unified() > 0) {
                if (!prog)
                        return 0;

                return cgroup_bpf_whitelist_device(prog, S_ISCHR(mode) ? BPF_DEVCG_DEV_CHAR : BPF_DEVCG_DEV_BLOCK,
                                                   major(rdev), minor(rdev), acc);

        } else {
                char buf[2+DECIMAL_STR_MAX(dev_t)*2+2+4];

                sprintf(buf,
                        "%c %u:%u %s",
                        S_ISCHR(mode) ? 'c' : 'b',
                        major(rdev), minor(rdev),
                        acc);

                /* Changing the devices list of a populated cgroup might result in EINVAL, hence ignore EINVAL here. */

                r = cg_set_attribute("devices", path, "devices.allow", buf);
                if (r < 0)
                        return log_full_errno(IN_SET(r, -ENOENT, -EROFS, -EINVAL, -EACCES, -EPERM) ? LOG_DEBUG : LOG_WARNING,
                                              r, "Failed to set devices.allow on %s: %m", path);

                return 0;
        }
}

static int whitelist_major(BPFProgram *prog, const char *path, const char *name, char type, const char *acc) {
        _cleanup_fclose_ FILE *f = NULL;
        char buf[2+DECIMAL_STR_MAX(unsigned)+3+4];
        bool good = false;
        unsigned maj;
        int r;

        assert(path);
        assert(acc);
        assert(IN_SET(type, 'b', 'c'));

        if (streq(name, "*")) {
                /* If the name is a wildcard, then apply this list to all devices of this type */

                if (cg_all_unified() > 0) {
                        if (!prog)
                                return 0;

                        (void) cgroup_bpf_whitelist_class(prog, type == 'c' ? BPF_DEVCG_DEV_CHAR : BPF_DEVCG_DEV_BLOCK, acc);
                } else {
                        xsprintf(buf, "%c *:* %s", type, acc);

                        r = cg_set_attribute("devices", path, "devices.allow", buf);
                        if (r < 0)
                                log_full_errno(IN_SET(r, -ENOENT, -EROFS, -EINVAL, -EACCES) ? LOG_DEBUG : LOG_WARNING, r,
                                               "Failed to set devices.allow on %s: %m", path);
                        return 0;
                }
        }

        if (safe_atou(name, &maj) >= 0 && DEVICE_MAJOR_VALID(maj)) {
                /* The name is numeric and suitable as major. In that case, let's take is major, and create the entry
                 * directly */

                if (cg_all_unified() > 0) {
                        if (!prog)
                                return 0;

                        (void) cgroup_bpf_whitelist_major(prog,
                                                          type == 'c' ? BPF_DEVCG_DEV_CHAR : BPF_DEVCG_DEV_BLOCK,
                                                          maj, acc);
                } else {
                        xsprintf(buf, "%c %u:* %s", type, maj, acc);

                        r = cg_set_attribute("devices", path, "devices.allow", buf);
                        if (r < 0)
                                log_full_errno(IN_SET(r, -ENOENT, -EROFS, -EINVAL, -EACCES) ? LOG_DEBUG : LOG_WARNING, r,
                                               "Failed to set devices.allow on %s: %m", path);
                }

                return 0;
        }

        f = fopen("/proc/devices", "re");
        if (!f)
                return log_warning_errno(errno, "Cannot open /proc/devices to resolve %s (%c): %m", name, type);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *w, *p;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_warning_errno(r, "Failed to read /proc/devices: %m");
                if (r == 0)
                        break;

                if (type == 'c' && streq(line, "Character devices:")) {
                        good = true;
                        continue;
                }

                if (type == 'b' && streq(line, "Block devices:")) {
                        good = true;
                        continue;
                }

                if (isempty(line)) {
                        good = false;
                        continue;
                }

                if (!good)
                        continue;

                p = strstrip(line);

                w = strpbrk(p, WHITESPACE);
                if (!w)
                        continue;
                *w = 0;

                r = safe_atou(p, &maj);
                if (r < 0)
                        continue;
                if (maj <= 0)
                        continue;

                w++;
                w += strspn(w, WHITESPACE);

                if (fnmatch(name, w, 0) != 0)
                        continue;

                if (cg_all_unified() > 0) {
                        if (!prog)
                                continue;

                        (void) cgroup_bpf_whitelist_major(prog,
                                                          type == 'c' ? BPF_DEVCG_DEV_CHAR : BPF_DEVCG_DEV_BLOCK,
                                                          maj, acc);
                } else {
                        sprintf(buf,
                                "%c %u:* %s",
                                type,
                                maj,
                                acc);

                        /* Changing the devices list of a populated cgroup might result in EINVAL, hence ignore EINVAL
                         * here. */

                        r = cg_set_attribute("devices", path, "devices.allow", buf);
                        if (r < 0)
                                log_full_errno(IN_SET(r, -ENOENT, -EROFS, -EINVAL, -EACCES, -EPERM) ? LOG_DEBUG : LOG_WARNING,
                                               r, "Failed to set devices.allow on %s: %m", path);
                }
        }

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

static uint64_t cgroup_context_cpu_weight(CGroupContext *c, ManagerState state) {
        if (IN_SET(state, MANAGER_STARTING, MANAGER_INITIALIZING) &&
            c->startup_cpu_weight != CGROUP_WEIGHT_INVALID)
                return c->startup_cpu_weight;
        else if (c->cpu_weight != CGROUP_WEIGHT_INVALID)
                return c->cpu_weight;
        else
                return CGROUP_WEIGHT_DEFAULT;
}

static uint64_t cgroup_context_cpu_shares(CGroupContext *c, ManagerState state) {
        if (IN_SET(state, MANAGER_STARTING, MANAGER_INITIALIZING) &&
            c->startup_cpu_shares != CGROUP_CPU_SHARES_INVALID)
                return c->startup_cpu_shares;
        else if (c->cpu_shares != CGROUP_CPU_SHARES_INVALID)
                return c->cpu_shares;
        else
                return CGROUP_CPU_SHARES_DEFAULT;
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
                char v[FORMAT_TIMESPAN_MAX];
                log_unit_full(u, u->warned_clamping_cpu_quota_period ? LOG_DEBUG : LOG_WARNING, 0,
                              "Clamping CPU interval for cpu.max: period is now %s",
                              format_timespan(v, sizeof(v), new_period, 1));
                u->warned_clamping_cpu_quota_period = true;
        }

        return new_period;
}

static void cgroup_apply_unified_cpu_weight(Unit *u, uint64_t weight) {
        char buf[DECIMAL_STR_MAX(uint64_t) + 2];

        xsprintf(buf, "%" PRIu64 "\n", weight);
        (void) set_attribute_and_warn(u, "cpu", "cpu.weight", buf);
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
        return CLAMP(weight * CGROUP_CPU_SHARES_DEFAULT / CGROUP_WEIGHT_DEFAULT,
                     CGROUP_CPU_SHARES_MIN, CGROUP_CPU_SHARES_MAX);
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
        if (IN_SET(state, MANAGER_STARTING, MANAGER_INITIALIZING) &&
            c->startup_io_weight != CGROUP_WEIGHT_INVALID)
                return c->startup_io_weight;
        else if (c->io_weight != CGROUP_WEIGHT_INVALID)
                return c->io_weight;
        else
                return CGROUP_WEIGHT_DEFAULT;
}

static uint64_t cgroup_context_blkio_weight(CGroupContext *c, ManagerState state) {
        if (IN_SET(state, MANAGER_STARTING, MANAGER_INITIALIZING) &&
            c->startup_blockio_weight != CGROUP_BLKIO_WEIGHT_INVALID)
                return c->startup_blockio_weight;
        else if (c->blockio_weight != CGROUP_BLKIO_WEIGHT_INVALID)
                return c->blockio_weight;
        else
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

static void cgroup_apply_io_device_weight(Unit *u, const char *dev_path, uint64_t io_weight) {
        char buf[DECIMAL_STR_MAX(dev_t)*2+2+DECIMAL_STR_MAX(uint64_t)+1];
        dev_t dev;
        int r;

        r = lookup_block_device(dev_path, &dev);
        if (r < 0)
                return;

        xsprintf(buf, "%u:%u %" PRIu64 "\n", major(dev), minor(dev), io_weight);
        (void) set_attribute_and_warn(u, "io", "io.weight", buf);
}

static void cgroup_apply_blkio_device_weight(Unit *u, const char *dev_path, uint64_t blkio_weight) {
        char buf[DECIMAL_STR_MAX(dev_t)*2+2+DECIMAL_STR_MAX(uint64_t)+1];
        dev_t dev;
        int r;

        r = lookup_block_device(dev_path, &dev);
        if (r < 0)
                return;

        xsprintf(buf, "%u:%u %" PRIu64 "\n", major(dev), minor(dev), blkio_weight);
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
                xsprintf(buf, "%u:%u target=%" PRIu64 "\n", major(dev), minor(dev), target);
        else
                xsprintf(buf, "%u:%u target=max\n", major(dev), minor(dev));

        (void) set_attribute_and_warn(u, "io", "io.latency", buf);
}

static void cgroup_apply_io_device_limit(Unit *u, const char *dev_path, uint64_t *limits) {
        char limit_bufs[_CGROUP_IO_LIMIT_TYPE_MAX][DECIMAL_STR_MAX(uint64_t)];
        char buf[DECIMAL_STR_MAX(dev_t)*2+2+(6+DECIMAL_STR_MAX(uint64_t)+1)*4];
        CGroupIOLimitType type;
        dev_t dev;
        int r;

        r = lookup_block_device(dev_path, &dev);
        if (r < 0)
                return;

        for (type = 0; type < _CGROUP_IO_LIMIT_TYPE_MAX; type++)
                if (limits[type] != cgroup_io_limit_defaults[type])
                        xsprintf(limit_bufs[type], "%" PRIu64, limits[type]);
                else
                        xsprintf(limit_bufs[type], "%s", limits[type] == CGROUP_LIMIT_MAX ? "max" : "0");

        xsprintf(buf, "%u:%u rbps=%s wbps=%s riops=%s wiops=%s\n", major(dev), minor(dev),
                 limit_bufs[CGROUP_IO_RBPS_MAX], limit_bufs[CGROUP_IO_WBPS_MAX],
                 limit_bufs[CGROUP_IO_RIOPS_MAX], limit_bufs[CGROUP_IO_WIOPS_MAX]);
        (void) set_attribute_and_warn(u, "io", "io.max", buf);
}

static void cgroup_apply_blkio_device_limit(Unit *u, const char *dev_path, uint64_t rbps, uint64_t wbps) {
        char buf[DECIMAL_STR_MAX(dev_t)*2+2+DECIMAL_STR_MAX(uint64_t)+1];
        dev_t dev;
        int r;

        r = lookup_block_device(dev_path, &dev);
        if (r < 0)
                return;

        sprintf(buf, "%u:%u %" PRIu64 "\n", major(dev), minor(dev), rbps);
        (void) set_attribute_and_warn(u, "blkio", "blkio.throttle.read_bps_device", buf);

        sprintf(buf, "%u:%u %" PRIu64 "\n", major(dev), minor(dev), wbps);
        (void) set_attribute_and_warn(u, "blkio", "blkio.throttle.write_bps_device", buf);
}

static bool unit_has_unified_memory_config(Unit *u) {
        CGroupContext *c;

        assert(u);

        c = unit_get_cgroup_context(u);
        assert(c);

        return c->memory_min > 0 || unit_get_ancestor_memory_low(u) > 0 ||
               c->memory_high != CGROUP_LIMIT_MAX || c->memory_max != CGROUP_LIMIT_MAX ||
               c->memory_swap_max != CGROUP_LIMIT_MAX;
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

        /* The 'io' controller attributes are not exported on the host's root cgroup (being a pure cgroup v2
         * controller), and in case of containers we want to leave control of these attributes to the container manager
         * (and we couldn't access that stuff anyway, even if we tried if proper delegation is used). */
        if ((apply_mask & CGROUP_MASK_IO) && !is_local_root) {
                char buf[8+DECIMAL_STR_MAX(uint64_t)+1];
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

                xsprintf(buf, "default %" PRIu64 "\n", weight);
                (void) set_attribute_and_warn(u, "io", "io.weight", buf);

                /* FIXME: drop this when distro kernels properly support BFQ through "io.weight"
                 * See also: https://github.com/systemd/systemd/pull/13335 */
                xsprintf(buf, "%" PRIu64 "\n", weight);
                (void) set_attribute_and_warn(u, "io", "io.bfq.weight", buf);

                if (has_io) {
                        CGroupIODeviceLatency *latency;
                        CGroupIODeviceLimit *limit;
                        CGroupIODeviceWeight *w;

                        LIST_FOREACH(device_weights, w, c->io_device_weights)
                                cgroup_apply_io_device_weight(u, w->path, w->weight);

                        LIST_FOREACH(device_limits, limit, c->io_device_limits)
                                cgroup_apply_io_device_limit(u, limit->path, limit->limits);

                        LIST_FOREACH(device_latencies, latency, c->io_device_latencies)
                                cgroup_apply_io_device_latency(u, latency->path, latency->target_usec);

                } else if (has_blockio) {
                        CGroupBlockIODeviceWeight *w;
                        CGroupBlockIODeviceBandwidth *b;

                        LIST_FOREACH(device_weights, w, c->blockio_device_weights) {
                                weight = cgroup_weight_blkio_to_io(w->weight);

                                log_cgroup_compat(u, "Applying BlockIODeviceWeight=%" PRIu64 " as IODeviceWeight=%" PRIu64 " for %s",
                                                  w->weight, weight, w->path);

                                cgroup_apply_io_device_weight(u, w->path, weight);
                        }

                        LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths) {
                                uint64_t limits[_CGROUP_IO_LIMIT_TYPE_MAX];
                                CGroupIOLimitType type;

                                for (type = 0; type < _CGROUP_IO_LIMIT_TYPE_MAX; type++)
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
                        char buf[DECIMAL_STR_MAX(uint64_t)+1];
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

                        xsprintf(buf, "%" PRIu64 "\n", weight);
                        (void) set_attribute_and_warn(u, "blkio", "blkio.weight", buf);

                        if (has_io) {
                                CGroupIODeviceWeight *w;

                                LIST_FOREACH(device_weights, w, c->io_device_weights) {
                                        weight = cgroup_weight_io_to_blkio(w->weight);

                                        log_cgroup_compat(u, "Applying IODeviceWeight=%" PRIu64 " as BlockIODeviceWeight=%" PRIu64 " for %s",
                                                          w->weight, weight, w->path);

                                        cgroup_apply_blkio_device_weight(u, w->path, weight);
                                }
                        } else if (has_blockio) {
                                CGroupBlockIODeviceWeight *w;

                                LIST_FOREACH(device_weights, w, c->blockio_device_weights)
                                        cgroup_apply_blkio_device_weight(u, w->path, w->weight);
                        }
                }

                /* The bandwidth limits are something that make sense to be applied to the host's root but not container
                 * roots, as there we want the container manager to handle it */
                if (is_host_root || !is_local_root) {
                        if (has_io) {
                                CGroupIODeviceLimit *l;

                                LIST_FOREACH(device_limits, l, c->io_device_limits) {
                                        log_cgroup_compat(u, "Applying IO{Read|Write}Bandwidth=%" PRIu64 " %" PRIu64 " as BlockIO{Read|Write}BandwidthMax= for %s",
                                                          l->limits[CGROUP_IO_RBPS_MAX], l->limits[CGROUP_IO_WBPS_MAX], l->path);

                                        cgroup_apply_blkio_device_limit(u, l->path, l->limits[CGROUP_IO_RBPS_MAX], l->limits[CGROUP_IO_WBPS_MAX]);
                                }
                        } else if (has_blockio) {
                                CGroupBlockIODeviceBandwidth *b;

                                LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths)
                                        cgroup_apply_blkio_device_limit(u, b->path, b->rbps, b->wbps);
                        }
                }
        }

        /* In unified mode 'memory' attributes do not exist on the root cgroup. In legacy mode 'memory.limit_in_bytes'
         * exists on the root cgroup, but any writes to it are refused with EINVAL. And if we run in a container we
         * want to leave control to the container manager (and if proper cgroup v2 delegation is used we couldn't even
         * write to this if we wanted to.) */
        if ((apply_mask & CGROUP_MASK_MEMORY) && !is_local_root) {

                if (cg_all_unified() > 0) {
                        uint64_t max, swap_max = CGROUP_LIMIT_MAX;

                        if (unit_has_unified_memory_config(u)) {
                                max = c->memory_max;
                                swap_max = c->memory_swap_max;
                        } else {
                                max = c->memory_limit;

                                if (max != CGROUP_LIMIT_MAX)
                                        log_cgroup_compat(u, "Applying MemoryLimit=%" PRIu64 " as MemoryMax=", max);
                        }

                        cgroup_apply_unified_memory_limit(u, "memory.min", c->memory_min);
                        cgroup_apply_unified_memory_limit(u, "memory.low", unit_get_ancestor_memory_low(u));
                        cgroup_apply_unified_memory_limit(u, "memory.high", c->memory_high);
                        cgroup_apply_unified_memory_limit(u, "memory.max", max);
                        cgroup_apply_unified_memory_limit(u, "memory.swap.max", swap_max);

                        (void) set_attribute_and_warn(u, "memory", "memory.oom.group", one_zero(c->memory_oom_group));

                } else {
                        char buf[DECIMAL_STR_MAX(uint64_t) + 1];
                        uint64_t val;

                        if (unit_has_unified_memory_config(u)) {
                                val = c->memory_max;
                                log_cgroup_compat(u, "Applying MemoryMax=%" PRIi64 " as MemoryLimit=", val);
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
            (is_host_root || cg_all_unified() > 0 || !is_local_root)) {
                _cleanup_(bpf_program_unrefp) BPFProgram *prog = NULL;
                CGroupDeviceAllow *a;

                if (cg_all_unified() > 0) {
                        r = cgroup_init_device_bpf(&prog, c->device_policy, c->device_allow);
                        if (r < 0)
                                log_unit_warning_errno(u, r, "Failed to initialize device control bpf program: %m");
                } else {
                        /* Changing the devices list of a populated cgroup might result in EINVAL, hence ignore EINVAL
                         * here. */

                        if (c->device_allow || c->device_policy != CGROUP_AUTO)
                                r = cg_set_attribute("devices", path, "devices.deny", "a");
                        else
                                r = cg_set_attribute("devices", path, "devices.allow", "a");
                        if (r < 0)
                                log_unit_full(u, IN_SET(r, -ENOENT, -EROFS, -EINVAL, -EACCES, -EPERM) ? LOG_DEBUG : LOG_WARNING, r,
                                              "Failed to reset devices.allow/devices.deny: %m");
                }

                if (c->device_policy == CGROUP_CLOSED ||
                    (c->device_policy == CGROUP_AUTO && c->device_allow)) {
                        static const char auto_devices[] =
                                "/dev/null\0" "rwm\0"
                                "/dev/zero\0" "rwm\0"
                                "/dev/full\0" "rwm\0"
                                "/dev/random\0" "rwm\0"
                                "/dev/urandom\0" "rwm\0"
                                "/dev/tty\0" "rwm\0"
                                "/dev/ptmx\0" "rwm\0"
                                /* Allow /run/systemd/inaccessible/{chr,blk} devices for mapping InaccessiblePaths */
                                "/run/systemd/inaccessible/chr\0" "rwm\0"
                                "/run/systemd/inaccessible/blk\0" "rwm\0";

                        const char *x, *y;

                        NULSTR_FOREACH_PAIR(x, y, auto_devices)
                                (void) whitelist_device(prog, path, x, y);

                        /* PTS (/dev/pts) devices may not be duplicated, but accessed */
                        (void) whitelist_major(prog, path, "pts", 'c', "rw");
                }

                LIST_FOREACH(device_allow, a, c->device_allow) {
                        char acc[4], *val;
                        unsigned k = 0;

                        if (a->r)
                                acc[k++] = 'r';
                        if (a->w)
                                acc[k++] = 'w';
                        if (a->m)
                                acc[k++] = 'm';

                        if (k == 0)
                                continue;

                        acc[k++] = 0;

                        if (path_startswith(a->path, "/dev/"))
                                (void) whitelist_device(prog, path, a->path, acc);
                        else if ((val = startswith(a->path, "block-")))
                                (void) whitelist_major(prog, path, val, 'b', acc);
                        else if ((val = startswith(a->path, "char-")))
                                (void) whitelist_major(prog, path, val, 'c', acc);
                        else
                                log_unit_debug(u, "Ignoring device '%s' while writing cgroup attribute.", a->path);
                }

                r = cgroup_apply_device_bpf(u, prog, c->device_policy, c->device_allow);
                if (r < 0) {
                        static bool warned = false;

                        log_full_errno(warned ? LOG_DEBUG : LOG_WARNING, r,
                                 "Unit %s configures device ACL, but the local system doesn't seem to support the BPF-based device controller.\n"
                                 "Proceeding WITHOUT applying ACL (all devices will be accessible)!\n"
                                 "(This warning is only shown for the first loaded unit using device ACL.)", u->id);

                        warned = true;
                }
        }

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

                        if (c->tasks_max != CGROUP_LIMIT_MAX) {
                                u->manager->sysctl_pid_max_changed = true;
                                r = procfs_tasks_set_limit(c->tasks_max);
                        } else if (u->manager->sysctl_pid_max_changed)
                                r = procfs_tasks_set_limit(TASKS_MAX);
                        else
                                r = 0;
                        if (r < 0)
                                log_unit_full(u, LOG_LEVEL_CGROUP_WRITE(r), r,
                                              "Failed to write to tasks limit sysctls: %m");
                }

                /* The attribute itself is not available on the host root cgroup, and in the container case we want to
                 * leave it for the container manager. */
                if (!is_local_root) {
                        if (c->tasks_max != CGROUP_LIMIT_MAX) {
                                char buf[DECIMAL_STR_MAX(uint64_t) + 2];

                                sprintf(buf, "%" PRIu64 "\n", c->tasks_max);
                                (void) set_attribute_and_warn(u, "pids", "pids.max", buf);
                        } else
                                (void) set_attribute_and_warn(u, "pids", "pids.max", "max\n");
                }
        }

        if (apply_mask & CGROUP_MASK_BPF_FIREWALL)
                cgroup_apply_firewall(u);
}

static bool unit_get_needs_bpf_firewall(Unit *u) {
        CGroupContext *c;
        Unit *p;
        assert(u);

        c = unit_get_cgroup_context(u);
        if (!c)
                return false;

        if (c->ip_accounting ||
            c->ip_address_allow ||
            c->ip_address_deny ||
            c->ip_filters_ingress ||
            c->ip_filters_egress)
                return true;

        /* If any parent slice has an IP access list defined, it applies too */
        for (p = UNIT_DEREF(u->slice); p; p = UNIT_DEREF(p->slice)) {
                c = unit_get_cgroup_context(p);
                if (!c)
                        return false;

                if (c->ip_address_allow ||
                    c->ip_address_deny)
                        return true;
        }

        return false;
}

static CGroupMask unit_get_cgroup_mask(Unit *u) {
        CGroupMask mask = 0;
        CGroupContext *c;

        assert(u);

        c = unit_get_cgroup_context(u);

        assert(c);

        /* Figure out which controllers we need, based on the cgroup context object */

        if (c->cpu_accounting)
                mask |= get_cpu_accounting_mask();

        if (cgroup_context_has_cpu_weight(c) ||
            cgroup_context_has_cpu_shares(c) ||
            c->cpu_quota_per_sec_usec != USEC_INFINITY)
                mask |= CGROUP_MASK_CPU;

        if (cgroup_context_has_io_config(c) || cgroup_context_has_blockio_config(c))
                mask |= CGROUP_MASK_IO | CGROUP_MASK_BLKIO;

        if (c->memory_accounting ||
            c->memory_limit != CGROUP_LIMIT_MAX ||
            unit_has_unified_memory_config(u))
                mask |= CGROUP_MASK_MEMORY;

        if (c->device_allow ||
            c->device_policy != CGROUP_AUTO)
                mask |= CGROUP_MASK_DEVICES | CGROUP_MASK_BPF_DEVICES;

        if (c->tasks_accounting ||
            c->tasks_max != CGROUP_LIMIT_MAX)
                mask |= CGROUP_MASK_PIDS;

        return CGROUP_MASK_EXTEND_JOINED(mask);
}

static CGroupMask unit_get_bpf_mask(Unit *u) {
        CGroupMask mask = 0;

        /* Figure out which controllers we need, based on the cgroup context, possibly taking into account children
         * too. */

        if (unit_get_needs_bpf_firewall(u))
                mask |= CGROUP_MASK_BPF_FIREWALL;

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

        return (unit_get_cgroup_mask(u) | unit_get_bpf_mask(u) | unit_get_delegate_mask(u)) & ~unit_get_ancestor_disable_mask(u);
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

CGroupMask unit_get_members_mask(Unit *u) {
        assert(u);

        /* Returns the mask of controllers all of the unit's children require, merged */

        if (u->cgroup_members_mask_valid)
                return u->cgroup_members_mask; /* Use cached value if possible */

        u->cgroup_members_mask = 0;

        if (u->type == UNIT_SLICE) {
                void *v;
                Unit *member;
                Iterator i;

                HASHMAP_FOREACH_KEY(v, member, u->dependencies[UNIT_BEFORE], i) {
                        if (UNIT_DEREF(member->slice) == u)
                                u->cgroup_members_mask |= unit_get_subtree_mask(member); /* note that this calls ourselves again, for the children */
                }
        }

        u->cgroup_members_mask_valid = true;
        return u->cgroup_members_mask;
}

CGroupMask unit_get_siblings_mask(Unit *u) {
        assert(u);

        /* Returns the mask of controllers all of the unit's siblings
         * require, i.e. the members mask of the unit's parent slice
         * if there is one. */

        if (UNIT_ISSET(u->slice))
                return unit_get_members_mask(UNIT_DEREF(u->slice));

        return unit_get_subtree_mask(u); /* we are the top-level slice */
}

CGroupMask unit_get_disable_mask(Unit *u) {
        CGroupContext *c;

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        return c->disable_controllers;
}

CGroupMask unit_get_ancestor_disable_mask(Unit *u) {
        CGroupMask mask;

        assert(u);
        mask = unit_get_disable_mask(u);

        /* Returns the mask of controllers which are marked as forcibly
         * disabled in any ancestor unit or the unit in question. */

        if (UNIT_ISSET(u->slice))
                mask |= unit_get_ancestor_disable_mask(UNIT_DEREF(u->slice));

        return mask;
}

CGroupMask unit_get_subtree_mask(Unit *u) {

        /* Returns the mask of this subtree, meaning of the group
         * itself and its children. */

        return unit_get_own_mask(u) | unit_get_members_mask(u);
}

CGroupMask unit_get_target_mask(Unit *u) {
        CGroupMask mask;

        /* This returns the cgroup mask of all controllers to enable
         * for a specific cgroup, i.e. everything it needs itself,
         * plus all that its children need, plus all that its siblings
         * need. This is primarily useful on the legacy cgroup
         * hierarchy, where we need to duplicate each cgroup in each
         * hierarchy that shall be enabled for it. */

        mask = unit_get_own_mask(u) | unit_get_members_mask(u) | unit_get_siblings_mask(u);

        if (mask & CGROUP_MASK_BPF_FIREWALL & ~u->manager->cgroup_supported)
                emit_bpf_firewall_warning(u);

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
        assert(u);

        /* Recurse invalidate the member masks cache all the way up the tree */
        u->cgroup_members_mask_valid = false;

        if (UNIT_ISSET(u->slice))
                unit_invalidate_cgroup_members_masks(UNIT_DEREF(u->slice));
}

const char *unit_get_realized_cgroup_path(Unit *u, CGroupMask mask) {

        /* Returns the realized cgroup path of the specified unit where all specified controllers are available. */

        while (u) {

                if (u->cgroup_path &&
                    u->cgroup_realized &&
                    FLAGS_SET(u->cgroup_realized_mask, mask))
                        return u->cgroup_path;

                u = UNIT_DEREF(u->slice);
        }

        return NULL;
}

static const char *migrate_callback(CGroupMask mask, void *userdata) {
        return unit_get_realized_cgroup_path(userdata, mask);
}

char *unit_default_cgroup_path(const Unit *u) {
        _cleanup_free_ char *escaped = NULL, *slice = NULL;
        int r;

        assert(u);

        if (unit_has_name(u, SPECIAL_ROOT_SLICE))
                return strdup(u->manager->cgroup_root);

        if (UNIT_ISSET(u->slice) && !unit_has_name(UNIT_DEREF(u->slice), SPECIAL_ROOT_SLICE)) {
                r = cg_slice_to_path(UNIT_DEREF(u->slice)->id, &slice);
                if (r < 0)
                        return NULL;
        }

        escaped = cg_escape(u->id);
        if (!escaped)
                return NULL;

        return path_join(empty_to_root(u->manager->cgroup_root), slice, escaped);
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

                return log_unit_error_errno(u, errno, "Failed to add control inotify watch descriptor for control group %s: %m", u->cgroup_path);
        }

        r = hashmap_put(u->manager->cgroup_control_inotify_wd_unit, INT_TO_PTR(u->cgroup_control_inotify_wd), u);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to add control inotify watch descriptor to hash map: %m");

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

                return log_unit_error_errno(u, errno, "Failed to add memory inotify watch descriptor for control group %s: %m", u->cgroup_path);
        }

        r = hashmap_put(u->manager->cgroup_memory_inotify_wd_unit, INT_TO_PTR(u->cgroup_memory_inotify_wd), u);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to add memory inotify watch descriptor to hash map: %m");

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

        path = unit_default_cgroup_path(u);
        if (!path)
                return log_oom();

        r = unit_set_cgroup_path(u, path);
        if (r == -EEXIST)
                return log_unit_error_errno(u, r, "Control group %s exists already.", path);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to set unit's control group path to %s: %m", path);

        return 0;
}

static int unit_create_cgroup(
                Unit *u,
                CGroupMask target_mask,
                CGroupMask enable_mask,
                ManagerState state) {

        bool created;
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
                return log_unit_error_errno(u, r, "Failed to create cgroup %s: %m", u->cgroup_path);
        created = r;

        /* Start watching it */
        (void) unit_watch_cgroup(u);
        (void) unit_watch_cgroup_memory(u);

        /* Preserve enabled controllers in delegated units, adjust others. */
        if (created || !u->cgroup_realized || !unit_cgroup_delegate(u)) {
                CGroupMask result_mask = 0;

                /* Enable all controllers we need */
                r = cg_enable_everywhere(u->manager->cgroup_supported, enable_mask, u->cgroup_path, &result_mask);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to enable/disable controllers on cgroup %s, ignoring: %m", u->cgroup_path);

                /* If we just turned off a controller, this might release the controller for our parent too, let's
                 * enqueue the parent for re-realization in that case again. */
                if (UNIT_ISSET(u->slice)) {
                        CGroupMask turned_off;

                        turned_off = (u->cgroup_realized ? u->cgroup_enabled_mask & ~result_mask : 0);
                        if (turned_off != 0) {
                                Unit *parent;

                                /* Force the parent to propagate the enable mask to the kernel again, by invalidating
                                 * the controller we just turned off. */

                                for (parent = UNIT_DEREF(u->slice); parent; parent = UNIT_DEREF(parent->slice))
                                        unit_invalidate_cgroup(parent, turned_off);
                        }
                }

                /* Remember what's actually enabled now */
                u->cgroup_enabled_mask = result_mask;
        }

        /* Keep track that this is now realized */
        u->cgroup_realized = true;
        u->cgroup_realized_mask = target_mask;

        if (u->type != UNIT_SLICE && !unit_cgroup_delegate(u)) {

                /* Then, possibly move things over, but not if
                 * subgroups may contain processes, which is the case
                 * for slice and delegation units. */
                r = cg_migrate_everywhere(u->manager->cgroup_supported, u->cgroup_path, u->cgroup_path, migrate_callback, u);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to migrate cgroup from to %s, ignoring: %m", u->cgroup_path);
        }

        /* Set attributes */
        cgroup_context_apply(u, target_mask, state);
        cgroup_xattr_apply(u);

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
        path_simplify(pp, false);

        r = sd_bus_call_method(u->manager->system_bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "AttachProcessesToUnit",
                               &error, NULL,
                               "ssau",
                               NULL /* empty unit name means client's unit, i.e. us */, pp, 1, (uint32_t) pid);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to attach unit process " PID_FMT " via the bus: %s", pid, bus_error_message(&error, r));

        return 0;
}

int unit_attach_pids_to_cgroup(Unit *u, Set *pids, const char *suffix_path) {
        CGroupMask delegated_mask;
        const char *p;
        Iterator i;
        void *pidp;
        int r, q;

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
        else
                p = prefix_roota(u->cgroup_path, suffix_path);

        delegated_mask = unit_get_delegate_mask(u);

        r = 0;
        SET_FOREACH(pidp, pids, i) {
                pid_t pid = PTR_TO_PID(pidp);
                CGroupController c;

                /* First, attach the PID to the main cgroup hierarchy */
                q = cg_attach(SYSTEMD_CGROUP_CONTROLLER, p, pid);
                if (q < 0) {
                        log_unit_debug_errno(u, q, "Couldn't move process " PID_FMT " to requested cgroup '%s': %m", pid, p);

                        if (MANAGER_IS_USER(u->manager) && IN_SET(q, -EPERM, -EACCES)) {
                                int z;

                                /* If we are in a user instance, and we can't move the process ourselves due to
                                 * permission problems, let's ask the system instance about it instead. Since it's more
                                 * privileged it might be able to move the process across the leaves of a subtree who's
                                 * top node is not owned by us. */

                                z = unit_attach_pid_to_cgroup_via_bus(u, pid, suffix_path);
                                if (z < 0)
                                        log_unit_debug_errno(u, z, "Couldn't move process " PID_FMT " to requested cgroup '%s' via the system bus either: %m", pid, p);
                                else
                                        continue; /* When the bus thing worked via the bus we are fully done for this PID. */
                        }

                        if (r >= 0)
                                r = q; /* Remember first error */

                        continue;
                }

                q = cg_all_unified();
                if (q < 0)
                        return q;
                if (q > 0)
                        continue;

                /* In the legacy hierarchy, attach the process to the request cgroup if possible, and if not to the
                 * innermost realized one */

                for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                        CGroupMask bit = CGROUP_CONTROLLER_TO_MASK(c);
                        const char *realized;

                        if (!(u->manager->cgroup_supported & bit))
                                continue;

                        /* If this controller is delegated and realized, honour the caller's request for the cgroup suffix. */
                        if (delegated_mask & u->cgroup_realized_mask & bit) {
                                q = cg_attach(cgroup_controller_to_string(c), p, pid);
                                if (q >= 0)
                                        continue; /* Success! */

                                log_unit_debug_errno(u, q, "Failed to attach PID " PID_FMT " to requested cgroup %s in controller %s, falling back to unit's cgroup: %m",
                                                     pid, p, cgroup_controller_to_string(c));
                        }

                        /* So this controller is either not delegate or realized, or something else weird happened. In
                         * that case let's attach the PID at least to the closest cgroup up the tree that is
                         * realized. */
                        realized = unit_get_realized_cgroup_path(u, bit);
                        if (!realized)
                                continue; /* Not even realized in the root slice? Then let's not bother */

                        q = cg_attach(cgroup_controller_to_string(c), realized, pid);
                        if (q < 0)
                                log_unit_debug_errno(u, q, "Failed to attach PID " PID_FMT " to realized cgroup %s in controller %s, ignoring: %m",
                                                     pid, realized, cgroup_controller_to_string(c));
                }
        }

        return r;
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

        LIST_PREPEND(cgroup_realize_queue, u->manager->cgroup_realize_queue, u);
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
        int r;

        assert(u);

        /* First go deal with this unit's parent, or we won't be able to enable
         * any new controllers at this layer. */
        if (UNIT_ISSET(u->slice)) {
                r = unit_realize_cgroup_now_enable(UNIT_DEREF(u->slice), state);
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

        return unit_create_cgroup(u, new_target_mask, new_enable_mask, state);
}

/* Controllers can only be disabled depth-first, from the leaves of the
 * hierarchy upwards to the unit in question. */
static int unit_realize_cgroup_now_disable(Unit *u, ManagerState state) {
        Iterator i;
        Unit *m;
        void *v;

        assert(u);

        if (u->type != UNIT_SLICE)
                return 0;

        HASHMAP_FOREACH_KEY(v, m, u->dependencies[UNIT_BEFORE], i) {
                CGroupMask target_mask, enable_mask, new_target_mask, new_enable_mask;
                int r;

                if (UNIT_DEREF(m->slice) != u)
                        continue;

                /* The cgroup for this unit might not actually be fully
                 * realised yet, in which case it isn't holding any controllers
                 * open anyway. */
                if (!m->cgroup_path)
                        continue;

                /* We must disable those below us first in order to release the
                 * controller. */
                if (m->type == UNIT_SLICE)
                        (void) unit_realize_cgroup_now_disable(m, state);

                target_mask = unit_get_target_mask(m);
                enable_mask = unit_get_enable_mask(m);

                /* We can only disable in this direction, don't try to enable
                 * anything. */
                if (unit_has_mask_disables_realized(m, target_mask, enable_mask))
                        continue;

                new_target_mask = m->cgroup_realized_mask & target_mask;
                new_enable_mask = m->cgroup_enabled_mask & enable_mask;

                r = unit_create_cgroup(m, new_target_mask, new_enable_mask, state);
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
        if (UNIT_ISSET(u->slice)) {
                r = unit_realize_cgroup_now_enable(UNIT_DEREF(u->slice), state);
                if (r < 0)
                        return r;
        }

        /* Now actually deal with the cgroup we were trying to realise and set attributes */
        r = unit_create_cgroup(u, target_mask, enable_mask, state);
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

static void unit_add_siblings_to_cgroup_realize_queue(Unit *u) {
        Unit *slice;

        /* This adds the siblings of the specified unit and the
         * siblings of all parent units to the cgroup queue. (But
         * neither the specified unit itself nor the parents.) */

        while ((slice = UNIT_DEREF(u->slice))) {
                Iterator i;
                Unit *m;
                void *v;

                HASHMAP_FOREACH_KEY(v, m, u->dependencies[UNIT_BEFORE], i) {
                        /* Skip units that have a dependency on the slice
                         * but aren't actually in it. */
                        if (UNIT_DEREF(m->slice) != slice)
                                continue;

                        /* No point in doing cgroup application for units
                         * without active processes. */
                        if (UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(m)))
                                continue;

                        /* If the unit doesn't need any new controllers
                         * and has current ones realized, it doesn't need
                         * any changes. */
                        if (unit_has_mask_realized(m,
                                                   unit_get_target_mask(m),
                                                   unit_get_enable_mask(m)))
                                continue;

                        unit_add_to_cgroup_realize_queue(m);
                }

                u = slice;
        }
}

int unit_realize_cgroup(Unit *u) {
        assert(u);

        if (!UNIT_HAS_CGROUP_CONTEXT(u))
                return 0;

        /* So, here's the deal: when realizing the cgroups for this
         * unit, we need to first create all parents, but there's more
         * actually: for the weight-based controllers we also need to
         * make sure that all our siblings (i.e. units that are in the
         * same slice as we are) have cgroups, too. Otherwise, things
         * would become very uneven as each of their processes would
         * get as much resources as all our group together. This call
         * will synchronously create the parent cgroups, but will
         * defer work on the siblings to the next event loop
         * iteration. */

        /* Add all sibling slices to the cgroup queue. */
        unit_add_siblings_to_cgroup_realize_queue(u);

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

void unit_prune_cgroup(Unit *u) {
        int r;
        bool is_root_slice;

        assert(u);

        /* Removes the cgroup, if empty and possible, and stops watching it. */

        if (!u->cgroup_path)
                return;

        (void) unit_get_cpu_usage(u, NULL); /* Cache the last CPU usage value before we destroy the cgroup */

        is_root_slice = unit_has_name(u, SPECIAL_ROOT_SLICE);

        r = cg_trim_everywhere(u->manager->cgroup_supported, u->cgroup_path, !is_root_slice);
        if (r < 0)
                /* One reason we could have failed here is, that the cgroup still contains a process.
                 * However, if the cgroup becomes removable at a later time, it might be removed when
                 * the containing slice is stopped. So even if we failed now, this unit shouldn't assume
                 * that the cgroup is still realized the next time it is started. Do not return early
                 * on error, continue cleanup. */
                log_unit_full(u, r == -EBUSY ? LOG_DEBUG : LOG_WARNING, r, "Failed to destroy cgroup %s, ignoring: %m", u->cgroup_path);

        if (is_root_slice)
                return;

        unit_release_cgroup(u);

        u->cgroup_realized = false;
        u->cgroup_realized_mask = 0;
        u->cgroup_enabled_mask = 0;

        u->bpf_device_control_installed = bpf_program_unref(u->bpf_device_control_installed);
}

int unit_search_main_pid(Unit *u, pid_t *ret) {
        _cleanup_fclose_ FILE *f = NULL;
        pid_t pid = 0, npid;
        int r;

        assert(u);
        assert(ret);

        if (!u->cgroup_path)
                return -ENXIO;

        r = cg_enumerate_processes(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, &f);
        if (r < 0)
                return r;

        while (cg_read_pid(f, &npid) > 0)  {

                if (npid == pid)
                        continue;

                if (pid_is_my_child(npid) == 0)
                        continue;

                if (pid != 0)
                        /* Dang, there's more than one daemonized PID
                        in this group, so we don't know what process
                        is the main process. */

                        return -ENODATA;

                pid = npid;
        }

        *ret = pid;
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
                ret = r;
        else {
                pid_t pid;

                while ((r = cg_read_pid(f, &pid)) > 0) {
                        r = unit_watch_pid(u, pid, false);
                        if (r < 0 && ret >= 0)
                                ret = r;
                }

                if (r < 0 && ret >= 0)
                        ret = r;
        }

        r = cg_enumerate_subgroups(SYSTEMD_CGROUP_CONTROLLER, path, &d);
        if (r < 0) {
                if (ret >= 0)
                        ret = r;
        } else {
                char *fn;

                while ((r = cg_read_subgroup(d, &fn)) > 0) {
                        _cleanup_free_ char *p = NULL;

                        p = path_join(empty_to_root(path), fn);
                        free(fn);

                        if (!p)
                                return -ENOMEM;

                        r = unit_watch_pids_in_path(u, p);
                        if (r < 0 && ret >= 0)
                                ret = r;
                }

                if (r < 0 && ret >= 0)
                        ret = r;
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
        Manager *m = userdata;
        Unit *u;
        int r;

        assert(s);
        assert(m);

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

        unit_add_to_gc_queue(u);

        if (UNIT_VTABLE(u)->notify_cgroup_empty)
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
                log_unit_debug_errno(u, r, "Failed to determine whether cgroup %s is empty: %m", u->cgroup_path);
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

int unit_check_oom(Unit *u) {
        _cleanup_free_ char *oom_kill = NULL;
        bool increased;
        uint64_t c;
        int r;

        if (!u->cgroup_path)
                return 0;

        r = cg_get_keyed_attribute("memory", u->cgroup_path, "memory.events", STRV_MAKE("oom_kill"), &oom_kill);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to read oom_kill field of memory.events cgroup attribute: %m");

        r = safe_atou64(oom_kill, &c);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to parse oom_kill field: %m");

        increased = c > u->oom_kill_last;
        u->oom_kill_last = c;

        if (!increased)
                return 0;

        log_struct(LOG_NOTICE,
                   "MESSAGE_ID=" SD_MESSAGE_UNIT_OUT_OF_MEMORY_STR,
                   LOG_UNIT_ID(u),
                   LOG_UNIT_INVOCATION_ID(u),
                   LOG_UNIT_MESSAGE(u, "A process of this unit has been killed by the OOM killer."));

        if (UNIT_VTABLE(u)->notify_cgroup_oom)
                UNIT_VTABLE(u)->notify_cgroup_oom(u);

        return 1;
}

static int on_cgroup_oom_event(sd_event_source *s, void *userdata) {
        Manager *m = userdata;
        Unit *u;
        int r;

        assert(s);
        assert(m);

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

static int on_cgroup_inotify_event(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;

        assert(s);
        assert(fd >= 0);
        assert(m);

        for (;;) {
                union inotify_event_buffer buffer;
                struct inotify_event *e;
                ssize_t l;

                l = read(fd, &buffer, sizeof(buffer));
                if (l < 0) {
                        if (IN_SET(errno, EINTR, EAGAIN))
                                return 0;

                        return log_error_errno(errno, "Failed to read control group inotify events: %m");
                }

                FOREACH_INOTIFY_EVENT(e, buffer, l) {
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
                                unit_add_to_cgroup_empty_queue(u);

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
        if (r > 0)
                mask |= CGROUP_MASK_BPF_FIREWALL;

        /* BPF-based device access control */
        r = bpf_devices_supported();
        if (r > 0)
                mask |= CGROUP_MASK_BPF_DEVICES;

        *ret = mask;
        return 0;
}

int manager_setup_cgroup(Manager *m) {
        _cleanup_free_ char *path = NULL;
        const char *scope_path;
        CGroupController c;
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

        r = cg_unified_flush();
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
        m->cgroup_empty_event_source = sd_event_source_unref(m->cgroup_empty_event_source);
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

                m->cgroup_inotify_event_source = sd_event_source_unref(m->cgroup_inotify_event_source);
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

                r = cg_install_release_agent(SYSTEMD_CGROUP_CONTROLLER, SYSTEMD_CGROUP_AGENT_PATH);
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
        r = cg_mask_supported(&m->cgroup_supported);
        if (r < 0)
                return log_error_errno(r, "Failed to determine supported controllers: %m");

        /* 9. Figure out which bpf-based pseudo-controllers are supported */
        r = cg_bpf_mask_supported(&mask);
        if (r < 0)
                return log_error_errno(r, "Failed to determine supported bpf-based pseudo-controllers: %m");
        m->cgroup_supported |= mask;

        /* 10. Log which controllers are supported */
        for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++)
                log_debug("Controller '%s' supported: %s", cgroup_controller_to_string(c), yes_no(m->cgroup_supported & CGROUP_CONTROLLER_TO_MASK(c)));

        return 0;
}

void manager_shutdown_cgroup(Manager *m, bool delete) {
        assert(m);

        /* We can't really delete the group, since we are in it. But
         * let's trim it. */
        if (delete && m->cgroup_root && m->test_run_flags != MANAGER_TEST_RUN_MINIMAL)
                (void) cg_trim(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_root, false);

        m->cgroup_empty_event_source = sd_event_source_unref(m->cgroup_empty_event_source);

        m->cgroup_control_inotify_wd_unit = hashmap_free(m->cgroup_control_inotify_wd_unit);
        m->cgroup_memory_inotify_wd_unit = hashmap_free(m->cgroup_memory_inotify_wd_unit);

        m->cgroup_inotify_event_source = sd_event_source_unref(m->cgroup_inotify_event_source);
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

        p = strdupa(cgroup);
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

Unit *manager_get_unit_by_pid_cgroup(Manager *m, pid_t pid) {
        _cleanup_free_ char *cgroup = NULL;

        assert(m);

        if (!pid_is_valid(pid))
                return NULL;

        if (cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &cgroup) < 0)
                return NULL;

        return manager_get_unit_by_cgroup(m, cgroup);
}

Unit *manager_get_unit_by_pid(Manager *m, pid_t pid) {
        Unit *u, **array;

        assert(m);

        /* Note that a process might be owned by multiple units, we return only one here, which is good enough for most
         * cases, though not strictly correct. We prefer the one reported by cgroup membership, as that's the most
         * relevant one as children of the process will be assigned to that one, too, before all else. */

        if (!pid_is_valid(pid))
                return NULL;

        if (pid == getpid_cached())
                return hashmap_get(m->units, SPECIAL_INIT_SCOPE);

        u = manager_get_unit_by_pid_cgroup(m, pid);
        if (u)
                return u;

        u = hashmap_get(m->watch_pids, PID_TO_PTR(pid));
        if (u)
                return u;

        array = hashmap_get(m->watch_pids, PID_TO_PTR(-pid));
        if (array)
                return array[0];

        return NULL;
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

int unit_get_memory_current(Unit *u, uint64_t *ret) {
        _cleanup_free_ char *v = NULL;
        int r;

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
        if (r > 0)
                r = cg_get_attribute("memory", u->cgroup_path, "memory.current", &v);
        else
                r = cg_get_attribute("memory", u->cgroup_path, "memory.usage_in_bytes", &v);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;

        return safe_atou64(v, ret);
}

int unit_get_tasks_current(Unit *u, uint64_t *ret) {
        _cleanup_free_ char *v = NULL;
        int r;

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

        r = cg_get_attribute("pids", u->cgroup_path, "pids.current", &v);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;

        return safe_atou64(v, ret);
}

static int unit_get_cpu_usage_raw(Unit *u, nsec_t *ret) {
        _cleanup_free_ char *v = NULL;
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
        } else {
                r = cg_get_attribute("cpuacct", u->cgroup_path, "cpuacct.usage", &v);
                if (r == -ENOENT)
                        return -ENODATA;
                if (r < 0)
                        return r;

                r = safe_atou64(v, &ns);
                if (r < 0)
                        return r;
        }

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

int unit_reset_ip_accounting(Unit *u) {
        int r = 0, q = 0;

        assert(u);

        if (u->ip_accounting_ingress_map_fd >= 0)
                r = bpf_firewall_reset_accounting(u->ip_accounting_ingress_map_fd);

        if (u->ip_accounting_egress_map_fd >= 0)
                q = bpf_firewall_reset_accounting(u->ip_accounting_egress_map_fd);

        zero(u->ip_accounting_extra);

        return r < 0 ? r : q;
}

int unit_reset_io_accounting(Unit *u) {
        int r;

        assert(u);

        for (CGroupIOAccountingMetric i = 0; i < _CGROUP_IO_ACCOUNTING_METRIC_MAX; i++)
                u->io_accounting_last[i] = UINT64_MAX;

        r = unit_get_io_accounting_raw(u, u->io_accounting_base);
        if (r < 0) {
                zero(u->io_accounting_base);
                return r;
        }

        return 0;
}

int unit_reset_accounting(Unit *u) {
        int r, q, v;

        assert(u);

        r = unit_reset_cpu_accounting(u);
        q = unit_reset_io_accounting(u);
        v = unit_reset_ip_accounting(u);

        return r < 0 ? r : q < 0 ? q : v;
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
                Iterator i;
                void *v;

                HASHMAP_FOREACH_KEY(v, member, u->dependencies[UNIT_BEFORE], i) {
                        if (UNIT_DEREF(member->slice) == u)
                                unit_invalidate_cgroup_bpf(member);
                }
        }
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
        Iterator i;
        Unit *u;

        assert(m);

        SET_FOREACH(u, m->startup_units, i)
                unit_invalidate_cgroup(u, CGROUP_MASK_CPU|CGROUP_MASK_IO|CGROUP_MASK_BLKIO);
}

static int unit_get_nice(Unit *u) {
        ExecContext *ec;

        ec = unit_get_exec_context(u);
        return ec ? ec->nice : 0;
}

static uint64_t unit_get_cpu_weight(Unit *u) {
        ManagerState state = manager_state(u->manager);
        CGroupContext *cc;

        cc = unit_get_cgroup_context(u);
        return cc ? cgroup_context_cpu_weight(cc, state) : CGROUP_WEIGHT_DEFAULT;
}

int compare_job_priority(const void *a, const void *b) {
        const Job *x = a, *y = b;
        int nice_x, nice_y;
        uint64_t weight_x, weight_y;
        int ret;

        if ((ret = CMP(x->unit->type, y->unit->type)) != 0)
                return -ret;

        weight_x = unit_get_cpu_weight(x->unit);
        weight_y = unit_get_cpu_weight(y->unit);

        if ((ret = CMP(weight_x, weight_y)) != 0)
                return -ret;

        nice_x = unit_get_nice(x->unit);
        nice_y = unit_get_nice(y->unit);

        if ((ret = CMP(nice_x, nice_y)) != 0)
                return ret;

        return strcmp(x->unit->id, y->unit->id);
}

static const char* const cgroup_device_policy_table[_CGROUP_DEVICE_POLICY_MAX] = {
        [CGROUP_AUTO] = "auto",
        [CGROUP_CLOSED] = "closed",
        [CGROUP_STRICT] = "strict",
};

DEFINE_STRING_TABLE_LOOKUP(cgroup_device_policy, CGroupDevicePolicy);
