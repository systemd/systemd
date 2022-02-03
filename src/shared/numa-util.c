/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sched.h>

#include "alloc-util.h"
#include "cpu-set-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "missing_syscall.h"
#include "numa-util.h"
#include "stdio-util.h"
#include "string-table.h"

bool numa_policy_is_valid(const NUMAPolicy *policy) {
        assert(policy);

        if (!mpol_is_valid(numa_policy_get_type(policy)))
                return false;

        if (!policy->nodes.set &&
            !IN_SET(numa_policy_get_type(policy), MPOL_DEFAULT, MPOL_LOCAL, MPOL_PREFERRED))
                return false;

        if (policy->nodes.set &&
            numa_policy_get_type(policy) == MPOL_PREFERRED &&
            CPU_COUNT_S(policy->nodes.allocated, policy->nodes.set) != 1)
                return false;

        return true;
}

static int numa_policy_to_mempolicy(const NUMAPolicy *policy, unsigned long *ret_maxnode, unsigned long **ret_nodes) {
        unsigned node, bits = 0, ulong_bits;
        _cleanup_free_ unsigned long *out = NULL;

        assert(policy);
        assert(ret_maxnode);
        assert(ret_nodes);

        if (IN_SET(numa_policy_get_type(policy), MPOL_DEFAULT, MPOL_LOCAL) ||
            (numa_policy_get_type(policy) == MPOL_PREFERRED && !policy->nodes.set)) {
                *ret_nodes = NULL;
                *ret_maxnode = 0;
                return 0;
        }

        bits = policy->nodes.allocated * 8;
        ulong_bits = sizeof(unsigned long) * 8;

        out = new0(unsigned long, DIV_ROUND_UP(policy->nodes.allocated, sizeof(unsigned long)));
        if (!out)
                return -ENOMEM;

        /* We don't make any assumptions about internal type libc is using to store NUMA node mask.
           Hence we need to convert the node mask to the representation expected by set_mempolicy() */
        for (node = 0; node < bits; node++)
                if (CPU_ISSET_S(node, policy->nodes.allocated, policy->nodes.set))
                        out[node / ulong_bits] |= 1ul << (node % ulong_bits);

        *ret_nodes = TAKE_PTR(out);
        *ret_maxnode = bits + 1;
        return 0;
}

int apply_numa_policy(const NUMAPolicy *policy) {
        int r;
        _cleanup_free_ unsigned long *nodes = NULL;
        unsigned long maxnode;

        assert(policy);

        if (get_mempolicy(NULL, NULL, 0, 0, 0) < 0 && errno == ENOSYS)
                return -EOPNOTSUPP;

        if (!numa_policy_is_valid(policy))
                return -EINVAL;

        r = numa_policy_to_mempolicy(policy, &maxnode, &nodes);
        if (r < 0)
                return r;

        r = set_mempolicy(numa_policy_get_type(policy), nodes, maxnode);
        if (r < 0)
                return -errno;

        return 0;
}

int numa_to_cpu_set(const NUMAPolicy *policy, CPUSet *ret) {
        int r;
        size_t i;
        _cleanup_(cpu_set_reset) CPUSet s = {};

        assert(policy);
        assert(ret);

        for (i = 0; i < policy->nodes.allocated * 8; i++) {
                _cleanup_free_ char *l = NULL;
                char p[STRLEN("/sys/devices/system/node/node//cpulist") + DECIMAL_STR_MAX(size_t) + 1];
                _cleanup_(cpu_set_reset) CPUSet part = {};

                if (!CPU_ISSET_S(i, policy->nodes.allocated, policy->nodes.set))
                        continue;

                xsprintf(p, "/sys/devices/system/node/node%zu/cpulist", i);

                r = read_one_line_file(p, &l);
                if (r < 0)
                        return r;

                r = parse_cpu_set(l, &part);
                if (r < 0)
                        return r;

                r = cpu_set_add_all(&s, &part);
                if (r < 0)
                        return r;
        }

        *ret = s;
        s = (CPUSet) {};

        return 0;
}

static int numa_max_node(void) {
        _cleanup_closedir_ DIR *d = NULL;
        int r, max_node = 0;

        d = opendir("/sys/devices/system/node");
        if (!d)
                return -errno;

        FOREACH_DIRENT(de, d, break) {
                int node;
                const char *n;

                if (de->d_type != DT_DIR)
                        continue;

                n = startswith(de->d_name, "node");
                if (!n)
                        continue;

                r = safe_atoi(n, &node);
                if (r < 0)
                        continue;

                if (node > max_node)
                        max_node = node;
        }

        return max_node;
}

int numa_mask_add_all(CPUSet *mask) {
        int m;

        assert(mask);

        m = numa_max_node();
        if (m < 0) {
                log_debug_errno(m, "Failed to determine maximum NUMA node index, assuming 1023: %m");
                m = 1023; /* CONFIG_NODES_SHIFT is set to 10 on x86_64, i.e. 1024 NUMA nodes in total */
        }

        for (int i = 0; i <= m; i++) {
                int r;

                r = cpu_set_add(mask, i);
                if (r < 0)
                        return r;
        }

        return 0;
}

static const char* const mpol_table[] = {
        [MPOL_DEFAULT]    = "default",
        [MPOL_PREFERRED]  = "preferred",
        [MPOL_BIND]       = "bind",
        [MPOL_INTERLEAVE] = "interleave",
        [MPOL_LOCAL]      = "local",
};

DEFINE_STRING_TABLE_LOOKUP(mpol, int);
