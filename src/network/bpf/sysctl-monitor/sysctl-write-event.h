/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/* It would be nice to size these members to bigger values, but the stack
 * in BPF programs is limited to 512 bytes, and allocating bigger structures
 * leads to this compile time error:
 *   error: Looks like the BPF stack limit is exceeded.
 *   Please move large on stack variables into BPF per-cpu array map.
 *   For non-kernel uses, the stack can be increased using -mllvm -bpf-stack-size. */
struct sysctl_write_event {
        /* Used to track changes in the struct layout */
        int version;

        /* Error code returned to userspace to handle eventual failures. */
        int errorcode;

        /* The PID of the process which is writing the sysctl. */
        pid_t pid;

        /* The cgroup id of the process. */
        uint64_t cgroup_id;

        /* The name of the binary. */
        char comm[TASK_COMM_LEN];

        /* The path of the sysctl, relative to /proc/sys/.
         * The longest path observed is 64 bytes:
         * net/ipv4/conf/123456789012345/igmpv3_unsolicited_report_interval
         * so set it to 100 gives us lot of headroom */
        char path[100];

        /* The value of the sysctl just before the write.
         * The longest value observed is net.core.netdev_rss_key which
         * contains 155 bytes, so set it to 160 to have some headroom
         * even in this corner case. */
        char current[160];

        /* The new value being written into the sysctl.
         * same sizing as 'current' */
        char newvalue[160];
};
