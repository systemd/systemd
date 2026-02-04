/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Copied from src/basic/ratelimit.h */
struct ratelimit {
        uint64_t interval;
        uint32_t burst;
        uint32_t num;
        uint64_t begin;
};

#define PID1_NOTIFY_SOCKET "/run/systemd/notify"
#define NOTIFY_RATELIMIT_HASH_SIZE_MAX 2048
#define U32_MAX (~(uint32_t)0) /* In order to avoid including stdint.h which conflicts with vmlinux.h */
#define UNIX_PATH_MAX 108
#define EAGAIN 11

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, uint64_t);              /* cgroup ID */
        __type(value, struct ratelimit);    /* ratelimiter state */
        __uint(max_entries, NOTIFY_RATELIMIT_HASH_SIZE_MAX);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} notify_ratelimit_hash SEC(".maps");

struct bpf_sock_addr_kern;
extern void *bpf_cast_to_kern_ctx(void *obj) __ksym;

static inline uint64_t usec_sub_unsigned(uint64_t timestamp, uint64_t delta) {
        if (timestamp < delta)
                return 0;

        return timestamp - delta;
}

static bool ratelimit_below(struct ratelimit *rl) {
        uint64_t ts = bpf_ktime_get_ns() / 1000;

        if (rl->interval == 0 || rl->burst == 0)
                return true;

        if (rl->begin == 0 || usec_sub_unsigned(ts, rl->begin) > rl->interval) {
                rl->begin = ts;
                rl->num = 1;
                return true;
        }

        if (rl->num == U32_MAX)
                return false;

        rl->num++;
        return rl->num <= rl->burst;
}

SEC("cgroup/sendmsg_unix")
int sd_notify_ratelimit(struct bpf_sock_addr *ctx) {
        struct bpf_sock_addr_kern *sa_kern = bpf_cast_to_kern_ctx(ctx);
        struct sockaddr_un *sun;
        struct ratelimit *rl;
        uint64_t cgroup_id;
        void *uaddr;

        uaddr = BPF_CORE_READ(sa_kern, uaddr);
        if (bpf_probe_read_kernel(&sun, sizeof(sun), uaddr) < 0)
                return 1;

        cgroup_id = bpf_get_current_cgroup_id();

        rl = bpf_map_lookup_elem(&notify_ratelimit_hash, &cgroup_id);
        if (!rl)
                return 1;

        if (!ratelimit_below(rl)) {
                bpf_printk("sd_notify_ratelimit: cgroup %llu exceeded rate limit, blocking", cgroup_id);
                bpf_set_retval(-EAGAIN);
                return 0;
        }

        return 1;
}

static const char _license[] SEC("license") = "GPL";
