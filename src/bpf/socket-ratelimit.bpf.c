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

#define SOCKET_RATELIMIT_MAX_MAP_SIZE 2048
#define U32_MAX (~(uint32_t)0) /* In order to avoid including stdint.h which conflicts with vmlinux.h */
#define EAGAIN 11

struct xattr_value {
        uint8_t buf[32];
};

struct {
        __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __type(key, __u32);
        __type(value, struct xattr_value);
} xattr_storage SEC(".maps");

struct ratelimit_flag {
        uint32_t is_ratelimited;
};

struct {
        __uint(type, BPF_MAP_TYPE_SK_STORAGE);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __type(key, int);
        __type(value, struct ratelimit_flag);
} socket_ratelimit_flag_map SEC(".maps");

struct ratelimit {
        struct bpf_spin_lock lock;
        uint64_t interval;
        uint32_t burst;
        uint32_t num;
        uint64_t begin;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, uint64_t);
        __type(value, struct ratelimit);
        __uint(max_entries, SOCKET_RATELIMIT_MAX_MAP_SIZE);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} socket_ratelimit_map SEC(".maps");

static inline uint64_t usec_sub_unsigned(uint64_t timestamp, uint64_t delta) {
        if (timestamp < delta)
                return 0;

        return timestamp - delta;
}

static bool ratelimit_below(struct ratelimit *rl) {
        uint64_t ts = bpf_ktime_get_ns() / 1000;
        int ret;

        if (rl->interval == 0 || rl->burst == 0)
                return true;

        bpf_spin_lock(&rl->lock);

        if (rl->begin == 0 || usec_sub_unsigned(ts, rl->begin) > rl->interval) {
                rl->begin = ts;
                rl->num = 1;
                ret = true;
                goto unlock;
        }

        if (rl->num == U32_MAX) {
                ret = false;
                goto unlock;
        }

        rl->num++;
        ret = rl->num <= rl->burst;

unlock:
        bpf_spin_unlock(&rl->lock);
        return ret;
}

SEC("lsm.s/socket_bind")
int BPF_PROG(sd_socket_ratelimit_bind, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
        struct ratelimit_flag *flag;
        struct bpf_dynptr xattr;
        struct xattr_value *s;
        struct sock *sk;
        int r;

        if (ret != 0)
                return ret;

        sk = sock->sk;
        if (!sk)
                return 0;

        s = bpf_task_storage_get(&xattr_storage,
                                 bpf_get_current_task_btf(), NULL,
                                 BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (!s)
                return 0;

        bpf_dynptr_from_mem(s->buf, sizeof(s->buf), 0, &xattr);

        r = bpf_sock_read_xattr(sock, "user.ratelimit", &xattr);
        if (r < 0)
                return 0;

        if (bpf_strncmp(s->buf, 1, "1"))
                return 0;

        flag = bpf_sk_storage_get(&socket_ratelimit_flag_map, sk, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (flag)
                flag->is_ratelimited = 1;

        return 0;
}

SEC("lsm/unix_may_send")
int BPF_PROG(sd_socket_ratelimit_send, struct socket *sock, struct socket *other, int ret)
{
        struct ratelimit_flag *flag = NULL;
        struct ratelimit *rl = NULL;
        struct sock *sk = NULL;
        uint64_t cgroup_id;

        if (ret != 0)
                return ret;

        sk = other->sk;
        if (!sk)
                return 0;

        flag = bpf_sk_storage_get(&socket_ratelimit_flag_map, sk, 0, 0);
        if (!flag || !flag->is_ratelimited)
                return 0;

        cgroup_id = bpf_get_current_cgroup_id();
        rl = bpf_map_lookup_elem(&socket_ratelimit_map, &cgroup_id);
        if (!rl)
                return 0;

        if (!ratelimit_below(rl))
                return -EAGAIN;

        return 0;
}

static const char _license[] SEC("license") = "GPL";
