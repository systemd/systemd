/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "monitor-varlink-api.bpf.h"

#define AF_UNIX 1U
#ifndef UID_INVALID
#define UID_INVALID ((uint32_t) -1)
#endif

/* Ring buffer for delivering captured packets to userspace. */
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, MONITOR_VARLINK_RINGBUF_SIZE);
} monitor_varlink_ringbuf SEC(".maps");

/* Capture filters populated by the daemon before attaching. Each filter's
 * fields are ANDed; the array is ORed. n_filters == 0 means capture all. */
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, MONITOR_VARLINK_MAX_FILTERS);
        __type(key, __u32);
        __type(value, struct monitor_varlink_filter);
} monitor_varlink_filters SEC(".maps");

__u32 n_filters;

/* __builtin_memcmp/__builtin_memcpy may emit calls the BPF JIT cannot
 * link, and bpf_strncmp requires a read-only map. Bounded inline loops
 * avoid both problems. max_len must be a compile-time constant. */
static __always_inline bool mem_equal(const char *a, const char *b, int len, int max_len) {
        for (int i = 0; i < max_len && i < len; i++)
                if (a[i] != b[i])
                        return false;
        return true;
}

static __always_inline void mem_copy(char *dst, const char *src, int len, int max_len) {
        for (int i = 0; i < max_len && i < len; i++)
                dst[i] = src[i];
}

/* Per-CPU scratch buffer for xattr reads. bpf_dynptr_from_mem does not accept
 * stack memory; plain globals would race across CPUs. */
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, char[sizeof("server")]);
} scratch SEC(".maps");

extern int bpf_sock_read_xattr(struct socket *sock, const char *name__str,
                               struct bpf_dynptr *value) __ksym;

static __noinline enum varlink_socket_type get_varlink_socket_type(struct socket *sock) {
        __u32 key = 0;
        char *buf = bpf_map_lookup_elem(&scratch, &key);
        if (!buf)
                return VARLINK_SOCKET_NONE;

        struct bpf_dynptr value;
        bpf_dynptr_from_mem(buf, sizeof("server"), 0, &value);

        int r = bpf_sock_read_xattr(sock, MONITOR_VARLINK_XATTR_NAME, &value);
        if (r < 0)
                return VARLINK_SOCKET_NONE;

        if (r == sizeof("client") - 1 && bpf_strncmp(buf, r, "client") == 0)
                return VARLINK_SOCKET_CLIENT;
        if (r == sizeof("server") - 1 && bpf_strncmp(buf, r, "server") == 0)
                return VARLINK_SOCKET_SERVER;

        return VARLINK_SOCKET_NONE;
}

struct unix_socket_path {
        __u8 len;
        char path[MONITOR_VARLINK_MAX_PATH];
};

/* Read the socket path from the unix_address. The connected side of a
 * socketpair has no address, so fall back to the peer's address. */
static __always_inline void read_socket_path(struct socket *sock, struct unix_socket_path *ps) {
        ps->len = 0;

        struct unix_sock *u = (struct unix_sock *)BPF_CORE_READ(sock, sk);
        struct unix_address *addr = BPF_CORE_READ(u, addr);

        if (!addr) {
                struct sock *peer = BPF_CORE_READ(u, peer);
                if (!peer)
                        return;

                addr = BPF_CORE_READ((struct unix_sock *)peer, addr);
                if (!addr)
                        return;
        }

        int len = BPF_CORE_READ(addr, len);
        if (len <= 3)
                return;

        /* Both pathname and abstract sockets subtract 3 from len:
         * pathname: sizeof(sa_family_t) + NUL terminator
         * abstract: sizeof(sa_family_t) + NUL prefix */
        int path_len = len - 3;

        char first = 0;
        bpf_probe_read_kernel(&first, 1, addr->name[0].sun_path);

        if (first == '\0') {
                if (path_len + 1 > MONITOR_VARLINK_MAX_PATH)
                        return;
                ps->path[0] = '@';
                ps->len = path_len + 1;
                bpf_probe_read_kernel(ps->path + 1, path_len,
                                      addr->name[0].sun_path + 1);
        } else {
                if (path_len > MONITOR_VARLINK_MAX_PATH)
                        return;
                ps->len = path_len;
                bpf_probe_read_kernel(ps->path, path_len,
                                      addr->name[0].sun_path);
        }
}

static __always_inline bool match_filters(
                __u32 uid,
                __u32 peer_uid,
                __u32 pid,
                __u32 peer_pid,
                __u64 pidfd_id,
                __u64 peer_pidfd_id,
                const struct unix_socket_path *ps) {

        if (n_filters == 0)
                return true;

        for (__u32 i = 0; i < MONITOR_VARLINK_MAX_FILTERS; i++) {
                if (i >= n_filters)
                        break;

                struct monitor_varlink_filter *f = bpf_map_lookup_elem(&monitor_varlink_filters, &i);
                if (!f)
                        break;

                if (f->uid != UID_INVALID && uid != f->uid && peer_uid != f->uid)
                        continue;

                if (f->pid != 0 && pid != f->pid && peer_pid != f->pid)
                        continue;

                if (f->pidfd_id != 0 && pidfd_id != f->pidfd_id && peer_pidfd_id != f->pidfd_id)
                        continue;

                if (f->has_path) {
                        if (ps->len != f->path_len)
                                continue;
                        if (ps->len > 0 && !mem_equal(ps->path, f->path, ps->len, MONITOR_VARLINK_MAX_PATH))
                                continue;
                }

                return true;
        }

        return false;
}

struct send_state {
        void *data;
        unsigned long nr_segs;
        struct iovec synth_iov;
        __u64 timestamp_ns;
        __u64 sock_ino;
        __u64 sock_cookie;
        __u64 pidfd_id;
        __u64 peer_pidfd_id;
        __u32 uid;
        __u32 peer_uid;
        __u32 pid;
        __u32 peer_pid;
        enum varlink_socket_type type;
        __u8 path_len;
        char path[MONITOR_VARLINK_MAX_PATH];
};

/* Saved iter and metadata from the LSM hook, consumed by fexit. Task storage
 * follows the thread across CPU migrations between the two hooks. */
struct {
        __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __type(key, int);
        __type(value, struct send_state);
} send_state_map SEC(".maps");

/* CO-RE flavor for kernels that have struct pid::ino (6.9+) */
struct pid___ino {
        __u64 ino;
};

static __always_inline __u64 pidfd_id_from_pid(struct pid *p) {
        if (p && bpf_core_field_exists(((struct pid___ino *)p)->ino))
                return BPF_CORE_READ((struct pid___ino *)p, ino);
        return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(
                monitor_varlink_socket_sendmsg,
                struct socket *sock,
                struct msghdr *msg,
                int size) {

        if (BPF_CORE_READ(sock, sk, __sk_common.skc_family) != AF_UNIX)
                return 0;

        enum varlink_socket_type type = get_varlink_socket_type(sock);
        if (type == VARLINK_SOCKET_NONE)
                return 0;

        __u64 sock_ino = BPF_CORE_READ(sock, file, f_inode, i_ino);

        struct sock *sk = sock->sk;
        if (!sk)
                return 0;

        __u32 cur_pid = bpf_get_current_pid_tgid() >> 32;

        struct task_struct *task = bpf_get_current_task_btf();
        __u32 uid = BPF_CORE_READ(task, cred, euid.val);
        struct pid *cur_pid_s = BPF_CORE_READ(task, thread_pid);
        __u64 pidfd_id = pidfd_id_from_pid(cur_pid_s);

        __u32 peer_uid = UID_INVALID;
        const struct cred *peer_cred = BPF_CORE_READ(sk, sk_peer_cred);
        if (peer_cred)
                peer_uid = BPF_CORE_READ(peer_cred, euid.val);

        struct pid *peer_pid_s = BPF_CORE_READ(sk, sk_peer_pid);
        __u32 peer_pid = peer_pid_s ? BPF_CORE_READ(peer_pid_s, numbers[0].nr) : 0;
        __u64 peer_pidfd_id = pidfd_id_from_pid(peer_pid_s);

        struct unix_socket_path ps;
        read_socket_path(sock, &ps);

        if (!match_filters(uid, peer_uid, cur_pid, peer_pid, pidfd_id, peer_pidfd_id, &ps))
                return 0;

        struct send_state *state = bpf_task_storage_get(&send_state_map, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (!state)
                return 0;

        __u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
        if (iter_type == ITER_UBUF) {
                void *ubuf = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
                state->synth_iov.iov_base = ubuf;
                state->synth_iov.iov_len = size;
                state->data = &state->synth_iov;
                state->nr_segs = 1;
        } else if (iter_type == ITER_IOVEC) {
                state->data = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
                state->nr_segs = BPF_CORE_READ(msg, msg_iter.nr_segs);
        } else {
                return 0;
        }

        state->timestamp_ns = bpf_ktime_get_boot_ns();
        state->sock_ino = sock_ino;
        state->sock_cookie = bpf_get_socket_cookie(sk);
        state->pidfd_id = pidfd_id;
        state->peer_pidfd_id = peer_pidfd_id;
        state->uid = uid;
        state->peer_uid = peer_uid;
        state->pid = cur_pid;
        state->peer_pid = peer_pid;
        state->type = type;

        state->path_len = ps.len;
        mem_copy(state->path, ps.path, ps.len, MONITOR_VARLINK_MAX_PATH);

        return 0;
}

static __noinline void emit_packet(
                struct send_state *state,
                size_t actual_len,
                size_t data_len,
                void *data_ptr) {

        struct monitor_varlink_packet *p = bpf_ringbuf_reserve(&monitor_varlink_ringbuf, sizeof(*p), 0);
        if (!p)
                return;

        p->timestamp_ns = state->timestamp_ns;
        p->sock_ino = state->sock_ino;
        p->sock_cookie = state->sock_cookie;
        p->pidfd_id = state->pidfd_id;
        p->peer_pidfd_id = state->peer_pidfd_id;
        p->uid = state->uid;
        p->peer_uid = state->peer_uid;
        p->pid = state->pid;
        p->peer_pid = state->peer_pid;
        p->total_len = actual_len;
        p->type = state->type;
        p->path_len = state->path_len;
        bpf_probe_read_kernel(p->path, state->path_len, state->path);

        if (data_len > MONITOR_VARLINK_MAX_DATA)
                data_len = MONITOR_VARLINK_MAX_DATA;

        p->data_len = data_len;
        bpf_probe_read_user(p->data, data_len, data_ptr);
        bpf_ringbuf_submit(p, 0);
}

/* Capture hook: emits packet data using state saved by the LSM hook. */
SEC("fexit/unix_stream_sendmsg")
int BPF_PROG(
                monitor_varlink_unix_stream_sendmsg,
                struct socket *sock,
                struct msghdr *msg,
                size_t len,
                int ret) {

        struct task_struct *task = bpf_get_current_task_btf();
        struct send_state *state = bpf_task_storage_get(&send_state_map, task, NULL, 0);
        if (!state)
                return 0;

        unsigned long nr_segs = state->nr_segs;
        state->nr_segs = 0;

        if (ret <= 0 || nr_segs == 0)
                return 0;

        if (state->sock_cookie != bpf_get_socket_cookie(sock->sk))
                return 0;

        size_t actual_len = ret;

        size_t emitted = 0;

        for (int seg = 0; seg < MONITOR_VARLINK_MAX_SEGS; seg++) {
                if ((__u64)seg >= nr_segs)
                        break;
                if (emitted >= actual_len)
                        break;

                struct iovec iov;
                bpf_probe_read_kernel(&iov, sizeof(iov),
                                      (const struct iovec *)state->data + seg);

                void *base = iov.iov_base;
                size_t seg_len = iov.iov_len;

                if (seg_len > actual_len - emitted)
                        seg_len = actual_len - emitted;

                for (int pkt = 0; pkt < MONITOR_VARLINK_MAX_PACKETS; pkt++) {
                        size_t offset = (__u64)pkt * MONITOR_VARLINK_MAX_DATA;
                        if (offset >= seg_len)
                                break;

                        size_t chunk = seg_len - offset;
                        if (chunk > MONITOR_VARLINK_MAX_DATA)
                                chunk = MONITOR_VARLINK_MAX_DATA;

                        emit_packet(state, actual_len, chunk, base + offset);
                }

                emitted += seg_len;
        }

        return 0;
}

static const char _license[] SEC("license") = "GPL";
