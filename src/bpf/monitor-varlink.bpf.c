/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include "vmlinux.h"

#include <errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "monitor-varlink-api.bpf.h"

#define SOCKET_PROTOCOL_VARLINK_NAME "user.varlink"
#define AF_UNIX 1U
#define MAX_PACKETS_PER_SENDMSG 8U
#define MAX_VARLINK_SOCKETS (16U * 1024U)
#define RINGBUF_SIZE (256U * 1024U)

extern int bpf_sock_read_xattr(struct socket *sock, const char *name__str,
                                struct bpf_dynptr *value) __ksym;

/* Cache of discovered varlink sockets, keyed by inode number. Populated by the
 * LSM hook on first sendmsg so that the fentry capture hook can do a cheap
 * lookup instead of reading xattrs on every message. */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_VARLINK_SOCKETS);
        __type(key, __u64);
        __type(value, enum varlink_socket_type);
} varlink_sock_map SEC(".maps");

/* Ring buffer for delivering captured packets to userspace. */
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, RINGBUF_SIZE);
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

struct path_scratch {
        __u8 len;
        char path[MONITOR_VARLINK_MAX_PATH];
};

/* Per-CPU scratch buffer shared by the LSM hook (xattr reads) and the fentry
 * hook (socket path reads). Stack variables won't pass the verifier for these
 * helpers and plain globals would race across CPUs. */
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, union { char xattr[sizeof("server")]; struct path_scratch path; });
} scratch SEC(".maps");

static __noinline enum varlink_socket_type get_varlink_socket_type(struct socket *sock) {
        __u32 key = 0;
        char *buf = bpf_map_lookup_elem(&scratch, &key);
        if (!buf)
                return VARLINK_SOCKET_NONE;

        struct bpf_dynptr value;
        bpf_dynptr_from_mem(buf, sizeof("server"), 0, &value);

        int r = bpf_sock_read_xattr(sock, SOCKET_PROTOCOL_VARLINK_NAME, &value);
        if (r < 0)
                return VARLINK_SOCKET_NONE;

        if (r == sizeof("client") - 1 && bpf_strncmp(buf, r, "client") == 0)
                return VARLINK_SOCKET_CLIENT;
        if (r == sizeof("server") - 1 && bpf_strncmp(buf, r, "server") == 0)
                return VARLINK_SOCKET_SERVER;

        return VARLINK_SOCKET_NONE;
}

/* Discovery hook: classifies AF_UNIX sockets as varlink by reading their xattr
 * and populates the socket map for the capture hook. Both sides of a varlink
 * connection should set user.varlink on their socket inode. */
SEC("lsm/socket_sendmsg")
int BPF_PROG(
                monitor_varlink_socket_sendmsg,
                struct socket *sock,
                void *msg,
                int size) {

        if (BPF_CORE_READ(sock, sk, __sk_common.skc_family) != AF_UNIX)
                return 0;

        __u64 sock_ino = BPF_CORE_READ(sock, file, f_inode, i_ino);

        /* Already classified as varlink — non-varlink sockets are not cached
         * and will re-check the xattr on every sendmsg, but that fails fast. */
        if (bpf_map_lookup_elem(&varlink_sock_map, &sock_ino))
                return 0;

        enum varlink_socket_type type = get_varlink_socket_type(sock);
        if (type != VARLINK_SOCKET_NONE) {
                bpf_map_update_elem(&varlink_sock_map, &sock_ino, &type, BPF_NOEXIST);
                return 0;
        }

        /* Fallback for sockets that don't set the xattr: check if the peer is
         * a known varlink socket and infer the opposite type. */
        struct unix_sock *u = (struct unix_sock *)BPF_CORE_READ(sock, sk);
        struct sock *peer = BPF_CORE_READ(u, peer);
        if (!peer)
                return 0;

        __u64 peer_ino = BPF_CORE_READ(peer, sk_socket, file, f_inode, i_ino);
        /* Can only check the map here — bpf_sock_read_xattr requires a trusted
         * pointer which we don't have for the peer socket. */
        enum varlink_socket_type *peer_type_p = bpf_map_lookup_elem(&varlink_sock_map, &peer_ino);
        if (!peer_type_p)
                return 0;

        type = *peer_type_p == VARLINK_SOCKET_CLIENT ? VARLINK_SOCKET_SERVER : VARLINK_SOCKET_CLIENT;
        bpf_map_update_elem(&varlink_sock_map, &sock_ino, &type, BPF_NOEXIST);

        return 0;
}

/* Read the socket path from the unix_address into the per-CPU scratch buffer.
 * The connected side of a socketpair has no address, so fall back to the
 * peer's address. */
static __always_inline struct path_scratch *read_socket_path(struct socket *sock) {
        __u32 key = 0;
        struct path_scratch *ps = bpf_map_lookup_elem(&scratch, &key);
        if (!ps)
                return NULL;

        ps->len = 0;

        struct unix_sock *u = (struct unix_sock *)BPF_CORE_READ(sock, sk);
        struct unix_address *addr = BPF_CORE_READ(u, addr);

        if (!addr) {
                struct sock *peer = BPF_CORE_READ(u, peer);
                if (!peer)
                        return ps;

                addr = BPF_CORE_READ((struct unix_sock *)peer, addr);
                if (!addr)
                        return ps;
        }

        int len = BPF_CORE_READ(addr, len);
        if (len <= 3)
                return ps;

        int path_len = len - 3; /* subtract sizeof(sa_family_t) + NUL terminator */
        if (path_len > MONITOR_VARLINK_MAX_PATH)
                return ps;

        ps->len = path_len;
        /* Zero-pad so that __builtin_memcmp against the NUL-padded filter
         * path can safely compare the full MONITOR_VARLINK_MAX_PATH bytes. */
        __builtin_memset(ps->path, 0, MONITOR_VARLINK_MAX_PATH);
        bpf_probe_read_kernel(ps->path, path_len,
                              addr->name[0].sun_path);
        return ps;
}

static __always_inline bool match_filters(
                __u32 uid,
                __u32 peer_uid,
                __u32 pid,
                __u32 peer_pid,
                __u64 pidfd_ino,
                __u64 peer_pidfd_ino,
                struct path_scratch *ps) {

        if (n_filters == 0)
                return true;

        for (__u32 i = 0; i < MONITOR_VARLINK_MAX_FILTERS; i++) {
                if (i >= n_filters)
                        break;

                struct monitor_varlink_filter *f = bpf_map_lookup_elem(&monitor_varlink_filters, &i);
                if (!f)
                        break;

                if (f->uid != (__u32)-1 && uid != f->uid && peer_uid != f->uid)
                        continue;

                if (f->pid != (__u32)-1 && pid != f->pid && peer_pid != f->pid)
                        continue;

                if (f->pidfd_ino != (__u64)-1 && pidfd_ino != f->pidfd_ino && peer_pidfd_ino != f->pidfd_ino)
                        continue;

                if (f->has_path) {
                        if (!ps || ps->len != f->path_len)
                                continue;
                        /* bpf_strncmp requires a read-only map for s2, and
                         * __builtin_memcmp with a dynamic size compiles to a
                         * memcmp call which does not exist in BPF. Use a
                         * constant-size memcmp; both buffers are NUL-padded. */
                        if (ps->len > 0 &&
                            __builtin_memcmp(ps->path, f->path, MONITOR_VARLINK_MAX_PATH) != 0)
                                continue;
                }

                return true;
        }

        return false;
}

/* Capture hook: records varlink message data for sockets already discovered
 * by the LSM hook above. */
SEC("fentry/unix_stream_sendmsg")
int BPF_PROG(
                monitor_varlink_unix_stream_sendmsg,
                struct socket *sock,
                struct msghdr *msg,
                size_t len) {

        struct sock *sk = sock->sk;

        __u64 sock_ino = BPF_CORE_READ(sock, file, f_inode, i_ino);
        __u64 sock_cookie = bpf_get_socket_cookie(sk);

        /* Only capture sockets classified as varlink by the LSM discovery hook */
        enum varlink_socket_type *type = bpf_map_lookup_elem(&varlink_sock_map, &sock_ino);
        if (!type)
                return 0;

        __u32 uid = bpf_get_current_uid_gid();
        __u32 cur_pid = bpf_get_current_pid_tgid() >> 32;

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct pid *cur_pid_s = BPF_CORE_READ(task, thread_pid);
        __u64 pidfd_ino = cur_pid_s && bpf_core_field_exists(cur_pid_s->ino)
                        ? BPF_CORE_READ(cur_pid_s, ino) : (__u64)-1;

        __u32 peer_uid = (__u32)-1;
        const struct cred *peer_cred = BPF_CORE_READ(sk, sk_peer_cred);
        if (peer_cred)
                peer_uid = BPF_CORE_READ(peer_cred, uid.val);

        struct pid *peer_pid_s = BPF_CORE_READ(sk, sk_peer_pid);
        __u32 peer_pid = peer_pid_s ? BPF_CORE_READ(peer_pid_s, numbers[0].nr) : 0;
        __u64 peer_pidfd_ino = peer_pid_s && bpf_core_field_exists(peer_pid_s->ino)
                             ? BPF_CORE_READ(peer_pid_s, ino) : (__u64)-1;

        struct path_scratch *ps = read_socket_path(sock);

        if (!match_filters(uid, peer_uid, cur_pid, peer_pid, pidfd_ino, peer_pidfd_ino, ps))
                return 0;

        /* Capture the packet metadata and data into the ring buffer */
        __u64 timestamp_ns = bpf_ktime_get_boot_ns();

        void *ubuf = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
        size_t iov_offset = BPF_CORE_READ(msg, msg_iter.iov_offset);

        /* Split into fixed-size packets; data beyond MAX_PACKETS_PER_SENDMSG *
         * MONITOR_VARLINK_MAX_DATA is truncated. Userspace detects this via total_len. */
        for (int i = 0; i < MAX_PACKETS_PER_SENDMSG; i++) {
                size_t offset = (__u64)i * MONITOR_VARLINK_MAX_DATA;

                if (offset >= len)
                        break;

                struct monitor_varlink_packet *p = bpf_ringbuf_reserve(&monitor_varlink_ringbuf, sizeof(*p), 0);
                if (!p)
                        return 0;

                p->timestamp_ns = timestamp_ns;
                p->sock_ino = sock_ino;
                p->sock_cookie = sock_cookie;
                p->pidfd_ino = pidfd_ino;
                p->peer_pidfd_ino = peer_pidfd_ino;
                p->uid = uid;
                p->peer_uid = peer_uid;
                p->pid = cur_pid;
                p->peer_pid = peer_pid;
                p->total_len = len;
                p->type = *type;

                if (ps) {
                        p->path_len = ps->len;
                        __builtin_memcpy(p->path, ps->path, MONITOR_VARLINK_MAX_PATH);
                } else
                        p->path_len = 0;

                size_t remaining = len - offset;
                p->data_len = remaining < MONITOR_VARLINK_MAX_DATA ? remaining : MONITOR_VARLINK_MAX_DATA;

                bpf_probe_read_user(p->data, MONITOR_VARLINK_MAX_DATA, ubuf + iov_offset + offset);

                bpf_ringbuf_submit(p, 0);
        }

        return 0;
}

/* Cleanup hook: removes sockets from the map when they are closed. */
SEC("fentry/unix_release_sock")
int BPF_PROG(
                monitor_varlink_unix_release_sock,
                struct sock *sk,
                int embrion) {

        __u64 ino = BPF_CORE_READ(sk, sk_socket, file, f_inode, i_ino);

        bpf_map_delete_elem(&varlink_sock_map, &ino);

        return 0;
}

static const char _license[] SEC("license") = "GPL";
