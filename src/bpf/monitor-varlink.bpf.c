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
#define AF_UNIX 1
#define MAX_PACKETS_PER_SENDMSG 8
#define MAX_VARLINK_SOCKETS (16 * 1024)
#define RINGBUF_SIZE (256 * 1024)

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

__u32 allowed_uid;

/* Per-CPU scratch buffer for xattr reads. A stack variable won't pass the
 * verifier and a plain global would race across CPUs. */
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, char[sizeof("server")]);
} xattr_scratch SEC(".maps");

static __noinline enum varlink_socket_type get_varlink_socket_type(struct socket *sock) {
        __u32 key = 0;
        char *buf = bpf_map_lookup_elem(&xattr_scratch, &key);
        if (!buf)
                return VARLINK_SOCKET_NONE;

        struct bpf_dynptr value;
        bpf_dynptr_from_mem(buf, sizeof("server"), 0, &value);

        int r = bpf_sock_read_xattr(sock, SOCKET_PROTOCOL_VARLINK_NAME, &value);
        if (r < 0)
                return VARLINK_SOCKET_NONE;

        if (bpf_strncmp(buf, sizeof("client"), "client") == 0)
                return VARLINK_SOCKET_CLIENT;
        if (bpf_strncmp(buf, sizeof("server"), "server") == 0)
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

        type = (*peer_type_p == VARLINK_SOCKET_CLIENT ? VARLINK_SOCKET_SERVER : VARLINK_SOCKET_CLIENT);
        bpf_map_update_elem(&varlink_sock_map, &sock_ino, &type, BPF_NOEXIST);

        return 0;
}

/* Read the socket path from the unix_address. The connected side of a
 * socketpair has no address, so fall back to the peer's address. */
static __always_inline void read_socket_path(
                struct monitor_varlink_packet *p,
                struct socket *sock) {

        struct unix_sock *u = (struct unix_sock *)BPF_CORE_READ(sock, sk);
        struct unix_address *addr = BPF_CORE_READ(u, addr);

        if (!addr) {
                struct sock *peer = BPF_CORE_READ(u, peer);
                if (!peer)
                        goto none;

                addr = BPF_CORE_READ((struct unix_sock *)peer, addr);
                if (!addr)
                        goto none;
        }

        int len = BPF_CORE_READ(addr, len);
        int path_len = len - 2; /* subtract sizeof(sa_family_t) */
        if (path_len <= 0 || path_len > MONITOR_VARLINK_MAX_PATH)
                goto none;

        p->path_len = path_len;
        bpf_probe_read_kernel(p->path, MONITOR_VARLINK_MAX_PATH,
                              addr->name[0].sun_path);
        return;

none:
        p->path_len = 0;
}

/* Capture hook: records varlink message data for sockets already discovered
 * by the LSM hook above. */
SEC("fentry/unix_stream_sendmsg")
int BPF_PROG(
                monitor_varlink_unix_stream_sendmsg,
                struct socket *sock,
                struct msghdr *msg,
                size_t len) {

        struct sock *sk = BPF_CORE_READ(sock, sk);

        __u32 uid = bpf_get_current_uid_gid();

        __u32 peer_uid = (__u32)-1;
        const struct cred *peer_cred = BPF_CORE_READ(sk, sk_peer_cred);
        if (peer_cred)
                peer_uid = BPF_CORE_READ(peer_cred, uid.val);

        /* Security boundary: only allow traffic the caller is authorized to see */
        if (allowed_uid != (__u32)-1 && uid != allowed_uid && peer_uid != allowed_uid)
                return 0;

        __u64 sock_ino = BPF_CORE_READ(sock, file, f_inode, i_ino);

        /* Only capture sockets classified as varlink by the LSM discovery hook */
        enum varlink_socket_type *type = bpf_map_lookup_elem(&varlink_sock_map, &sock_ino);
        if (!type)
                return 0;

        /* Capture the packet metadata and data into the ring buffer */
        __u32 cur_pid = bpf_get_current_pid_tgid() >> 32;

        struct pid *peer_pid_s = BPF_CORE_READ(sk, sk_peer_pid);
        __u32 peer_pid = peer_pid_s ? BPF_CORE_READ(peer_pid_s, numbers[0].nr) : 0;

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
                p->uid = uid;
                p->peer_uid = peer_uid;
                p->pid = cur_pid;
                p->peer_pid = peer_pid;
                p->total_len = len;
                p->type = *type;

                read_socket_path(p, sock);

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
