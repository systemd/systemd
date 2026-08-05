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

#define AF_UNIX 1

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, __u32);
        __type(value, __u8);
} varlink_ino_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 4096);
        __type(key, __u64);
        __type(value, __u8);
} varlink_sock_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} monitor_varlink_ringbuf SEC(".maps");

static __always_inline bool match_xattr_name(const char *name) {
        char buf[sizeof(SOCKET_PROTOCOL_VARLINK_NAME)];

        if (bpf_probe_read_kernel(buf, sizeof(buf), name) < 0)
                return false;

        return bpf_strncmp(buf, sizeof(SOCKET_PROTOCOL_VARLINK_NAME) - 1,
                           SOCKET_PROTOCOL_VARLINK_NAME) == 0;
}

#define XATTR_VALUE_LISTEN     "listen"
#define XATTR_VALUE_SERVER     "server"
#define XATTR_VALUE_ENTRYPOINT "entrypoint"

enum varlink_xattr_role {
        VARLINK_XATTR_NONE,
        VARLINK_XATTR_LISTEN,
        VARLINK_XATTR_SERVER,
        VARLINK_XATTR_ENTRYPOINT,
};

static __always_inline enum varlink_xattr_role match_xattr_value(const void *value, size_t size) {
        char buf[sizeof(XATTR_VALUE_ENTRYPOINT) - 1];

        if (size > sizeof(buf))
                return VARLINK_XATTR_NONE;

        if (bpf_probe_read_kernel(buf, sizeof(buf), value) < 0)
                return VARLINK_XATTR_NONE;

        if (size == sizeof(XATTR_VALUE_LISTEN) - 1 &&
            bpf_strncmp(buf, sizeof(XATTR_VALUE_LISTEN) - 1, XATTR_VALUE_LISTEN) == 0)
                return VARLINK_XATTR_LISTEN;

        if (size == sizeof(XATTR_VALUE_SERVER) - 1 &&
            bpf_strncmp(buf, sizeof(XATTR_VALUE_SERVER) - 1, XATTR_VALUE_SERVER) == 0)
                return VARLINK_XATTR_SERVER;

        if (size == sizeof(XATTR_VALUE_ENTRYPOINT) - 1 &&
            bpf_strncmp(buf, sizeof(XATTR_VALUE_ENTRYPOINT) - 1, XATTR_VALUE_ENTRYPOINT) == 0)
                return VARLINK_XATTR_ENTRYPOINT;

        return VARLINK_XATTR_NONE;
}

SEC("lsm/inode_post_setxattr")
int BPF_PROG(
                monitor_varlink_inode_post_setxattr,
                struct dentry *dentry,
                const char *name,
                const void *value,
                size_t size,
                int flags) {

        enum varlink_xattr_role role;
        __u8 val = 1;

        if (!match_xattr_name(name))
                return 0;

        role = match_xattr_value(value, size);

        switch (role) {

        case VARLINK_XATTR_LISTEN:
        case VARLINK_XATTR_SERVER: {
                __u64 sock_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
                bpf_map_update_elem(&varlink_sock_map, &sock_ino, &val, BPF_ANY);
                break;
        }

        case VARLINK_XATTR_ENTRYPOINT: {
                __u32 fs_ino = (__u32)BPF_CORE_READ(dentry, d_inode, i_ino);
                bpf_map_update_elem(&varlink_ino_map, &fs_ino, &val, BPF_ANY);
                break;
        }

        default:
                break;
        }

        return 0;
}

static __always_inline int remove_xattr(struct dentry *dentry, const char *name) {
        __u64 ino;

        if (!match_xattr_name(name))
                return 0;

        ino = BPF_CORE_READ(dentry, d_inode, i_ino);

        bpf_map_delete_elem(&varlink_sock_map, &ino);

        __u32 ino32 = (__u32)ino;
        bpf_map_delete_elem(&varlink_ino_map, &ino32);

        return 0;
}

SEC("lsm/inode_removexattr")
int BPF_PROG(
                monitor_varlink_inode_removexattr___new,
                struct mnt_idmap *idmap,
                struct dentry *dentry,
                const char *name) {
        return remove_xattr(dentry, name);
}

SEC("lsm/inode_removexattr")
int BPF_PROG(
                monitor_varlink_inode_removexattr___old,
                struct dentry *dentry,
                const char *name) {
        return remove_xattr(dentry, name);
}

static __always_inline __u64 get_fs_ino(struct unix_sock *u) {
        struct dentry *d = BPF_CORE_READ(u, path.dentry);

        if (!d)
                return 0;

        return BPF_CORE_READ(d, d_inode, i_ino);
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(
                monitor_varlink_socket_sendmsg,
                struct socket *sock,
                void *msg,
                int size) {

        __u64 sock_ino, fs_ino;
        __u32 fs_ino32;
        __u8 val = 1;

        if (BPF_CORE_READ(sock, sk, __sk_common.skc_family) != AF_UNIX)
                return 0;

        sock_ino = BPF_CORE_READ(sock, file, f_inode, i_ino);

        if (bpf_map_lookup_elem(&varlink_sock_map, &sock_ino))
                return 0;

        /* Check if the socket's bound path belongs to a known varlink listener. Accepted sockets inherit
         * the listener's path (the kernel copies it during unix_stream_connect), so this covers both
         * listeners and accepted server sockets. */
        struct unix_sock *u = (struct unix_sock *)BPF_CORE_READ(sock, sk);

        fs_ino = get_fs_ino(u);
        if (fs_ino) {
                fs_ino32 = (__u32)fs_ino;
                if (bpf_map_lookup_elem(&varlink_ino_map, &fs_ino32)) {
                        bpf_map_update_elem(&varlink_sock_map, &sock_ino, &val, BPF_NOEXIST);
                        return 0;
                }
        }

        /* For client sockets (no path of their own), check the peer — which is the server-side accepted
         * socket and carries the listener's path. */
        struct sock *peer = BPF_CORE_READ(u, peer);
        if (!peer)
                return 0;

        struct unix_sock *peer_u = (struct unix_sock *)peer;
        fs_ino = get_fs_ino(peer_u);
        if (!fs_ino)
                return 0;

        fs_ino32 = (__u32)fs_ino;
        if (bpf_map_lookup_elem(&varlink_ino_map, &fs_ino32))
                bpf_map_update_elem(&varlink_sock_map, &sock_ino, &val, BPF_NOEXIST);

        return 0;
}

/* Sockets created via socketpair() and passed over an existing varlink connection (fd passing) have no
 * unix_sock->addr on either end, so path_len will be 0. To track their origin we'd need to hook SCM_RIGHTS
 * fd passing and associate child sockets with the parent connection that carried them. */
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
        if (path_len <= 0 || path_len > UNIX_SOCKET_MAX_PATH)
                goto none;

        p->path_len = path_len;
        /* The verifier requires a constant size; bytes beyond path_len are
         * unused padding within sun_path and bounded by path_len in userspace. */
        bpf_probe_read_kernel(p->path, UNIX_SOCKET_MAX_PATH,
                              addr->name[0].sun_path);
        return;

none:
        p->path_len = 0;
}

SEC("fentry/unix_stream_sendmsg")
int BPF_PROG(
                monitor_varlink_unix_stream_sendmsg,
                struct socket *sock,
                struct msghdr *msg,
                size_t len) {

        struct monitor_varlink_packet *p;
        __u64 sock_ino;
        void *ubuf;
        size_t iov_offset, offset = 0;

        sock_ino = BPF_CORE_READ(sock, file, f_inode, i_ino);

        if (!bpf_map_lookup_elem(&varlink_sock_map, &sock_ino))
                return 0;

        ubuf = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
        iov_offset = BPF_CORE_READ(msg, msg_iter.iov_offset);

        for (int i = 0; i < MONITOR_VARLINK_MAX_PACKETS; i++) {
                size_t remaining;

                if (offset >= len)
                        break;

                p = bpf_ringbuf_reserve(&monitor_varlink_ringbuf, sizeof(*p), 0);
                if (!p)
                        return 0;

                p->timestamp_ns = bpf_ktime_get_boot_ns();
                p->sock_ino = sock_ino;
                p->uid = bpf_get_current_uid_gid() >> 32;
                p->peer_uid = BPF_CORE_READ(sock, sk, sk_peer_cred, uid.val);
                p->pid = bpf_get_current_pid_tgid() >> 32;
                p->peer_pid = BPF_CORE_READ(sock, sk, sk_peer_pid, numbers[0].nr);

                read_socket_path(p, sock);

                remaining = len - offset;
                p->data_len = remaining < MONITOR_VARLINK_MAX_DATA ? remaining : MONITOR_VARLINK_MAX_DATA;

                bpf_probe_read_user(p->data, MONITOR_VARLINK_MAX_DATA, ubuf + iov_offset + offset);

                bpf_ringbuf_submit(p, 0);
                offset += MONITOR_VARLINK_MAX_DATA;
        }

        return 0;
}

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
