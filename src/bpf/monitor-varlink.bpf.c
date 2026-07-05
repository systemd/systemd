/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include "unix-socket-protocol-api.bpf.h"
#include "vmlinux.h"

#include <errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "monitor-varlink-api.bpf.h"

#define AF_UNIX 1

struct {
        __uint(type, BPF_MAP_TYPE_INODE_STORAGE);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __type(key, int);
        __type(value, struct unix_socket_protocol_data);
} unix_socket_protocol_ino_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, struct inode*);
        __type(value, struct unix_socket_protocol_data);
} monitor_varlink_socket_prot_cache SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} monitor_varlink_ringbuf SEC(".maps");

/* We need a hook in unix_stream_sendmsg because it's where the data we want to capture actually gets sent */
SEC("fentry/unix_stream_sendmsg")
int BPF_PROG(monitor_varlink_unix_stream_sendmsg, struct socket *sock, struct msghdr *msg, size_t len)
{
        struct monitor_varlink_packet *p;
        struct unix_socket_protocol_data *cached;
        struct inode *ino;
        void *ubuf;
        size_t iov_offset;

        ino = sock->file->f_inode;
        cached = bpf_map_lookup_elem(&monitor_varlink_socket_prot_cache, &ino);

        if (!cached || cached->protocol != UNIX_SOCKET_PROTOCOL_VARLINK)
                return 0;

        p = bpf_ringbuf_reserve(&monitor_varlink_ringbuf, sizeof(*p), 0);
        if (!p)
                return 0;

        p->uid = bpf_get_current_uid_gid() >> 32;
        p->peer_uid = BPF_CORE_READ(sock, sk, sk_peer_cred, uid.val);
        p->pid = bpf_get_current_pid_tgid() >> 32;
        p->peer_pid = BPF_CORE_READ(sock, sk, sk_peer_pid, numbers[0].nr);

        p->accepted = cached->accepted;
        p->path_len = cached->path_len;
        if (cached->path_len > 0)
                __builtin_memcpy(p->path, cached->path, UNIX_SOCKET_MAX_PATH);

        p->data_len = len < MONITOR_VARLINK_MAX_DATA ? len : MONITOR_VARLINK_MAX_DATA;

        ubuf = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
        iov_offset = BPF_CORE_READ(msg, msg_iter.iov_offset);

        bpf_probe_read_user(p->data, MONITOR_VARLINK_MAX_DATA, ubuf + iov_offset);

        bpf_ringbuf_submit(p, 0);
        return 0;
}

/* The inode storage is only available in LSM hooks. Let's move it over to a cache hashmap so we can look the
 * data up in kprobe/unix_stream_sendmsg. */
SEC("lsm/socket_sendmsg")
int BPF_PROG(monitor_varlink_socket_sendmsg, struct socket *sock, void *msg, int size)
{
        struct inode *ino;
        struct unix_socket_protocol_data *data;

        if (BPF_CORE_READ(sock, sk, __sk_common.skc_family) != AF_UNIX)
                return 0;

        data = bpf_inode_storage_get(
                &unix_socket_protocol_ino_map,
                (void *)sock->file->f_inode,
                0,
                0);

        if (!data)
                return 0;

        ino = sock->file->f_inode;
        bpf_map_update_elem(&monitor_varlink_socket_prot_cache, &ino, data, BPF_ANY);

        return 0;
}

/* And we also have to get rid of the entries in the hashmap */
SEC("fentry/unix_release_sock")
int BPF_PROG(monitor_varlink_unix_release_sock, struct sock *sk, int embrion)
{
        struct inode *ino;

        ino = sk->sk_socket->file->f_inode;
        bpf_map_delete_elem(&monitor_varlink_socket_prot_cache, &ino);

        return 0;
}

static const char _license[] SEC("license") = "GPL";
