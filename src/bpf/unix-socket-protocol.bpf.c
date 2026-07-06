/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include "unix-socket-protocol-api.bpf.h"
#include "vmlinux.h"

#include <errno.h>
#include <string.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
        __uint(type, BPF_MAP_TYPE_INODE_STORAGE);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __type(key, int);
        __type(value, struct unix_socket_protocol_data);
} unix_socket_protocol_ino_map SEC(".maps");

static int match_xattr_protocol(const char *name) {
        char buf[260];
        buf[0] = 0;

        if (bpf_probe_read_kernel(buf, sizeof(buf), name) < 0)
                return -1;

        if (bpf_strncmp (buf, strlen(SOCKET_PROTOCOL_VARLINK_NAME), SOCKET_PROTOCOL_VARLINK_NAME) == 0)
                return UNIX_SOCKET_PROTOCOL_VARLINK;

        return UNIX_SOCKET_PROTOCOL_NONE;
}

SEC("lsm/inode_post_setxattr")
int BPF_PROG(
                unix_socket_protocol_inode_post_setxattr,
                struct dentry *dentry,
                const char *name,
                const void *value,
                size_t size,
                int flags) {
        enum unix_socket_protocol prot;
        struct unix_socket_protocol_data *storage;

        prot = match_xattr_protocol(name);
        if (prot < 0 || prot == UNIX_SOCKET_PROTOCOL_NONE)
                return 0;

        storage = bpf_inode_storage_get(
                &unix_socket_protocol_ino_map,
                (void *)dentry->d_inode,
                0,
                BPF_LOCAL_STORAGE_GET_F_CREATE);

        if (storage == NULL)
                return 0;

        storage->protocol = prot;
        storage->accepted = 0;

        return 0;
}

static int remove_xattr(struct dentry *dentry, const char *name) {
        enum unix_socket_protocol prot;

        prot = match_xattr_protocol(name);
        if (prot < 0 || prot == UNIX_SOCKET_PROTOCOL_NONE)
                return 0;

        bpf_inode_storage_delete(&unix_socket_protocol_ino_map, (void *)dentry->d_inode);
        return 0;
}

SEC("lsm/inode_removexattr")
int BPF_PROG(
                unix_socket_protocol_inode_removexattr___new,
                struct mnt_idmap *idmap,
                struct dentry *dentry,
                const char *name) {
        return remove_xattr(dentry, name);
}

SEC("lsm/inode_removexattr")
int BPF_PROG(
                unix_socket_protocol_inode_removexattr___old,
                struct dentry *dentry,
                const char *name) {
        return remove_xattr(dentry, name);
}

#define AF_UNIX 1

SEC("lsm/socket_bind")
int BPF_PROG(
                unix_socket_protocol_socket_bind,
                struct socket *sock,
                struct sockaddr *address,
                int addrlen) {
        struct unix_socket_protocol_data *storage;
        struct sockaddr_un *sun = (struct sockaddr_un *)address;
        int path_len;

        if (address->sa_family != AF_UNIX)
                return 0;

        path_len = addrlen - 2;
        if (path_len <= 0 || path_len > UNIX_SOCKET_MAX_PATH)
                return 0;

        /* Abstract sockets have sun_path[0] == '\0' — skip those */
        if (sun->sun_path[0] == '\0')
                return 0;

        storage = bpf_inode_storage_get(
                &unix_socket_protocol_ino_map,
                (void *)sock->file->f_inode,
                0,
                BPF_LOCAL_STORAGE_GET_F_CREATE);

        if (storage == NULL)
                return 0;

        storage->path_len = path_len;
        bpf_probe_read_kernel(storage->path, UNIX_SOCKET_MAX_PATH, sun->sun_path);

        return 0;
}

SEC("lsm/socket_accept")
int BPF_PROG(
                unix_socket_protocol_socket_accept,
                struct socket *sock,
                struct socket *newsock) {
        struct unix_socket_protocol_data *storage;
        struct unix_socket_protocol_data *newstorage;

        storage = bpf_inode_storage_get(
                &unix_socket_protocol_ino_map,
                (void *)sock->file->f_inode,
                0, 0);

        if (storage == NULL)
                return 0;

        newstorage = bpf_inode_storage_get(
                &unix_socket_protocol_ino_map,
                (void *)newsock->file->f_inode,
                0, BPF_LOCAL_STORAGE_GET_F_CREATE);

        if (newstorage == NULL)
                return 0;

        newstorage->protocol = storage->protocol;
        newstorage->accepted = 1;
        newstorage->path_len = storage->path_len;
        if (storage->path_len > 0)
                bpf_probe_read_kernel(newstorage->path, UNIX_SOCKET_MAX_PATH, storage->path);

        return 0;
}

char _license[] SEC("license") = "GPL";
