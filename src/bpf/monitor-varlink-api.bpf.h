/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#ifndef __VMLINUX_H__
#include <stdint.h>
#endif

#ifndef UID_INVALID
#define UID_INVALID ((uint32_t) -1)
#endif

#define MONITOR_VARLINK_MAX_PATH 108U
#define MONITOR_VARLINK_MAX_DATA 1024U
#define MONITOR_VARLINK_MAX_FILTERS 16U

enum varlink_socket_type {
        VARLINK_SOCKET_NONE,
        VARLINK_SOCKET_CLIENT,
        VARLINK_SOCKET_SERVER,
        _VARLINK_SOCKET_TYPE_MAX,
};

struct monitor_varlink_filter {
        uint32_t uid;        /* match sender or peer uid, UID_INVALID = any */
        uint32_t pid;        /* match sender or peer pid, 0 = any */
        uint64_t pidfd_id;   /* match sender or peer pidfd inode, 0 = any */
        uint8_t has_path;    /* if false, accept any path */
        uint8_t path_len;    /* 0 = match anonymous sockets, >0 = match this path */
        char path[MONITOR_VARLINK_MAX_PATH];
};

struct monitor_varlink_packet {
        uint64_t timestamp_ns;
        uint64_t sock_ino;
        uint64_t sock_cookie;
        uint64_t pidfd_id;
        uint64_t peer_pidfd_id;
        uint32_t uid;
        uint32_t peer_uid;
        uint32_t pid;
        uint32_t peer_pid;
        uint32_t data_len;
        uint32_t total_len;
        uint8_t type;
        uint8_t path_len;
        char path[MONITOR_VARLINK_MAX_PATH];
        uint8_t data[MONITOR_VARLINK_MAX_DATA];
};
