/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#ifndef __VMLINUX_H__
#include <stdint.h>
#endif

#define MONITOR_VARLINK_MAX_PATH 108
#define MONITOR_VARLINK_MAX_DATA 1024

enum varlink_socket_type {
        VARLINK_SOCKET_NONE   = 0,
        VARLINK_SOCKET_CLIENT = 1,
        VARLINK_SOCKET_SERVER = 2,
        _VARLINK_SOCKET_TYPE_MAX,
};

struct monitor_varlink_packet {
        uint64_t timestamp_ns;
        uint64_t sock_ino;
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
