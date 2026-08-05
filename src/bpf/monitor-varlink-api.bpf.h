/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#ifndef __VMLINUX_H__
#include <stdint.h>
#endif

#define SOCKET_PROTOCOL_VARLINK_NAME "user.varlink"
#define UNIX_SOCKET_MAX_PATH 108
#define MONITOR_VARLINK_MAX_DATA 1024
#define MONITOR_VARLINK_MAX_PACKETS 8

struct monitor_varlink_packet {
        uint64_t timestamp_ns;
        uint64_t sock_ino;
        uint32_t uid;
        uint32_t peer_uid;
        uint32_t pid;
        uint32_t peer_pid;
        uint8_t path_len;
        char path[UNIX_SOCKET_MAX_PATH];
        uint32_t data_len;
        uint8_t data[MONITOR_VARLINK_MAX_DATA];
};
