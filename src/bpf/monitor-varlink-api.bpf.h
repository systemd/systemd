/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "unix-socket-protocol-api.bpf.h"

#ifndef __VMLINUX_H__
#include <stdint.h>
#endif

#define MONITOR_VARLINK_MAX_DATA 1024

struct monitor_varlink_packet {
        uint32_t uid;
        uint32_t peer_uid;
        uint32_t pid;
        uint32_t peer_pid;
        uint8_t accepted;
        uint8_t path_len;
        char path[UNIX_SOCKET_MAX_PATH];
        uint32_t data_len;
        uint8_t data[MONITOR_VARLINK_MAX_DATA];
};
