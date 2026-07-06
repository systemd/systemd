/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#define XATTR_PREFIX "user."

#define SOCKET_PROTOCOL_VARLINK_NAME XATTR_PREFIX "varlink"

#define UNIX_SOCKET_MAX_PATH 108

enum unix_socket_protocol {
        UNIX_SOCKET_PROTOCOL_NONE,
        UNIX_SOCKET_PROTOCOL_VARLINK,
};

struct unix_socket_protocol_data {
        enum unix_socket_protocol protocol;
        unsigned char accepted;
        unsigned char path_len;
        char path[UNIX_SOCKET_MAX_PATH];
};
