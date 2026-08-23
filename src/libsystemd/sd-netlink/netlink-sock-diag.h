/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

/* TODO: to be exported later */

int sd_sock_diag_socket_open(sd_netlink **ret);
int sd_sock_diag_message_new_unix(sd_netlink *sdnl, sd_netlink_message **ret, ino_t inode, uint64_t cookie, uint32_t show);
int sd_sock_diag_message_new_unix_dump(sd_netlink *sdnl, sd_netlink_message **ret, uint32_t states, uint32_t show);
int sd_sock_diag_message_get_unix(sd_netlink_message *m, struct unix_diag_msg *ret);
