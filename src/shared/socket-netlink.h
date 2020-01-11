/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-netlink.h"

#include "in-addr-util.h"
#include "macro.h"
#include "socket-util.h"

int resolve_ifname(sd_netlink **rtnl, const char *name);
int resolve_interface(sd_netlink **rtnl, const char *name);
int resolve_interface_or_warn(sd_netlink **rtnl, const char *name);

int make_socket_fd(int log_level, const char* address, int type, int flags);

int socket_address_parse(SocketAddress *a, const char *s);
int socket_address_parse_and_warn(SocketAddress *a, const char *s);
int socket_address_parse_netlink(SocketAddress *a, const char *s);

bool socket_address_is(const SocketAddress *a, const char *s, int type);
bool socket_address_is_netlink(const SocketAddress *a, const char *s);

int in_addr_ifindex_from_string_auto(const char *s, int *family, union in_addr_union *ret, int *ifindex);
