/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/if_packet.h>

#include "macro.h"
#include "util.h"

union sockaddr_union {
        struct sockaddr sa;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        struct sockaddr_un un;
        struct sockaddr_nl nl;
        struct sockaddr_storage storage;
        struct sockaddr_ll ll;
};

union in_addr_union {
        struct in_addr in;
        struct in6_addr in6;
};

typedef struct SocketAddress {
        union sockaddr_union sockaddr;

        /* We store the size here explicitly due to the weird
         * sockaddr_un semantics for abstract sockets */
        socklen_t size;

        /* Socket type, i.e. SOCK_STREAM, SOCK_DGRAM, ... */
        int type;

        /* Socket protocol, IPPROTO_xxx, usually 0, except for netlink */
        int protocol;
} SocketAddress;

typedef enum SocketAddressBindIPv6Only {
        SOCKET_ADDRESS_DEFAULT,
        SOCKET_ADDRESS_BOTH,
        SOCKET_ADDRESS_IPV6_ONLY,
        _SOCKET_ADDRESS_BIND_IPV6_ONLY_MAX,
        _SOCKET_ADDRESS_BIND_IPV6_ONLY_INVALID = -1
} SocketAddressBindIPv6Only;

#define socket_address_family(a) ((a)->sockaddr.sa.sa_family)

int socket_address_parse(SocketAddress *a, const char *s);
int socket_address_parse_netlink(SocketAddress *a, const char *s);
int socket_address_print(const SocketAddress *a, char **p);
int socket_address_verify(const SocketAddress *a) _pure_;
int socket_address_unlink(SocketAddress *a);

bool socket_address_can_accept(const SocketAddress *a) _pure_;

int socket_address_listen(
                const SocketAddress *a,
                int flags,
                int backlog,
                SocketAddressBindIPv6Only only,
                const char *bind_to_device,
                bool free_bind,
                bool transparent,
                mode_t directory_mode,
                mode_t socket_mode,
                const char *label);
int make_socket_fd(int log_level, const char* address, int flags);

bool socket_address_is(const SocketAddress *a, const char *s, int type);
bool socket_address_is_netlink(const SocketAddress *a, const char *s);

bool socket_address_matches_fd(const SocketAddress *a, int fd);

bool socket_address_equal(const SocketAddress *a, const SocketAddress *b) _pure_;

const char* socket_address_get_path(const SocketAddress *a);

bool socket_ipv6_is_supported(void);

int sockaddr_pretty(const struct sockaddr *_sa, socklen_t salen, bool translate_ipv6, char **ret);
int getpeername_pretty(int fd, char **ret);
int getsockname_pretty(int fd, char **ret);

const char* socket_address_bind_ipv6_only_to_string(SocketAddressBindIPv6Only b) _const_;
SocketAddressBindIPv6Only socket_address_bind_ipv6_only_from_string(const char *s) _pure_;

int netlink_family_to_string_alloc(int b, char **s);
int netlink_family_from_string(const char *s) _pure_;

int in_addr_null(unsigned family, union in_addr_union *u);
int in_addr_equal(unsigned family, union in_addr_union *a, union in_addr_union *b);
int in_addr_prefix_intersect(unsigned family, const union in_addr_union *a, unsigned aprefixlen, const union in_addr_union *b, unsigned bprefixlen);
int in_addr_prefix_next(unsigned family, union in_addr_union *u, unsigned prefixlen);
int in_addr_to_string(unsigned family, const union in_addr_union *u, char **ret);
int in_addr_from_string(unsigned family, const char *s, union in_addr_union *ret);
