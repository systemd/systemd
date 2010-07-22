/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foosocketutilhfoo
#define foosocketutilhfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <net/if.h>
#include <selinux/selinux.h>

#include "macro.h"
#include "util.h"

typedef struct SocketAddress {
        union {
                struct sockaddr sa;
                struct sockaddr_in in4;
                struct sockaddr_in6 in6;
                struct sockaddr_un un;
                struct sockaddr_storage storage;
        } sockaddr;

        /* We store the size here explicitly due to the weird
         * sockaddr_un semantics for abstract sockets */
        socklen_t size;

        /* Socket type, i.e. SOCK_STREAM, SOCK_DGRAM, ... */
        int type;
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
int socket_address_print(const SocketAddress *a, char **p);
int socket_address_verify(const SocketAddress *a);

bool socket_address_can_accept(const SocketAddress *a);

int socket_address_listen(
                const SocketAddress *a,
                int backlog,
                SocketAddressBindIPv6Only only,
                const char *bind_to_device,
                bool free_bind,
                mode_t directory_mode,
                mode_t socket_mode,
                security_context_t scon,
                int *ret);

bool socket_address_is(const SocketAddress *a, const char *s, int type);

bool socket_address_equal(const SocketAddress *a, const SocketAddress *b);

bool socket_address_needs_mount(const SocketAddress *a, const char *prefix);

const char* socket_address_bind_ipv6_only_to_string(SocketAddressBindIPv6Only b);
SocketAddressBindIPv6Only socket_address_bind_ipv6_only_from_string(const char *s);

#endif
