/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "macro.h"
#include "util.h"
#include "socket-util.h"
#include "missing.h"
#include "label.h"

int socket_address_parse(SocketAddress *a, const char *s) {
        int r;
        char *e, *n;
        unsigned u;

        assert(a);
        assert(s);

        zero(*a);
        a->type = SOCK_STREAM;

        if (*s == '[') {
                /* IPv6 in [x:.....:z]:p notation */

                if (!(e = strchr(s+1, ']')))
                        return -EINVAL;

                if (!(n = strndup(s+1, e-s-1)))
                        return -ENOMEM;

                errno = 0;
                if (inet_pton(AF_INET6, n, &a->sockaddr.in6.sin6_addr) <= 0) {
                        free(n);
                        return errno != 0 ? -errno : -EINVAL;
                }

                free(n);

                e++;
                if (*e != ':')
                        return -EINVAL;

                e++;
                if ((r = safe_atou(e, &u)) < 0)
                        return r;

                if (u <= 0 || u > 0xFFFF)
                        return -EINVAL;

                a->sockaddr.in6.sin6_family = AF_INET6;
                a->sockaddr.in6.sin6_port = htons((uint16_t) u);
                a->size = sizeof(struct sockaddr_in6);

        } else if (*s == '/') {
                /* AF_UNIX socket */

                size_t l;

                l = strlen(s);
                if (l >= sizeof(a->sockaddr.un.sun_path))
                        return -EINVAL;

                a->sockaddr.un.sun_family = AF_UNIX;
                memcpy(a->sockaddr.un.sun_path, s, l);
                a->size = sizeof(sa_family_t) + l + 1;

        } else if (*s == '@') {
                /* Abstract AF_UNIX socket */
                size_t l;

                l = strlen(s+1);
                if (l >= sizeof(a->sockaddr.un.sun_path) - 1)
                        return -EINVAL;

                a->sockaddr.un.sun_family = AF_UNIX;
                memcpy(a->sockaddr.un.sun_path+1, s+1, l);
                a->size = sizeof(sa_family_t) + 1 + l;

        } else {

                if ((e = strchr(s, ':'))) {

                        if ((r = safe_atou(e+1, &u)) < 0)
                                return r;

                        if (u <= 0 || u > 0xFFFF)
                                return -EINVAL;

                        if (!(n = strndup(s, e-s)))
                                return -ENOMEM;

                        /* IPv4 in w.x.y.z:p notation? */
                        if ((r = inet_pton(AF_INET, n, &a->sockaddr.in4.sin_addr)) < 0) {
                                free(n);
                                return -errno;
                        }

                        if (r > 0) {
                                /* Gotcha, it's a traditional IPv4 address */
                                free(n);

                                a->sockaddr.in4.sin_family = AF_INET;
                                a->sockaddr.in4.sin_port = htons((uint16_t) u);
                                a->size = sizeof(struct sockaddr_in);
                        } else {
                                unsigned idx;

                                if (strlen(n) > IF_NAMESIZE-1) {
                                        free(n);
                                        return -EINVAL;
                                }

                                /* Uh, our last resort, an interface name */
                                idx = if_nametoindex(n);
                                free(n);

                                if (idx == 0)
                                        return -EINVAL;

                                a->sockaddr.in6.sin6_family = AF_INET6;
                                a->sockaddr.in6.sin6_port = htons((uint16_t) u);
                                a->sockaddr.in6.sin6_scope_id = idx;
                                a->sockaddr.in6.sin6_addr = in6addr_any;
                                a->size = sizeof(struct sockaddr_in6);

                        }
                } else {

                        /* Just a port */
                        if ((r = safe_atou(s, &u)) < 0)
                                return r;

                        if (u <= 0 || u > 0xFFFF)
                                return -EINVAL;

                        a->sockaddr.in6.sin6_family = AF_INET6;
                        a->sockaddr.in6.sin6_port = htons((uint16_t) u);
                        a->sockaddr.in6.sin6_addr = in6addr_any;
                        a->size = sizeof(struct sockaddr_in6);
                }
        }

        return 0;
}

int socket_address_verify(const SocketAddress *a) {
        assert(a);

        switch (socket_address_family(a)) {
                case AF_INET:
                        if (a->size != sizeof(struct sockaddr_in))
                                return -EINVAL;

                        if (a->sockaddr.in4.sin_port == 0)
                                return -EINVAL;

                        return 0;

                case AF_INET6:
                        if (a->size != sizeof(struct sockaddr_in6))
                                return -EINVAL;

                        if (a->sockaddr.in6.sin6_port == 0)
                                return -EINVAL;

                        return 0;

                case AF_UNIX:
                        if (a->size < sizeof(sa_family_t))
                                return -EINVAL;

                        if (a->size > sizeof(sa_family_t)) {

                                if (a->sockaddr.un.sun_path[0] != 0) {
                                        char *e;

                                        /* path */
                                        if (!(e = memchr(a->sockaddr.un.sun_path, 0, sizeof(a->sockaddr.un.sun_path))))
                                                return -EINVAL;

                                        if (a->size != sizeof(sa_family_t) + (e - a->sockaddr.un.sun_path) + 1)
                                                return -EINVAL;
                                }
                        }

                        return 0;

                default:
                        return -EAFNOSUPPORT;
        }
}

int socket_address_print(const SocketAddress *a, char **p) {
        int r;
        assert(a);
        assert(p);

        if ((r = socket_address_verify(a)) < 0)
                return r;

        switch (socket_address_family(a)) {
                case AF_INET: {
                        char *ret;

                        if (!(ret = new(char, INET_ADDRSTRLEN+1+5+1)))
                                return -ENOMEM;

                        if (!inet_ntop(AF_INET, &a->sockaddr.in4.sin_addr, ret, INET_ADDRSTRLEN)) {
                                free(ret);
                                return -errno;
                        }

                        sprintf(strchr(ret, 0), ":%u", ntohs(a->sockaddr.in4.sin_port));
                        *p = ret;
                        return 0;
                }

                case AF_INET6: {
                        char *ret;

                        if (!(ret = new(char, 1+INET6_ADDRSTRLEN+2+5+1)))
                                return -ENOMEM;

                        ret[0] = '[';
                        if (!inet_ntop(AF_INET6, &a->sockaddr.in6.sin6_addr, ret+1, INET6_ADDRSTRLEN)) {
                                free(ret);
                                return -errno;
                        }

                        sprintf(strchr(ret, 0), "]:%u", ntohs(a->sockaddr.in6.sin6_port));
                        *p = ret;
                        return 0;
                }

                case AF_UNIX: {
                        char *ret;

                        if (a->size <= sizeof(sa_family_t)) {

                                if (!(ret = strdup("<unamed>")))
                                        return -ENOMEM;

                        } else if (a->sockaddr.un.sun_path[0] == 0) {
                                /* abstract */

                                /* FIXME: We assume we can print the
                                 * socket path here and that it hasn't
                                 * more than one NUL byte. That is
                                 * actually an invalid assumption */

                                if (!(ret = new(char, sizeof(a->sockaddr.un.sun_path)+1)))
                                        return -ENOMEM;

                                ret[0] = '@';
                                memcpy(ret+1, a->sockaddr.un.sun_path+1, sizeof(a->sockaddr.un.sun_path)-1);
                                ret[sizeof(a->sockaddr.un.sun_path)] = 0;

                        } else {

                                if (!(ret = strdup(a->sockaddr.un.sun_path)))
                                        return -ENOMEM;
                        }

                        *p = ret;
                        return 0;
                }

                default:
                        return -EINVAL;
        }
}

int socket_address_listen(
                const SocketAddress *a,
                int backlog,
                SocketAddressBindIPv6Only only,
                const char *bind_to_device,
                bool free_bind,
                mode_t directory_mode,
                mode_t socket_mode,
                const char *label,
                int *ret) {

        int r, fd, one;
        assert(a);
        assert(ret);

        if ((r = socket_address_verify(a)) < 0)
                return r;

        r = label_socket_set(label);
        if (r < 0)
                return r;

        fd = socket(socket_address_family(a), a->type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        r = fd < 0 ? -errno : 0;

        label_socket_clear();

        if (r < 0)
                return r;

        if (socket_address_family(a) == AF_INET6 && only != SOCKET_ADDRESS_DEFAULT) {
                int flag = only == SOCKET_ADDRESS_IPV6_ONLY;

                if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag)) < 0)
                        goto fail;
        }

        if (bind_to_device)
                if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, bind_to_device, strlen(bind_to_device)+1) < 0)
                        goto fail;

        if (free_bind) {
                one = 1;
                if (setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)) < 0)
                        log_warning("IP_FREEBIND failed: %m");
        }

        one = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
                goto fail;

        if (socket_address_family(a) == AF_UNIX && a->sockaddr.un.sun_path[0] != 0) {
                mode_t old_mask;

                /* Create parents */
                mkdir_parents(a->sockaddr.un.sun_path, directory_mode);

                /* Enforce the right access mode for the socket*/
                old_mask = umask(~ socket_mode);

                /* Include the original umask in our mask */
                umask(~socket_mode | old_mask);

                r = bind(fd, &a->sockaddr.sa, a->size);

                if (r < 0 && errno == EADDRINUSE) {
                        /* Unlink and try again */
                        unlink(a->sockaddr.un.sun_path);
                        r = bind(fd, &a->sockaddr.sa, a->size);
                }

                umask(old_mask);
        } else
                r = bind(fd, &a->sockaddr.sa, a->size);

        if (r < 0)
                goto fail;

        if (a->type == SOCK_STREAM)
                if (listen(fd, backlog) < 0)
                        goto fail;

        *ret = fd;
        return 0;

fail:
        r = -errno;
        close_nointr_nofail(fd);
        return r;
}

bool socket_address_can_accept(const SocketAddress *a) {
        assert(a);

        return
                a->type == SOCK_STREAM ||
                a->type == SOCK_SEQPACKET;
}

bool socket_address_equal(const SocketAddress *a, const SocketAddress *b) {
        assert(a);
        assert(b);

        /* Invalid addresses are unequal to all */
        if (socket_address_verify(a) < 0 ||
            socket_address_verify(b) < 0)
                return false;

        if (a->type != b->type)
                return false;

        if (a->size != b->size)
                return false;

        if (socket_address_family(a) != socket_address_family(b))
                return false;

        switch (socket_address_family(a)) {

        case AF_INET:
                if (a->sockaddr.in4.sin_addr.s_addr != b->sockaddr.in4.sin_addr.s_addr)
                        return false;

                if (a->sockaddr.in4.sin_port != b->sockaddr.in4.sin_port)
                        return false;

                break;

        case AF_INET6:
                if (memcmp(&a->sockaddr.in6.sin6_addr, &b->sockaddr.in6.sin6_addr, sizeof(a->sockaddr.in6.sin6_addr)) != 0)
                        return false;

                if (a->sockaddr.in6.sin6_port != b->sockaddr.in6.sin6_port)
                        return false;

                break;

        case AF_UNIX:

                if ((a->sockaddr.un.sun_path[0] == 0) != (b->sockaddr.un.sun_path[0] == 0))
                        return false;

                if (a->sockaddr.un.sun_path[0]) {
                        if (strncmp(a->sockaddr.un.sun_path, b->sockaddr.un.sun_path, sizeof(a->sockaddr.un.sun_path)) != 0)
                                return false;
                } else {
                        if (memcmp(a->sockaddr.un.sun_path, b->sockaddr.un.sun_path, a->size) != 0)
                                return false;
                }

                break;

        default:
                /* Cannot compare, so we assume the addresses are different */
                return false;
        }

        return true;
}

bool socket_address_is(const SocketAddress *a, const char *s, int type) {
        struct SocketAddress b;

        assert(a);
        assert(s);

        if (socket_address_parse(&b, s) < 0)
                return false;

        b.type = type;

        return socket_address_equal(a, &b);
}

bool socket_address_needs_mount(const SocketAddress *a, const char *prefix) {
        assert(a);

        if (socket_address_family(a) != AF_UNIX)
                return false;

        if (a->sockaddr.un.sun_path[0] == 0)
                return false;

        return path_startswith(a->sockaddr.un.sun_path, prefix);
}

static const char* const socket_address_bind_ipv6_only_table[_SOCKET_ADDRESS_BIND_IPV6_ONLY_MAX] = {
        [SOCKET_ADDRESS_DEFAULT] = "default",
        [SOCKET_ADDRESS_BOTH] = "both",
        [SOCKET_ADDRESS_IPV6_ONLY] = "ipv6-only"
};

DEFINE_STRING_TABLE_LOOKUP(socket_address_bind_ipv6_only, SocketAddressBindIPv6Only);
