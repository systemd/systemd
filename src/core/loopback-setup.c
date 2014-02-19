/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <asm/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "util.h"
#include "macro.h"
#include "loopback-setup.h"
#include "socket-util.h"
#include "sd-rtnl.h"
#include "rtnl-util.h"

static int pipe_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        int *counter = userdata;
        int r;

        (*counter) --;

        r = sd_rtnl_message_get_errno(m);

        return r == -EEXIST ? 0 : r;
}

static int add_addresses(sd_rtnl *rtnl, int if_loopback, struct in_addr *ipv4_address, int *counter) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *ipv4 = NULL, *ipv6 = NULL;
        int r;

        r = sd_rtnl_message_new_addr(rtnl, &ipv4, RTM_NEWADDR, if_loopback, AF_INET);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_prefixlen(ipv4, 8);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_flags(ipv4, IFA_F_PERMANENT);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_scope(ipv4, RT_SCOPE_HOST);
        if (r < 0)
                return r;

        r = sd_rtnl_message_append_in_addr(ipv4, IFA_LOCAL, ipv4_address);
        if (r < 0)
                return r;

        r = sd_rtnl_call_async(rtnl, ipv4, &pipe_handler, counter, 0, NULL);
        if (r < 0)
                return r;

        (*counter) ++;

        if (!socket_ipv6_is_supported())
                return 0;

        r = sd_rtnl_message_new_addr(rtnl, &ipv6, RTM_NEWADDR, if_loopback, AF_INET6);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_prefixlen(ipv6, 128);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_flags(ipv6, IFA_F_PERMANENT);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_scope(ipv6, RT_SCOPE_HOST);
        if (r < 0)
                return r;

        r = sd_rtnl_message_append_in6_addr(ipv6, IFA_LOCAL, &in6addr_loopback);
        if (r < 0)
                return r;

        r = sd_rtnl_call_async(rtnl, ipv6, &pipe_handler, counter, 0, NULL);
        if (r < 0)
                return r;

        (*counter) ++;

        return 0;
}

static int start_interface(sd_rtnl *rtnl, int if_loopback, struct in_addr *ipv4_address, int *counter) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_SETLINK, if_loopback);
        if (r < 0)
                return r;

        r = sd_rtnl_message_link_set_flags(req, IFF_UP, IFF_UP);
        if (r < 0)
                return r;

        r = sd_rtnl_call_async(rtnl, req, &pipe_handler, counter, 0, NULL);
        if (r < 0)
                return r;

        (*counter) ++;

        return 0;
}

static int check_loopback(void) {
        int r;
        _cleanup_close_ int fd = -1;
        union {
                struct sockaddr sa;
                struct sockaddr_in in;
        } sa = {
                .in.sin_family = AF_INET,
                .in.sin_addr.s_addr = INADDR_LOOPBACK,
        };

        /* If we failed to set up the loop back device, check whether
         * it might already be set up */

        fd = socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        if (bind(fd, &sa.sa, sizeof(sa.in)) >= 0)
                r = 1;
        else
                r = errno == EADDRNOTAVAIL ? 0 : -errno;

        return r;
}

int loopback_setup(void) {
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        int r, if_loopback, counter = 0;
        bool eperm = false;
        struct in_addr ipv4_address;

        errno = 0;
        if_loopback = (int) if_nametoindex("lo");
        if (if_loopback <= 0)
                return errno ? -errno : -ENODEV;

        ipv4_address.s_addr = htonl(INADDR_LOOPBACK);

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0)
                return r;

        r = add_addresses(rtnl, if_loopback, &ipv4_address, &counter);
        if (r < 0)
                return r;

        r = start_interface(rtnl, if_loopback, &ipv4_address, &counter);
        if (r < 0)
                return r;

        while (counter > 0) {
                r = sd_rtnl_wait(rtnl, 0);
                if (r < 0)
                        return r;

                r = sd_rtnl_process(rtnl, 0);
                if (r < 0) {
                        if (r == -EPERM)
                                eperm = true;
                        else {
                                log_warning("Failed to configure loopback device: %s", strerror(-r));
                                return r;
                        }
                }
        }

        if (eperm && check_loopback() < 0) {
                log_warning("Failed to configure loopback device: %s", strerror(EPERM));
                return -EPERM;
        }

        return 0;
}
