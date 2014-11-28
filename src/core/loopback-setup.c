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

/* this is hardcoded in the kernel, so don't look it up */
#define LOOPBACK_IFINDEX 1

static int start_loopback(sd_rtnl *rtnl) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_SETLINK, LOOPBACK_IFINDEX);
        if (r < 0)
                return r;

        r = sd_rtnl_message_link_set_flags(req, IFF_UP, IFF_UP);
        if (r < 0)
                return r;

        r = sd_rtnl_call(rtnl, req, 0, NULL);
        if (r < 0)
                return r;

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
        int r;

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0)
                return r;

        r = start_loopback(rtnl);
        if (r == -EPERM) {
                if (check_loopback() < 0)
                        return log_warning_errno(EPERM, "Failed to configure loopback device: %m");
        } else if (r < 0)
                return log_warning_errno(r, "Failed to configure loopback device: %m");


        return 0;
}
