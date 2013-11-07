/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include <linux/netlink.h>

#include "refcnt.h"

struct sd_rtnl {
        RefCount n_ref;

        int fd;

        union {
                struct sockaddr sa;
                struct sockaddr_nl nl;
        } sockaddr;

        uint32_t serial;

        pid_t original_pid;
};

#define RTNL_DEFAULT_TIMEOUT ((usec_t) (10 * USEC_PER_SEC))

int message_get_errno(sd_rtnl_message *m);
int message_get_serial(sd_rtnl_message *m);
int message_seal(sd_rtnl *nl, sd_rtnl_message *m);
int socket_write_message(sd_rtnl *nl, sd_rtnl_message *m);
int socket_read_message(sd_rtnl *nl, sd_rtnl_message **ret);
