/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include <inttypes.h>

#include "sd-event.h"
#include "sd-netlink.h"
#include "list.h"
#include "in-addr-util.h"

typedef struct ExposePort {
        int protocol;
        uint16_t host_port;
        uint16_t container_port;
        LIST_FIELDS(struct ExposePort, ports);
} ExposePort;

void expose_port_free_all(ExposePort *p);
int expose_port_parse(ExposePort **l, const char *s);

int expose_port_watch_rtnl(sd_event *event, int recv_fd, sd_netlink_message_handler_t handler, union in_addr_union *exposed, sd_netlink **ret);
int expose_port_send_rtnl(int send_fd);

int expose_port_execute(sd_netlink *rtnl, ExposePort *l, union in_addr_union *exposed);
int expose_port_flush(ExposePort* l, union in_addr_union *exposed);
