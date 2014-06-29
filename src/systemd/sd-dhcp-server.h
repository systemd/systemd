/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosddhcpserverhfoo
#define foosddhcpserverhfoo

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.
  Copyright (C) 2014 Tom Gundersen

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

#include <stdbool.h>
#include <netinet/in.h>

#include "sd-event.h"

typedef struct sd_dhcp_server sd_dhcp_server;

sd_dhcp_server *sd_dhcp_server_ref(sd_dhcp_server *server);
sd_dhcp_server *sd_dhcp_server_unref(sd_dhcp_server *server);

int sd_dhcp_server_new(sd_dhcp_server **ret, int ifindex);

int sd_dhcp_server_attach_event(sd_dhcp_server *client, sd_event *event, int priority);
int sd_dhcp_server_detach_event(sd_dhcp_server *client);
sd_event *sd_dhcp_server_get_event(sd_dhcp_server *client);

bool sd_dhcp_server_is_running(sd_dhcp_server *server);

int sd_dhcp_server_start(sd_dhcp_server *server);
int sd_dhcp_server_stop(sd_dhcp_server *server);

int sd_dhcp_server_set_address(sd_dhcp_server *server, struct in_addr *address);
int sd_dhcp_server_set_lease_pool(sd_dhcp_server *server, struct in_addr *start, size_t size);
#endif
