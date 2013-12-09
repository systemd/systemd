/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosddhcpclienthfoo
#define foosddhcpclienthfoo

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.

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

#include <netinet/in.h>

typedef struct sd_dhcp_client sd_dhcp_client;

int sd_dhcp_client_set_request_option(sd_dhcp_client *client, uint8_t option);
int sd_dhcp_client_set_request_address(sd_dhcp_client *client,
                                       const struct in_addr *last_address);
int sd_dhcp_client_set_index(sd_dhcp_client *client, int interface_index);

sd_dhcp_client *sd_dhcp_client_new(void);

#endif
