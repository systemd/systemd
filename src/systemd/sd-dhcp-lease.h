/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosddhcpleasehfoo
#define foosddhcpleasehfoo

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

#include <netinet/in.h>
#include <net/ethernet.h>

typedef struct sd_dhcp_lease sd_dhcp_lease;
struct sd_dhcp_route;

sd_dhcp_lease *sd_dhcp_lease_ref(sd_dhcp_lease *lease);
sd_dhcp_lease *sd_dhcp_lease_unref(sd_dhcp_lease *lease);
int sd_dhcp_lease_get_address(sd_dhcp_lease *lease, struct in_addr *addr);
int sd_dhcp_lease_get_lifetime(sd_dhcp_lease *lease, uint32_t *lifetime);
int sd_dhcp_lease_get_netmask(sd_dhcp_lease *lease, struct in_addr *addr);
int sd_dhcp_lease_get_router(sd_dhcp_lease *lease, struct in_addr *addr);
int sd_dhcp_lease_get_next_server(sd_dhcp_lease *lease, struct in_addr *addr);
int sd_dhcp_lease_get_server_identifier(sd_dhcp_lease *lease, struct in_addr *addr);
int sd_dhcp_lease_get_dns(sd_dhcp_lease *lease, struct in_addr **addr, size_t *addr_size);
int sd_dhcp_lease_get_ntp(sd_dhcp_lease *lease, struct in_addr **addr, size_t *addr_size);
int sd_dhcp_lease_get_mtu(sd_dhcp_lease *lease, uint16_t *mtu);
int sd_dhcp_lease_get_domainname(sd_dhcp_lease *lease, const char **domainname);
int sd_dhcp_lease_get_hostname(sd_dhcp_lease *lease, const char **hostname);
int sd_dhcp_lease_get_root_path(sd_dhcp_lease *lease, const char **root_path);
int sd_dhcp_lease_get_routes(sd_dhcp_lease *lease, struct sd_dhcp_route **routes, size_t *routes_size);
#endif
