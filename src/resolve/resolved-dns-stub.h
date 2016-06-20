#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include "resolved-manager.h"

/* 127.0.0.53 in native endian */
#define INADDR_DNS_STUB ((in_addr_t) 0x7f000035U)

int manager_dns_stub_udp_fd(Manager *m);
int manager_dns_stub_tcp_fd(Manager *m);

void manager_dns_stub_stop(Manager *m);
int manager_dns_stub_start(Manager *m);
