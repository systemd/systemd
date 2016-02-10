#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include "sd-bus.h"

void bus_socket_setup(sd_bus *b);

int bus_socket_connect(sd_bus *b);
int bus_socket_exec(sd_bus *b);
int bus_socket_take_fd(sd_bus *b);
int bus_socket_start_auth(sd_bus *b);

int bus_socket_write_message(sd_bus *bus, sd_bus_message *m, size_t *idx);
int bus_socket_read_message(sd_bus *bus);

int bus_socket_process_opening(sd_bus *b);
int bus_socket_process_authenticating(sd_bus *b);

bool bus_socket_auth_needs_write(sd_bus *b);
