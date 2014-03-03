/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include "manager.h"

int bus_send_queued_message(Manager *m);

int bus_init(Manager *m, bool try_bus_connect);
void bus_done(Manager *m);

int bus_fdset_add_all(Manager *m, FDSet *fds);

void bus_track_serialize(sd_bus_track *t, FILE *f);
int bus_track_deserialize_item(char ***l, const char *line);
int bus_track_coldplug(Manager *m, sd_bus_track **t, char ***l);

int bus_foreach_bus(Manager *m, sd_bus_track *subscribed2, int (*send_message)(sd_bus *bus, void *userdata), void *userdata);
