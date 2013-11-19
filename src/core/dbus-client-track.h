/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
#include "set.h"
#include "manager.h"

typedef struct BusTrackedClient {
        Set *set;
        sd_bus *bus;
        char name[0];
} BusTrackedClient;

int bus_client_track(Set **s, sd_bus *bus, const char *name);

int bus_client_untrack(Set *s, sd_bus *bus, const char *name);
int bus_client_untrack_bus(Set *s, sd_bus *bus);

void bus_client_track_free(Set *s);

void bus_client_track_serialize(Manager *m, FILE *f, Set *s);
int bus_client_track_deserialize_item(Manager *m, Set **s, const char *line);
