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

#include <dbus/dbus.h>

#include "manager.h"

int bus_init(Manager *m, bool try_bus_connect);
void bus_done(Manager *m);

unsigned bus_dispatch(Manager *m);

void bus_watch_event(Manager *m, Watch *w, int events);
void bus_timeout_event(Manager *m, Watch *w, int events);

int bus_query_pid(Manager *m, const char *name);

int bus_broadcast(Manager *m, DBusMessage *message);

bool bus_has_subscriber(Manager *m);
bool bus_connection_has_subscriber(Manager *m, DBusConnection *c);

int bus_fdset_add_all(Manager *m, FDSet *fds);

void bus_broadcast_finished(Manager *m, usec_t firmware_usec, usec_t loader_usec, usec_t kernel_usec, usec_t initrd_usec, usec_t userspace_usec, usec_t total_usec);
void bus_broadcast_reloading(Manager *m, bool active);

Set *bus_acquire_subscribed(Manager *m, DBusConnection *c);

void bus_serialize(Manager *m, FILE *f);
int bus_deserialize_item(Manager *m, const char *line);

#define BUS_CONNECTION_SUBSCRIBED(m, c) dbus_connection_get_data((c), (m)->subscribed_data_slot)
#define BUS_PENDING_CALL_NAME(m, p) dbus_pending_call_get_data((p), (m)->name_data_slot)

extern const char * const bus_interface_table[];
