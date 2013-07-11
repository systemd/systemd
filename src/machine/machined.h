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

#include <stdbool.h>
#include <inttypes.h>
#include <dbus/dbus.h>

#include "util.h"
#include "list.h"
#include "hashmap.h"

typedef struct Manager Manager;

#include "machine.h"

struct Manager {
        DBusConnection *bus;

        int bus_fd;
        int epoll_fd;

        Hashmap *machines;
        Hashmap *machine_units;

        LIST_HEAD(Machine, machine_gc_queue);
};

enum {
        FD_BUS
};

Manager *manager_new(void);
void manager_free(Manager *m);

int manager_add_machine(Manager *m, const char *name, Machine **_machine);

int manager_enumerate_machines(Manager *m);

int manager_startup(Manager *m);
int manager_run(Manager *m);

void manager_gc(Manager *m, bool drop_not_started);

int manager_get_machine_by_pid(Manager *m, pid_t pid, Machine **machine);

extern const DBusObjectPathVTable bus_manager_vtable;

DBusHandlerResult bus_message_filter(DBusConnection *c, DBusMessage *message, void *userdata);

int manager_start_scope(Manager *manager, const char *scope, pid_t pid, const char *slice, const char *description, DBusMessageIter *more_properties, DBusError *error, char **job);
int manager_stop_unit(Manager *manager, const char *unit, DBusError *error, char **job);
int manager_kill_unit(Manager *manager, const char *unit, KillWho who, int signo, DBusError *error);
int manager_unit_is_active(Manager *manager, const char *unit);
