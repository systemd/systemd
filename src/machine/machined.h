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

#include "list.h"
#include "hashmap.h"
#include "sd-event.h"
#include "sd-bus.h"

typedef struct Manager Manager;

#include "machine.h"
#include "machine-dbus.h"
#include "image-dbus.h"

struct Manager {
        sd_event *event;
        sd_bus *bus;

        Hashmap *machines;
        Hashmap *machine_units;
        Hashmap *machine_leaders;

        Hashmap *polkit_registry;

        Hashmap *image_cache;
        sd_event_source *image_cache_defer_event;

        LIST_HEAD(Machine, machine_gc_queue);

        Machine *host_machine;
};

Manager *manager_new(void);
void manager_free(Manager *m);

int manager_add_machine(Manager *m, const char *name, Machine **_machine);
int manager_enumerate_machines(Manager *m);

int manager_startup(Manager *m);
int manager_run(Manager *m);

void manager_gc(Manager *m, bool drop_not_started);

int manager_get_machine_by_pid(Manager *m, pid_t pid, Machine **machine);

extern const sd_bus_vtable manager_vtable[];

int match_reloading(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_unit_removed(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_properties_changed(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_job_removed(sd_bus_message *message, void *userdata, sd_bus_error *error);

int manager_start_scope(Manager *manager, const char *scope, pid_t pid, const char *slice, const char *description, sd_bus_message *more_properties, sd_bus_error *error, char **job);
int manager_stop_unit(Manager *manager, const char *unit, sd_bus_error *error, char **job);
int manager_kill_unit(Manager *manager, const char *unit, int signo, sd_bus_error *error);
int manager_unit_is_active(Manager *manager, const char *unit);
int manager_job_is_active(Manager *manager, const char *path);
