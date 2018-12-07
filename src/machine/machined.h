/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "hashmap.h"
#include "list.h"

typedef struct Manager Manager;

#include "image-dbus.h"
#include "machine-dbus.h"
#include "machine.h"
#include "operation.h"

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

        LIST_HEAD(Operation, operations);
        unsigned n_operations;

        sd_event_source *nscd_cache_flush_event;
};

int manager_add_machine(Manager *m, const char *name, Machine **_machine);
int manager_get_machine_by_pid(Manager *m, pid_t pid, Machine **machine);

extern const sd_bus_vtable manager_vtable[];

int match_reloading(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_unit_removed(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_properties_changed(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_job_removed(sd_bus_message *message, void *userdata, sd_bus_error *error);

int manager_start_scope(Manager *manager, const char *scope, pid_t pid, const char *slice, const char *description, sd_bus_message *more_properties, sd_bus_error *error, char **job);
int manager_stop_unit(Manager *manager, const char *unit, sd_bus_error *error, char **job);
int manager_kill_unit(Manager *manager, const char *unit, int signo, sd_bus_error *error);
int manager_unref_unit(Manager *m, const char *unit, sd_bus_error *error);
int manager_unit_is_active(Manager *manager, const char *unit);
int manager_job_is_active(Manager *manager, const char *path);

int manager_enqueue_nscd_cache_flush(Manager *m);
