/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"
#include "sd-event.h"

typedef struct Manager Manager;

#include "hashmap.h"
#include "image-dbus.h"
#include "list.h"
#include "machine-dbus.h"
#include "machine.h"
#include "operation.h"
#include "varlink.h"

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

#if ENABLE_NSCD
        sd_event_source *nscd_cache_flush_event;
#endif

        VarlinkServer *varlink_server;
};

int manager_add_machine(Manager *m, const char *name, Machine **_machine);
int manager_get_machine_by_pid(Manager *m, pid_t pid, Machine **machine);

extern const BusObjectImplementation manager_object;

int match_reloading(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_unit_removed(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_properties_changed(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_job_removed(sd_bus_message *message, void *userdata, sd_bus_error *error);

int manager_stop_unit(Manager *manager, const char *unit, sd_bus_error *error, char **job);
int manager_kill_unit(Manager *manager, const char *unit, int signo, sd_bus_error *error);
int manager_unref_unit(Manager *m, const char *unit, sd_bus_error *error);
int manager_unit_is_active(Manager *manager, const char *unit);
int manager_job_is_active(Manager *manager, const char *path);

#if ENABLE_NSCD
int manager_enqueue_nscd_cache_flush(Manager *m);
#else
static inline void manager_enqueue_nscd_cache_flush(Manager *m) {}
#endif

int manager_find_machine_for_uid(Manager *m, uid_t host_uid, Machine **ret_machine, uid_t *ret_internal_uid);
int manager_find_machine_for_gid(Manager *m, gid_t host_gid, Machine **ret_machine, gid_t *ret_internal_gid);
