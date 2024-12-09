/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-varlink.h"

typedef struct Manager Manager;

#include "hashmap.h"
#include "image-dbus.h"
#include "list.h"
#include "local-addresses.h"
#include "machine-dbus.h"
#include "machine.h"
#include "operation.h"
#include "pidref.h"

struct Manager {
        sd_event *event;
        sd_bus *bus;

        Hashmap *machines;
        Hashmap *machines_by_unit;
        Hashmap *machines_by_leader;

        sd_event_source *deferred_gc_event_source;

        Hashmap *polkit_registry;

        Hashmap *image_cache;
        sd_event_source *image_cache_defer_event;

        LIST_HEAD(Machine, machine_gc_queue);

        Machine *host_machine;

        LIST_HEAD(Operation, operations);
        unsigned n_operations;

        sd_varlink_server *varlink_userdb_server;
        sd_varlink_server *varlink_machine_server;

        RuntimeScope runtime_scope; /* for now: always RUNTIME_SCOPE_SYSTEM */
};

int manager_add_machine(Manager *m, const char *name, Machine **ret);
int manager_get_machine_by_pidref(Manager *m, const PidRef *pidref, Machine **ret);

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

int manager_find_machine_for_uid(Manager *m, uid_t host_uid, Machine **ret_machine, uid_t *ret_internal_uid);
int manager_find_machine_for_gid(Manager *m, gid_t host_gid, Machine **ret_machine, gid_t *ret_internal_gid);

void manager_gc(Manager *m, bool drop_not_started);
void manager_enqueue_gc(Manager *m);

int machine_get_addresses(Machine* machine, struct local_address **ret_addresses);
int machine_get_os_release(Machine *machine, char ***ret_os_release);
int manager_acquire_image(Manager *m, const char *name, Image **ret);
int rename_image_and_update_cache(Manager *m, Image *image, const char* new_name);
