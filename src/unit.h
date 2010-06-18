/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foounithfoo
#define foounithfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdbool.h>
#include <stdlib.h>

typedef union Unit Unit;
typedef struct Meta Meta;
typedef struct UnitVTable UnitVTable;
typedef enum UnitType UnitType;
typedef enum UnitLoadState UnitLoadState;
typedef enum UnitActiveState UnitActiveState;
typedef enum UnitDependency UnitDependency;

#include "set.h"
#include "util.h"
#include "list.h"
#include "socket-util.h"
#include "execute.h"

#define UNIT_NAME_MAX 128
#define DEFAULT_TIMEOUT_USEC (60*USEC_PER_SEC)
#define DEFAULT_RESTART_USEC (100*USEC_PER_MSEC)

typedef enum KillMode {
        KILL_CONTROL_GROUP = 0,
        KILL_PROCESS_GROUP,
        KILL_PROCESS,
        KILL_NONE,
        _KILL_MODE_MAX,
        _KILL_MODE_INVALID = -1
} KillMode;

enum UnitType {
        UNIT_SERVICE = 0,
        UNIT_SOCKET,
        UNIT_TARGET,
        UNIT_DEVICE,
        UNIT_MOUNT,
        UNIT_AUTOMOUNT,
        UNIT_SNAPSHOT,
        UNIT_TIMER,
        UNIT_SWAP,
        UNIT_PATH,
        _UNIT_TYPE_MAX,
        _UNIT_TYPE_INVALID = -1
};

enum UnitLoadState {
        UNIT_STUB,
        UNIT_LOADED,
        UNIT_FAILED,
        UNIT_MERGED,
        _UNIT_LOAD_STATE_MAX,
        _UNIT_LOAD_STATE_INVALID = -1
};

enum UnitActiveState {
        UNIT_ACTIVE,
        UNIT_ACTIVE_RELOADING,
        UNIT_INACTIVE,
        UNIT_ACTIVATING,
        UNIT_DEACTIVATING,
        _UNIT_ACTIVE_STATE_MAX,
        _UNIT_ACTIVE_STATE_INVALID = -1
};

static inline bool UNIT_IS_ACTIVE_OR_RELOADING(UnitActiveState t) {
        return t == UNIT_ACTIVE || t == UNIT_ACTIVE_RELOADING;
}

static inline bool UNIT_IS_ACTIVE_OR_ACTIVATING(UnitActiveState t) {
        return t == UNIT_ACTIVE || t == UNIT_ACTIVATING || t == UNIT_ACTIVE_RELOADING;
}

static inline bool UNIT_IS_INACTIVE_OR_DEACTIVATING(UnitActiveState t) {
        return t == UNIT_INACTIVE || t == UNIT_DEACTIVATING;
}

enum UnitDependency {
        /* Positive dependencies */
        UNIT_REQUIRES,
        UNIT_REQUIRES_OVERRIDABLE,
        UNIT_REQUISITE,
        UNIT_REQUISITE_OVERRIDABLE,
        UNIT_WANTS,

        /* Inverse of the above */
        UNIT_REQUIRED_BY,             /* inverse of 'requires' and 'requisite' is 'required_by' */
        UNIT_REQUIRED_BY_OVERRIDABLE, /* inverse of 'soft_requires' and 'soft_requisite' is 'soft_required_by' */
        UNIT_WANTED_BY,               /* inverse of 'wants' */

        /* Negative dependencies */
        UNIT_CONFLICTS,               /* inverse of 'conflicts' is 'conflicts' */

        /* Order */
        UNIT_BEFORE,                  /* inverse of 'before' is 'after' and vice versa */
        UNIT_AFTER,

        /* Reference information for GC logic */
        UNIT_REFERENCES,              /* Inverse of 'references' is 'referenced_by' */
        UNIT_REFERENCED_BY,

        _UNIT_DEPENDENCY_MAX,
        _UNIT_DEPENDENCY_INVALID = -1
};

#include "manager.h"
#include "job.h"
#include "cgroup.h"

struct Meta {
        Manager *manager;

        UnitType type;
        UnitLoadState load_state;
        Unit *merged_into;

        /* Refuse manual starting, allow starting only indirectly via dependency. */
        bool only_by_dependency;

        char *id; /* One name is special because we use it for identification. Points to an entry in the names set */
        char *instance;

        Set *names;
        Set *dependencies[_UNIT_DEPENDENCY_MAX];

        char *description;
        char *fragment_path; /* if loaded from a config file this is the primary path to it */

        /* If there is something to do with this unit, then this is
         * the job for it */
        Job *job;

        timestamp inactive_exit_timestamp;
        timestamp active_enter_timestamp;
        timestamp active_exit_timestamp;
        timestamp inactive_enter_timestamp;

        /* Counterparts in the cgroup filesystem */
        CGroupBonding *cgroup_bondings;

        /* Per type list */
        LIST_FIELDS(Meta, units_per_type);

        /* Load queue */
        LIST_FIELDS(Meta, load_queue);

        /* D-Bus queue */
        LIST_FIELDS(Meta, dbus_queue);

        /* Cleanup queue */
        LIST_FIELDS(Meta, cleanup_queue);

        /* GC queue */
        LIST_FIELDS(Meta, gc_queue);

        /* Used during GC sweeps */
        unsigned gc_marker;

        /* If we go down, pull down everything that depends on us, too */
        bool recursive_stop;

        /* Garbage collect us we nobody wants or requires us anymore */
        bool stop_when_unneeded;

        /* When deserializing, temporarily store the job type for this
         * unit here, if there was a job scheduled */
        int deserialized_job; /* This is actually of type JobType */

        bool in_load_queue:1;
        bool in_dbus_queue:1;
        bool in_cleanup_queue:1;
        bool in_gc_queue:1;

        bool sent_dbus_new_signal:1;
};

#include "service.h"
#include "timer.h"
#include "socket.h"
#include "target.h"
#include "device.h"
#include "mount.h"
#include "automount.h"
#include "snapshot.h"
#include "swap.h"
#include "path.h"

union Unit {
        Meta meta;
        Service service;
        Timer timer;
        Socket socket;
        Target target;
        Device device;
        Mount mount;
        Automount automount;
        Snapshot snapshot;
        Swap swap;
        Path path;
};

struct UnitVTable {
        const char *suffix;

        /* This should reset all type-specific variables. This should
         * not allocate memory, and is called with zero-initialized
         * data. It should hence only initialize variables that need
         * to be set != 0. */
        void (*init)(Unit *u);

        /* This should free all type-specific variables. It should be
         * idempotent. */
        void (*done)(Unit *u);

        /* Actually load data from disk. This may fail, and should set
         * load_state to UNIT_LOADED, UNIT_MERGED or leave it at
         * UNIT_STUB if no configuration could be found. */
        int (*load)(Unit *u);

        /* If a a lot of units got created via enumerate(), this is
         * where to actually set the state and call unit_notify(). */
        int (*coldplug)(Unit *u);

        void (*dump)(Unit *u, FILE *f, const char *prefix);

        int (*start)(Unit *u);
        int (*stop)(Unit *u);
        int (*reload)(Unit *u);

        bool (*can_reload)(Unit *u);

        /* Write all data that cannot be restored from other sources
         * away using unit_serialize_item() */
        int (*serialize)(Unit *u, FILE *f, FDSet *fds);

        /* Restore one item from the serialization */
        int (*deserialize_item)(Unit *u, const char *key, const char *data, FDSet *fds);

        /* Boils down the more complex internal state of this unit to
         * a simpler one that the engine can understand */
        UnitActiveState (*active_state)(Unit *u);

        /* Returns the substate specific to this unit type as
         * string. This is purely information so that we can give the
         * user a more finegrained explanation in which actual state a
         * unit is in. */
        const char* (*sub_state_to_string)(Unit *u);

        /* Return true when there is reason to keep this entry around
         * even nothing references it and it isn't active in any
         * way */
        bool (*check_gc)(Unit *u);

        /* Return true when this unit is suitable for snapshotting */
        bool (*check_snapshot)(Unit *u);

        void (*fd_event)(Unit *u, int fd, uint32_t events, Watch *w);
        void (*sigchld_event)(Unit *u, pid_t pid, int code, int status);
        void (*timer_event)(Unit *u, uint64_t n_elapsed, Watch *w);

        /* Called whenever any of the cgroups this unit watches for
         * ran empty */
        void (*cgroup_notify_empty)(Unit *u);

        /* Called whenever a process of this unit sends us a message */
        void (*notify_message)(Unit *u, pid_t pid, char **tags);

        /* Called whenever a name thus Unit registered for comes or
         * goes away. */
        void (*bus_name_owner_change)(Unit *u, const char *name, const char *old_owner, const char *new_owner);

        /* Called whenever a bus PID lookup finishes */
        void (*bus_query_pid_done)(Unit *u, const char *name, pid_t pid);

        /* Called for each message received on the bus */
        DBusHandlerResult (*bus_message_handler)(Unit *u, DBusMessage *message);

        /* This is called for each unit type and should be used to
         * enumerate existing devices and load them. However,
         * everything that is loaded here should still stay in
         * inactive state. It is the job of the coldplug() call above
         * to put the units into the initial state.  */
        int (*enumerate)(Manager *m);

        /* Type specific cleanups. */
        void (*shutdown)(Manager *m);

        /* Can units of this type have multiple names? */
        bool no_alias:1;

        /* If true units of this types can never have "Requires"
         * dependencies, because state changes can only be observed,
         * not triggered */
        bool no_requires:1;

        /* Instances make no sense for this type */
        bool no_instances:1;

        /* Exclude this type from snapshots */
        bool no_snapshots:1;

        /* Exclude from automatic gc */
        bool no_gc:1;

        /* Exclude from isolation requests */
        bool no_isolate:1;
};

extern const UnitVTable * const unit_vtable[_UNIT_TYPE_MAX];

#define UNIT_VTABLE(u) unit_vtable[(u)->meta.type]

/* For casting a unit into the various unit types */
#define DEFINE_CAST(UPPERCASE, MixedCase)                               \
        static inline MixedCase* UPPERCASE(Unit *u) {                   \
                if (!u || u->meta.type != UNIT_##UPPERCASE)             \
                        return NULL;                                    \
                                                                        \
                return (MixedCase*) u;                                  \
        }

/* For casting the various unit types into a unit */
#define UNIT(u) ((Unit*) (u))

DEFINE_CAST(SOCKET, Socket);
DEFINE_CAST(TIMER, Timer);
DEFINE_CAST(SERVICE, Service);
DEFINE_CAST(TARGET, Target);
DEFINE_CAST(DEVICE, Device);
DEFINE_CAST(MOUNT, Mount);
DEFINE_CAST(AUTOMOUNT, Automount);
DEFINE_CAST(SNAPSHOT, Snapshot);
DEFINE_CAST(SWAP, Swap);
DEFINE_CAST(PATH, Path);

Unit *unit_new(Manager *m);
void unit_free(Unit *u);

int unit_add_name(Unit *u, const char *name);

int unit_add_dependency(Unit *u, UnitDependency d, Unit *other, bool add_reference);
int unit_add_dependency_by_name(Unit *u, UnitDependency d, const char *name, const char *filename, bool add_reference);
int unit_add_dependency_by_name_inverse(Unit *u, UnitDependency d, const char *name, const char *filename, bool add_reference);

int unit_add_exec_dependencies(Unit *u, ExecContext *c);

int unit_add_cgroup(Unit *u, CGroupBonding *b);
int unit_add_cgroup_from_text(Unit *u, const char *name);
int unit_add_default_cgroup(Unit *u);
CGroupBonding* unit_get_default_cgroup(Unit *u);

int unit_choose_id(Unit *u, const char *name);
int unit_set_description(Unit *u, const char *description);

bool unit_check_gc(Unit *u);

void unit_add_to_load_queue(Unit *u);
void unit_add_to_dbus_queue(Unit *u);
void unit_add_to_cleanup_queue(Unit *u);
void unit_add_to_gc_queue(Unit *u);

int unit_merge(Unit *u, Unit *other);
int unit_merge_by_name(Unit *u, const char *other);

Unit *unit_follow_merge(Unit *u);

int unit_load_fragment_and_dropin(Unit *u);
int unit_load_fragment_and_dropin_optional(Unit *u);
int unit_load_nop(Unit *u);
int unit_load(Unit *unit);

const char *unit_description(Unit *u);

bool unit_has_name(Unit *u, const char *name);

UnitActiveState unit_active_state(Unit *u);

const char* unit_sub_state_to_string(Unit *u);

void unit_dump(Unit *u, FILE *f, const char *prefix);

bool unit_can_reload(Unit *u);
bool unit_can_start(Unit *u);

int unit_start(Unit *u);
int unit_stop(Unit *u);
int unit_reload(Unit *u);

void unit_notify(Unit *u, UnitActiveState os, UnitActiveState ns);

int unit_watch_fd(Unit *u, int fd, uint32_t events, Watch *w);
void unit_unwatch_fd(Unit *u, Watch *w);

int unit_watch_pid(Unit *u, pid_t pid);
void unit_unwatch_pid(Unit *u, pid_t pid);

int unit_watch_timer(Unit *u, usec_t delay, Watch *w);
void unit_unwatch_timer(Unit *u, Watch *w);

int unit_watch_bus_name(Unit *u, const char *name);
void unit_unwatch_bus_name(Unit *u, const char *name);

bool unit_job_is_applicable(Unit *u, JobType j);

int set_unit_path(const char *p);

char *unit_dbus_path(Unit *u);

int unit_load_related_unit(Unit *u, const char *type, Unit **_found);
int unit_get_related_unit(Unit *u, const char *type, Unit **_found);

char *unit_name_printf(Unit *u, const char* text);
char *unit_full_printf(Unit *u, const char *text);
char **unit_full_printf_strv(Unit *u, char **l);

bool unit_can_serialize(Unit *u);
int unit_serialize(Unit *u, FILE *f, FDSet *fds);
void unit_serialize_item_format(Unit *u, FILE *f, const char *key, const char *value, ...) _printf_attr_(4,5);
void unit_serialize_item(Unit *u, FILE *f, const char *key, const char *value);
int unit_deserialize(Unit *u, FILE *f, FDSet *fds);

int unit_add_node_link(Unit *u, const char *what, bool wants);

int unit_coldplug(Unit *u);

const char *unit_type_to_string(UnitType i);
UnitType unit_type_from_string(const char *s);

const char *unit_load_state_to_string(UnitLoadState i);
UnitLoadState unit_load_state_from_string(const char *s);

const char *unit_active_state_to_string(UnitActiveState i);
UnitActiveState unit_active_state_from_string(const char *s);

const char *unit_dependency_to_string(UnitDependency i);
UnitDependency unit_dependency_from_string(const char *s);

const char *kill_mode_to_string(KillMode k);
KillMode kill_mode_from_string(const char *s);

#endif
