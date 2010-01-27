/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foounithfoo
#define foounithfoo

#include <stdbool.h>
#include <stdlib.h>

typedef union Unit Unit;
typedef struct Meta Meta;
typedef struct UnitVTable UnitVTable;
typedef enum UnitType UnitType;
typedef enum UnitLoadState UnitLoadState;
typedef enum UnitActiveState UnitActiveState;
typedef enum UnitDependency UnitDependency;

#include "job.h"
#include "manager.h"
#include "set.h"
#include "util.h"
#include "list.h"
#include "socket-util.h"
#include "execute.h"
#include "util.h"

#define UNIT_NAME_MAX 32
#define DEFAULT_TIMEOUT_USEC (20*USEC_PER_SEC)
#define DEFAULT_RESTART_USEC (100*USEC_PER_MSEC)

enum UnitType {
        UNIT_SERVICE = 0,
        UNIT_TIMER,
        UNIT_SOCKET,
        UNIT_TARGET,
        UNIT_DEVICE,
        UNIT_MOUNT,
        UNIT_AUTOMOUNT,
        UNIT_SNAPSHOT,
        _UNIT_TYPE_MAX,
        _UNIT_TYPE_INVALID = -1,
};

enum UnitLoadState {
        UNIT_STUB,
        UNIT_LOADED,
        UNIT_FAILED,
        _UNIT_LOAD_STATE_MAX
};

enum UnitActiveState {
        UNIT_ACTIVE,
        UNIT_ACTIVE_RELOADING,
        UNIT_INACTIVE,
        UNIT_ACTIVATING,
        UNIT_DEACTIVATING,
        _UNIT_ACTIVE_STATE_MAX
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
        UNIT_SOFT_REQUIRES,
        UNIT_WANTS,
        UNIT_REQUISITE,
        UNIT_SOFT_REQUISITE,

        /* Inverse of the above */
        UNIT_REQUIRED_BY,       /* inverse of 'requires' and 'requisite' is 'required_by' */
        UNIT_SOFT_REQUIRED_BY,  /* inverse of 'soft_requires' and 'soft_requisite' is 'soft_required_by' */
        UNIT_WANTED_BY,         /* inverse of 'wants' */

        /* Negative dependencies */
        UNIT_CONFLICTS,         /* inverse of 'conflicts' is 'conflicts' */

        /* Order */
        UNIT_BEFORE,            /* inverse of before is after and vice versa */
        UNIT_AFTER,

        _UNIT_DEPENDENCY_MAX,
        _UNIT_DEPENDENCY_INVALID = -1
};

struct Meta {
        Manager *manager;
        UnitType type;
        UnitLoadState load_state;

        char *id; /* One name is special because we use it for identification. Points to an entry in the names set */

        Set *names;
        Set *dependencies[_UNIT_DEPENDENCY_MAX];

        char *description;
        char *load_path; /* if loaded from a config file this is the primary path to it */

        /* If there is something to do with this unit, then this is
         * the job for it */
        Job *job;

        bool in_load_queue:1;

        usec_t active_enter_timestamp;
        usec_t active_exit_timestamp;

        /* Load queue */
        LIST_FIELDS(Meta, load_queue);
};

#include "service.h"
#include "timer.h"
#include "socket.h"
#include "target.h"
#include "device.h"
#include "mount.h"
#include "automount.h"
#include "snapshot.h"

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
};

struct UnitVTable {
        const char *suffix;

        int (*init)(Unit *u);
        void (*done)(Unit *u);

        void (*dump)(Unit *u, FILE *f, const char *prefix);

        int (*start)(Unit *u);
        int (*stop)(Unit *u);
        int (*reload)(Unit *u);

        bool (*can_reload)(Unit *u);

        /* Boils down the more complex internal state of this unit to
         * a simpler one that the engine can understand */
        UnitActiveState (*active_state)(Unit *u);

        void (*fd_event)(Unit *u, int fd, uint32_t events, Watch *w);
        void (*sigchld_event)(Unit *u, pid_t pid, int code, int status);
        void (*timer_event)(Unit *u, uint64_t n_elapsed, Watch *w);
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

UnitType unit_name_to_type(const char *n);
bool unit_name_is_valid(const char *n);
char *unit_name_change_suffix(const char *n, const char *suffix);

Unit *unit_new(Manager *m);
void unit_free(Unit *u);

int unit_add_name(Unit *u, const char *name);
int unit_add_dependency(Unit *u, UnitDependency d, Unit *other);

void unit_add_to_load_queue(Unit *u);

int unit_merge(Unit *u, Unit *other);

int unit_load_fragment_and_dropin(Unit *u);
int unit_load(Unit *unit);

const char* unit_id(Unit *u);
const char *unit_description(Unit *u);

UnitActiveState unit_active_state(Unit *u);

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

bool unit_job_is_applicable(Unit *u, JobType j);

const char *unit_path(void);
int set_unit_path(const char *p);


#endif
