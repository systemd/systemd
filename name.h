/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foonamehfoo
#define foonamehfoo

#include <stdbool.h>
#include <stdlib.h>

typedef union Name Name;
typedef struct Meta Meta;
typedef struct NameVTable NameVTable;
typedef enum NameType NameType;
typedef enum NameLoadState NameLoadState;
typedef enum NameActiveState NameActiveState;
typedef enum NameDependency NameDependency;

#include "job.h"
#include "manager.h"
#include "set.h"
#include "util.h"
#include "list.h"
#include "socket-util.h"
#include "execute.h"

#define NAME_MAX 32

enum NameType {
        NAME_SERVICE = 0,
        NAME_TIMER,
        NAME_SOCKET,
        NAME_MILESTONE,
        NAME_DEVICE,
        NAME_MOUNT,
        NAME_AUTOMOUNT,
        NAME_SNAPSHOT,
        _NAME_TYPE_MAX,
        _NAME_TYPE_INVALID = -1,
};

enum NameLoadState {
        NAME_STUB,
        NAME_LOADED,
        NAME_FAILED,
        _NAME_LOAD_STATE_MAX
};

enum NameActiveState {
        NAME_ACTIVE,
        NAME_ACTIVE_RELOADING,
        NAME_INACTIVE,
        NAME_ACTIVATING,
        NAME_DEACTIVATING,
        _NAME_ACTIVE_STATE_MAX
};

static inline bool NAME_IS_ACTIVE_OR_RELOADING(NameActiveState t) {
        return t == NAME_ACTIVE || t == NAME_ACTIVE_RELOADING;
}

static inline bool NAME_IS_ACTIVE_OR_ACTIVATING(NameActiveState t) {
        return t == NAME_ACTIVE || t == NAME_ACTIVATING || t == NAME_ACTIVE_RELOADING;
}

static inline bool NAME_IS_INACTIVE_OR_DEACTIVATING(NameActiveState t) {
        return t == NAME_INACTIVE || t == NAME_DEACTIVATING;
}

enum NameDependency {
        /* Positive dependencies */
        NAME_REQUIRES,
        NAME_SOFT_REQUIRES,
        NAME_WANTS,
        NAME_REQUISITE,
        NAME_SOFT_REQUISITE,
        NAME_REQUIRED_BY,       /* inverse of 'requires' and 'requisite' is 'required_by' */
        NAME_SOFT_REQUIRED_BY,  /* inverse of 'soft_requires' and 'soft_requisite' is 'soft_required_by' */
        NAME_WANTED_BY,         /* inverse of 'wants' */

        /* Negative dependencies */
        NAME_CONFLICTS,         /* inverse of 'conflicts' is 'conflicts' */

        /* Order */
        NAME_BEFORE,            /* inverse of before is after and vice versa */
        NAME_AFTER,
        _NAME_DEPENDENCY_MAX
};

struct Meta {
        Manager *manager;
        NameType type;
        NameLoadState load_state;

        Set *names;
        Set *dependencies[_NAME_DEPENDENCY_MAX];

        char *description;

        /* If there is something to do with this name, then this is
         * the job for it */
        Job *job;

        bool linked:1;

        /* Load queue */
        LIST_FIELDS(Meta);
};

#include "service.h"
#include "timer.h"
#include "socket.h"
#include "milestone.h"
#include "device.h"
#include "mount.h"
#include "automount.h"
#include "snapshot.h"

union Name {
        Meta meta;
        Service service;
        Timer timer;
        Socket socket;
        Milestone milestone;
        Device device;
        Mount mount;
        Automount automount;
        Snapshot snapshot;
};

struct NameVTable {
        const char *suffix;

        int (*load)(Name *n);
        void (*dump)(Name *n, FILE *f, const char *prefix);

        int (*start)(Name *n);
        int (*stop)(Name *n);
        int (*reload)(Name *n);

        /* Boils down the more complex internal state of this name to
         * a simpler one that the engine can understand */
        NameActiveState (*active_state)(Name *n);

        void (*free_hook)(Name *n);
};

/* For casting a name into the various name types */
#define DEFINE_CAST(UPPERCASE, MixedCase)                               \
        static inline MixedCase* UPPERCASE(Name *name) {                \
                if (!name || name->meta.type != NAME_##UPPERCASE)       \
                        return NULL;                                    \
                                                                        \
                return (MixedCase*) name;                               \
        }

/* For casting the various name types into a name */
#define NAME(o) ((Name*) (o))

DEFINE_CAST(SOCKET, Socket);
DEFINE_CAST(TIMER, Timer);
DEFINE_CAST(SERVICE, Service);
DEFINE_CAST(MILESTONE, Milestone);
DEFINE_CAST(DEVICE, Device);
DEFINE_CAST(MOUNT, Mount);
DEFINE_CAST(AUTOMOUNT, Automount);
DEFINE_CAST(SNAPSHOT, Snapshot);

NameActiveState name_active_state(Name *name);

bool name_type_can_start(NameType t);
bool name_type_can_reload(NameType t);

NameType name_type_from_string(const char *n);
bool name_is_valid(const char *n);

Name *name_new(Manager *m);
void name_free(Name *name);
int name_link(Name *name);
int name_link_names(Name *name, bool replace);
int name_merge(Name *name, Name *other);
int name_sanitize(Name *n);
int name_load_fragment_and_dropin(Name *n);
int name_load(Name *name);
const char* name_id(Name *n);
const char *name_description(Name *n);

void name_dump(Name *n, FILE *f, const char *prefix);

int name_start(Name *n);
int name_stop(Name *n);
int name_reload(Name *n);

void name_notify(Name *n, NameActiveState os, NameActiveState ns);

#endif
