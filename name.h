/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foonamehfoo
#define foonamehfoo

#include <stdbool.h>
#include <stdlib.h>

typedef union Name Name;
typedef struct Meta Meta;
typedef struct Service Service;
typedef struct Timer Timer;
typedef struct Socket Socket;
typedef struct Milestone Milestone;
typedef struct Device Device;
typedef struct Mount Mount;
typedef struct Automount Automount;
typedef struct Snapshot Snapshot;

#include "job.h"
#include "manager.h"
#include "set.h"
#include "util.h"
#include "list.h"

typedef enum NameType {
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
} NameType;

typedef enum NameState {
        NAME_STUB,
        NAME_LOADED,
        NAME_FAILED
} NameState;

typedef enum NameDependency {
        /* Positive dependencies */
        NAME_REQUIRES,
        NAME_SOFT_REQUIRES,
        NAME_WANTS,
        NAME_REQUISITE,
        NAME_SOFT_REQUISITE,
        NAME_REQUIRED_BY,   /* inverse of 'requires' and 'requisite' is 'required_by' */
        NAME_WANTED_BY,     /* inverse of 'wants', 'soft_requires' and 'soft_requisite' is 'wanted_by' */

        /* Negative dependencies */
        NAME_CONFLICTS,     /* inverse of 'conflicts' is 'conflicts' */

        /* Order */
        NAME_BEFORE,        /* inverse of before is after and vice versa */
        NAME_AFTER,
        _NAME_DEPENDENCY_MAX
} NameDependency;

struct Meta {
        Manager *manager;
        NameType type;
        NameState state;

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

typedef enum ServiceState {
        SERVICE_DEAD,
        SERVICE_BEFORE,
        SERVICE_START_PRE,
        SERVICE_START,
        SERVICE_START_POST,
        SERVICE_RUNNING,
        SERVICE_RELOAD_PRE,
        SERVICE_RELOAD,
        SERVICE_RELOAD_POST,
        SERVICE_STOP_PRE,
        SERVICE_STOP,
        SERVICE_SIGTERM,
        SERVICE_SIGKILL,
        SERVICE_STOP_POST,
        SERVICE_HOLDOFF,
        SERVICE_MAINTAINANCE
} ServiceState;

typedef enum ServiceMode {
        SERVICE_ONCE,
        SERVICE_RESTART
} ServiceMode;

struct Service {
        Meta meta;

        ServiceState state;
        ServiceMode mode;
};

typedef enum TimerState {
        TIMER_DEAD,
        TIMER_BEFORE,
        TIMER_START_PRE,
        TIMER_START,
        TIMER_START_POST,
        TIMER_WAITING,
        TIMER_RUNNING,
        TIMER_STOP_PRE,
        TIMER_STOP,
        TIMER_STOP_POST,
        TIMER_MAINTAINANCE
} TimerState;

struct Timer {
        Meta meta;

        TimerState state;
        Service *subject;

        clockid_t clock_id;
        usec_t next_elapse;
};

typedef enum SocketState {
        SOCKET_DEAD,
        SOCKET_BEFORE,
        SOCKET_START_PRE,
        SOCKET_START,
        SOCKET_START_POST,
        SOCKET_LISTENING,
        SOCKET_RUNNING,
        SOCKET_STOP_PRE,
        SOCKET_STOP,
        SOCKET_STOP_POST,
        SOCKET_MAINTAINANCE
} SocketState;

struct Socket {
        Meta meta;

        SocketState state;
        int *fds;
        unsigned n_fds;

        Service *subject;
};

typedef enum MilestoneState {
        MILESTONE_DEAD,
        MILESTONE_BEFORE,
        MILESTONE_ACTIVE
} MilestoneState;

struct Milestone {
        Meta meta;

        MilestoneState state;
};

typedef enum DeviceState {
        DEVICE_DEAD,
        DEVICE_BEFORE,
        DEVICE_AVAILABLE
} DeviceState;

struct Device {
        Meta meta;

        DeviceState state;
        char *sysfs;
};

typedef enum MountState {
        MOUNT_DEAD,
        MOUNT_BEFORE,
        MOUNT_MOUNTED
} MountState;

struct Mount {
        Meta meta;

        MountState state;
        char *path;
};

typedef enum AutomountState {
        AUTOMOUNT_DEAD,
        AUTOMOUNT_BEFORE,
        AUTOMOUNT_START_PRE,
        AUTOMOUNT_START,
        AUTOMOUNT_START_POST,
        AUTOMOUNT_WAITING,
        AUTOMOUNT_RUNNING,
        AUTOMOUNT_STOP_PRE,
        AUTOMOUNT_STOP,
        AUTOMOUNT_STOP_POST,
        AUTOMOUNT_MAINTAINANCE
} AutomountState;

struct Automount {
        Meta meta;

        AutomountState state;
        char *path;
        Mount *subject;
};

typedef enum SnapshotState {
        SNAPSHOT_DEAD,
        SNAPSHOT_BEFORE,
        SNAPSHOT_ACTIVE
} SnapshotState;

struct Snapshot {
        Meta meta;

        SnapshotState state;
        bool cleanup:1;
};

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

/* For casting a name into the various name types */

#define DEFINE_CAST(UPPERCASE, MixedCase, lowercase)                    \
        static inline MixedCase* UPPERCASE(Name *name) {                \
                if (name->meta.type != NAME_##UPPERCASE)                \
                        return NULL;                                    \
                                                                        \
                return &name->lowercase;                                \
        }

DEFINE_CAST(SERVICE, Service, service);
DEFINE_CAST(TIMER, Timer, timer);
DEFINE_CAST(SOCKET, Socket, socket);
DEFINE_CAST(MILESTONE, Milestone, milestone);
DEFINE_CAST(DEVICE, Device, device);
DEFINE_CAST(MOUNT, Mount, mount);
DEFINE_CAST(AUTOMOUNT, Automount, automount);
DEFINE_CAST(SNAPSHOT, Snapshot, snapshot);

/* For casting the various name types into a name */
#define NAME(o) ((Name*) (o))

bool name_is_ready(Name *name);
NameType name_type_from_string(const char *n);
bool name_is_valid(const char *n);

Name *name_new(Manager *m);
void name_free(Name *name);
int name_link(Name *name);
int name_merge(Name *name, Name *other);
int name_augment(Name *n);

#endif
