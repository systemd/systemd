/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foomanagerhfoo
#define foomanagerhfoo

#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>

typedef struct Manager Manager;
typedef enum WatchType WatchType;
typedef struct Watch Watch;

enum WatchType {
        WATCH_INVALID,
        WATCH_SIGNAL_FD,
        WATCH_FD,
        WATCH_TIMER
};

struct Watch {
        int fd;
        WatchType type;
        union Unit *unit;
};

#include "unit.h"
#include "job.h"
#include "hashmap.h"
#include "list.h"
#include "set.h"

#define SPECIAL_DEFAULT_TARGET "default.target"
#define SPECIAL_SYSLOG_SERVICE "syslog.service"
#define SPECIAL_DBUS_SERVICE "messagebus.service"
#define SPECIAL_LOGGER_SOCKET "systemd-logger.socket"
#define SPECIAL_KBREQUEST_TARGET "kbrequest.target"
#define SPECIAL_CTRL_ALT_DEL_TARGET "ctrl-alt-del.target"

struct Manager {
        uint32_t current_job_id;

        /* Note that the set of units we know of is allowed to be
         * incosistent. However the subset of it that is loaded may
         * not, and the list of jobs may neither. */

        /* Active jobs and units */
        Hashmap *units;  /* name string => Unit object n:1 */
        Hashmap *jobs;   /* job id => Job object 1:1 */

        /* Units that need to be loaded */
        LIST_HEAD(Meta, load_queue); /* this is actually more a stack than a queue, but uh. */

        /* Jobs that need to be run */
        LIST_HEAD(Job, run_queue);   /* more a stack than a queue, too */

        /* Jobs to be added */
        Hashmap *transaction_jobs;      /* Unit object => Job object list 1:1 */
        JobDependency *transaction_anchor;

        bool dispatching_load_queue:1;
        bool dispatching_run_queue:1;

        Hashmap *watch_pids;  /* pid => Unit object n:1 */

        int epoll_fd;

        Watch signal_watch;

        struct udev* udev;
};

Manager* manager_new(void);
void manager_free(Manager *m);

int manager_coldplug(Manager *m);

Job *manager_get_job(Manager *m, uint32_t id);
Unit *manager_get_unit(Manager *m, const char *name);

int manager_load_unit(Manager *m, const char *path_or_name, Unit **_ret);
int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, bool force, Job **_ret);

void manager_dump_units(Manager *s, FILE *f, const char *prefix);
void manager_dump_jobs(Manager *s, FILE *f, const char *prefix);

void manager_transaction_unlink_job(Manager *m, Job *j);

void manager_clear_jobs(Manager *m);

void manager_dispatch_load_queue(Manager *m);
void manager_dispatch_run_queue(Manager *m);

int manager_loop(Manager *m);

#endif
