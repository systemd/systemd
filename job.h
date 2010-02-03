/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foojobhfoo
#define foojobhfoo

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
#include <inttypes.h>

typedef struct Job Job;
typedef struct JobDependency JobDependency;
typedef enum JobType JobType;
typedef enum JobState JobState;
typedef enum JobMode JobMode;

#include "manager.h"
#include "unit.h"
#include "hashmap.h"
#include "list.h"

enum JobType {
        JOB_START,                  /* if a unit does not support being started, we'll just wait until it becomes active */
        JOB_VERIFY_ACTIVE,

        JOB_STOP,

        JOB_RELOAD,                 /* if running reload */
        JOB_RELOAD_OR_START,        /* if running reload, if not running start */

        /* Note that restarts are first treated like JOB_STOP, but
         * then instead of finishing are patched to become
         * JOB_START. */
        JOB_RESTART,                /* if running stop, then start unconditionally */
        JOB_TRY_RESTART,            /* if running stop and then start */

        _JOB_TYPE_MAX,
        _JOB_TYPE_INVALID = -1
};

enum JobState {
        JOB_WAITING,
        JOB_RUNNING,
        _JOB_STATE_MAX,
        _JOB_STATE_INVALID = -1
};

enum JobMode {
        JOB_FAIL,
        JOB_REPLACE,
        _JOB_MODE_MAX,
        _JOB_MODE_INVALID = -1
};

struct JobDependency {
        /* Encodes that the 'subject' job needs the 'object' job in
         * some way. This structure is used only while building a transaction. */
        Job *subject;
        Job *object;

        bool matters;

        LIST_FIELDS(JobDependency, subject);
        LIST_FIELDS(JobDependency, object);
};

struct Job {
        Manager *manager;
        uint32_t id;

        Unit *unit;

        JobType type;
        JobState state;

        bool installed:1;
        bool in_run_queue:1;
        bool matters_to_anchor:1;
        bool forced:1;

        LIST_FIELDS(Job, transaction);
        LIST_FIELDS(Job, run_queue);

        LIST_HEAD(JobDependency, subject_list);
        LIST_HEAD(JobDependency, object_list);

        /* Used for graph algs as a "I have been here" marker */
        Job* marker;
        unsigned generation;

};

Job* job_new(Manager *m, JobType type, Unit *unit);
void job_free(Job *job);
void job_dump(Job *j, FILE*f, const char *prefix);

JobDependency* job_dependency_new(Job *subject, Job *object, bool matters);
void job_dependency_free(JobDependency *l);
void job_dependency_delete(Job *subject, Job *object, bool *matters);

bool job_is_anchor(Job *j);

int job_merge(Job *j, Job *other);

int job_type_merge(JobType *a, JobType b);
bool job_type_is_mergeable(JobType a, JobType b);
bool job_type_is_superset(JobType a, JobType b);
bool job_type_is_conflicting(JobType a, JobType b);

bool job_is_runnable(Job *j);

void job_schedule_run(Job *j);
int job_run_and_invalidate(Job *j);
int job_finish_and_invalidate(Job *j, bool success);

const char* job_type_to_string(JobType t);
JobType job_type_from_string(const char *s);

const char* job_state_to_string(JobState t);
JobState job_state_from_string(const char *s);

const char* job_mode_to_string(JobMode t);
JobMode job_mode_from_string(const char *s);

char *job_dbus_path(Job *j);

#endif
