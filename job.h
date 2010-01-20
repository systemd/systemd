/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foojobhfoo
#define foojobhfoo

#include <stdbool.h>
#include <inttypes.h>

typedef struct Job Job;
typedef struct JobDependency JobDependency;
typedef enum JobType JobType;
typedef enum JobMode JobMode;
typedef enum JobState JobState;

#include "manager.h"
#include "name.h"
#include "hashmap.h"
#include "list.h"

enum JobType {
        JOB_START,
        JOB_STOP,
        JOB_VERIFY_STARTED,
        JOB_RELOAD,          /* reload if running */
        JOB_RELOAD_OR_START, /* reload if running, start if not running */
        JOB_RESTART,         /* stop if running, then start unconditionally */
        JOB_TRY_RESTART,     /* stop and start if running */
        _JOB_TYPE_MAX,
        _JOB_TYPE_INVALID = -1
};

enum JobState {
        JOB_WAITING,
        JOB_RUNNING,
        JOB_DONE,
        _JOB_STATE_MAX
};

enum JobMode {
        JOB_FAIL,
        JOB_REPLACE,
        _JOB_MODE_MAX
};

struct JobDependency {
        /* Encodes that the 'subject' job needs the 'object' job in
         * some way. This structure is used only while building a transaction. */
        Job *subject;
        Job *object;

        bool matters;

        /* Linked list for the subjects, resp objects */
        JobDependency *subject_prev, *subject_next;
        JobDependency *object_prev, *object_next;
};

struct Job {
        Manager *manager;
        uint32_t id;

        Name *name;

        JobType type;
        JobState state;

        bool linked:1;
        bool matters_to_anchor:1;

        /* These fields are used only while building a transaction */
        Job *transaction_next, *transaction_prev;

        JobDependency *subject_list;
        JobDependency *object_list;

        /* used for graph algs as a "I have been here" marker */
        Job* marker;
        unsigned generation;
};

Job* job_new(Manager *m, JobType type, Name *name);
void job_free(Job *job);
void job_dump(Job *j, FILE*f);

JobDependency* job_dependency_new(Job *subject, Job *object, bool matters);
void job_dependency_free(JobDependency *l);
void job_dependency_delete(Job *subject, Job *object, bool *matters);

bool job_is_anchor(Job *j);

int job_merge(Job *j, Job *other);

#endif
