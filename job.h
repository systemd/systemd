/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foojobhfoo
#define foojobhfoo

#include <stdbool.h>
#include <inttypes.h>

typedef struct Job Job;
typedef enum JobType JobType;
typedef enum JobMode JobMode;

#include "manager.h"
#include "name.h"
#include "hashmap.h"
#include "list.h"

enum JobType {
        JOB_START,
        JOB_STOP,
        JOB_VERIFY_STARTED,
        JOB_RELOAD,
        JOB_RESTART,
        JOB_TRY_RESTART, /* restart if running */
        JOB_RESTART_FINISH, /* 2nd part of a restart, i.e. the actual starting */
        _JOB_TYPE_MAX
};

typedef enum JobState {
        JOB_WAITING,
        JOB_RUNNING,
        JOB_DONE,
        _JOB_STATE_MAX
} JobState;

enum JobMode {
        JOB_FAIL,
        JOB_REPLACE,
        _JOB_MODE_MAX
};

struct Job {
        Manager *manager;
        uint32_t id;

        JobType type;
        JobState state;
        Name *name;

        bool linked:1;
};

Job* job_new(Manager *m, JobType type, Name *name);
int job_link(Job *job);
void job_free(Job *job);
void job_dump(Job *j, FILE*f);

#endif
