/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>

#include "macro.h"
#include "job.h"

Job* job_new(Manager *m, JobType type, Name *name) {
        Job *j;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(name);

        if (!(j = new0(Job, 1)))
                return NULL;

        j->manager = m;
        j->id = m->current_job_id++;
        j->type = type;
        j->name = name;

        /* We don't link it here, that's what job_link() is for */

        return j;
}

void job_free(Job *j) {
        assert(j);

        /* Detach from next 'bigger' objects */

        if (j->linked) {
                if (j->name->meta.job == j)
                        j->name->meta.job = NULL;

                hashmap_remove(j->manager->jobs, UINT32_TO_PTR(j->id));
        }

        hashmap_remove(j->manager->jobs_to_add, j->name);
        set_remove(j->manager->jobs_to_remove, j);

        /* Free data and next 'smaller' objects */
        free(j);
}

void job_dump(Job *j, FILE*f) {

        static const char* const job_type_table[_JOB_TYPE_MAX] = {
                [JOB_START] = "start",
                [JOB_STOP] = "stop",
                [JOB_VERIFY_STARTED] = "verify-started",
                [JOB_RELOAD] = "reload",
                [JOB_RESTART] = "restart",
                [JOB_TRY_RESTART] = "try-restart",
                [JOB_RESTART_FINISH] = "restart-finish"
        };

        static const char* const job_state_table[_JOB_STATE_MAX] = {
                [JOB_WAITING] = "waiting",
                [JOB_RUNNING] = "running",
                [JOB_DONE] = "done"
        };

        assert(j);
        assert(f);

        fprintf(f, "Job %u (%s) → %s in state %s\n",
                j->id,
                name_id(j->name),
                job_type_table[j->type],
                job_state_table[j->state]);
}
