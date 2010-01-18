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

int job_link(Job *j) {
        int r;

        assert(j);
        assert(!j->linked);

        if ((r = hashmap_put(j->manager->jobs, UINT32_TO_PTR(j->id), j)) < 0)
                return r;

        j->name->meta.job = j;

        j->linked = true;

        return 0;
}

void job_free(Job *j) {
        assert(j);

        /* Detach from next 'bigger' objects */

        if (j->linked) {
                assert(j->name);
                assert(j->name->meta.job == j);
                j->name->meta.job = NULL;

                hashmap_remove(j->manager->jobs, UINT32_TO_PTR(j->id));
        }

        hashmap_remove(j->manager->jobs_to_add, j->name);
        set_remove(j->manager->jobs_to_remove, j);

        /* Free data and next 'smaller' objects */
        free(j);
}
